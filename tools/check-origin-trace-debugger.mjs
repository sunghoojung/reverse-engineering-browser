import {checkVmRequestLinkageUI} from './check-vm-request-linkage-ui.mjs';

import {checkSourceWindowModel} from './check-source-window.mjs';
import {checkTrafficComparisonController} from './check-traffic-comparison-ui.mjs';
import {checkTrafficComparisonModel} from './check-traffic-comparison.mjs';
import {canvasEvidenceFixture, checkCanvasFixture} from './check-canvas-ui.mjs';
import {checkConsoleDOM} from './check-console-workspace.mjs';
import {checkNativeConsoleLiveDocuments} from './check-native-console-live-documents.mjs';
import {checkFloat32Model} from './check-float32-ui.mjs';
import { runInNewContext } from "node:vm";
import {readFile, writeFile} from "node:fs/promises";
import { join } from "node:path";

import assert from "node:assert/strict";
import {checkCollectionController} from "./check-origin-trace-collection.mjs";
import {checkInvestigationCore} from "./check-investigation-navigation.mjs";
import {checkAnalystController} from './check-analyst-editor.mjs';
import {checkNotebookCore} from './check-investigation-notebook.mjs';
import {checkSourcesHistoryFixture} from "./check-sources-history.mjs";
import {checkSourcesTreeFixture} from "./check-sources-tree.mjs";
import {checkSourceTreeModel} from "./check-source-tree-model.mjs";
const fieldsOnly = process.argv[2] === "--field-provenance-only";
if (process.argv[2] && process.argv[2].startsWith('--') && !fieldsOnly) {
  throw new Error('Rendered/CDP UI modes are retired; use --field-provenance-only for retained offline assertions. No rendered QA is claimed.');
}
const root = process.argv[fieldsOnly ? 3 : 2] || new URL("..", import.meta.url).pathname;
await checkSourceWindowModel(root);
await checkSourceTreeModel(root);
await checkTrafficComparisonModel(root);
await checkTrafficComparisonController(root);
await checkConsoleDOM(root);
await checkNativeConsoleLiveDocuments(root);
await checkCollectionController(root);
await checkInvestigationCore(root);
await checkNotebookCore(root);
await checkAnalystController(root);
await checkFloat32Model(root);
// The fixture serves the same declared public leaves as the product. Inspect
// raw origin-form paths before URL normalization, so encoded/traversing paths
// cannot become an allowed asset accidentally.
const fixturePublicAssets = new Set(['index.html', ...[...(await readFile(join(root,'apps/research-ui/index.html'),'utf8')).matchAll(/(?:src|href)="([^"/]+\.(?:js|css))"/g)].map(match=>match[1])]);
function fixtureAssetName(raw) {
  const path=raw.split('?')[0],name=path==='/'?'index.html':path.startsWith('/')?path.slice(1):'';
  return /^[a-z][a-z0-9_]*\.(?:html|js|css)$/.test(name) && fixturePublicAssets.has(name) ? name : null;
}
async function serveFixtureAsset(request,response) {
  const name=fixtureAssetName(request.url);
  if (!name) {response.writeHead(404);response.end();return;}
  try {
    response.writeHead(200, {'Content-Type':name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':'text/html'});
    response.end(await readFile(join(root,'apps/research-ui',name)));
  } catch {response.writeHead(404);response.end();}
}
for (const path of ['/float32_inspector.js','/float32_inspector.js?cache=1','/']) {
  let status,body;await serveFixtureAsset({url:path},{writeHead:value=>{status=value;},end:value=>{body=value;}});
  assert.equal(status,200);assert.deepEqual(body,await readFile(join(root,'apps/research-ui',fixtureAssetName(path))));
}
for (const path of ['/../float32_inspector.js','/x/../float32_inspector.js','/%66loat32_inspector.js','/%2e%2e/float32_inspector.js','/x%2ffloat32_inspector.js','//float32_inspector.js','/float32_inspector.js/','/analyst_runner_core.js','/missing.js','/float32_inspector.js#fragment']) {
  let status;await serveFixtureAsset({url:path},{writeHead:value=>{status=value;},end(){}});assert.equal(status,404,path);
}
console.log('PASS actual fixture public-asset handler: Float32 bytes, canonical paths, private/unknown/traversing/encoded negatives (not rendered QA)');
// Facts are UI projections over the already validated Rust contract. These
// fixtures exercise identity and stale/cancelled request ownership, not JS execution.
const sourceFactsUI = runInNewContext(
  (await readFile(join(root, 'apps/research-ui/source_facts.js'), 'utf8')) +
  ';({sourceFactsFields,sourceFactsIdentity,sourceFactsUnavailable,isSourceFactsReport,sourceFactsPosition,sourceFactsReadBytes,createSourceFactsController,sourceFactsReferenceTarget,sourceFactsBindingOperations,sourceFactsOperationSummary,sourceFactsReferenceContext,createSourceFactsPanel})',
  {TextEncoder, TextDecoder, Uint8Array, AbortController, setTimeout, clearTimeout, fetch, crypto},
);
function factsReferenceFixture(source) {
  const text = '\ufefflet 雪 = "😀";\nfunction shadow(雪) { return 雪; }\nfunction closure() { return 雪; }\n雪++;\nvar duplicate; var duplicate;\nduplicate(); new duplicate();\nconst spare = 0;\nunknown; object.雪;\n' + '雪;\n'.repeat(105);
  const bytes = new TextEncoder().encode(text);
  const range = (needle, after = 0) => {const index = text.indexOf(needle, after); assert(index >= 0); return {start:Buffer.byteLength(text.slice(0,index)),end:Buffer.byteLength(text.slice(0,index+needle.length))};};
  const full = {start:0,end:bytes.length};
  const target = id => ({kind:'binding',binding_ids:[id],resolution:'lexical-only',name:'雪'});
  const ambiguous = {kind:'ambiguous',binding_ids:[2,3],resolution:'duplicate-declarations',name:'duplicate'};
  const operation = (id, kind, range, target, region_id=0) => ({id,region_id,order:id,range,kind,detail:{target}});
  const operations = [
    operation(0,'read',range('雪',text.indexOf('closure')),target(0),2),
    operation(1,'read',range('雪',text.indexOf('return')),target(1),1),
    operation(2,'read',range('雪++'),target(0)),operation(3,'write',range('雪++'),target(0)),
    operation(4,'call',range('duplicate()'),ambiguous),operation(5,'construct',range('new duplicate()'),ambiguous),
    operation(6,'read',range('unknown'),{kind:'unresolved',binding_ids:[],resolution:'dynamic-scope',name:'雪'}),
    operation(7,'read',range('object.雪'),{kind:'property',object_range:range('object'),key_range:range('雪',text.indexOf('object')),computed:false}),
  ];
  let after=text.indexOf('object.雪;')+'object.雪;'.length;
  for(let i=0;i<105;i++){const start=text.indexOf('雪;',after);operations.push(operation(8+i,'read',range('雪',start),target(0)));after=start+2;}
  const scope = (id, needle) => ({id,parent_id:0,range:range(needle),kind:'function'});
  const scopes = [{id:0,parent_id:null,range:full,kind:'program'},scope(1,'function shadow(雪) { return 雪; }'),scope(2,'function closure() { return 雪; }')];
  const binding = (id,name,kind,scope_id,after=0) => ({id,name,kind,scope_id,range:range(name,after)});
  const report = {schema:'reb-javascript-source-facts-v1',profile:'lexical-effects-v1',offset_unit:'utf-8-byte',source_bytes:bytes.length,source,ok:true,scopes,
    bindings:[binding(0,'雪','let',0),binding(1,'雪','parameter',1,text.indexOf('shadow')),binding(2,'duplicate','var',0),binding(3,'duplicate','var',0,text.indexOf('duplicate;')+10),binding(4,'spare','const',0)],callables:[],
    regions:scopes.map(({id,range})=>({id,parent_id:id?0:null,callable_id:null,range,kind:id?'conditional-then':'program',entry_order:id})),operations,
    coverage:{status:'partial',truncated:false,diagnostics:[],frontiers:[{range:range('duplicate()'),reason:'unknown-call-mutation-or-throw'}]},
    limits:{max_source_bytes:4194304,max_ast_nodes:32768,max_facts:16384,max_frontiers:256,max_binding_candidates:64,preflight_depth:128,preflight_nodes:500000}};
  return {text,bytes,report};
}
const references = factsReferenceFixture();
assert.deepEqual(Array.from(sourceFactsUI.sourceFactsBindingOperations(references.report,1),row=>row.id),[1],'Shadowed spelling must not join outer lexical operations');
assert.equal(sourceFactsUI.sourceFactsBindingOperations(references.report,0,'read').length,107,'Closure and outer reads share the exact binding ID');
assert.deepEqual(Array.from(sourceFactsUI.sourceFactsBindingOperations(references.report,0,'write'),row=>row.id),[3]);
assert.deepEqual(Array.from(sourceFactsUI.sourceFactsBindingOperations(references.report,2),row=>row.id),[4,5]);
assert.deepEqual(Array.from(sourceFactsUI.sourceFactsBindingOperations(references.report,3),row=>row.id),[4,5]);
assert.equal(sourceFactsUI.sourceFactsBindingOperations(references.report,4).length,0);
assert.equal(sourceFactsUI.sourceFactsBindingOperations(references.report,999).length,0);
const cachedReferenceContext = sourceFactsUI.sourceFactsReferenceContext(references.report);
assert.equal(sourceFactsUI.sourceFactsReferenceContext(references.report),cachedReferenceContext,'Filters and paging reuse one bounded report context');
assert.equal(cachedReferenceContext.target(references.report.operations[0]),references.report.operations[0].detail.target,'Cache retains the existing target, never copies candidate arrays');
assert.notEqual(sourceFactsUI.sourceFactsReferenceContext(structuredClone(references.report)),cachedReferenceContext,'Reanalysis must receive a fresh report-local cache');
const referenceBindings = new Map(references.report.bindings.map(row=>[row.id,row]));
assert.match(sourceFactsUI.sourceFactsOperationSummary(references.report.operations[4],referenceBindings),/Ambiguous.*runtime call target unknown/);
assert.match(sourceFactsUI.sourceFactsOperationSummary(references.report.operations[6],referenceBindings),/Unresolved: dynamic-scope/);
assert.match(sourceFactsUI.sourceFactsOperationSummary(references.report.operations[7],referenceBindings),/Property target; runtime object unknown/);
for(const invalid of [{kind:'binding',binding_ids:[0,1],resolution:'lexical-only'},{kind:'ambiguous',binding_ids:[2,2],resolution:'duplicate-declarations'},{kind:'binding',binding_ids:[999],resolution:'lexical-only'},{kind:'binding',binding_ids:[0],resolution:'runtime'},{kind:'ambiguous',binding_ids:Array.from({length:65},(_,i)=>i),resolution:'duplicate-declarations'}]) {
  assert.equal(sourceFactsUI.sourceFactsReferenceTarget({...references.report.operations[0],detail:{target:invalid}},referenceBindings),null);
}
assert.equal(sourceFactsUI.sourceFactsReferenceTarget({...references.report.operations[0],detail:{nested:{target:references.report.operations[0].detail.target}}},referenceBindings),null,'Arbitrary nested JSON is never lexical evidence');
console.log('PASS Facts lexical joins: same-name shadowing, closures, reads/writes, ambiguous declaration candidates, unresolved/property refusal, malformed joins and operation filtering (not rendered QA)');
async function checkFactsReferencePanel() {
const panelSource = await readFile(join(root,'apps/research-ui/source_facts.js'),'utf8');
const reference = factsReferenceFixture();
let document;
class FactsReviewNode {
  constructor(tag) {
    this.tagName = tag; this.children = []; this.dataset = {}; this.attributes = {};
    this.listeners = {}; this._text = ''; this.value = ''; this.disabled = false;
    this.selectionStart = 0; this.selectionEnd = 0; this.parentNode = null;
  }
  set textContent(value) { this._text = String(value); this.replaceChildren(); }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...nodes) { for (const node of nodes) { node.parentNode = this; this.children.push(node); } }
  replaceChildren(...nodes) {
    for (const child of this.children) {
      if (child.contains(document?.activeElement)) document.activeElement = null;
      child.parentNode = null;
    }
    this.children = []; this.append(...nodes);
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  addEventListener(name, handler) { (this.listeners[name] ??= []).push(handler); }
  fire(name, values = {}) { for (const handler of this.listeners[name] ?? []) handler({target: this, currentTarget: this, ...values}); }
  click() { if (!this.disabled) this.fire('click'); }
  contains(node) { return this === node || this.children.some(child => child.contains(node)); }
  get isConnected() { return roots.some(root => root.contains(this)); }
  focus() { if (this.isConnected) document.activeElement = this; }
  setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }
  getClientRects() { return this.isConnected ? [1] : []; }
  scrollIntoView() {}
  matches(selector) {
    if (selector.includes(',')) return selector.split(',').some(value => this.matches(value.trim()));
    if (selector.startsWith('.')) return this.className?.split(' ').includes(selector.slice(1)) ?? false;
    if (selector.startsWith('[')) {
      const match = selector.match(/^\[([^=\]]+)(?:="?([^"\]]*)"?)?\]$/);
      if (!match) return false;
      const name = match[1];
      const value = name.startsWith('data-') ? this.dataset[name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] : this.attributes[name];
      return match[2] === undefined ? value !== undefined : value === match[2];
    }
    return selector === this.tagName;
  }
  querySelectorAll(selector) { return this.children.flatMap(child => [...(child.matches(selector) ? [child] : []), ...child.querySelectorAll(selector)]); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
  closest(selector) { return this.matches(selector) ? this : this.parentNode?.closest(selector); }
}
const toggle = new FactsReviewNode('button');
const details = new FactsReviewNode('details');
const container = new FactsReviewNode('div');
const roots = [toggle, details];
details.append(new FactsReviewNode('summary'), container);
details.open = true;
document = {activeElement: null, createElement: tag => new FactsReviewNode(tag), querySelector: selector => ({'#source-facts-toggle': toggle, '#source-facts-details': details, '#source-facts-report': container}[selector])};
let selected = {source_type: 'artifact', protocol_version: 1, artifact_id: '12', session_id: '11', navigation_id: '13', frame_id: '17', parent_artifact_id: '0', creator_event_id: '19', execution_context_id: '23', capture_origin: 'dynamic_javascript', kind: 'javascript', url: 'https://fixture.invalid/facts-12.js', mime_type: 'text/javascript', byte_size: reference.bytes.length, sha256: Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',reference.bytes)),byte=>byte.toString(16).padStart(2,'0')).join(''), sensitive: false};
let reportError = false, finishOriginal, navigations = 0;
const create = Function('document', 'location', 'fetch', `${panelSource}; return createSourceFactsPanel;`)(document, {protocol: 'http:'}, async url => url.startsWith('/api/artifacts/') ? new Promise(resolve=>{finishOriginal=()=>resolve(new Response(reference.bytes,{headers:{'X-Artifact-Total-Bytes':String(reference.bytes.length),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}}));}) : reportError ? Response.json({error: 'Authored retry failure'}, {status: 503}) : Response.json(factsReferenceFixture(selected).report));
const panel = create({getSource: () => selected, onNavigate() { navigations++; }, openSidebar() {}});
const control = selector => { const node = container.querySelector(selector); assert(node, `Missing ${selector}`); return node; };
const action = name => control(`[data-facts-action="${name}"]`);
const category = value => { const node = control('[aria-label="JavaScript fact category"]'); node.value = value; node.fire('change'); };
const row = id => control(`[data-fact-id="${id}"]`);
panel.sync(selected);
const idleArtifact = selected;
selected = {source_type:'script',kind:'javascript'};panel.sync(selected);
selected = idleArtifact;assert.doesNotThrow(()=>panel.sync(selected),'Idle captured → unsupported → captured must rebuild the retained DOM');
await panel.load();
assert.equal(container.querySelectorAll('article').length, 100);
category('bindings');
const composingInput = control('[data-facts-binding-query]'); composingInput.focus();
composingInput.fire('compositionstart'); composingInput.value = '雪';
composingInput.fire('input', {isComposing: true});
let composingEscapePrevented = false, composingEscapeStopped = false;
details.fire('keydown',{key:'Escape',isComposing:true,preventDefault(){composingEscapePrevented=true;},stopPropagation(){composingEscapeStopped=true;}});
assert.equal(composingEscapeStopped,true,'IME Escape must not bubble into the document Sources shortcut and toggle Console');
assert.equal(details.open,true);assert.equal(composingEscapePrevented,false,'IME Escape must remain available to composition');
assert(composingInput.isConnected, 'Composition must not detach its input');
assert.equal(document.activeElement, composingInput);
composingInput.fire('compositionend', {isComposing: false});
assert.equal(container.querySelectorAll('article').length, 2);
assert.equal(document.activeElement.value, '雪');
row(1).querySelector('[data-facts-action="explore-binding"]').click();
assert.equal(container.querySelectorAll('article').length, 1);
assert.equal(container.querySelector('article').dataset.factId, '1', 'Shadowed name must not join outer references');
action('reveal-declaration').click();
for(let turn=0;turn<20&&!finishOriginal;turn++)await new Promise(resolve=>setTimeout(resolve,0));
assert(finishOriginal,'Verified original read did not start');
const pendingAllBindings = action('all-bindings');
panel.cancel('A newer interaction retired this original-range return.');
assert(pendingAllBindings.isConnected,'Capture-phase cancellation must preserve the pending click target');
pendingAllBindings.click();assert(control('[data-facts-binding-query]'),'The original click must still change the view after capture cancellation');
finishOriginal();
await new Promise(resolve=>setTimeout(resolve,0));
assert.equal(navigations,0,'Changing lexical selection must retire a pending original range');
const retiredQuery = control('[data-facts-binding-query]');
const retiredCategory = control('[aria-label="JavaScript fact category"]');
const retiredExplore = action('explore-binding');
selected = {...selected, artifact_id: '13'}; panel.sync(selected); await panel.load(); category('operations');
const currentText = container.textContent;
retiredQuery.value = 'must not leak'; retiredQuery.fire('input');
retiredCategory.value = 'frontiers'; retiredCategory.fire('change'); retiredExplore.click();
assert.equal(container.textContent, currentText, 'Detached controls must not change the newer source/report');
category('bindings'); row(0).querySelector('[data-facts-action="explore-binding"]').click();
reportError = true; await panel.load();
assert(container.querySelector('.source-facts-binding').textContent.includes('Binding #0'), 'Failed retry must preserve the selected declaration');
reportError = false; await panel.load();
assert.equal(container.querySelector('.source-facts-binding'), null, 'Successful reanalysis must retire report-local binding selection');
console.log('PASS offline Facts panel read-cancellation, composing-Escape, IME input lifetime, same-name shadowing, detached controls, failed-retry selection retention and successful-retry invalidation. Not rendered QA.');

}
await checkFactsReferencePanel();
const factsBytes = new TextEncoder().encode('\ufeffconst 雪 = "😀";\n雪++;');
const factsHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', factsBytes)), byte => byte.toString(16).padStart(2, '0')).join('');
const factsArtifact = {source_type:'artifact', protocol_version:1, artifact_id:'7', session_id:'11', navigation_id:'13', frame_id:'17', parent_artifact_id:'0', creator_event_id:'19', execution_context_id:'23', capture_origin:'dynamic_javascript', kind:'javascript', url:'https://fixture.invalid/facts.js', mime_type:'text/javascript', byte_size:factsBytes.length, sha256:factsHash, sensitive:false};
const factsFixture = source => ({schema:'reb-javascript-source-facts-v1', profile:'lexical-effects-v1', offset_unit:'utf-8-byte', source_bytes:source.byte_size, ok:true,
  source:Object.fromEntries(Object.entries(source).filter(([key]) => key !== 'source_type')),
  scopes:[{id:0,parent_id:null,range:{start:0,end:source.byte_size},kind:'program'}], bindings:[], callables:[], regions:[{id:0,parent_id:null,callable_id:null,range:{start:0,end:source.byte_size},kind:'program',entry_order:0}], operations:[],
  coverage:{status:'complete',truncated:false,frontiers:[],diagnostics:[]}, limits:{max_source_bytes:4194304,max_ast_nodes:32768,max_facts:16384,max_frontiers:256,max_binding_candidates:64,preflight_depth:128,preflight_nodes:500000}});
assert.equal(sourceFactsUI.sourceFactsUnavailable(factsArtifact, 'http:'), '');
assert.match(sourceFactsUI.sourceFactsUnavailable(factsArtifact, 'reb:'), /stored-evidence native mode/);
assert.match(sourceFactsUI.sourceFactsUnavailable({...factsArtifact,source_type:'script'}, 'http:'), /captured JavaScript/);
for (const source of [{...factsArtifact,artifact_id:'07'},{...factsArtifact,session_id:'18446744073709551616'},{...factsArtifact,byte_size:4194305}]) assert(sourceFactsUI.sourceFactsUnavailable(source, 'http:'));
const factsReport = factsFixture(factsArtifact);
assert(sourceFactsUI.isSourceFactsReport(factsReport, factsArtifact));
for (const field of Object.keys(factsReport.source)) {
  const foreign = structuredClone(factsReport); foreign.source[field] = null;
  assert.equal(sourceFactsUI.isSourceFactsReport(foreign, factsArtifact), false, field);
}
for (const update of [{offset_unit:'utf-16'}, {source_bytes:0}, {ok:false}, {bindings:Array(16385).fill({})},
  {scopes:[{...factsReport.scopes[0],range:{start:0,end:factsBytes.length+1}}]},
  {scopes:[factsReport.scopes[0],factsReport.scopes[0]]},
  {scopes:[{...factsReport.scopes[0],kind:'executed'}]},
  {coverage:{status:'complete',truncated:true,frontiers:[],diagnostics:[]}},
  {coverage:{status:'partial',truncated:false,frontiers:Array(257).fill({}),diagnostics:[]}}]) {
  assert.equal(sourceFactsUI.isSourceFactsReport({...factsReport,...update}, factsArtifact), false);
}
const partialFacts = {...factsReport, coverage:{status:'partial',truncated:true,frontiers:[{range:{start:0,end:0},reason:'fact-limit'}],diagnostics:['Bounded coverage']}};
assert(sourceFactsUI.isSourceFactsReport(partialFacts, factsArtifact));
const unavailableFacts = {...factsReport,ok:false,scopes:[],regions:[],coverage:{status:'unavailable',truncated:false,frontiers:[],diagnostics:['Malformed source']}};
assert(sourceFactsUI.isSourceFactsReport(unavailableFacts, factsArtifact));
assert.equal(sourceFactsUI.isSourceFactsReport({...unavailableFacts,scopes:factsReport.scopes}, factsArtifact), false);
const snowOffset = new TextEncoder().encode('\ufeffconst ').length;
const snowPosition = sourceFactsUI.sourceFactsPosition(factsBytes,{start:snowOffset,end:snowOffset+3});
assert.equal(snowPosition.line,0); assert.equal(snowPosition.column,7); assert.equal(snowPosition.length,1);
assert.throws(() => sourceFactsUI.sourceFactsPosition(factsBytes,{start:snowOffset+1,end:snowOffset+3}));
assert.equal(sourceFactsUI.sourceFactsPosition(factsBytes,{start:0,end:factsBytes.length}).multiline,true);
assert.equal(sourceFactsUI.sourceFactsPosition(new Uint8Array(),{start:0,end:0}).column,0);
await assert.rejects(sourceFactsUI.sourceFactsReadBytes(new Response(new Uint8Array(5)),4), /byte limit/);
// Response storage owns one bounded byte buffer, never a retained chunk list.
const factsReaderFixture = (read, cancel = async () => {}) => {
  const counts = {reads:0,cancels:0,releases:0};
  return {counts, response:{body:{getReader:()=>({
    read:()=>{counts.reads++;return read(counts.reads);},
    cancel:()=>{counts.cancels++;return cancel();},
    releaseLock:()=>{counts.releases++;},
  })}}};
};
const factsFragmented = (count, width) => factsReaderFixture(async index => index>count
  ? {done:true} : {done:false,value:new Uint8Array(width).fill(index%251)});
for (const [count,width] of [[0,0],[65536,0],[65536,1]]) {
  const fixture=factsFragmented(count,width);
  const result=await sourceFactsUI.sourceFactsReadBytes(fixture.response,count*width);
  assert.equal(result.length,count*width);assert.equal(result.buffer.byteLength,count*width);
  if(width) for(let index=0;index<result.length;index++) assert.equal(result[index],(index+1)%251);
  assert.deepEqual(fixture.counts,{reads:count+1,cancels:0,releases:1});
}
for (const width of [0,1]) {
  const fixture=factsFragmented(65537,width);
  await assert.rejects(sourceFactsUI.sourceFactsReadBytes(fixture.response,65537),/stream chunk limit/);
  assert.deepEqual(fixture.counts,{reads:65537,cancels:1,releases:1});
}
const oversizedFacts=factsFragmented(1,5);
await assert.rejects(sourceFactsUI.sourceFactsReadBytes(oversizedFacts.response,4),/byte limit/);
assert.deepEqual(oversizedFacts.counts,{reads:1,cancels:1,releases:1});
const nonbyteFacts=factsReaderFixture(async()=>({done:false,value:[1]}));
await assert.rejects(sourceFactsUI.sourceFactsReadBytes(nonbyteFacts.response,4),/non-byte chunk/);
assert.equal(nonbyteFacts.counts.cancels,1);assert.equal(nonbyteFacts.counts.releases,1);
const reusedFactsChunk=new Uint8Array(1024*1024);
const aliasedFacts=factsReaderFixture(async index=>{
  if(index>factsBytes.length)return {done:true};
  reusedFactsChunk[17]=factsBytes[index-1];
  return {done:false,value:reusedFactsChunk.subarray(17,18)};
});
const ownedFactsBytes=await sourceFactsUI.sourceFactsReadBytes(aliasedFacts.response,factsBytes.length);
assert.deepEqual(ownedFactsBytes,factsBytes,'Copy each fragmented UTF-8/BOM byte before its producer reuses the backing store');
assert.equal(ownedFactsBytes.buffer.byteLength,factsBytes.length);
assert.notEqual(ownedFactsBytes.buffer,reusedFactsChunk.buffer);
const cancelledFactsSignal=new AbortController();cancelledFactsSignal.abort();
const preCancelledFacts=factsFragmented(1,1);
await assert.rejects(sourceFactsUI.sourceFactsReadBytes(preCancelledFacts.response,1,cancelledFactsSignal.signal),/cancelled/);
assert.deepEqual(preCancelledFacts.counts,{reads:0,cancels:1,releases:1});
const fragmentedFactsSignal=new AbortController();
const interruptibleFacts=factsFragmented(65537,1);
const interruptFactsTimer=setTimeout(()=>fragmentedFactsSignal.abort(),0);
try {
  await assert.rejects(sourceFactsUI.sourceFactsReadBytes(interruptibleFacts.response,65537,fragmentedFactsSignal.signal),/cancelled/);
} finally {clearTimeout(interruptFactsTimer);}
assert(interruptibleFacts.counts.reads<=256,'Fragmented streams must yield to cancellation/deadline tasks');
assert.equal(interruptibleFacts.counts.cancels,1);assert.equal(interruptibleFacts.counts.releases,1);
const stalledFactsSignal=new AbortController();let stalledFactsCancelled=0;
const stalledFactsResponse=new Response(new ReadableStream({cancel(){stalledFactsCancelled++;return new Promise(()=>{});}}));
const stalledFactsRead=sourceFactsUI.sourceFactsReadBytes(stalledFactsResponse,4,stalledFactsSignal.signal);
stalledFactsSignal.abort();
let stalledFactsWatchdog;
try {
  await assert.rejects(Promise.race([stalledFactsRead,new Promise((_,reject)=>{stalledFactsWatchdog=setTimeout(()=>reject(new Error('Stalled reader did not cancel promptly')),1000);})]),/cancelled/);
} finally {clearTimeout(stalledFactsWatchdog);}
assert.equal(stalledFactsCancelled,1);assert.equal(stalledFactsResponse.body.locked,false);
console.log('PASS Sources owned response bytes, exact byte/chunk limits, empty/fragmented/aliased streams and cancellation despite stalled producer cleanup');
let selectedFactsArtifact = factsArtifact;
let factsPending = [];
let factsNavigations = [];
const factsController = sourceFactsUI.createSourceFactsController({getSource:()=>selectedFactsArtifact,protocol:'http:',onChange:()=>{},onNavigate:(...args)=>factsNavigations.push(args),cryptoApi:crypto,
  fetcher:(url,options)=>new Promise(resolve=>factsPending.push({url,options,resolve}))});
const deliverFacts = (entry, source = selectedFactsArtifact) => entry.resolve(Response.json(factsFixture(source)));
factsController.sync(selectedFactsArtifact);
const firstFactsLoad = factsController.load();
assert.equal(factsPending.length,1); assert.match(factsPending[0].url,/session_id=11&artifact_id=7$/);
await factsController.load(); assert.equal(factsPending.length,1,'Repeated load shares one in-flight request');
factsController.cancel(); assert.equal(factsPending[0].options.signal.aborted,true);
const secondFactsLoad = factsController.load();
deliverFacts(factsPending[1]); await secondFactsLoad;
const retainedFactsReport = factsController.model.report;
deliverFacts(factsPending[0]); await firstFactsLoad;
assert.equal(factsController.model.report,retainedFactsReport,'A cancelled older response cannot replace current facts');
const staleFactsLoad = factsController.load();
selectedFactsArtifact = {...factsArtifact,session_id:'12'}; factsController.sync(selectedFactsArtifact);
deliverFacts(factsPending[2],factsArtifact); await staleFactsLoad;
assert.equal(factsController.model.report,null,'Switching source clears facts and rejects delayed responses');
selectedFactsArtifact = factsArtifact; factsController.sync(selectedFactsArtifact);
const matchingFactsLoad = factsController.load(); deliverFacts(factsPending[3]); await matchingFactsLoad;
const nav = factsController.navigate({start:snowOffset,end:snowOffset+3});
assert.match(factsPending[4].url,/artifact[s]\/7\/content\?offset=0&limit=2097152$/);
factsPending[4].resolve(new Response(factsBytes,{headers:{'X-Artifact-Total-Bytes':String(factsBytes.length),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}})); await nav;
assert.equal(factsNavigations.length,1); assert.equal(factsNavigations[0][2].column,7);
assert.equal(factsController.original(factsArtifact),'\ufeffconst 雪 = "😀";\n雪++;');
await factsController.navigate({start:0,end:0}); assert.equal(factsPending.length,5,'Repeated navigation reuses verified original bytes');
selectedFactsArtifact = {...factsArtifact,sha256:'b'.repeat(64)}; factsController.sync(selectedFactsArtifact);
assert.equal(factsController.original(selectedFactsArtifact),undefined,'Changed hash invalidates original bytes');
const mismatchedFactsLoad = factsController.load(); deliverFacts(factsPending[5],factsArtifact); await mismatchedFactsLoad;
assert.equal(factsController.model.status,'error'); assert.equal(factsController.model.report,null);
for (const body of [new Response(factsBytes,{headers:{'X-Artifact-Truncated':'1'}}),new Response(new Uint8Array(factsBytes.length),{headers:{'X-Artifact-Total-Bytes':String(factsBytes.length),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}})]) {
  const attempt = factsController.navigate({start:0,end:0}); factsPending.at(-1).resolve(body); await attempt;
  assert.equal(factsController.model.status,'error'); assert.equal(factsController.original(selectedFactsArtifact),undefined);
}
selectedFactsArtifact = factsArtifact;
let timeoutNavigations = 0;
const slowFacts = sourceFactsUI.createSourceFactsController({getSource:()=>selectedFactsArtifact,protocol:'http:',deadline:5,onChange:()=>{},onNavigate:()=>timeoutNavigations++,cryptoApi:crypto,
  fetcher:async(_url,{signal})=>new Response(new ReadableStream({start(stream){signal.addEventListener('abort',()=>stream.error(new DOMException('Aborted','AbortError')),{once:true});}}))});
await slowFacts.load(); assert.match(slowFacts.model.error,/timed out/); assert.equal(timeoutNavigations,0);
assert.equal(slowFacts.model.report,null);
for (const mode of ['facts','source']) {
  let cancelledBody=0, bodyChunks=0;
  const fragmentedController=sourceFactsUI.createSourceFactsController({getSource:()=>factsArtifact,protocol:'http:',deadline:5,onChange:()=>{},onNavigate:()=>{throw new Error('Timed-out fragmented source navigated');},cryptoApi:crypto,
    fetcher:async()=>new Response(new ReadableStream({
      pull(stream){bodyChunks++;stream.enqueue(new Uint8Array());},
      cancel(){cancelledBody++;return new Promise(()=>{});},
    }),{headers:{'X-Artifact-Total-Bytes':String(factsBytes.length),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}})});
  const operation=mode==='facts'?fragmentedController.load():fragmentedController.navigate({start:0,end:0});
  let watchdog;
  try {
    await Promise.race([operation,new Promise((_,reject)=>{watchdog=setTimeout(()=>reject(new Error('Fragmented controller deadline stalled')),2000);})]);
  } finally {clearTimeout(watchdog);}
  assert.match(fragmentedController.model.error,/timed out/);assert.equal(fragmentedController.model.status,'error');
  assert.equal(fragmentedController.model.report,null);assert.equal(fragmentedController.model.original,null);
  assert.equal(cancelledBody,1);assert(bodyChunks<65536,'Body deadlines must run before exhausting the chunk budget');
}
let finishFactsDigest, factsDigestArrived, factsDigestTimedOut;
const digestArrival = new Promise(resolve=>{factsDigestArrived=resolve;});
const digestTimeout = new Promise(resolve=>{factsDigestTimedOut=resolve;});
const digestFacts = sourceFactsUI.createSourceFactsController({getSource:()=>factsArtifact,protocol:'http:',deadline:100,onChange:model=>{if(model.status==='error') factsDigestTimedOut();},onNavigate:()=>{throw new Error('Late digest navigated');},
  cryptoApi:{subtle:{digest:()=>new Promise(resolve=>{finishFactsDigest=resolve;factsDigestArrived();})}},
  fetcher:async()=>new Response(factsBytes,{headers:{'X-Artifact-Total-Bytes':String(factsBytes.length),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}})});
const digestNavigation = digestFacts.navigate({start:0,end:0});
let digestWatchdog;
try { await Promise.race([Promise.all([digestArrival,digestTimeout]),new Promise((_,reject)=>{digestWatchdog=setTimeout(()=>reject(new Error('Digest timeout fixture did not reach both states')),2000);})]); }
finally { clearTimeout(digestWatchdog); }
assert.equal(digestFacts.model.status,'error','Deadline ends busy state while non-abortable digest is pending');
assert.match(digestFacts.model.error,/timed out/);
finishFactsDigest(await crypto.subtle.digest('SHA-256',factsBytes)); await digestNavigation;
assert.equal(digestFacts.model.status,'error'); assert.equal(digestFacts.model.original,null);
console.log('PASS Sources facts identity, UTF-8/BOM ranges, bounded streams, repeated loads, cancellation, stale responses, hash checks and timeout');

// Native capabilities must not depend on callers remembering a URL flag.
// Execute the actual JS consumer; Swift normalization itself is tested by the
// compiled app during macOS app-build, not by a JS translation here.
const nativeStateMarker=(await readFile(join(root,'apps/research-ui/app_state.js'),'utf8')).split('\n')[0];
for(const [search,expected] of [['',false],['?x=a%2Bb&x=c%26d',false],['?native=1',true],['?native=0&native=2',true],['?%6Eative=1',true],['?Native=1',false]]){
  let native=false;runInNewContext(nativeStateMarker,{location:{search},URLSearchParams,document:{documentElement:{classList:{add(name){assert.equal(name,'native-shell');native=true;}}}}});assert.equal(native,expected);
}
const nativeAppSource=await readFile(join(root,'apps/research-ui/macos/OriginTraceApp.swift'),'utf8');
assert.match(nativeAppSource,/return nativeUIURL\(arguments\[urlFlag \+ 1\]\)/);
assert.match(nativeAppSource,/let nativeURL = nativeUIURL\(liveURL\.absoluteString\)/);
assert.match(nativeAppSource,/webView\.load\(URLRequest\(url: nativeURL\)\)/);
assert.match(nativeAppSource,/webView\.load\(URLRequest\(url: requestedUIURL \?\? localApplicationURL\)\)/);
assert.match(nativeAppSource,/webView\.load\(URLRequest\(url: localApplicationURL\)\)/);
assert.match(nativeAppSource,/self\.localApplicationURL = localApplicationURL/);
assert.match(nativeAppSource,/URL\(string: "reb:\/\/app\/index\.html\?native=1"\)/);
assert.equal((nativeAppSource.match(/webView\.load\(URLRequest\(url:/g)??[]).length,3,'Review every new native entry path');
assert.match(nativeAppSource,/components\.percentEncodedQuery = \(retained \+ \["native=1"\]\)\.joined/);
assert.match(nativeAppSource,/name\.removingPercentEncoding != "native"/);
assert.match(nativeAppSource,/contains\("--check-native-ui-url"\) \{\s+checkNativeUIURLs\(\)\s+return/);
assert.match(await readFile(join(root,'scripts/build-research-app.sh'),'utf8'),/"\$\{macos_path\}\/OriginTrace" --check-native-ui-url/);
console.log('PASS native entry-path wiring and actual JS query consumer (Swift helper execution requires macOS app-build)');

// Exact-byte package workflow: the real HTTP validator remains authoritative.
const packageUI = runInNewContext(
  (await readFile(join(root, 'apps/research-ui/evidence_package.js'), 'utf8')) +
  ';({evidencePackageKey,evidencePackageKeyText,evidencePackageSelectionKey,evidencePackageUnavailable,evidencePackageReadBytes,evidencePackageValidationResult,evidencePackageView,createEvidencePackageController})',
  {TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout,clearTimeout,fetch},
);
const packageGoldenBytes = new Uint8Array(await readFile(join(root,'apps/origin-trace-backend/assets/evidence-packages/golden-v1.json')));
const packageGolden = JSON.parse(new TextDecoder().decode(packageGoldenBytes));
const packageValid = {protocol_version:1,status:'valid',package_id:packageGolden.package_id,origin:'untrusted_input',authenticity:'not_established',artifact_bytes:'not_present_not_reverified',
  checks:{structure:'passed',semantic_digest:'passed',references:'passed',metadata_profile:'passed'},issues:[],issues_truncated:false};
const packageInvalid = {...packageValid,status:'invalid',package_id:null,checks:{...packageValid.checks,structure:'failed'},issues:[{code:'duplicate_json_key',section:'document',index:null}]};
assert(packageUI.evidencePackageValidationResult(packageValid));
for (const value of [{...packageValid,authenticity:'verified'}, {...packageValid,artifact_bytes:'verified'}, {...packageValid,checks:{...packageValid.checks,references:'not_run'}},
  {...packageValid,issues:packageInvalid.issues}, {...packageValid,package_id:null}, {...packageValid,issues_truncated:true}]) assert.equal(packageUI.evidencePackageValidationResult(value),false);
assert.equal(packageUI.evidencePackageKey('event',{session_id:'18446744073709551615',process_id:4294967295,sequence_number:'18446744073709551615'}).sequence_number,'18446744073709551615');
for (const key of [{session_id:7,process_id:42,sequence_number:'1'}, {session_id:'07',process_id:42,sequence_number:'1'}, {session_id:'7',process_id:0,sequence_number:'1'},
  {session_id:'7',process_id:42,sequence_number:'18446744073709551616'}, {session_id:'7',process_id:42,sequence_number:'0'}]) assert.equal(packageUI.evidencePackageKey('event',key),null);
assert.equal(packageUI.evidencePackageKey('artifact',{session_id:'7',artifact_id:'9',payload:'secret'}).payload,undefined);
assert.notEqual(packageUI.evidencePackageKeyText('event',{session_id:'7',process_id:42,sequence_number:'1'}),packageUI.evidencePackageKeyText('event',{session_id:'8',process_id:42,sequence_number:'1'}));
assert.match(packageUI.evidencePackageUnavailable('reb:'),/stored-evidence native mode/);
assert.match(packageUI.evidencePackageUnavailable('file:'),/browser development UI/);
assert.equal(packageUI.evidencePackageUnavailable('http:'),'');
assert.equal(packageUI.evidencePackageView(packageGolden,packageValid).package_id,packageValid.package_id);
assert.throws(()=>packageUI.evidencePackageView({...packageGolden,package_id:'different'},packageValid));
await assert.rejects(packageUI.evidencePackageReadBytes(new Response(new Uint8Array(5)),4),/byte limit/);
// Transport fragmentation cannot create an unbounded retained chunk array.
let fragmentIndex=0;
const fragmented=new Response(new ReadableStream({pull(stream){if(fragmentIndex===8192)stream.close();else stream.enqueue(new Uint8Array([fragmentIndex++%251]));}}));
const fragmentedBytes=await packageUI.evidencePackageReadBytes(fragmented,8192);
assert.equal(fragmentedBytes.length,8192);assert.equal(fragmentedBytes.buffer.byteLength,8192);
assert(fragmentedBytes.every((byte,index)=>byte===index%251));
let fragmentedCancelled=false;
await assert.rejects(packageUI.evidencePackageReadBytes(new Response(new ReadableStream({pull(stream){stream.enqueue(new Uint8Array());},cancel(){fragmentedCancelled=true;}})),4),/transport chunk limit/);
assert.equal(fragmentedCancelled,true);
// Real streams close pending reads before their producer's cancellation cleanup
// settles; a never-settling cancel hook must not defeat limits or UI deadlines.
const packageWithinDeadline=async promise=>{let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Package reader did not retire within the fixture deadline')),2000);})]);}finally{clearTimeout(timer);}};
for(const empty of [false,true]){
  let cancelled=0;
  const response=new Response(new ReadableStream({pull(stream){stream.enqueue(new Uint8Array(empty?0:5));},cancel(){cancelled++;return new Promise(()=>{});}}));
  await packageWithinDeadline(assert.rejects(packageUI.evidencePackageReadBytes(response,4),empty?/transport chunk limit/:/byte limit/));
  assert.equal(cancelled,1);assert.equal(response.body.locked,false);
}
const packageAbort=new AbortController();let cancelledPending=0;
const pendingBody=new Response(new ReadableStream({cancel(){cancelledPending++;return new Promise(()=>{});}}));
const pendingRead=packageUI.evidencePackageReadBytes(pendingBody,4,packageAbort.signal);
packageAbort.abort();await packageWithinDeadline(assert.rejects(pendingRead,/cancelled/));assert.equal(cancelledPending,1);assert.equal(pendingBody.body.locked,false);
const packageSharedChunk=new Uint8Array(1024*1024);let packageSharedIndex=0;
const sharedResponse=new Response(new ReadableStream({pull(stream){if(packageSharedIndex===16)stream.close();else{packageSharedChunk[17]=packageSharedIndex++;stream.enqueue(packageSharedChunk.subarray(17,18));}}},{highWaterMark:0}));
const sharedBytes=await packageUI.evidencePackageReadBytes(sharedResponse,16);assert.deepEqual([...sharedBytes],Array.from({length:16},(_,i)=>i));assert.equal(sharedBytes.buffer.byteLength,16);
for(const width of [0,1,64]) {
  let fragmentedTimeoutCancels=0;
  const fragmentDeadline=packageUI.createEvidencePackageController({getSelection:()=>packageGolden.selection,protocol:'http:',onChange:()=>{},deadline:5,
    fetcher:async()=>new Response(new ReadableStream({pull(stream){stream.enqueue(new Uint8Array(width));},cancel(){fragmentedTimeoutCancels++;return new Promise(()=>{});}}))});
  await packageWithinDeadline(fragmentDeadline.export());assert.equal(fragmentDeadline.model.status,'error');assert.match(fragmentDeadline.model.message,/timed out/);assert.equal(fragmentedTimeoutCancels,1);
}
const packageRequests=[];
let packageSelection=structuredClone(packageGolden.selection);
const packageController=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:async(url,options)=>{
  packageRequests.push({url,options}); return url.endsWith('/export') ? new Response(packageGoldenBytes) : Response.json(packageValid);
}});
await packageController.export();
assert.equal(packageRequests.length,2);
assert.equal(packageRequests[0].url,'/api/evidence/packages/export');
assert.equal(packageRequests[1].url,'/api/evidence/packages/validate');
assert.deepEqual(JSON.parse(new TextDecoder().decode(packageRequests[0].options.body)),{protocol_version:1,profile:'reb-metadata-only-v1',selection:packageSelection});
assert.deepEqual(packageRequests[1].options.body,packageGoldenBytes,'Export validation must preserve exact bytes');
assert.equal(packageController.model.status,'ready');
assert.deepEqual(packageController.model.bytes,packageGoldenBytes);
packageController.clear(); assert.equal(packageController.model.bytes,null);
// Duplicate members, invalid UTF-8, whitespace and BOM survive the client boundary.
for (const bytes of [new TextEncoder().encode('{"format":"a","format":"b"}'),new Uint8Array([0xef,0xbb,0xbf,0x7b,0xff,0x7d]),new TextEncoder().encode('  {"x":1}\n')]) {
  let received;
  const control=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:async(url,options)=>{
    assert.equal(url,'/api/evidence/packages/validate'); received=options.body; return Response.json(packageInvalid);
  }});
  await control.validate({size:bytes.length,arrayBuffer:async()=>bytes.buffer});
  assert.deepEqual(received,bytes,'Never parse or reserialize input before server validation');
  assert.equal(control.model.status,'invalid'); assert.equal(control.model.bytes,null); assert.equal(control.model.document,null);
}
let packagePending=[];
const delayedPackage=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:(url,options)=>new Promise(resolve=>packagePending.push({url,options,resolve}))});
const packageFirst=delayedPackage.export(); await delayedPackage.export(); assert.equal(packagePending.length,1,'Double export starts only one operation');
delayedPackage.cancel(); assert.equal(packagePending[0].options.signal.aborted,true);
packagePending[0].resolve(new Response(packageGoldenBytes)); await packageFirst;
assert.equal(packagePending.length,1,'Cancelled export cannot begin validation'); assert.equal(delayedPackage.model.document,null);
const packageSecond=delayedPackage.export(); packagePending[1].resolve(new Response(packageGoldenBytes));
while(packagePending.length<3) await new Promise(resolve=>setTimeout(resolve,0));
delayedPackage.clear(); packagePending[2].resolve(Response.json(packageValid)); await packageSecond;
assert.equal(delayedPackage.model.bytes,null,'Changed selection/close cannot accept delayed validation');
let packageFileResolve;
const packageSlowFile=delayedPackage.validate({size:packageGoldenBytes.length,arrayBuffer:()=>new Promise(resolve=>{packageFileResolve=resolve;})});
delayedPackage.cancel(); packageFileResolve(packageGoldenBytes.buffer); await packageSlowFile;
assert.equal(packagePending.length,3,'A cancelled file read cannot send a request');
for (const status of [400,404,408,409,413,422,503]) {
  let calls=0;
  const rejected=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:async()=>{calls++;return new Response('{}',{status});}});
  await rejected.export(); assert.equal(calls,1,'Rejected export must not auto-retry or validate'); assert.equal(rejected.model.status,'error'); assert.equal(rejected.model.bytes,null);
  if(status===409) assert.match(rejected.model.message,/No writer was stopped/);
  if(status===503) assert.match(rejected.model.message,/legacy stores are unsupported/);
}
const packageOffline=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'reb:',onChange:()=>{},fetcher:()=>{throw new Error('Offline must not fetch');}});
await packageOffline.export(); assert.equal(packageOffline.model.status,'error');
let oversizedRead=false;
await packageController.validate({size:4194305,arrayBuffer:async()=>{oversizedRead=true;return new ArrayBuffer(0);}});
assert.equal(oversizedRead,false,'File size checked before allocation/read');
const packageWrongSelection=packageUI.createEvidencePackageController({getSelection:()=>({events:packageSelection.events.slice(0,1),artifacts:[]}),protocol:'http:',onChange:()=>{},
  fetcher:async url=>url.endsWith('/export')?new Response(packageGoldenBytes):Response.json(packageValid)});
await packageWrongSelection.export(); assert.equal(packageWrongSelection.model.status,'error'); assert.equal(packageWrongSelection.model.bytes,null);
let packageTimeoutChanges=0;
const packageSlow=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',deadline:5,onChange:()=>packageTimeoutChanges++,
  fetcher:async(_url,{signal})=>new Response(new ReadableStream({start(stream){signal.addEventListener('abort',()=>stream.error(new DOMException('Aborted','AbortError')),{once:true});}}))});
await packageSlow.export(); assert.equal(packageSlow.model.status,'error'); assert.match(packageSlow.model.message,/timed out/); assert.equal(packageSlow.model.bytes,null); assert(packageTimeoutChanges>=2);
console.log('Evidence package exact-byte, selection, bounds and interruption contracts passed');
// Canonical backend JSON sorts object members; identity is order-independent.
const reorderedPackage = structuredClone(packageGolden);
for (const kind of ['events', 'artifacts']) {
  reorderedPackage.selection[kind] = reorderedPackage.selection[kind].map(key => Object.fromEntries(Object.entries(key).sort())).reverse();
}
assert.equal(packageUI.evidencePackageSelectionKey(reorderedPackage.selection), packageUI.evidencePackageSelectionKey(packageGolden.selection));
const orderedBytes = new TextEncoder().encode(JSON.stringify(reorderedPackage));
const orderedControl = packageUI.createEvidencePackageController({getSelection:()=>packageGolden.selection,protocol:'http:',onChange:()=>{},
  fetcher:async url=>url.endsWith('/export')?new Response(orderedBytes):Response.json(packageValid)});
await orderedControl.export(); assert.equal(orderedControl.model.status,'ready'); assert.deepEqual(orderedControl.model.bytes,orderedBytes);
await orderedControl.validate({size:4194305}); assert.equal(orderedControl.model.bytes,null,'An invalid new file cannot leave an older package downloadable');
let selectionReply;
const changingControl = packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},
  fetcher:()=>new Promise(resolve=>{selectionReply=resolve;})});
const changedSelectionRun = changingControl.export(); packageSelection = {events:[],artifacts:[]};
selectionReply(new Response(packageGoldenBytes)); await changedSelectionRun;
assert.equal(changingControl.model.bytes,null); assert.equal(changingControl.model.status,'idle');
packageSelection = structuredClone(packageGolden.selection);
let timeoutFileResolve, timeoutFileCalls = 0;
const timeoutFile = packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',deadline:5,onChange:()=>{},fetcher:()=>{timeoutFileCalls++;}});
const timeoutFileRun = timeoutFile.validate({size:packageGoldenBytes.length,arrayBuffer:()=>new Promise(resolve=>{timeoutFileResolve=resolve;})});
await new Promise(resolve=>setTimeout(resolve,15)); assert.equal(timeoutFile.model.status,'error');
timeoutFileResolve(packageGoldenBytes.buffer); await timeoutFileRun;
assert.equal(timeoutFileCalls,0,'A file read completing after timeout cannot send original bytes');
for (const status of ['invalid','unsupported']) {
  const control=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:async()=>Response.json({...packageInvalid,status})});
  await control.validate({size:packageGoldenBytes.length,arrayBuffer:async()=>packageGoldenBytes.buffer});
  assert.equal(control.model.status,status); assert.equal(control.model.bytes,null);
}
console.log('PASS package canonical-key order, direct stale selection, unsupported response and non-abortable file deadline');

const complete = runInNewContext(
  (await readFile(join(root, "apps/research-ui/source_syntax.js"), "utf8")) +
    (await readFile(join(root, "apps/research-ui/native_console_completion.js"), "utf8")) +
    ";nativeConsoleSuggestions",
);
const suggestions = text => complete(text, text.length)?.items.map(item => item.name) ?? [];
assert.deepEqual(Array.from(suggestions("document.que")), ["querySelector", "querySelectorAll"]);
for (const text of ["document.querySelector", "document.querySelectorAll", "window", "Math.log", "document.body"]) {
  assert.equal(complete(text, text.length), null, text);
  assert.equal(complete(text, text.length, true).items[0].name, text.split(".").at(-1), text);
}
const longerIdentifier = "document.querySelectorAll";
assert.ok(complete(longerIdentifier, "document.querySelector".length).items.some(item => item.name === "querySelector"));
assert.ok(suggestions('window.document.querySelector("main").classList.').includes("toggle"));
assert.ok(suggestions('document.querySelector(document.querySelector("a")).sty').includes("style"));
assert.ok(suggestions("window?.navigator.clipboard.re").includes("readText"));
assert.ok(suggestions("new Map().").includes("get"));
assert.ok(suggestions("[1, 2].ma").includes("map"));
assert.ok(suggestions('"snow 雪".toU').includes("toUpperCase"));
assert.ok(suggestions("Promise.resolve(1).th").includes("then"));
for (const text of ['"document.que', "'document.que", "`document.que", "// document.que", "/* document.que", "/document.que", "const pattern = /document.que", "customPageObject.", "window[pageGetter()]."]) {
  assert.equal(complete(text, text.length), null, text);
}
assert.ok(suggestions("/* inert */ document.que").includes("querySelector"));
assert.ok(suggestions("// inert\nMath.ra").includes("random"));
const middle = complete('"雪"; document.querySelectorAll("main")', 19);
assert.equal(middle.start, 14);
assert.equal(middle.end, 30);
assert.ok(middle.items.some(item => item.name === "querySelector"));
assert.equal(complete("a".repeat(8193), 8193), null);
assert.ok(complete("", 0, true).items.length <= 24);
assert.equal(complete("document.", -1), null);
const completionQuery = runInNewContext(
  (await readFile(join(root, "apps/research-ui/source_syntax.js"), "utf8")) +
  (await readFile(join(root, "apps/research-ui/native_console_completion.js"), "utf8")) +
  ";nativeConsoleCompletionQuery",
);
assert.deepEqual(Array.from(completionQuery("customPageObject.method", 23).path), ["customPageObject"]);
for (const text of ['"customPageObject.', "// obj.", "/* obj.", "/obj.", "const pattern = /obj.", "obj[pageGetter()].", "obj.method()."]) assert.equal(completionQuery(text, text.length), null, text);
assert.equal(completionQuery("a".repeat(8193), 8193), null);
assert.equal(completionQuery("window.", -1), null);
assert.equal(completionQuery("a".repeat(129) + ".", 130), null);
console.log("PASS bounded local console completions, lexical exclusions, property chains and UTF-16 replacement");
const ui = runInNewContext(
  (await readFile(join(root, "apps/research-ui/evidence_models.js"), "utf8")) +
    ";({isBrokerEvent,isWasmInspection})",
  { TextEncoder, URL },
);
// Reject foreign, malformed and unbounded binary listings before rendering them.
const wasmSource = {artifact_id: "1", sha256: "a".repeat(64), byte_size: 32};
const wasmReport = {schema: "wasm-inspection-v1", ...wasmSource, status: "decoded",
  sections: 1, defined_functions: 1, imported_functions: 0, instructions: 1,
  notice: "Static only", omissions: [], rows: [{kind: "instruction", byte_offset: 12,
    byte_end: 14, function_index: 0, text: "i32.const {value: 7}", text_truncated: false}]};
assert.equal(ui.isWasmInspection(wasmReport, wasmSource), true);
for (const patch of [{sha256: "b".repeat(64)}, {artifact_id: "2"}, {byte_size: 33},
  {status: "confirmed"}, {rows: Array(8193).fill(wasmReport.rows[0])},
  {rows: [{...wasmReport.rows[0], byte_end: 33}]},
  {rows: [{...wasmReport.rows[0], byte_offset: -1}]},
  {rows: [{...wasmReport.rows[0], text: "x".repeat(541)}]},
  {rows: [{...wasmReport.rows[0], text: "import e\nv"}]},
  {rows: [{...wasmReport.rows[0], text: "import e\rv"}]},
  {rows: [{...wasmReport.rows[0], text: "import e\u2028v"}]},
  {rows: [{...wasmReport.rows[0], text: "import e\u2029v"}]},
  {omissions: [null]}, {instructions: NaN}]) {
  assert.equal(ui.isWasmInspection({...wasmReport, ...patch}, wasmSource), false);
}
console.log("PASS WASM inspection identity, coordinate and resource bounds");
// A minimal DOM verifies the real reconciliation code and bounded state, not
// pixels. `make rendered-ui-check` is the separate rendered interaction path.
class TrafficFixtureNode {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.attributes = new Map();
    this.listeners = new Map(); this.className = ""; this._text = ""; this.value = ""; this.scrollTop = 0; this.parentNode = null;
    this.classList = {add: name => {if (!this.className.split(" ").includes(name)) this.className += ` ${name}`;},
      remove: name => {this.className = this.className.split(" ").filter(value => value !== name).join(" ");},
      toggle: (name, active) => active ? this.classList.add(name) : this.classList.remove(name),
      contains: name => this.className.split(" ").includes(name)};
  }
  set textContent(value) {this._text = String(value); this.children.forEach(node => {node.parentNode = null;}); this.children = [];}
  get textContent() {return this._text + this.children.map(node => node.textContent).join("");}
  get lastElementChild() {return this.children.at(-1);}
  get offsetTop() {return Math.max(0, this.parentNode?.children.indexOf(this) ?? 0) * 28;}
  get offsetHeight() {return 28;}
  get isConnected() {return true;}
  setAttribute(key, value) {this.attributes.set(key, String(value));}
  getAttribute(key) {return this.attributes.get(key) ?? null;}
  removeAttribute(key) {this.attributes.delete(key);}
  addEventListener(key, callback) {this.listeners.set(key, [...(this.listeners.get(key) ?? []), callback]);}
  append(...nodes) {for (const node of nodes) this.insertBefore(node, null);}
  insertBefore(node, next) {node.remove(); node.parentNode = this; const index = next ? this.children.indexOf(next) : -1; this.children.splice(index < 0 ? this.children.length : index, 0, node);}
  replaceChildren(...nodes) {this._text = ""; this.children.forEach(node => {node.parentNode = null;}); this.children = []; this.append(...nodes);}
  remove() {if (this.parentNode) {if (this.contains(trafficDocument.activeElement)) trafficDocument.activeElement = null; const index = this.parentNode.children.indexOf(this); this.parentNode.children.splice(index, 1); this.parentNode = null;}}
  contains(node) {return node === this || this.children.some(child => child.contains(node));}
  matches(selector) {return selector[0] === "." ? this.classList.contains(selector.slice(1)) : selector === "[aria-pressed]" ? this.attributes.has("aria-pressed") : this.tagName.toLowerCase() === selector;}
  querySelectorAll(selector) {return this.children.flatMap(node => [...(node.matches(selector) ? [node] : []), ...node.querySelectorAll(selector)]);}
  querySelector(selector) {return this.querySelectorAll(selector)[0] ?? null;}
  focus() {trafficDocument.activeElement = this;}
  click() {for (const callback of this.listeners.get("click") ?? []) callback({target: this, currentTarget: this});}
}
const trafficDocument = {activeElement: null, createElement: tag => new TrafficFixtureNode(tag), createTextNode: text => {
  const node = new TrafficFixtureNode("text"); node.textContent = text; return node;
}};
// Minimal DOM tests exercise the actual panel's event listeners and ownership.
// They are not rendered, pointer-hit-test, native WebKit or visual QA.
const packageSource = await readFile(join(root, 'apps/research-ui/evidence_package.js'), 'utf8');
function packagePanelFixture(native = false) {
  let copyResolve, downloadBlob, downloads = 0, copies = 0;
  const packageDocument = {activeElement:null,body:null};
  class PackageNode extends TrafficFixtureNode {
    focus() {packageDocument.activeElement=this;}
    remove() {if(this.parentNode) {if(this.contains(packageDocument.activeElement)) packageDocument.activeElement=null;this.parentNode.children.splice(this.parentNode.children.indexOf(this),1);this.parentNode=null;}}
    replaceChildren(...nodes) {if(this.contains(packageDocument.activeElement)) packageDocument.activeElement=null;super.replaceChildren(...nodes);}
    async emit(type, fields = {}) {await Promise.all((this.listeners.get(type)??[]).map(callback=>callback({target:this,currentTarget:this,...fields})));}
    click() {if(this.tagName==='A') downloads++;return this.emit('click');}
  }
  packageDocument.createElement=tag=>new PackageNode(tag);
  packageDocument.body=new PackageNode('body'); packageDocument.documentElement=new PackageNode('html');
  if(native) packageDocument.documentElement.classList.add('native-shell');
  const names=['scope','candidates','selection','selected','notice','report','file','export','validate','cancel','download','copy','save-note','page','previous','next','clear','context'];
  const host=new PackageNode('section');
  const nodes=Object.fromEntries(names.map(name=>[name,new PackageNode(name==='scope'?'select':name==='file'?'input':'div')]));
  host.append(...Object.values(nodes)); packageDocument.body.append(host);
  host.querySelector=selector=>nodes[/^\[data-package-(.+)\]$/.exec(selector)?.[1]];
  packageDocument.querySelector=()=>host; nodes.scope.value='request'; nodes.scope.selectedOptions=[{textContent:'Selected request native events'}]; nodes.file.files=[];
  let context={requestId:'fixture',events:packageGolden.records.events.map(row=>({...row,...row.key})),artifacts:packageGolden.records.artifacts.map(row=>({...row,...row.key})),eventsLimited:false};
  context.requestEvents=context.events;
  let pending = null;
  const calls=[];
  const fetcher=async(url,options)=>{calls.push({url,options});if(pending) return new Promise(resolve=>pending.push({resolve,options}));return url.endsWith('/export')?new Response(packageGoldenBytes):Response.json(packageValid);};
  const create = runInNewContext(packageSource+';createEvidencePackagePanel', {document:packageDocument,location:{protocol:'http:'},fetch:fetcher,
    TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout,clearTimeout,Blob,
    URL:{createObjectURL:blob=>{downloadBlob=blob;return 'blob:synthetic';},revokeObjectURL(){}},
    navigator:{clipboard:{writeText:()=>{copies++;return new Promise(resolve=>{copyResolve=resolve;});}}}});
  const panel=create({getContext:()=>context}); panel.setVisible(true);
  return {panel,nodes,host,document:packageDocument,calls,get context(){return context;},set context(value){context=value;},
    defer(){pending=[];return pending;},resume(){pending=null;},resolveCopy(){copyResolve();},get copies(){return copies;},get downloads(){return downloads;},get blob(){return downloadBlob;}};
}
const panel = packagePanelFixture();
const choosePackageRow = async (fixture,index=0,checked=true) => {const input=fixture.nodes.candidates.querySelectorAll('input')[index];input.checked=checked;await input.emit('change');return input;};
for(let index=0;index<4;index++) await choosePackageRow(panel,index);
panel.nodes.scope.value='artifacts'; await panel.nodes.scope.emit('change');
for(let index=0;index<2;index++) await choosePackageRow(panel,index);
await panel.nodes.export.emit('click');
assert.equal(panel.panel.controller.model.status,'ready'); assert.equal(panel.downloads,0); assert.equal(panel.copies,0,'Validation must never copy automatically');
assert.match(panel.nodes.report.textContent,/Authenticity.*not established/); assert.match(panel.nodes.report.textContent,/Unknown historical facts/);
assert.match(panel.nodes.report.textContent,/markers.*overlap/i); assert.match(panel.nodes.report.textContent,/time 10 ns/);
await panel.nodes.download.emit('click'); assert.equal(panel.downloads,1); assert.deepEqual(new Uint8Array(await panel.blob.arrayBuffer()),packageGoldenBytes);
const staleCopy=panel.nodes.copy.emit('click'); assert.equal(panel.copies,1); await panel.nodes.clear.emit('click');
const clearedNotice=panel.nodes.notice.textContent;panel.resolveCopy();await staleCopy;assert.equal(panel.nodes.notice.textContent,clearedNotice);
// Repeated clipboard actions share the active explicit write, and leaving/reopening retires its notice.
await panel.panel.controller.validate({size:packageGoldenBytes.length,arrayBuffer:async()=>packageGoldenBytes.buffer});
const copy=panel.nodes.copy.emit('click');await panel.nodes.copy.emit('click');assert.equal(panel.copies,2);
panel.panel.setVisible(false);panel.panel.setVisible(true);const reopenedNotice=panel.nodes.notice.textContent;panel.resolveCopy();await copy;
assert.equal(panel.nodes.notice.textContent,reopenedNotice);
const nativePanel=packagePanelFixture(true);
await nativePanel.panel.controller.validate({size:packageGoldenBytes.length,arrayBuffer:async()=>packageGoldenBytes.buffer});
assert.equal(nativePanel.nodes.download.disabled,true);assert.match(nativePanel.nodes['save-note'].textContent,/Download is unavailable in the native app/);
await nativePanel.nodes.download.emit('click');assert.equal(nativePanel.downloads,0);assert.equal(nativePanel.nodes.copy.disabled,false);
const nativeCopy=nativePanel.nodes.copy.emit('click');nativePanel.resolveCopy();await nativeCopy;assert.match(nativePanel.nodes.notice.textContent,/copied/);
// The focused identity and scroll survive an artifact-only catalog refresh.
panel.nodes.scope.value='artifacts';await panel.nodes.scope.emit('change');
const focused=await choosePackageRow(panel,0);focused.focus();panel.nodes.candidates.scrollTop=42;
panel.context={...panel.context,artifacts:[...panel.context.artifacts,{...panel.context.artifacts[0],artifact_id:'10'}]};panel.panel.sync();
assert.equal(panel.document.activeElement.dataset.packageKey,focused.dataset.packageKey);assert.equal(panel.nodes.candidates.scrollTop,42);
const selectedDisclosure=panel.nodes.selected.children[0];selectedDisclosure.open=true;panel.panel.sync();assert.equal(panel.nodes.selected.children[0],selectedDisclosure);
panel.context={...panel.context,artifacts:[]};panel.panel.sync();assert.equal(panel.nodes.candidates.children.length,0);
assert.equal(panel.document.activeElement,panel.nodes.candidates);assert.match(panel.nodes.selected.textContent,/session 7 \/ artifact 9/,'Eviction keeps exact selection visible');
// Late export and validation cannot win after Escape, another request, or leaving the screen.
panel.nodes.scope.value='request';await panel.nodes.scope.emit('change');await choosePackageRow(panel,0);
let pending=panel.defer();const escaped=panel.nodes.export.emit('click');assert.equal(pending.length,1);assert.equal(panel.document.activeElement,panel.nodes.cancel);
await panel.host.emit('keydown',{key:'Escape',preventDefault(){},stopPropagation(){}});assert.equal(pending[0].options.signal.aborted,true);
pending[0].resolve(new Response(packageGoldenBytes));await escaped;assert.equal(panel.panel.controller.model.status,'cancelled');
const switched=panel.nodes.export.emit('click');assert.equal(pending.length,2);panel.context={...panel.context,requestId:'other'};panel.panel.sync();
pending[1].resolve(new Response(packageGoldenBytes));await switched;assert.equal(panel.panel.controller.model.bytes,null);assert.match(panel.nodes.selection.textContent,/0 \/ 1,024/);
await choosePackageRow(panel,0);const leaving=panel.nodes.export.emit('click');panel.panel.setVisible(false);pending[2].resolve(new Response(packageGoldenBytes));await leaving;
assert.equal(panel.panel.controller.model.bytes,null);panel.panel.setVisible(true);panel.resume();
// Candidate mounting is bounded, paging never selects new rows, and the artifact cap holds across pages.
panel.context={...panel.context,artifacts:Array.from({length:65},(_,index)=>({...packageGolden.records.artifacts[0],session_id:'7',artifact_id:String(index+1)}))};
panel.nodes.scope.value='artifacts';await panel.nodes.scope.emit('change');assert.equal(panel.nodes.candidates.children.length,50);
await panel.nodes.clear.emit('click');for(let index=0;index<50;index++) await choosePackageRow(panel,index);
await panel.nodes.next.emit('click');assert.equal(panel.nodes.candidates.children.length,15);for(let index=0;index<15;index++) await choosePackageRow(panel,index);
assert.match(panel.nodes.selection.textContent,/64 \/ 64/);assert.equal(panel.nodes.candidates.querySelectorAll('input')[14].checked,false);assert.match(panel.nodes.notice.textContent,/Selection limit/);
assert.equal(panel.nodes.selected.children[0].querySelectorAll('li').length,50);
await panel.nodes.clear.emit('click');
panel.context={...panel.context,requestEvents:Array.from({length:1025},(_,index)=>({...packageGolden.records.events[0],session_id:'7',process_id:42,sequence_number:String(index+1)}))};
panel.nodes.scope.value='request';await panel.nodes.scope.emit('change');
for(let page=0;page<21;page++) {
  assert(panel.nodes.candidates.children.length<=50);
  for(let index=0;index<panel.nodes.candidates.children.length;index++) await choosePackageRow(panel,index);
  if(page<20) await panel.nodes.next.emit('click');
}
assert.match(panel.nodes.selection.textContent,/1024 \/ 1,024/);assert.equal(panel.nodes.candidates.querySelectorAll('input')[24].checked,false);
console.log('PASS package panel explicit actions, exact download bytes, native fallback, clipboard ownership, keyed refresh focus, eviction, caps, paging, Escape/navigation and stale selection (DOM fixture; not rendered QA)');

const trafficSource = await readFile(join(root, "apps/research-ui/traffic_view.js"), "utf8");
const trafficUI = runInNewContext(trafficSource + ";({trafficSortedRequests,trafficWindow,renderTrafficRows,renderTrafficDetails,trafficPaneSignature,trafficTableTypeLabel,TRAFFIC_ROW_LIMIT})", {
  document: trafficDocument, URL, TextEncoder, TextDecoder, Uint8Array, queueMicrotask,
  navigator: {clipboard: {writeText: async () => {}}}, setTimeout: () => 0,
  createSourceTokenizer: () => ({}), sourceSyntaxTokens: text => [{type: "plain", text}],
});
const uiRequest = (id, patch = {}) => ({id, path: `https://fixture.invalid/${id}`, method: "GET", status: "pending",
  time: "pending", type: "xhr", origin: "live", tabId: "fixture-tab", operation: "request_started", events: [],
  exchange: {request: {state: "empty", headers: []}, response: {state: "loading", headers: []}}, ...patch});
const retainedTraffic = Array.from({length: 5000}, (_, index) => uiRequest(String(index), {time: index % 20}));
assert.equal(trafficUI.TRAFFIC_ROW_LIMIT, 500);
for (const type of ["constructor", "__proto__", null]) assert.equal(trafficUI.trafficTableTypeLabel(type), "Other");
assert.equal(trafficUI.trafficWindow(retainedTraffic, 0).rows.length, 500);
assert.equal(trafficUI.trafficWindow(retainedTraffic, 5000).start, 4500);
assert.equal(trafficUI.trafficWindow(retainedTraffic.slice(30), 300, "300").start, 270);
for (const direction of [1, -1]) {
  const sorted = trafficUI.trafficSortedRequests(retainedTraffic, "time", direction);
  assert.equal(sorted[0].time, direction === 1 ? 0 : 19);
  assert.equal(sorted[0].id, direction === 1 ? "0" : "19");
}
assert.equal(trafficUI.trafficSortedRequests([uiRequest("pending"), uiRequest("done", {time: 2})], "time", -1)[0].id, "done");
assert.deepEqual(Array.from(trafficUI.trafficSortedRequests([uiRequest("native", {time: "12.300 ms"}), uiRequest("cdp", {time: 2})], "time"), request => request.id), ["cdp", "native"]);
// Supplied-package comparison is secondary, explicit, bounded and read-only.
const comparisonResult = JSON.parse(await readFile(join(root,'apps/origin-trace-backend/assets/evidence-packages/comparison-equal-v1.json'),'utf8'));
const comparisonChangedInput = new Uint8Array(await readFile(join(root,'apps/origin-trace-backend/assets/evidence-packages/comparison-changed-input-v1.json')));
const comparisonChangedResult = JSON.parse(await readFile(join(root,'apps/origin-trace-backend/assets/evidence-packages/comparison-changed-result-v1.json'),'utf8'));
const comparisonSource = await readFile(join(root,'apps/research-ui/evidence_comparison.js'),'utf8');
const comparisonUI = runInNewContext(packageSource+'\n'+comparisonSource+'\nRebEvidenceComparison', {TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout,clearTimeout,fetch});
const comparisonFile = raw => { const bytes = new TextEncoder().encode(raw);return {size:bytes.length,arrayBuffer:async()=>bytes.buffer}; };
const comparisonOriginal = JSON.stringify(packageGolden);
let comparisonReply = () => Response.json(comparisonResult), comparisonCalls = [];
const comparisonController = comparisonUI.createController({fetcher:async(url,options)=>{comparisonCalls.push({url,options});return comparisonReply();}});
comparisonController.select(0,comparisonFile(comparisonOriginal)); comparisonController.select(1,comparisonFile(comparisonOriginal));
assert.equal(comparisonCalls.length,0,'Choosing local files must not dispatch');
assert(await comparisonController.compare()); assert.equal(comparisonCalls.length,1);
assert.equal(comparisonCalls[0].url,'/api/evidence/packages/compare');assert.equal(comparisonController.model.result.selected_metadata_equal,true);
const previousComparison=comparisonController.model.result;comparisonReply=()=>Response.json({error:'PRIVATE_CANARY'},{status:400});
assert.equal(await comparisonController.compare(),false);assert.equal(comparisonController.model.result,previousComparison);assert(!comparisonController.model.message.includes('PRIVATE_CANARY'));
comparisonReply=()=>Response.json({error:'PRIVATE_CANARY',code:'resource_limit'},{status:503});assert.equal(await comparisonController.compare(),false);assert.match(comparisonController.model.message,/busy or unavailable/);assert.equal(comparisonController.model.result,previousComparison);assert(!comparisonController.model.message.includes('PRIVATE_CANARY'));
comparisonController.select(0,comparisonFile(comparisonOriginal.replace('"process_id":42','"process_id":42,"process_id":42')));
await comparisonController.compare();assert.match(comparisonCalls.at(-1).options.body,/"process_id":42,"process_id":42/,'Original duplicate members reach strict service unchanged');
comparisonController.select(0,{size:4194305,arrayBuffer(){throw new Error('Oversized file read');}});const noReadCalls=comparisonCalls.length;await comparisonController.compare();assert.equal(comparisonCalls.length,noReadCalls);
comparisonController.select(0,{size:1,arrayBuffer:async()=>new Uint8Array([255]).buffer});await comparisonController.compare();assert.equal(comparisonCalls.length,noReadCalls,'Invalid UTF-8 never dispatches');
let finishComparisonFile;comparisonController.select(0,{size:1,arrayBuffer:()=>new Promise(resolve=>{finishComparisonFile=resolve;})});
const cancelledComparison=comparisonController.compare();comparisonController.close();assert.equal(await cancelledComparison,false);finishComparisonFile(new Uint8Array([123]).buffer);await Promise.resolve();assert.equal(comparisonCalls.length,noReadCalls,'Retired file read cannot dispatch');
let finishComparisonReply;comparisonReply=()=>new Promise(resolve=>{finishComparisonReply=resolve;});comparisonController.select(0,comparisonFile(comparisonOriginal));
const lateComparison=comparisonController.compare();while(!finishComparisonReply) await new Promise(resolve=>setTimeout(resolve,0));
await comparisonController.compare();assert.equal(comparisonCalls.length,noReadCalls+1,'Repeated Compare does not replay');
comparisonController.clear();assert.equal(await lateComparison,false);finishComparisonReply(Response.json(comparisonResult));await new Promise(resolve=>setTimeout(resolve,0));assert.equal(comparisonController.model.result,null);
comparisonReply=()=>Response.json({...comparisonResult,right_package_id:'reb-package-v1:sha256:'+'0'.repeat(64)});
comparisonController.select(0,comparisonFile(comparisonOriginal));comparisonController.select(1,comparisonFile(comparisonOriginal));assert.equal(await comparisonController.compare(),false);assert.equal(comparisonController.model.result,null,'Wrong input identity cannot populate results');
comparisonReply=()=>new Response(new Uint8Array(524289));assert.equal(await comparisonController.compare(),false);assert.equal(comparisonController.model.result,null);
comparisonController.dispose();
let comparisonLateDeadline;
const comparisonDeadline=comparisonUI.createController({deadline:10,fetcher:()=>new Promise(resolve=>{comparisonLateDeadline=resolve;})});
comparisonDeadline.select(0,comparisonFile(comparisonOriginal));comparisonDeadline.select(1,comparisonFile(comparisonOriginal));
let comparisonWatchdog;
try {assert.equal(await Promise.race([comparisonDeadline.compare(),new Promise((_,reject)=>{comparisonWatchdog=setTimeout(()=>reject(new Error('Comparison deadline failed to settle')),2000);})]),false);}finally{clearTimeout(comparisonWatchdog);}
assert.equal(comparisonDeadline.model.busy,false);assert.match(comparisonDeadline.model.message,/timed out/);assert.equal(comparisonDeadline.model.result,null);comparisonLateDeadline(Response.json(comparisonResult));await new Promise(resolve=>setTimeout(resolve,0));assert.equal(comparisonDeadline.model.result,null);comparisonDeadline.dispose();

// Actual mount/event listeners use a small DOM. This is not rendered UI proof.
class ComparisonNode extends TrafficFixtureNode {
  async emit(type){await Promise.all((this.listeners.get(type)||[]).map(fn=>fn({target:this})));}
  removeEventListener(type,fn){this.listeners.set(type,(this.listeners.get(type)||[]).filter(v=>v!==fn));}
}
const comparisonDocument={createElement:tag=>new ComparisonNode(tag)};const comparisonHost=new ComparisonNode('section');comparisonHost.ownerDocument=comparisonDocument;
const comparisonMounted=comparisonUI.mount(comparisonHost,{fetcher:async()=>Response.json(comparisonResult)});
assert.equal(comparisonUI.mount(comparisonHost),comparisonMounted,'Mount is idempotent');
const comparisonInputs=comparisonHost.querySelectorAll('input');comparisonInputs.forEach(input=>{input.files=[comparisonFile(comparisonOriginal)];});for(const input of comparisonInputs) await input.emit('change');
await comparisonHost.querySelectorAll('button')[0].emit('click');assert.match(comparisonHost.textContent,/11 equal/);assert.match(comparisonHost.textContent,/unknown or partial capture/i);assert.match(comparisonHost.textContent,/Raw bytes were not reverified/);
assert.equal(comparisonHost.querySelectorAll('li').length,11);comparisonMounted.close();assert.equal(comparisonMounted.controller.model.result.comparison_id,comparisonResult.comparison_id);
comparisonMounted.dispose();assert.equal(comparisonHost.children.length,0);assert.equal(comparisonHost.rebEvidenceComparison,undefined);
console.log('PASS secondary comparison originals, UTF-8, size bounds, explicit dispatch, duplicate preservation, stable identities, retained failures, repeated clicks, cancellation, late replies and mount/dispose');

// Review regressions: malformed successful replies must preserve the last result.
const differentPackageId='reb-package-v1:sha256:'+'1'.repeat(64);
const distinctComparison=structuredClone(comparisonResult);
distinctComparison.right_package_id=differentPackageId;distinctComparison.package_metadata_equal=false;
for(const row of distinctComparison.rows)if(row.right)row.right.package_id=differentPackageId;
assert(comparisonUI.validResult(distinctComparison,0,comparisonResult.left_package_id,differentPackageId));
const changedComparison=structuredClone(distinctComparison);
changedComparison.rows[0].status='changed_declared_metadata';changedComparison.rows[0].differences=[{field:'kind',left:{kind:'scalar',value:'javascript'},right:{kind:'scalar',value:'wasm'}}];
changedComparison.counts.equal_declared_metadata--;changedComparison.counts.changed_declared_metadata++;changedComparison.selected_metadata_equal=false;
assert(comparisonUI.validResult(changedComparison,0,comparisonResult.left_package_id,differentPackageId),'Changed descriptors may retain matching declared hashes');
const corruptComparisons=[];
for(const wrap of [id=>[id],id=>({value:id}),()=>null,()=>17,()=>true,id=>id+'\n']){
  const comparison=structuredClone(comparisonResult);comparison.comparison_id=wrap(comparison.comparison_id);corruptComparisons.push(comparison);
  const row=structuredClone(comparisonResult);row.rows[0].row_id=wrap(row.rows[0].row_id);corruptComparisons.push(row);
}
const duplicateArrayIds=structuredClone(comparisonResult);duplicateArrayIds.comparison_id=[duplicateArrayIds.comparison_id];duplicateArrayIds.rows[0].row_id=[duplicateArrayIds.rows[0].row_id];duplicateArrayIds.rows[1]=structuredClone(duplicateArrayIds.rows[0]);corruptComparisons.push(duplicateArrayIds);
const duplicateStringIds=structuredClone(comparisonResult);duplicateStringIds.rows[1].row_id=duplicateStringIds.rows[0].row_id;corruptComparisons.push(duplicateStringIds);
const countsContradiction=structuredClone(comparisonResult);countsContradiction.rows[0].status='changed_declared_metadata';countsContradiction.rows[0].differences=[{field:'byte_size',left:{kind:'scalar',value:'0'},right:{kind:'scalar',value:'1'}}];countsContradiction.rows[0].declared_content_hash_match=false;corruptComparisons.push(countsContradiction);
const equalityContradiction=structuredClone(comparisonResult);equalityContradiction.package_metadata_equal=false;corruptComparisons.push(equalityContradiction);
const hashContradiction=structuredClone(comparisonResult);hashContradiction.rows[0].declared_content_hash_match=false;corruptComparisons.push(hashContradiction);
let repairReply=comparisonResult;
const repairController=comparisonUI.createController({fetcher:async()=>Response.json(repairReply)});
repairController.select(0,comparisonFile(comparisonOriginal));repairController.select(1,comparisonFile(comparisonOriginal));assert(await repairController.compare());const retainedRepairResult=repairController.model.result;
for(const malformed of corruptComparisons){assert.equal(comparisonUI.validResult(malformed,0,comparisonResult.left_package_id,comparisonResult.right_package_id),false);repairReply=malformed;assert.equal(await repairController.compare(),false);assert.equal(repairController.model.result,retainedRepairResult,'Malformed success must not replace retained evidence');}
assert.equal(comparisonUI.validResult(comparisonResult,0,[comparisonResult.left_package_id],comparisonResult.right_package_id),false);
repairController.dispose();
// Counts are global; partial-page counts may be smaller, never greater.
const partialComparison=structuredClone(changedComparison);partialComparison.page={offset:50,limit:50,total:61,next_offset:null};partialComparison.counts.equal_declared_metadata+=50;
assert(comparisonUI.validResult(partialComparison,50,comparisonResult.left_package_id,differentPackageId));
for(const full of [false,true]){
 const mismatch=structuredClone(full?changedComparison:partialComparison);mismatch.counts.equal_declared_metadata++;mismatch.counts.changed_declared_metadata--;mismatch.selected_metadata_equal=true;
 assert.equal(comparisonUI.validResult(mismatch,mismatch.page.offset,comparisonResult.left_package_id,differentPackageId),false,'Visible changed row cannot coexist with global zero changed rows');
}
// This mock supplies a backend-validated result for distinct package IDs; the
// client must check reply consistency without implementing package validation.
let countReply=distinctComparison;
const countController=comparisonUI.createController({fetcher:async()=>Response.json(countReply)});
countController.select(0,comparisonFile(comparisonOriginal));countController.select(1,comparisonFile(JSON.stringify({...packageGolden,package_id:differentPackageId})));
assert(await countController.compare());const retainedCounts=countController.model.result;
for(const full of [false,true]){
 countReply=structuredClone(full?changedComparison:partialComparison);countReply.counts.equal_declared_metadata++;countReply.counts.changed_declared_metadata--;countReply.selected_metadata_equal=true;
 assert.equal(await countController.compare(countReply.page.offset),false);assert.equal(countController.model.result,retainedCounts,'Page/count contradiction must preserve the previous page');
}
countController.dispose();
const ambiguityComparison=structuredClone(distinctComparison);
for(const index of [0,1]){const row=ambiguityComparison.rows[index];row.left=null;row.status='right_only';row.alignment=index===0?'ambiguous_cross_scope':'unmatched';row.cross_scope_candidates=index===0?1:0;row.declared_content_hash_match=null;}
Object.assign(ambiguityComparison.counts,{equal_declared_metadata:9,right_only:2,ambiguous_cross_scope:1});ambiguityComparison.selected_metadata_equal=false;
assert(comparisonUI.validResult(ambiguityComparison,0,comparisonResult.left_package_id,differentPackageId));
ambiguityComparison.counts.ambiguous_cross_scope=2;assert.equal(comparisonUI.validResult(ambiguityComparison,0,comparisonResult.left_package_id,differentPackageId),false,'Full-page ambiguity count must be exact');
const wrongHash=structuredClone(changedComparison);wrongHash.rows[0].differences[0]={field:'byte_size',left:{kind:'scalar',value:'0'},right:{kind:'scalar',value:'1'}};assert.equal(comparisonUI.validResult(wrongHash,0,comparisonResult.left_package_id,differentPackageId),false);
wrongHash.rows[0].declared_content_hash_match=false;assert(comparisonUI.validResult(wrongHash,0,comparisonResult.left_package_id,differentPackageId));
const fakeEqualScalars=structuredClone(changedComparison);fakeEqualScalars.rows[0].differences[0].right.value='javascript';assert.equal(comparisonUI.validResult(fakeEqualScalars,0,comparisonResult.left_package_id,differentPackageId),false);
// A file that settles after its deadline cannot advance to more reads or fetch.
for(const side of [0,1]){
 let finishFile,requests=0,leftReads=0,rightReads=0;
 const c=comparisonUI.createController({deadline:5,fetcher:async()=>{requests++;return Response.json(comparisonResult);}});
 c.select(0,{size:packageGoldenBytes.length,arrayBuffer:()=>{leftReads++;return side===0?new Promise(resolve=>{finishFile=resolve;}):Promise.resolve(packageGoldenBytes.buffer);}});
 c.select(1,{size:packageGoldenBytes.length,arrayBuffer:()=>{rightReads++;return side===1?new Promise(resolve=>{finishFile=resolve;}):Promise.resolve(packageGoldenBytes.buffer);}});
 assert.equal(await c.compare(),false);assert.match(c.model.message,/timed out/);finishFile(packageGoldenBytes.buffer);await new Promise(resolve=>setTimeout(resolve,0));
 assert.equal(requests,0);assert.equal(leftReads,1);assert.equal(rightReads,side===0?0:1);assert.equal(c.model.result,null);c.dispose();
}
// A previously disposed handle has no authority over a replacement mount.
let finishRemount;const remounted=comparisonUI.mount(comparisonHost,{fetcher:()=>new Promise(resolve=>{finishRemount=resolve;})});
remounted.controller.select(0,comparisonFile(comparisonOriginal));remounted.controller.select(1,comparisonFile(comparisonOriginal));const remountWork=remounted.controller.compare();while(!finishRemount)await new Promise(resolve=>setTimeout(resolve,0));
const mountedChildren=[...comparisonHost.children];comparisonMounted.dispose();assert.equal(comparisonHost.rebEvidenceComparison,remounted);assert.deepEqual(comparisonHost.children,mountedChildren);assert.equal(remounted.controller.model.busy,true);
finishRemount(Response.json(comparisonResult));assert(await remountWork);remounted.dispose();remounted.dispose();assert.equal(comparisonHost.children.length,0);
console.log('PASS comparison review repairs: strict string/unique IDs, package/hash/page/count consistency, rejected-success retention, stale dispose ownership, and no post-timeout file/fetch work');

const ledger = new TrafficFixtureNode();
const rowOptions = {selectedId: "3", newIds: new Set(["3"]), onSelect() {}, onKey() {}};
trafficUI.renderTrafficRows(ledger, retainedTraffic.slice(0, 500), rowOptions);
assert.equal(ledger.children[0].children[1].textContent, "Pending");
assert.equal(ledger.children[0].children[2].textContent, "XHR/F");
assert.equal(ledger.children[0].children[2].title, "Fetch/XHR");
const selectedRow = ledger.children[3];
selectedRow.focus(); ledger.scrollTop = 84;
assert(selectedRow.classList.contains("is-new"));
for (const callback of selectedRow.listeners.get("animationend")) callback();
const pendingName = selectedRow.children[0];
trafficUI.renderTrafficRows(ledger, retainedTraffic.slice(0, 500), rowOptions);
assert.equal(ledger.children[3], selectedRow);
assert.equal(selectedRow.children[0], pendingName);
assert(!selectedRow.classList.contains("is-new"));
for (const patch of [{status: 200, time: 4}, {status: 503, failed: true, time: 6}]) {
  const changed = retainedTraffic.slice(0, 500); changed[3] = {...changed[3], ...patch};
  trafficUI.renderTrafficRows(ledger, changed, rowOptions);
  assert.equal(ledger.children[3], selectedRow);
  assert.equal(trafficDocument.activeElement, selectedRow);
  assert.equal(ledger.scrollTop, 84);
  assert(!selectedRow.classList.contains("is-new"));
}
assert.equal(selectedRow.children[1].textContent, "Failed");
trafficUI.renderTrafficRows(ledger, retainedTraffic.slice(1, 501), rowOptions);
assert.equal(ledger.children[2], selectedRow);
assert.equal(ledger.scrollTop, 56, "Retained-window eviction preserves the first visible row anchor");
assert.equal(trafficDocument.activeElement, selectedRow);
trafficUI.renderTrafficRows(ledger, retainedTraffic.slice(4, 504), rowOptions);
assert.equal(trafficDocument.activeElement, ledger.children[0]);
assert.equal(ledger.children.length, 500);
const details = new TrafficFixtureNode();
let selectedTraffic = uiRequest("inspect", {exchange: {request: {state: "empty", headers: []}, response: {state: "available", mime: "text/plain", text: "first", headers: [["x-version", "one"]]}}});
trafficUI.renderTrafficDetails(details, selectedTraffic, "response", () => {}, () => {});
const responsePane = details.querySelector(".exchange-pane");
const responseViewer = responsePane.querySelector(".exchange-content");
const responseSearch = responsePane.querySelector(".exchange-search");
responseSearch.focus(); responseViewer.scrollTop = 28;
selectedTraffic = {...selectedTraffic, exchange: {...selectedTraffic.exchange, response: {...selectedTraffic.exchange.response, text: "other"}}};
trafficUI.renderTrafficDetails(details, selectedTraffic, "response", () => {}, () => {});
await Promise.resolve();
assert.equal(details.querySelector(".exchange-pane"), responsePane);
assert.match(responseViewer.textContent, /other/);
assert.equal(responseViewer.scrollTop, 28);
assert.equal(trafficDocument.activeElement, responseSearch);
trafficUI.renderTrafficDetails(details, selectedTraffic, "headers", () => {}, () => {});
assert.match(details.textContent, /x-versionone/);
selectedTraffic.exchange.response.headers = [["x-version", "two"]];
trafficUI.renderTrafficDetails(details, selectedTraffic, "headers", () => {}, () => {});
assert.match(details.textContent, /x-versiontwo/);
for (const [state, expected] of [["loading", /Loading response/], ["error", /could not be loaded/], ["empty", /No response body/], ["missing", /not captured/], ["redacted", /redacted/]]) {
  selectedTraffic.exchange.response = {state, headers: []};
  trafficUI.renderTrafficDetails(details, selectedTraffic, "response", () => {}, () => {});
  assert.match(details.textContent, expected);
}
selectedTraffic.exchange.response = {state: "available", mime: "application/json", text: "{malformed", headers: []};
trafficUI.renderTrafficDetails(details, selectedTraffic, "preview", () => {}, () => {});
assert.match(details.textContent, /Invalid JSON/);
assert.match(details.textContent, /malformed/);
trafficUI.renderTrafficDetails(details, null, "headers", () => {}, () => {}, null, "Selected request left the retained window.");
assert.match(details.textContent, /left the retained window/);
console.log("PASS Traffic 500-row paging, sorting, anchored eviction, stable lifecycle focus, one-shot arrivals, equal-length body/header updates, and explicit capture states (DOM fixture; not rendered QA)");

// Run the actual source load/refresh lifecycle with rendering and transport
// stubbed. This verifies retention and races, not browser interaction or pixels.
const appSource = await readFile(join(root, "apps/research-ui/app.js"), "utf8");
function appSection(start, end) {
  const offset = appSource.indexOf(start);
  const boundary = appSource.indexOf(end, offset);
  assert(offset >= 0 && boundary > offset, `Missing fixture boundary: ${start}`);
  return appSource.slice(offset, boundary);
}

// Request profiles belong to an exact retained request, even while headers or
// JSON bodies are pending. Exercise production selection, validation and commit.
const signalProfileSource = (await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8')) +
  appSection('      function requestSignalRoot(', '      function signalEventKey(') +
  appSection('      function requestSignalProfileSelection(', '      function renderFields(') +
  ';({refresh:refreshRequestSignalProfile,selection:requestSignalProfileSelection,validate:isRequestSignalProfile})';
function signalProfileFixture() {
  const requests = [1, 2].map(id => ({id:`r${id}`, origin:'live', events:[{
    session_id:'11', request_id:String(id), process_id:17, sequence_number:String(id), type:'request_started'
  }]}));
  const state = {requests, selectedRequestId:'r1', signalProfileGeneration:0, inspectorTab:'signals',
    signalProfile:null, signalProfileKey:null, signalProfileEtag:null, signalProfileStatus:'idle', signalProfileError:null};
  const calls = [], renders = [], location = {protocol:'http:'};
  const fixture = {state, calls, renders, location, reply:() => signalProfileResponse(signalProfileBody(1))};
  Object.assign(fixture, runInNewContext(signalProfileSource, {
    state, location, URLSearchParams, TextDecoder,
    document:{querySelector:() => ({hidden:false})},
    renderInspector:() => renders.push('inspector'), renderFingerprintActivity:() => renders.push('fingerprinting'),
    fetch:(url, options) => {calls.push({url, options}); return fixture.reply();}
  }));
  return fixture;
}
function signalProfileBody(id, category = id === 1 ? 'canvas' : 'webgl') {
  return {protocol_version:1, document_kind:'request-signal-profile', session_id:'11', request_id:String(id),
    root_event:{process_id:17, sequence_number:String(id)}, initiator_event:null, navigation_id:'1', frame_id:'1',
    signals:[{category, relation:'parent_chain', confidence:'observed', event_count:'1',
      first_event:{process_id:17, sequence_number:'7'}, last_event:{process_id:17, sequence_number:'7'}}],
    coverage:{parent_depth:1, parent_depth_limit:32, copied_from_initiator:false, retention_truncated:false,
      parent_depth_limited:false, count_saturated:false}};
}
function signalProfileResponse(body, status = 200, etag = 'profile-etag') {
  return {status, ok:status === 200, headers:{get:() => etag}, json:async () => body};
}
function signalProfileDeferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {resolve = yes; reject = no;});
  return {promise, resolve, reject};
}
for (const sameRequest of [false, true]) {
  for (const outcome of ['valid', 'malformed', 'rejected']) {
    const fixture = signalProfileFixture(), held = signalProfileDeferred(), reading = signalProfileDeferred();
    fixture.reply = () => ({...signalProfileResponse(null), json:() => {reading.resolve(); return held.promise;}});
    const pending = fixture.refresh(); await reading.promise;
    const next = signalProfileBody(sameRequest ? 1 : 2, 'webgl');
    fixture.state.selectedRequestId = sameRequest ? 'r1' : 'r2';
    fixture.reply = () => signalProfileResponse(next, 200, 'new-etag');
    await fixture.refresh();
    const renders = fixture.renders.length, key = fixture.state.signalProfileKey;
    if (outcome === 'rejected') held.reject(new Error('Old JSON read failed'));
    else held.resolve(outcome === 'valid' ? signalProfileBody(1) : {});
    await pending;
    assert.equal(fixture.state.signalProfile, next, 'A superseded JSON body cannot replace current request evidence');
    assert.equal(fixture.state.signalProfileStatus, 'ready');
    assert.equal(fixture.state.signalProfileError, null);
    assert.equal(fixture.state.signalProfileEtag, 'new-etag');
    assert.equal(fixture.state.signalProfileKey, key);
    assert.equal(fixture.renders.length, renders, 'Superseded completion does not render');
  }
}
for (const status of [200, 304, 404, 500, 'rejected']) {
  const fixture = signalProfileFixture(), held = signalProfileDeferred();
  fixture.reply = () => held.promise;
  const pending = fixture.refresh(); fixture.state.selectedRequestId = 'r2';
  const next = signalProfileBody(2); fixture.reply = () => signalProfileResponse(next);
  await fixture.refresh(); const renders = fixture.renders.length;
  if (status === 'rejected') held.reject(new Error('Old fetch failed'));
  else held.resolve(signalProfileResponse(signalProfileBody(1), status));
  await pending;
  assert.equal(fixture.state.signalProfile, next); assert.equal(fixture.state.signalProfileStatus, 'ready');
  assert.equal(fixture.renders.length, renders);
}
for (const phase of ['headers', 'body', 'failure']) {
  for (const change of ['selection', 'session_id', 'request_id', 'process_id', 'sequence_number', 'evicted', 'ambiguous']) {
    const fixture = signalProfileFixture(), held = signalProfileDeferred(), reading = signalProfileDeferred();
    await fixture.refresh();
    fixture.reply = () => phase === 'headers' ? held.promise
      : {...signalProfileResponse(null), json:() => {reading.resolve(); return held.promise;}};
    const pending = fixture.refresh(); if (phase !== 'headers') await reading.promise;
    if (change === 'selection') fixture.state.selectedRequestId = 'r2';
    else if (change === 'evicted') fixture.state.requests = [];
    else if (change === 'ambiguous') fixture.state.requests.push(structuredClone(fixture.state.requests[0]));
    else fixture.state.requests[0].events[0][change] = change === 'process_id' ? 18 : '99';
    if (phase === 'failure') held.reject(new Error('Old body failed'));
    else held.resolve(phase === 'headers' ? signalProfileResponse(signalProfileBody(1)) : signalProfileBody(1));
    await pending;
    assert.equal(fixture.state.signalProfile, null, `${phase}/${change} retires evidence owned by the prior tuple`);
    assert.equal(fixture.state.signalProfileKey, null); assert.equal(fixture.state.signalProfileEtag, null);
    assert.equal(fixture.state.signalProfileStatus, 'error');
    assert.match(fixture.state.signalProfileError, /selected request.*changed/i);
  }
}
for (const field of ['session_id', 'request_id', 'process_id', 'sequence_number']) {
  const fixture = signalProfileFixture(); await fixture.refresh(); const previous = fixture.state.signalProfile;
  const foreign = signalProfileBody(1); foreign.signals = [];
  if (field === 'process_id' || field === 'sequence_number') foreign.root_event[field] = field === 'process_id' ? 18 : '99';
  else foreign[field] = '99';
  assert(fixture.validate(foreign), 'Foreign profile is structurally valid');
  fixture.reply = () => signalProfileResponse(foreign); await fixture.refresh();
  assert.equal(fixture.state.signalProfile, previous); assert.equal(fixture.state.signalProfileStatus, 'error');
  assert.match(fixture.state.signalProfileError, /different.*request|different.*event/i);
  assert.equal(fixture.state.signalProfileEtag, null);
}
for (const outcome of ['malformed', 'json', 'fetch', 'http']) {
  const fixture = signalProfileFixture(); await fixture.refresh(); const previous = fixture.state.signalProfile;
  fixture.reply = () => outcome === 'fetch' ? Promise.reject(new Error('Disconnected'))
    : outcome === 'json' ? {...signalProfileResponse(null), json:async () => {throw new SyntaxError('Invalid JSON');}}
      : signalProfileResponse({}, outcome === 'http' ? 500 : 200);
  await fixture.refresh();
  assert.equal(fixture.state.signalProfile, previous); assert.equal(fixture.state.signalProfileStatus, 'error');
  assert.equal(fixture.state.signalProfileEtag, null, 'A failed refresh requires a full validated retry');
  fixture.reply = () => signalProfileResponse(signalProfileBody(1)); await fixture.refresh();
  assert.equal(fixture.calls.at(-1).options.headers['If-None-Match'], undefined);
  assert.equal(fixture.state.signalProfileStatus, 'ready'); assert.equal(fixture.state.signalProfileError, null);
}
{
  const fixture = signalProfileFixture(); await fixture.refresh(); const previous = fixture.state.signalProfile;
  fixture.reply = () => signalProfileResponse(null, 304); await fixture.refresh();
  assert.equal(fixture.state.signalProfile, previous); assert.equal(fixture.state.signalProfileStatus, 'ready');
  assert.equal(fixture.calls.at(-1).options.headers['If-None-Match'], 'profile-etag');
  fixture.state.selectedRequestId = 'r2'; fixture.reply = () => signalProfileResponse(null, 404); await fixture.refresh();
  assert.equal(fixture.state.signalProfile, null); assert.equal(fixture.state.signalProfileStatus, 'empty');
  assert.equal(fixture.calls.at(-1).options.headers['If-None-Match'], undefined);
  fixture.reply = () => signalProfileResponse(null, 304); await fixture.refresh();
  assert.equal(fixture.state.signalProfileStatus, 'empty');
  fixture.state.selectedRequestId = 'r1'; await fixture.refresh();
  assert.equal(fixture.state.signalProfile, null); assert.equal(fixture.state.signalProfileStatus, 'error');
  assert.equal(fixture.state.signalProfileEtag, null, 'An unsolicited 304 cannot authenticate a cache entry');
}
for (const unavailable of ['missing', 'sample', 'file']) {
  const fixture = signalProfileFixture(); await fixture.refresh(); const calls = fixture.calls.length;
  if (unavailable === 'missing') fixture.state.selectedRequestId = null;
  else if (unavailable === 'sample') fixture.state.requests[0].origin = 'sample';
  else fixture.location.protocol = 'file:';
  await fixture.refresh();
  assert.equal(fixture.state.signalProfile, null); assert.equal(fixture.state.signalProfileStatus, 'empty');
  assert.equal(fixture.state.signalProfileKey, null); assert.equal(fixture.state.signalProfileEtag, null);
  assert.equal(fixture.calls.length, calls);
}
{
  const fixture = signalProfileFixture(), held = signalProfileDeferred(), reading = signalProfileDeferred();
  fixture.reply = () => ({...signalProfileResponse(null), json:() => {reading.resolve(); return held.promise;}});
  const pending = fixture.refresh(); await reading.promise;
  fixture.state.requests = structuredClone(fixture.state.requests);
  held.resolve(signalProfileBody(1)); await pending;
  assert.equal(fixture.state.signalProfileStatus, 'ready', 'Unchanged exact tuples survive catalog object replacement');
}
console.log('PASS request signal profile late headers/bodies/errors, exact owner and response identity, cache recovery and unavailable states (production functions; not rendered QA)');
// Related VM uses an exact native request start; rows without one stay in Traffic.
await checkVmRequestLinkageUI(root);
console.log('PASS unlinked rows cannot become exact VM queries; native pivot preserved');

// Additive machine-readable failure reasons must not make the bundled UI
// reject its existing application result envelope. Exercise the actual validators.
const applicationResults = runInNewContext(
  (await readFile(join(root, "apps/research-ui/evidence_models.js"), "utf8")) +
  appSection("      const analystExactKeys =", "      function isLocalAnalystWorkspace") +
  appSection("      function isLocalAnalystResult", "      function analystFolder(") +
  appSection("      function isJwtInspection", "      function decoderBytesToBase64") +
  ";({isLocalAnalystResult,isJwtInspection,isJwtCreation})", {TextEncoder},
);
const analystResult = {protocol_version: 1, run_id: 1, script_id: 1, library_generation: 1,
  ok: false, outcome: "failed", result_type: "error", result_text: "", result_truncated: false,
  logs: [], logs_truncated: false, duration_ms: 1, error: "Synthetic failure"};
for (const [outcome, code] of [["failed", "application_failed"], ["cancelled", "cancelled"], ["timed_out", "timeout"]]) {
  const legacy = {...analystResult, outcome};
  const annotated = {...legacy, code, details: {phase: "worker"}};
  assert(applicationResults.isLocalAnalystResult(legacy, legacy));
  assert(applicationResults.isLocalAnalystResult(annotated, legacy));
  for (const patch of [{code: "invented"}, {details: {}}, {details: {phase: "worker", raw: "private"}}, {details: {phase: "command_exchange"}}]) {
    assert.equal(applicationResults.isLocalAnalystResult({...annotated, ...patch}, legacy), false);
  }
}
const completedAnalyst = {...analystResult, ok: true, outcome: "completed", error: ""};
assert(applicationResults.isLocalAnalystResult(completedAnalyst, completedAnalyst));
assert.equal(applicationResults.isLocalAnalystResult({...completedAnalyst, code: "application_failed", details: {phase: "worker"}}, completedAnalyst), false);
const jwtCommon = {protocol_version: 1, ok: false, error: "Synthetic failure", duration_us: 1};
for (const [validate, legacy] of [
  [applicationResults.isJwtInspection, {...jwtCommon, algorithm: "", signature_status: "invalid", header_json: "", payload_json: "", token_bytes: 0, signature_bytes: 0}],
  [applicationResults.isJwtCreation, {...jwtCommon, token: ""}],
]) {
  assert(validate(legacy));
  const annotated = {...legacy, code: "application_failed", details: {}};
  assert(validate(annotated));
  for (const patch of [{code: "invented"}, {details: {raw: "private"}}, {code: undefined}, {details: undefined}, {ok: true}]) {
    assert.equal(validate({...annotated, ...patch}), false);
  }
  assert(validate({...legacy, ok: true, error: ""}));
}
console.log("PASS legacy and annotated Analyst/JWT failures, unchanged successes and bounded reason rejection");

// An unchanged event ETag must not prevent artifact-only updates reaching Evidence.
const packageRefreshState = {artifactRefreshing:false,artifactEtag:null,artifactCatalogSignature:null,artifacts:[],openArtifactIds:[],selectedArtifactId:null,sessionMode:'live'};
let packageRefreshBody={artifacts:packageGolden.records.artifacts.map(row=>({...row,...row.key}))}, packageRefreshSyncs=0;
const packageArtifactRefresh=runInNewContext(appSection('      function sourceIdentity(', '      function capturedSources(') + appSection('      async function refreshArtifacts()', '      function showScreen(')+';refreshArtifacts',{
  canvasGalleryVisible:()=>false, retireCanvasPreviews(){},
  syncFloat32Panel(){}, // Actual Float32 host integration is exercised in check-float32-ui.mjs.
  sourceFactsFields:sourceFactsUI.sourceFactsFields, sourceFactsIdentity:sourceFactsUI.sourceFactsIdentity, state:packageRefreshState,location:{protocol:'http:'},fetch:async()=>Response.json(packageRefreshBody),isArtifactResponse:()=>true,
  renderShellStatus(){},renderSourceHealth(){},renderSources(){},renderFingerprintActivity(){},loadArtifactContent(){},loadWasmInspection(){},
  nativeCanvasCaptureDisplayLimit:10,document:{querySelector:()=>({hidden:true})},evidenceWorkspace:{sync(){}},evidencePackagePanel:{sync(){packageRefreshSyncs++;}}
});
await packageArtifactRefresh();assert.equal(packageRefreshState.artifacts.length,2);assert.equal(packageRefreshSyncs,1);
packageRefreshBody={artifacts:[]};await packageArtifactRefresh();assert.equal(packageRefreshState.artifacts.length,0);assert.equal(packageRefreshSyncs,2);
console.log('PASS artifact-only and empty-catalog refresh synchronize the Evidence panel');

// Background request eviction also happens outside Traffic; it must retire an
// Evidence operation immediately rather than waiting for the next view render.
const packageResetState={selectedRequestId:'evicted',originTraceGeneration:0,signalProfileGeneration:0};let packageResetContext;
const packageReset=runInNewContext(appSection('      function resetRequestSelection()', '      function renderRequestCount(')+';resetRequestSelection',{
  state:packageResetState,passiveSecurityPanel:{sync(){}},evidencePackagePanel:{sync(){packageResetContext=packageResetState.selectedRequestId;}}
});packageReset();assert.equal(packageResetContext,null);

// Every inspector render must refresh the strip from the same current request;
// lifecycle callers must not be able to leave a stale pending/status badge.
const summaryState = {selectedRequestId: "current", requests: [uiRequest("current")], inspectorTab: "headers",
  trafficDetailOpen: true, trafficSelectionNotice: null};
const summaryElements = {};
for (const name of ["selectedMethod", "selectedStatus", "selectedUrl", "requestCopyUrl", "requestCollectionPivot", "requestInspector", "requestSearchScope", "requestFilter"]) summaryElements[name] = new TrafficFixtureNode();
summaryElements.requestSearchScope.value = "url";
const summaryNodes = new Map(["#exchange-inspector", "#traffic-comparison", ".traffic-grid", ".detail-pane", "#request-evidence-toggle", "#request-package-entry"].map(key => [key, new TrafficFixtureNode()]));
let renderedSummaryRequest;
const summaryInspector = runInNewContext(
  appSection("      function updateSelectionSummary(", "      function selectRequest(") +
  appSection("      function renderInspector()", "      function renderEvidence()") + ";renderInspector", {
    state: summaryState, elements: summaryElements, evidencePackagePanel: {sync() {}}, trafficCaptureExport: {sync() {}}, passiveSecurityPanel: {sync() {}}, capturedClientWorkflow: {sync() {}},
    document: {querySelectorAll: () => [], querySelector: selector => summaryNodes.get(selector)},
    renderTrafficDetails: (_container, request) => {renderedSummaryRequest = request;}, renderTrafficComparison() {}, openFieldProvenance() {},
  });
for (const [status, failed] of [["pending", false], [200, false], ["failed", true]]) {
  summaryState.requests = [{...summaryState.requests[0], status, failed}];
  summaryInspector();
  assert.equal(summaryElements.selectedStatus.textContent, String(status));
  assert.equal(summaryElements.selectedStatus.classList.contains("status-error"), failed);
  assert.equal(renderedSummaryRequest, summaryState.requests[0]);
}
summaryState.requests = [{...summaryState.requests[0], method: "POST", path: "https://fixture.invalid/new-path"}];
summaryInspector();
assert.equal(summaryElements.selectedMethod.textContent, "POST");
assert.equal(summaryElements.selectedUrl.textContent, "https://fixture.invalid/new-path");
summaryState.requests = []; summaryState.selectedRequestId = null;
summaryInspector();
assert.equal(summaryElements.selectedStatus.textContent, "-");
assert.equal(summaryElements.requestCopyUrl.disabled, true);
console.log("PASS selected strip and inspector share current pending/response/failed/empty request metadata");

// Exercise the actual production listeners: selecting a tab is idempotent,
// whereas the shortcut deliberately toggles Evidence back to Headers.
const stickyInspectorState={inspectorTab:'evidence',fieldTab:'body',requests:[],selectedRequestId:null};
const explicitEvidenceTab=new TrafficFixtureNode('button');explicitEvidenceTab.dataset.inspectorTab='evidence';
const evidenceShortcut=new TrafficFixtureNode('button');
runInNewContext(appSection("      document.querySelectorAll('.inspector-tab').forEach(button => button.addEventListener('click'", "      enableTabKeyboardNavigation('.inspector-tab');"), {
  state:stickyInspectorState,document:{querySelectorAll:()=>[explicitEvidenceTab],querySelector:()=>evidenceShortcut},
  renderInspector(){},renderEvidence(){},refreshRequestSignalProfile(){}
});
explicitEvidenceTab.click();assert.equal(stickyInspectorState.inspectorTab,'evidence');
evidenceShortcut.click();assert.equal(stickyInspectorState.inspectorTab,'headers');
explicitEvidenceTab.click();assert.equal(stickyInspectorState.inspectorTab,'evidence');
explicitEvidenceTab.click();assert.equal(stickyInspectorState.inspectorTab,'evidence');
evidenceShortcut.click();assert.equal(stickyInspectorState.inspectorTab,'headers');
console.log('PASS explicit Evidence tab selection preserves sticky selection while its shortcut deliberately toggles to Headers');

const pivotProfile = {signals: [{category: "canvas", event_count: "1", confidence: "observed", relation: "parent_chain"}]};
const pivotState = {requests: [uiRequest("selected", {operation:"request_started"})], selectedRequestId: "selected", signalProfile: pivotProfile,
  signalProfileStatus: "ready", trafficDetailOpen: false, inspectorTab: "headers"};
const pivotElements = {signalRequestProfile: new TrafficFixtureNode(), signalDetail: new TrafficFixtureNode()};
const signalTab = new TrafficFixtureNode("button");
let pivotScreen;
let pivotInspectorOpen = false;
const signalPivots = runInNewContext(appSection("      function renderSignalRequestProfile()", "      function signalTabKey(") +
  ";({renderSignalRequestProfile,renderFingerprintDetail})", {
  state: pivotState, elements: pivotElements, document: {...trafficDocument, querySelector: () => signalTab},
  textElement: (tag, className, text) => {const node = new TrafficFixtureNode(tag); node.className = className; node.textContent = text; return node;},
  fingerprintSignalLabels: new Map([["canvas", "Canvas"]]), signalCoverageLabel: () => "Bounded",
  decodePayload: () => "getImageData", signalTypeLabel: value => value, signalTabKey: () => "tab",
  matchingSignalProfileFamily: () => pivotProfile.signals[0], signalEventKey: () => "event", integerText: () => "1",
  showScreen: screen => {pivotScreen = screen;}, renderInspector: () => {pivotInspectorOpen = pivotState.trafficDetailOpen;},
  refreshRequestSignalProfile() {}, requestAnimationFrame: callback => callback(),
  fingerprintEventsFromEvents: events => (events ?? []).filter(event => event.category === 'canvas'),
});
for (const render of [() => signalPivots.renderSignalRequestProfile(), () => signalPivots.renderFingerprintDetail({category: "canvas", type: "api_call", thread_id: 1})]) {
  pivotState.trafficDetailOpen = false; pivotInspectorOpen = false; render();
  const root = pivotElements.signalDetail.children.length ? pivotElements.signalDetail : pivotElements.signalRequestProfile;
  root.querySelector("button").click();
  assert.equal(pivotScreen, "traffic");
  assert.equal(pivotInspectorOpen, true, "Explicit fingerprint pivots reopen a previously dismissed inspector");
  assert.equal(pivotState.inspectorTab, "signals");
  assert.equal(pivotState.signalProfile, pivotProfile, "Pivots retain the already loaded signal profile");
}
console.log("PASS Fingerprinting native request-profile/event-detail pivots");

// Adversarial Sources ownership tests run production functions, not a second
// controller. Transport/DOM fixtures are inert and are not rendered acceptance.
function sourceProductionFunction(name) {
  const start = appSource.search(new RegExp(`^      (?:async )?function ${name}\\(`, 'm'));
  assert(start >= 0, name);
  const end = /^      }$/m.exec(appSource.slice(start));
  assert(end, name);
  return appSource.slice(start, start + end.index + end[0].length);
}
const ownershipFunctionNames = ['sourceIdentity', 'sourceIsCurrent', 'sourceReference',
  'retireSourceAnalysis', 'releaseSourcePreview', 'canvasGalleryVisible', 'releaseCanvasPreview', 'retireCanvasPreviews', 'syncCanvasPreviews', 'pumpCanvasPreviews', 'retryCanvasPreview', 'boundSourcePreviews', 'boundSourceAnalysis',
  'capturedSources', 'selectedSource', 'deobfuscationKey', 'validateSourceAnalysis', 'loadDeobfuscation',
  'sourceDisplayView', 'sourceViewLabel', 'sourceDerivedView', 'loadArtifactContent', 'refreshArtifacts',
  'closeSource',
  'sourceDisplayName', 'sourceKindLabel', 'sourceIcon', 'renderSourceWindowControls', 'revealSourceColumn', 'moveSourceWindow', 'syncSourceDisplayControls', 'renderSourceTabs', 'retrySourcePreview', 'renderSourceContent',
  'sourceArtifactIdentityMatches', 'selectArtifact', 'sourceFormattedView', 'syncFloat32Panel', 'textElement', 'deobfuscationRow', 'deobfuscationOwner', 'cancelDeobfuscation', 'retryDeobfuscation', 'retireDeobfuscationReveal',
  'discardStaticCleanup', 'toggleStaticCleanupComparison', 'updateDeobfuscationView', 'setDeobfuscationDisclosure', 'revealDeobfuscationChange', 'deobfuscationButton', 'deobfuscationDisclosure', 'renderDeobfuscationReport'];
const canvasProductionRules=runInNewContext(
  appSection('      const nativeCanvasCaptureDisplayLimit =','      const nativeCanvasDrawingMethods')+
  appSection('      const canvasDataUrlPattern =','      function canvasReadbackName(')+
  ';({nativeCanvasCaptureDisplayLimit,canvasPreviewByteLimit,canvasPreviewReadLimit,canvasDataUrlPattern,canvasPreviewAxisLimit,canvasPreviewPixelLimit,canvasGalleryPixelLimit,inspectCanvasPng})', {atob});
const ownershipModels = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const ownershipSyntax = await readFile(join(root, 'apps/research-ui/source_syntax.js'), 'utf8');
const ownershipProvenanceSite = '';
const ownershipHash = async text => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',
  typeof text === 'string' ? new TextEncoder().encode(text) : text)), byte => byte.toString(16).padStart(2, '0')).join('');
const ownedArtifact = async (id, text = 'const a = 1;', session = '1') => ({protocol_version:1, artifact_id:id, session_id:session,
  navigation_id:'1', frame_id:'1', parent_artifact_id:'0', creator_event_id:'0', kind:'javascript',
  url:`https://fixture.invalid/${id}.js`, mime_type:'text/javascript', byte_size:Buffer.byteLength(text), sha256:await ownershipHash(text), sensitive:false});
const ownedPayload = (source, text) => ({schema:'deobfuscation-analysis-v1', engine:'rust-oxc', mode:'derived', source_truncated:false,
  artifact_id:source.source_type === 'script' ? null : source.artifact_id,
  script_id:source.source_type === 'script' ? source.script_id : null, original_source:text,
  analysis:{source:{sha256:source.sha256 ?? source.hash,byte_size:Buffer.byteLength(text)},assumptions:[]},
  representation:{text,offset_unit:'utf-8-byte',segments:text ? [{kind:'verbatim',original_start:0,original_end:Buffer.byteLength(text),derived_start:0,derived_end:Buffer.byteLength(text)}] : []}});
function ownedContext(patch = {}) {
  const state = {artifacts:[], openArtifactIds:[], selectedArtifactId:null, deobfuscationRequests:new Map(), deobfuscationCache:new Map(),
    sourceFormatCache:new Map(), wasmRequests:new Map(), wasmCache:new Map(),
    sourceDeobfuscated:false, sourceFormatted:false, sourceWasm:false, sessionMode:'live', ...patch.state};
  const sandbox = {console, state, TextEncoder, TextDecoder, Uint8Array, crypto, AbortController, setTimeout, clearTimeout,
    sourceFactsFields:sourceFactsUI.sourceFactsFields, sourceFactsIdentity:sourceFactsUI.sourceFactsIdentity, sourceFactsUnavailable:sourceFactsUI.sourceFactsUnavailable, sourceFactsReadBytes:sourceFactsUI.sourceFactsReadBytes,
    appendSourceSyntax:(node,tokens)=>{node.textContent=tokens.map(value=>value.text).join('');}, sourceOccurrenceRange:()=>null,
    sourceFactsPanel:{original:()=>undefined,cancel(){}}, investigationBeforeSelection(){}, investigationPassiveSource:false, location:{protocol:'http:'}, document:{querySelector:()=>({hidden:true})},
    renderSources(){}, renderSourceHealth(){}, renderShellStatus(){}, renderFingerprintActivity(){}, applySourceSearch(){},
    elements:{signalRenderList:new TrafficFixtureNode()}, ...canvasProductionRules,
    sourceName:source=>source.url, evidencePackagePanel:{sync(){}}, evidenceWorkspace:{sync(){}},
    ...patch, state};
  const functions = [...(patch.productionFunctions ?? ownershipFunctionNames), ...(patch.functions ?? [])];
  return {state, sandbox, api:runInNewContext(ownershipModels + ownershipSyntax + ownershipProvenanceSite + functions.map(sourceProductionFunction).join('\n') +
    (patch.productionSource ?? '') + `;({${functions.join(',')},${(patch.productionExports ?? []).join(',')}})`, sandbox)};
}
const sourceOwnershipReceipt = [];
const ownedDeferred = () => {let resolve; const promise = new Promise(done=>{resolve=done;}); return {promise,resolve};};
{
  const artifact=await ownedArtifact('1'), added=await ownedArtifact('2'), held=ownedDeferred(); let reads=0;
  const {state,api}=ownedContext({state:{artifacts:[artifact],openArtifactIds:['1'],selectedArtifactId:'1'},
    fetch:async url=>url.startsWith('/api/artifacts?') ? Response.json({count:2,artifacts:[{...artifact,loading:undefined},added]}) : (reads++,held.promise)});
  const pending=api.loadArtifactContent(artifact); assert(artifact.loading);
  await api.refreshArtifacts(); assert.equal(state.artifacts[0],artifact,'Refresh must preserve its pending owner');
  held.resolve(new Response('const a = 1;')); await pending;
  assert.equal(state.artifacts[0].content,'const a = 1;'); assert.equal(artifact.loading,false); assert.equal(reads,1);
  sourceOwnershipReceipt.push({test:'pending_refresh_owner',status:'passed',contentReads:reads});
}
{
  const old=await ownedArtifact('1'), newer=await ownedArtifact('1','const newer = 2;','2');
  const held=ownedDeferred(); let signal, reads=0;
  const {state,api}=ownedContext({state:{artifacts:[old],openArtifactIds:['1'],selectedArtifactId:'1'}, fetch:async (url,options)=>{
    if(url.startsWith('/api/artifacts?')) return Response.json({count:1,artifacts:[newer]});
    reads++; if(reads===1){signal=options.signal;return held.promise;} return new Response('const newer = 2;');
  }});
  const pending=api.loadArtifactContent(old); await api.refreshArtifacts(); assert(signal.aborted);
  held.resolve(new Response('const a = 1;')); await pending;
  await new Promise(resolve=>setImmediate(resolve));
  // The newly selected owner may still be in WebCrypto; await only that owner.
  for(let i=0;i<50 && state.artifacts[0].loading;i++) await new Promise(resolve=>setTimeout(resolve,1));
  assert.equal(state.artifacts[0].session_id,'2'); assert.equal(state.artifacts[0].content,'const newer = 2;');
  assert.equal(old.content,undefined); assert.equal(reads,2);
  sourceOwnershipReceipt.push({test:'session_reuse_retires_late_preview',status:'passed'});
}
{
  const artifact=await ownedArtifact('1'); let reads=0, bytes='const b = 1;';
  const {state,api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},fetch:async()=>{reads++;return new Response(bytes);}});
  await api.loadArtifactContent(artifact); assert.match(artifact.loadError,/SHA-256/); assert.equal(artifact.content,undefined);
  await api.loadArtifactContent(artifact); assert.equal(reads,1,'No implicit retry');
  bytes='const a = 1;'; await api.loadArtifactContent(artifact,{retry:true}); assert.equal(artifact.content,bytes);
  api.closeSource({...artifact,source_type:'artifact'}); assert.equal(artifact.content,undefined);
  assert.equal(artifact.sha256,await ownershipHash(bytes)); assert.equal(state.artifacts.length,1);
  sourceOwnershipReceipt.push({test:'wrong_preview_hash_explicit_retry_preserves_descriptor',status:'passed'});
}
{
  const original='\ufeffconst 雪 = "😀";\r\n雪;'; const artifact=await ownedArtifact('1',original); artifact.content=original;
  let payload=ownedPayload(artifact,original);
  const {state,api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},fetch:async()=>Response.json(payload)});
  await api.loadDeobfuscation(api.selectedSource()); const key=api.deobfuscationKey(api.selectedSource());
  assert.equal(state.deobfuscationRequests.get(key).status,'ready'); const successful=state.deobfuscationCache.get(key);
  const malformed = [value=>{value.artifact_id='999';}, value=>{value.analysis.source.sha256='b'.repeat(64);},
    value=>{value.original_source=original.replace('const','throw');}, value=>{value.analysis.source.byte_size++;},
    value=>{value.mode='analysis';}, value=>{value.source_truncated=true;}, value=>{value.analysis.assumptions=['standard-intrinsics'];},
    value=>{value.representation.segments[0].original_start=1;}, value=>{value.representation.segments=[];},
    value=>{value.representation.text='other';}, value=>{value.analysis.omissions={};},
    value=>{value.analysis.classification={evidence:[null]};},value=>{value.analysis.string_tables=[null];}];
  for(const corrupt of malformed) {
    payload=structuredClone(successful);corrupt(payload); await api.loadDeobfuscation(api.selectedSource(),{retry:true});
    assert.equal(state.deobfuscationRequests.get(key).status,'error'); assert.equal(state.deobfuscationCache.get(key),successful);
    assert.equal(api.sourceDisplayView(api.selectedSource()).content,original); assert.match(api.sourceViewLabel(api.selectedSource()),/Original evidence preview/);
  }
  // Even a forged cache cannot replace the original-mode preview.
  state.deobfuscationCache.set(key,{...successful,original_source:'forged evidence'});
  assert.equal(api.sourceDisplayView(api.selectedSource()).content,original);
  sourceOwnershipReceipt.push({test:'deob_identity_hash_assumptions_map_original_separation',status:'passed',rejections:malformed.length});
}
{
  const artifact=await ownedArtifact('1'); const held=ownedDeferred(); const {state,api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},fetch:async()=>held.promise});
  const pending=api.loadDeobfuscation(api.selectedSource());
  state.artifacts=[{...artifact,session_id:'99'}];
  held.resolve(Response.json(ownedPayload(artifact,'const a = 1;'))); await pending;
  assert.equal(state.deobfuscationCache.size,0);
  sourceOwnershipReceipt.push({test:'late_analysis_new_session_same_id_hash_rejected',status:'passed'});
}
{
  const text='x'.repeat(2097152), artifacts=await Promise.all(Array.from({length:12},(_,index)=>ownedArtifact(String(index+1),text)));
  const {state,api}=ownedContext({state:{artifacts,openArtifactIds:artifacts.map(value=>value.artifact_id)},fetch:async()=>new Response(text)});
  for(const artifact of artifacts){state.selectedArtifactId=artifact.artifact_id;await api.loadArtifactContent(artifact);}
  const loaded=artifacts.filter(value=>value.content!==undefined), characters=loaded.reduce((sum,value)=>sum+value.content.length,0);
  assert(loaded.length<=8 && characters<=8*1024*1024); assert.equal(artifacts[0].content,undefined);
  state.selectedArtifactId='1';await api.loadArtifactContent(artifacts[0]);assert.equal(artifacts[0].content,text);
  const binary=new Uint8Array(2097152);const wasm={...await ownedArtifact('99'),kind:'wasm',mime_type:'application/wasm',byte_size:binary.length,sha256:await ownershipHash(binary)};
  const hex=ownedContext({state:{artifacts:[wasm],selectedArtifactId:'99'},fetch:async()=>new Response(binary)});
  await hex.api.loadArtifactContent(wasm);
  assert(wasm.contentTruncated);
  assert(wasm.wasmHexBytes < binary.length && wasm.wasmHexBytes % 16 === 0);
  assert(wasm.content.length <= 8 * 1024 * 1024);
  assert(wasm.content.includes('Hex preview limited'));
  assert(wasm.content.split('\n').length > 20003);
  sourceOwnershipReceipt.push({test:'preview_byte_budget_and_bounded_hex',status:'passed',retainedPreviews:loaded.length,retainedUTF16TextBytes:characters*2,hexRows:wasm.content.split('\n').length});
}
{
  const artifact=await ownedArtifact('1');artifact.content='const a = 1;';let reads=0;
  const {state,api}=ownedContext({state:{artifacts:[artifact]},fetch:async()=>{reads++;return new Response('const a = 1;');}});
  const identity={type:'captured-artifact',session:artifact.session_id,artifact:'1',sha256:artifact.sha256,bytes:artifact.byte_size};
  for(const wrong of [{...identity,session:'2'},{...identity,sha256:'b'.repeat(64)},{...identity,bytes:1}]) {
    assert.equal(api.selectArtifact('1',null,{passive:true,identity:wrong}),false);assert.equal(state.selectedArtifactId,null);
  }
  assert.equal(api.selectArtifact('1',null,{passive:true,identity}),true);assert.equal(state.selectedArtifactId,'1');assert.equal(reads,0);
  state.artifacts.push({...artifact,session_id:'2'});assert.equal(api.selectArtifact('1',null,{identity}),false);
  assert.equal(api.selectedSource(),null);assert.equal(reads,0);
  sourceOwnershipReceipt.push({test:'exact_passive_artifact_entry_and_global_ambiguity',status:'passed'});
}
{
  const artifact=await ownedArtifact('1'), held=ownedDeferred(),timers=new Map();let sequence=0,reads=0,signal;
  const {api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},
    setTimeout(callback,delay){const id=++sequence;timers.set(id,{callback,delay});return id;},clearTimeout(id){timers.delete(id);},
    fetch:async(url,options)=>{reads++;signal=options.signal;return reads===1?held.promise:new Response('const a = 1;');}});
  const old=api.loadArtifactContent(artifact);const timer=[...timers.values()][0];assert.equal(timer.delay,10000);timer.callback();
  assert(signal.aborted);assert.equal(artifact.loading,false);assert.match(artifact.loadError,/timed out/);
  await api.loadArtifactContent(artifact,{retry:true});assert.equal(artifact.content,'const a = 1;');
  held.resolve(new Response('old wrong content'));await old;assert.equal(artifact.content,'const a = 1;');assert.equal(timers.size,0);
  sourceOwnershipReceipt.push({test:'preview_deadline_late_headers_explicit_retry',status:'passed'});
}
{
  const artifact=await ownedArtifact('1');artifact.content='const a = 1;';
  const digest=ownedDeferred(),timers=new Map();let sequence=0,hashes=0;
  const realHash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(artifact.content));
  const {state,api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},
    crypto:{subtle:{digest(){hashes++;return hashes===1?digest.promise:Promise.resolve(realHash);}}},
    setTimeout(callback,delay){const id=++sequence;timers.set(id,{callback,delay});return id;},clearTimeout(id){timers.delete(id);},
    fetch:async()=>Response.json(ownedPayload(artifact,'const a = 1;'))});
  const old=api.loadDeobfuscation(api.selectedSource());for(let i=0;i<50&&!hashes;i++)await new Promise(resolve=>setImmediate(resolve));assert.equal(hashes,1);
  const key=api.deobfuscationKey(api.selectedSource());[...timers.values()][0].callback();
  assert.equal(state.deobfuscationRequests.get(key).status,'error');assert.match(state.deobfuscationRequests.get(key).error,/timed out/);
  await api.loadDeobfuscation(api.selectedSource(),{retry:true});const newer=state.deobfuscationCache.get(key);assert(newer);
  digest.resolve(realHash);await old;assert.equal(state.deobfuscationCache.get(key),newer);assert.equal(timers.size,0);
  sourceOwnershipReceipt.push({test:'analysis_deadline_late_crypto_cannot_replace_retry',status:'passed'});
}
{
  const artifact=await ownedArtifact('1'); const {api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},
    fetch:async()=>new Response(new Uint8Array(2097153))});
  await api.loadArtifactContent(artifact);assert.equal(artifact.content,undefined);assert.match(artifact.loadError,/byte limit/);
  sourceOwnershipReceipt.push({test:'preview_reader_rejects_oversized_body_before_decode',status:'passed'});
}
{
  const artifact=await ownedArtifact('1');const source={...artifact,source_type:'artifact',content:'retained preview',deobfuscation:{original_source:'retained analysis'},controller:new AbortController()};
  const {api}=ownedContext();const reference=api.sourceReference(source);
  assert.equal(api.sourceIdentity(reference),api.sourceIdentity(source));
  for(const field of ['content','deobfuscation','controller'])assert.equal(Object.hasOwn(reference,field),false);
  sourceOwnershipReceipt.push({test:'ui_source_references_do_not_retain_evicted_payloads',status:'passed'});
}
// Minimal DOM fixture checks identity-stable remount avoidance and actual tab
// handlers. Real keyboard, hit-testing and geometry remain the browser gate.
{
  let active=null, searches=0, renders=0;let api;
  class Node {
    constructor(tag='div'){this.tagName=tag;this.children=[];this.attributes={};this.listeners={};this.dataset={};this.scrollLeft=0;this.scrollTop=0;this.textContent='';this.hidden=false;this.classList={contains:()=>false,add(){},toggle(){}};}
    setAttribute(key,value){this.attributes[key]=value;}getAttribute(key){return this.attributes[key];}
    append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;renders++;}
    contains(node){return this===node || this.children.some(child=>child.contains?.(node));}
    addEventListener(key,callback){(this.listeners[key]??=[]).push(callback);}getBoundingClientRect(){return{left:0,right:500};}
    focus(){active=this;}querySelector(selector){return selector==='[aria-selected="true"]'?this.children.find(node=>node.attributes['aria-selected']==='true'):null;}
  }
  const artifact=await ownedArtifact('1','a\nb\nc'),second=await ownedArtifact('2','second');artifact.content='a\nb\nc';second.content='second';
  const elements=Object.fromEntries(['sourceLanguage','sourceCode','sourceCodeEmpty','sourceCodeWrap','sourceEditorTabs','sourceTree'].map(key=>[key,new Node()]));
  const doc={createElement:tag=>new Node(tag),querySelector:()=>({hidden:false}),get activeElement(){return active;}};
  const context=ownedContext({state:{artifacts:[artifact,second],openArtifactIds:['1','2'],selectedArtifactId:'1'},elements,document:doc,
    renderSources(){api?.renderSourceTabs();},updateSourceDecorations(){},appendSourceSyntax(node,tokens){node.textContent=tokens.map(value=>value.text).join('');},
    applySourceSearch(){searches++;},fetch:async()=>new Response('a\nb\nc')});api=context.api;
  const source=api.selectedSource();api.renderSourceContent(source,{content:source.content,lineMap:null});const row=elements.sourceCode.children[0];
  elements.sourceCodeWrap.scrollTop=713;elements.sourceCodeWrap.scrollLeft=143;context.state.sourceSearchIndex=3;const oldRenders=renders,oldSearches=searches;
  api.renderSourceContent(api.selectedSource(),{content:source.content,lineMap:null});assert.equal(elements.sourceCode.children[0],row);
  assert.equal(elements.sourceCodeWrap.scrollTop,713);assert.equal(elements.sourceCodeWrap.scrollLeft,143);assert.equal(context.state.sourceSearchIndex,3);
  assert.equal(renders,oldRenders);assert.equal(searches,oldSearches);
  api.renderSourceTabs();elements.sourceEditorTabs.children[0].focus();
  const press=key=>active.listeners.keydown[0]({key,preventDefault(){}});
  press('ArrowRight');assert.equal(context.state.selectedArtifactId,'2');assert.equal(active.getAttribute('aria-selected'),'true');
  press('Home');assert.equal(context.state.selectedArtifactId,'1');press('End');assert.equal(context.state.selectedArtifactId,'2');
  press('Delete');assert.equal(context.state.openArtifactIds.length,1);assert.equal(context.state.selectedArtifactId,'1');assert.equal(second.content,undefined);
  sourceOwnershipReceipt.push({test:'same_view_scroll_find_dom_retained_keyboard_tabs',status:'passed',scrollTop:713,findOccurrence:3});
}
// Corrective integration regressions from independent review. These use the
// actual renderer, decoration updater, cursor receiver and Field trace pivot.
class SourceReviewNode {
  constructor(tag='div',doc){this.tagName=tag;this.doc=doc;this.children=[];this.attributes={};this.listeners={};this.dataset={};this.scrollLeft=0;this.scrollTop=0;this.hidden=false;this._text='';this.classes=new Set();this.classList={add:value=>this.classes.add(value),contains:value=>this.classes.has(value),toggle:(value,on)=>on?this.classes.add(value):this.classes.delete(value)};this.style={setProperty(){}};}
  set className(value){this.classes=new Set(value.split(' '));}get className(){return [...this.classes].join(' ');}
  get textContent(){return this._text+this.children.map(node=>node.textContent??'').join('');}set textContent(value){this._text=value;this.children=[];}
  setAttribute(key,value){this.attributes[key]=value;}getAttribute(key){return this.attributes[key];}
  append(...nodes){for(let node of nodes){if(typeof node==='string')node=this.doc.createTextNode(node);node.parent=this;this.children.push(node);}}replaceChildren(...nodes){this._text='';this.children=[];this.append(...nodes);}
  contains(node){return this===node||this.children.some(child=>child.contains?.(node));}addEventListener(key,callback){(this.listeners[key]??=[]).push(callback);}
  getBoundingClientRect(){return {left:0,right:500};}focus(){this.doc.activeElement=this;}scrollIntoView(){}
  matches(selector){const data=/^\[data-([a-z-]+)="([^"]*)"\]$/.exec(selector);if(data)return this.dataset[data[1].replace(/-([a-z])/g,(_,c)=>c.toUpperCase())]===data[2];if(selector==='[data-deob-control]')return this.dataset.deobControl!==undefined;if(selector==='[aria-selected="true"]')return this.attributes['aria-selected']==='true';if(selector==='.source-line[data-line]')return this.classes.has('source-line')&&this.dataset.line!==undefined;if(selector==='.source-line.current')return this.classes.has('source-line')&&this.classes.has('current');if(selector.startsWith('.'))return this.classes.has(selector.slice(1));return this.tagName===selector;}
  querySelectorAll(selector){return this.children.flatMap(node=>[...(node.matches?.(selector)?[node]:[]),...(node.querySelectorAll?.(selector)??[])]);}querySelector(selector){return this.querySelectorAll(selector)[0]??null;}closest(selector){return this.matches(selector)?this:this.parent?.closest(selector);}
}
function sourceReviewDOM() {
  const document={activeElement:null,querySelector:()=>({hidden:false})};
  document.createElement=tag=>new SourceReviewNode(tag,document);
  document.createTextNode=text=>{const node=new SourceReviewNode('text',document);node.textContent=text;return node;};
  const elements=Object.fromEntries(['sourceLanguage','sourceCode','sourceCodeEmpty','sourceCodeWrap','sourceEditorTabs','sourceTree','sourcePosition','sourceViewKind','sourceWasm','sourcePretty','sourceDeob','sourceHookPivot','deobfuscationReport','deobfuscationIntrinsics'].map(key=>[key,new SourceReviewNode('div',document)]));
  return {document,elements};
}
{
  const original='\ufeff'+Array.from({length:20001},(_,line)=>line===20000?'const lateNeedle="😀";':`// row ${line}`).join('\r\n');
  const artifact=await ownedArtifact('20001',original);Object.assign(artifact,{content:original,sourceTextLength:original.length});
  const {document,elements}=sourceReviewDOM();
  elements.sourceSearch=document.createElement('input');elements.sourceSearch.value='';elements.sourceSearchStatus=document.createElement('p');
  const ctx=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'20001'},document,elements,sourceOccurrenceRange:()=>null,
    functions:['applySourceSearch'],renderSources(){}});
  ctx.api.renderSourceContent(ctx.api.selectedSource());elements.sourceSearch.value='lateNeedle';ctx.api.applySourceSearch();
  assert.equal(ctx.state.sourceEditorView.window.line,20000);assert.match(elements.sourcePosition.textContent,/1 of 1 matches.*Line 20001, Column 7/);
  assert.equal(elements.sourceCode.querySelector('[data-local-line="20000"]').querySelector('.source-text').textContent,'const lateNeedle="😀";');
  assert(elements.sourceCode.children.length<=1000);
  elements.sourceSearch.value='no-match';ctx.api.applySourceSearch();assert.match(elements.sourcePosition.textContent,/complete retained text/);
  artifact.contentTruncated=true;ctx.api.renderSourceContent(ctx.api.selectedSource());assert.match(elements.sourcePosition.textContent,/coverage is incomplete/);
  artifact.contentTruncated=false;artifact.contentLossy=true;ctx.api.renderSourceContent(ctx.api.selectedSource());assert.match(elements.sourceSearchStatus.textContent,/Lossy/);
  artifact.contentLossy=false;artifact.content=original+'\n[Viewer preview limited to the first 2 MiB; original bytes are unchanged]';artifact.contentTruncated=true;
  ctx.api.renderSourceContent(ctx.api.selectedSource());elements.sourceSearch.value='Viewer preview';ctx.api.applySourceSearch();assert.match(elements.sourcePosition.textContent,/0 matches/);
  assert.equal(ctx.state.sourceEditorView.content,original,'Presentation notices never enter Find or mappings');
  elements.sourceSearch.value='';ctx.api.applySourceSearch();assert(!elements.sourcePosition.textContent.includes('matches'));
  ctx.api.moveSourceWindow(999,3);assert.equal(document.activeElement.dataset.localLine,'999');
  ctx.api.moveSourceWindow(1000,3);assert.equal(document.activeElement.dataset.localLine,'1000');
  ctx.state.selectedArtifactId='missing';elements.sourceSearch.value='lateNeedle';ctx.api.applySourceSearch();assert.match(elements.sourcePosition.textContent,/nothing searched/);
  sourceOwnershipReceipt.push({test:'retained_find_20001_line_coverage_notice_exclusion_stale_owner_and_window_boundaries',status:'passed'});
}
// Live script column selection retired with the CDP source transport.
{
  const original='const a=1; const b=2;',artifact=await ownedArtifact('map-complete',original);
  const {api}=ownedContext();
  for(const [text,segments] of [
    ['const b=2;',[{kind:'verbatim',original_start:11,original_end:21,derived_start:0,derived_end:10}]],
    ['const a=1;',[{kind:'verbatim',original_start:0,original_end:10,derived_start:0,derived_end:10}]],
    ['(3)',[{kind:'replacement',original_start:0,original_end:0,derived_start:0,derived_end:3}]],
  ]) {
    const payload=ownedPayload(artifact,original);payload.representation.text=text;payload.representation.segments=segments;
    await assert.rejects(api.validateSourceAnalysis(payload,{...artifact,source_type:'artifact'},false),/source map/);
  }
  sourceOwnershipReceipt.push({test:'deob_complete_original_map_no_implicit_deletion_or_zero_width_replacement',status:'passed'});
}
// Changed-span inspection uses production admission, controller and DOM code.
// These fixtures never execute analyzed JavaScript and are not rendered QA.
function ownedDerivedPayload(source, original, replacements) {
  const payload=ownedPayload(source,original), segments=[];let cursor=0,derived='';
  const append=(kind,start,end,text)=>{const begin=Buffer.byteLength(derived);derived+=text;segments.push({kind,original_start:Buffer.byteLength(original.slice(0,start)),original_end:Buffer.byteLength(original.slice(0,end)),derived_start:begin,derived_end:Buffer.byteLength(derived)});};
  for(const [before,after] of replacements){const start=original.indexOf(before,cursor);assert(start>=cursor);if(start>cursor)append('verbatim',cursor,start,original.slice(cursor,start));append('replacement',start,start+before.length,after);cursor=start+before.length;}
  if(cursor<original.length)append('verbatim',cursor,original.length,original.slice(cursor));
  payload.representation={text:derived,offset_unit:'utf-8-byte',segments,truncated:false};
  payload.analysis.representation={status:'derived',derived_bytes:Buffer.byteLength(derived),segment_count:segments.length,truncated:false,transformations:replacements.map((_,index)=>({id:`fixture-family-${index}`,kind:'rewrite',count:1,detail:'Authored aggregate fixture; no per-change rule.'}))};
  return payload;
}
{
  const original='\ufeffconst 雪="😀";'+Array.from({length:7},(_,i)=>`const v${i}=1+${i};`).join('');
  const artifact=await ownedArtifact('inspector',original);artifact.content=original;
  let payload=ownedDerivedPayload(artifact,original,Array.from({length:7},(_,i)=>[`1+${i}`,`(${i+1})`]));
  payload.analysis.omissions=['Generic unsupported operations remain unresolved.'];
  payload.analysis.limits={max_source_bytes:4194304,max_transformations:4096};
  payload.analysis.classification={label:'minified',confidence:95,evidence:[{id:'fixture-signal',detail:'Heuristic fixture signal'}]};
  payload.analysis.string_tables=Array.from({length:5},(_,i)=>({kind:`table-${i+1}`,offset:0,entry_count:8,encodings:['literal'],decoded_preview:'<script>inert</script>'}));
  const {document,elements}=sourceReviewDOM();let api;
  const ctx=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id,sourceDeobfuscated:true},document,elements,
    formatByteSize:value=>`${value} bytes`,renderSources(){api?.renderDeobfuscationReport(api.selectedSource());},fetch:async()=>Response.json(payload)});api=ctx.api;
  await api.loadDeobfuscation(api.selectedSource());const source=api.selectedSource(),key=api.deobfuscationKey(source),good=ctx.state.deobfuscationCache.get(key),report=elements.deobfuscationReport;
  assert.equal(ctx.state.deobfuscationRequests.get(key).status,'ready');
  assert.equal(good.sourceInspection.changes.length,7);assert.equal(good.sourceInspection.changes[0].original_start,original.indexOf('1+0'));
  assert.match(report.textContent,/7 changed spans/);assert.match(report.textContent,/7 reported rewrites/);assert(!report.textContent.includes('confidence 95'));
  assert.match(report.textContent,/Recovered tables \(5\)/);assert(report.textContent.includes('table-4'));assert(!report.textContent.includes('table-5'));
  assert.equal(report.querySelectorAll('script').length,0);assert(report.textContent.includes('<script>inert</script>'));
  const control=key=>report.querySelectorAll('[data-deob-control]').find(node=>node.dataset.deobControl===key);
  const click=async key=>{const node=control(key);assert(node && !node.disabled,key);node.focus();await node.listeners.click[0]();};
  const originalNode=report.querySelectorAll('pre')[0];originalNode.scrollLeft=77;report.scrollTop=43;originalNode.focus();
  api.renderDeobfuscationReport(api.selectedSource());assert.equal(report.querySelectorAll('pre')[0],originalNode);assert.equal(originalNode.scrollLeft,77);assert.equal(document.activeElement,originalNode);
  const tables=report.querySelectorAll('details').find(node=>node.querySelector('summary').textContent.startsWith('Recovered tables'));
  tables.open=true;await click('tables-next'); // Native toggle delivery may still be queued.
  assert(report.textContent.includes('table-5'));assert(!report.textContent.includes('table-1'));
  assert.equal(report.querySelectorAll('details').find(node=>node.querySelector('summary').textContent.startsWith('Recovered tables')).open,true);
  tables.open=false;tables.listeners.toggle[0]({currentTarget:tables});assert.equal(good.inspectorView.open.tables,true,'Detached queued toggle must not overwrite the current disclosure');
  await click('transformations-next');assert(report.textContent.includes('fixture-family-6'));assert(!report.textContent.includes('fixture-family-0'));
  await click('change-next');assert.match(report.textContent,/Change 2 of 7/);assert.equal(document.activeElement.dataset.deobControl,'change-next');assert.equal(report.scrollTop,43);
  for(let i=0;i<5;i++)await click('change-next');assert.equal(document.activeElement.dataset.deobControl,'change-previous');
  ctx.state.deobfuscationRequests.set(key,{status:'error',error:'Authored retry failure'});api.renderDeobfuscationReport(api.selectedSource());
  assert.match(report.textContent,/Authored retry failure/);assert.match(report.textContent,/Last successful report remains below/);assert.equal(report.querySelectorAll('pre').length,2);
  assert.equal(api.sourceDisplayView(api.selectedSource()).content,good.representation.text);
  const corruptions=[
    value=>{value.representation.segments.shift();value.representation.text=value.representation.text.slice(good.sourceInspection.changes[0].derived_start);},
    value=>{const last=value.representation.segments.pop();value.representation.text=value.representation.text.slice(0,last.derived_start);},
    value=>{value.representation.segments[1].original_end=value.representation.segments[1].original_start;},
    value=>{value.analysis.representation.transformations[0].count++;},
    value=>{value.representation.transformations=[{id:'claimed',count:9999,detail:'Untrusted claim'}];},
    value=>{value.analysis.limits={max_source_bytes:'unbounded'};},
    value=>{value.engine='unknown-engine';},
    value=>{value.representation.segments[0].original_end=1;},
  ];
  for(const corrupt of corruptions){payload=structuredClone(good);corrupt(payload);await api.loadDeobfuscation(api.selectedSource(),{retry:true});assert.equal(ctx.state.deobfuscationRequests.get(key).status,'error');assert.equal(ctx.state.deobfuscationCache.get(key),good);}
  // A stale control must not affect a fresh owner with different assumption mode.
  const stale=control('retry');ctx.state.deobfuscationAssumeIntrinsics=true;const before=ctx.state.deobfuscationRequests.size;await stale.listeners.click[0]();assert.equal(ctx.state.deobfuscationRequests.size,before);
  api.releaseSourcePreview(source);ctx.state.selectedArtifactId=null;api.renderDeobfuscationReport(null);assert.equal(report.deobfuscationRender,null);assert.equal(report.querySelectorAll('pre').length,0);
  sourceOwnershipReceipt.push({test:'deob_changed_spans_unicode_paging_inert_reports_focus_retry_and_admission',status:'passed',changes:7,tables:5,corruptions:corruptions.length});
}
{
  const {document,elements}=sourceReviewDOM();
  const details=document.createElement('details'),screen=document.createElement('section');
  document.querySelector=selector=>selector==='#deobfuscation-details'?details:screen;
  elements.sourceSidebar=document.createElement('aside');elements.sourceSidebar.hidden=true;
  elements.sourceSidebarToggle=document.createElement('button');
  const state={sourceSidebarOpen:false,sourceDeobfuscated:false};
  let renders=0,cancellations=0;
  const context={document,elements,state,investigationPassiveSource:true,sourceFactsPanel:{cancel(){cancellations++;}},renderSources(){renders++;}};
  runInNewContext(sourceProductionFunction('renderSourceSidebar')+appSection("      elements.sourceDeob.addEventListener('click'", "      elements.sourceWasm.addEventListener('click'"),context);
  elements.sourceDeob.listeners.click[0]();
  assert.equal(elements.sourceSidebar.hidden,true,'Cleanup must not overlay the code editor');
  assert.equal(state.sourceSidebarOpen,false,'Cleanup preserves the explicit Details preference');
  assert.equal(details.open,true);assert.equal(state.sourceDeobfuscated,true);
  elements.sourceDeob.listeners.click[0]();assert.equal(state.sourceDeobfuscated,false);assert.equal(renders,2);assert.equal(cancellations,2);
  state.sourceSidebarOpen=true;context.renderSourceSidebar();
  elements.sourceDeob.listeners.click[0]();
  assert.equal(elements.sourceSidebar.hidden,false,'Already open Details stays open');
  assert.equal(state.sourceSidebarOpen,true);
  sourceOwnershipReceipt.push({test:'static_cleanup_preserves_sidebar_visibility_and_original_toggle',status:'passed'});
}
{
  const original='/*'+'x'.repeat(8189)+'😀'+'y'.repeat(200)+'*/ const result=1+2;';
  const artifact=await ownedArtifact('cleanup-compare',original);artifact.content=original;
  const payload=ownedDerivedPayload(artifact,original,[['1+2','(3)']]);
  const dom=sourceReviewDOM();let api,gate=null,calls=0;
  const ctx=ownedContext({...dom,state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id,sourceDeobfuscated:true},formatByteSize:String,
    renderSources(){api?.renderDeobfuscationReport(api.selectedSource());},fetch:async()=>{calls++;if(gate)await gate.promise;return Response.json(payload);}});api=ctx.api;
  await api.loadDeobfuscation(api.selectedSource());
  const source=api.selectedSource(),good=source.deobfuscation,view=good.inspectorView,key=api.deobfuscationKey(source);
  assert.equal(good.sourceInspection.derivedSha256,await ownershipHash(payload.representation.text));
  assert.match(dom.elements.deobfuscationReport.textContent,/Recovery is partial in scope/);
  api.toggleStaticCleanupComparison(source,view);
  const previews=dom.elements.deobfuscationReport.querySelectorAll('pre').filter(n=>n.dataset.deobControl.startsWith('comparison-'));
  assert.equal(previews.length,2);
  for(const pre of previews){assert(pre.textContent.length<=8192);assert(!/[\uD800-\uDBFF]$/.test(pre.textContent));}
  assert.match(dom.elements.deobfuscationReport.textContent,/prefix preview/);
  assert.match(dom.elements.deobfuscationReport.textContent,/8191 of/);
  api.toggleStaticCleanupComparison(source,view);assert.equal(view.compare,false);
  gate=ownedDeferred();const pending=api.loadDeobfuscation(api.selectedSource(),{retry:true});
  const request=ctx.state.deobfuscationRequests.get(key),signal=request.controller.signal;
  api.discardStaticCleanup(source,view);
  assert(signal.aborted);assert.equal(request.status,'cancelled');assert.equal(ctx.state.deobfuscationCache.size,0);
  assert.equal(ctx.state.sourceDeobfuscated,false);assert.equal(artifact.content,original);assert.equal(artifact.sha256,await ownershipHash(original));
  gate.resolve();await pending;assert.equal(ctx.state.deobfuscationCache.size,0);
  await api.loadDeobfuscation(api.selectedSource());assert.equal(calls,2,'Discard requires explicit retry');
  gate=null;await api.loadDeobfuscation(api.selectedSource(),{retry:true});assert.equal(calls,3);
  const fresh=api.selectedSource().deobfuscation;
  api.discardStaticCleanup(source,view);assert.equal(ctx.state.deobfuscationCache.get(key),fresh,'Stale discard cannot delete replacement result');
  sourceOwnershipReceipt.push({test:'static_cleanup_hash_bounded_comparison_unicode_discard_late_reply_retry_stale_controls',status:'passed'});
}
{
  const original='const result=1+2;',artifact=await ownedArtifact('deob-cancel',original);artifact.content=original;
  const gate=ownedDeferred();let calls=0;
  const {api,state}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},fetch:async()=>{calls++;await gate.promise;return Response.json(ownedDerivedPayload(artifact,original,[['1+2','(3)']]));}});
  const source=api.selectedSource(),key=api.deobfuscationKey(source),pending=api.loadDeobfuscation(source),request=state.deobfuscationRequests.get(key);
  api.cancelDeobfuscation(source,request);assert.equal(request.status,'cancelled');await api.loadDeobfuscation(source);assert.equal(calls,1);
  const newer=api.loadDeobfuscation(source,{retry:true}),newRequest=state.deobfuscationRequests.get(key);api.cancelDeobfuscation(source,request);assert.equal(newRequest.status,'loading');api.cancelDeobfuscation(source,newRequest);
  gate.resolve();await Promise.all([pending,newer]);assert.equal(state.deobfuscationCache.size,0);assert.equal(request.status,'cancelled');
  const second=ownedDeferred();const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(original));let hashing=false;
  const hashCtx=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},crypto:{subtle:{digest(){hashing=true;return second.promise;}}},fetch:async()=>Response.json(ownedDerivedPayload(artifact,original,[['1+2','(3)']]))});
  const hashPending=hashCtx.api.loadDeobfuscation(hashCtx.api.selectedSource());for(let i=0;i<20&&!hashing;i++)await new Promise(resolve=>setTimeout(resolve,1));assert(hashing);
  hashCtx.api.cancelDeobfuscation(hashCtx.api.selectedSource());second.resolve(hash);await hashPending;assert.equal(hashCtx.state.deobfuscationCache.size,0);
  sourceOwnershipReceipt.push({test:'deob_explicit_cancel_late_body_and_digest_no_implicit_retry',status:'passed'});
}
{
  const original='const result="'+('x'.repeat(2047))+'😀'+('y'.repeat(64))+'";',artifact=await ownedArtifact('101',original);artifact.content=original;
  const before=original.slice(13,-1),payload=ownedDerivedPayload(artifact,original,[[before,'("short")']]);
  const {document,elements}=sourceReviewDOM();const navigated=[];
  const context=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},document,elements,formatByteSize:String,
    sourceFactsPanel:{original:()=>undefined,cancel(){},model:{status:'ready',error:''},navigate:async range=>navigated.push(range)},fetch:async()=>Response.json(payload)});
  await context.api.loadDeobfuscation(context.api.selectedSource());context.api.renderDeobfuscationReport(context.api.selectedSource());
  const report=elements.deobfuscationReport,pre=report.querySelectorAll('pre')[0];assert(pre.textContent.length<=2048);assert(!/[\uD800-\uDBFF]$/.test(pre.textContent));assert.match(report.textContent,/Snippet shows/);
  const good=context.api.selectedSource().deobfuscation;await context.api.revealDeobfuscationChange(context.api.selectedSource(),good.inspectorView);
  assert.equal(navigated.length,1);assert.equal(navigated[0].start,payload.representation.segments[1].original_start);assert.equal(navigated[0].end,payload.representation.segments[1].original_end);
  sourceOwnershipReceipt.push({test:'deob_bounded_snippet_and_verified_original_range_handoff',status:'passed'});
}

{
  for (const action of ['option','replacement','selection','eviction']) {
    const original='const result=1+2;',artifact=await ownedArtifact('102',original);artifact.content=original;
    const payload=ownedDerivedPayload(artifact,original,[['1+2','(3)']]),gate=ownedDeferred();let navigations=0;
    const {document,elements}=sourceReviewDOM();
    const ctx=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},document,elements,formatByteSize:String,fetch:async()=>Response.json(payload)});
    await ctx.api.loadDeobfuscation(ctx.api.selectedSource());const source=ctx.api.selectedSource(),good=source.deobfuscation,view=good.inspectorView,key=ctx.api.deobfuscationKey(source);
    const facts=sourceFactsUI.createSourceFactsController({getSource:ctx.api.selectedSource,protocol:'http:',onChange(){},onNavigate(){navigations++;},cryptoApi:crypto,
      fetcher:async()=>{await gate.promise;return new Response(original,{headers:{'X-Artifact-Total-Bytes':String(Buffer.byteLength(original)),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}});}});
    ctx.sandbox.sourceFactsPanel=facts;
    const pending=ctx.api.revealDeobfuscationChange({...source,deobfuscationAssumption:false},view);assert(view.revealing);
    if(action==='option')ctx.state.deobfuscationAssumeIntrinsics=true;
    if(action==='replacement')ctx.state.deobfuscationCache.set(key,{...good,inspectorView:{change:0,pages:{},open:{},notice:''}});
    if(action==='selection')ctx.api.updateDeobfuscationView(source,view,'changes',1);
    if(action==='eviction')ctx.api.releaseSourcePreview(source);
    gate.resolve();await pending;assert.equal(navigations,0,action);assert.equal(view.revealing,false,action);assert.notEqual(facts.model.status,'loading-source',action);
  }
  sourceOwnershipReceipt.push({test:'deob_reveal_guard_before_real_facts_navigation_option_report_selection_eviction',status:'passed'});
}
{
  const original='const result=1+2;',artifact=await ownedArtifact('103',original);artifact.content=original;
  const payload=ownedDerivedPayload(artifact,original,[['1+2','(3)']]),oldGate=ownedDeferred(),factsGate=ownedDeferred();let factsSignal;
  const dom=sourceReviewDOM();
  const ctx=ownedContext({...dom,formatByteSize:String,state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},fetch:async()=>Response.json(payload)});
  await ctx.api.loadDeobfuscation(ctx.api.selectedSource());const source=ctx.api.selectedSource(),view=source.deobfuscation.inspectorView;
  const facts=sourceFactsUI.createSourceFactsController({getSource:ctx.api.selectedSource,protocol:'http:',onChange(){},onNavigate(){throw Error('Retired reveal navigated');},cryptoApi:crypto,
    fetcher:async(url,options)=>{if(url.startsWith('/api/source-facts')){factsSignal=options.signal;await factsGate.promise;return Response.json({});}await oldGate.promise;return new Response(original);}});
  ctx.sandbox.sourceFactsPanel=facts;const old=ctx.api.revealDeobfuscationChange(source,view);facts.cancel();const unrelated=facts.load();assert(factsSignal&&!factsSignal.aborted);
  ctx.api.retireDeobfuscationReveal(view);assert.equal(factsSignal.aborted,false,'Retiring an old reveal must not cancel newer unrelated Facts work');
  facts.cancel();oldGate.resolve();factsGate.resolve();await Promise.all([old,unrelated]);
  sourceOwnershipReceipt.push({test:'deob_owned_reveal_cancellation_preserves_unrelated_facts',status:'passed'});
}

{
  const text='const a = 1;', artifact={...await ownedArtifact('mapped',text),source_type:'artifact',content:text};
  for(const mode of ['pretty','derived']) {
    const {document,elements}=sourceReviewDOM();let navigation;
    const {api,state}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id,sourceFormatted:mode==='pretty',sourceDeobfuscated:mode==='derived'},document,elements,
      appendSourceSyntax:(node,tokens)=>{node.textContent=tokens.map(value=>value.text).join('');},applySourceSearch(){},
      revealOriginalLine:(source,line,column)=>{navigation={source,line,column};}});
    const view={content:text,lineMap:[{originalLine:0,originalColumn:4}],...(mode==='pretty'?{formatted:{}}:{derived:{}})};
    api.renderSourceContent(artifact,view);const gutter=elements.sourceCode.children[0].querySelector('.source-gutter');
    for(let refresh=0;refresh<3;refresh++){api.renderSourceContent(artifact,view);assert.equal(gutter.disabled,false);assert.equal(gutter.getAttribute('aria-label'),'Show original source at line 1');}
    gutter.listeners.click[0]({stopPropagation(){}});assert.equal(navigation.line,0);assert.equal(navigation.column,4);
    // Retained original source is read-only; its gutter never becomes an action.
    state.sourceFormatted=false;state.sourceDeobfuscated=false;api.renderSourceContent(artifact,{content:text,lineMap:null});
    assert.equal(elements.sourceCode.children[0].querySelector('.source-gutter').getAttribute('aria-label'),'Retained source line');
    assert.equal(elements.sourceCode.children[0].querySelector('.source-gutter').disabled,true);
  }
  sourceOwnershipReceipt.push({test:'review_mapped_artifact_gutters_survive_refresh',status:'passed',representations:['pretty','derived']});
}
{
  const {document,elements}=sourceReviewDOM();const first=await ownedArtifact('retry-1'),second=await ownedArtifact('retry-2','second');
  first.loadError='Synthetic preview error';second.content='second';
  const {api,state,sandbox}=ownedContext({state:{artifacts:[first,second],selectedArtifactId:first.artifact_id},document,elements,
    textElement:(tag,kind,text)=>{const node=document.createElement(tag);node.className=kind;node.textContent=text;return node;},
    appendSourceSyntax:(node,tokens)=>{node.textContent=tokens.map(value=>value.text).join('');},applySourceSearch(){}});
  const key=api.deobfuscationKey({...first,source_type:'artifact'}),analysis=ownedPayload(first,'const a = 1;');state.deobfuscationCache.set(key,analysis);
  api.renderSourceContent(api.selectedSource());const retry=elements.sourceCodeEmpty.children[1];assert(retry.listeners.click);
  api.releaseSourcePreview({...first,source_type:'artifact'});state.selectedArtifactId=second.artifact_id;api.renderSourceContent(api.selectedSource());
  assert.equal(elements.sourceCodeEmpty.hidden,true);assert.equal(elements.sourceCodeEmpty.children.length,0);assert.equal(state.deobfuscationCache.size,0);
  // Even an externally retained old handler receives descriptor-only data.
  state.selectedArtifactId=first.artifact_id;let received;
  sandbox.sourceIsCurrent=source=>{received=source;return false;};retry.listeners.click[0]();
  assert(received);for(const key of ['content','deobfuscation','controller'])assert.equal(Object.hasOwn(received,key),false);
  sourceOwnershipReceipt.push({test:'review_hidden_retry_dom_and_bound_reference_release',status:'passed',hiddenRetryNodes:0});
}
// Shared history must restore only after the actual preview renderer settles.
// The DOM is inert: scroll clamping, geometry and keyboard acceptance still need CI.
const sourceHistoryNavigation = await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
async function sourceHistoryFixture(kind = 'artifact') {
  const {document,elements}=sourceReviewDOM(),frames=[],reads=[],held=ownedDeferred();
  elements.signalRenderList=document.createElement('div');
  const text=Array.from({length:100},(_,line)=>`const row${line} = "${'x'.repeat(120)}";`).join('\n');
  const artifact={...await ownedArtifact('7',text),content:text};
  if(kind==='wasm'){artifact.kind='wasm';artifact.mime_type='application/wasm';}
  for(const name of ['sourceLocation','sourceSize','sourceHash','sourceViewKind','sourceWasm','sourcePretty','sourceDeob','sourceHookPivot','requestFilter'])elements[name]=document.createElement('button');
  const screens=Object.fromEntries(['sources','tools','signals'].map(name=>[name,document.createElement('section')]));
  for(const [name,node] of Object.entries(screens)){node.id=`screen-${name}`;node.hidden=name!=='sources';}
  elements.sourceCodeWrap.id='source-code-wrap';elements.sourceTree.id='source-tree';
  screens.sources.append(elements.sourceCodeWrap,elements.sourceTree,elements.sourcePretty);
  screens.signals.append(elements.signalRenderList);
  elements.sourceCodeWrap.append(elements.sourceCode,elements.sourceCodeEmpty);
  elements.sourcePretty.id='source-pretty';
  const back=document.createElement('button'),forward=document.createElement('button'),notice=document.createElement('p'),bar=document.createElement('div');back.id='investigation-back';forward.id='investigation-forward';
  back.disabled=true;forward.disabled=true;
  const byId=new Map([...Object.values(screens),...Object.values(elements),back,forward].filter(node=>node.id).map(node=>[`#${node.id}`,node]));
  byId.set('#investigation-decode-range',document.createElement('button'));
  for(const node of [...Object.values(screens),...Object.values(elements)]){
    const matches=node.matches.bind(node);node.matches=selector=>selector.startsWith('#')?selector===`#${node.id}`:matches(selector);
  }
  screens.sources.querySelectorAll=selector=>selector.includes(',')?[elements.sourceCodeWrap,elements.sourceTree]:Object.values(elements).filter(node=>node.matches(selector));
  screens.sources.querySelector=selector=>byId.get(selector)??null;
  const navigation={open:false,contains:()=>false};
  document.querySelector=selector=>selector==='.screen:not([hidden])'?Object.values(screens).find(node=>!node.hidden):selector==='#investigation-notice'?notice:selector==='#investigation-navigation'?bar:selector==='#advanced-navigation'?navigation:byId.get(selector)??null;
  document.querySelectorAll=selector=>selector==='.screen'?Object.values(screens):[];
  document.getElementById=id=>Object.values(screens).find(node=>node.id===id)??byId.get(`#${id}`)??null;
  bar.querySelector=()=>({open:false});
  const noop=()=>{};
  const fixture=ownedContext({elements,document,CSS:{escape:value=>value},requestAnimationFrame:fn=>frames.push(fn),
    state:{artifacts:[artifact],requests:[],decoderSteps:[],selectedArtifactId:'7',
      sourceCollection:'captured',sourceFactsOpen:false,openArtifactIds:['7']},
    sourceFactsPanel:{original:()=>undefined,sync:noop,cancel:noop},float32Panel:{cancel:noop},evidenceWorkspace:{setVisible:noop,sync:noop},
    renderDebugger:noop,renderSourceTree:noop,renderSourceTabs:noop,renderSourceFacts:noop,renderDeobfuscationReport:noop,
    renderTools:noop,refreshDecoderEngine:noop,formatByteSize:String,applySourceSearch:noop,
    appendSourceSyntax(node,tokens){node.textContent=tokens.map(token=>token.text).join('');},
    fetch:async(url,options)=>{reads.push({url,signal:options.signal});if(url.startsWith('/api/artifacts?'))return Response.json({count:1,artifacts:[Object.fromEntries(sourceFactsUI.sourceFactsFields.filter(key=>Object.hasOwn(artifact,key)).map(key=>[key,artifact[key]]))]});return held.promise;},
    productionFunctions:[...ownershipFunctionNames.filter(name=>!['renderSourceTabs','renderDeobfuscationReport'].includes(name)), 'renderSources','showScreen','wasmKey','loadWasmInspection'],
    productionSource:sourceHistoryNavigation+'\ninvestigationNavigation=createInvestigationHistory({snapshot:investigationSnapshot,restore:restoreInvestigation,changed({back,forward}){document.querySelector("#investigation-back").disabled=!back;document.querySelector("#investigation-forward").disabled=!forward;}});',
    productionExports:['investigationSnapshot','restoreInvestigation','retireInvestigationReturn','history:investigationNavigation','pendingReturn:()=>investigationPendingReturn']});
  const {state,api}=fixture;
  // Observe the actual production promises. A fixed number of setImmediate
  // turns can expire before WebCrypto finishes, even though the UI is correct.
  const completion=sourceOwnershipOperationObserver({artifact:api.loadArtifactContent,wasm:api.loadWasmInspection},api.sourceIdentity);
  fixture.sandbox.loadArtifactContent=completion.wrappers.artifact;
  fixture.sandbox.loadWasmInspection=completion.wrappers.wasm;
  if(kind==='wasm'){
    state.sourceWasm=true;
    state.wasmCache.set(api.wasmKey(artifact),{...wasmReport,artifact_id:'7',sha256:artifact.sha256,byte_size:artifact.byte_size});
    state.wasmRequests.set(api.wasmKey(artifact),{status:'ready'});
  }
  api.renderSources();elements.sourcePretty.focus();elements.sourceCodeWrap.scrollTop=713;elements.sourceCodeWrap.scrollLeft=143;elements.sourceTree.scrollTop=81;
  const saved=api.investigationSnapshot();
  api.showScreen('tools');
  api.releaseSourcePreview(api.selectedSource());
  if(kind==='wasm')state.wasmCache.clear();
  frames.length=0;
  const flush=async()=>{await new Promise(resolve=>setImmediate(resolve));for(const callback of frames.splice(0))callback();};
  const settle=async()=>{
    const deadline=Date.now()+5000;
    do {
      await flush();
      if(completion.failures().pending===0&&api.pendingReturn()===null&&frames.length===0)return;
      await new Promise(resolve=>setTimeout(resolve,1));
    }while(Date.now()<deadline);
    assert.fail('Sources history production loader/return did not reach observable completion');
  };
  return {...fixture,elements,document,held,reads,text,saved,frames,screens,notice,flush,settle};
}
for(const kind of ['artifact']) {
  const fixture=await sourceHistoryFixture(kind),{api,held,reads,elements,document,text,flush}=fixture;
  assert(api.history.back());await flush();assert.equal(reads.length,1,'Shared Back deduplicates the selected preview read');
  assert.match(elements.sourceCodeEmpty.textContent,/Loading/);
  held.resolve(new Response(text));
  await fixture.settle();
  assert.equal(elements.sourceCodeWrap.scrollTop,713,`${kind}: Back restores vertical scroll after preview completion`);
  assert.equal(elements.sourceCodeWrap.scrollLeft,143,`${kind}: Back restores horizontal scroll after preview completion`);
  assert.equal(elements.sourceTree.scrollTop,81);assert.equal(document.activeElement,elements.sourcePretty);
  assert(api.history.forward());assert.equal(fixture.screens.tools.hidden,false);
}
for(const kind of ['artifact']) for(const interruption of ['interaction','forward','identity','error']) {
  const fixture=await sourceHistoryFixture(kind),{api,state,held,elements,document,text,flush}=fixture;
  assert(api.history.back());await flush();
  if(interruption==='interaction')api.retireInvestigationReturn();
  if(interruption==='forward')assert(api.history.forward());
  if(interruption==='identity'){
    state.artifacts[0]={...state.artifacts[0],session_id:'2',content:'newer source',loading:false};
    api.renderSources();
  }
  elements.sourceTree.scrollTop=777;elements.sourceTree.focus();
  held.resolve(interruption==='error'?new Response('{}',{status:503}):new Response(text));
  await fixture.settle();
  if(interruption==='error'){
    assert.match(elements.sourceCodeEmpty.textContent,/unavailable/i);
    assert.equal(document.activeElement.id,'investigation-forward','When saved focus and the consumed Back control are disabled, Forward owns focus');
  } else {
    assert.equal(elements.sourceTree.scrollTop,777,'Late readers cannot restore superseded pane scroll');
    if(interruption==='forward')assert.notEqual(document.activeElement,elements.sourcePretty,'A Source reader cannot reclaim focus after Forward');
    else assert.equal(document.activeElement,elements.sourceTree,`${kind}/${interruption}: late readers cannot reclaim newer focus`);
  }
  assert.equal(api.pendingReturn(),null,'Terminal or superseded returns release their metadata');
}
{
  const fixture=await sourceHistoryFixture('wasm'),{api,held,reads,elements,text,flush}=fixture;
  assert(api.history.back());held.resolve(new Response(text));
  await fixture.settle();
  assert.equal(reads.length,1,'Passive Back cannot automatically run an evicted static inspection');
  assert.doesNotMatch(elements.sourceCodeEmpty.textContent,/Inspecting immutable module bytes/,'An evicted report with no read in flight is not loading');
  assert.match(elements.sourceCodeEmpty.textContent,/released|Retry inspection/);
  await api.refreshArtifacts();assert.equal(reads.filter(read=>read.url.startsWith('/api/wasm')).length,0,'A passive return stays passive on later catalog refresh');
  assert.match(elements.sourceViewKind.textContent,/released/);
  assert.equal(api.pendingReturn(),null);
  let inspections=0;
  fixture.sandbox.fetch=async()=>{inspections++;return Response.json({...wasmReport,artifact_id:'7',sha256:api.selectedSource().sha256,byte_size:api.selectedSource().byte_size});};
  const retry=elements.sourceCodeEmpty.querySelector('button');assert.equal(retry.textContent,'Retry inspection');
  api.retireInvestigationReturn();retry.listeners.click[0]();
  await fixture.settle();
  assert.equal(inspections,1);assert.equal(elements.sourceCode.hidden,false);assert.match(elements.sourceLanguage.textContent,/WASM disassembly/);
}
console.log('PASS shared Sources Back/Forward after preview and WASM report eviction through actual selection, shell, readers and renderer (DOM fixture; not rendered QA)');

if (process.env.REB_SOURCE_OWNERSHIP_BACKEND_URL) {
  const endpoint=new URL(process.env.REB_SOURCE_OWNERSHIP_BACKEND_URL);
  assert(endpoint.protocol==='http:' && ['127.0.0.1','localhost','[::1]'].includes(endpoint.hostname),'Sources fixture backend must be loopback');
  const catalog=await (await fetch(new URL('/api/artifacts?limit=500',endpoint))).json();
  const {state,api}=ownedContext({state:{artifacts:catalog.artifacts},fetch:(url,options)=>fetch(new URL(url,endpoint),options)});
  const javascript=state.artifacts.filter(source=>source.kind==='javascript');assert(javascript.length);
  for(const artifact of javascript) {
    state.selectedArtifactId=artifact.artifact_id;await api.loadArtifactContent(artifact);assert.equal(artifact.loadError,null);
    const original=artifact.content;
    for(const intrinsics of [false,true]) {
      state.deobfuscationAssumeIntrinsics=intrinsics;await api.loadDeobfuscation(api.selectedSource());
      const request=state.deobfuscationRequests.get(api.deobfuscationKey(api.selectedSource()));assert.equal(request.status,'ready',request.error);
      assert.equal(api.sourceDisplayView(api.selectedSource()).content,original);assert.equal(artifact.content,original);
    }
    const response=await fetch(new URL(`/api/artifacts/${artifact.artifact_id}/content?limit=2097152`,endpoint));
    assert.equal(await ownershipHash(new Uint8Array(await response.arrayBuffer())),artifact.sha256);
  }
  sourceOwnershipReceipt.push({test:'real_rust_worker_http_to_sources_admission',status:'passed',artifacts:javascript.length,intrinsicModes:2});
}
console.log('PASS Sources pending refresh owners, analyzer identity/hash/maps, worker targets, cursor scope, explicit retry, close/eviction byte bounds, bounded hex, stable editor and keyboard tab handlers (not rendered QA)');
// Canvas ownership uses the real catalog, reader, renderer and screen transition.
// Data URLs are inert authored text; no image is decoded by this fixture.
const canvasOwnershipReceipt=[];
const canvasText='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAAXNSR0IArs4c6QAAAARzQklUCAgICHwIZIgAAAANSURBVHicY/jPwPAfAAUAAf+JmT0dAAAAAElFTkSuQmCC';
async function canvasArtifact(id,text=canvasText,session='1') {
  return {...await ownedArtifact(id,text,session),kind:'canvas_data_url',mime_type:'text/plain',
    capture_origin:'canvas_to_data_url',execution_context_id:'0',creator_event_id:id,sensitive:true};
}
function canvasContext(patch={}) {
  const sourceAssignments=[];
  class CanvasNode extends TrafficFixtureNode {
    get parentElement(){return this.parentNode;}
    matches(selector){return selector==='details[open]'?this.tagName==='DETAILS'&&this.open:super.matches(selector);}
    focus(){document.activeElement=this;}
    set src(value){sourceAssignments.push(this);this.setAttribute('src',value);}get src(){return this.getAttribute('src')??'';}
  }
  const screen=new TrafficFixtureNode();screen.id='screen-signals';screen.hidden=patch.hidden??false;
  const navigation=new TrafficFixtureNode();
  const document={activeElement:null,createElement:tag=>new CanvasNode(tag),
    getElementById:id=>id==='screen-signals'?screen:id==='screen-other'?navigation:null,
    querySelector:selector=>selector==='#screen-signals'?screen:navigation,
    querySelectorAll:selector=>selector==='.screen'?[screen]:[]};
  const elements=Object.fromEntries(['signalRenderList','signalRenderCount','signalRenderSummary'].map(key=>[key,new TrafficFixtureNode()]));
  let context, events=[];
  const canvasEvents=artifacts=>artifacts.map(artifact=>({category:'canvas',type:'api_call',operation:'canvas.toDataURL',payload:Buffer.from('canvas.toDataURL').toString('hex'),
    session_id:artifact.session_id,process_id:1,frame_id:'1',sequence_number:artifact.creator_event_id,monotonic_time_ns:artifact.creator_event_id}));
  context=ownedContext({functions:['canvasReadbackName','canvasCallLabel','canvasRenderCaptures','canvasPreview','renderCanvasCapture','renderFingerprintRendering','showScreen'],
    document,elements,nativeCanvasDrawingMethods:new Set(),nativeCanvasCallLimit:128,
    integerValue:(event,key)=>BigInt(event[key]),integerText:(event,key)=>String(event[key]),decodePayload:event=>event.operation,
    textElement:(tag,className,text)=>{const node=new CanvasNode(tag);node.className=className;node.textContent=text;return node;},
    signalEventKey:event=>`${event.session_id}:${event.sequence_number}`,matchingSignalProfileFamily:()=>null,
    renderSignalSurfaceOverview(){},renderFingerprintActivity(){context.api.renderFingerprintRendering(events);},
    investigationBeforeScreen(){},float32Panel:{cancel(){}},evidenceWorkspace:{sync(){},setVisible(){}},
    ...patch,state:{signalView:'rendering',canvasImageCaptureEnabled:true,canvasRenderCaptures:[],...patch.state}});
  return {...context,screen,elements,sourceAssignments,events(artifacts){events=canvasEvents(artifacts);},render(){context.api.renderFingerprintRendering(events);}};
}
async function canvasSettled(context) {
  for(let attempt=0;attempt<1000;attempt++) {
    if(!(context.state.canvasPreviewReads?.size)) return;
    await new Promise(resolve=>setTimeout(resolve,1));
  }
  assert.fail('Canvas fixture did not settle');
}
function canvasAccounting(context) {
  const loaded=context.state.artifacts.filter(value=>value.kind==='canvas_data_url'&&value.content!==undefined);
  const reserved=[...(context.state.canvasPreviewOwners?.values()??[])].reduce((sum,owner)=>sum+owner.artifact.byte_size*2,0);
  const textBytes=loaded.reduce((sum,artifact)=>sum+artifact.content.length*2,0);
  assert(loaded.length<=24);assert(reserved<=8*1024*1024);assert(textBytes<=reserved);
  assert((context.state.canvasPreviewOwners?.size??0)<=24);assert((context.state.canvasPreviewReads?.size??0)<=2);
  return {loaded:loaded.length,reservedUTF16Bytes:reserved,retainedUTF16Bytes:textBytes};
}
{
  const original=await canvasArtifact('1');let catalog=[],reads=0;
  const context=canvasContext({hidden:true,fetch:async url=>url.startsWith('/api/artifacts?')
    ? Response.json({count:catalog.length,artifacts:catalog}) : (reads++,new Response(canvasText))});
  for(let total=24;total<=480;total+=24) {
    catalog=Array.from({length:total},(_,index)=>({...original,artifact_id:String(index+1),creator_event_id:String(index+1)}));
    await context.api.refreshArtifacts();assert.equal(context.state.artifactReceiverError,null);canvasAccounting(context);
  }
  assert.equal(reads,0);assert.equal(context.state.artifacts.length,480);
  await context.api.loadArtifactContent(context.state.artifacts[0]);assert.equal(reads,0,'Generic selected-source loads cannot bypass Canvas ownership');
  canvasOwnershipReceipt.push({test:'20_hidden_catalogs_480_descriptors',status:'passed',contentReads:reads,...canvasAccounting(context)});
}
{
  const original=await canvasArtifact('1');let catalog=[],reads=0,maxReads=0,maxLoaded=0,rawReservations=0,maxRawReservations=0;
  const context=canvasContext({fetch:async url=>url.startsWith('/api/artifacts?')
    ? Response.json({count:catalog.length,artifacts:catalog}) : (reads++,new Response(canvasText))});
  context.sandbox.sourceFactsReadBytes=async(...args)=>{
    maxReads=Math.max(maxReads,context.state.canvasPreviewReads.size);canvasAccounting(context);
    rawReservations+=args[1];maxRawReservations=Math.max(maxRawReservations,rawReservations);assert(rawReservations<=4*1024*1024);
    try{return await sourceFactsUI.sourceFactsReadBytes(...args);}finally{rawReservations-=args[1];}
  };
  for(let total=24;total<=480;total+=24) {
    catalog=Array.from({length:total},(_,index)=>({...original,artifact_id:String(index+1),creator_event_id:String(index+1)}));
    context.events(catalog);await context.api.refreshArtifacts();await canvasSettled(context);
    assert.equal(context.state.artifactReceiverError,null);maxLoaded=Math.max(maxLoaded,canvasAccounting(context).loaded);
  }
  assert.equal(reads,480);assert.equal(maxReads,2);assert.equal(maxLoaded,24);
  const retained=context.state.artifacts.filter(artifact=>artifact.content!==undefined);
  assert.equal(retained[0].artifact_id,'457');assert.equal(context.elements.signalRenderList.querySelectorAll('img').length,24);
  for(let refresh=0;refresh<20;refresh++)context.render();await canvasSettled(context);assert.equal(reads,480,'Stable gallery must not churn');
  const detached=[...context.elements.signalRenderList.querySelectorAll('img')];assert(detached.every(image=>image.src===canvasText));
  context.state.signalView='activity';context.render();assert.equal(context.elements.signalRenderList.children.length,0);
  assert(detached.every(image=>!image.getAttribute('src')));assert.equal(canvasAccounting(context).loaded,0);
  context.state.signalView='rendering';context.events(context.state.artifacts.slice(0,3));context.render();await canvasSettled(context);
  assert.equal(canvasAccounting(context).loaded,3);assert(context.state.artifacts.slice(0,3).every(artifact=>artifact.content===canvasText));
  context.api.showScreen('other',{classList:{contains:()=>true}});assert.equal(canvasAccounting(context).loaded,0);
  assert.equal(context.elements.signalRenderList.children.length,0);assert.equal(context.state.artifacts.length,480);
  canvasOwnershipReceipt.push({test:'visible_growth_rollover_stable_scope_activity_navigation',status:'passed',maxReads,maxRawReadBufferReservations:maxRawReservations,maxRetained:maxLoaded,retainedDescriptors:480,afterNavigation:canvasAccounting(context)});
}
{
  const large='data:image/png;base64,'+'A'.repeat(2097152-'data:image/png;base64,'.length),original=await canvasArtifact('1',large);let reads=0;
  const artifacts=Array.from({length:24},(_,index)=>({...original,artifact_id:String(index+1),creator_event_id:String(index+1)}));
  const context=canvasContext({state:{artifacts},fetch:async()=>{reads++;return new Response(large);}});
  context.events(artifacts);context.render();await canvasSettled(context);
  assert.equal(reads,2);assert.equal(canvasAccounting(context).loaded,2);
  assert.equal(context.state.canvasPreviewOwners.size,2);assert.equal(artifacts.filter(value=>/8 MiB/.test(value.canvasPreviewNotice)).length,22);
  for(let refresh=0;refresh<30;refresh++)context.render();await canvasSettled(context);assert.equal(reads,2);
  canvasOwnershipReceipt.push({test:'aggregate_reservations_stop_byte_budget_reload_churn',status:'passed',contentReads:reads,...canvasAccounting(context)});
}
{
  const old=await canvasArtifact('1'),other=await canvasArtifact('2'),replacement=await canvasArtifact('1',canvasText,'2');
  const held=[],signals=[];let catalog=[old,other],reads=0,cancelled=0,lateBodyReads=0;
  const context=canvasContext({fetch:async(url,options)=>{
    if(url.startsWith('/api/artifacts?'))return Response.json({count:catalog.length,artifacts:catalog});
    reads++;signals.push(options.signal);const pending=ownedDeferred();held.push(pending);return pending.promise;
  }});
  context.events(catalog);await context.api.refreshArtifacts();assert.equal(reads,2);const stale=[...context.state.artifacts];
  context.events([replacement]);catalog=[replacement];await context.api.refreshArtifacts();
  assert(signals.every(signal=>signal.aborted));assert.equal(reads,2,'Retired noncooperative reads still occupy the two slots');
  assert.equal(context.elements.signalRenderList.querySelectorAll('img').length,0);
  held[0].resolve({ok:true,body:{cancel:async()=>{cancelled++;},getReader(){lateBodyReads++;throw Error('Stale body read');}}});
  held[1].resolve({ok:true,body:{cancel:async()=>{cancelled++;},getReader(){lateBodyReads++;throw Error('Stale body read');}}});
  for(let attempt=0;attempt<100&&reads<3;attempt++)await new Promise(resolve=>setTimeout(resolve,1));
  assert.equal(reads,3);assert.equal(cancelled,2);assert.equal(lateBodyReads,0);assert(stale.every(artifact=>artifact.content===undefined));
  held[2].resolve(new Response(canvasText));await canvasSettled(context);assert.equal(context.state.artifacts[0].session_id,'2');
  assert.equal(context.state.artifacts[0].content,canvasText);
  canvasOwnershipReceipt.push({test:'catalog_session_replacement_late_headers_keep_read_credit',status:'passed',staleBodyReads:lateBodyReads,cancelledResponses:cancelled,...canvasAccounting(context)});
}
{
  const artifact=await canvasArtifact('1');let status=200,reads=0,failContent=true;
  const context=canvasContext({fetch:async url=>url.startsWith('/api/artifacts?')
    ? new Response(JSON.stringify({count:1,artifacts:[artifact]}),{status,headers:{ETag:'"canvas"'}})
    : (reads++,new Response(failContent?'wrong bytes':canvasText))});
  context.events([artifact]);await context.api.refreshArtifacts();await canvasSettled(context);
  assert.equal(reads,1);assert.match(context.state.artifacts[0].loadError,/byte size/);
  for(let repeat=0;repeat<3;repeat++)await context.api.refreshArtifacts();await canvasSettled(context);assert.equal(reads,1);
  failContent=false;context.elements.signalRenderList.querySelector('button').click();await canvasSettled(context);assert.equal(reads,2);
  const image=context.elements.signalRenderList.querySelector('img');assert(image);
  status=503;await context.api.refreshArtifacts();assert.equal(context.state.artifactEtag,null);assert.equal(canvasAccounting(context).loaded,0);
  assert.equal(context.state.artifacts.length,1);assert(!image.getAttribute('src'));assert.match(context.elements.signalRenderList.textContent,/catalog is unavailable/);
  status=200;await context.api.refreshArtifacts();await canvasSettled(context);assert.equal(reads,3,'An unchanged recovered catalog restores the visible gallery');
  assert.equal(context.state.artifacts[0].content,canvasText);
  canvasOwnershipReceipt.push({test:'explicit_retry_catalog_error_cleanup_same_catalog_recovery',status:'passed',contentReads:reads,...canvasAccounting(context)});
}
{
  const source=await ownedArtifact('50');source.content='const a = 1;';
  const one=await canvasArtifact('1'),two=await canvasArtifact('2');const held=[],signals=[];let reads=0;
  const context=canvasContext({state:{artifacts:[source,one,two]},fetch:async(url,options)=>{
    reads++;signals.push(options.signal);
    if(reads>2)return new Response(canvasText);
    return new Response(new ReadableStream({start(controller){held.push(controller);},cancel(){}}));
  }});
  const sourceKey=context.api.sourceIdentity(source)+'|verified';const result={original_source:'const a = 1;'};
  context.state.deobfuscationCache.set(sourceKey,result);
  context.events([one,two]);context.render();await new Promise(resolve=>setImmediate(resolve));assert.equal(reads,2);
  context.api.showScreen('other',{classList:{contains:()=>true}});await canvasSettled(context);
  assert(signals.every(signal=>signal.aborted));assert.equal(canvasAccounting(context).loaded,0);
  assert.equal(source.content,'const a = 1;');assert.equal(context.state.deobfuscationCache.get(sourceKey),result);
  context.screen.hidden=false;context.render();await canvasSettled(context);assert.equal(reads,4);
  const detached=[...context.elements.signalRenderList.querySelectorAll('img')];assert.equal(detached.length,2);
  context.events([]);context.render();assert.equal(canvasAccounting(context).loaded,0);assert(detached.every(image=>!image.src));
  assert.match(context.elements.signalRenderList.textContent,/No Canvas readback/);
  canvasOwnershipReceipt.push({test:'body_abort_reopen_empty_scope_preserves_source_analysis',status:'passed',abortedReads:2,contentReads:reads,...canvasAccounting(context)});
}
{
  const artifacts=await Promise.all(['1','2','3'].map(id=>canvasArtifact(id)));const held=[],timers=new Map();let sequence=0,reads=0,cancelled=0;
  const context=canvasContext({state:{artifacts},
    setTimeout(callback,delay){const id=++sequence;timers.set(id,{callback,delay});return id;},clearTimeout(id){timers.delete(id);},
    fetch:async()=>{reads++;if(reads>2)return new Response(canvasText);const pending=ownedDeferred();held.push(pending);return pending.promise;}});
  context.events(artifacts);context.render();assert.equal(reads,2);assert.equal(timers.size,2);
  for(const timer of [...timers.values()]){assert.equal(timer.delay,10000);timer.callback();}
  assert.equal(reads,2);assert.equal(context.state.canvasPreviewReads.size,2);
  assert.equal(artifacts.filter(artifact=>/timed out/.test(artifact.loadError)).length,2);
  for(const pending of held)pending.resolve({body:{cancel:async()=>{cancelled++;}},ok:true});
  await canvasSettled(context);assert.equal(cancelled,2);assert.equal(reads,3);assert.equal(canvasAccounting(context).loaded,1);
  context.render();await canvasSettled(context);assert.equal(reads,3,'Timed-out previews require explicit retry');
  assert.equal(timers.size,0);
  canvasOwnershipReceipt.push({test:'deadline_keeps_noncooperative_fetch_credit_and_failed_reason',status:'passed',lateHeadersCancelled:cancelled,contentReads:reads,...canvasAccounting(context)});
}
{
  const oversized={...await canvasArtifact('1'),byte_size:2097153},invalid=await canvasArtifact('2','invalid image'),wrongHash={...await canvasArtifact('3'),sha256:'b'.repeat(64)};
  const artifacts=[oversized,invalid,wrongHash];let reads=0;
  const context=canvasContext({state:{artifacts},fetch:async url=>{reads++;return new Response(url.includes('/2/')?'invalid image':canvasText);}});
  context.events(artifacts);context.render();await canvasSettled(context);assert.equal(reads,2);assert.equal(canvasAccounting(context).loaded,0);
  assert.match(oversized.canvasPreviewNotice,/2 MiB/);assert.match(invalid.loadError,/image data URL validator/);assert.match(wrongHash.loadError,/SHA-256/);
  for(let repeat=0;repeat<5;repeat++)context.render();await canvasSettled(context);assert.equal(reads,2);
  context.sandbox.fetch=async()=>Response.json({count:0,artifacts:[]});await context.api.refreshArtifacts();
  assert.equal(context.state.artifacts.length,0);assert.equal(context.state.canvasPreviewOwners.size,0);assert.equal(context.elements.signalRenderList.children.length,0);
  canvasOwnershipReceipt.push({test:'oversize_invalid_hash_admission_and_empty_live_catalog',status:'passed',contentReads:reads,...canvasAccounting(context)});
}
// Cancellation itself is an owned operation. A producer may settle a read or
// return error/stale headers while keeping body/reader cancellation pending.
for(const boundary of ['error-headers','reader-error']) {
  const original=await canvasArtifact('1'),artifacts=Array.from({length:24},(_,index)=>({...original,artifact_id:String(index+1),creator_event_id:String(index+1)}));
  const pending=[];let reads=0,active=0,maximum=0;
  const context=canvasContext({state:{artifacts},fetch:async()=>{
    reads++;
    const cancel=()=>{const held=ownedDeferred();pending.push(held);active++;maximum=Math.max(maximum,active);return held.promise.finally(()=>{active--;});};
    return boundary==='error-headers'?{ok:false,status:503,body:{cancel}}
      :{ok:true,headers:new Headers(),body:{getReader:()=>({read:async()=>({done:false,value:'not a byte chunk'}),cancel,releaseLock(){}})}};
  }});
  context.events(artifacts);context.render();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(reads,2);assert.equal(active,2);assert.equal(context.state.canvasPreviewReads.size,2);
  assert.equal(artifacts.filter(artifact=>artifact.loadError).length,2,'Failure is visible without waiting for cancellation');
  assert.equal(context.elements.signalRenderList.querySelectorAll('button').length,2);
  for(let repeat=0;repeat<10;repeat++)context.render();await new Promise(resolve=>setImmediate(resolve));assert.equal(reads,2);
  for(let wave=0;wave<24;wave++) {
    pending.splice(0).forEach((held,index)=>held.resolve(index%2?Promise.reject(new Error('Cancellation rejected')):undefined));
    await new Promise(resolve=>setImmediate(resolve));assert(active<=2);canvasAccounting(context);
    if(reads===24&&active===0&&context.state.canvasPreviewReads.size===0)break;
  }
  assert.equal(reads,24);assert.equal(active,0);assert.equal(context.state.canvasPreviewReads.size,0);assert.equal(maximum,2);
  context.render();await canvasSettled(context);assert.equal(reads,24,'Failed owners cannot cause cancellation/retry churn');
  canvasOwnershipReceipt.push({test:`${boundary}_credit_includes_pending_and_rejected_cancellation`,status:'passed',fetchesBeforeCancellationSettlement:2,maxPendingCancellations:maximum,contentReads:reads});
}
for(const boundary of ['stale-headers','reader-abort']) {
  const old=await Promise.all(['1','2'].map(id=>canvasArtifact(id))),newer=await Promise.all(['1','2'].map(id=>canvasArtifact(id,canvasText,'2')));
  const headers=[],bodyReads=[],cancellations=[];let reads=0,cancelled=0;
  const context=canvasContext({state:{artifacts:old},fetch:async()=>{
    reads++;if(reads>2)return new Response(canvasText);
    const cancel=()=>{cancelled++;const held=ownedDeferred();cancellations.push(held);return held.promise;};
    if(boundary==='stale-headers'){const held=ownedDeferred();headers.push({held,response:{ok:true,body:{cancel}}});return held.promise;}
    const held=ownedDeferred();bodyReads.push(held);
    return {ok:true,headers:new Headers(),body:{getReader:()=>({read:()=>held.promise,cancel,releaseLock(){}})}};
  }});
  context.events(old);context.render();await new Promise(resolve=>setImmediate(resolve));assert.equal(reads,2);
  context.api.showScreen('other',{classList:{contains:()=>true}});
  context.state.artifacts=newer;context.events(newer);context.screen.hidden=false;context.render();
  for(const {held,response} of headers)held.resolve(response);
  for(const held of bodyReads)held.resolve({done:true});
  await new Promise(resolve=>setImmediate(resolve));assert.equal(cancelled,2);assert.equal(reads,2);assert.equal(context.state.canvasPreviewReads.size,2);
  for(let repeat=0;repeat<10;repeat++){context.api.showScreen('other',{classList:{contains:()=>true}});context.screen.hidden=false;context.render();}
  assert.equal(reads,2);assert(old.every(artifact=>artifact.content===undefined));assert(newer.every(artifact=>artifact.content===undefined));
  cancellations.forEach(held=>held.resolve());await canvasSettled(context);assert.equal(reads,4);
  assert(newer.every(artifact=>artifact.content===canvasText));assert(old.every(artifact=>artifact.content===undefined));
  canvasOwnershipReceipt.push({test:`${boundary}_holds_cancellation_credit_across_replacement_and_reopen`,status:'passed',fetchesBeforeCancellationSettlement:2,retiredOwners:2,contentReads:reads,...canvasAccounting(context)});
}
{
  const artifact=await canvasArtifact('1'),held=ownedDeferred();let reads=0;
  const context=canvasContext({state:{artifacts:[artifact]},fetch:async()=>++reads===1?{ok:false,status:503,body:{cancel:()=>held.promise}}:new Response(canvasText)});
  context.events([artifact]);context.render();await new Promise(resolve=>setImmediate(resolve));assert.match(artifact.loadError,/503/);
  context.elements.signalRenderList.querySelector('button').click();await new Promise(resolve=>setImmediate(resolve));assert.equal(reads,1);
  assert.equal(context.state.canvasPreviewReads.size,1);held.resolve();await canvasSettled(context);
  assert.equal(reads,2);assert.equal(artifact.content,canvasText);assert.equal(artifact.loadError,null);
  canvasOwnershipReceipt.push({test:'explicit_retry_waits_for_prior_cancellation_credit',status:'passed',contentReads:reads,...canvasAccounting(context)});
}
{
  const artifact=await ownedArtifact('1'),held=ownedDeferred();let cancelled=0;
  const context=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},fetch:async()=>({ok:false,status:503,body:{cancel(){cancelled++;return held.promise;}}})});
  await context.api.loadArtifactContent(artifact);assert.equal(cancelled,1);assert.match(artifact.loadError,/503/);
  assert.equal(artifact.loading,false);assert.equal(context.state.canvasPreviewReads,undefined);held.resolve();
  canvasOwnershipReceipt.push({test:'non_canvas_sources_keep_nonblocking_cancellation_behavior',status:'passed'});
}
{
  const artifact=await canvasArtifact('1'),cleanup=ownedDeferred(),newHeaders=ownedDeferred();let reads=0;
  const context=canvasContext({state:{artifacts:[artifact]},fetch:async()=>++reads===1?{ok:false,status:503,body:{cancel:()=>cleanup.promise}}:newHeaders.promise});
  context.events([artifact]);context.render();await new Promise(resolve=>setImmediate(resolve));
  context.api.showScreen('other',{classList:{contains:()=>true}});context.screen.hidden=false;context.render();
  context.elements.signalRenderList.querySelector('button').click();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(reads,2);assert.equal(context.state.canvasPreviewReads.size,2);const controller=artifact.controller;
  assert(controller&&!controller.signal.aborted);cleanup.resolve();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(artifact.controller,controller);assert.equal(artifact.loading,true);assert.equal(artifact.loadError,null);
  newHeaders.resolve(new Response(canvasText));await canvasSettled(context);assert.equal(artifact.content,canvasText);assert.equal(artifact.loadError,null);
  canvasOwnershipReceipt.push({test:'retired_cancellation_cannot_clear_reopened_same_artifact_owner',status:'passed',contentReads:reads,...canvasAccounting(context)});
}
{
  const artifact=await canvasArtifact('1'),cleanup=ownedDeferred();let renders=0,settled=false;
  const context=canvasContext({state:{artifacts:[artifact]},renderFingerprintActivity(){renders++;throw new Error('Fixture render failed');},
    fetch:async()=>({ok:false,status:503,body:{cancel:()=>cleanup.promise}})});
  const owner={artifact,identity:context.api.sourceIdentity(artifact)};context.state.canvasPreviewOwners=new Map([[owner.identity,owner]]);
  const result=context.api.loadArtifactContent(artifact,{canvasOwner:owner}).then(()=>{settled=true;return null;},error=>{settled=true;return error;});
  await new Promise(resolve=>setImmediate(resolve));assert.equal(renders,1);assert.equal(settled,false,'A render exception cannot skip owned cancellation settlement');
  cleanup.resolve();assert.match((await result).message,/Fixture render failed/);assert.equal(settled,true);assert.match(artifact.loadError,/503/);
  canvasOwnershipReceipt.push({test:'render_exception_cannot_release_pending_cancellation',status:'passed'});
}
// Fixtures only rewrite headers/chunks around a one-pixel PNG. They never
// inflate data or ask a browser to decode the oversized declared dimensions.
function canvasPngChunk(type,data=Buffer.alloc(0)) {
  const bytes=Buffer.concat([Buffer.from(type),data]);let crc=0xffffffff;
  for(const byte of bytes){crc^=byte;for(let bit=0;bit<8;bit++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}
  const chunk=Buffer.alloc(data.length+12);chunk.writeUInt32BE(data.length);bytes.copy(chunk,4);chunk.writeUInt32BE((crc^0xffffffff)>>>0,data.length+8);return chunk;
}
function canvasPngFixture({width=1,height=1,depth=8,color=6,compression=0,filter=0,interlace=0,before=[],after=[],idat,tail=Buffer.alloc(0)}={}) {
  const original=Buffer.from(canvasText.split(',')[1],'base64'),header=Buffer.alloc(13),idatOffset=original.indexOf(Buffer.from('IDAT'));
  header.writeUInt32BE(width);header.writeUInt32BE(height,4);header.set([depth,color,compression,filter,interlace],8);
  return Buffer.concat([original.subarray(0,8),canvasPngChunk('IHDR',header),...before,
    ...(idat??[canvasPngChunk('IDAT',original.subarray(idatOffset+4,idatOffset+4+original.readUInt32BE(idatOffset-4)))]),...after,canvasPngChunk('IEND'),tail]);
}
const canvasPngUrl=bytes=>'data:image/png;base64,'+bytes.toString('base64');
{
  const inspect=canvasProductionRules.inspectCanvasPng,valid=canvasPngFixture();
  assert.deepEqual({...inspect(canvasText)},{width:1,height:1,pixels:1});
  for(const options of [{width:4096,height:1024},{width:1024,height:4096},{width:2048,height:2048},{color:2}]) {
    const admitted=inspect(canvasPngUrl(canvasPngFixture(options)));assert.equal(admitted.reason,undefined,JSON.stringify(options));
    assert.equal(admitted.pixels,(options.width??1)*(options.height??1));
  }
  const sRGB=canvasPngChunk('sRGB',Buffer.from([0])),sBIT=canvasPngChunk('sBIT',Buffer.from([8,8,8,8])),pHYs=canvasPngChunk('pHYs',Buffer.from([0,0,14,196,0,0,14,196,1]));
  assert.equal(inspect(canvasPngUrl(canvasPngFixture({before:[sRGB,sBIT,pHYs]}))).reason,undefined);
  assert.equal(inspect(canvasPngUrl(canvasPngFixture({color:2,before:[canvasPngChunk('sBIT',Buffer.from([8,8,8]))]}))).reason,undefined);
  const negatives=[
    ['zero-width',{width:0},/axis/],['zero-height',{height:0},/axis/],['wide',{width:4097},/axis/],['tall',{height:4097},/axis/],
    ['huge',{width:0xffffffff,height:0xffffffff},/axis/],['pixel-product',{width:2049,height:2048},/4 Mi-pixel/],
    ['16-bit',{depth:16},/8-bit/],['palette',{color:3},/RGB/],['greyscale',{color:0},/RGB/],
    ['interlaced',{interlace:1},/non-interlaced/],['compression',{compression:1},/compression/],['filter',{filter:1},/filtering/],
    ['animation-control',{before:[canvasPngChunk('acTL',Buffer.alloc(8))]},/Animated/],
    ['animation-frame',{after:[canvasPngChunk('fcTL',Buffer.alloc(26))]},/Animated/],
    ['animation-data',{after:[canvasPngChunk('fdAT',Buffer.alloc(4))]},/Animated/],
    ['embedded-profile',{before:[canvasPngChunk('iCCP',Buffer.from('x\0\0'))]},/unsupported/],
    ['compressed-text',{before:[canvasPngChunk('zTXt')]},/unsupported/],['unknown-critical',{before:[canvasPngChunk('ABCD')]},/unsupported/],
    ['palette-chunk',{before:[canvasPngChunk('PLTE',Buffer.alloc(3))]},/unsupported/],
    ['duplicate-header',{before:[valid.subarray(8,33)]},/duplicate/],['empty-idat',{idat:[canvasPngChunk('IDAT')]},/incomplete/],
    ['missing-idat',{idat:[]},/incomplete/],['trailing-byte',{tail:Buffer.from([0])},/trailing/],
    ['duplicate-end',{tail:canvasPngChunk('IEND')},/trailing/],['early-end',{before:[canvasPngChunk('IEND')]},/incomplete/],
    ['sbit-length',{before:[canvasPngChunk('sBIT',Buffer.from([8,8,8]))]},/metadata/],['sbit-zero',{before:[canvasPngChunk('sBIT',Buffer.from([0,8,8,8]))]},/metadata/],
    ['sbit-large',{before:[canvasPngChunk('sBIT',Buffer.from([9,8,8,8]))]},/metadata/],['sbit-duplicate',{before:[sBIT,sBIT]},/duplicated/],
    ['srgb-length',{before:[canvasPngChunk('sRGB')]},/metadata/],['srgb-value',{before:[canvasPngChunk('sRGB',Buffer.from([4]))]},/metadata/],
    ['phys-length',{before:[canvasPngChunk('pHYs')]},/metadata/],['phys-unit',{before:[canvasPngChunk('pHYs',Buffer.from([0,0,0,0,0,0,0,0,2]))]},/metadata/],
    ['duplicate-metadata',{before:[sRGB,sRGB]},/duplicated/],['nonconsecutive-idat',{idat:[canvasPngChunk('IDAT',Buffer.from([1])),sRGB,canvasPngChunk('IDAT',Buffer.from([2]))]},/follows/],
    ['reserved-bit',{before:[canvasPngChunk('abca')]},/type/],['nonletter',{before:[canvasPngChunk('ab1D')]},/type/],
    ['chunk-count',{idat:Array.from({length:255},()=>canvasPngChunk('IDAT',Buffer.from([1])))},/256-chunk/],
  ];
  for(const [name,options,reason] of negatives)assert.match(inspect(canvasPngUrl(canvasPngFixture(options))).reason,reason,name);
  for(const index of [12,20,32,45,57,69]){const broken=Buffer.from(valid);broken[index]^=1;assert(inspect(canvasPngUrl(broken)).reason,`CRC/type mutation ${index}`);}
  for(let length=0;length<valid.length;length++)assert(inspect(canvasPngUrl(valid.subarray(0,length))).reason,`truncated ${length}`);
  const hugeLength=Buffer.from(valid);hugeLength.writeUInt32BE(0xffffffff,8);assert.match(inspect(canvasPngUrl(hugeLength)).reason,/length/);
  const nonHeader=Buffer.concat([valid.subarray(0,8),canvasPngChunk('IDAT',Buffer.from([1]))]);assert.match(inspect(canvasPngUrl(nonHeader)).reason,/IHDR/);
  const canonical=canvasPngUrl(valid);
  for(const text of [canonical+'\n',canonical.replace('base64,','base64, '),canonical.replace(/==$/,'='),canonical.replace(/==$/,'A==='),canonical.replace('ggg==','ggh==')])assert(inspect(text).reason,'Malformed/noncanonical base64');
  for(const mime of ['jpeg','webp','gif','svg+xml','avif','apng'])assert.match(inspect(canvasText.replace('image/png',`image/${mime}`)).reason,/only static PNG/);
  canvasOwnershipReceipt.push({test:'bounded_png_header_crc_chunk_profile_and_base64_negatives',status:'passed',negativeProfiles:negatives.length,truncatedBoundaries:valid.length,noInflation:true});
}
{
  const fixtures=[
    ['oversized',canvasPngUrl(canvasPngFixture({width:100000,height:100000})),/4096-pixel/],
    ['pixels',canvasPngUrl(canvasPngFixture({width:4096,height:4096})),/4 Mi-pixel/],
    ['animated',canvasPngUrl(canvasPngFixture({after:[canvasPngChunk('acTL',Buffer.alloc(8))]})),/Animated/],
    ['profile',canvasPngUrl(canvasPngFixture({before:[canvasPngChunk('iCCP')]})),/unsupported/],
    ...['jpeg','webp','gif','svg+xml','avif','apng'].map(mime=>[mime,canvasText.replace('image/png',`image/${mime}`),/only static PNG/]),
  ];
  for(const [name,text,reason] of fixtures) {
    const artifact=await canvasArtifact('1',text);let reads=0;
    const c=canvasContext({state:{artifacts:[artifact]},fetch:async()=>{reads++;return new Response(text);}});
    c.events([artifact]);c.render();await canvasSettled(c);
    assert.equal(c.elements.signalRenderList.querySelectorAll('img').length,0,name);assert.equal(c.sourceAssignments.length,0,name);
    assert.match(c.elements.signalRenderList.textContent,reason,name);assert.equal(artifact.content,text,'Retained exact bytes are unchanged');
    assert.match(c.elements.signalRenderList.textContent,/Sensitive Canvas output was captured locally/,'Unsupported preview does not erase capture provenance');
    for(let refresh=0;refresh<20;refresh++)c.render();await canvasSettled(c);assert.equal(reads,1,'No refusal/refetch churn');
    c.api.showScreen('other',{classList:{contains:()=>true}});assert.equal(artifact.content,undefined);
  }
  canvasOwnershipReceipt.push({test:'unsupported_and_oversized_never_assign_src_original_bytes_preserved',status:'passed',cases:fixtures.length});
}
{
  const text=canvasPngUrl(canvasPngFixture({width:2048,height:2048}));
  const artifacts=await Promise.all(Array.from({length:6},(_,i)=>canvasArtifact(String(i+1),text)));
  const c=canvasContext({state:{artifacts},fetch:async()=>new Response(text)});let maxPixels=0;
  c.sandbox.document.createElement=(original=>tag=>{
    const node=original(tag);if(tag==='img')Object.defineProperty(node,'src',{set(value){
      const owner=[...c.state.canvasPreviewOwners.values()].find(owner=>owner.image===node);assert(owner?.mounted&&owner.imageInfo);
      const active=c.sourceAssignments.filter(image=>image.getAttribute('src')).length;maxPixels=Math.max(maxPixels,(active+1)*4*1024*1024);assert(maxPixels<=16*1024*1024);
      c.sourceAssignments.push(node);node.setAttribute('src',value);
    },get(){return node.getAttribute('src')??'';}});return node;
  })(c.sandbox.document.createElement);
  c.events(artifacts);c.render();await canvasSettled(c);
  assert.equal(c.elements.signalRenderList.querySelectorAll('img').length,4);assert.equal(maxPixels,16*1024*1024);
  assert.deepEqual([...c.state.canvasPreviewOwners.values()].filter(owner=>owner.mounted).map(owner=>owner.artifact.artifact_id),['6','5','4','3']);
  assert.match(c.elements.signalRenderList.textContent,/16 Mi-pixel/);
  const oldImages=[...c.elements.signalRenderList.querySelectorAll('img')];
  for(let i=0;i<10;i++)c.render();assert(oldImages.every(image=>image.src));
  assert.deepEqual(c.elements.signalRenderList.querySelectorAll('img'),oldImages,'Unchanged refresh keeps admitted image nodes without overlapping source allocation');
  assert.equal(c.elements.signalRenderList.querySelectorAll('img').length,4);
  c.events(artifacts.slice(0,2));c.render();assert.equal(c.elements.signalRenderList.querySelectorAll('img').length,2);
  assert(artifacts.slice(2).every(artifact=>artifact.content===undefined));
  c.state.signalView='activity';c.render();assert(c.sourceAssignments.every(image=>!image.src));
  canvasOwnershipReceipt.push({test:'aggregate_newest_priority_never_overlaps_old_and_new_sources',status:'passed',maxMountedDeclaredPixels:maxPixels});
}
{
  const artifact=await canvasArtifact('1'),c=canvasContext({state:{artifacts:[artifact]},fetch:async()=>new Response(canvasText)});
  c.events([artifact]);c.render();await canvasSettled(c);
  assert.match(c.elements.signalRenderList.textContent,/Sensitive Canvas output was captured locally/);
  const oldImage=c.elements.signalRenderList.querySelector('img'),owner=c.state.canvasPreviewOwners.values().next().value;
  const pressedSummary=c.elements.signalRenderList.querySelector('summary'),details=pressedSummary.parentNode;
  details.open=true;pressedSummary.focus();
  const sourceCount=c.sourceAssignments.length;
  for(let refresh=0;refresh<200;refresh++)c.render();
  assert.equal(c.elements.signalRenderList.querySelector('summary'),pressedSummary,'Unchanged refresh must retain the pressed native summary until pointer release');
  assert.equal(c.sandbox.document.activeElement,pressedSummary);assert.equal(details.open,true);
  assert.equal(c.sourceAssignments.length,sourceCount,'Unchanged refresh does not reassign image src');
  // The production reader refuses a second write while the verified text is
  // present. Replaced source objects and catalog failure are tested separately.
  c.sandbox.fetch=async()=>{throw new Error('Verified Canvas text must not be fetched or mutated in place');};
  await c.api.loadArtifactContent(artifact,{canvasOwner:owner});assert.equal(artifact.content,canvasText);
  c.state.canvasImageCaptureEnabled=false;c.render();
  assert.notEqual(c.elements.signalRenderList.querySelector('summary'),pressedSummary,'Changed visible input invalidates render cache');
  assert.equal(c.elements.signalRenderList.querySelector('details').open,true,'Genuine update preserves expanded disclosure');
  assert.equal(c.sandbox.document.activeElement,c.elements.signalRenderList.querySelector('summary'),'Genuine update restores disclosure focus');
  c.sandbox.fetch=async()=>new Response(canvasText);
  const currentImage=c.elements.signalRenderList.querySelector('img');
  for(const fail of oldImage.listeners.get('error'))fail();assert.equal(owner.imageError,undefined,'Detached error cannot poison current render');
  for(const fail of currentImage.listeners.get('error'))fail();assert.match(owner.imageError,/could not decode/);
  assert.equal(c.elements.signalRenderList.querySelectorAll('img').length,0);assert.equal(artifact.content,canvasText);
  for(let i=0;i<5;i++)c.render();assert.equal(c.elements.signalRenderList.querySelectorAll('img').length,0);
  c.api.showScreen('other',{classList:{contains:()=>true}});c.screen.hidden=false;c.render();await canvasSettled(c);
  const replacement=c.state.canvasPreviewOwners.values().next().value;assert.notEqual(replacement,owner);assert(replacement.image);
  for(const fail of currentImage.listeners.get('error'))fail();assert.equal(replacement.imageError,undefined,'Old owner error cannot poison reopened owner');
  const forged=c.api.canvasPreview({artifact:{...artifact},dataUrl:canvasText,calls:[],demo:false},'forged','forged',true);
  assert.equal(forged.querySelectorAll('img').length,0,'Copied descriptors cannot reuse owner admission');
  const absent=canvasContext();absent.events([artifact]);absent.render();assert.match(absent.elements.signalRenderList.textContent,/Operation metadata remains available/);
  canvasOwnershipReceipt.push({test:'decoder_error_visible_retained_bytes_stale_dom_and_owner_events_ignored',status:'passed'});
}
{
  const artifact=await canvasArtifact('1'),c=canvasContext({state:{artifacts:[artifact]},fetch:async()=>new Response(canvasText)});
  c.events([artifact]);c.render();await canvasSettled(c);
  const original=c.elements.signalRenderList.querySelector('summary'),oldImage=c.elements.signalRenderList.querySelector('img');
  const originalCaptures=c.sandbox.canvasRenderCaptures;
  c.sandbox.canvasRenderCaptures=events=>originalCaptures(events).map(capture=>({...capture,calls:[{name:'fillRect',arguments:[],observedOnly:true}]}));
  c.render();assert.notEqual(c.elements.signalRenderList.querySelector('summary'),original,'Changed calls replace stale cards');assert.equal(oldImage.src,'');
  const currentImage=c.elements.signalRenderList.querySelector('img');
  c.state.artifactReceiverError='Catalog unavailable';c.render();
  assert.equal(currentImage.src,'');assert.equal(c.elements.signalRenderList.querySelectorAll('img').length,0);
  assert.equal(c.state.canvasPreviewOwners.size,0,'Catalog error retires every owner');
  c.state.artifactReceiverError=null;
  const replacement=await canvasArtifact('1',canvasText,'2');c.state.artifacts=[replacement];c.events([replacement]);c.render();await canvasSettled(c);
  assert.notEqual(c.elements.signalRenderList.querySelector('summary'),original,'New session cannot reuse old disclosure');
  assert(c.elements.signalRenderList.querySelector('img'));
  c.events([]);c.render();assert.equal(c.elements.signalRenderList.querySelectorAll('img').length,0);assert.equal(c.state.canvasPreviewOwners.size,0);
  canvasOwnershipReceipt.push({test:'unchanged_pressed_summary_and_image_stability_changed_inputs_catalog_failure_and_scope_invalidation',status:'passed',unchangedRefreshes:200});
}
console.log('PASS Canvas PNG admission before img.src: declared axes/per-image/gallery pixels, narrow static RGB/RGBA8 profile, CRC/chunk/base64 validation, no inflation, exact owners and stale decoder-error protection (not decoder-memory or rendered QA)');

console.log('PASS Canvas gallery ownership: hidden/visible 480-entry growth, 24 owners / 8 MiB UTF-16 reservations, two unsettled reads, no churn, scope/navigation/DOM cleanup, session replacement, stale headers and explicit retry (no image decoding or RSS claim)');
if(process.env.REB_CANVAS_OWNERSHIP_RECEIPT)await writeFile(process.env.REB_CANVAS_OWNERSHIP_RECEIPT,JSON.stringify({scope:'Production-function and DOM ownership accounting, not image decoding or process RSS',results:canvasOwnershipReceipt},null,2));

if (process.env.REB_SOURCE_OWNERSHIP_RECEIPT) await writeFile(process.env.REB_SOURCE_OWNERSHIP_RECEIPT, JSON.stringify({scope:'Production-function and DOM fixtures; not rendered acceptance',results:sourceOwnershipReceipt},null,2));

// The decoded-field handoff must never silently rebind a chain to edited input
// or another request, or turn a binary/preview result into a source-text match.
const fieldHandoff = runInNewContext(
  (await readFile(join(root, "apps/research-ui/field_provenance.js"), "utf8")) +
    `;function decoderCurrentInputKey() {return currentKey;}
    ({decodedFieldCandidate, clearDecoderFieldOrigin, provenanceDecoderBytes,
      setup(selection, steps, selected, key = 'original') {
        fieldProvenanceSelection = selection;
        decoderFieldOrigin = {selection, key: 'original'};
        state.decoderSteps = steps; state.decoderSelectedStepId = selected;
        state.decoderPending = false; currentKey = key;
      }, changeField() {fieldProvenanceSelection = {};}, pending() {state.decoderPending = true;}})`,
  {
    TextDecoder,
    TextEncoder,
    URL,
    document: { querySelector: () => ({ hidden: true, addEventListener() {} }) },
    state: {},
    currentKey: "original",
    decoderBase64ToBytes: (value) => new Uint8Array(Buffer.from(value, "base64")),
  },
);
const candidateStep = (id, value) => ({
  id, operation: "base64-decode", input_bytes: 32,
  output_bytes: Buffer.byteLength(value), output_base64: Buffer.from(value).toString("base64"),
});
const field = { value: "original", selector: "/payload" };
const steps = [candidateStep(1, "intermediate"), candidateStep(2, "\ufeff雪\r\n<script>inert</script>")];
fieldHandoff.setup(field, steps, 2);
const candidate = fieldHandoff.decodedFieldCandidate();
assert.equal(candidate.value, "\ufeff雪\r\n<script>inert</script>");
assert.equal(candidate.steps.length, 2);
assert.equal(field.value, "original");
fieldHandoff.setup(field, steps, 1);
assert.equal(fieldHandoff.decodedFieldCandidate().steps.length, 1);
fieldHandoff.setup(field, steps, null);
assert.match(fieldHandoff.decodedFieldCandidate().error, /completed transformation/);
fieldHandoff.setup(field, steps, 2, "edited");
assert.match(fieldHandoff.decodedFieldCandidate().error, /Input changed/);
fieldHandoff.setup(field, steps, 2);
fieldHandoff.changeField();
assert.match(fieldHandoff.decodedFieldCandidate().error, /field changed/);
fieldHandoff.setup(field, steps, 2);
fieldHandoff.pending();
assert.match(fieldHandoff.decodedFieldCandidate().error, /Wait/);
fieldHandoff.setup(field, [candidateStep(1, "x".repeat(4096))], 1);
assert.equal(fieldHandoff.decodedFieldCandidate().value.length, 4096);
for (const value of ["", "雪".repeat(1366)]) {
  fieldHandoff.setup(field, [candidateStep(1, value)], 1);
  assert.match(fieldHandoff.decodedFieldCandidate().error, /4 KiB/);
}
fieldHandoff.setup(field, [{ ...candidateStep(1, "x"), output_base64: "/w==" }], 1);
assert.match(fieldHandoff.decodedFieldCandidate().error, /Binary/);
fieldHandoff.clearDecoderFieldOrigin();
assert.match(fieldHandoff.decodedFieldCandidate().error, /Start from/);
const vmDispatchSample = {
  protocol_version: 2,
  session_id: "1", sequence_number: "1", monotonic_time_ns: "1",
  navigation_id: "1", frame_id: "1", artifact_id: "1", parent_event_id: "0",
  request_id: "0", browser_context_id_high: "0", browser_context_id_low: "0",
  process_id: 1, thread_id: 1, initiator_request_id: 0, initiator_process_id: 0,
  resource_type: 0, flags: 0, status_code: 0, error_code: 0,
  encoded_data_length: "0", decoded_body_length: "0",
  category: "vm", type: "vm_dispatch_sample",
  payload_size: 128, payload_encoding: "hex", payload: "0100800000000000500000000000000000000000000000000100000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  payload_truncated: false,
};
assert.equal(ui.isBrokerEvent(vmDispatchSample), true);
assert.equal(fieldHandoff.provenanceDecoderBytes("\ud800"), null);
assert.equal(fieldHandoff.provenanceDecoderBytes("\udc00"), null);
assert.equal(new TextDecoder("utf-8", {ignoreBOM: true}).decode(
  fieldHandoff.provenanceDecoderBytes("\ufeff雪\r\n😀")), "\ufeff雪\r\n😀");
console.log('PASS decoded field identity, chain prefix, UTF-8 and bounds');
async function sourceFactsBrowserFixture() {
  const text = '\ufeffconst 雪 = "😀";\nfunction shadow(雪) { return 雪; }\n雪;';
  const bytes = Buffer.from(text);
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)), byte=>byte.toString(16).padStart(2,'0')).join('');
  const artifact = id => ({protocol_version:1,artifact_id:id,session_id:'11',navigation_id:'13',frame_id:'17',parent_artifact_id:'0',creator_event_id:'19',execution_context_id:'23',capture_origin:'dynamic_javascript',kind:'javascript',url:`https://fixture.invalid/facts-${id}.js`,mime_type:'text/javascript',byte_size:bytes.length,sha256:hash,sensitive:false});
  const artifacts = [artifact('7'),artifact('8')];
  const snow = Buffer.byteLength('\ufeffconst ');
  const documents = new Map(artifacts.map(source=>[source.artifact_id,bytes]));
  const fixture = {mode:'partial',pending:[],requests:[],artifacts,bytes,snow,documents,
    previewMode:'ready',previewPending:[],deobMode:'ready',deobPending:[],analysisRequests:[],previewRequests:[],
    rejectedWrites:[],factsReports:new Map()};
  fixture.addSource = async (id,text) => {
    const content=Buffer.from(text),source={...artifact(id),byte_size:content.length,sha256:await ownershipHash(content)};
    artifacts.push(source);documents.set(id,content);return source;
  };
  const report = source => ({schema:'reb-javascript-source-facts-v1',profile:'lexical-effects-v1',offset_unit:'utf-8-byte',source_bytes:bytes.length,source,ok:fixture.mode!=='unavailable',
    scopes:fixture.mode==='unavailable'?[]:[{id:0,parent_id:null,range:{start:0,end:bytes.length},kind:'program'}],
    regions:fixture.mode==='unavailable'?[]:[{id:0,parent_id:null,callable_id:null,range:{start:0,end:bytes.length},kind:'program',entry_order:0}],
    bindings:fixture.mode==='unavailable'?[]:[{id:0,scope_id:0,name:'雪',range:{start:snow,end:snow+3},kind:'const'}],callables:[],
    operations:fixture.mode==='unavailable'?[]:Array.from({length:205},(_,id)=>({id,region_id:0,order:id,range:{start:snow,end:snow+3},kind:'read',detail:{target:{kind:'binding',binding_ids:[0],resolution:'lexical-only',name:'雪'}}})),
    coverage:{status:fixture.mode==='unavailable'?'unavailable':fixture.mode==='complete'?'complete':'partial',truncated:fixture.mode==='truncated',diagnostics:fixture.mode==='unavailable'?['Synthetic parse rejection']:[],frontiers:['unavailable','complete'].includes(fixture.mode)?[]:[{range:{start:snow,end:snow+3},reason:'abrupt-completion'}]},
    limits:{max_source_bytes:4194304,max_ast_nodes:32768,max_facts:16384,max_frontiers:256,max_binding_candidates:64,preflight_depth:128,preflight_nodes:500000}});
  fixture.handle = async (request,response) => {
    const url = new URL(request.url,'http://127.0.0.1');
    const json = (status,value) => {if(!response.destroyed){response.writeHead(status,{'Content-Type':'application/json'});response.end(JSON.stringify(value));}};
    // Every route is read-only. Record attempted writes instead of serving them.
    if((request.method??'GET')!=='GET'){
      fixture.rejectedWrites.push({method:request.method,path:url.pathname});
      json(405,{error:'The Sources fixture is read-only'});return true;
    }
    if(url.pathname==='/api/events'){json(200,{count:0,events:[],capture_mode:'demo',broker_connected:false,capture_controls_available:false});return true;}
    if(url.pathname==='/api/artifacts'){json(200,{count:artifacts.length,artifacts});return true;}
    if(url.pathname==='/api/source-facts'){
      fixture.requests.push(url.search);
      const source=artifacts.find(value=>value.artifact_id===url.searchParams.get('artifact_id') && value.session_id===url.searchParams.get('session_id'));
      if(!source){json(404,{error:'Synthetic exact source not found'});return true;}
      if(fixture.mode==='pending') await new Promise(resolve=>fixture.pending.push(resolve));
      if(fixture.mode==='error'){json(503,{error:fixture.errorMessage??'Synthetic worker unavailable',code:'dependency_unavailable',details:{}});return true;}
      const value=fixture.factsReports.has(source.artifact_id)?{...fixture.factsReports.get(source.artifact_id),source}:report(source);
      if(fixture.mode==='malformed') value.source={...source,sha256:'b'.repeat(64)};
      json(200,value);return true;
    }
    if(url.pathname==='/api/deobfuscation'){
      fixture.analysisRequests.push(url.search);
      const source=artifacts.find(value=>value.artifact_id===url.searchParams.get('artifact_id'));
      if(!source){json(404,{error:'Synthetic source unavailable'});return true;}
      const text=documents.get(source.artifact_id).toString('utf8');
      if(fixture.deobMode==='error'){json(503,{error:'Authored analyzer retry failure'});return true;}
      const payload=fixture.changedSource&&source.artifact_id===fixture.changedSource?ownedDerivedPayload(source,text,Array.from({length:7},(_,i)=>[`1+${i}`,`(${i+1})`])):ownedPayload(source,text);
      if(fixture.changedSource&&source.artifact_id===fixture.changedSource){
        payload.analysis.omissions=['Unsupported runtime behavior remains unresolved.'];
        payload.analysis.string_tables=Array.from({length:5},(_,i)=>({kind:`table-${i+1}`,offset:0,entry_count:8,encodings:['literal'],decoded_preview:'<script>inert fixture</script>'}));
      }
      payload.analysis.source.sha256=await ownershipHash(text);
      payload.analysis.source.lines=text.split('\n').length;
      payload.analysis.assumptions=url.searchParams.get('assume_intrinsics')==='1'?['standard-intrinsics']:[];
      if(fixture.deobMode==='wrong-id')payload.artifact_id='999';
      if(fixture.deobMode==='wrong-hash')payload.analysis.source.sha256='b'.repeat(64);
      if(fixture.deobMode==='pending')await new Promise(resolve=>fixture.deobPending.push(resolve));
      json(200,payload);return true;
    }
    if(/^\/api\/artifacts\/[0-9]+\/content$/.test(url.pathname)){
      const id=url.pathname.split('/')[3], content=documents.get(id);
      if(!content){json(404,{error:'Synthetic artifact unavailable'});return true;}
      fixture.previewRequests.push(id);
      const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||2097152);
      const chunk=Buffer.from(content.subarray(offset,offset+limit)),mode=fixture.previewMode;
      if(mode==='wrong-bytes' && chunk.length)chunk[0]^=1;
      response.writeHead(200,{'Content-Type':'application/octet-stream','X-Artifact-Total-Bytes':String(content.length),'X-Artifact-Offset':String(offset),'X-Artifact-Truncated':String(offset+chunk.length<content.length)});
      if(mode==='pending-body'){response.flushHeaders?.();await new Promise(resolve=>fixture.previewPending.push(resolve));}
      if(!response.destroyed)response.end(chunk);return true;
    }
    return false;
  };
  fixture.releasePreview = () => {for(const resolve of fixture.previewPending.splice(0)) resolve();};
  fixture.release = () => {for(const resolve of [...fixture.pending.splice(0),...fixture.previewPending.splice(0),...fixture.deobPending.splice(0)]) resolve();};
  return fixture;
}

// Keep fixture routing admissible to the normal refresh path before launching
// Chrome; a blanket offline events response would prevent artifact discovery.
const sourcesFixtureControl = await sourceFactsBrowserFixture();
const sourcesFixtureModels = runInNewContext((await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8'))+';({isBrokerResponse,isArtifactResponse})',{TextEncoder});
async function sourcesFixtureResponse(url) {
  const response={destroyed:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(body){this.body=body;}};
  assert(await sourcesFixtureControl.handle({url},response));return response;
}
const sourcesEventsControl=await sourcesFixtureResponse('/api/events?limit=5000');
assert.equal(sourcesEventsControl.status,200);assert(sourcesFixtureModels.isBrokerResponse(JSON.parse(sourcesEventsControl.body)));
const sourcesArtifactsControl=await sourcesFixtureResponse('/api/artifacts?limit=500');
assert.equal(sourcesArtifactsControl.status,200);assert(sourcesFixtureModels.isArtifactResponse(JSON.parse(sourcesArtifactsControl.body)));
const sourcesFactsControl=await sourcesFixtureResponse('/api/source-facts?session_id=11&artifact_id=7');
assert.equal(JSON.parse(sourcesFactsControl.body).source.artifact_id,'7');
assert.equal((await sourcesFixtureResponse('/api/source-facts?session_id=12&artifact_id=7')).status,404);
const sourcesBytesControl=await sourcesFixtureResponse('/api/artifacts/7/content?offset=0&limit=2097152');
assert.equal(sourcesBytesControl.headers['X-Artifact-Truncated'],'false');assert.deepEqual(sourcesBytesControl.body,sourcesFixtureControl.bytes);
const analysisControl=JSON.parse((await sourcesFixtureResponse('/api/deobfuscation?artifact_id=7&mode=derived')).body);
assert.equal(analysisControl.artifact_id,'7');assert.equal(analysisControl.script_id,null);
assert.equal(analysisControl.analysis.source.sha256,await ownershipHash(analysisControl.original_source));
const rejectedControl={destroyed:false,writeHead(status){this.status=status;},end(){}};
assert(await sourcesFixtureControl.handle({url:'/api/artifacts',method:'POST'},rejectedControl));assert.equal(rejectedControl.status,405);
assert.equal(sourcesFixtureControl.rejectedWrites.length,1);
console.log('PASS Sources browser fixture event/artifact admission, exact source text, inert analysis replies and read-only routes (not rendered QA)');
await checkSourcesHistoryFixture(await sourceFactsBrowserFixture(),root);
await checkSourcesTreeFixture(await sourceFactsBrowserFixture(),root);

// Test-only observation of the actual loader promises. Each wrapper calls its
// loader exactly once with the original receiver/arguments and returns the same
// promise. Receipts contain identities/status only, never source text or payloads.
function sourceOwnershipOperationObserver(loaders, identify) {
  const entries=new Map(),failures=[];let sequence=0,failureCount=0,pendingCount=0;
  const settle=(entry,status,error)=>{
    entry.status=status;entry.settled_at=Date.now();pendingCount--;
    if(status!=='fulfilled'){
      entry.error_name=String(error?.name??'Error').slice(0,64);entry.error_message=String(error?.message??error).slice(0,256);
      failureCount++;failures.push({...entry});if(failures.length>64)failures.shift();
    }
  };
  const observe=(promise,entry)=>{promise.then(()=>settle(entry,'fulfilled'),error=>settle(entry,'rejected',error));};
  const wrappers=Object.fromEntries(Object.entries(loaders).map(([kind,loader])=>[kind,function(...args){
    const entry={id:++sequence,kind,identity:identify(args[0]),status:'pending',started_at:Date.now(),settled_at:null};
    entries.set(entry.id,entry);pendingCount++;
    // This observer is installed only for the three held-operation cases.
    // Overflow fails receipt lookup rather than changing production execution.
    while(entries.size>64)entries.delete(entries.keys().next().value);
    try {const promise=Reflect.apply(loader,this,args);observe(promise,entry);return promise;}
    catch(error){settle(entry,'threw',error);throw error;}
  }]));
  return {wrappers,read:id=>entries.has(id)?{...entries.get(id)}:null,failures:()=>({count:failureCount,pending:pendingCount,entries:failures.map(entry=>({...entry}))}),
    pending:(kind,identity)=>[...entries.values()].filter(entry=>entry.kind===kind&&entry.identity===identity&&entry.status==='pending').map(entry=>({...entry}))};
}

async function waitForSourceOwnershipSettlement(read,expected,timeoutMs=5000) {
  const deadline=Date.now()+timeoutMs;
  do {
    const entry=await read(expected.id);
    assert(entry&&entry.id===expected.id&&entry.kind===expected.kind&&entry.identity===expected.identity,'Held source operation lost its exact receipt');
    if(entry.status!=='pending'){
      assert(['fulfilled','rejected','threw'].includes(entry.status)&&Number.isFinite(entry.settled_at),'Invalid source terminal receipt');
      return entry;
    }
    const remaining=deadline-Date.now();
    if(remaining<=0)break;
    await new Promise(resolve=>setTimeout(resolve,Math.min(25,remaining)));
  } while(Date.now()<=deadline);
  assert.fail(`Held ${expected.kind} source operation ${expected.id} did not settle within ${timeoutMs} ms`);
}

// A completion later than the old 50 ms sleep must be observed before accepting
// no-stale-commit assertions. Stalled work must fail closed, not pass on timeout.
const settlementReceiver={receiver:'unchanged'};
let releaseObserved,rejectObserved,observedCalls=0,lateObservedCommit=false;
const delayedObserved=new Promise(resolve=>{releaseObserved=resolve;});
const rejectedObserved=new Promise((resolve,reject)=>{rejectObserved=reject;});
const settlementObserver=sourceOwnershipOperationObserver({
  live:function(source,extra){assert.equal(this,settlementReceiver);assert.equal(source.identity,'exact-owner');assert.equal(extra,'unchanged');observedCalls++;return delayedObserved;},
  analysis:()=>rejectedObserved,stalled:()=>new Promise(()=>{}),
},source=>source.identity);
assert.equal(settlementObserver.wrappers.live.call(settlementReceiver,{identity:'exact-owner'},'unchanged'),delayedObserved);
assert.equal(observedCalls,1);
const observedPending=settlementObserver.pending('live','exact-owner');assert.equal(observedPending.length,1);
setTimeout(()=>{lateObservedCommit=true;releaseObserved();},180);
const observedTerminal=await waitForSourceOwnershipSettlement(settlementObserver.read,observedPending[0]);
assert.equal(observedTerminal.status,'fulfilled');assert(lateObservedCommit,'Settlement accepted before the obsolete completion');
assert.throws(()=>assert.equal(lateObservedCommit,false),'A late stale commit must fail the post-settlement acceptance');
assert.equal(settlementObserver.wrappers.analysis({identity:'exact-owner'}),rejectedObserved);
const rejectedPending=settlementObserver.pending('analysis','exact-owner')[0];rejectObserved(new Error('Synthetic cancellation'));
assert.equal((await waitForSourceOwnershipSettlement(settlementObserver.read,rejectedPending)).status,'rejected');
assert.equal(settlementObserver.failures().count,1);assert.equal(settlementObserver.failures().entries[0].error_message,'Synthetic cancellation');
settlementObserver.wrappers.stalled({identity:'exact-owner'});
await assert.rejects(waitForSourceOwnershipSettlement(settlementObserver.read,settlementObserver.pending('stalled','exact-owner')[0],60),/did not settle/);
await assert.rejects(waitForSourceOwnershipSettlement(settlementObserver.read,{...observedPending[0],identity:'other-owner'}),/exact receipt/);
console.log('PASS Sources held-operation terminal receipts: same promise/arguments/receiver, delayed stale-commit refusal, rejection, exact identity and bounded nonsettlement (not rendered QA)');

const observationSourceBytes = Buffer.from('// Synthetic capture fixture.\nfunction collect() { return "metadata"; }\n');
const observationSourceHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', observationSourceBytes)), byte => byte.toString(16).padStart(2, '0')).join('');
function observationEvent(sequence, category, type, text, extra = {}) {
  const payload = Buffer.from(text);
  return {protocol_version:3,session_id:'7',sequence_number:String(sequence),monotonic_time_ns:String(1320000000n + BigInt(sequence) * 100000n),
    navigation_id:'101',frame_id:'301',artifact_id:'0',parent_event_id:'0',request_id:'0',process_id:42,thread_id:44,
    browser_context_id_high:'0',browser_context_id_low:'0',tab_id:3,initiator_request_id:0,initiator_process_id:0,
    encoded_data_length:'0',decoded_body_length:'0',status_code:0,error_code:0,resource_type:13,flags:0,
    category,type,payload_encoding:'hex',payload_size:payload.length,payload:payload.toString('hex'),payload_truncated:false,...extra};
}
function observationFixtureContext() {
  const events = [
    observationEvent(100,'navigator','property_read','Navigator.hardwareConcurrency'),
    observationEvent(101,'canvas','api_call','CanvasRenderingContext2D.fillText',{parent_event_id:'99',artifact_id:'9'}),
    observationEvent(102,'canvas','api_call','HTMLCanvasElement.toDataURL',{parent_event_id:'101',artifact_id:'9'}),
    observationEvent(103,'network','request_initiated','POST telemetry.fixture.invalid',{parent_event_id:'102',request_id:'9'}),
    observationEvent(104,'webgl','api_call','WebGLRenderingContext.getParameter',{artifact_id:'12'}),
    observationEvent(105,'permissions','api_call','Permissions.query'),
    observationEvent(106,'network','request_completed','telemetry.fixture.invalid',{parent_event_id:'103',request_id:'9',status_code:204}),
    observationEvent(106,'runtime','gap','2'),
    observationEvent(1,'webrtc','api_call','RTCPeerConnection.getStats',{process_id:77,navigation_id:'202',frame_id:'404'})
  ];
  const artifacts = [{protocol_version:1,session_id:'7',artifact_id:'9',navigation_id:'101',frame_id:'301',parent_artifact_id:'0',creator_event_id:'95',execution_context_id:'23',capture_origin:'network_response',kind:'javascript',url:'https://fixture.invalid/assets/collector.js',mime_type:'text/javascript',byte_size:observationSourceBytes.length,sha256:observationSourceHash,sensitive:false}];
  return {events,artifacts,request:{id:'evidence-investigation-request',origin:'live',method:'POST',path:'telemetry.fixture.invalid',hostOnly:true,events:events.filter(event=>event.category==='network')},eventsLimited:false};
}
const observationCode = (await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8')) + '\n' + packageSource;
const observationUI = runInNewContext(observationCode + ';({evidenceObservationModel,evidenceRequestKey,evidenceArtifactReference,isBrokerResponse,isArtifactResponse})', {TextDecoder, Uint8Array});
const nativeNetworkProjection = runInNewContext(observationCode + ';({requestsFromEvents,evidenceObservationOutcome,evidenceObservationLabel,evidencePayload})', {TextDecoder, Uint8Array});
for (const disposition of ['proxy_destroyed', 'redirect_handoff']) {
  const interrupted = observationEvent(109, 'network', 'request_failed', disposition, {request_id:'19', error_code:-3});
  const row = nativeNetworkProjection.requestsFromEvents([interrupted])[0];
  assert.equal(row.status, 'incomplete');
  assert.equal(Boolean(row.failed), false);
  assert.match(nativeNetworkProjection.evidenceObservationOutcome(interrupted), /final network outcome unavailable/);
  assert.equal(nativeNetworkProjection.evidenceObservationLabel(interrupted, nativeNetworkProjection.evidencePayload(interrupted)), 'Network observation ended');
  const actualError = {...interrupted, error_code:-7};
  assert.equal(nativeNetworkProjection.requestsFromEvents([actualError])[0].status, 'failed');
  assert.match(nativeNetworkProjection.evidenceObservationOutcome(actualError), /Failure recorded/);
}
console.log('PASS native proxy teardown/handoff is incomplete observation, real network failures preserved');
const observationContext = observationFixtureContext();
assert(observationUI.isBrokerResponse({count:observationContext.events.length,events:observationContext.events,capture_mode:'demo'}));
assert(observationUI.isArtifactResponse({count:observationContext.artifacts.length,artifacts:observationContext.artifacts}));
const observationModel = observationUI.evidenceObservationModel(observationContext);
assert.deepEqual(Array.from(observationModel.rows.filter(row=>row.group==='parent'),row=>row.key),['7:42:101','7:42:102']);
assert.deepEqual(Array.from(observationModel.rows.filter(row=>row.group==='request'),row=>row.key),['7:42:103','7:42:106']);
assert.equal(observationModel.rows.find(row=>row.key==='7:42:100').group,'context');
assert.equal(observationModel.rows.find(row=>row.key==='7:77:1').group,'unlinked');
assert.equal(observationModel.missingParents,1); assert.equal(observationModel.queueMarkers,1);
assert.equal(observationModel.rows.find(row=>row.key==='7:42:102').outcome,'Outcome not recorded');
assert.equal(observationModel.rows.find(row=>row.key==='7:42:104').artifact.status,'missing');
assert.equal(observationModel.linkedArtifacts,1);
const cachedObservationContext=observationFixtureContext();cachedObservationContext.artifacts[0].content='large cached source'.repeat(200000);cachedObservationContext.artifacts[0].deobfuscation={original_source:cachedObservationContext.artifacts[0].content};cachedObservationContext.events[0].unexpected_payload=cachedObservationContext.artifacts[0].content;
const cachedObservationModel=observationUI.evidenceObservationModel(cachedObservationContext);
assert(JSON.stringify(cachedObservationModel).length<16000,'Evidence render state must never retain or stringify cached source/analysis text or unknown event fields');
assert(!Object.hasOwn(cachedObservationModel.rows.find(row=>row.artifact.artifact)?.artifact.artifact,'content'));
const longURLContext=observationFixtureContext();longURLContext.artifacts[0].url='x'.repeat(1000000);
assert.equal(observationUI.evidenceObservationModel(longURLContext).rows.find(row=>row.artifact.artifact).artifact.artifact.url.length,2048);
const observationUnknown=structuredClone(observationContext);observationUnknown.events[0].frame_id='0';
assert.equal(observationUI.evidenceObservationModel(observationUnknown).rows[0].group,'unlinked');
const observationForeign=structuredClone(observationContext);observationForeign.events[0].session_id='8';
assert.equal(observationUI.evidenceObservationModel(observationForeign).rows[0].group,'unlinked');
const observationCollision=structuredClone(observationContext);observationCollision.events.push({...observationCollision.events[2]});
assert.equal(observationUI.evidenceObservationModel(observationCollision).rows.find(row=>row.key==='7:42:102').group,'unlinked');
observationCollision.artifacts.push({...observationCollision.artifacts[0],session_id:'8'});
assert.equal(observationUI.evidenceObservationModel(observationCollision).rows.find(row=>row.key==='7:42:101').artifact.status,'ambiguous');
const observationReused={...observationContext.request,events:observationContext.request.events.map(event=>({...event,session_id:'8'}))};
assert.notEqual(observationUI.evidenceRequestKey(observationContext.request),observationUI.evidenceRequestKey(observationReused));
const observationLarge={...observationContext,request:null,events:Array.from({length:6000},(_,index)=>observationEvent(index+1,'runtime','api_call','Date.now'))};
const largeObservationModel=observationUI.evidenceObservationModel(observationLarge);
assert.equal(largeObservationModel.rows.length,5000);assert.equal(largeObservationModel.limited,true);assert.equal(largeObservationModel.rows[0].key,'7:42:1001');
const observationCycle=structuredClone(observationContext);observationCycle.events[1].parent_event_id='102';
assert.equal(observationUI.evidenceObservationModel(observationCycle).parentCycle,true);
const observationBinary=structuredClone(observationContext);observationBinary.events[0].payload='ff';observationBinary.events[0].payload_size=1;
assert.equal(observationUI.evidenceObservationModel(observationBinary).rows[0].payload.encoding,'hex');
console.log('PASS Evidence observation model: contract-valid records, scoped parents, nonzero context, unknown outcomes, exact artifact identity, ambiguity, eviction and bounds');

function observationPanelFixture(narrow = false, options = {}) {
  const document={activeElement:null};
  class ObservationNode extends TrafficFixtureNode {
    matches(selector) {
      const match=selector.match(/^(?:(\w+))?\[([\w-]+)(?:="([^"]*)")?\]$/);
      if(match){const [,tag,name,value]=match; const actual=name.startsWith('data-')?this.dataset[name.slice(5).replace(/-([a-z])/g,(_,letter)=>letter.toUpperCase())]:this.getAttribute(name);return (!tag||this.tagName.toLowerCase()===tag)&&actual!==null&&actual!==undefined&&(value===undefined||actual===value);}
      return super.matches(selector);
    }
    // Model the browser's disabled-focus fixup only for the native-key regression.
    set disabled(value){this._disabled=Boolean(value);if(options.nativeFocus&&this._disabled&&document.activeElement===this)document.activeElement=document.body;}
    get disabled(){return Boolean(this._disabled);}
    focus(){if(!options.nativeFocus||!this.disabled)document.activeElement=this;}
    scrollIntoView(){}
    removeEventListener(type,fn){this.listeners.set(type,(this.listeners.get(type)||[]).filter(listener=>listener!==fn));}
    replaceChildren(...nodes){if(this.contains(document.activeElement))document.activeElement=null;super.replaceChildren(...nodes);}
    emit(type,fields={}){for(const callback of this.listeners.get(type)??[])callback({target:this,currentTarget:this,preventDefault(){},stopPropagation(){},...fields});}
  }
  document.createElement=tag=>new ObservationNode(tag);document.body=new ObservationNode('body');document.documentElement=new ObservationNode('html');if(options.native)document.documentElement.classList.add('native-shell');
  const ids=['evidence-investigation','evidence-rows','evidence-inspector','evidence-search','evidence-scope','evidence-workspace-notice','evidence-package-toggle','evidence-package-mode','evidence-return','evidence-trace','evidence-window-count','evidence-previous','evidence-next','evidence-context-kind','evidence-context-title','evidence-context-note','evidence-count','evidence-coverage-summary','evidence-gap-details','evidence-coverage-details','evidence-coverage-popover','evidence-compare-toggle','evidence-comparison-section','evidence-comparison-panel','evidence-comparison-close','evidence-comparison-unavailable','evidence-package-panel'];
  const nodes=Object.fromEntries(ids.map(id=>[id,new ObservationNode()]));
  document.querySelector=selector=>nodes[selector.slice(1)]??null;
  const layout=new ObservationNode();layout.className='evidence-investigation-layout';
  const tabs=['observations','detail'].map(value=>{const tab=new ObservationNode('button');tab.dataset.evidencePane=value;return tab;});
  nodes['evidence-coverage-details'].append(new ObservationNode('summary'),nodes['evidence-coverage-popover']);
  nodes['evidence-investigation'].append(nodes['evidence-coverage-details'],layout,...tabs);layout.append(nodes['evidence-rows'],nodes['evidence-inspector']);
  let context=observationFixtureContext(),packageVisible=false,packageCancels=0,sourceCalls=0;
  let comparisonFetch=options.fetcher || (async()=>Response.json(comparisonResult));
  nodes['evidence-package-mode'].append(nodes['evidence-package-panel'],nodes['evidence-comparison-section']);
  nodes['evidence-comparison-section'].append(nodes['evidence-comparison-close'],nodes['evidence-comparison-unavailable'],nodes['evidence-comparison-panel']);
  const create=runInNewContext(observationCode+'\n'+comparisonSource+';createEvidenceWorkspace',{document,TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout,clearTimeout,fetch:(...args)=>comparisonFetch(...args),location:{protocol:options.protocol||'http:'},window:{matchMedia:()=>({matches:narrow})}});
  const panel=create({getContext:()=>context,packagePanel:{sync(){},setVisible(value){packageVisible=value;if(!value)packageCancels++;}},onTrace(){},onRequest(){},onSource(){sourceCalls++;return true;},canOpenSource:()=>true});
  panel.setVisible(true);
  return {panel,nodes,tabs,document,get context(){return context;},set context(value){context=value;},get packageVisible(){return packageVisible;},get packageCancels(){return packageCancels;},get sourceCalls(){return sourceCalls;}};
}
const observations=observationPanelFixture();
const observationRows=()=>observations.nodes['evidence-rows'].querySelectorAll('[data-evidence-key]');
assert.equal(observationRows().length,7);
assert.equal(observations.nodes['evidence-coverage-summary'].textContent,'1 missing parent · coverage unknown');
assert.match(observations.nodes['evidence-gap-details'].textContent,/1 missing or ambiguous parent references/);
observationRows().find(row=>row.dataset.evidenceKey==='7:42:102').click();
const stableObservationInspector=observations.nodes['evidence-inspector'].children[0];
const provenanceSummary=observations.nodes['evidence-inspector'].querySelector('summary');
observations.nodes['evidence-inspector'].querySelector('details').open=true;provenanceSummary.focus();observations.nodes['evidence-inspector'].scrollTop=127;observations.panel.sync();
assert.equal(observations.nodes['evidence-inspector'].children[0],stableObservationInspector,'Unchanged refresh must preserve the inspector DOM');
assert.equal(observations.document.activeElement,provenanceSummary);assert.equal(observations.nodes['evidence-inspector'].scrollTop,127);
assert.match(observations.nodes['evidence-inspector'].textContent,/Outcome not recorded/);
assert.doesNotMatch(observationRows()[0].textContent,/session 7|process 42/,'First-view rows must not be dominated by identifiers');
observations.nodes['evidence-package-toggle'].click();assert.equal(observations.packageVisible,true);
observations.nodes['evidence-return'].click();assert.equal(observations.packageVisible,false);assert.equal(observations.panel.snapshot().selectedKey,'7:42:102');
assert.equal(observations.document.activeElement,observations.nodes['evidence-package-toggle']);
// A stale source button must not reinterpret the selected event's reference.
const staleSourceButton=observations.nodes['evidence-inspector'].querySelector('[data-evidence-action="source"]');
observations.context={...observations.context,artifacts:[]};staleSourceButton.click();assert.equal(observations.sourceCalls,0);
assert.match(observations.nodes['evidence-inspector'].textContent,/absent from the retained catalog/);
observations.context=observationFixtureContext();observations.panel.sync();
const retainedRow=observationRows().find(row=>row.dataset.evidenceKey==='7:42:102');retainedRow.focus();observations.nodes['evidence-rows'].scrollTop=89;
observations.context.events.push(observationEvent(108,'runtime','api_call','Date.now'));observations.panel.sync();
assert.equal(observations.document.activeElement.dataset.evidenceKey,'7:42:102');assert.equal(observations.nodes['evidence-rows'].scrollTop,89);
observations.context={...observations.context,events:observations.context.events.filter(event=>event.sequence_number!=='102')};observations.panel.sync();
assert.equal(observations.panel.snapshot().selectedKey,null);assert.match(observations.nodes['evidence-workspace-notice'].textContent,/left the retained window/);
observations.panel.sync();assert.equal(observations.panel.snapshot().selectedKey,null,'Eviction must not silently choose a neighboring record');
observations.context=observationLarge;observations.panel.sync();assert.equal(observationRows().length,50);observations.nodes['evidence-next'].click();assert.match(observations.nodes['evidence-window-count'].textContent,/51–100 of 5000/);
observationRows()[0].emit('keydown',{key:'End'});assert.match(observations.nodes['evidence-window-count'].textContent,/4951–5000 of 5000/);
assert.equal(observations.document.activeElement.dataset.evidenceKey,'7:42:6000');
observations.nodes['evidence-search'].value='not-present';observations.nodes['evidence-search'].emit('input');assert.match(observations.nodes['evidence-rows'].textContent,/No retained observations match/);
observations.context={events:[],artifacts:[],request:null,error:'disconnected'};observations.panel.sync();assert.match(observations.nodes['evidence-workspace-notice'].textContent,/refresh is unavailable/);
observations.context={events:[],artifacts:[],request:null};observations.panel.sync();assert.doesNotMatch(observations.nodes['evidence-workspace-notice'].textContent,/refresh/);
console.log('PASS Evidence production reconciliation: stable inspector/focus/scroll, secondary package mode, stale exact-source refusal, eviction, CDP disclosure, 5,000-record paging, keyboard and failed refresh');

// Arrival order is not retained-identity membership and neither proves loss.
for (const [ids, holes, jumps, late] of [[[1,3,2],'0',1,1],[[1,4,3],'1',1,1],[[3,2,1],'0',0,2],[[1,5],'3',1,0]]) {
  const value=observationUI.evidenceObservationModel({events:ids.map(id=>observationEvent(id,'runtime','api_call','Date.now')),artifacts:[]});
  assert.equal(value.sequence.holes,holes);assert.equal(value.sequence.arrivalDiscontinuities,jumps);assert.equal(value.sequence.outOfOrderArrivals,late);
}
const scopedHoleEvents=[observationEvent(1,'runtime','api_call','Date.now'),observationEvent(3,'runtime','api_call','Date.now'),observationEvent(2,'runtime','api_call','Date.now',{session_id:'8'}),observationEvent(3,'runtime','gap','5')];
const scopedHoles=observationUI.evidenceObservationModel({events:scopedHoleEvents,artifacts:[]});
assert.equal(scopedHoles.sequence.holes,'1');assert.equal(scopedHoles.queueMarkers,1);
for (const narrow of [false,true]) {
  const panel=observationPanelFixture(narrow), nodes=panel.nodes;
  nodes['evidence-search'].value='toDataURL';nodes['evidence-search'].emit('input');
  const scopeBefore=nodes['evidence-scope'].value;
  nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:102"]').click();
  nodes['evidence-inspector'].querySelector('[data-evidence-action="parent"]').click();
  assert.equal(panel.panel.snapshot().selectedKey,'7:42:101');assert.equal(nodes['evidence-search'].value,'toDataURL');assert.equal(nodes['evidence-scope'].value,scopeBefore);
  assert.match(nodes['evidence-workspace-notice'].textContent,/selected parent is outside the current filter/);
  assert.equal(panel.document.activeElement,nodes['evidence-inspector'],'A parent outside the filter focuses its visible inspector; DOM fixture is not rendered proof');
  if(narrow)assert.equal(panel.panel.snapshot().pane,'detail');
  nodes['evidence-search'].value='';nodes['evidence-search'].emit('input');assert.equal(nodes['evidence-workspace-notice'].hidden,true,'Outside-filter notice must clear once the selected parent is included again');
}
const evictionNotice=observationPanelFixture();
evictionNotice.nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:102"]').click();
evictionNotice.context.events=evictionNotice.context.events.filter(event=>event.sequence_number!=='102');evictionNotice.context.error='disconnected';evictionNotice.panel.sync();
assert.match(evictionNotice.nodes['evidence-workspace-notice'].textContent,/left the retained window/);
evictionNotice.nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:101"]').click();
assert.doesNotMatch(evictionNotice.nodes['evidence-workspace-notice'].textContent,/left the retained window/);
assert.match(evictionNotice.nodes['evidence-workspace-notice'].textContent,/refresh is unavailable/);
evictionNotice.context.error=null;evictionNotice.panel.sync();assert.equal(evictionNotice.nodes['evidence-workspace-notice'].hidden,true);
const duplicateSource=observationPanelFixture();
duplicateSource.nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:102"]').click();
const duplicateSourceAction=duplicateSource.nodes['evidence-inspector'].querySelector('[data-evidence-action="source"]');
const exactSnapshot=duplicateSource.panel.snapshot();duplicateSource.context.events.push({...duplicateSource.context.events.find(event=>event.sequence_number==='102')});
duplicateSourceAction.click();assert.equal(duplicateSource.sourceCalls,0);assert.equal(duplicateSource.panel.canRestore(exactSnapshot),false);
const coveragePanel=observationPanelFixture();coveragePanel.nodes['evidence-coverage-details'].open=true;
coveragePanel.nodes['evidence-coverage-details'].emit('keydown',{key:'Escape',stopPropagation(){}});
assert.equal(coveragePanel.nodes['evidence-coverage-details'].open,false);assert.equal(coveragePanel.document.activeElement,coveragePanel.nodes['evidence-coverage-details'].querySelector('summary'));
console.log('PASS Evidence review regressions: arrival versus retained holes, scope separation, parent draft preservation, narrow visible-pane focus target, independent selection/error notices and stale duplicate source refusal');
// Execute the real Evidence workspace lifecycle with the immutable comparator.
let hostCalls=[],hostReply=null;
const comparisonHostFixture=observationPanelFixture(false,{fetcher:async(url,options)=>{hostCalls.push({url,options});return hostReply?hostReply():Response.json(comparisonResult);}});
const hc=comparisonHostFixture,n=hc.nodes;
const hostHandle=()=>n['evidence-comparison-panel'].rebEvidenceComparison;
assert.equal(hostHandle(),undefined,'Observation landing must not mount file tools');
n['evidence-package-toggle'].click();assert.equal(hostHandle(),undefined,'Opening package tools must not start comparison');
n['evidence-compare-toggle'].click();const originalHostHandle=hostHandle();assert(originalHostHandle);assert.equal(n['evidence-package-panel'].hidden,true);assert.equal(hc.packageVisible,false);assert.equal(hostCalls.length,0);
assert.equal(hc.document.activeElement,n['evidence-comparison-panel'].querySelector('[data-comparison-side="0"]'));
const hostInputs=n['evidence-comparison-panel'].querySelectorAll('input');for(const input of hostInputs){input.files=[comparisonFile(comparisonOriginal)];input.emit('change');}
const initialFile=hostHandle().controller.model.files[0];hostInputs[0].focus();const firstControl=n['evidence-comparison-panel'].children[1];
hc.panel.sync();assert.equal(hostHandle(),originalHostHandle);assert.equal(hostHandle().controller.model.files[0],initialFile);assert.equal(hc.document.activeElement,hostInputs[0]);assert.equal(n['evidence-comparison-panel'].children[1],firstControl);assert.equal(hostCalls.length,0);
assert(await hostHandle().controller.compare());const acceptedHostResult=hostHandle().controller.model.result;
let releaseHostResponse;hostReply=()=>new Promise(resolve=>{releaseHostResponse=resolve;});const hostPending=hostHandle().controller.compare();while(!releaseHostResponse)await new Promise(resolve=>setTimeout(resolve,0));
n['evidence-comparison-section'].emit('keydown',{key:'Escape'});assert.equal(await hostPending,false);assert.equal(n['evidence-comparison-section'].hidden,false);assert.equal(hc.document.activeElement,n['evidence-comparison-panel'].querySelector('[data-comparison-action="compare"]'));
releaseHostResponse(Response.json(comparisonResult));await new Promise(resolve=>setTimeout(resolve,0));assert.equal(hostHandle().controller.model.result,acceptedHostResult);
n['evidence-comparison-section'].emit('keydown',{key:'Escape'});assert.equal(n['evidence-comparison-section'].hidden,true);assert.equal(hc.document.activeElement,n['evidence-compare-toggle']);assert.equal(hc.packageVisible,true);
n['evidence-compare-toggle'].click();assert.equal(hostHandle(),originalHostHandle);assert.equal(hostHandle().controller.model.files[0],initialFile);assert.equal(hostHandle().controller.model.result,acceptedHostResult);
let releaseHostFile;hostHandle().controller.select(0,{size:packageGoldenBytes.length,arrayBuffer:()=>new Promise(resolve=>{releaseHostFile=resolve;})});const beforeHostFile=hostCalls.length;const lateHostFile=hostHandle().controller.compare();n['evidence-return'].click();assert.equal(await lateHostFile,false);releaseHostFile(packageGoldenBytes.buffer);await new Promise(resolve=>setTimeout(resolve,0));assert.equal(hostCalls.length,beforeHostFile);assert.equal(n['evidence-investigation'].hidden,false);assert.equal(hc.document.activeElement,n['evidence-package-toggle']);
n['evidence-package-toggle'].click();n['evidence-compare-toggle'].click();hostReply=null;hostHandle().controller.select(0,comparisonFile(comparisonOriginal));
let hideResponse;hostReply=()=>new Promise(resolve=>{hideResponse=resolve;});const hidePending=hostHandle().controller.compare();while(!hideResponse)await new Promise(resolve=>setTimeout(resolve,0));hc.panel.setVisible(false);assert.equal(await hidePending,false);hideResponse(Response.json(comparisonResult));await new Promise(resolve=>setTimeout(resolve,0));hc.panel.setVisible(true);assert.equal(n['evidence-comparison-section'].hidden,true);assert.equal(hostHandle().controller.model.files[1],hostInputs[1].files[0]);assert.equal(hostCalls.length,beforeHostFile+1);
assert.deepEqual(Object.keys(hc.panel.snapshot()).sort(),['packages','page','pane','requestKey','selectedKey'],'Navigation stores bounded view metadata, never comparison files or result objects');
n['evidence-compare-toggle'].click();const disposedHost=hostHandle();hc.panel.disposeComparison();assert.equal(hostHandle(),undefined);n['evidence-compare-toggle'].click();const replacementHost=hostHandle();assert.notEqual(replacementHost,disposedHost);assert.equal(replacementHost.controller.model.files[0],null);disposedHost.dispose();assert.equal(hostHandle(),replacementHost);assert(n['evidence-comparison-panel'].children.length>0);hc.panel.disposeComparison();
const storedComparison=observationPanelFixture(false,{protocol:'reb:',fetcher:()=>{throw new Error('Stored-native comparison must not dispatch');}});storedComparison.nodes['evidence-package-toggle'].click();storedComparison.nodes['evidence-compare-toggle'].click();assert.equal(storedComparison.nodes['evidence-comparison-panel'].rebEvidenceComparison,undefined);assert.match(storedComparison.nodes['evidence-comparison-unavailable'].textContent,/unavailable in stored-evidence native mode/);
// Unlike directly emitting on the section, a physical key begins at the current
// focus owner. Native disabled buttons lose focus before Escape can bubble.
for(const action of ['compare','previous','next']) {
  let release,requests=0;
  const fixture=observationPanelFixture(false,{nativeFocus:true,fetcher:()=>{requests++;return new Promise(resolve=>{release=resolve;});}});
  const {nodes,document:doc}=fixture;
  nodes['evidence-package-toggle'].click();nodes['evidence-compare-toggle'].click();
  const host=nodes['evidence-comparison-panel'],handle=host.rebEvidenceComparison;
  for(const input of host.querySelectorAll('input')){input.files=[comparisonFile(comparisonOriginal)];input.emit('change');}
  if(action!=='compare')handle.controller.model.result={...comparisonResult,page:{offset:50,next_offset:100}};
  const trigger=host.querySelector(`[data-comparison-action="${action}"]`);
  trigger.disabled=false;trigger.focus();trigger.click();
  assert.equal(handle.controller.model.busy,true);
  assert.equal(doc.activeElement,host.querySelector('[data-comparison-action="cancel"]'),`${action}: disabling the active trigger must hand keyboard ownership to Cancel`);
  for(let turn=0;turn<100&&!release;turn++)await new Promise(resolve=>setTimeout(resolve,0));
  assert(release,'Held comparison must reach the service');
  let stopped=false;
  for(let target=doc.activeElement;target&&!stopped;target=target.parentNode)target.emit('keydown',{key:'Escape',stopPropagation(){stopped=true;}});
  assert.equal(handle.controller.model.busy,false,'Escape from the actual focus owner must cancel');
  assert.equal(nodes['evidence-comparison-section'].hidden,false);
  assert.equal(doc.activeElement,host.querySelector('[data-comparison-action="compare"]'));
  release(Response.json(comparisonResult));await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(requests,1,'Cancellation must not retry');
  fixture.panel.disposeComparison();
}
// Completion may replace only its own disabled focus owner. A newer focus
// selection, including a file input or control outside comparison, wins.
for(const result of ['success','error']) for(const move of [null,'input','outside']) {
  let release;
  const fixture=observationPanelFixture(false,{nativeFocus:true,fetcher:()=>new Promise(resolve=>{release=resolve;})});
  const {nodes,document:doc}=fixture;
  fixture.panel.showPackages(true);fixture.panel.showComparison(true);
  const host=nodes['evidence-comparison-panel'],handle=host.rebEvidenceComparison,inputs=host.querySelectorAll('input');
  for(const input of inputs){input.files=[comparisonFile(comparisonOriginal)];input.emit('change');}
  const compare=host.querySelector('[data-comparison-action="compare"]');compare.focus();compare.click();
  for(let turn=0;turn<100&&!release;turn++)await new Promise(resolve=>setTimeout(resolve,0));
  assert(release);
  const expected=move==='input'?inputs[1]:move==='outside'?nodes['evidence-search']:compare;
  if(move)expected.focus();
  release(result==='success'?Response.json(comparisonResult):new Response('unavailable',{status:503}));
  for(let turn=0;turn<100&&handle.controller.model.busy;turn++)await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(handle.controller.model.busy,false);
  assert.equal(doc.activeElement,expected,`${result}: settlement must preserve ${move||'owned'} focus`);
  assert.equal(Boolean(handle.controller.model.result),result==='success');
  fixture.panel.disposeComparison();
}
console.log('PASS mounted comparison native-disabled focus ownership and focus-routed Escape for Compare/Previous/Next (DOM model, not rendered QA)');
console.log('PASS mounted Evidence comparison host: observation-first lazy entry, draft/focus/DOM retention on refresh, Escape/Close/Return/navigation ownership, late file suppression, metadata-only history, owned disposal/remount and stored-native unavailability');
// Invoke the actual application's page lifecycle handlers, not a replacement.
const comparisonLifecycleApp=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
const comparisonLifecycleSource=comparisonLifecycleApp.slice(comparisonLifecycleApp.indexOf('      // Ordinary refresh/navigation keeps file drafts'),comparisonLifecycleApp.indexOf('      function acceptVmOpcodeWorkspace('));
assert(comparisonLifecycleSource.includes("window.addEventListener('pagehide'"));
assert(!comparisonLifecycleSource.includes('const float32Panel'), 'Lifecycle fixture must stop before unrelated application startup');
let lifecycleReply=null,lifecycleCalls=0;
const lifecycleHost=observationPanelFixture(false,{fetcher:async()=>{lifecycleCalls++;return lifecycleReply?lifecycleReply():Response.json(comparisonResult);}}),lifecycleHooks={};
runInNewContext(comparisonLifecycleSource,{window:{addEventListener:(name,fn)=>{lifecycleHooks[name]=fn;}},document:{querySelector:()=>({hidden:false})},evidenceWorkspace:lifecycleHost.panel});
lifecycleHost.panel.showPackages(true);lifecycleHost.panel.showComparison(true);const lifecyclePanel=()=>lifecycleHost.nodes['evidence-comparison-panel'].rebEvidenceComparison;
for(const input of lifecycleHost.nodes['evidence-comparison-panel'].querySelectorAll('input')){input.files=[comparisonFile(comparisonOriginal)];input.emit('change');}
const lifecycleOriginal=lifecyclePanel(),lifecycleFiles=[...lifecycleOriginal.controller.model.files];
let releaseLifecycle;lifecycleReply=()=>new Promise(resolve=>{releaseLifecycle=resolve;});const lifecyclePending=lifecycleOriginal.controller.compare();while(!releaseLifecycle)await new Promise(resolve=>setTimeout(resolve,0));
lifecycleHooks.pagehide({persisted:true});assert.equal(await lifecyclePending,false);releaseLifecycle(Response.json(comparisonResult));lifecycleHooks.pageshow();assert.equal(lifecyclePanel(),lifecycleOriginal);assert(lifecyclePanel().controller.model.files.every((file,index)=>file===lifecycleFiles[index]));assert.equal(lifecycleHost.nodes['evidence-comparison-section'].hidden,true);assert.equal(lifecycleCalls,1);
lifecycleHost.panel.showComparison(true);lifecycleHooks.pagehide({persisted:false});assert.equal(lifecyclePanel(),undefined);lifecycleHooks.pageshow();assert.equal(lifecyclePanel(),undefined,'Page re-entry must not remount or request implicitly');lifecycleHost.panel.showComparison(true);assert.notEqual(lifecyclePanel(),lifecycleOriginal);assert.equal(lifecyclePanel().controller.model.files[0],null);assert.equal(lifecycleCalls,1);lifecycleHost.panel.disposeComparison();
// An HTTP workspace remains supported when the native application marker is set.
const liveNative=observationPanelFixture(false,{protocol:'http:',native:true});liveNative.panel.showPackages(true);liveNative.panel.showComparison(true);assert(liveNative.nodes['evidence-comparison-panel'].rebEvidenceComparison);assert.equal(liveNative.nodes['evidence-comparison-unavailable'].hidden,true);liveNative.panel.disposeComparison();
console.log('PASS actual pagehide/pageshow handlers: BFCache keeps drafts but cancels work, departing document disposes, re-entry is explicit, and native live HTTP stays supported');


// Exercise the actual shared boundary against the real Evidence controller.
// The lightweight DOM checks identity/ownership; CI owns visibility/geometry.
for (const scenario of ['return','evicted','duplicate','changed-session','interrupted']) {
  const fixture=observationPanelFixture(true), {nodes,document:owner}=fixture;
  const request=fixture.context.request;
  const other={...request,id:'other',events:request.events.map(event=>({...event,session_id:'8'}))};
  const state={requests:[request,other],events:fixture.context.events,artifacts:fixture.context.artifacts,selectedRequestId:request.id,decoderSteps:[],inspectorTab:'evidence'};
  for(const [id,node] of Object.entries(nodes))node.id=id;
  nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:102"]').click();
  const source=nodes['evidence-inspector'].querySelector('[data-evidence-action="source"]');source.focus();
  nodes['evidence-rows'].scrollTop=55;nodes['evidence-inspector'].scrollTop=81;
  const panes=[nodes['evidence-rows'],nodes['evidence-inspector'],nodes['evidence-package-mode']];
  const evidenceRoot={id:'screen-evidence',scrollTop:0,scrollLeft:0,contains:()=>true,matches:s=>s==='#screen-evidence',querySelectorAll:()=>panes,
    querySelector:selector=>selector==='#evidence-open-source'?nodes['evidence-inspector'].querySelector('[data-evidence-action="source"]'):nodes[selector.slice(1)]};
  let screen='evidence',notice='',selections=0;const raf=[];
  const back={focus(){owner.activeElement=back;}};
  const document={get activeElement(){return owner.activeElement;},querySelector:selector=>selector==='.screen:not([hidden])'?{id:`screen-${screen}`}:selector==='#screen-evidence'?evidenceRoot:selector==='#investigation-notice'?{textContent:notice}:selector==='#investigation-back'?back:null};
  const sandbox={state,document,CSS:{escape:s=>s},evidenceWorkspace:fixture.panel,sourceFactsPanel:{},selectedSource:()=>null,integerText:(e,k)=>String(e[k]),requestAnimationFrame:fn=>raf.push(fn),
    selectRequest:id=>{state.selectedRequestId=id;fixture.context={...fixture.context,request:state.requests.find(item=>item.id===id)};fixture.panel.sync();selections++;},
    showScreen:name=>{screen=name;fixture.panel.setVisible(name==='evidence');},noticeWriter:value=>{notice=value;}};
  const code=await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
  const nav=runInNewContext(appSection('      function requestTraceRoot(','      function requestSignalProfileSelection(')+code+';investigationNotice=noticeWriter;({snapshot:investigationSnapshot,restore:restoreInvestigation,retire:retireInvestigationReturn})',sandbox);
  const saved=nav.snapshot();assert.equal(saved.evidence.selectedKey,'7:42:102');assert.equal(saved.focus,'#evidence-open-source');
  assert(!JSON.stringify(saved).includes('payload'),'History cannot retain record payloads');
  screen='sources';state.selectedRequestId='other';fixture.context={...fixture.context,request:other};fixture.panel.sync();fixture.panel.setVisible(false);
  nodes['evidence-search'].value='newer filter';nodes['evidence-scope'].value='all';
  if(scenario==='evicted')fixture.context.events=fixture.context.events.filter(event=>event.sequence_number!=='102');
  if(scenario==='duplicate')fixture.context.events=[...fixture.context.events,{...fixture.context.events.find(event=>event.sequence_number==='102')}];
  if(scenario==='changed-session')state.requests=[{...request,events:other.events},other];
  const restored=nav.restore(saved);
  if(['evicted','duplicate','changed-session'].includes(scenario)) {assert.equal(restored,false);assert.equal(screen,'sources');assert.equal(selections,0,'Failed preflight must not mutate current request');continue;}
  assert.equal(restored,true);assert.equal(state.selectedRequestId,request.id);assert.equal(fixture.panel.snapshot().pane,'detail');
  if(scenario==='interrupted'){nav.retire();nodes['evidence-inspector'].scrollTop=777;owner.activeElement=nodes['evidence-search'];}
  await Promise.resolve();for(const callback of raf.splice(0))callback();
  assert.equal(nodes['evidence-search'].value,'newer filter');assert.equal(nodes['evidence-scope'].value,'all');
  if(scenario==='interrupted'){assert.equal(nodes['evidence-inspector'].scrollTop,777);assert.equal(owner.activeElement,nodes['evidence-search']);}
  else {assert.equal(nodes['evidence-rows'].scrollTop,55);assert.equal(nodes['evidence-inspector'].scrollTop,81);assert.equal(owner.activeElement.id,'evidence-open-source');assert.match(nodes['evidence-workspace-notice'].textContent,/outside the current filter/);}
}
console.log('PASS shared Evidence return with original request preflight, selected-key/pane ownership, independent scroll, exact focus, preserved current filters, evicted/duplicate/session refusal and interrupted focus (not rendered QA)');
// Final composition: actual shared snapshot/restore owns the Evidence return,
// while independent supplied-file drafts stay outside navigation history.
for(const phase of ['service','file']){
  let release,requests=0,hold=false;
  const fixture=observationPanelFixture(true,{fetcher:async()=>{requests++;return hold&&phase==='service'?new Promise(resolve=>{release=resolve;}):Response.json(comparisonResult);}}),{nodes,document:owner}=fixture;
  const request=fixture.context.request,other={...request,id:'other',events:request.events.map(e=>({...e,session_id:'8'}))};
  const state={requests:[request,other],events:fixture.context.events,artifacts:fixture.context.artifacts,selectedRequestId:request.id,decoderSteps:[],inspectorTab:'evidence'};
  for(const[id,node]of Object.entries(nodes))node.id=id;
  nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:102"]').click();fixture.panel.showPackages(true);fixture.panel.showComparison(true);
  const handle=nodes['evidence-comparison-panel'].rebEvidenceComparison;
  for(const input of nodes['evidence-comparison-panel'].querySelectorAll('input')){input.files=[comparisonFile(comparisonOriginal)];input.emit('change');}
  assert(await handle.controller.compare());const previous=handle.controller.model.result;hold=true;
  if(phase==='file')handle.controller.select(0,{size:packageGoldenBytes.length,arrayBuffer:()=>new Promise(resolve=>{release=resolve;})});
  const files=[...handle.controller.model.files],pending=handle.controller.compare();while(!release)await new Promise(resolve=>setTimeout(resolve,0));
  nodes['evidence-compare-toggle'].focus();nodes['evidence-rows'].scrollTop=55;nodes['evidence-inspector'].scrollTop=81;nodes['evidence-package-mode'].scrollTop=27;
  const panes=[nodes['evidence-rows'],nodes['evidence-inspector'],nodes['evidence-package-mode']];const evidenceRoot={id:'screen-evidence',scrollTop:0,scrollLeft:0,contains:()=>true,matches:s=>s==='#screen-evidence',querySelectorAll:()=>panes,querySelector:s=>nodes[s.slice(1)]};
  let screen='evidence',notice='';const raf=[],back={focus(){owner.activeElement=back;}};
  const document={get activeElement(){return owner.activeElement;},querySelector:s=>s==='.screen:not([hidden])'?{id:`screen-${screen}`}:s==='#screen-evidence'?evidenceRoot:s==='#investigation-notice'?{textContent:notice}:s==='#investigation-back'?back:null};
  const sandbox={state,document,CSS:{escape:s=>s},evidenceWorkspace:fixture.panel,sourceFactsPanel:{},selectedSource:()=>null,integerText:(e,k)=>String(e[k]),requestAnimationFrame:fn=>raf.push(fn),selectRequest:id=>{state.selectedRequestId=id;fixture.context={...fixture.context,request:state.requests.find(r=>r.id===id)};fixture.panel.sync();},showScreen:name=>{screen=name;fixture.panel.setVisible(name==='evidence');},noticeWriter:s=>{notice=s;}};
  const navCode=await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');const nav=runInNewContext(appSection('      function requestTraceRoot(','      function requestSignalProfileSelection(')+navCode+';investigationNotice=noticeWriter;({snapshot:investigationSnapshot,restore:restoreInvestigation,history:createInvestigationHistory})',sandbox);
  const saved=nav.snapshot();assert.equal(saved.focus,'#evidence-compare-toggle');assert.equal(saved.evidence.packages,true);assert(!JSON.stringify(saved).includes('reb-package-v1:sha256:'),'Comparison bytes/IDs are not stored in shared navigation');
  screen='sources';fixture.panel.setVisible(false);state.selectedRequestId='other';fixture.context={...fixture.context,request:other};fixture.panel.sync();assert.equal(await pending,false);
  nodes['evidence-search'].value='newer filter';nodes['evidence-scope'].value='all';assert(nav.restore(saved));await Promise.resolve();for(const callback of raf.splice(0))callback();
  release(phase==='file'?packageGoldenBytes.buffer:Response.json(comparisonResult));await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(screen,'evidence');assert.equal(state.selectedRequestId,request.id);assert.equal(fixture.panel.snapshot().selectedKey,'7:42:102');assert.equal(nodes['evidence-search'].value,'newer filter');assert.equal(nodes['evidence-scope'].value,'all');assert.equal(owner.activeElement,nodes['evidence-compare-toggle']);assert.equal(nodes['evidence-rows'].scrollTop,55);assert.equal(nodes['evidence-inspector'].scrollTop,81);assert.equal(nodes['evidence-package-mode'].scrollTop,27);
  assert.equal(nodes['evidence-comparison-section'].hidden,true);assert(handle.controller.model.files.every((f,i)=>f===files[i]));assert.equal(handle.controller.model.result,phase==='file'?null:previous);assert.equal(requests,phase==='file'?1:2);
  const calls=requests;fixture.panel.showComparison(true);assert.equal(requests,calls);assert.equal(nodes['evidence-comparison-panel'].rebEvidenceComparison,handle);fixture.panel.showComparison(false);fixture.panel.showPackages(false);assert.equal(fixture.panel.snapshot().selectedKey,'7:42:102');assert.equal(nodes['evidence-search'].value,'newer filter');assert.equal(nodes['evidence-rows'].scrollTop,55);
  // The actual workspace arrow consumes shared Back; returning to that saved
  // Evidence stop must use Forward, not a second Back on an empty back stack.
  const trafficRoot={id:'screen-traffic',dataset:{},contains:()=>false,querySelectorAll:()=>[],querySelector:()=>null};
  const sourceRoot={...trafficRoot,id:'screen-sources'},originalQuery=document.querySelector;
  document.querySelector=selector=>selector==='#screen-traffic'?trafficRoot:selector==='#screen-sources'?sourceRoot:selector==='#console-experiment-traffic'?{dataset:{}}:originalQuery(selector);
  sandbox.fieldSets={body:[]};sandbox.renderInspector=()=>{};state.fieldTab='body';
  let historyState,workspaceClick,fallbacks=0;
  const history=nav.history({snapshot:nav.snapshot,restore:nav.restore,changed:value=>{historyState=value;}});
  const flush=async()=>{await Promise.resolve();for(const callback of raf.splice(0))callback();};
  screen='traffic';fixture.panel.setVisible(false);history.record();
  screen='evidence';fixture.panel.setVisible(true);history.record();
  screen='sources';fixture.panel.setVisible(false);assert(history.back());await flush();
  assert.equal(screen,'evidence');assert.equal(historyState.back.screen,'traffic');
  fixture.panel.showPackages(true);fixture.panel.showComparison(true);release=null;
  const leaving=handle.controller.compare();while(!release)await new Promise(resolve=>setTimeout(resolve,0));
  const ownedFiles=[...handle.controller.model.files],beforeLeave=requests;
  const arrow={dataset:{screen:'traffic'},classList:{contains:name=>name==='back-button'},addEventListener:(name,callback)=>{assert.equal(name,'click');workspaceClick=callback;}};
  const workspaceHandler=appSection("      document.querySelectorAll('[data-screen]').forEach(",'      elements.signalFilters.forEach(');
  runInNewContext(workspaceHandler,{document:{querySelectorAll:()=>[arrow]},investigationNavigation:history,showScreen:()=>{fallbacks++;}});
  owner.activeElement=arrow;await workspaceClick();await flush();
  assert.equal(await leaving,false);assert.equal(screen,'traffic');assert.equal(fallbacks,0,'The arrow must use shared history rather than create a new navigation branch');
  assert.equal(historyState.back,null);assert.equal(historyState.forward.screen,'evidence');
  assert.equal(history.back(),false,'The old second-Back driver action cannot return to Evidence');assert.equal(screen,'traffic');
  release(phase==='file'?packageGoldenBytes.buffer:Response.json(comparisonResult));await new Promise(resolve=>setTimeout(resolve,0));
  assert(history.forward());await flush();
  assert.equal(screen,'evidence');assert.equal(state.selectedRequestId,request.id);
  assert.equal(fixture.panel.snapshot().selectedKey,'7:42:102');assert.equal(fixture.panel.snapshot().packages,true);
  assert.equal(nodes['evidence-comparison-panel'].rebEvidenceComparison,handle);
  assert(handle.controller.model.files.every((file,index)=>file===ownedFiles[index]));
  assert.equal(handle.controller.model.busy,false);assert.equal(nodes['evidence-comparison-section'].hidden,true);assert.equal(requests,beforeLeave,'Forward must not replay the cancelled comparison');
  assert.equal(nodes['evidence-search'].value,'newer filter');assert.equal(nodes['evidence-scope'].value,'all');
  assert.equal(owner.activeElement,back,'The workspace arrow has no stable selector; its return must retain the guarded shared fallback focus');
  assert.equal(nodes['evidence-rows'].scrollTop,55);assert.equal(nodes['evidence-inspector'].scrollTop,81);
  fixture.panel.showComparison(true);assert.equal(owner.activeElement,nodes['evidence-comparison-panel'].querySelector('[data-comparison-side="0"]'));assert.equal(requests,beforeLeave);
  fixture.panel.disposeComparison();
}
console.log('PASS final linked Evidence comparison: actual shared snapshot/restore preserves newer filters, selected record, stable entry focus, independent scroll and file drafts, while cancelling late service/file work without replay or history payloads');

// The rendered fixture tests presentation and user actions. The separate real
// native-writer/HTTP probe establishes authoritative export and validation.
function evidenceBrowserFixture() {
  const fixture={mode:'valid',requests:[],pending:[],lastValidation:null,observationActive:false,derivedRequests:0};
  fixture.observation=observationFixtureContext();
  const bytes=packageGoldenBytes;
  fixture.events=packageGolden.records.events.map(row=>({...row,...row.key}));
  fixture.artifacts=packageGolden.records.artifacts.map(row=>({...row,...row.key}));
  fixture.handle=async(request,response)=>{
    const path=new URL(request.url,'http://127.0.0.1').pathname;
    if(path==='/api/deobfuscation') fixture.derivedRequests++;
    if(fixture.observationActive){
      const send=value=>{response.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});response.end(JSON.stringify(value));};
      if(fixture.observationFrozen&&['/api/events','/api/artifacts'].includes(path)){response.writeHead(304);response.end();return true;}
      if(path==='/api/events'){send({count:fixture.observation.events.length,events:fixture.observation.events,capture_mode:'live',broker_connected:true,capture_controls_available:false});return true;}
      if(path==='/api/artifacts'){send({count:fixture.observation.artifacts.length,artifacts:fixture.observation.artifacts});return true;}
      if(path==='/api/artifacts/9/content'){
        const parameters=new URL(request.url,'http://127.0.0.1').searchParams,offset=Number(parameters.get('offset')||0),limit=Number(parameters.get('limit')||2097152);
        const bytes=observationSourceBytes.subarray(offset,offset+limit);
        response.writeHead(200,{'Content-Type':'application/octet-stream','X-Artifact-Total-Bytes':String(observationSourceBytes.length),'X-Artifact-Offset':String(offset),'X-Artifact-Truncated':String(offset+bytes.length<observationSourceBytes.length)});response.end(bytes);return true;
      }
    }
    if(!['/api/evidence/packages/export','/api/evidence/packages/validate','/api/evidence/packages/compare'].includes(path)) return false;
    let body=Buffer.alloc(0);
    for await(const chunk of request) {
      if(body.length+chunk.length>(path.endsWith('/compare')?8392704:4194304)){response.writeHead(413);response.end();return true;}
      body=Buffer.concat([body,chunk]);
    }
    fixture.requests.push({path,bytes:body.length});
    if(path.endsWith('/validate'))fixture.lastValidation=body;
    const mode=fixture.mode;
    if(mode==='pending_export'&&path.endsWith('/export')||mode==='pending_validate'&&path.endsWith('/validate')||mode==='pending_compare'&&path.endsWith('/compare')) await new Promise(resolve=>fixture.pending.push(resolve));
    if(response.destroyed)return true;
    const send=(status,value)=>{response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});response.end(value);};
    if(mode==='writer_busy'){send(409,'{"error":"Synthetic held writer lease"}');return true;}
    if(mode==='unavailable'){send(503,'{"error":"Synthetic unavailable guarded store"}');return true;}
    if(path.endsWith('/export')){send(200,bytes);return true;}
    if(path.endsWith('/compare')){
      let supplied;try{supplied=JSON.parse(body);}catch{send(400,'{}');return true;}
      if(mode==='invalid'||body.includes(Buffer.from('"protocol_version": 1, "protocol_version": 1'))){send(400,'{}');return true;}
      const value=supplied.right?.package_id===comparisonChangedResult.right_package_id?structuredClone(comparisonChangedResult):structuredClone(comparisonResult);
      if(mode==='comparison_inconsistent')value.counts.equal_declared_metadata++;
      if(mode==='comparison_wrong_id')value.right_package_id='reb-package-v1:sha256:'+'0'.repeat(64);
      send(200,JSON.stringify(value));return true;
    }
    const invalid=mode==='invalid'||body.includes(Buffer.from('"protocol_version": 1, "protocol_version": 1'));
    const value=mode==='unsupported'?{...packageInvalid,status:'unsupported'}:invalid?packageInvalid:packageValid;
    send(200,JSON.stringify(value));return true;
  };
  fixture.release=()=>{for(const resolve of fixture.pending.splice(0))resolve();};
  return fixture;
}
// Exercise raw request admission and fixture status transitions before launching
// Chrome so a broken synthetic service cannot silently masquerade as UI success.
const evidenceFixtureControl=evidenceBrowserFixture();
async function evidenceFixtureResponse(path,body,mode='valid') {
  evidenceFixtureControl.mode=mode;
  const response={destroyed:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(value){this.body=value;}};
  assert(await evidenceFixtureControl.handle({url:path,async *[Symbol.asyncIterator](){yield body;}},response));return response;
}
assert.deepEqual((await evidenceFixtureResponse('/api/evidence/packages/export',Buffer.from('{}'))).body,packageGoldenBytes);
assert.equal(JSON.parse((await evidenceFixtureResponse('/api/evidence/packages/validate',packageGoldenBytes)).body).status,'valid');
for(const [mode,status] of [['writer_busy',409],['unavailable',503]])assert.equal((await evidenceFixtureResponse('/api/evidence/packages/export',Buffer.from('{}'),mode)).status,status);
for(const status of ['invalid','unsupported'])assert.equal(JSON.parse((await evidenceFixtureResponse('/api/evidence/packages/validate',packageGoldenBytes,status)).body).status,status);
assert.equal(JSON.parse((await evidenceFixtureResponse('/api/evidence/packages/compare',Buffer.from('{}'))).body).comparison_id,comparisonResult.comparison_id);
assert.equal(JSON.parse((await evidenceFixtureResponse('/api/evidence/packages/compare',Buffer.from(JSON.stringify({right:{package_id:comparisonChangedResult.right_package_id}})))).body).counts.changed_declared_metadata,1);
assert(comparisonUI.validResult(comparisonChangedResult,0,packageGolden.package_id,JSON.parse(new TextDecoder().decode(comparisonChangedInput)).package_id),'Changed product fixture must pass the actual UI response contract');
console.log('PASS Evidence browser fixture raw bytes, valid/invalid/unsupported, comparison and guarded-export errors (not rendered QA)');


const canvasFixtureOptions={artifact:canvasArtifact,png:canvasPngFixture,pngUrl:canvasPngUrl,chunk:canvasPngChunk};
await checkCanvasFixture(await canvasEvidenceFixture(canvasFixtureOptions),sourcesFixtureModels,canvasProductionRules.inspectCanvasPng);

console.log('PASS retained native/offline UI models; no rendered browser QA performed');
