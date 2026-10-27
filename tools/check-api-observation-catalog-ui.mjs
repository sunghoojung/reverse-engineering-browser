#!/usr/bin/env node
// Authored local fixtures only. No real captures, target requests or mutation.
// The observed API catalog and GET /api/network/catalog were removed with CDP.
// This check covers the exact request identity helpers that remain shared by
// Traffic, investigation history, passive security and captured export, and
// proves the retained installer hides its entry point without fetching.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {runInNewContext} from 'node:vm';
import {network} from './traffic-capture-qa.mjs';

const root = resolve(new URL('..', import.meta.url).pathname);
const traffic = await readFile(join(root, 'apps/research-ui/traffic_view.js'), 'utf8');
const catalogSource = await readFile(join(root, 'apps/research-ui/api_catalog.js'), 'utf8');
const navigation = await readFile(join(root, 'apps/research-ui/investigation_navigation.js'), 'utf8');
const models = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const api = runInNewContext(`${models}\n${traffic}\n${catalogSource}\n${navigation}\n;({apiCatalogIdentity,apiCatalogRequestIdentity,apiCatalogResolveSource,requestsFromDebuggerNetwork,investigationRequestIdentity,investigationSame})`,
  {TextEncoder, TextDecoder, Uint8Array, URL, atob});
assert.equal(/network\/catalog'|fetch\(/.test(catalogSource), false, 'No catalog read remains');

const capture = network();
capture.requests = capture.requests.slice(0, 1);
capture.requests[0].started_monotonic_ms = 100.0000001;
const record = capture.requests[0];
const requests = api.requestsFromDebuggerNetwork(capture);
const original = JSON.stringify(capture);
const identity = api.apiCatalogIdentity({instance_id: capture.instance_id, capture_epoch: capture.capture_epoch},
  {request_id: record.id, target_id: record.target_id, started_monotonic_ms: record.started_monotonic_ms});
assert.equal(api.apiCatalogResolveSource(identity, requests).record, requests[0]);
for (const [key, value] of [['instance','other'],['epoch',2],['request','other'],['target','other'],['started',100.0000002]]) {
  assert.equal(api.apiCatalogResolveSource({...identity,[key]:value}, requests).record,null,key);
}
assert.equal(Math.round(100.0000001*1e6), Math.round(100.0000002*1e6), 'Fixture proves rounded timestamp collision');
assert.equal(api.apiCatalogResolveSource(identity, []).record,null);
assert.equal(api.apiCatalogResolveSource(null, requests).record,null);
assert.equal(api.apiCatalogResolveSource(identity, [requests[0], {...requests[0]}]).record,null);
assert.equal(api.apiCatalogResolveSource(identity, [requests[0], {...requests[0],captureOwner:['other',1]}]).record,null,'Visible row ID collision fails closed');
for (const owner of [[null,1],['same',Number.MAX_SAFE_INTEGER+1],['same',-1]]) assert.equal(api.apiCatalogRequestIdentity({...requests[0],captureOwner:owner}),null);
assert.equal(api.apiCatalogRequestIdentity({...requests[0],tabId:'wrong'}),null);
const strong = api.investigationRequestIdentity(requests[0]);
assert.equal(strong.startedMonotonicMs,100.0000001);
for (const changed of [{...requests[0],captureOwner:['new',1]}, {...requests[0],captureOwner:[identity.instance,2]},
  {...requests[0],captureRecord:{...requests[0].captureRecord,started_monotonic_ms:100.0000002}}]) {
  assert.equal(api.investigationSame(strong,api.investigationRequestIdentity(changed)),false,'History and Field trace cannot reuse a replaced capture');
}
assert.equal(JSON.stringify(capture),original,'Identity resolution must not alter retained raw fields');
console.log('PASS five-value request identity, rounded timestamp collision, ambiguity, owner-safe navigation and immutable raw values');

function checkRetiredEntryPoint() {
  const trigger = {hidden: false, addEventListener() { throw new Error('Retired catalog must not wire a trigger'); }};
  let fetched = 0;
  const document = {getElementById: id => id === 'open-api-catalog' ? trigger : null};
  const install = runInNewContext(`${catalogSource}\n;installApiObservationCatalog`, {document, fetch: () => { fetched++; }});
  const panel = install({getRequests: () => requests, openRequest: () => true});
  assert.equal(trigger.hidden, true, 'Retired catalog entry point is hidden');
  panel.sync();
  assert.equal(fetched, 0, 'Nothing is fetched');
  const absent = runInNewContext(`${catalogSource}\n;installApiObservationCatalog`, {document: {getElementById: () => null}});
  assert.equal(typeof absent().sync, 'function', 'Missing markup does not throw');
  console.log('PASS retired API catalog: entry point hidden, no fetch, inert sync');
}

async function checkHistory() {
  const state={requests,selectedRequestId:null,trafficDetailOpen:false,selectedCaptureIdentity:null,inspectorTab:'headers',fieldTab:'body',selectedField:null};
  const node={id:'screen-traffic',dataset:{},textContent:'',querySelectorAll:()=>[],hidden:false};
  const document={querySelector:()=>node,activeElement:null};
  let renderedSelection='not rendered',returnNotice='';
  const model=runInNewContext(`${traffic}\n${catalogSource}\n${navigation}\n
    investigationSelector=()=>null; investigationNotice=message=>recordNotice(message); retireInvestigationReturn=()=>{}; resumeInvestigationReturn=()=>{};
    ({investigationSnapshot,restoreInvestigation})`,{state,document,TextEncoder,recordNotice:message=>{returnNotice=message;},selectedSource:()=>null,fieldSets:{body:[]},
      selectRequest:id=>{state.selectedRequestId=id;state.trafficDetailOpen=true;},
      resetRequestSelection:()=>{state.selectedRequestId=null;state.selectedCaptureIdentity=null;},renderRequests:()=>{renderedSelection=state.selectedRequestId;},renderInspector:()=>{},showScreen:()=>{}});
  const empty=model.investigationSnapshot();assert.equal(empty.request,null);assert.equal(empty.requestSelectionKind,'empty');assert.equal(empty.trafficDetailOpen,false);
  state.selectedRequestId=requests[0].id;state.selectedCaptureIdentity=identity;state.trafficDetailOpen=true;
  const opened=model.investigationSnapshot();assert.equal(opened.requestSelectionKind,'exact');
  assert.equal(model.restoreInvestigation(empty),true);assert.equal(state.selectedRequestId,null);assert.equal(state.trafficDetailOpen,false);assert.equal(state.selectedCaptureIdentity,null);assert.equal(renderedSelection,null,'Null selection immediately repaints Traffic rows');
  assert.equal(model.restoreInvestigation(opened),true);assert.equal(state.selectedRequestId,requests[0].id);assert.equal(state.trafficDetailOpen,true);
  state.trafficDetailOpen=false;const closed=model.investigationSnapshot();state.trafficDetailOpen=true;
  assert.equal(model.restoreInvestigation(closed),true);assert.equal(state.selectedRequestId,requests[0].id);assert.equal(state.trafficDetailOpen,false,'Previously selected but closed inspector stays closed on Back');
  state.requests=[{id:'authored-demo-row',origin:'demo'}];state.selectedRequestId='authored-demo-row';
  const unavailable=model.investigationSnapshot();assert.equal(unavailable.request,null);assert.equal(unavailable.requestSelectionKind,'unavailable');
  assert.equal(model.restoreInvestigation(unavailable),false,'A selected row without exact identity is not an empty-selection return');
  assert.equal(state.selectedRequestId,'authored-demo-row','Refused return leaves current evidence untouched');
  assert.match(returnNotice,/Return unavailable:.*Nothing was fetched or recaptured/);
  state.requests=[{id:'authored-demo-row',origin:'demo',path:'changed'}];state.selectedRequestId='different-current-selection';
  assert.equal(model.restoreInvestigation(unavailable),false,'An unavailable identity must not rebind a reused row ID');
  assert.equal(state.selectedRequestId,'different-current-selection');
  state.requests=requests;
  await new Promise(done=>setImmediate(done));
  console.log('PASS catalog Traffic history: Back restores unselected/closed state; Forward restores exact capture; selected but closed inspector round-trips; selected-but-unidentifiable returns refuse without rebinding');
}

checkRetiredEntryPoint();
await checkHistory();
