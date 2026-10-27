import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';

// Historical validated snapshots exercise inert projection, identity, selection
// rebuild, and comparison ownership. This is not rendered UI or native-probe QA.
const read = name => readFile(new URL(`../apps/research-ui/${name}`, import.meta.url), 'utf8');
const [models, traffic, catalog, navigation, app] = await Promise.all(
  ['evidence_models.js','traffic_view.js','api_catalog.js','investigation_navigation.js','app.js'].map(read));
const rebuild = app.slice(app.indexOf('      function rebuildTrafficRequests('), app.indexOf('      function renderShellStatus('));
const body = text => ({state:'available',mime:'text/plain',text,base64:'',truncated:false,reason:''});
const row = (target, n) => ({id:`cdp:owner-${target}:${n}`,capture_owner:`owner-${target}`,target_id:target,target_title:target,
  protocol_request_id:'shared-protocol-id',url:`https://fixture.invalid/${target}`,url_truncated:false,method:'GET',method_truncated:false,
  resource_type:'Fetch',document_url:'https://fixture.invalid/',document_url_truncated:false,started_monotonic_ms:1,
  wall_time_ms:100, state:'complete',status:200,status_text:'OK',protocol:'h2',mime_type:'text/plain',duration_ms:1,
  encoded_data_length:1,from_disk_cache:false,from_service_worker:false,error_text:'',
  request:{headers:[],headers_truncated:false,body:body('')},response:{headers:[],headers_truncated:false,body:body(target)}});
const session = () => ({generation:10,target:{id:'A'},network:{instance_id:'backend-one',capture_epoch:1,target_id:'A',capture_enabled:true,
  requests:[row('A',1),row('B',2)],limits:{requests:1000,body_bytes:131072,headers:128,header_bytes:65536},dropped:0}});
function fixture() {
  const state={sessionMode:'live',debuggerSession:session(),nativeRequests:[],requests:[],debuggerNetworkBodyCache:new Map(),
    selectedCaptureIdentity:null,selectedRequestId:null,originTraceGeneration:0,signalProfileGeneration:0};
  let resets=0,aborts=0;
  state.originTraceController={abort(){aborts++;}};
  const api=runInNewContext(`${models}\n${traffic}\n${catalog}\n${navigation.slice(0,navigation.indexOf('function investigationResolve('))}\n${rebuild}\n;({rebuildTrafficRequests,apiCatalogRequestIdentity,
    apiCatalogResolveSource,trafficComparisonOwner,trafficHttpSnapshotOwner,trafficRetainedHttpIdentity,requestsFromDebuggerNetwork,
    pin:request=>trafficComparisonController.pin(request,state.requests,trafficComparisonOwner()),
    baseline:()=>trafficComparisonController.sync(state.requests,trafficComparisonOwner()),
    signalTabKey:${app.slice(app.indexOf('      function signalTabKey('),app.indexOf('      function renderFingerprintTabScopes(')).trim().replace('function signalTabKey(', 'function(')},
    fingerprintEventsFromEvents})`, {state,TextEncoder,TextDecoder,URL,Uint8Array,
      apiCatalogPanel:{sync(){}},investigationNotice(){},requestTraceRoot:()=>null,
      resetRequestSelection(){resets++;state.selectedRequestId=null;state.selectedCaptureIdentity=null;}});
  // Feed already-normalized retained rows to the native-only rebuild. This is
  // offline reader compatibility, not restoration of a live debugger producer.
  state.nativeRequests=api.requestsFromDebuggerNetwork(state.debuggerSession.network);
  api.rebuildTrafficRequests();
  const a=state.requests[0];state.selectedRequestId=a.id;state.selectedCaptureIdentity=api.apiCatalogRequestIdentity(a);assert(api.pin(a));
  function refresh(change, projectHistorical = true) {
    const previous=state.debuggerSession;
    // No render follows this production rebuild: model hidden Traffic, whose
    // former rendered-view guard must not retain evicted response bodies.
    state.trafficRenderedView={requests:state.requests};
    state.debuggerSession=structuredClone(previous);state.debuggerSession.generation++;
    change?.(state.debuggerSession);
    if(projectHistorical)state.nativeRequests=api.requestsFromDebuggerNetwork(state.debuggerSession.network);
    api.rebuildTrafficRequests(previous);
    assert.equal(state.trafficRenderedView,null,'Hidden refresh/clear/session change retires the old rendered snapshot');
  }
  return {state,api,refresh,resets:()=>resets,aborts:()=>aborts};
}
const focusB=s=>{s.target.id='B';s.network.target_id='B';s.network.capture_epoch++;};
{
  const f=fixture(),oldIdentity=f.state.selectedCaptureIdentity;
  assert.equal(new Set(f.state.requests.map(r=>r.tabId)).size,2);
  assert.equal(new Set(f.state.requests.map(r=>r.protocolRequestId)).size,1,'Raw request IDs deliberately collide');
  f.refresh(focusB);
  assert.equal(f.resets(),0);assert.equal(f.state.selectedRequestId,'cdp:owner-A:1');
  assert.equal(f.state.selectedCaptureIdentity.epoch,2);assert.equal(f.api.baseline().tabId,'A');
  assert.equal(f.api.apiCatalogResolveSource(oldIdentity,f.state.requests).record,null,'Old API links keep their epoch guard');
  assert.equal(f.aborts(),1);assert.equal(f.state.originTraceGeneration,1);assert.equal(f.state.signalProfileGeneration,1);
  f.refresh(s=>{s.targets=[{id:'B'}];s.live_tab_count=1;s.network.requests.push(row('B',3));});
  assert.equal(f.resets(),0);assert.equal(f.api.baseline().tabId,'A','Closing A keeps its retained evidence');
  f.refresh(s=>{s.target.id='A';s.network.target_id='A';s.network.capture_epoch++;});
  assert.equal(f.resets(),0);assert.equal(f.api.baseline().tabId,'A','A→B→A keeps the same immutable capture');
}
for(const [name,change] of [
  ['same-target reconnect',s=>s.network.capture_epoch++],
  ['backend restart',s=>{focusB(s);s.network.instance_id='backend-two';}],
  ['generation regression',s=>{focusB(s);s.generation=1;}],
  ['generation regression at same epoch',s=>{s.generation=1;}],
  ['negative generation',s=>{focusB(s);s.generation=-1;}],
  ['missing generation at same epoch',s=>{s.generation=null;}],
  ['capture disabled',s=>{focusB(s);s.network.capture_enabled=false;}],
  ['monotonic-generation clear',s=>{s.network.requests=[];}],
  ['recycled public ID with new capture owner',s=>{focusB(s);s.network.requests[0].capture_owner='replacement-owner';}],
  ['recycled public ID with new target',s=>{focusB(s);s.network.requests[0].target_id='replacement-target';}],
  ['recycled public ID with new protocol ID',s=>{focusB(s);s.network.requests[0].protocol_request_id='replacement-protocol';}],
  ['recycled public ID with new start',s=>{focusB(s);s.network.requests[0].started_monotonic_ms++;}],
  ['recycled public ID with new wall time',s=>{focusB(s);s.network.requests[0].wall_time_ms++;}],
  ['missing immutable owner',s=>{focusB(s);delete s.network.requests[0].capture_owner;}],
  ['duplicate ambiguous rows',s=>{focusB(s);s.network.requests.push(structuredClone(s.network.requests[0]));}],
  ['duplicate rows at unchanged epoch',s=>{s.network.requests.push(structuredClone(s.network.requests[0]));}],
  ['distinct-identity public ID duplicate',s=>{s.network.requests.push({...structuredClone(s.network.requests[0]),capture_owner:'replacement',started_monotonic_ms:2});}],
  ['owner replaced without epoch change',s=>{s.network.requests[0].capture_owner='replacement-owner';}],
]) {
  const f=fixture();f.refresh(change);
  assert.equal(f.state.selectedCaptureIdentity,null,name);assert.equal(f.api.baseline(),null,name);
  f.refresh(s=>{Object.assign(s,session());s.generation=20;});
  assert.equal(f.state.selectedCaptureIdentity,null,`${name}: no silent rebind`);assert.equal(f.api.baseline(),null,`${name}: baseline stays expired`);
}
{
  const f=fixture();delete f.state.debuggerSession.network.requests[0].capture_owner;f.state.nativeRequests=f.api.requestsFromDebuggerNetwork(f.state.debuggerSession.network);f.api.rebuildTrafficRequests();
  // A legacy row can be explicitly selected, but cannot survive a focus epoch change.
  const a=f.state.requests[0];f.state.selectedCaptureIdentity=f.api.apiCatalogRequestIdentity(a);f.state.selectedRequestId=a.id;
  assert(f.api.pin(a));f.refresh(focusB);assert.equal(f.state.selectedCaptureIdentity,null);assert.equal(f.api.baseline(),null);
}
{
  const f=fixture();const native={id:'native-row',origin:'live',operation:'request_started'};
  f.state.nativeRequests=[native];f.state.requests=[native];f.state.selectedRequestId=native.id;
  f.state.selectedCaptureIdentity=null;f.state.debuggerSession.network.capture_enabled=false;
  f.refresh(null,false);assert.equal(f.state.selectedRequestId,native.id);assert.equal(f.resets(),0,'Native selection is untouched by HTTP ownership');
}
{
  const f=fixture();const events=[{protocol_version:3,tab_id:'11',category:'canvas'},
    {protocol_version:3,tab_id:'22',category:'webgl'},{protocol_version:3,tab_id:'11',category:'navigator'},
    {protocol_version:2,category:'canvas'},{protocol_version:3,tab_id:'0',category:'webgl'}];
  const all=f.api.fingerprintEventsFromEvents(events);
  assert.equal(all.filter(e=>f.api.signalTabKey(e)==='11').length,2);
  assert.equal(all.filter(e=>f.api.signalTabKey(e)==='22').length,1);
  assert.equal(all.filter(e=>f.api.signalTabKey(e)==='unattributed').length,2);
}
console.log('PASS retained HTTP selection/baseline across exact focus transitions; epoch/API guards, restart/reuse/clear/ambiguity invalidation and synthetic native fingerprint owner projection (model only)');
