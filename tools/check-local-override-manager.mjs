import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import manager from '../apps/research-ui/local_override_manager.js';

const file = value => new Blob([value]);
const selected = {targetId:'owned',experimentId:7};
const session = () => ({state:'running',target:{id:'owned'},action_scope:{mode:'target',target_id:'owned'},
  request_interception:{isolated:true,state:'ready',target_id:'owned',experiment_id:7,rule:{mode:'continue'}}});
const options = {url:'http://127.0.0.1:17777/fixture.js?exact=1',method:'GET',contentType:'text/javascript; charset=utf-8',ttlMs:60000,reviewed:true};
const asset = await manager.snapshot(file('globalThis.fixture = 1;'));
assert(Object.isFrozen(asset));
const action = manager.prepare(asset,options,selected,10000);
assert(Object.isFrozen(action) && Object.isFrozen(action.local_override));
assert.equal(action.response_body,asset.body);
assert.equal(action.local_override.expires_at_ms,70000);
assert.equal(manager.context(session()).targetId,'owned');
assert(manager.canArm(action,session(),69999));
assert(!manager.canArm(action,session(),70000));
assert(!manager.canArm(action,{...session(),target:{id:'different'}},20000));
assert.equal(manager.context({...session(),action_scope:{mode:'global'}}),null);
assert.equal(manager.context({...session(),request_interception:{...session().request_interception,experiment_id:8}}).experimentId,8);
assert(!manager.canArm(action,{...session(),request_interception:{...session().request_interception,experiment_id:8}},20000));
assert.throws(()=>manager.prepare(asset,{...options,reviewed:false},selected));
for (const url of ['https://example.test','https://u:p@example.test/','https://example.test/#x','file:///tmp/a','https://example.test/\n']) assert.throws(()=>manager.prepare(asset,{...options,url},selected));
for (const ttlMs of [0,999,300001,NaN,Infinity]) assert.throws(()=>manager.prepare(asset,{...options,ttlMs},selected));
await assert.rejects(manager.snapshot(file(new Uint8Array([0xc0,0xaf]))),/UTF-8/);
await assert.rejects(manager.snapshot(file('x'.repeat(65537))),/64 KiB/);
assert.equal((await manager.snapshot(file('x'.repeat(65536)))).bytes,65536);
assert.equal((await manager.snapshot(file(''))).sha256,'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
assert.equal((await manager.snapshot(file('\ufeffx'))).body,'\ufeffx');
let mutable = 'before';
const changingFile = {size:6,slice() { return file(mutable); }};
const frozen = await manager.snapshot(changingFile); mutable = 'after!';
assert.equal(frozen.body,'before');
assert.equal(manager.prepare(frozen,options,selected).response_body,'before');
await assert.rejects(manager.snapshot({size:2,slice:()=>file('changed')}),/changed/);
const guarded = manager.disarm(action);
assert.deepEqual(guarded.expected_local_override,{metadata:action.local_override,method_filter:'GET',content_type:options.contentType});
const publicRule = {mode:'fulfill',method_filter:'GET',response_code:200,response_body_bytes:asset.bytes,
  local_override:{...action.local_override,exact_url:'http://127.0.0.1:17777/fixture.js'}};
assert(manager.summaryMatches(action,{...session().request_interception,rule:publicRule}));
assert(!manager.summaryMatches(action,{...session().request_interception,rule:{...publicRule,local_override:{...publicRule.local_override,asset_sha256:'0'.repeat(64)}}}));

// Controller-level races use the same actual module and deterministic DOM doubles.
class Control {
  constructor() {this.value='';this.checked=false;this.disabled=false;this.listeners={};this.files=[];this.textContent='';}
  addEventListener(name,handler) {this.listeners[name]=handler;}
  async event(name) {return this.listeners[name]?.();}
}
const controls = Object.fromEntries(['file','preview','facts','status','review','prepare','arm','disarm','clear','url','method','type','ttl'].map(name=>[name,new Control()]));
controls.url.value=options.url;controls.method.value='GET';controls.type.value=options.contentType;controls.ttl.value='60';
const events={},timers=[];
const scope = {TextEncoder,TextDecoder,URL,crypto:globalThis.crypto,console,Uint8Array,Date,
  setInterval:handler=>{timers.push(handler);return timers.length;},clearInterval:()=>{},addEventListener:(name,handler)=>{events[name]=handler;}};
runInNewContext(await readFile(new URL('../apps/research-ui/local_override_manager.js',import.meta.url),'utf8'),scope);
let current=session(),key='one',calls=[],answer=null;
const panel=scope.RebLocalOverrideManager.install({root:{querySelector:selector=>controls[selector.match(/data-override-(.+)]/)[1]]},getSession:()=>current,contextKey:()=>key,busy:()=>false,
  run:async request=>{calls.push(request);return answer;}});
let release;
controls.file.files=[{size:1,name:'review.js',slice:()=>({arrayBuffer:()=>new Promise(resolve=>{release=resolve;})})}];
const read=controls.file.event('change');
assert(controls.review.disabled);controls.review.checked=true;
release(new TextEncoder().encode('x').buffer);await read;
assert(!controls.review.checked);assert(controls.prepare.disabled);
controls.review.checked=true;await controls.review.event('change');await controls.prepare.event('click');
assert(!controls.arm.disabled);assert.equal(calls.length,0);
key='two';panel.render();assert(!controls.review.checked);assert(controls.arm.disabled);
controls.review.checked=true;await controls.review.event('change');await controls.prepare.event('click');
await controls.arm.event('click');await new Promise(resolve=>setImmediate(resolve));
assert.equal(calls.length,1);assert.match(controls.status.textContent,/outcome unknown/);assert(!controls.disarm.disabled);
await controls.clear.event('click');assert.equal(controls.preview.value,'');assert(!controls.disarm.disabled);
await controls.disarm.event('click');await new Promise(resolve=>setImmediate(resolve));
assert.equal(calls.length,2);assert.equal(calls[1].mode,'continue');assert.equal(calls[1].expected_local_override.metadata.exact_url,options.url);
key='three';panel.render();assert(controls.disarm.disabled);
events.pagehide();events.pageshow();assert.equal(timers.length,2);

// Extract the actual shared transport and prove narrow override deadlines release
// both unresponsive header/body waits, ignore late replies, and never retry.
const app = await readFile(new URL('../apps/research-ui/app.js',import.meta.url),'utf8');
const start=app.indexOf('      async function debuggerAction('),end=app.indexOf('\n      function debuggerScriptCatalogSignature',start);
for (const stalledBody of [false,true]) {
  let resolveTransport,deadline,fetches=0,aborted=false;
  const state={debuggerActionPending:false,debuggerRefreshing:true};
  const delayed=new Promise(resolve=>{resolveTransport=resolve;});
  const sandbox={state,AbortController:class {signal={};abort(){aborted=true;}},Promise,Error,JSON,
    memoryOriginTraceActive:()=>false,memoryActionDeadline:()=>0,renderDebugger:()=>{},renderMemory:()=>{},scheduleDebuggerRefresh:()=>{},
    setTimeout:(handler,ms)=>{assert.equal(ms,10000);deadline=handler;return 1;},clearTimeout:()=>{},
    fetch:()=>{fetches++;return stalledBody?Promise.resolve({ok:true,json:()=>delayed}):delayed;}};
  runInNewContext(app.slice(start,end)+'\nglobalThis.invoke=debuggerAction;',sandbox);
  const result=sandbox.invoke(action,null,{});await Promise.resolve();deadline();
  assert.equal(await result,null);assert(!state.debuggerActionPending);assert.equal(state.debuggerActionOwner,null);assert(aborted);assert.equal(fetches,1);
  resolveTransport(stalledBody?{ok:true}:{ok:true,json:async()=>({ok:true})});await Promise.resolve();await Promise.resolve();
  assert(!state.debuggerActionPending);assert.match(state.debuggerError,/completion is unknown/);
}
console.log('Local override manager: frozen files, UTF-8/size/digest, review races, scope/expiry, guarded disarm, BFCache and unknown/no-retry transport checks passed.');

for (const path of ['apps/research-ui/index.html','apps/origin-trace-backend/src/app.rs','apps/research-ui/macos/OriginTraceApp.swift','scripts/build-research-app.sh']) {
  assert((await readFile(new URL('../'+path,import.meta.url),'utf8')).includes('local_override_manager.js'), 'Missing asset wiring: '+path);
}
