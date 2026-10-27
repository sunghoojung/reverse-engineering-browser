#!/usr/bin/env node
// Authored local fixtures only. No real captures, target requests or mutation.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {runInNewContext} from 'node:vm';
import {network} from './traffic-capture-qa.mjs';

// Observe the completed viewport/layout boundary before the first action after
// passive-report cleanup. ResizeObserver/pane-layout work runs before the next
// frame; the second frame observes its result. This neither retries activation
// nor waits for a catalog fetch to hide a missed click.
export async function catalogActivationPoint() {
  const trigger=document.querySelector('#open-api-catalog');
  trigger.scrollIntoView({block:'nearest'});
  await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
  const r=trigger.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2;
  const hit=document.elementFromPoint(x,y);
  const receipt={x,y,left:r.left,right:r.right,top:r.top,bottom:r.bottom,
    viewport:{width:innerWidth,height:innerHeight},hit:hit?.id ?? null,
    passiveOpen:document.querySelector('#passive-security').open};
  if(trigger.disabled || receipt.passiveOpen || r.width<=0 || r.height<=0 ||
      r.left<0 || r.right>innerWidth || r.top<0 || r.bottom>innerHeight || !hit || !trigger.contains(hit)) {
    throw Error('Catalog activation target is not ready: '+JSON.stringify(receipt));
  }
  return receipt;
}

// A forced refresh can return immediately while an older poll is in flight.
// Select only after the expected fixture has reached the real Traffic model.
function catalogCaptureFixtureReady(generation, identity, evidence) {
  if (state.debuggerSession?.generation !== generation) return false;
  const record = apiCatalogResolveSource(identity, state.requests).record;
  return Boolean(record && JSON.stringify(record.captureRecord) === JSON.stringify(evidence));
}

function checkCatalogActivationReadiness() {
  const frames=[],rect=(y)=>({x:100,y,left:100,right:180,top:y,bottom:y+24,width:80,height:24});
  let painted=0,box=rect(700),overlay=false,passiveOpen=false,disabled=false;
  const trigger={id:'open-api-catalog',get disabled(){return disabled;},scrollIntoView(){},getBoundingClientRect:()=>box,contains:n=>n===trigger};
  const document={querySelector:s=>s==='#open-api-catalog'?trigger:{get open(){return passiveOpen;}},elementFromPoint:()=>overlay?{id:'foreign-overlay'}:trigger};
  const activation=runInNewContext('('+catalogActivationPoint.toString()+')',{document,innerWidth:1440,innerHeight:900,requestAnimationFrame:fn=>frames.push(fn)});
  const frame=()=>{const pending=frames.splice(0);painted++;for(const callback of pending)callback();};
  return (async()=>{
    // Counterexample: the old immediate click records the narrow-layout footer,
    // then scheduled responsive layout moves it before pointer release.
    const stale=box.y+box.height/2;
    frames.push(()=>{box=rect(850);});
    let settled=false;const pending=activation().then(value=>{settled=true;return value;});
    assert.equal(settled,false);frame();await Promise.resolve();assert.equal(settled,false);
    frame();const ready=await pending;
    assert.equal(painted,2);assert.notEqual(stale,ready.y);assert.equal(ready.y,862);
    assert.equal(ready.hit,'open-api-catalog');
    for(const blocked of ['overlay','passive','disabled','offscreen']) {
      overlay=blocked==='overlay';passiveOpen=blocked==='passive';disabled=blocked==='disabled';box=rect(blocked==='offscreen'?920:850);
      const rejected=assert.rejects(activation(),/Catalog activation target is not ready/);frame();frame();await rejected;
    }
    console.log('PASS catalog activation native-frame ordering, stale-coordinate counterexample and persistent overlay/modal/disabled/offscreen refusal (geometry model; not rendered QA)');
  })();
}
await checkCatalogActivationReadiness();
const root = resolve(new URL('..', import.meta.url).pathname);
const traffic = await readFile(join(root, 'apps/research-ui/traffic_view.js'), 'utf8');
const catalogSource = await readFile(join(root, 'apps/research-ui/api_catalog.js'), 'utf8');
const navigation = await readFile(join(root, 'apps/research-ui/investigation_navigation.js'), 'utf8');
const models = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const api = runInNewContext(`${models}\n${traffic}\n${catalogSource}\n${navigation}\n;({isApiObservationCatalog,apiCatalogIdentity,apiCatalogRequestIdentity,apiCatalogResolveSource,apiCatalogShapePath,apiCatalogSearchText,apiCatalogFilter,apiCatalogCompareBodies,requestsFromDebuggerNetwork,trafficRowsForLiveCapture,investigationRequestIdentity,investigationSame,isDebuggerResponse})`,
  {TextEncoder, TextDecoder, Uint8Array, URL, atob});
const copy = value => JSON.parse(JSON.stringify(value));
export async function catalogFixture() {
  const debuggerState = JSON.parse(await readFile(join(root, 'apps/origin-trace-backend/assets/debugger-empty.json'), 'utf8'));
  debuggerState.network = network(); debuggerState.generation = 17; debuggerState.state = 'running';
  debuggerState.target = {id:'synthetic-target',type:'page',title:'Synthetic catalog fixture',url:'https://example.test/'};
  debuggerState.targets = [debuggerState.target]; debuggerState.live_tab_count = 1;
  debuggerState.network.requests = debuggerState.network.requests.slice(0, 1);
  debuggerState.network.requests[0].started_monotonic_ms = 100.0000001;
  const record = debuggerState.network.requests[0];
  record.response.body = {state:'available', mime:'application/json', text:'{"*":"value","items":[{"name":"a"},{"name":"b"}],"<img src=x onerror=alert(1)>":true}', base64:'', truncated:false, reason:''};
  const property = name => ({kind:'property', name});
  const side = {header_names:['content-type'],header_names_omitted:0,headers_truncated:false,
    body:{state:'available',mime:'application/json',status:'observed',reason:null,
      shape:{root_type:'object',node_count:8,max_depth_observed:3,properties:[
        {path:[property('*')],types:['string'],observations:1},
        {path:[property('items')],types:['array'],observations:1},
        {path:[property('items'),{kind:'array-element'}],types:['object'],observations:2},
        {path:[property('items'),{kind:'array-element'},property('name')],types:['string'],observations:2},
        {path:[property('<img src=x onerror=alert(1)>')],types:['boolean'],observations:1}
      ]}}};
  const observation = {source:{request_id:record.id,target_id:record.target_id,started_monotonic_ms:record.started_monotonic_ms},state:record.state,status:record.status,
    query_parameters:{names:['token'],omitted:2}, request:{...copy(side),headers_truncated:true,header_names_omitted:3,
      body:{state:'available',mime:'application/json',status:'unavailable',reason:'duplicate_json_key',shape:null}},response:side};
  const catalog = {format:'reb-api-observation-catalog-v1',coverage:{instance_id:debuggerState.network.instance_id,capture_epoch:debuggerState.network.capture_epoch,
    debugger_generation:17,capture_enabled:true,debugger_state:'running',retained_records:3,window_records:2,older_records_not_examined:1,capture_dropped_records:4,skipped_records:1},
    limits:{records:64,url_bytes:8192,body_bytes:32768,names_per_surface:64,name_bytes:256,shape_nodes:2048,shape_depth:16,shape_fields:64,shape_path_bytes:16384},
    endpoints:[{method:'POST',origin:'https://example.test',path:'/path',observations:[observation]}],
    limitations:['Authored bounded fixture. No real capture or target request.','Observations do not infer required fields, authentication, or a service contract.']};
  return {debuggerState,catalog};
}
function comparisonFixture(catalog) {
  const result = copy(catalog), endpoint = result.endpoints[0], first = endpoint.observations[0];
  const second = copy(first);
  second.source = {...first.source, request_id:'synthetic-variant', started_monotonic_ms:101};
  second.status = 201; second.query_parameters.names = ['cursor'];
  second.request = copy(first.response);
  const fields = second.response.body.shape.properties;
  fields[0].types = ['number']; fields[2].observations = 1;
  fields.splice(3, 1);
  fields.push({path:[{kind:'property',name:'added'}],types:['null'],observations:1});
  const third = copy(first);
  third.source = {...first.source, request_id:'synthetic-truncated', started_monotonic_ms:102};
  third.status = 503;
  third.response.body = {state:'truncated',mime:'application/json',status:'unavailable',reason:'body_truncated',shape:null};
  endpoint.observations.push(second,third);
  Object.assign(result.coverage,{window_records:4,retained_records:5});
  return result;
}
const fixture = await catalogFixture();
assert(api.isDebuggerResponse(fixture.debuggerState));
assert(api.isApiObservationCatalog(fixture.catalog));
const requests = api.requestsFromDebuggerNetwork(fixture.debuggerState.network);
const original = JSON.stringify(fixture.debuggerState.network);
const identity = api.apiCatalogIdentity(fixture.catalog.coverage, fixture.catalog.endpoints[0].observations[0].source);
assert.equal(api.apiCatalogResolveSource(identity, requests).record, requests[0]);
for (const [key, value] of [['instance','other'],['epoch',2],['request','other'],['target','other'],['started',100.0000002]]) {
  assert.equal(api.apiCatalogResolveSource({...identity,[key]:value}, requests).record,null,key);
}
assert.equal(Math.round(100.0000001*1e6), Math.round(100.0000002*1e6), 'Fixture proves rounded timestamp collision');
assert.equal(api.apiCatalogResolveSource(identity, []).record,null);
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
assert.equal(api.apiCatalogShapePath([{kind:'property',name:'*'},{kind:'array-element'},{kind:'property',name:''},{kind:'property',name:'a/b.c'}]), '$["*"][*][""]["a/b.c"]');
for (const mutate of [value=>value.format='other',value=>value.coverage.capture_epoch=1.2,value=>value.coverage.capture_epoch=Number.MAX_SAFE_INTEGER+1,
  value=>value.coverage.skipped_records=99,value=>value.coverage.window_records=64,value=>value.limits.records=65,
  value=>value.endpoints[0].observations[0].source.started_monotonic_ms=NaN,
  value=>value.endpoints[0].observations[0].request.body.shape={},
  value=>value.endpoints[0].observations[0].response.body.shape.properties[0].path[0].kind='unknown',
  value=>value.endpoints[0].observations[0].response.body.shape.properties[0].types=['invented'],
  value=>value.endpoints[0].observations[0].query_parameters.names=['same','same'],
  value=>value.endpoints[0].observations[0].query_parameters.names=['雪'.repeat(100)],
  value=>value.endpoints[0].observations[0].response.body.shape.properties[0].path[0].name='x'.repeat(257),
  value=>value.endpoints[0].observations[0].response.body.shape.properties.push({
    ...value.endpoints[0].observations[0].response.body.shape.properties[0], path:[{name:'*',kind:'property'}]}),
  value=>value.endpoints[0].observations[0].response.body.raw='must not be accepted']) {
  const malformed = copy(fixture.catalog); mutate(malformed); assert.equal(api.isApiObservationCatalog(malformed),false);
}
assert.equal(JSON.stringify(fixture.debuggerState.network),original,'Catalog consumption must not alter retained raw fields');
console.log('PASS catalog validator, independent coverage, five-value identity, rounded timestamp collision, ambiguity, typed paths, owner-safe navigation and immutable raw values');

checkComparison();
await checkController();
await checkHistory();

if (process.argv.includes('--browser') || process.argv.includes('--serve')) throw new Error('CDP browser automation was removed; this check covers offline models only.');
function checkComparison() {
  const catalog = comparisonFixture(fixture.catalog);
  assert(api.isApiObservationCatalog(catalog));
  const before = JSON.stringify(catalog), endpoint = catalog.endpoints[0], [reference, comparison, missing] = endpoint.observations;
  const index = [{endpoint, observations:endpoint.observations.map(observation=>({observation,text:api.apiCatalogSearchText(endpoint,observation)}))}];
  const filtered = (query='',response='all') => api.apiCatalogFilter(index,query,response).flatMap(entry=>entry.observations);
  assert.equal(filtered().length,3);
  for (const query of ['/PATH','POST','EXAMPLE.TEST','content-type','token','items','name','boolean','duplicate_json_key','application/json','<img src=x onerror=alert(1)>']) assert(filtered(query).length,query);
  for (const query of ['Bearer synthetic-auth','synthetic-json','secret-token','.*','not-observed']) assert.equal(filtered(query).length,0,query);
  assert.equal(filtered('cursor')[0],comparison);
  assert.equal(filtered('','json').length,2); assert.equal(filtered('','unavailable')[0],missing);
  assert.equal(filtered('503','error')[0],missing); assert.equal(filtered('201','error').length,0);
  const report = api.apiCatalogCompareBodies(reference.response.body,comparison.response.body);
  assert.equal(report.available,true); assert.equal(report.differences.length,4);
  const rows = new Map(report.differences.map(row=>[api.apiCatalogShapePath(row.path),row]));
  assert.deepEqual(copy(rows.get('$["*"]').reference.types),['string']);
  assert.deepEqual(copy(rows.get('$["*"]').comparison.types),['number']);
  assert.equal(rows.get('$["items"][*]').comparison.observations,1);
  assert.equal(rows.get('$["items"][*]["name"]').comparison,null);
  assert.equal(rows.get('$["added"]').reference,null);
  assert.equal(api.apiCatalogCompareBodies(reference.request.body,comparison.request.body).available,false);
  assert.equal(api.apiCatalogCompareBodies(reference.response.body,missing.response.body).comparison,'body_truncated');
  for (const reason of ['body_unavailable','body_truncated','base64_not_analyzed','not_json_media_type','body_byte_limit','malformed_json','duplicate_json_key','shape_resource_limit']) {
    const body = {...missing.response.body,reason};
    assert.equal(api.apiCatalogCompareBodies(body,reference.response.body).reference,reason);
    assert.equal(api.apiCatalogCompareBodies(body,body).differences.length,0);
  }
  const same = copy(reference.response.body);
  same.shape.properties.reverse(); same.shape.properties[0].path[0] = {name:'<img src=x onerror=alert(1)>',kind:'property'};
  assert.equal(api.apiCatalogCompareBodies(reference.response.body,same).differences.length,0,'Property serialization and field order do not invent differences');
  same.shape.root_type='array';
  assert.equal(api.apiCatalogShapePath(api.apiCatalogCompareBodies(reference.response.body,same).differences[0].path),'$');
  const special = copy(reference.response.body);
  special.shape.properties = ['*','','a/b.c','__proto__'].map(name=>({path:[{kind:'property',name}],types:['string','null'],observations:1}));
  special.shape.properties.push({path:[{kind:'array-element'}],types:['object'],observations:1});
  const reordered = copy(special); reordered.shape.properties.forEach(field=>field.types.reverse());
  assert.equal(api.apiCatalogCompareBodies(special,reordered).differences.length,0,'Type sets and typed special paths compare without collisions');
  reordered.shape.properties[0].types=['boolean'];
  assert.equal(api.apiCatalogCompareBodies(special,reordered).differences.length,1);
  const maximum = prefix=>({...reference.response.body,shape:{...reference.response.body.shape,properties:Array.from({length:64},(_,i)=>({path:[{kind:'property',name:prefix+i}],types:['string'],observations:1}))}});
  assert.equal(api.apiCatalogCompareBodies(maximum('before'),maximum('after')).differences.length,128,'Two bounded disjoint shapes remain bounded');
  assert.equal(JSON.stringify(catalog),before,'Filtering and comparison preserve the complete input');
  console.log('PASS structural search, response filters, typed-path/type/count differences, independent unavailable reasons, root and special-name cases, immutable bounded comparison');
}
async function checkController() {
  class Node {
    constructor(tag='div') {this.tagName=tag;this.children=[];this.events={};this.attributes={};this.dataset={};this.text='';this.open=false;this.value='';}
    set textContent(value) {this.text=String(value);this.children=[];}
    get textContent() {return this.text+this.children.map(child=>child.textContent).join('');}
    append(...children) {this.children.push(...children);}
    replaceChildren(...children) {this.children=children;this.text='';}
    setAttribute(key,value) {this.attributes[key]=String(value);}
    addEventListener(type,handler) {this.events[type]=handler;}
    click() {if(!this.disabled)this.events.click?.();}
    focus() {document.activeElement=this;}
    showModal() {this.open=true;}
    close() {this.open=false;this.events.close?.();}
  }
  const ids=new Map(['api-catalog','open-api-catalog','api-catalog-refresh','api-catalog-status','api-catalog-content','api-catalog-close','api-catalog-search','api-catalog-response','api-catalog-clear','api-catalog-filter-status'].map(id=>[id,new Node()]));
  const document={getElementById:id=>ids.get(id),createElement:tag=>new Node(tag)};
  ids.get('api-catalog-response').value='all';
  let encodedValues=0, ledgerReads=0;
  class CountedEncoder extends TextEncoder {encode(...args) {encodedValues++;return super.encode(...args);}}
  const install=runInNewContext(`${traffic}\n${catalogSource}\ninstallApiObservationCatalog`,{document,TextEncoder:CountedEncoder,AbortController,setTimeout,clearTimeout});
  let current=requests, opens=0, reads=0, mode='ready', release, supplied=fixture.catalog;
  const panel=install({getRequests:()=>{ledgerReads++;return current;},openRequest:()=>{opens++;return true;},fetchCatalog:async (path,options)=>{
    reads++;assert.equal(path,'/api/network/catalog');assert.equal(options.cache,'no-store');assert.equal(options.method,undefined);
    if(mode==='pending')await new Promise(done=>{release=done;});
    return {ok:mode!=='failure',status:mode==='failure'?503:200,text:async()=>JSON.stringify(mode==='malformed'?{bad:true}:mode==='comparison'?comparisonFixture(fixture.catalog):supplied)};
  }});
  const get=id=>ids.get(id),flush=()=>new Promise(done=>setImmediate(done));
  const all=(node,predicate)=>[...(predicate(node)?[node]:[]),...node.children.flatMap(child=>all(child,predicate))];
  assert.equal(reads,0);panel.sync();assert.equal(reads,0);
  get('open-api-catalog').click();await flush();assert.equal(reads,1);assert.match(get('api-catalog-status').textContent,/Snapshot loaded/);
  const group=all(get('api-catalog-content'),node=>node.className==='api-catalog-endpoint')[0];
  group.open=true;group.events.toggle();assert.equal(all(group,node=>node.tagName==='article').length,1);
  group.events.toggle();assert.equal(all(group,node=>node.tagName==='article').length,1,'Repeated toggle does not duplicate observations');
  const button=all(group,node=>node.tagName==='button')[0];assert.equal(button.disabled,false);
  assert.match(group.textContent,/\$\["\*"\]/);assert.match(group.textContent,/\$\["items"\]\[\*\]/);
  assert.match(group.textContent,/duplicate_json_key/);assert.match(group.textContent,/omitted occurrences: 3/);assert.match(group.textContent,/upstream headers truncated: yes/);
  assert.equal(all(group,node=>node.tagName==='img').length,0,'Captured names remain text');
  current=[];button.click();assert.equal(opens,0);assert.equal(button.disabled,true);assert.equal(get('api-catalog').open,true);
  current=requests;panel.sync();button.click();assert.equal(opens,1);assert.equal(get('api-catalog').open,false);
  get('open-api-catalog').click();assert.equal(reads,1,'Reopen does not read again');
  const preserved=get('api-catalog-content').children;
  for(const failing of ['failure','malformed']) {
    mode=failing;get('api-catalog-refresh').click();await flush();assert.equal(get('api-catalog-content').children,preserved);assert.match(get('api-catalog-status').textContent,/Previous snapshot preserved/);
  }
  mode='pending';get('api-catalog-refresh').click();await flush();assert.equal(get('api-catalog-refresh').disabled,true);
  get('api-catalog-close').click();assert.equal(get('api-catalog-content').attributes['aria-busy'],'false');assert.match(get('api-catalog-status').textContent,/canceled.*preserved/);
  get('open-api-catalog').click();const readCount=reads;release();await flush();assert.equal(reads,readCount);assert.equal(get('api-catalog-content').children,preserved,'Late closed response does not replace retained snapshot');
  for(const key of [{key:'p',ctrlKey:true},{key:'ArrowLeft',altKey:true},{key:'j',metaKey:true},{key:'Escape'},{key:'Tab'}]) {
    let stopped=false,prevented=false;get('api-catalog').events.keydown({...key,stopPropagation:()=>{stopped=true;},preventDefault:()=>{prevented=true;}});
    assert.equal(stopped,true);assert.equal(prevented,!['Escape','Tab'].includes(key.key));
  }
  mode='comparison';get('api-catalog-refresh').click();await flush();
  const comparisonGroup=all(get('api-catalog-content'),node=>node.className==='api-catalog-endpoint')[0];
  comparisonGroup.open=true;comparisonGroup.events.toggle();
  const controls=all(comparisonGroup,node=>node.className==='api-catalog-compare-controls')[0];
  const [left,right]=all(controls,node=>node.tagName==='select');
  const compare=all(controls,node=>node.tagName==='button')[0];
  const result=all(comparisonGroup,node=>node.className==='api-catalog-comparison-result')[0];
  const explicitReads=reads;
  compare.click();assert.match(result.textContent,/4 observed difference/);assert.match(result.textContent,/duplicate_json_key/);
  const firstResult=result.textContent;compare.click();assert.equal(result.textContent,firstResult,'Repeated compare replaces rather than duplicates the report');
  right.value='2';right.events.change();assert.equal(result.textContent,'');compare.click();assert.match(result.textContent,/body_truncated/);
  right.value='0';right.events.change();assert.equal(compare.disabled,true);assert.match(result.textContent,/two different captured source identities/);
  left.value='1';left.events.change();assert.equal(compare.disabled,false);compare.click();assert.match(result.textContent,/4 observed difference/);
  const changeSearch=value=>{get('api-catalog-search').value=value;get('api-catalog-search').events.input();};
  changeSearch('cursor');assert.match(get('api-catalog-filter-status').textContent,/1 of 3 observations/);
  assert.equal(all(get('api-catalog-content'),node=>node.tagName==='article').length,1,'Filtering preserves expansion and exact observation selection');
  assert.equal(all(get('api-catalog-content'),node=>node.className==='api-catalog-comparison').length,0,'One matching observation cannot compare against hidden rows');
  changeSearch('not-observed');assert.match(get('api-catalog-content').textContent,/No observations match/);
  assert.match(get('api-catalog-content').textContent,/4 examined of 5 retained/,'Filtering never rewrites coverage');
  get('api-catalog-clear').click();assert.equal(document.activeElement,get('api-catalog-search'));
  assert.equal(all(get('api-catalog-content'),node=>node.tagName==='article').length,3);
  get('api-catalog-response').value='error';get('api-catalog-response').events.change();
  assert.match(get('api-catalog-filter-status').textContent,/1 of 3 observations/);assert.match(get('api-catalog-content').textContent,/503/);
  const filteredContent=get('api-catalog-content').children;
  mode='failure';get('api-catalog-refresh').click();await flush();assert.equal(get('api-catalog-content').children,filteredContent);
  assert.equal(get('api-catalog-response').value,'error','Failed refresh preserves filters and the rendered result');
  get('api-catalog-clear').click();assert.equal(reads,explicitReads+1,'Only explicit refresh fetches; filtering and comparison stay local');
  assert.equal(JSON.stringify(fixture.debuggerState.network),original);
  // All 64 groups expanded against the full 1,000-record ledger. Count work
  // instead of timing: no cumulative rescan for each freshly rebuilt group.
  current=Array.from({length:1000},(_,index)=>({...requests[0],id:`bounded-${index}`,
    captureRecord:{...requests[0].captureRecord,id:`bounded-${index}`,started_monotonic_ms:100+index}}));
  supplied=copy(fixture.catalog);
  supplied.endpoints=Array.from({length:64},(_,index)=>({...copy(fixture.catalog.endpoints[0]),path:`/group-${index}`,
    observations:[{...copy(fixture.catalog.endpoints[0].observations[0]),source:{request_id:`bounded-${index}`,target_id:requests[0].tabId,started_monotonic_ms:100+index}}]}));
  Object.assign(supplied.coverage,{window_records:64,retained_records:64,older_records_not_examined:0,skipped_records:0});
  assert(api.isApiObservationCatalog(supplied));
  mode='ready';get('api-catalog-refresh').click();await flush();
  for(const endpoint of all(get('api-catalog-content'),node=>node.className==='api-catalog-endpoint')) {endpoint.open=true;endpoint.events.toggle();}
  const beforeLedgerReads=ledgerReads, beforeEncodedValues=encodedValues;
  changeSearch('group');
  assert.equal(ledgerReads-beforeLedgerReads,1,'A filtered render snapshots the Traffic ledger exactly once');
  assert.equal(encodedValues-beforeEncodedValues,64*6,'Only 64 snapshot identities and matching Traffic identities are validated, not every unrelated retained row');
  const sourceButtons=all(get('api-catalog-content'),node=>node.tagName==='button');
  assert.equal(sourceButtons.length,64);assert(sourceButtons.every(button=>!button.disabled));
  current.push({...current[0],captureOwner:['other-instance',1]});panel.sync();
  assert.equal(sourceButtons[0].disabled,true,'Indexed lookup keeps same-ID collisions in other capture owners ambiguous');
  assert.equal(sourceButtons[1].disabled,false);
  current=requests;
  get('api-catalog').close();
  console.log('PASS catalog DOM/controller: explicit-only reads, lazy disclosure, inert names, click-time expiry, raw handoff, filtered comparison controls, stale result clearing, preserved failed/malformed snapshots, canceled late responses and modal shortcut isolation (not rendered QA)');
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
