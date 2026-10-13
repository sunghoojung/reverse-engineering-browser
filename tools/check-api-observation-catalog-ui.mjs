#!/usr/bin/env node
// Authored local fixtures only. No real captures, target requests or mutation.
import assert from 'node:assert/strict';
import {readFile, writeFile, mkdtemp, mkdir, rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {runInNewContext} from 'node:vm';
import {network} from './traffic-capture-qa.mjs';

const root = resolve(new URL('..', import.meta.url).pathname);
const traffic = await readFile(join(root, 'apps/research-ui/traffic_view.js'), 'utf8');
const catalogSource = await readFile(join(root, 'apps/research-ui/api_catalog.js'), 'utf8');
const navigation = await readFile(join(root, 'apps/research-ui/investigation_navigation.js'), 'utf8');
const models = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const api = runInNewContext(`${models}\n${traffic}\n${catalogSource}\n${navigation}\n;({isApiObservationCatalog,apiCatalogIdentity,apiCatalogRequestIdentity,apiCatalogResolveSource,apiCatalogShapePath,apiCatalogSearchText,apiCatalogFilter,apiCatalogCompareBodies,requestsFromDebuggerNetwork,investigationRequestIdentity,investigationSame,isDebuggerResponse})`,
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

if (process.argv.includes('--browser') || process.argv.includes('--serve')) await checkBrowser();
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
async function checkBrowser() {
  const html = await readFile(join(root,'apps/research-ui/index.html'),'utf8');
  const assets = new Set(['index.html', ...[...html.matchAll(/(?:src|href)="([^"/]+\.(?:js|css))"/g)].map(match=>match[1])]);
  const logs = [], mutations = [], errors = []; let mode = 'ready', catalogReads = 0, held = [];
  const server = createServer(async (request,response) => {
    if(request.headers.host !== `127.0.0.1:${server.address().port}`) {response.writeHead(400);response.end();return;}
    const reply = (status,value,type='application/json') => {response.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store'});response.end(type==='application/json'?JSON.stringify(value):value);};
    if(request.method !== 'GET') {mutations.push(request.url.slice(0,1024));if(mutations.length>64)mutations.shift();reply(405,{});return;}
    const path = request.url.split('?')[0]; logs.push(path.slice(0,1024));if(logs.length>256)logs.shift();
    if(path === '/api/network/catalog') {
      catalogReads++;
      if(mode==='pending') {held.push(()=>reply(200,fixture.catalog));return;}
      if(mode==='failure') {reply(503,{});return;}
      if(mode==='malformed') {reply(200,{format:'wrong'});return;}
      if(mode==='comparison') {reply(200,comparisonFixture(fixture.catalog));return;}
      if(mode==='empty'||mode==='off') {const empty=copy(fixture.catalog);empty.endpoints=[];Object.assign(empty.coverage,{retained_records:0,window_records:0,older_records_not_examined:0,skipped_records:0,capture_enabled:mode==='empty',debugger_state:'unavailable'});reply(200,empty);return;}
      reply(200,fixture.catalog);return;
    }
    if(path==='/api/debugger') {reply(200,fixture.debuggerState);return;}
    if(path==='/api/events') {reply(200,{count:0,events:[],capture_mode:'live',capture_content_enabled:true,broker_connected:false,capture_controls_available:false});return;}
    if(path==='/api/artifacts') {reply(200,{count:0,artifacts:[]});return;}
    if(path.startsWith('/api/')) {reply(503,{error:'Synthetic fixture unavailable'});return;}
    const name=path==='/'?'index.html':path.slice(1);
    if(!assets.has(name)) {reply(404,{});return;}
    reply(200,await readFile(join(root,'apps/research-ui',name)),name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':'text/html');
  });
  const directory=await mkdtemp(join(tmpdir(),'reb-api-catalog-ui-'));
  const output=resolve(process.env.REB_API_CATALOG_QA_OUTPUT || join(root,'build/api-catalog-ui'));
  await mkdir(output,{recursive:true});
  await rm(join(output,'validation.json'),{force:true});
  await rm(join(output,'failure.png'),{force:true});
  let browser, socket, sequence=0, diagnostics='', phase='fixture startup', firstFailure=null, browserClosed=false; const commands=new Map();
  const grouped=process.platform!=='win32';
  const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
  async function until(check,description) {phase=description;for(let i=0;i<200;i++){const value=await check();if(value)return value;await delay(50);}throw new Error(`Timed out: ${description}`);}
  const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence,timer=setTimeout(()=>{commands.delete(id);reject(new Error(`CDP timeout: ${method}`));},10000);commands.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params}));});
  const evaluate=async expression=>{const result=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw new Error(result.exceptionDetails.text+' '+JSON.stringify(result.exceptionDetails.exception));return result.result.value;};
  const key=async (key,code)=>{
    const windowsVirtualKeyCode={Tab:9,Enter:13,Escape:27,Home:36,End:35,ArrowDown:40,ArrowUp:38}[key];
    // Match the repository's native CDP input shape. Enter needs its character
    // event for native summary/button activation, not only a keydown event.
    await send('Input.dispatchKeyEvent',{type:key==='Enter'?'keyDown':'rawKeyDown',key,code,windowsVirtualKeyCode,
      ...(key==='Enter'?{text:'\r',unmodifiedText:'\r'}:{})});
    await send('Input.dispatchKeyEvent',{type:'keyUp',key,code,windowsVirtualKeyCode});
  };
  const click=async selector=>{const point=await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});n.scrollIntoView({block:'nearest'});const r=n.getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2};})()`);await send('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});await send('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});};
  const shot=async name=>{const result=await send('Page.captureScreenshot',{format:'png'});await writeFile(join(output,`${name}.png`),Buffer.from(result.data,'base64'));};
  const scrollCatalogTo=async selector=>{
    const geometry=await evaluate(`(()=>{const c=document.querySelector('#api-catalog-content').getBoundingClientRect(),r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return{x:c.x+c.width/2,y:c.y+c.height/2,deltaY:r.top-c.top-8};})()`);
    await send('Input.dispatchMouseEvent',{type:'mouseWheel',...geometry,deltaX:0});
    await until(()=>evaluate(`(()=>{const c=document.querySelector('#api-catalog-content').getBoundingClientRect(),r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return r.top>=c.top-1&&r.bottom<=c.bottom+1;})()`),'comparison result visible after pointer scroll');
  };
  try {
    await new Promise(ready=>server.listen(0,'127.0.0.1',ready));
    if (process.argv.includes('--serve')) {
      console.log(`Synthetic catalog UI: http://127.0.0.1:${server.address().port}/`);
      await new Promise(done => {process.once('SIGINT',done);process.once('SIGTERM',done);});
      return;
    }
    const executable=process.env.REB_UI_CHROMIUM || '/usr/bin/chromium';
    browser=spawn(executable,['--headless=new','--remote-debugging-port=0',`--user-data-dir=${directory}`,'--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','about:blank'],{detached:grouped,stdio:['ignore','ignore','pipe']});
    browser.once('close',()=>{browserClosed=true;});
    browser.stderr.on('data',chunk=>{diagnostics=(diagnostics+chunk).slice(-8192);}); browser.on('error',error=>{diagnostics=(diagnostics+error.message).slice(-8192);});
    const port=await until(async()=>{if(browser.exitCode!==null||browser.signalCode!==null)throw new Error(`Browser startup failed (${browser.exitCode ?? browser.signalCode}): ${diagnostics}`);try{return (await readFile(join(directory,'DevToolsActivePort'),'utf8')).split('\n')[0];}catch{return null;}},'sandboxed Chromium startup');
    const pages=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    socket=new WebSocket(pages.find(page=>page.type==='page').webSocketDebuggerUrl);
    await new Promise((ready,reject)=>{socket.addEventListener('open',ready,{once:true});socket.addEventListener('error',reject,{once:true});});
    socket.addEventListener('message',event=>{const message=JSON.parse(event.data);if(message.method==='Runtime.exceptionThrown'){errors.push(message.params.exceptionDetails);if(errors.length>32)errors.shift();}const command=commands.get(message.id);if(command){clearTimeout(command.timer);commands.delete(message.id);if(message.error)command.reject(new Error(message.error.message));else command.resolve(message.result);}});
    await send('Runtime.enable');await send('Page.enable');await send('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
    await send('Page.navigate',{url:`http://127.0.0.1:${server.address().port}/`});
    await until(()=>evaluate("typeof state !== 'undefined' && state.requests.length===1"),'loaded real Traffic UI');
    assert.equal(catalogReads,0,'Boot and debugger polling must not read catalog');
    const raw=await evaluate('JSON.stringify(state.requests[0].captureRecord)');
    await click('#open-api-catalog');
    await until(()=>evaluate("document.querySelector('#api-catalog-status').textContent.includes('Snapshot loaded')"),'catalog loaded');
    assert.equal(catalogReads,1);assert.equal(await evaluate('document.activeElement.id'),'api-catalog-close');
    for (const shortcut of [{key:'p',code:'KeyP',modifiers:2},{key:'ArrowLeft',code:'ArrowLeft',modifiers:1},{key:'j',code:'KeyJ',modifiers:2},{key:'F8',code:'F8'}]) {
      await send('Input.dispatchKeyEvent',{type:'keyDown',...shortcut});await send('Input.dispatchKeyEvent',{type:'keyUp',...shortcut});
      assert.equal(await evaluate("document.querySelector('#api-catalog').open && !document.querySelector('#screen-traffic').hidden && document.querySelector('#native-console-panel').hidden"),true,'Modal shortcuts cannot affect underlying workspace or console');
    }
    await key('Tab','Tab');assert.equal(await evaluate('document.activeElement.id'),'api-catalog-search');
    await send('Input.insertText',{text:'not-observed'});
    assert.equal(await evaluate("document.querySelectorAll('.api-catalog-endpoint').length"),0);
    assert.match(await evaluate("document.querySelector('#api-catalog-filter-status').textContent"),/0 of 1 observations/);
    assert.match(await evaluate("document.querySelector('#api-catalog-content').textContent"),/No observations match/);
    assert.equal(catalogReads,1,'Typing a local filter must not fetch');
    await key('Tab','Tab');assert.equal(await evaluate('document.activeElement.id'),'api-catalog-response');
    await key('Tab','Tab');assert.equal(await evaluate('document.activeElement.id'),'api-catalog-clear');
    await key('Enter','Enter');assert.equal(await evaluate('document.activeElement.id'),'api-catalog-search');
    await key('Tab','Tab');await key('Tab','Tab');assert.equal(await evaluate('document.activeElement.id'),'api-catalog-content');
    await key('Tab','Tab');await key('Tab','Tab');
    assert.equal(await evaluate("document.activeElement.matches('.api-catalog-endpoint > summary')"),true);
    await key('Enter','Enter');
    await until(()=>evaluate("document.querySelectorAll('.api-catalog-observation').length===1"),'keyboard endpoint expansion');
    await key('Tab','Tab');assert.equal(await evaluate('document.activeElement.textContent'),'Open captured request');
    await key('Enter','Enter');
    await until(()=>evaluate("!document.querySelector('#api-catalog').open && state.selectedRequestId==='synthetic-json' && state.trafficDetailOpen"),'exact Traffic handoff');
    await until(()=>evaluate("document.activeElement.dataset.requestId==='synthetic-json'"),'destination request focus');
    assert.equal(await evaluate('state.selectedCaptureIdentity.started'),100.0000001);
    assert.equal(await evaluate('JSON.stringify(state.requests[0].captureRecord)'),raw);
    assert.equal(await evaluate('state.inspectorTab'),'headers');
    assert.match(await evaluate("document.querySelector('#exchange-inspector').textContent"),/Bearer synthetic-auth/,'Original header value remains visible');
    await click('#investigation-back');
    assert.equal(await evaluate('state.selectedRequestId===null && !state.trafficDetailOpen'),true,'Back restores the initial unselected, closed Traffic inspector');
    assert.equal(await evaluate("document.querySelectorAll('#request-rows [aria-selected=\"true\"]').length"),0,'Back immediately clears selected-row ARIA without waiting for polling');
    await click('#investigation-forward');
    assert.equal(await evaluate("state.selectedRequestId==='synthetic-json' && state.trafficDetailOpen"),true,'Forward restores exact selected capture');
    await click('#open-api-catalog');assert.equal(catalogReads,1,'Reopen retains explicit snapshot without fetching');
    await click('.api-catalog-side:last-child > summary');
    assert.equal(await evaluate("document.querySelectorAll('#api-catalog img').length"),0);
    assert.match(await evaluate("document.querySelector('#api-catalog-content').textContent"),/duplicate_json_key/);
    assert.match(await evaluate("document.querySelector('#api-catalog-content').textContent"),/\$\["\*"\]/);
    assert.match(await evaluate("document.querySelector('#api-catalog-content').textContent"),/\$\["items"\]\[\*\]/);
    for(const [width,height] of [[1440,900],[760,560],[360,740]]) {
      await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
      const geometry=await evaluate("(()=>{const d=document.querySelector('#api-catalog'),c=document.querySelector('#api-catalog-content'),r=d.getBoundingClientRect();return{left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:innerWidth,height:innerHeight,scroll:c.scrollHeight,client:c.clientHeight,overflow:document.documentElement.scrollWidth};})()");
      assert(geometry.left>=0&&geometry.right<=width&&geometry.top>=0&&geometry.bottom<=height&&geometry.client>80&&geometry.overflow<=width,JSON.stringify(geometry));
      for(const selector of ['#api-catalog-close','#api-catalog-refresh']) assert.equal(await evaluate(`(()=>{const r=document.querySelector('${selector}').getBoundingClientRect();return r.width>0&&r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight;})()`),true);
      await shot(`catalog-${width}`);
      const box=await evaluate("(()=>{const r=document.querySelector('#api-catalog-content').getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2};})()");
      await send('Input.dispatchMouseEvent',{type:'mouseWheel',...box,deltaY:600,deltaX:0});await delay(120);
      if(geometry.scroll>geometry.client)assert((await evaluate("document.querySelector('#api-catalog-content').scrollTop"))>0);
      await shot(`catalog-${width}-shape`);
    }
    mode='failure';await click('#api-catalog-refresh');await until(()=>evaluate("document.querySelector('#api-catalog-status').textContent.includes('Previous snapshot preserved')"),'failed refresh');
    assert.equal(await evaluate("document.querySelectorAll('.api-catalog-observation').length"),1);await shot('catalog-refresh-failure');
    mode='malformed';await click('#api-catalog-refresh');await until(()=>evaluate("document.querySelector('#api-catalog-status').textContent.includes('Malformed')"),'malformed catalog');
    assert.equal(await evaluate("document.querySelectorAll('.api-catalog-observation').length"),1);
    const beforeEpoch=fixture.debuggerState.network.capture_epoch;fixture.debuggerState.network.capture_epoch++;
    await evaluate('refreshDebugger(true)');
    await until(()=>evaluate("document.querySelector('.api-catalog-observation button').disabled"),'owner replacement invalidation');
    assert.equal(await evaluate('state.selectedRequestId'),null);assert.match(await evaluate("document.querySelector('#api-catalog-content').textContent"),/Source is not retained/);
    await shot('catalog-expired-source');
    fixture.debuggerState.network.capture_epoch=beforeEpoch;await evaluate('refreshDebugger(true)');
    await until(()=>evaluate("!document.querySelector('.api-catalog-observation button').disabled"),'exact source available again');
    mode='pending';await click('#api-catalog-refresh');await until(()=>Promise.resolve(held.length>0),'held catalog request');
    assert.match(await evaluate("document.querySelector('#api-catalog-status').textContent"),/Refreshing/);
    await key('Escape','Escape');assert.equal(await evaluate("document.querySelector('#api-catalog').open"),false);
    held.splice(0).forEach(release=>release());await delay(100);
    assert.match(await evaluate("document.querySelector('#api-catalog-status').textContent"),/canceled.*preserved/);
    await click('#open-api-catalog');assert.equal(await evaluate("document.querySelectorAll('.api-catalog-observation').length"),1,'Late canceled response cannot replace prior DOM');
    for(const variant of ['off','empty']) {
      mode=variant;await click('#api-catalog-refresh');await until(()=>evaluate("document.querySelector('#api-catalog-status').textContent.includes('Snapshot loaded')"),`${variant} catalog`);
      assert.equal(await evaluate("document.querySelectorAll('.api-catalog-endpoint').length"),0);
      assert.match(await evaluate("document.querySelector('#api-catalog-content').textContent"),variant==='off'?/Content capture is off/:/No eligible HTTP/);await shot(`catalog-${variant}`);
    }
    mode='comparison';await click('#api-catalog-refresh');
    await until(()=>evaluate("document.querySelector('#api-catalog-filter-status').textContent.includes('3 of 3 observations')"),'comparison snapshot');
    const beforeComparisonReads=catalogReads;
    await click('.api-catalog-endpoint > summary');
    await until(()=>evaluate("document.querySelectorAll('.api-catalog-observation').length===3"),'comparison endpoint expansion');
    await click('.api-catalog-compare-controls button');
    assert.match(await evaluate("document.querySelector('.api-catalog-comparison-result').textContent"),/4 observed difference/);
    assert.match(await evaluate("document.querySelector('.api-catalog-comparison-result').textContent"),/duplicate_json_key/);
    assert.equal(await evaluate("document.querySelectorAll('.api-catalog-differences li').length"),4);
    assert.equal(await evaluate("document.querySelectorAll('#api-catalog img').length"),0);
    for(const [width,height] of [[1440,900],[760,560],[360,740]]) {
      await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
      await evaluate("document.querySelector('.api-catalog-comparison').scrollIntoView({block:'start'})");
      const geometry=await evaluate("(()=>{const c=document.querySelector('#api-catalog-content'),f=document.querySelector('.api-catalog-filters');return {height:c.clientHeight,overflow:document.documentElement.scrollWidth,contentOverflow:c.scrollWidth-c.clientWidth,filters:[...f.querySelectorAll('input,select,button')].map(n=>{const r=n.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight;})};})()");
      assert(geometry.height>=80&&geometry.overflow<=width&&geometry.contentOverflow<=1&&geometry.filters.every(Boolean),JSON.stringify(geometry));
      await shot(`catalog-comparison-${width}`);
    }
    await scrollCatalogTo('.api-catalog-differences li');
    await shot('catalog-comparison-differences-360');
    await evaluate("document.querySelector('.api-catalog-compare-controls label:nth-child(2) select').focus()");
    await key('End','End');
    assert.equal(await evaluate("document.querySelector('.api-catalog-compare-controls label:nth-child(2) select').value"),'2');
    assert.equal(await evaluate("document.querySelector('.api-catalog-comparison-result').textContent"),'','Changing a comparison choice clears stale results');
    await click('.api-catalog-compare-controls button');
    assert.match(await evaluate("document.querySelector('.api-catalog-comparison-result').textContent"),/body_truncated/);
    await scrollCatalogTo('.api-catalog-comparison-result p:last-child');
    await shot('catalog-comparison-unavailable-360');
    // Programmatic focus avoids opening a platform select popup; the selection
    // itself still uses keyboard input, including the same-source refusal.
    await evaluate("document.querySelector('.api-catalog-compare-controls label:nth-child(2) select').focus()");
    await key('Home','Home');
    assert.equal(await evaluate("document.querySelector('.api-catalog-compare-controls button').disabled"),true);
    assert.match(await evaluate("document.querySelector('.api-catalog-comparison-result').textContent"),/two different captured source identities/);
    await click('#api-catalog-search');await send('Input.insertText',{text:'cursor'});
    assert.match(await evaluate("document.querySelector('#api-catalog-filter-status').textContent"),/1 of 3 observations/);
    assert.equal(await evaluate("document.querySelectorAll('.api-catalog-comparison').length"),0);
    assert.equal(await evaluate("document.querySelectorAll('.api-catalog-observation').length"),1,'Expanded endpoint stays open after filtering');
    assert.match(await evaluate("document.querySelector('.api-catalog-observation').textContent"),/synthetic-variant/);
    await click('#api-catalog-clear');
    await evaluate("document.querySelector('#api-catalog-response').focus()");await key('End','End');
    assert.match(await evaluate("document.querySelector('#api-catalog-filter-status').textContent"),/1 of 3 observations/);
    assert.match(await evaluate("document.querySelector('.api-catalog-observation').textContent"),/503/);
    await click('#api-catalog-clear');
    assert.equal(catalogReads,beforeComparisonReads,'Filtering, clear, selection and comparison never fetch or send');
    await key('Escape','Escape');assert.equal(await evaluate('document.activeElement.id'),'open-api-catalog');
    assert.equal(await evaluate('JSON.stringify(state.requests[0].captureRecord)'),raw,'Raw record unchanged after catalog lifecycle');
    // Real full-ledger Traffic with a longer status and new-request control
    // keeps every footer action reachable. The existing Requests suite checks
    // the independent 56px-ledger / 80px-preview split-pane invariant.
    if(await evaluate("document.querySelector('#investigation-navigation details').open"))await click('#investigation-navigation details > summary');
    await click('[data-request-id="synthetic-json"]');await click('#request-detail-close');await click('#request-filter');
    await send('Input.insertText',{text:'new'});
    await until(()=>evaluate("JSON.parse(state.trafficFilterKey)[3]==='new' && document.querySelectorAll('#request-rows .request-row').length===0"),'settled Traffic filter before new arrivals');
    for(let index=1;index<=2;index++)fixture.debuggerState.network.requests.push({...copy(fixture.debuggerState.network.requests[0]),
      id:`footer-new-${index}`,protocol_request_id:`footer-new-${index}`,url:`https://example.test/new-${index}`,started_monotonic_ms:101+index});
    await until(()=>evaluate("state.requests.length===3 && !document.querySelector('#request-latest').hidden"),'new Traffic footer controls');
    assert.match(await evaluate("document.querySelector('#request-window-status').textContent"),/Selection outside filter/);
    const footer=await evaluate(`(()=>{const pane=document.querySelector('.request-pane').getBoundingClientRect(),
      table=document.querySelector('.request-table').getBoundingClientRect(),rows=document.querySelector('#request-rows').getBoundingClientRect();
      return {ledger:Math.min(rows.bottom,pane.bottom,table.bottom)-Math.max(rows.top,pane.top,table.top),
        controls:[...document.querySelectorAll('.request-window button:not([hidden])')].map(button=>{const r=button.getBoundingClientRect();
          return {id:button.id,visible:r.width>0&&r.left>=0&&r.right<=innerWidth&&r.top>=pane.top&&r.bottom<=Math.min(pane.bottom,table.bottom,innerHeight)};})};})()`);
    assert(footer.ledger>=56,JSON.stringify(footer));assert.equal(footer.controls.length,5);
    assert(footer.controls.every(control=>control.visible),JSON.stringify(footer));await shot('catalog-traffic-footer-360');
    // The catalog source opens the same retained capture used by the client workflow.
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
    await evaluate("elements.requestFilter.value=''; elements.requestFilter.dispatchEvent(new Event('input',{bubbles:true}));");
    await click('[data-request-id="synthetic-json"]');
    await click('#traffic-capture-export > summary');
    await click('[data-client-capture="draft"]');
    await until(()=>evaluate("document.querySelector('#captured-client-review').open"),'unsupported captured client review');
    assert.equal(await evaluate("document.querySelector('[data-client-apply]').disabled"),true);
    assert.match(await evaluate("document.querySelector('[data-client-review-content]').textContent"),/credential|credentials/);
    await shot('client-review-unsupported');await key('Escape','Escape');
    const selected=fixture.debuggerState.network.requests[0];
    selected.url='https://example.test/a%2Fb?x=1&%78=2&q=a+b&q=a%20b';
    selected.request.headers=[['Content-Type','application/json; charset=utf-8'],['X-Authored','exact-value']];
    selected.request.body.text='雪\r\n{"inert":"</script>"}';
    Object.assign(fixture.debuggerState.request_interception,{isolated:true,experiment_id:1,state:'ready',target_id:'synthetic-target',created_at_ms:1});
    Object.assign(fixture.debuggerState.repeater,{session_id:1,state:'ready'});
    fixture.debuggerState.generation++;
    assert(api.isDebuggerResponse(fixture.debuggerState),'Client fixture uses validated real debugger schema');
    await evaluate('refreshDebugger(true)');
    await until(()=>evaluate("state.debuggerSession.request_interception.isolated && state.requests[0].captureRecord.url.includes('a%2Fb')"),'eligible captured client fixture');
    await click('[data-request-id="synthetic-json"]');
    await evaluate("elements.repeaterRequestUrl.value='https://example.test/older-draft';state.repeaterDraftDirty=true;markRepeaterDraftChanged();");
    if(!await evaluate("document.querySelector('#traffic-capture-export').open"))await click('#traffic-capture-export > summary');
    await click('[data-client-capture="draft"]');
    assert.equal(await evaluate("document.querySelector('[data-client-apply]').disabled"),true,'Existing draft requires replacement confirmation');
    assert.equal(await evaluate("document.activeElement.matches('[data-client-close]')"),true);
    await click('.captured-client-content details:last-child > summary');
    for(const [width,height] of [[1440,900],[760,560],[360,740]]) {
      await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
      const geometry=await evaluate("(()=>{const d=document.querySelector('#captured-client-review'),c=d.querySelector('[data-client-review-content]'),r=d.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,client:c.clientHeight,overflow:document.documentElement.scrollWidth};})()");
      assert(geometry.left>=0&&geometry.right<=width&&geometry.top>=0&&geometry.bottom<=height&&geometry.client>=80&&geometry.overflow<=width,JSON.stringify(geometry));
      assert.equal(await evaluate("document.querySelectorAll('#captured-client-review script').length"),0);
      await shot(`client-review-${width}`);
    }
    await click('[data-client-replace]');
    assert.equal(await evaluate("document.querySelector('[data-client-apply]').disabled"),false);
    await click('[data-client-apply]');
    await until(()=>evaluate("!document.querySelector('#captured-client-review').open && !document.querySelector('#screen-experiments').hidden && state.experimentMode==='repeater'"),'reviewed exact Repeater draft');
    assert.equal(await evaluate('elements.repeaterRequestUrl.value'),selected.url);
    assert.equal(await evaluate('elements.repeaterRequestMethod.value'),'POST');
    assert.deepEqual(JSON.parse(await evaluate('elements.repeaterRequestHeaders.value')),Object.fromEntries(selected.request.headers));
    assert.equal(await evaluate('elements.repeaterRequestBody.value'),selected.request.body.text.replace(/\r\n?/g,'\n'),'Textarea display normalization is explicit');
    assert.equal(await evaluate('state.repeaterBodyRepresentation.text'),selected.request.body.text,'Original request body remains exact');
    await evaluate(`window.__clientSendFunctions={runExperimentAction,applyRepeaterVariables,currentExperimentReceipt};
      applyRepeaterVariables=async()=>({});currentExperimentReceipt=value=>value;
      runExperimentAction=async payload=>{window.__clientSubmitted=payload;return null;};`);
    await click('#repeater-send');
    await until(()=>evaluate("window.__clientSubmitted?.action==='run_repeater_request'"),'explicit reviewed request submission');
    assert.equal(await evaluate('window.__clientSubmitted.body'),selected.request.body.text,'Actual Send payload preserves original CRLF');
    await click('[data-repeater-editor-tab="body"]');
    await shot('client-repeater-original-body-360');
    await click('#repeater-request-body');
    await evaluate('elements.repeaterRequestBody.setSelectionRange(elements.repeaterRequestBody.value.length,elements.repeaterRequestBody.value.length);window.__clientSubmitted=null;');
    await send('Input.insertText',{text:'\nEdited deliberately'});
    await click('#repeater-send');
    await until(()=>evaluate("window.__clientSubmitted?.action==='run_repeater_request'"),'explicit edited request submission');
    assert.equal(await evaluate('window.__clientSubmitted.body'),selected.request.body.text.replace(/\r\n?/g,'\n')+'\nEdited deliberately','Explicit body edit uses editor line endings');
    await evaluate(`({runExperimentAction,applyRepeaterVariables,currentExperimentReceipt}=window.__clientSendFunctions);`);
    assert.equal(await evaluate('state.repeaterCaptureSource.source.identity.started'),100.0000001);
    await shot('client-repeater-edited-body-360');
    assert.deepEqual(mutations,[],'Review/import in an existing isolated context never sends target requests');
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
    await evaluate("showScreen('traffic')");
    if(!await evaluate("document.querySelector('#traffic-capture-export').open"))await click('#traffic-capture-export > summary');
    await send('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:output});
    await click('[data-client-capture="raw"]');
    const downloaded=await until(async()=>{try{return await readFile(join(output,'reb-client-project.raw.zip'));}catch{return null;}},'explicit client ZIP download');
    assert.equal(downloaded.readUInt32LE(0),0x04034b50);
    assert.deepEqual(mutations,[]);assert.deepEqual(errors,[]);
    await writeFile(join(output,'validation.json'),JSON.stringify({status:'passed',product_path:'browser development UI with authored loopback fixtures',viewports:[[1440,900],[760,560],[360,740]],catalog_reads:catalogReads,mutations,errors,screenshots:output,states:['deliberate-only','loading','ready','local structural search','response filters','two-observation structural comparison','unknown-side comparison','same-source refusal','comparison selection invalidation','exact Traffic handoff','refresh failure','malformed','epoch replacement','cancel late reply','capture off','empty','unsupported client review','dirty draft replacement','exact capture to Repeater','explicit ZIP download'],keyboard:['Tab filter focus','Enter clear filters','Home/End comparison selection','Enter endpoint expansion','Enter source handoff','Escape close'],native_macos:'not run; cloud-only scope'},null,2)+'\n');
    console.log(`PASS rendered catalog: keyboard and pointer, three viewports, scrolling, inert markup, raw header preservation, explicit read-only lifecycle, source invalidation. Evidence: ${output}`);
  } catch (error) {
    firstFailure=error;
    // Persist the first failure before browser teardown. Only the authored local
    // fixture is ever loaded; bound text diagnostics independently of screenshots.
    const failure={status:'failed',phase,error:String(error.stack ?? error).slice(0,8192),browser_stderr:diagnostics.slice(-8192),
      browser_exit:browser?.exitCode ?? null,browser_signal:browser?.signalCode ?? null,catalog_reads:catalogReads,
      requests:logs.slice(-256),mutations:mutations.slice(-64),runtime_errors:JSON.stringify(errors).slice(0,16384),rendered:false};
    if(socket?.readyState===WebSocket.OPEN) {
      try {await shot('failure');failure.rendered=true;failure.screenshot='failure.png';}
      catch(captureError){failure.screenshot_error=String(captureError).slice(0,2048);}
      try {failure.dom=await evaluate(`(()=>{const active=document.activeElement, dialog=document.querySelector('#api-catalog');
        const box=node=>{const r=node?.getBoundingClientRect();return r?{x:r.x,y:r.y,width:r.width,height:r.height}:null;};
        return {url:location.href,ready:document.readyState,viewport:{width:innerWidth,height:innerHeight},
          focus:active?{tag:active.tagName,id:active.id,classes:active.className,text:active.textContent.slice(0,256)}:null,
          catalog_open:dialog?.open ?? null,catalog_box:box(dialog),
          catalog_status:document.querySelector('#api-catalog-status')?.textContent.slice(0,2048),
          catalog_content:document.querySelector('#api-catalog-content')?.textContent.slice(0,4096),
          selected_request:typeof state==='undefined'?null:state.selectedRequestId,
          traffic_detail_open:typeof state==='undefined'?null:state.trafficDetailOpen,
          selected_rows:[...document.querySelectorAll('#request-rows [aria-selected="true"]')].slice(0,4).map(node=>node.dataset.requestId),
          screens:[...document.querySelectorAll('.screen:not([hidden])')].map(node=>node.id)};})()`);}
      catch(inspectError){failure.dom_error=String(inspectError).slice(0,2048);}
    }
    try {await writeFile(join(output,'validation.json'),JSON.stringify(failure,null,2)+'\n');}
    catch(writeError){console.error('Could not save catalog failure receipt:',String(writeError).slice(0,2048));}
    console.error(`Catalog browser failure at ${phase}; diagnostics: ${output}`);
    throw error;
  } finally {
    const cleanupErrors=[];let profileReleased=!browser?.pid;
    const cleanup=async task=>{try{await task();}catch(error){cleanupErrors.push(String(error).slice(0,2048));}};
    await cleanup(async()=>{held.splice(0).forEach(release=>release());for(const command of commands.values())clearTimeout(command.timer);socket?.close();});
    await cleanup(async()=>{
      if(!browser?.pid)return;
      const alive=()=>{if(!grouped)return !browserClosed;try{process.kill(-browser.pid,0);return true;}catch(error){if(error.code==='ESRCH')return false;throw error;}};
      // The detached process group belongs only to this authored browser run.
      // Stop launcher helpers too, then await close before removing their profile.
      for(const signal of ['SIGTERM','SIGKILL']) {
        if(!alive()&&browserClosed)break;
        try{if(grouped)process.kill(-browser.pid,signal);else browser.kill(signal);}catch(error){if(error.code!=='ESRCH')throw error;}
        const deadline=Date.now()+2000;
        while((alive()||!browserClosed)&&Date.now()<deadline)await delay(25);
      }
      if(alive()||!browserClosed)throw new Error('Owned catalog browser did not close after bounded cleanup');
      profileReleased=true;
    });
    await cleanup(async()=>{server.closeAllConnections();await new Promise(done=>server.close(done));});
    if(profileReleased)await cleanup(()=>rm(directory,{recursive:true,force:true,maxRetries:8,retryDelay:100}));
    else cleanupErrors.push(`Retained owned profile ${directory}: browser termination was not verified.`);
    if(cleanupErrors.length) {
      console.error('Catalog browser cleanup:',cleanupErrors.join('; '));
      await cleanup(async()=>{let receipt={};try{receipt=JSON.parse(await readFile(join(output,'validation.json'),'utf8'));}catch{}
        await writeFile(join(output,'validation.json'),JSON.stringify({...receipt,status:'failed',cleanup_errors:cleanupErrors},null,2)+'\n');});
      // A cleanup failure must never hide the original assertion or timeout.
      if(!firstFailure)throw new Error(`Catalog browser cleanup failed: ${cleanupErrors.join('; ')}`);
    }
  }
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
