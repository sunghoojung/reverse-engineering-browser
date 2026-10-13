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
const navigation = await readFile(join(root, 'apps/research-ui/investigation_navigation.js'), 'utf8');
const models = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const api = runInNewContext(`${models}\n${traffic}\n${navigation}\n;({isApiObservationCatalog,apiCatalogIdentity,apiCatalogRequestIdentity,apiCatalogResolveSource,apiCatalogShapePath,requestsFromDebuggerNetwork,investigationRequestIdentity,investigationSame,isDebuggerResponse})`,
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
  value=>value.endpoints[0].observations[0].response.body.raw='must not be accepted']) {
  const malformed = copy(fixture.catalog); mutate(malformed); assert.equal(api.isApiObservationCatalog(malformed),false);
}
assert.equal(JSON.stringify(fixture.debuggerState.network),original,'Catalog consumption must not alter retained raw fields');
console.log('PASS catalog validator, independent coverage, five-value identity, rounded timestamp collision, ambiguity, typed paths, owner-safe navigation and immutable raw values');

await checkController();
await checkHistory();

if (process.argv.includes('--browser') || process.argv.includes('--serve')) await checkBrowser();
async function checkBrowser() {
  const html = await readFile(join(root,'apps/research-ui/index.html'),'utf8');
  const assets = new Set(['index.html', ...[...html.matchAll(/(?:src|href)="([^"/]+\.(?:js|css))"/g)].map(match=>match[1])]);
  const logs = [], mutations = [], errors = []; let mode = 'ready', catalogReads = 0, held = [];
  const server = createServer(async (request,response) => {
    if(request.headers.host !== `127.0.0.1:${server.address().port}`) {response.writeHead(400);response.end();return;}
    const reply = (status,value,type='application/json') => {response.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store'});response.end(type==='application/json'?JSON.stringify(value):value);};
    if(request.method !== 'GET') {mutations.push(request.url);reply(405,{});return;}
    const path = request.url.split('?')[0]; logs.push(path);
    if(path === '/api/network/catalog') {
      catalogReads++;
      if(mode==='pending') {held.push(()=>reply(200,fixture.catalog));return;}
      if(mode==='failure') {reply(503,{});return;}
      if(mode==='malformed') {reply(200,{format:'wrong'});return;}
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
  let browser, socket, sequence=0; const commands=new Map();
  const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
  async function until(check,description) {for(let i=0;i<200;i++){const value=await check();if(value)return value;await delay(50);}throw new Error(`Timed out: ${description}`);}
  const send=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence,timer=setTimeout(()=>{commands.delete(id);reject(new Error(`CDP timeout: ${method}`));},10000);commands.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params}));});
  const evaluate=async expression=>{const result=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw new Error(result.exceptionDetails.text+' '+JSON.stringify(result.exceptionDetails.exception));return result.result.value;};
  const key=async (key,code)=>{await send('Input.dispatchKeyEvent',{type:'keyDown',key,code,windowsVirtualKeyCode:{Tab:9,Enter:13,Escape:27}[key]});await send('Input.dispatchKeyEvent',{type:'keyUp',key,code});};
  const click=async selector=>{const point=await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});n.scrollIntoView({block:'nearest'});const r=n.getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2};})()`);await send('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});await send('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});};
  const shot=async name=>{const result=await send('Page.captureScreenshot',{format:'png'});await writeFile(join(output,`${name}.png`),Buffer.from(result.data,'base64'));};
  try {
    await new Promise(ready=>server.listen(0,'127.0.0.1',ready));
    if (process.argv.includes('--serve')) {
      console.log(`Synthetic catalog UI: http://127.0.0.1:${server.address().port}/`);
      await new Promise(done => {process.once('SIGINT',done);process.once('SIGTERM',done);});
      return;
    }
    const executable=process.env.REB_UI_CHROMIUM || '/usr/bin/chromium';
    browser=spawn(executable,['--headless=new','--remote-debugging-port=0',`--user-data-dir=${directory}`,'--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','about:blank'],{stdio:['ignore','ignore','pipe']});
    let diagnostics=''; browser.stderr.on('data',chunk=>{diagnostics=(diagnostics+chunk).slice(-8192);}); browser.on('error',error=>{diagnostics+=error.message;});
    const port=await until(async()=>{if(browser.exitCode!==null||browser.signalCode!==null)throw new Error(`Browser startup failed (${browser.exitCode ?? browser.signalCode}): ${diagnostics}`);try{return (await readFile(join(directory,'DevToolsActivePort'),'utf8')).split('\n')[0];}catch{return null;}},'sandboxed Chromium startup');
    const pages=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    socket=new WebSocket(pages.find(page=>page.type==='page').webSocketDebuggerUrl);
    await new Promise((ready,reject)=>{socket.addEventListener('open',ready,{once:true});socket.addEventListener('error',reject,{once:true});});
    socket.addEventListener('message',event=>{const message=JSON.parse(event.data);if(message.method==='Runtime.exceptionThrown')errors.push(message.params.exceptionDetails);const command=commands.get(message.id);if(command){clearTimeout(command.timer);commands.delete(message.id);if(message.error)command.reject(new Error(message.error.message));else command.resolve(message.result);}});
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
    await key('Tab','Tab');assert.equal(await evaluate('document.activeElement.id'),'api-catalog-content');
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
    await key('Escape','Escape');assert.equal(await evaluate('document.activeElement.id'),'open-api-catalog');
    assert.equal(await evaluate('JSON.stringify(state.requests[0].captureRecord)'),raw,'Raw record unchanged after catalog lifecycle');
    assert.deepEqual(mutations,[]);assert.deepEqual(errors,[]);
    await writeFile(join(output,'validation.json'),JSON.stringify({status:'passed',product_path:'browser development UI with authored loopback fixtures',viewports:[[1440,900],[760,560],[360,740]],catalog_reads:catalogReads,mutations,errors,screenshots:output,states:['deliberate-only','loading','ready','exact Traffic handoff','refresh failure','malformed','epoch replacement','cancel late reply','capture off','empty'],keyboard:['Tab focus','Enter endpoint expansion','Enter source handoff','Escape close'],native_macos:'not run; cloud-only scope'},null,2)+'\n');
    console.log(`PASS rendered catalog: keyboard and pointer, three viewports, scrolling, inert markup, raw header preservation, explicit read-only lifecycle, source invalidation. Evidence: ${output}`);
  } finally {
    held.splice(0).forEach(release=>release());for(const command of commands.values())clearTimeout(command.timer);socket?.close();
    if(browser && browser.exitCode===null){browser.kill('SIGTERM');await Promise.race([new Promise(done=>browser.once('exit',done)),delay(3000)]);if(browser.exitCode===null)browser.kill('SIGKILL');}
    server.closeAllConnections();await new Promise(done=>server.close(done));await rm(directory,{recursive:true,force:true});
  }
}

async function checkController() {
  class Node {
    constructor(tag='div') {this.tagName=tag;this.children=[];this.events={};this.attributes={};this.dataset={};this.text='';this.open=false;}
    set textContent(value) {this.text=String(value);this.children=[];}
    get textContent() {return this.text+this.children.map(child=>child.textContent).join('');}
    append(...children) {this.children.push(...children);}
    replaceChildren(...children) {this.children=children;this.text='';}
    setAttribute(key,value) {this.attributes[key]=String(value);}
    addEventListener(type,handler) {this.events[type]=handler;}
    click() {if(!this.disabled)this.events.click?.();}
    showModal() {this.open=true;}
    close() {this.open=false;this.events.close?.();}
  }
  const ids=new Map(['api-catalog','open-api-catalog','api-catalog-refresh','api-catalog-status','api-catalog-content','api-catalog-close'].map(id=>[id,new Node()]));
  const document={getElementById:id=>ids.get(id),createElement:tag=>new Node(tag)};
  const install=runInNewContext(`${traffic}\ninstallApiObservationCatalog`,{document,TextEncoder,AbortController,setTimeout,clearTimeout});
  let current=requests, opens=0, reads=0, mode='ready', release;
  const panel=install({getRequests:()=>current,openRequest:()=>{opens++;return true;},fetchCatalog:async (path,options)=>{
    reads++;assert.equal(path,'/api/network/catalog');assert.equal(options.cache,'no-store');assert.equal(options.method,undefined);
    if(mode==='pending')await new Promise(done=>{release=done;});
    return {ok:mode!=='failure',status:mode==='failure'?503:200,text:async()=>JSON.stringify(mode==='malformed'?{bad:true}:fixture.catalog)};
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
  get('api-catalog').close();
  console.log('PASS catalog DOM/controller: explicit-only reads, lazy disclosure, inert names, click-time expiry, raw handoff, preserved failed/malformed snapshots, canceled late responses and modal shortcut isolation (not rendered QA)');
}

async function checkHistory() {
  const state={requests,selectedRequestId:null,trafficDetailOpen:false,selectedCaptureIdentity:null,inspectorTab:'headers',fieldTab:'body',selectedField:null};
  const node={id:'screen-traffic',dataset:{},textContent:'',querySelectorAll:()=>[],hidden:false};
  const document={querySelector:()=>node,activeElement:null};
  let renderedSelection='not rendered';
  const model=runInNewContext(`${traffic}\n${navigation}\n
    investigationSelector=()=>null; investigationNotice=()=>{}; retireInvestigationReturn=()=>{}; resumeInvestigationReturn=()=>{};
    ({investigationSnapshot,restoreInvestigation})`,{state,document,TextEncoder,selectedSource:()=>null,fieldSets:{body:[]},
      selectRequest:id=>{state.selectedRequestId=id;state.trafficDetailOpen=true;},
      resetRequestSelection:()=>{state.selectedRequestId=null;state.selectedCaptureIdentity=null;},renderRequests:()=>{renderedSelection=state.selectedRequestId;},renderInspector:()=>{},showScreen:()=>{}});
  const empty=model.investigationSnapshot();assert.equal(empty.request,null);assert.equal(empty.trafficDetailOpen,false);
  state.selectedRequestId=requests[0].id;state.selectedCaptureIdentity=identity;state.trafficDetailOpen=true;
  const opened=model.investigationSnapshot();
  assert.equal(model.restoreInvestigation(empty),true);assert.equal(state.selectedRequestId,null);assert.equal(state.trafficDetailOpen,false);assert.equal(state.selectedCaptureIdentity,null);assert.equal(renderedSelection,null,'Null selection immediately repaints Traffic rows');
  assert.equal(model.restoreInvestigation(opened),true);assert.equal(state.selectedRequestId,requests[0].id);assert.equal(state.trafficDetailOpen,true);
  state.trafficDetailOpen=false;const closed=model.investigationSnapshot();state.trafficDetailOpen=true;
  assert.equal(model.restoreInvestigation(closed),true);assert.equal(state.selectedRequestId,requests[0].id);assert.equal(state.trafficDetailOpen,false,'Previously selected but closed inspector stays closed on Back');
  await new Promise(done=>setImmediate(done));
  console.log('PASS catalog Traffic history: Back restores unselected/closed state; Forward restores exact capture; selected but closed inspector round-trips');
}
