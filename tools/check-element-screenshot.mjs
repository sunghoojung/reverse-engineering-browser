#!/usr/bin/env node
// Synthetic protocol/controller checks, not browser/native capture acceptance.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import {createHash} from 'node:crypto';
import {elementCaptureResponseMatches,enterElementExperiments,assertElementModeTabGeometry} from './check-element-screenshot-ui.mjs';
const source = await readFile(new URL('../apps/research-ui/element_screenshot.js',import.meta.url),'utf8');
const sandbox = {TextEncoder,AbortController,setTimeout,clearTimeout};
runInNewContext(source,sandbox);
const api = sandbox.RebElementScreenshot;
const copy = value => JSON.parse(JSON.stringify(value));
export const documentFixture = () => ({selection:{instance_id:'synthetic-instance',connection_epoch:1,session_id:1,target_id:'owned',document_epoch:1,frame_id:'frame',loader_id:'loader',document_node_id:'1',revision:'a'.repeat(64)},
  viewport:{x:10,y:20,width:100,height:80},elements:[{number:1,node_id:'2',x:0,y:0,width:35,height:30,viewport_clipped:true},{number:2,node_id:'3',x:50,y:40,width:25,height:20,viewport_clipped:false}],outside_viewport:3,
  limitations:['Observed drift only, not atomic.','Bounds only; occlusion unknown.','Private/editable/frames refused.','Raw local pixels may be sensitive.']});
const stateFixture = () => ({state:'running',network:{instance_id:'synthetic-instance',capture_epoch:1},element_document_epoch:1,target:{id:'owned'},request_interception:{isolated:true,target_id:'owned'},object_experiment:{session_id:1,isolated:true,target_id:'owned'}});
const fakePng = Buffer.alloc(33); Buffer.from([137,80,78,71,13,10,26,10]).copy(fakePng); fakePng.writeUInt32BE(13,8);fakePng.write('IHDR',12);fakePng.writeUInt32BE(200,16);fakePng.writeUInt32BE(160,20);
export const captureFixture = () => ({format:'reb-element-screenshot-v1',document:documentFixture(),image:{mime:'image/png',base64:fakePng.toString('base64'),width:200,height:160,sha256:createHash('sha256').update(fakePng).digest('hex')},consistency:'before-after-observed-stable',occlusion:'unknown'});
function fixture() {
  let state = stateFixture(), resolve, reject, timer;
  const calls = [], changes = [];
  const controller = api.createController({getState:() => state,request:(body,signal) => { calls.push({body,signal});return new Promise((yes,no) => { resolve=yes;reject=no; }); },onChange:(snapshot,message) => changes.push({snapshot,message}),setTimer:fn => {timer=fn;return 1;},clearTimer:() => {timer=null;}});
  return {controller,calls,changes,get state(){return state;},set state(value){state=value;},resolve:value=>resolve(copy(value)),reject:error=>reject(error),timeout:() => timer()};
}
assert(api.documentValid(documentFixture()));assert(api.captureValid(captureFixture()));
for (const mutate of [d=>d.selection.revision='bad',d=>d.selection.connection_epoch=0,d=>d.elements.push(copy(d.elements[0])),d=>d.elements[0].x=-1,d=>d.elements[0].width=101,d=>d.elements[0].height=NaN,d=>d.selection.document_epoch=1.5,d=>d.viewport.width=5000,d=>d.elements[0].html='<script>',d=>d.elements=Array.from({length:129},()=>d.elements[0])]) {
  const value=documentFixture();mutate(value);assert(!api.documentValid(value));
}
for (const mutate of [c=>c.image.mime='image/svg+xml',c=>c.image.width=5000,c=>c.image.base64='data:image/png;base64,x',c=>c.image.sha256='bad',c=>c.occlusion='visible',c=>c.consistency='atomic',c=>c.image.base64='A'.repeat(5592408)]) {
  const value=captureFixture();mutate(value);assert(!api.captureValid(value));
}
{
  const f=fixture();const pending=f.controller.inspect();assert.equal(f.calls.length,1);assert.equal(await f.controller.inspect(),false);
  f.resolve({ok:true,document:documentFixture()});assert.equal(await pending,true);assert(f.controller.snapshot().document);
  assert.equal(await f.controller.capture(false),false);assert.equal(f.calls.length,1);
  const capture=f.controller.capture(true);assert.equal(f.calls[1].body.confirm_sensitive,true);assert.deepEqual(copy(f.calls[1].body.selection),documentFixture().selection);
  f.resolve({ok:true,capture:captureFixture()});assert.equal(await capture,true);assert(f.controller.snapshot().capture);
  f.controller.clear();assert.equal(f.controller.snapshot().capture,null);assert.equal(f.controller.snapshot().document,null);
}
for (const change of ['cancel','navigation','target','disposed','object-disposed','object-target','session','reconnect','disconnected','instance']) {
  const f=fixture();const inspected=f.controller.inspect();f.resolve({ok:true,document:documentFixture()});await inspected;
  const pending=f.controller.capture(true);
  if(change==='cancel') f.controller.clear();
  else { if(change==='navigation') f.state.element_document_epoch++;
    if(change==='target') f.state.target.id='different';
    if(change==='disposed') f.state.request_interception.isolated=false;
    if(change==='object-disposed') f.state.object_experiment.isolated=false;
    if(change==='object-target') f.state.object_experiment.target_id='different';
    if(change==='session') f.state.object_experiment.session_id++;
    if(change==='reconnect') f.state.network.capture_epoch++;
    if(change==='disconnected') f.state.state='waiting';
    if(change==='instance') f.state.network.instance_id='different';
    f.controller.refresh(); }
  assert(f.calls.at(-1).signal.aborted,change);f.resolve({ok:true,capture:captureFixture()});assert.equal(await pending,false);
  assert.equal(f.controller.snapshot().capture,null,change);assert.equal(f.controller.snapshot().document,null,change);
}
{
  const f=fixture();const inspected=f.controller.inspect();f.resolve({ok:true,document:documentFixture()});await inspected;
  const captured=f.controller.capture(true);f.resolve({ok:true,capture:captureFixture()});await captured;
  // Every other owner/document field and running state remains identical; the
  // UI never observes the intervening connecting/waiting snapshot.
  f.state.network.capture_epoch++;f.controller.refresh();
  assert.equal(f.controller.snapshot().capture,null);assert.equal(f.controller.snapshot().document,null);
  assert.equal(await f.controller.capture(true),false);assert.equal(f.calls.length,2);
}
{
  const f=fixture();const pending=f.controller.inspect();f.state.element_document_epoch++;f.resolve({ok:true,document:documentFixture()});assert.equal(await pending,false);
  assert.equal(f.controller.snapshot().document,null,'Unpolled context drift still refuses the reply');
}
{
  const f=fixture();const first=f.controller.inspect();f.resolve({ok:true,document:documentFixture()});await first;
  const pending=f.controller.capture(true);f.state.element_document_epoch++;f.resolve({ok:true,capture:captureFixture()});assert.equal(await pending,false);
  assert.equal(f.controller.snapshot().document,null);assert.equal(f.controller.snapshot().capture,null);
}
{
  const f=fixture();const first=f.controller.inspect();f.resolve({ok:true,document:documentFixture()});await first;
  const pending=f.controller.capture(true);const wrong=captureFixture();wrong.document.elements[0].width=34;f.resolve({ok:true,capture:wrong});assert.equal(await pending,false);assert.equal(f.controller.snapshot().capture,null);
}
{
  const f=fixture();const pending=f.controller.inspect();f.timeout();assert.equal(await pending,false);assert(f.calls[0].signal.aborted);assert(f.changes.some(c=>c.message?.includes('deadline')));
}
{
  const f=fixture();f.state.target.id='baseline';assert.equal(await f.controller.inspect(),false);assert.equal(f.calls.length,0);
}
const spec=JSON.parse(await readFile(new URL('../protocol/openapi.json',import.meta.url),'utf8'));
const elementSchemaNames=['ElementDocumentSelection','ElementViewport','ElementCaptureBox','ElementDocument','ElementScreenshot','DebuggerElementDocumentResult','DebuggerElementScreenshotResult'];
const elementActionResults={inspect_element_document:'DebuggerElementDocumentResult',capture_element_screenshot:'DebuggerElementScreenshotResult'};
function checkOpenAPI(document) {
  const schemas=document.components?.schemas;assert(schemas && typeof schemas==='object' && !Array.isArray(schemas),'components.schemas must own the schemas');
  for(const name of elementSchemaNames) {
    assert(Object.hasOwn(schemas,name),`${name} belongs in components.schemas`);
    assert.equal(schemas[name].type,'object');assert.equal(schemas[name].additionalProperties,false,`${name} is closed`);
  }
  let references=0;
  const resolve=ref=>{
    assert.equal(typeof ref,'string');assert(ref.startsWith('#/'),`Only local refs are supported: ${ref}`);
    let target=document;
    for(const part of ref.slice(2).split('/')) {
      assert(!/~(?![01])/u.test(part),`Invalid JSON pointer escape: ${ref}`);
      const key=part.replace(/~1/g,'/').replace(/~0/g,'~');
      assert(target && typeof target==='object' && Object.hasOwn(target,key),`Unresolved local ref: ${ref}`);target=target[key];
    }
    assert(target && typeof target==='object' && !Array.isArray(target),`Ref must target an object: ${ref}`);references++;return target;
  };
  const walk=(value,path=[])=>{
    if(!value || typeof value!=='object') return;
    for(const [key,child] of Object.entries(value)) {
      if(elementSchemaNames.includes(key)) assert.deepEqual(path,['components','schemas'],`${key} has the wrong schema owner`);
      if(key==='$ref' || key==='x-result-schema') resolve(child);
      else walk(child,[...path,key]);
    }
  };
  walk(document);
  const actions=schemas.DebuggerAction.oneOf;
  const result=schemas.DebuggerResult;
  const names=actions.map(action=>action.properties.action.const);
  assert.equal(new Set(names).size,names.length,'Debugger action names must be unique');
  assert.deepEqual([...names].sort(),Object.keys(result['x-action-results']).sort(),'Every action has exactly one result mapping');
  for(const action of actions) {
    const name=action.properties.action.const;
    const ref=result['x-action-results'][name].$ref;
    assert.equal(ref,action['x-result-schema'],`${name} result annotation agrees with map`);
    assert(result.oneOf.some(schema=>schema.$ref===ref),`${name} result appears in DebuggerResult.oneOf`);
  }
  for(const [name,resultName] of Object.entries(elementActionResults)) {
    const action=actions.find(action=>action.properties.action.const===name);assert(action,`Missing ${name}`);
    assert.equal(action.additionalProperties,false);assert(action['x-reb-execution'].effects.includes('sensitive-capture'));
    assert.equal(action['x-result-schema'],`#/components/schemas/${resultName}`);
  }
  const capture=actions.find(action=>action.properties.action.const==='capture_element_screenshot');
  assert.equal(capture.properties.selection.$ref,'#/components/schemas/ElementDocumentSelection');
  assert(schemas.ElementDocumentSelection.required.includes('connection_epoch'));
  assert.equal(schemas.ElementDocumentSelection.properties.connection_epoch.minimum,1);
  assert.equal(capture.properties.confirm_sensitive.const,true);
  assert.deepEqual([...capture.required].sort(),['action','confirm_sensitive','selection']);
  assert.equal(schemas.DebuggerElementDocumentResult.properties.document.$ref,'#/components/schemas/ElementDocument');
  assert.equal(schemas.DebuggerElementScreenshotResult.properties.capture.$ref,'#/components/schemas/ElementScreenshot');
  assert.equal(schemas.ElementScreenshot.properties.document.$ref,'#/components/schemas/ElementDocument');
  assert.equal(schemas.ElementDocument.properties.selection.$ref,'#/components/schemas/ElementDocumentSelection');
  assert.equal(schemas.ElementDocument.properties.viewport.$ref,'#/components/schemas/ElementViewport');
  assert.equal(schemas.ElementDocument.properties.elements.items.$ref,'#/components/schemas/ElementCaptureBox');
  return references;
}
const referenceCount=checkOpenAPI(spec);
for(const mutate of [
  s=>{s.components.ElementDocument=s.components.schemas.ElementDocument;delete s.components.schemas.ElementDocument;},
  s=>{s.ElementDocument=s.components.schemas.ElementDocument;},
  s=>{s.components.schemas.DebuggerResult['x-action-results'].capture_element_screenshot.$ref='#/components/schemas/DebuggerElementDocumentResult';},
  s=>{s.components.schemas.ElementDocument.properties.viewport.$ref='#/components/schemas/MissingViewport';},
  s=>{s.components.schemas.ElementDocument.properties.viewport.$ref='#/components/schemas/ElementCaptureBox';},
  s=>{s.components.schemas.ElementDocument.properties.viewport.$ref='https://example.invalid/schema';},
]) {const invalid=copy(spec);mutate(invalid);assert.throws(()=>checkOpenAPI(invalid),'Malformed schema placement/reference must be rejected');}
console.log(`PASS OpenAPI components.schemas ownership, exact element action/result bindings, all ${referenceCount} local reference/annotation resolutions and negative misplaced/broken schema cases`);
const actionURL='http://127.0.0.1:1234/api/debugger/actions';
const held={request:{url:actionURL,method:'POST',postData:JSON.stringify({action:'capture_element_screenshot'})},responseStatusCode:200};
assert(elementCaptureResponseMatches(held,actionURL));
for(const wrong of [{...held,responseStatusCode:undefined},{...held,request:{...held.request,url:actionURL+'?wrong=1'}},{...held,request:{...held.request,method:'GET'}},{...held,request:{...held.request,postData:'{'}},{...held,request:{...held.request,postData:JSON.stringify({action:'inspect_element_document'})}}])assert(!elementCaptureResponseMatches(wrong,actionURL));
const mainSource=await readFile(new URL('../apps/research-ui/app.js',import.meta.url),'utf8');
assert.match(mainSource,/elementScreenshotPanel\.setVisible\(state\.experimentMode === 'screenshot' && document\.querySelector\('#screen-experiments'\)\?\.hidden === false\)/,'Off-screen polling cannot reopen the screenshot workspace');
const visibilityStatement=mainSource.split('\n').find(line=>line.includes("elementScreenshotPanel.setVisible(state.experimentMode"));
for(const hidden of [true,false]) for(const mode of ['screenshot','object']) {
  let visible=null;runInNewContext(visibilityStatement,{elementScreenshotPanel:{setVisible:value=>{visible=value;}},state:{experimentMode:mode},document:{querySelector:()=>({hidden})}});
  assert.equal(visible,!hidden&&mode==='screenshot','Real renderExperiment admission requires both screen and mode ownership');
}
const css=await readFile(new URL('../apps/research-ui/app.css',import.meta.url),'utf8');
assert.doesNotMatch(css.match(/\.element-screenshot-box\[aria-pressed="true"\] \{([^}]+)\}/)[1],/z-index/,'Selected full-page bounds cannot cover smaller pointer targets');
assert.match(css,/#screen-experiments \.element-screenshot-workspace \{ grid-column: 1 \/ -1; grid-row: 3;/,'Wide workspace must own the full content row');
assert.match(css,/@media \(max-width: 1000px\) \{ #screen-experiments \.element-screenshot-workspace \{ grid-row: 4;/,'Narrow workspace must follow the extra chrome row');
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|Runtime\.evaluate|sendBeacon/);
console.log('PASS element screenshot strict geometry/image contracts, ownership, double clicks, confirmation, exact binding, cancel/navigation/disposal/disconnect, stale replies and deadline (synthetic; no real capture claim)');

// Exercise production DOM rendering and selection with inert authored responses.
// This is a DOM fixture, not browser layout, image-decoder, or pixel evidence.
{
  const {webcrypto}=await import('node:crypto');
  const doc={activeElement:null}; let failDecode=false;
  class Node {
    constructor(tag='div') {this.tagName=tag;this.children=[];this.dataset={};this.style={};this.attributes={};this.handlers={};this.className='';this.checked=false;this.disabled=false;this.textContent='';this.classList={contains:name=>this.className.split(' ').includes(name)};}
    set src(value){this._src=value;if(this.tagName==='img'){this.naturalWidth=this.width;this.naturalHeight=this.height;queueMicrotask(()=>failDecode ? this.onerror?.() : this.onload?.());}}
    append(...nodes){this.children.push(...nodes);}
    replaceChildren(...nodes){this.children=[...nodes];}
    setAttribute(key,value){this.attributes[key]=String(value);}
    addEventListener(event,handler){(this.handlers[event]??=[]).push(handler);}
    focus(){doc.activeElement=this;}
    async emit(event,details={}){for(const handler of this.handlers[event]??[]) await handler({preventDefault(){},...details});}
  }
  doc.createElement=tag=>new Node(tag);
  const names=['inspect','capture','clear','confirm','notice','stage','list','metadata','limits'];
  const nodes=Object.fromEntries(names.map(name=>[name,new Node()]));
  const root=new Node();root.querySelector=selector=>nodes[selector.match(/data-element-([^\]]+)/)[1]];
  root.querySelectorAll=()=>[...nodes.stage.children,...nodes.list.children].filter(n=>n.dataset.elementNumber);
  let state=stateFixture(), requests=[], resolver, urlCreated=0,urlRevoked=0;const events={};
  const ownedDocument=()=>{const value=documentFixture();value.selection.connection_epoch=state.network.capture_epoch;return value;};
  const ownedCapture=()=>{const value=captureFixture();value.document=ownedDocument();return value;};
  const context={TextEncoder,AbortController,setTimeout,clearTimeout,Uint8Array,DataView,Blob,crypto:webcrypto,atob:value=>Buffer.from(value,'base64').toString('binary'),
    URL:{createObjectURL(){urlCreated++;return 'blob:synthetic-local';},revokeObjectURL(){urlRevoked++;}},document:doc,
    addEventListener:(name,handler)=>{events[name]=handler;},fetch:async()=>{throw Error('Unexpected default fetch');}};
  runInNewContext(source,context);
  const panel=context.RebElementScreenshot.install({root,getState:()=>state,fetcher:async(url,options)=>{requests.push({url,options});return new Promise(resolve=>{resolver=resolve;});}});
  panel.setVisible(true);assert.equal(nodes.capture.disabled,true);
  await nodes.inspect.emit('click');assert.equal(requests.length,1);assert.equal(nodes.inspect.disabled,true);
  resolver({ok:true,json:async()=>({ok:true,document:ownedDocument()})});
  const flush=async()=>{for(let i=0;i<20;i++)await Promise.resolve();};await flush();assert.equal(nodes.confirm.disabled,false);
  nodes.confirm.checked=true;await nodes.confirm.emit('change');assert.equal(nodes.capture.disabled,false);
  const captureClick=nodes.capture.emit('click');resolver({ok:true,json:async()=>({ok:true,capture:ownedCapture()})});await captureClick;await flush();
  for(let i=0;i<50 && nodes.list.children.length!==2;i++)await new Promise(resolve=>setTimeout(resolve,2));
  assert.equal(nodes.list.children.length,2);assert.equal(urlCreated,1);assert.equal(nodes.stage.children.filter(n=>n.tagName==='img').length,1);
  await nodes.list.children[1].emit('click');assert.equal(nodes.list.children[1].attributes['aria-pressed'],'true');
  const matching=nodes.stage.children.find(n=>n.dataset.elementNumber==='2');assert.equal(matching.attributes['aria-pressed'],'true');
  await nodes.list.children[1].emit('keydown',{key:'Home'});assert.equal(doc.activeElement,nodes.list.children[0]);
  await nodes.list.children[0].emit('keydown',{key:'End'});assert.equal(doc.activeElement,nodes.list.children[1]);
  await matching.emit('click');assert.equal(nodes.list.children[1].attributes['aria-pressed'],'true');
  assert.equal(matching.style.left,'50%');assert.equal(matching.style.top,'50%');assert.equal(matching.style.width,'25%');
  state.network.capture_epoch++;panel.refresh();assert.equal(nodes.stage.children.length,0);assert.equal(nodes.list.children.length,0);assert.equal(nodes.confirm.checked,false);assert.equal(urlRevoked,1,'Same-page reconnect revokes the displayed PNG and consent without observing a disconnected state');
  panel.setVisible(false);assert.equal(nodes.stage.children.length,0);assert.equal(nodes.list.children.length,0);assert.equal(urlRevoked,1);assert.equal(nodes.confirm.checked,false);
  panel.setVisible(true);await nodes.inspect.emit('click');resolver({ok:true,json:async()=>({ok:true,document:ownedDocument()})});await flush();
  failDecode=true;nodes.confirm.checked=true;await nodes.confirm.emit('change');const failedClick=nodes.capture.emit('click');resolver({ok:true,json:async()=>({ok:true,capture:ownedCapture()})});await failedClick;
  for(let i=0;i<50 && urlRevoked!==2;i++)await new Promise(resolve=>setTimeout(resolve,2));
  assert.equal(urlRevoked,2);assert.equal(nodes.stage.children.length,0);assert.equal(nodes.list.children.length,0);assert.match(nodes.notice.textContent,/could not be decoded/);assert.equal(nodes.confirm.checked,false);
  panel.setVisible(true);await nodes.inspect.emit('click');panel.setVisible(false);resolver({ok:true,json:async()=>({ok:true,document:ownedDocument()})});await flush();assert.equal(nodes.confirm.disabled,true);
  assert(requests.at(-1).options.signal.aborted);assert(requests.every(r=>r.url==='/api/debugger/actions'));
  console.log('PASS production screenshot DOM fixture: numbered pointer/list selection, Home/End focus, CSS scaling, local blob revocation, decode failure refusal, close and late reply retirement (not rendered/native QA)');
}

// Navigation must open the real chooser on entry and after returning from
// Traffic. A strict mock refuses the original hidden Experiments click.
for(const initiallyOpen of [false,true]) {
  let open=initiallyOpen,visible=false;const clicks=[];
  const evaluate=async()=>open;
  const click=async selector=>{
    clicks.push(selector);
    if(selector==='#advanced-navigation > summary') {assert(!open);open=true;}
    else {assert.equal(selector,'[data-screen="experiments"]');assert(open,'Experiments is hidden until Advanced opens');open=false;visible=true;}
  };
  const until=async expression=>{assert(expression.includes("#advanced-navigation"));assert(expression.includes('#screen-experiments') ? visible&&!open : open);};
  await enterElementExperiments({evaluate,click,until});
  assert.deepEqual(clicks,initiallyOpen?['[data-screen="experiments"]']:['#advanced-navigation > summary','[data-screen="experiments"]']);
  visible=false;clicks.length=0;
  await enterElementExperiments({evaluate,click,until});
  assert.deepEqual(clicks,['#advanced-navigation > summary','[data-screen="experiments"]']);
}
console.log('PASS element screenshot chooser entry and return use visible pointer navigation');

// The strip's border consumes one pixel of its fixed 40px grid row. The old
// child min-height:40px cannot fit a 39px client box, even at a valid center hit.
assert.throws(()=>assertElementModeTabGeometry({clip:{top:99,bottom:138},tabs:[{top:99,bottom:139}]}),/entirely/);
for(const bottom of [138,123]) assert.doesNotThrow(()=>assertElementModeTabGeometry({clip:{top:99,bottom},tabs:[{top:99,bottom},{top:99,bottom}]}));
assert.throws(()=>assertElementModeTabGeometry({clip:{top:99,bottom:138},tabs:[{top:98,bottom:137}]}),/entirely/);
assert.match(css,/#screen-experiments \.experiment-mode-tab \{[^}]*min-height: 0;/,'Tabs must stretch within the bordered strip rather than force its outer height');
console.log('PASS mode tabs preserve strict full-height clipping checks and fit the bordered scrollport');
