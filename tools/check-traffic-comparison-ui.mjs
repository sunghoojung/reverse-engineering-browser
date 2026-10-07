import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

export async function checkTrafficComparisonController(root) {
  const app = await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const source = await readFile(join(root,'apps/research-ui/traffic_view.js'),'utf8');
  const navigation = await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
  const algorithms = await readFile(join(root,'apps/research-ui/traffic_comparison.js'),'utf8');
  const requestRoot = app.slice(app.indexOf('      function requestTraceRoot('),app.indexOf('      function requestSignalProfileSelection('));
  const state = {sessionMode:'live',requests:[],selectedRequestId:null,debuggerSession:{generation:5,target:{id:'target-a'},network:{target_id:'target-a',capture_enabled:true}}};
  const document = {activeElement:null};
  class Node {
    constructor(tag) {this.tagName=tag;this.children=[];this.dataset={};this.events={};this.attributes={};this.text='';}
    set textContent(value){this.text=String(value);this.children=[];}
    get textContent(){return this.text+this.children.map(child=>child.textContent).join('');}
    append(...children){this.children.push(...children);}
    replaceChildren(...children){this.children=children;this.text='';}
    setAttribute(key,value){this.attributes[key]=String(value);}
    addEventListener(name,handler){this.events[name]=handler;}
    focus(){document.activeElement=this;}
    click(){if(!this.disabled)this.events.click?.();}
  }
  document.createElement=tag=>new Node(tag);
  const container=new Node('section'); let ui;
  const redraw=()=>ui.renderTrafficComparison(container,state.requests.find(value=>value.id===state.selectedRequestId),true);
  ui=runInNewContext(`${requestRoot}\n${navigation}\n${algorithms}\n${source}\n;({createTrafficComparisonController,investigationRequestIdentity,investigationSame,renderTrafficComparison,syncTrafficComparison,identity:()=>trafficComparisonController?.identity})`,
    {state,document,TextEncoder,TextDecoder,Uint8Array,URL,integerText:(event,key)=>String(event[key]),renderInspector:redraw});
  const owner={mode:'live',target:'target-a',capture:true,generation:5};
  const body=text=>({state:'available',mime:'application/json',text,headers:[['content-type','application/json']]});
  const request=(id,patch={})=>({id,origin:'live',operation:'cdp_completed',tabId:'target-a',protocolRequestId:id,firstTimestamp:1n,method:'POST',path:'https://fixture.invalid/test',status:200,
    exchange:{request:body('{"request":1}'),response:body('{"response":1}')},...patch});
  const a=request('a'),b=request('b');
  const controller=ui.createTrafficComparisonController(ui.investigationRequestIdentity,ui.investigationSame);
  assert(controller.pin(a,[a,b],owner));
  assert.equal(controller.sync([a,b],{...owner,generation:6}),a);
  assert.deepEqual(Object.keys(controller.identity).sort(),['id','protocol','started','target','type']);
  assert.equal(controller.sync([b],owner),null);assert.match(controller.notice,/expired/);
  assert.equal(controller.sync([a,b],owner),null,'An expired baseline must never silently rebind');
  for(const change of [{target:'target-b'},{generation:1},{capture:false},{mode:'demo'}]){
    assert(controller.pin(a,[a,b],owner));assert.equal(controller.sync([a,b],{...owner,...change}),null);assert.equal(controller.sync([a,b],owner),null);
  }
  assert.equal(controller.pin(a,[a,{...a}],owner),false);
  assert.equal(controller.pin({...a,origin:'sample'},[{...a,origin:'sample'}],owner),false);
  const event={session_id:'9007199254740993',process_id:17,sequence_number:'18446744073709551615',request_id:'91',type:'request_started'};
  const native={id:'native',origin:'live',operation:'request_started',events:[event]};
  assert(controller.pin(native,[native],owner));assert.equal(controller.identity.session,event.session_id);
  assert.equal(controller.sync([{...native,events:[{...event,session_id:'9007199254740994'}]}],owner),null);
  assert(controller.pin(a,[a,b],owner));controller.clear();assert.equal(controller.identity,null);

  state.requests=[a,b];state.selectedRequestId='a';redraw();
  assert.equal(container.rebComparison.pin.disabled,false);container.rebComparison.pin.click();assert(ui.identity());
  const pin=container.rebComparison.pin;
  state.selectedRequestId='b';b.exchange.response=body('{"response":2,"html":"<img src=x onerror=alert(1)>"}');redraw();
  assert.match(container.textContent,/response.*changed/s);assert.match(container.textContent,/<img/);
  assert.equal(container.children.flatMap(child=>child.children).some(node=>node.tagName==='img'),false);
  const view=container.rebComparison;
  const identityDisclosure=container.children[2],identitySummary=view.identitySummary;
  identityDisclosure.open=true;identitySummary.focus();
  b.status=201;redraw();assert.equal(container.children[2],identityDisclosure);assert.equal(identityDisclosure.open,true);assert.equal(document.activeElement,identitySummary);
  b.status=200;redraw();

  const result=view.result.children;view.result.scrollTop=120;view.result.focus();redraw();
  assert.equal(container.rebComparison.pin,pin);assert.equal(view.result.children,result);assert.equal(view.result.scrollTop,120);assert.equal(document.activeElement,view.result);
  const responseSection=view.result.children.find(value=>value.dataset.label==='Response body');
  responseSection.open=false;responseSection.children[0].focus();
  b.exchange.response=body('{"response":3}');redraw();assert.match(container.textContent,/Selected: 3/);
  const changedResponseSection=view.result.children.find(value=>value.dataset.label==='Response body');
  assert.equal(changedResponseSection.open,false);assert.equal(document.activeElement,changedResponseSection.children[0]);

  for(const [field,value] of [['methodTruncated',true],['urlTruncated',true],['hostOnly',true],['targetKind','unknown']]){
    b[field]=value;redraw();assert.match(container.textContent,/General · incomplete/);delete b[field];redraw();assert.match(container.textContent,/General · equal/);
  }
  for(const field of ['headersTruncated','headers_truncated']){
    b.exchange.request[field]=true;redraw();assert.match(container.textContent,/Request headers · incomplete/);delete b.exchange.request[field];redraw();assert.match(container.textContent,/Request headers · equal/);
  }
  assert.equal(controller.pin(a,[a,{...a,tabId:'other-target'}],owner),false,'Same visible request ID with different exact identities cannot be pinned ambiguously');

  b.exchange.response={...body(''),bytes:new TextEncoder().encode('{"response":3}')};delete b.exchange.response.text;redraw();
  b.exchange.response.bytes[12]=52;redraw();assert.match(container.textContent,/Selected: 4/,'In-place byte updates invalidate comparison exactly');
  assert(view.byteSnapshots.reduce((sum,value)=>sum+(value?.bytes.length??0),0)<=4*128*1024);
  state.debuggerSession.generation=1;redraw();assert.equal(ui.identity(),null);assert.match(container.textContent,/Baseline expired/);assert.equal(view.result.children.length,0);assert.equal(document.activeElement,view.pin,'Expiry transfers focused summary to the enabled pin action');
  state.debuggerSession.generation=5;redraw();assert.equal(ui.identity(),null);
  state.selectedRequestId='a';redraw();container.rebComparison.pin.click();state.selectedRequestId='b';redraw();
  view.result.children.find(value=>value.dataset.label==='Response body').children[0].focus();
  state.requests=[a,b,{...b,tabId:'other-target'}];redraw();
  assert.equal(document.activeElement,container,'Ambiguous selection transfers focused summary to the comparison panel');
  assert.equal(view.pin.disabled,true);assert.equal(view.result.children.length,0);
  state.requests=[a,b];redraw();
  container.rebComparison.pin.click();assert(ui.identity());container.rebComparison.clear.click();assert.equal(ui.identity(),null);assert.equal(view.byteSnapshots.length,0);assert.equal(document.activeElement,container.rebComparison.pin);
  const aHead={...a,method:'HEAD',status:204},bHead={...b,method:'HEAD',status:204};delete aHead.exchange;delete bHead.exchange;
  state.requests=[aHead,bHead];state.selectedRequestId='a';redraw();view.pin.click();state.selectedRequestId='b';redraw();
  assert.match(container.textContent,/Response body · unavailable/);
  for(const value of state.requests)value.exchange={request:{state:'missing'},response:{state:'empty',reason:'This HTTP response has no body.'}};
  redraw();assert.match(container.textContent,/Response body · equal/,'Capture presence differs from an inspector-only HTTP empty fallback');
  state.requests=[{...native,method:'GET',path:'https://fixture.invalid/native',status:200}];state.selectedRequestId='native';redraw();view.pin.click();
  state.requests=[{...state.requests[0],id:'renamed-native'}];state.selectedRequestId='renamed-native';redraw();
  assert.match(view.identitySummary.textContent,/Baseline:.*renamed-native.*selected:.*renamed-native/,'Visible row IDs refresh even when exact native event identity is unchanged');
  ui.renderTrafficComparison(container,b,false);assert.equal(container.children.length,0,'Leaving comparison erases its copied result DOM');
  console.log('PASS captured comparison: production identity/session/generation expiry, ambiguity, explicit repin/clear, inert DOM and unchanged refresh ownership');
}

export async function checkCapturedComparisonInteractions({evaluate,viewport,click,key,wheel,screenshot,emptyDebugger}) {
  await viewport(1440,900);
  await evaluate(`window.comparisonOriginal={requests:state.requests,sessionMode:state.sessionMode,debuggerSession:state.debuggerSession,events:state.events,eventsLimited:state.eventsLimited,broker:state.broker,eventFailureKind:state.eventFailureKind};state.debuggerSession=${JSON.stringify(emptyDebugger)};state.debuggerSession.generation=50;state.debuggerSession.target={id:'comparison-target',title:'Synthetic capture',url:'https://fixture.invalid/'};state.debuggerSession.network.target_id='comparison-target';state.debuggerSession.network.capture_enabled=true;
    state.requests=[0,1].map(i=>({id:'comparison-'+i,origin:'live',operation:'cdp_completed',tabId:'comparison-target',protocolRequestId:'protocol-'+i,firstTimestamp:BigInt(100+i),method:'POST',path:'https://fixture.invalid/compare-'+i,status:i?201:200,time:10,type:'xhr',events:[],exchange:{request:{state:'available',mime:'application/json',text:i?'{"a/b~":{"count":2},"large":9007199254740993}':'{"a/b~":{"count":1},"large":9007199254740992}',headers:[['content-type','application/json']]},response:{state:'available',mime:'application/json',text:JSON.stringify({result:i?'<img src=x onerror=alert(1)>':'baseline',rows:Array.from({length:12},(_,n)=>n+i)}),headers:[['content-type','application/json'],['x-variant',String(i)]]}}}));
    state.sessionMode='live';state.requestTabId='all';state.requestDomain='all';state.requestType='all';elements.requestFilter.value='';state.trafficWindowStart=0;state.trafficWindowAnchor=null;state.trafficSort='capture';renderRequests();renderInspector();renderShellStatus();renderNetworkNotice();`);
  const press=value=>key(value,value,{windowsVirtualKeyCode:({ArrowRight:39,Tab:9,Enter:13,Escape:27})[value],...(value==='Enter'?{text:'\r',unmodifiedText:'\r'}:{})});
  for(const [width,height] of [[1440,900],[760,560],[360,740]]){
    await viewport(width,height);await click('[data-request-id="comparison-0"]');
    // Tabs have a native horizontal scroll strip. Start at its visible selected
    // tab using native Home, then advance with real keyboard events.
    await click('.inspector-tab[aria-selected="true"]');
    await key('Home','Home',{windowsVirtualKeyCode:36});
    for(let i=0;i<4;i++)await press('ArrowRight');
    assert.equal(await evaluate('state.inspectorTab'),'compare');
    await press('Tab');assert.equal(await evaluate('document.activeElement.id'),'traffic-comparison-pin');await press('Enter');
    assert.equal(await evaluate('trafficComparisonController.identity.id'),'comparison-0');
    await click('[data-request-id="comparison-1"]');
    assert.match(await evaluate("document.querySelector('#traffic-comparison').textContent"),/a~1b~0\/count/);
    assert.match(await evaluate("document.querySelector('#traffic-comparison').textContent"),/9007199254740993/);
    assert.equal(await evaluate("document.querySelectorAll('#traffic-comparison img').length"),0);
    const g=await evaluate("(()=>{const n=document.querySelector('#traffic-comparison'),r=n.getBoundingClientRect();return {left:r.left,right:r.right,bottom:r.bottom,height:r.height,page:document.documentElement.scrollWidth,width:innerWidth,heightWindow:innerHeight,scroll:n.scrollHeight,client:n.clientHeight};})()");
    assert(g.height>=80&&g.left>=0&&g.right<=g.width+1&&g.bottom<=g.heightWindow+1&&g.page<=g.width+1,'Comparison must fit the real narrow inspector');
    const layout=await evaluate("(()=>{const filters=document.querySelector('.request-filters').getBoundingClientRect(),tools=document.querySelector('.network-tools').getBoundingClientRect(),notice=document.querySelector('#network-notice').getBoundingClientRect();return {filtersBottom:filters.bottom,toolsBottom:tools.bottom,noticeTop:notice.top};})()");
    assert(layout.filtersBottom<=layout.toolsBottom+1&&layout.toolsBottom<=layout.noticeTop+1,'Wrapped filter controls and warnings must not overlap in short windows');
    assert.match(await evaluate("document.querySelector('.traffic-comparison-identities > summary').textContent"),/Baseline: POST \/compare-0.*selected: POST \/compare-1/);
    await screenshot(`requests-comparison-${width}`);
    await wheel('#traffic-comparison',120);
    const before=await evaluate("document.querySelector('#traffic-comparison').scrollTop");assert(before>0);
    await screenshot(`requests-comparison-${width}-changes`);
    await evaluate('renderInspector()');assert.equal(await evaluate("document.querySelector('#traffic-comparison').scrollTop"),before);
    await wheel('#traffic-comparison',-10000);
    await click('#traffic-comparison-clear');assert.equal(await evaluate('trafficComparisonController.identity'),null);
    assert.equal(await evaluate('document.activeElement.id'),'traffic-comparison-pin');
  }
  await viewport(1440,900);await click('[data-request-id="comparison-0"]');await click('#traffic-comparison-pin');
  await click('[data-request-id="comparison-1"]');
  await evaluate("state.debuggerSession.generation=1;renderInspector()");
  assert.equal(await evaluate('trafficComparisonController.identity'),null);assert.match(await evaluate("document.querySelector('#traffic-comparison').textContent"),/Baseline expired/);
  await evaluate("state.debuggerSession.generation=51;renderInspector()");assert.equal(await evaluate('trafficComparisonController.identity'),null);
  await click('#traffic-comparison-pin');
  await evaluate("state.requests=state.requests.filter(value=>value.id!=='comparison-1');renderRequests();renderInspector()");
  assert.equal(await evaluate('trafficComparisonController.identity'),null);
  await screenshot('requests-comparison-expired');
  // Healthy metadata-only capture legitimately hides the notice. Keep the
  // table in the final bounded track with either search-status visibility.
  for(const [width,height] of [[1440,900],[760,560],[360,740]])for(const search of [false,true]){
    await viewport(width,height);
    await evaluate(`state.events=[{protocol_version:1,session_id:1,sequence_number:1,monotonic_time_ns:1,navigation_id:1,frame_id:1,artifact_id:0,parent_event_id:0,process_id:1,thread_id:1,category:'network',type:'request_started',payload_size:0,payload_encoding:'hex',payload:''}];if(!isBrokerEvent(state.events[0]))throw Error('Invalid healthy event fixture');state.eventsLimited=false;state.broker='connected';state.eventFailureKind=null;state.debuggerSession.network.capture_enabled=false;
      state.requests=Array.from({length:520},(_,i)=>({id:'healthy-'+i,origin:'live',method:'GET',path:'https://fixture.invalid/healthy-'+i,status:200,time:1,type:'xhr',events:[]}));
      state.requestTabId='all';state.requestDomain='all';state.trafficWindowStart=0;state.trafficWindowAnchor=null;elements.requestSearchScope.value=${JSON.stringify(search?'content':'url')};elements.requestFilter.value=${JSON.stringify(search?'healthy':'')};renderRequests();renderInspector();renderNetworkNotice();`);
    const healthy=await evaluate("(()=>{const pane=document.querySelector('.request-pane'),table=document.querySelector('.request-table'),rows=elements.requestRows;return {hidden:elements.networkNotice.hidden,search:!elements.requestSearchStatus.hidden,row:getComputedStyle(table).gridRowStart,height:rows.clientHeight,content:rows.scrollHeight,outer:pane.scrollTop,count:rows.children.length};})()");
    assert.equal(healthy.hidden,true);assert.equal(healthy.search,search);assert.equal(healthy.row,'-2');
    assert(healthy.count===500&&healthy.height>=28&&healthy.height<height&&healthy.content>healthy.height,'Healthy retained window must stay in an independently bounded ledger');
    await screenshot(`requests-healthy-${width}-${search?'search':'plain'}`);
    await wheel('#request-rows',112);
    assert(await evaluate('elements.requestRows.scrollTop>0'),'Healthy ledger responds to native wheel input');
  }
  await evaluate("Object.assign(state,comparisonOriginal);delete window.comparisonOriginal;renderRequests();renderInspector()");
  return {viewports:[[1440,900],[760,560],[360,740]],checks:['exact baseline pin and selected request comparison','native keyboard pin/clear','JSON pointer escaping and large integers','inert text','independent narrow scrolling','unchanged refresh','generation restart and eviction expire permanently']};
}
