import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext,createContext,runInContext} from 'node:vm';

export async function checkInvestigationCore(root) {
  const app = await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const requestRoot = app.slice(app.indexOf('      function requestTraceRoot('),app.indexOf('      function requestSignalProfileSelection('));
  const source = await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
  const model = runInNewContext(`function integerText(event,field){return String(event[field]);}\n${requestRoot}\n${source}\n;({investigationId,investigationEventIdentity,investigationArtifactIdentity,investigationRequestIdentity,investigationSame,investigationResolve,createInvestigationHistory})`);
  const event={session_id:'18446744073709551615',process_id:17,sequence_number:'9007199254740993',request_id:'91',type:'request_started'};
  const request={id:'native',origin:'live',operation:'request_started',events:[event]};
  const identity=model.investigationRequestIdentity(request);
  assert.equal(identity.session,event.session_id);assert.equal(identity.sequence,event.sequence_number);
  for(const bad of ['01','-1','18446744073709551616','1e3',NaN,9007199254740992,{},null]) assert.equal(model.investigationId(bad),null);
  for(const field of ['session_id','sequence_number','process_id']) assert.equal(model.investigationEventIdentity({...event,[field]:'0'}),null);
  assert.equal(model.investigationRequestIdentity({...request,origin:'demo'}),null);
  const cdp=model.investigationRequestIdentity({...request,operation:'cdp_completed',tabId:'target-1',protocolRequestId:'cdp-7',firstTimestamp:1n});
  assert.equal(cdp.type,'debugger-request');assert.equal(model.investigationSame(cdp,identity),false,'A host/time correlation is not an exact native request');
  const artifact={session_id:'11',artifact_id:'7',sha256:'a'.repeat(64),byte_size:100};
  const artifactId=model.investigationArtifactIdentity(artifact);
  for(const altered of [{session_id:'12'},{sha256:'b'.repeat(64)},{byte_size:99},{artifact_id:'8'}]) assert.equal(model.investigationSame(artifactId,model.investigationArtifactIdentity({...artifact,...altered})),false);
  assert.equal(model.investigationResolve(artifactId,[],model.investigationArtifactIdentity).status,'stale');
  assert.equal(model.investigationResolve(artifactId,[artifact,artifact],model.investigationArtifactIdentity).status,'ambiguous');
  assert.equal(model.investigationResolve(artifactId,[{...artifact,session_id:'12'},artifact],model.investigationArtifactIdentity).record,artifact);
  let current=0, allow=true, view;
  const history=model.createInvestigationHistory({snapshot:()=>({value:current}),restore:entry=>{if(!allow)return false;current=entry.value;return true;},changed:next=>{view=next;}});
  for(let i=0;i<100;i++){history.record();current++;}
  assert.equal(view.count,24); assert.equal(view.back.value,99);
  allow=false;assert.equal(history.back(),false);assert.equal(view.count,24);assert.equal(current,100,'Unavailable destination must leave source intact');
  allow=true;assert(history.back());assert.equal(current,99);assert(history.forward());assert.equal(current,100);
  for(let i=0;i<24;i++) assert(history.back());assert.equal(current,76);assert.equal(history.back(),false);
  history.record();current=101;assert.equal(history.forward(),false,'New branch retires forward history');
  history.clear();assert.equal(view.count,0);
  assert(!/localStorage|sessionStorage|pushState|replaceState/.test(source),'Evidence navigation never persists history');
  for(const asset of ['apps/origin-trace-backend/src/app.rs','apps/research-ui/macos/OriginTraceApp.swift','scripts/build-research-app.sh','apps/research-ui/index.html']) assert((await readFile(join(root,asset),'utf8')).includes('investigation_navigation.js'),asset);
  const evidence = runInNewContext((await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8'))+';({isBrokerResponse,isOriginTraceResponse,requestsFromEvents})',{TextDecoder});
  const fixture = investigationFixture({handle:async()=>false,release(){}});
  assert(evidence.isBrokerResponse({count:1,events:[fixture.event]}),'Synthetic investigation event must pass normal broker admission');
  assert(evidence.isOriginTraceResponse(fixture.trace),'Synthetic trace must pass the production trace contract');
  const captureTrace = structuredClone(fixture.trace);
  captureTrace.gaps.push({reason:'capture_gap',after_step:0,detail:'The retained stream contains native queue-drop markers; this does not identify a missing predecessor.'});
  captureTrace.coverage.gap_count = 2;
  assert(evidence.isOriginTraceResponse(captureTrace),'Queue-loss coverage must remain visible in the production trace consumer');
  const coverageStart = app.indexOf('          const {linked_steps: linked, gap_count: gaps} = trace.coverage;');
  const coverage = app.slice(coverageStart,app.indexOf('        } else {',coverageStart));
  const coverageValue = {};
  runInNewContext(coverage,{trace:captureTrace,elements:{coverageValue}});
  assert.match(coverageValue.textContent,/2 reported gaps/);
  assert.doesNotMatch(coverageValue.textContent,/missing predecessor|predecessor coverage/);
  assert.match(coverageValue.title,/do not identify missing links or prove value flow/);
  // Fixture counterexample: session replacement retires a selection, not every
  // request. Derive each replacement through the real /api/events handler/model.
  const fixtureRequests=async session=>{
    fixture.session=session;let body;
    await fixture.handle({url:'/api/events?limit=5000',method:'GET'},{writeHead(){},end:value=>{body=JSON.parse(value);}});
    assert(evidence.isBrokerResponse(body));
    return evidence.requestsFromEvents(body.events,'live');
  };
  const originalRequests=await fixtureRequests('11'),oldIdentity=model.investigationRequestIdentity(originalRequests[0]);
  const replacedRequests=await fixtureRequests('12');
  assert.equal(replacedRequests.length,1,'A stale selection notice does not mean the retained request window is empty');
  assert.equal(model.investigationResolve(oldIdentity,replacedRequests,model.investigationRequestIdentity).status,'stale');
  const retiredSelection={selectedRequestId:originalRequests[0].id,trafficDetailOpen:true,originTraceGeneration:0,signalProfileGeneration:0};
  const resetSelection=app.slice(app.indexOf('      function resetRequestSelection('),app.indexOf('      function renderRequestCount('));
  runInNewContext(resetSelection+';resetRequestSelection()',{state:retiredSelection,evidencePackagePanel:{sync(){}},passiveSecurityPanel:{sync(){}}});
  assert.equal(retiredSelection.selectedRequestId,null);assert.match(retiredSelection.trafficSelectionNotice,/left the retained capture window/);
  assert.equal(retiredSelection.trafficDetailOpen,true,'Retiring the old identity intentionally leaves its inspector open; later QA must close it through the control');
  const freshRequests=await fixtureRequests('14'),freshIdentity=model.investigationRequestIdentity(freshRequests[0]);
  assert.equal(freshRequests.length,1);assert.equal(freshIdentity.session,'14');assert.equal(freshIdentity.request,'91');
  assert.equal(model.investigationResolve(freshIdentity,freshRequests,model.investigationRequestIdentity).status,'ready');
  assert.equal(model.investigationResolve(freshIdentity,await fixtureRequests('13'),model.investigationRequestIdentity).status,'stale');
  console.log('PASS investigation fixture counterexample: stale selection can coexist with a retained replacement; fresh exact request comes from normal event admission (not rendered QA)');
  await checkNativeRequestBacktrace(root);
  await checkAdvancedNavigation(root);
  await checkInvestigationReturns(root);
  await checkCollectionNavigation(root, source);
  console.log('PASS investigation exact identity, u64 boundaries, CDP correlation separation, stale/ambiguous resolution, bounded branching return history and packaged asset wiring (not rendered QA)');
}

// Content capture must not erase the native root merely because the CDP row
// carries its events as a host/method/time candidate. Exercise the real chooser,
// root selector and trace reader, with only DOM leaves and HTTP delivery faked.
export async function checkNativeRequestBacktrace(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const models=await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8');
  const navigation=await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
  const section=(a,b)=>{const start=app.indexOf(a),end=app.indexOf(b,start+1);assert(start>=0&&end>start,`Missing retained app boundary: ${a} → ${b}`);return app.slice(start,end);};
  const fixture=investigationFixture({handle:async()=>false,release(){}});
  const initiated={...fixture.event,type:'request_initiated'};
  const started={...fixture.event,process_id:23,sequence_number:'52',request_id:'200',
    type:'request_started',initiator_process_id:17,initiator_request_id:91};
  const emptyBody=()=>({state:'empty',mime:'',text:'',base64:'',truncated:false,reason:''});
  const record={id:'cdp-native-candidate',protocol_request_id:'cdp-91',target_id:'target',target_title:'Fixture',
    url:'http://fixture.invalid/path',method:'POST',resource_type:'Fetch',started_monotonic_ms:1,
    state:'complete',status:200,mime_type:'text/plain',duration_ms:1,
    request:{headers:[],body:emptyBody()},response:{headers:[],body:emptyBody()}};
  const trace={...fixture.trace,request_id:'200',steps:[
    {...fixture.trace.steps[0],event:{session_id:'11',process_id:23,sequence_number:'52'},request_id:'200'},
    {...fixture.trace.steps[0],operation:'request_initiated',relation:'request_initiator'}
  ],gaps:[{...fixture.trace.gaps[0],after_step:1}],
    coverage:{linked_steps:1,observed_links:1,correlated_links:0,gap_count:1,percent:50}};
  const node=()=>({dataset:{},children:[],replaceChildren(...children){this.children=children;},
    querySelectorAll:()=>[],removeAttribute(name){delete this[name];}});
  const elements=Object.fromEntries(['traceRequest','traceLoad','backtraceSubtitle','traceContent','traceEmpty',
    'traceEvidence','traceFirstRequest','traceNotice','traceEmptyTitle','traceEmptyMessage','backtraceSteps',
    'traceStepDetails','coverageValue'].map(name=>[name,node()]));
  const state={requests:[],selectedRequestId:null,originTrace:null,originTraceKey:null,
    originTraceStatus:'idle',originTraceGeneration:0};
  const reads=[];
  const context={state,elements,TextDecoder,TextEncoder,URL,URLSearchParams,atob,Uint8Array,
    AbortController,setTimeout,clearTimeout,location:{protocol:'http:'},
    document:{activeElement:null,createElement:node},traceStepElement:node,traceStepDetails(){},renderEvidence(){},
    sourceFactsReadBytes:async response=>new TextEncoder().encode(JSON.stringify(await response.json())),
    fetch:async url=>{reads.push(new URL(url,'http://fixture.invalid'));return {ok:true,status:200,headers:{get:()=>null},json:async()=>trace};}};
  const api=runInNewContext(models+'\n'+navigation+'\n'+
    section('      function requestTraceRoot(', '      function requestSignalProfileSelection(')+
    section('      function originTraceSelection(', '      function traceStepDetails(')+
    section('      function renderBacktrace(', '      function collectionFolder(')+
    ';({isBrokerEvent,isOriginTraceResponse,requestsFromEvents,requestsFromDebuggerNetwork,trafficRowsForLiveCapture,requestTraceRoot,originTraceSelection,refreshOriginTrace,renderBacktrace})',context);
  assert(api.isBrokerEvent(initiated));assert(api.isBrokerEvent(started));assert(api.isOriginTraceResponse(trace));
  const native=api.requestsFromEvents([initiated,started]);
  assert.equal(native.length,1,'Explicit initiator identifiers group the native observations');
  const cdp=api.requestsFromDebuggerNetwork({capture_enabled:true,requests:[record]},native);
  assert.equal(cdp[0].events.length,2,'Exercise a CDP row with heuristic native candidate events');
  state.requests=api.trafficRowsForLiveCapture(cdp,native);
  api.renderBacktrace();
  assert.deepEqual(Array.from(elements.traceRequest.children,option=>option.value),[native[0].id],
    'The independent native row must remain a Backtraces choice during content capture');
  assert.equal(elements.traceRequest.disabled,false);
  assert.equal(elements.traceEmptyTitle.textContent,'Choose a captured request');
  state.selectedRequestId=native[0].id;
  api.renderBacktrace();
  assert.equal(elements.traceLoad.disabled,false);
  assert.equal(api.requestTraceRoot(native[0]),started,'Use the browser start, not the renderer or CDP id');
  await api.refreshOriginTrace();
  assert.equal(reads.length,1);assert.equal(reads[0].pathname,'/api/origin-trace');
  assert.deepEqual(Object.fromEntries(reads[0].searchParams),{
    request_id:'200',session_id:'11',root_process_id:'23',root_sequence_number:'52'});
  assert.equal(state.originTraceStatus,'ready');
  assert.equal(state.originTrace.steps[1].relation,'request_initiator');
  assert.equal(elements.traceContent.hidden,false);
  state.selectedRequestId=cdp[0].id;
  api.renderBacktrace();
  assert.equal(api.requestTraceRoot(cdp[0]),null);
  assert.equal(api.originTraceSelection(),null);
  assert.equal(elements.traceLoad.disabled,true,'Candidate events must not enable a CDP trace');
  await api.refreshOriginTrace();
  assert.equal(reads.length,1,'A CDP selection must not query the candidate native root');
  assert.equal(elements.traceContent.hidden,true,'Do not show the previous native trace as CDP evidence');
  assert.deepEqual(Array.from(elements.traceRequest.children,option=>option.value),[cdp[0].id,native[0].id]);
  assert.equal(cdp[0].nativeLink,null,'A non-numeric DevTools id is not a renderer request join');
  const rendererPayload=Buffer.from('POST fixture.invalid').toString('hex');
  const initiatedExact={...fixture.event,type:'request_initiated',request_id:'345',sequence_number:'77',process_id:19,
    payload:rendererPayload,payload_size:Buffer.byteLength('POST fixture.invalid')};
  const exactNative={id:'native-devtools',method:'POST',path:'fixture.invalid',firstTimestamp:9_000_000_000n,
    events:[initiatedExact,{...fixture.event,type:'request_started',request_id:'200',sequence_number:'78',process_id:23}],
    event:initiatedExact};
  const heuristicNative={id:'native-heuristic',method:'POST',path:'fixture.invalid',firstTimestamp:1_000_000n,
    events:[{id:'heuristic-marker'}],event:{id:'heuristic-marker'}};
  const joinedRecord={...record,id:'cdp-joined',protocol_request_id:'12.345'};
  const joined=api.requestsFromDebuggerNetwork({capture_enabled:true,requests:[joinedRecord]},[heuristicNative,exactNative]);
  assert.equal(joined[0].nativeCandidateId,'native-heuristic','Timing correlation stays a separate navigation');
  assert.equal(joined[0].nativeLink.kind,'devtools-request-id');
  assert.equal(joined[0].nativeLink.nativeRequestId,'native-devtools');
  assert.equal(joined[0].nativeLink.requestId,'345');
  assert.equal(api.requestTraceRoot(joined[0]),initiatedExact,'The join uses the renderer id, not the browser request_started id');
  state.requests=api.trafficRowsForLiveCapture(joined,[heuristicNative,exactNative]);
  state.selectedRequestId=joined[0].id;
  state.originTrace=null;state.originTraceKey=null;state.originTraceStatus='idle';
  api.renderBacktrace();
  assert.equal(elements.traceLoad.disabled,false);
  assert.match(elements.backtraceSubtitle.textContent,/DevTools request id join/);
  await api.refreshOriginTrace();
  assert.equal(reads.at(-1).searchParams.get('request_id'),'345');
  assert.equal(reads.at(-1).searchParams.get('root_process_id'),'19');
  assert.equal(reads.at(-1).searchParams.get('root_sequence_number'),'77');
  const bare=api.requestsFromDebuggerNetwork({capture_enabled:true,requests:[{...joinedRecord,protocol_request_id:'345'}]},[exactNative]);
  assert.equal(bare[0].nativeLink.requestId,'345');
  const padded=api.requestsFromDebuggerNetwork({capture_enabled:true,requests:[{...joinedRecord,protocol_request_id:'12.0345'}]},[exactNative]);
  assert.equal(padded[0].nativeLink,null,'A non-canonical renderer id is not a join');
  const startedOnly={...exactNative,id:'browser-counter',events:[{...fixture.event,type:'request_started',request_id:'345'}]};
  const browserCounter=api.requestsFromDebuggerNetwork({capture_enabled:true,requests:[joinedRecord]},[startedOnly]);
  assert.equal(browserCounter[0].nativeLink,null,'request_started ids are not DevTools renderer ids');
  assert.equal(api.requestTraceRoot(browserCounter[0]),null);
  const duplicate={...exactNative,id:'native-devtools-2'};
  const ambiguous=api.requestsFromDebuggerNetwork({capture_enabled:true,requests:[joinedRecord]},[exactNative,duplicate]);
  assert.equal(ambiguous[0].nativeLink,null,'Two renderer rows with the same id are not an exact join');
  assert.equal(api.requestTraceRoot(ambiguous[0]),null);
  console.log('PASS retained native Traffic row → Backtraces choice → exact session/process/sequence query; heuristic CDP root stays unavailable; unique DevTools renderer id joins (production functions, not rendered QA)');
}

// Exercise the actual shared-shell switch, rather than a navigation stub. A
// workspace under Advanced is still a destination, not a request to open its menu.
export async function checkAdvancedNavigation(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const source=app.slice(app.indexOf('      function showScreen('),app.indexOf('      async function refresh()'));
  const html=await readFile(join(root,'apps/research-ui/index.html'),'utf8');
  const vmEntry=html.match(/<button\b[^>]*id="nav-vm-workspace"[^>]*>/)?.[0];
  assert(vmEntry,'VM workspace must have a primary entry');
  assert.equal((html.match(/id="nav-vm-workspace"/g)||[]).length,1);
  assert(html.indexOf('id="nav-vm-workspace"')<html.indexOf('id="advanced-navigation"'),'VM must precede and be outside Advanced');
  assert.match(vmEntry,/class="[^"]*\bnav-button\b[^"]*"/,'VM entry must use shared navigation focus semantics');
  const advanced=['backtrace','analyst','tools'];
  const names=['traffic','api-collection','sources','vm','signals',...advanced,'evidence','field-provenance'];
  for(const narrow of [false,true]) {
    const focused=[],frames=[];let current='traffic';
    const document={activeElement:null};
    const summary={focus(){document.activeElement=this;focused.push('summary');}};
    const group={open:false,contains:node=>node===summary||buttons.some(button=>advanced.includes(button.dataset.screen)&&node===button),querySelector:()=>summary};
    const buttons=names.filter(name=>!['evidence','field-provenance'].includes(name)).map(name=>({
      dataset:{screen:name},classList:{contains:value=>value==='nav-button'},
      closest:()=>advanced.includes(name)?group:null,
      setAttribute(key,value){this[key]=value;},removeAttribute(key){delete this[key];},
    }));
    const screens=names.map(name=>({id:`screen-${name}`,hidden:name!=='traffic'}));
    document.getElementById=id=>screens.find(screen=>screen.id===id)??null;
    const destination={focus(){document.activeElement=this;focused.push('destination');}};
    document.querySelectorAll=selector=>selector==='.screen'?screens:selector==='.nav-button'?buttons:[];
    document.querySelector=selector=>selector==='#advanced-navigation'?group:selector.endsWith('.back-button')?destination:null;
    const noop=()=>{};
    const context={document,state:{requests:[],selectedRequestId:null,originTraceStatus:'idle'},investigationRevision:0,
      investigationBeforeScreen:name=>{current=name;},investigationScreen:()=>current,
      evidencePackagePanel:{setVisible:noop},sourceFactsPanel:{cancel:noop},float32Panel:{cancel:noop},
      evidenceWorkspace:{setVisible:noop},retireCanvasPreviews:noop,
      window:{matchMedia:()=>({matches:narrow})},requestAnimationFrame:callback=>frames.push(callback),selectedSource:()=>null,
      elements:{requestRows:{querySelectorAll:()=>[]},requestFilter:destination}};
    for(const name of ['renderRequests','updateSelectionSummary','renderInspector','renderFingerprintActivity','renderBacktrace','renderApiCollection','refreshApiCollection','renderLocalAnalyst','refreshLocalAnalyst','renderTools','refreshDecoderEngine','renderSources','renderVmLab'])context[name]=noop;
    const showScreen=runInNewContext(source+';showScreen',context);
    const flush=()=>{for(const callback of frames.splice(0))callback();};
    for(const name of ['traffic','backtraces','sources','tools','sources','backtrace','traffic','evidence','vm','field-provenance']) {
      showScreen(name);flush();
      assert.equal(group.open,false,`${name}: linked navigation must not open or retain Advanced at ${narrow?'narrow':'wide'} widths`);
      assert.equal(screens.filter(screen=>!screen.hidden).length,1);
      const currentButtons=buttons.filter(button=>button['aria-current']==='page');
      assert.equal(currentButtons.length,1,'Exactly one workspace tab is current');
      assert.equal(currentButtons[0].dataset.screen,name==='backtraces'||name==='evidence'?'backtrace':name==='field-provenance'?'traffic':name);
    }
    for(const name of advanced) {
      const button=buttons.find(button=>button.dataset.screen===name);
      group.open=true;document.activeElement=button;focused.length=0;
      showScreen(name,button);flush();
      assert.equal(group.open,false,`${name}: choosing a menu destination must dismiss Advanced`);
      assert.equal(button['aria-current'],'page');
      assert.equal(document.activeElement,summary,'A hidden menu item must not retain focus');
      assert.deepEqual(focused,['summary']);
      // Selecting the current workspace again is also a completed choice.
      group.open=true;showScreen(name,button);assert.equal(group.open,false);
    }
    for(const name of ['sources','vm']){
      const primary=buttons.find(button=>button.dataset.screen===name);
      group.open=true;document.activeElement=primary;focused.length=0;
      showScreen(name,primary);flush();
      assert.equal(group.open,false);assert.equal(document.activeElement,primary);
      assert.deepEqual(focused,[],'Primary navigation must keep its own focus');
    }
    group.open=true;document.activeElement=destination;focused.length=0;
    showScreen('tools');
    assert.equal(group.open,false);assert.deepEqual(focused,[],'Linked navigation must not redirect unrelated focus to the menu');
    flush();assert.equal(document.activeElement,destination);
    group.open=true;document.activeElement=buttons.find(button=>button.dataset.screen==='backtrace');focused.length=0;
    showScreen('sources');assert.equal(document.activeElement,summary);flush();
    assert.deepEqual(focused,['summary','destination'],'Existing destination focus must follow safe dismissal');
  }
  console.log('PASS shared Advanced chooser dismissal, repeated choices, primary focus and linked destination focus at wide/narrow widths (production functions, not rendered QA)');
}

export function investigationFixture(base) {
  const event={protocol_version:2,session_id:'11',process_id:17,thread_id:1,sequence_number:'41',monotonic_time_ns:'1000000',navigation_id:'13',frame_id:'17',artifact_id:'7',parent_event_id:'0',request_id:'91',category:'network',type:'request_started',payload_size:Buffer.byteLength('POST fixture.invalid'),payload_encoding:'hex',payload:Buffer.from('POST fixture.invalid').toString('hex'),initiator_request_id:0,initiator_process_id:0,resource_type:13,flags:0,status_code:0,error_code:0,encoded_data_length:'0',decoded_body_length:'0',payload_truncated:false};
  const trace={contract_version:1,document_kind:'origin-trace',request_id:'91',status:'partial',steps:[{event:{session_id:'11',process_id:17,sequence_number:'41'},monotonic_time_ns:'1000000',frame_id:'17',artifact_id:'7',request_id:'91',category:'network',operation:'request_started',relation:'trace_target',confidence:'observed',value:'POST fixture.invalid'}],gaps:[{reason:'no_predecessor',after_step:0,detail:'No earlier relationship was retained in this synthetic investigation.'}],artifacts:[],coverage:{linked_steps:0,observed_links:0,correlated_links:0,gap_count:1,percent:0}};
  const fixture={...base,event,trace,traceMode:'ready',artifactMode:'ready',tracePending:[],calls:[],session:'11'};
  fixture.handle=async(request,response)=>{
    const url=new URL(request.url,'http://127.0.0.1');fixture.calls.push({path:url.pathname,method:request.method||'GET'});
    if(fixture.calls.length>1024)fixture.calls.shift();
    const json=value=>{if(!response.destroyed){response.writeHead(200,{'Content-Type':'application/json'});response.end(JSON.stringify(value));}};
    if(url.pathname==='/api/events'){json({count:1,events:[{...event,session_id:fixture.session}],capture_mode:'live',broker_connected:true});return true;}
    if(url.pathname==='/api/artifacts'){const artifacts=fixture.artifactMode==='missing'?base.artifacts.filter(item=>item.artifact_id!=='7'):fixture.artifactMode==='ambiguous'?[...base.artifacts,base.artifacts[0]]:base.artifacts;json({count:artifacts.length,artifacts});return true;}
    if(url.pathname==='/api/origin-trace'){
      if(fixture.traceMode==='pending')await new Promise(resolve=>fixture.tracePending.push(resolve));
      json(fixture.traceMode==='foreign'?{...trace,steps:[{...trace.steps[0],event:{...trace.steps[0].event,session_id:'99'}}]}:trace);return true;
    }
    return base.handle(request,response);
  };
  fixture.releaseTrace=()=>{for(const done of fixture.tracePending.splice(0))done();};
  fixture.release=()=>{fixture.releaseTrace();base.release();};
  return fixture;
}

// These regressions exercise the production navigation and selection functions,
// including the independently reproduced same-workspace and retained-root races.
async function checkInvestigationReturns(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const nav=await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
  const section=(a,b)=>{const start=app.indexOf(a),end=app.indexOf(b,start+1);assert(start>=0&&end>start,`Missing retained app boundary: ${a} → ${b}`);return app.slice(start,end);};
  const selection=section('      function selectRequest(', '      function moveRequestSelection(');
  const artifactSelection=section('      function sourceArtifactIdentityMatches(', '      function closeSource(');
  const rootFunction=section('      function requestTraceRoot(', '      function requestSignalProfileSelection(');
  const traceSelection=section('      function originTraceSelection(', '      async function refreshOriginTrace(');
  const traceReader=section('      async function refreshOriginTrace(', '      function traceStepDetails(');
  function setup() {
    let screen='sources', traceReads=0, cancelled=0;
    const raf=[], focused=[], sourceReads=[], renders=[];
    const pane={id:'pane',scrollTop:0,scrollLeft:0,focus(){focused.push('pane');},matches:s=>s==='#pane'};
    const trigger={id:'source-trigger',focus(){focused.push('source-trigger');}};
    const back={focus(){focused.push('back');}};
    const rootNode={id:'screen-sources',dataset:{},scrollTop:0,scrollLeft:0,contains:()=>true,matches:s=>s==='#screen-sources',querySelector:s=>s==='#pane'?pane:s==='#source-trigger'?trigger:null,querySelectorAll:()=>[pane]};
    const notice={textContent:''}, panel={dataset:{},querySelector:()=>({open:false})}, consolePanel={dataset:{}};
    const requests=[1,2].map(n=>({id:`request-${n}`,origin:'live',operation:'request_started',events:[{session_id:'11',process_id:17,sequence_number:String(n),request_id:String(n),type:'request_started'}]}));
    const artifacts=[7,8].map(n=>({session_id:'11',artifact_id:String(n),sha256:'a'.repeat(64),byte_size:100,kind:'javascript'}));
    const state={requests,artifacts,selectedRequestId:'request-2',selectedArtifactId:'7',originTrace:{steps:[]},originTraceGeneration:0,signalProfileGeneration:0,decoderSteps:[],openArtifactIds:[],inspectorTab:'evidence',fieldTab:'body',sourceFormatted:false,sourceDeobfuscated:false,sourceWasm:false};
    const globals={state,CSS:{escape:s=>s},Promise,URLSearchParams,AbortController,TextDecoder,setTimeout,clearTimeout,location:{protocol:'http:'},
      sourceFactsReadBytes:async response=>new TextEncoder().encode(JSON.stringify(await response.json())),
      document:{activeElement:trigger,querySelector:s=>s==='.screen:not([hidden])'?{id:`screen-${screen}`}:s==='#investigation-notice'?notice:s==='#investigation-navigation'?panel:s==='#investigation-back'?back:s.startsWith('#screen-')?rootNode:s==='#console-experiment-traffic'?consolePanel:null},
      requestAnimationFrame:fn=>raf.push(fn),integerText:(e,k)=>String(e[k]),sourceFactsPanel:{navigate:()=>null,cancel:()=>{cancelled++;}},
      selectedSource:()=>state.artifacts.find(a=>a.artifact_id===state.selectedArtifactId),
      renderInspector(){},renderRequests(){},renderEvidence(){},renderBacktrace(){},refreshRequestSignalProfile(){},updateSelectionSummary(){},
      sourceIdentity:source=>JSON.stringify([source.session_id,source.artifact_id,source.sha256]),retireSourceAnalysis(){},renderSourceHealth(){},
      renderSources:()=>renders.push({id:state.selectedArtifactId,passive:run('investigationPassiveSource')}),loadArtifactContent:async artifact=>{sourceReads.push(artifact.artifact_id);},
      fieldSets:{body:[]},elements:{requestSearchScope:{value:'all'},prompt:{},sourceCodeWrap:{focus(){focused.push('code');}}},
      showScreen:name=>{screen=name;run('investigationBeforeScreen('+JSON.stringify(name)+')');},
      refreshOriginTrace:async()=>{traceReads++;state.originTrace={steps:[{event:state.requests.find(r=>r.id===state.selectedRequestId).events[0]}],gaps:[]};state.originTraceStatus='ready';state.originTraceKey=run('originTraceSelection().key');}};
    const context=createContext(globals);const run=code=>runInContext(code,context);
    run(rootFunction+'\n'+selection+'\n'+artifactSelection+'\n'+traceSelection+'\n'+nav);
    return {run,context,state,pane,raf,focused,notice,sourceReads,renders,setScreen:value=>{screen=value;},traceReads:()=>traceReads,cancelled:()=>cancelled,
      async flush(){await Promise.resolve();await Promise.resolve();for(const callback of raf.splice(0))callback();}};
  }
  const sourceEntry=t=>({screen:'sources',label:'Sources',artifact:t.run('investigationArtifactIdentity(state.artifacts[0])'),script:null,request:null,sourceRange:{start:1,end:3},sourceFormatted:false,sourceDeobfuscated:false,sourceWasm:false,focus:'#source-trigger',scroll:[{selector:'#pane',top:20,left:0}],notice:'original source'});
  for(const interaction of ['different-artifact','same-artifact-interaction']) {
    const t=setup();t.setScreen('tools');let resolve;t.context.sourceFactsPanel.navigate=()=>new Promise(done=>{resolve=done;});
    t.context.entry=sourceEntry(t);assert(t.run('restoreInvestigation(entry)'));t.pane.scrollTop=777;
    if(interaction==='different-artifact')t.state.selectedArtifactId='8';else t.run('retireInvestigationReturn()');
    resolve();await t.flush();assert.equal(t.pane.scrollTop,777);assert.deepEqual(t.focused,[]);
    if(interaction==='same-artifact-interaction')assert.equal(t.cancelled(),2);
  }
  {
    const t=setup();t.context.entry=t.run('investigationSnapshot()');assert(t.context.entry.scroll.some(item=>item.selector==='#pane'&&item.top===0));
    t.pane.scrollTop=777;assert(t.run('restoreInvestigation(entry)'));await t.flush();assert.equal(t.pane.scrollTop,0);
  }
  {
    const t=setup();t.setScreen('tools');t.context.entry={screen:'backtrace',label:'Backtrace',request:t.run('investigationRequestIdentity(state.requests[0])'),traceRow:'17:1',scroll:[],focus:null};
    assert(t.run('restoreInvestigation(entry)'));await t.flush();assert.equal(t.traceReads(),1);assert.equal(t.state.originTraceStatus,'ready');assert.equal(t.state.selectedTraceRow,'17:1');
  }
  {
    const t=setup();t.setScreen('tools');const rows=['target-A','target-B'].map((target,index)=>({id:'same',origin:'live',operation:'cdp_completed',tabId:target,protocolRequestId:'native-1',firstTimestamp:BigInt(index+1)}));
    t.state.requests=rows;t.state.selectedRequestId=null;t.context.route={kind:'request',identity:t.run('investigationRequestIdentity(state.requests[1])')};
    assert.equal(t.run('openInvestigation(route)'),false);assert.equal(t.state.selectedRequestId,null);assert.match(t.notice.textContent,/disambiguate/);
    assert.equal(t.run('selectRequest("same", route.identity)'),false,'Actual selection boundary must retain the exact identity, not first-match an ID');
    assert.equal(t.state.selectedRequestId,null);
  }
  {
    const t=setup();t.setScreen('tools');t.state.selectedArtifactId='8';t.context.route={kind:'artifact',identity:t.run('investigationArtifactIdentity(state.artifacts[0])')};
    assert(t.run('openInvestigation(route)'));assert.deepEqual(t.sourceReads,['7']);assert(t.renders.every(item=>item.id==='7'&&item.passive));
  }
  {
    const t=setup();t.state.originTrace={steps:[{event:t.state.requests[0].events[0]},{event:t.state.requests[1].events[0]}],gaps:[{after_step:0,reason:'missing_event',detail:'Original gap'}]};t.state.selectedTraceRow='gap:0:0';
    t.context.saved=t.run('investigationSelectedGap()');t.state.originTrace.steps.reverse();t.state.originTrace.gaps[0].after_step=1;
    assert.equal(t.run('investigationGapKey(saved)'),'gap:1:0');t.state.originTrace.gaps[0].detail='Different gap';assert.equal(t.run('investigationGapKey(saved)'),null);
    const dynamic={dataset:{},id:'',localName:'button'};t.context.dynamic=dynamic;t.context.owner={contains:()=>true,querySelectorAll:()=>[],querySelector:()=>null};
    assert.equal(t.run('investigationSelector(dynamic,owner,true)'),null,'Ordinal focus cannot target a different dynamic record');
  }
  {
    const t=setup();t.run(traceReader);const fixture=investigationFixture({handle:async()=>false,release(){}});
    t.context.isOriginTraceResponse=()=>true;
    const calls=[];
    t.context.fetch=async url=>{const query=new URL(url,'http://127.0.0.1').searchParams;calls.push(query);
      return {ok:true,status:200,headers:{get:()=>null},json:async()=>({...fixture.trace,steps:[{...fixture.trace.steps[0],event:{session_id:query.get('session_id'),process_id:17,sequence_number:'9007199254740993'}}]})};};
    // These IDs arrive as canonical JSON strings; unsafe JSON numbers cannot be recovered.
    for(const session of ['9007199254740992','9007199254740993','18446744073709551615']) {
      t.state.requests=[{id:'same',origin:'live',operation:'request_started',events:[{...fixture.event,session_id:session,sequence_number:'9007199254740993'}]}];t.state.selectedRequestId='same';
      await t.context.refreshOriginTrace();assert.equal(t.state.originTraceStatus,'ready');
      assert.equal(calls.at(-1).get('session_id'),session);assert.equal(calls.at(-1).get('root_sequence_number'),'9007199254740993');
    }
    for(const field of ['session_id','sequence_number','request_id']) {
      for(const invalid of [9007199254740992,'01','18446744073709551616',null]) {
        t.state.requests[0].events=[{...fixture.event,[field]:invalid}];
        assert.equal(t.run('originTraceSelection()'),null);await t.context.refreshOriginTrace();
      }
    }
    t.state.requests[0].events=[fixture.event];t.state.requests.push({...t.state.requests[0]});
    assert.equal(t.run('originTraceSelection()'),null);await t.context.refreshOriginTrace();
    assert.equal(calls.length,3,'Unsafe or ambiguous identities must never be sent');
  }
  for(const phase of ['fetch','body','304']) {
    const t=setup();t.run(traceReader);const fixture=investigationFixture({handle:async()=>false,release(){}});
    const request={id:'stable-row',origin:'live',operation:'request_started',events:[fixture.event]};t.state.requests=[request];t.state.selectedRequestId=request.id;
    t.state.originTrace=fixture.trace;t.state.originTraceKey=t.run('originTraceSelection().key');t.state.originTraceEtag='old';
    t.context.isOriginTraceResponse=()=>true;
    let release,bodyStarted=false;
    const response={ok:true,status:phase==='304'?304:200,headers:{get:()=>null},json:()=>{bodyStarted=true;return phase==='body'?new Promise(done=>{release=()=>done(fixture.trace);}):Promise.resolve(fixture.trace);}};
    t.context.fetch=()=>phase==='body'?Promise.resolve(response):new Promise(done=>{release=()=>done(response);});
    const pending=t.context.refreshOriginTrace();if(phase==='body'){for(let turn=0;turn<10&&!bodyStarted;turn++)await Promise.resolve();assert(bodyStarted);}
    t.state.requests=[{...request,events:[{...fixture.event,sequence_number:'42',type:'response_completed'}]}];release();await pending;
    assert.equal(t.state.originTrace,null);assert.equal(t.state.originTraceStatus,'error');assert.match(t.state.originTraceError,/selected request event changed/);
  }
  {
    const t=setup();t.run(traceReader);const fixture=investigationFixture({handle:async()=>false,release(){}});
    t.state.requests=[{id:'same',origin:'live',operation:'request_started',events:[fixture.event]}];t.state.selectedRequestId='same';
    t.context.isOriginTraceResponse=()=>true;const pending=[];let deadline;
    t.context.setTimeout=(callback,delay)=>{assert.equal(delay,10000);deadline=callback;return 1;};t.context.clearTimeout=()=>{};
    t.context.fetch=(url,{signal})=>new Promise((resolve,reject)=>{pending.push({resolve,signal});signal.addEventListener('abort',()=>reject(Object.assign(new Error('Aborted'),{name:'AbortError'})),{once:true});});
    const first=t.context.refreshOriginTrace(),firstController=t.state.originTraceController;
    const second=t.context.refreshOriginTrace();assert.equal(firstController.signal.aborted,true);await first;
    assert.equal(t.state.originTraceStatus,'loading');assert.equal(pending.length,2);
    pending[1].resolve({ok:true,status:200,headers:{get:()=>null},json:async()=>fixture.trace});await second;
    assert.equal(t.state.originTraceStatus,'ready');assert.equal(t.state.originTraceController,null);
    const timed=t.context.refreshOriginTrace();deadline();await timed;assert.equal(t.state.originTraceStatus,'error');assert.match(t.state.originTraceError,/timed out or was cancelled/);assert.equal(t.state.originTraceController,null);
  }
  {
    const event={session_id:'11',process_id:17,sequence_number:'42',request_id:'91',type:'response_completed'};
    const state={selectedRequestId:'same',selectedField:{path:'selected'},requests:[{id:'same',origin:'live',operation:'response_completed',events:[event]}],originTraceKey:'same:11:17:41',originTrace:{steps:[{event:{...event,sequence_number:'41'},monotonic_time_ns:'1',confidence:'observed',category:'network',operation:'request_started',frame_id:'1',request_id:'91',artifact_id:'7',value:'prior root'}],gaps:[]}};
    const node=()=>({children:[],setAttribute(){},append(...children){this.children.push(...children);},replaceChildren(...children){this.children=children;}});
    const elements={evidenceRows:node(),evidenceCount:node(),evidenceLinkCount:node()};
    const context=createContext({state,elements,evidencePackagePanel:{sync(){}},evidenceWorkspace:{sync(){}},sampleEvidence:[{value:'must not substitute sample data'}],document:{querySelectorAll:()=>[],querySelector:()=>({hidden:true}),createElement:node},integerText:(event,key)=>String(event[key]),formatMilliseconds:String,renderBacktrace(){}});
    runInContext(nav.slice(nav.indexOf('const investigationId ='),nav.indexOf('function investigationEventIdentity('))+'\n'+rootFunction+'\n'+section('      function renderEvidence(', '      async function refreshOriginTrace('),context);
    context.renderEvidence();assert.equal(elements.evidenceRows.children.length,0);assert.equal(elements.evidenceLinkCount.textContent,'0','Completed stale trace cannot become an Evidence count');
    state.originTrace=null;context.renderEvidence();assert.equal(elements.evidenceRows.children.length,0,'Live requests never fall back to sample evidence');
  }
  // The real shell changes screens synchronously, but return focus belongs to
  // its guarded animation frame. Screen arrival alone is not a focus receipt.
  for(const interruption of [null,'interaction','identity']) {
    const frames=[],document={activeElement:null};
    const trigger={id:'trace-origin',focus(){document.activeElement=this;}};
    const back={id:'investigation-back',classList:{contains:()=>false},focus(){document.activeElement=this;}};
    const row={dataset:{requestId:'native'},focus(){document.activeElement=this;}};
    const screens=['traffic','backtrace'].map(name=>({id:`screen-${name}`,hidden:name!=='backtrace',dataset:{},
      contains:node=>name==='traffic'&&node===trigger,querySelector:s=>s==='#trace-origin'?trigger:null,querySelectorAll:()=>[]}));
    const notice={textContent:''},bar={dataset:{},querySelector:()=>({open:false})},consolePanel={dataset:{}};
    const navigation={open:false,contains:()=>false};
    const request={id:'native',origin:'live',operation:'request_started',events:[{session_id:'11',process_id:17,sequence_number:'41',request_id:'91',type:'request_started'}]};
    const state={requests:[request],selectedRequestId:'native',inspectorTab:'evidence',fieldTab:'body',originTraceStatus:'ready',decoderSteps:[]};
    const noop=()=>{};
    document.querySelector=s=>s==='.screen:not([hidden])'?screens.find(screen=>!screen.hidden):s==='#advanced-navigation'?navigation:s==='#investigation-back'?back:s==='#investigation-notice'?notice:s==='#investigation-navigation'?bar:s==='#console-experiment-traffic'?consolePanel:screens.find(screen=>'#'+screen.id===s)??null;
    document.querySelectorAll=s=>s==='.screen'?screens:[];
    document.getElementById=id=>screens.find(screen=>screen.id===id)??null;
    const context=createContext({document,state,CSS:{escape:s=>s},Promise,requestAnimationFrame:fn=>frames.push(fn),integerText:(e,k)=>String(e[k]),
      selectedSource:()=>null,sourceFactsPanel:{cancel:noop},float32Panel:{cancel:noop},evidenceWorkspace:{setVisible:noop},retireCanvasPreviews:noop,
      renderRequests:noop,updateSelectionSummary:noop,renderInspector:noop,fieldSets:{body:[]},elements:{requestRows:{querySelectorAll:()=>[row]},requestFilter:row}});
    const run=code=>runInContext(code,context);
    run(rootFunction+'\n'+nav+'\n'+section('      function showScreen(', '      async function refresh()'));
    context.entry={screen:'traffic',label:'Requests',request:run('investigationRequestIdentity(state.requests[0])'),inspectorTab:'evidence',fieldTab:'body',fieldPath:'',focus:'#trace-origin',scroll:[]};
    document.activeElement=back;
    assert(run('restoreInvestigation(entry)'));
    assert.equal(run('investigationScreen()'),'traffic','The screen arrives before the deferred return focus');
    assert.equal(document.activeElement,back,'An immediate screen-only assertion reproduces the CI pre-frame focus');
    await Promise.resolve();await Promise.resolve();
    assert.equal(frames.length,2,'Both production shell and exact-return focus are deferred');
    if(interruption==='interaction')run('retireInvestigationReturn()');
    if(interruption==='identity')state.requests=[{...request,events:[{...request.events[0],session_id:'12'}]}];
    for(const frame of frames.splice(0))frame();
    if(!interruption)assert.equal(document.activeElement,trigger,'Settled exact return restores the original trigger');
    else assert.notEqual(document.activeElement,trigger,'A newer interaction or replaced identity must prevent stale trigger focus');
  }
  console.log('PASS investigation screen-before-focus counterexample, real shell/return frame ordering, settled trigger and interruption/identity guards (production functions, not rendered QA)');
  console.log('PASS production return ownership, zero scroll, exact trace reread, stable gap/focus identity, actual request-ID collision guard, original-only source pivot and fetch/body/304 retained-root races (not rendered QA)');
}

// Receiving Collection controller stays authoritative for draft guards and
// confirmed persistence. No captured identity is copied into its document.
async function checkCollectionNavigation(root, navigation) {
  const {checkCollectionController} = await import('./check-origin-trace-collection.mjs');
  const deferred = () => {let resolve; const promise = new Promise(done => {resolve=done;}); return {promise,resolve};};
  const setup = async () => {
    const fixture = await checkCollectionController(root, true);
    const {state,elements,ui} = fixture;
    let screen='traffic', notice='', focus=0;
    const raf=[];
    state.requests=[{id:'cdp-1',origin:'live',operation:'cdp_completed',tabId:'page-1',protocolRequestId:'7',firstTimestamp:1n,method:'POST',path:'https://fixture.invalid/path?secret=omitted#fragment'}];
    state.selectedRequestId='cdp-1';
    elements.requestCollectionPivot={textContent:'Add to Collection'};
    elements.collectionRequestName.focus=()=>{focus++;};
    const context=createContext({state,elements,URL,Number,sourceFactsPanel:{},requestAnimationFrame:fn=>raf.push(fn),renderInspector(){},
      refreshApiCollection:ui.refreshApiCollection,createCollectionRequest:ui.createCollectionRequest,
      document:{querySelector:()=>({id:`screen-${screen}`})},
      showScreen:name=>{screen=name;}});
    runInContext(navigation+`;investigationNotice=message=>{noticeWriter(message);};`,Object.assign(context,{noticeWriter:value=>{notice=value;}}));
    return {...fixture,context,run:code=>runInContext(code,context),screen:()=>screen,notice:()=>notice,focus:()=>focus,flush:()=>raf.splice(0).forEach(fn=>fn())};
  };
  const settle=async(t,code,mutate)=>{
    const pending=t.run(code);assert.equal(t.pending.length,1);
    mutate?.();t.pending.shift().resolve({ok:true,status:304,headers:{get:()=>null}});
    for(let i=0;i<10;i++)await Promise.resolve();return pending;
  };
  {
    const t=await setup();t.state.collectionDraftDirty=true;t.state.collectionRequestDraftId=1;t.state.collectionRequestDraftCreatedAt=1000;
    assert.equal(await settle(t,'copyInvestigationRequestToCollection()'),null);assert.equal(t.pending.length,0);
    assert.equal(t.state.collectionDraftDirty,true);assert.equal(t.screen(),'traffic');assert.match(t.notice(),/Unsaved edits|declined/);
  }
  for(const change of ['request','session','interaction']) {
    const t=await setup();assert.equal(await settle(t,'copyInvestigationRequestToCollection()',()=>{
      if(change==='request')t.state.selectedRequestId='other';else if(change==='session')t.state.requests[0].tabId='other';else t.run('retireInvestigationReturn()');
    }),null);assert.equal(t.pending.length,0);assert.equal(t.screen(),'traffic');
  }
  for(const outcome of ['success','newer','refused']) {
    const t=await setup();const first=t.run('copyInvestigationRequestToCollection()');
    assert.equal(await t.run('copyInvestigationRequestToCollection()'),null,'Repeat copy must not start a second write');
    t.pending.shift().resolve({ok:true,status:304,headers:{get:()=>null}});for(let i=0;i<10;i++)await Promise.resolve();
    assert.equal(t.pending.length,1);const action=t.pending.shift();assert.equal(action.url,'/api/api-collection/actions');
    const submitted=JSON.parse(action.options.body);assert(!action.options.body.includes('secret'));assert(!action.options.body.includes('protocolRequestId'));
    const saved=structuredClone(t.state.apiCollection);saved.generation++;
    saved.requests=submitted.requests.map(value=>({...value,created_at_ms:value.created_at_ms??2000,updated_at_ms:2000}));
    if(outcome==='newer')t.run('retireInvestigationReturn()');
    action.resolve({ok:outcome!=='refused',status:outcome==='refused'?500:200,json:async()=>outcome==='refused'?{error:'save refused'}:saved});
    const id=await first;t.flush();
    assert.equal(t.focus(),outcome==='success'?1:0,'Late copy cannot focus another workspace');
    assert.equal(t.screen(),outcome==='success'?'api-collection':'traffic');
    assert.equal(t.actions.length,0,'Copy never sends or evaluates a request');
    if(outcome==='refused')assert.equal(id,null);else {
      assert(Number.isSafeInteger(id));const recipe=t.state.apiCollection.requests.find(item=>item.id===id);
      assert.equal(recipe.url,'https://fixture.invalid/path');assert.equal(recipe.body,'');assert.equal(recipe.headers.length,0);assert.equal(recipe.variables.length,0);
    }
  }
  console.log('PASS exact request→Collection confirmed copy, query stripping, actual dirty guard, stale selection/session/interaction, repeated copy, failed save, late focus and no execution (not rendered QA)');
}
