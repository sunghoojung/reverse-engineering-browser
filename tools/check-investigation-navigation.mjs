import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext,createContext,runInContext} from 'node:vm';

export async function checkInvestigationCore(root) {
  const app = await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const requestRoot = app.slice(app.indexOf('      function requestTraceRoot('),app.indexOf('      function requestSignalProfileSelection('));
  const source = await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
  const model = runInNewContext(`function integerText(event,field){return String(event[field]);}\n${requestRoot}\n${source}\n;({investigationId,investigationEventIdentity,investigationArtifactIdentity,investigationScriptIdentity,investigationRequestIdentity,investigationSame,investigationResolve,createInvestigationHistory})`);
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
  const script={script_id:'live-1',target_id:'target-1',hash:'opaque-token',execution_context_id:7,start_line:2,start_column:3,length:40};
  const scriptId=model.investigationScriptIdentity(script);assert.equal(scriptId.type,'live-script');
  for(const field of ['script_id','target_id','hash']) {
    assert(model.investigationScriptIdentity({...script,[field]:'x'.repeat(256)}));
    for(const value of ['x'.repeat(257),'x'.repeat(2*1024*1024),'']) assert.equal(model.investigationScriptIdentity({...script,[field]:value}),null);
  }
  for(const field of ['execution_context_id','start_line','start_column','length']) {
    assert.equal(model.investigationSame(scriptId,model.investigationScriptIdentity({...script,[field]:script[field]+1})),false);
    assert.equal(model.investigationScriptIdentity({...script,[field]:Number.MAX_SAFE_INTEGER+1}),null);
  }
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
  runInNewContext(resetSelection+';resetRequestSelection()',{state:retiredSelection,evidencePackagePanel:{sync(){}}});
  assert.equal(retiredSelection.selectedRequestId,null);assert.match(retiredSelection.trafficSelectionNotice,/left the retained capture window/);
  assert.equal(retiredSelection.trafficDetailOpen,true,'Retiring the old identity intentionally leaves its inspector open; later QA must close it through the control');
  const freshRequests=await fixtureRequests('14'),freshIdentity=model.investigationRequestIdentity(freshRequests[0]);
  assert.equal(freshRequests.length,1);assert.equal(freshIdentity.session,'14');assert.equal(freshIdentity.request,'91');
  assert.equal(model.investigationResolve(freshIdentity,freshRequests,model.investigationRequestIdentity).status,'ready');
  assert.equal(model.investigationResolve(freshIdentity,await fixtureRequests('13'),model.investigationRequestIdentity).status,'stale');
  console.log('PASS investigation fixture counterexample: stale selection can coexist with a retained replacement; fresh exact request comes from normal event admission (not rendered QA)');
  await checkAdvancedNavigation(root);
  await checkInvestigationReturns(root);
  await checkCollectionNavigation(root, source);
  console.log('PASS investigation exact identity, u64 boundaries, CDP correlation separation, stale/ambiguous resolution, bounded branching return history and packaged asset wiring (not rendered QA)');
}

// Exercise the actual shared-shell switch, rather than a navigation stub. A
// workspace under Advanced is still a destination, not a request to open its menu.
export async function checkAdvancedNavigation(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const source=app.slice(app.indexOf('      function showScreen('),app.indexOf('      async function refresh()'));
  const advanced=['backtrace','memory','experiments','analyst','tools'];
  const names=['traffic','api-collection','sources','signals',...advanced,'evidence','vm','field-provenance'];
  for(const narrow of [false,true]) {
    const focused=[],frames=[];let current='traffic';
    const document={activeElement:null};
    const summary={focus(){document.activeElement=this;focused.push('summary');}};
    const group={open:false,contains:node=>node===summary||buttons.some(button=>advanced.includes(button.dataset.screen)&&node===button),querySelector:()=>summary};
    const buttons=names.filter(name=>!['evidence','vm','field-provenance'].includes(name)).map(name=>({
      dataset:{screen:name},classList:{contains:value=>value==='nav-button'},
      closest:()=>advanced.includes(name)?group:null,
      setAttribute(key,value){this[key]=value;},removeAttribute(key){delete this[key];},
    }));
    const screens=names.map(name=>({id:`screen-${name}`,hidden:name!=='traffic'}));
    const destination={focus(){document.activeElement=this;focused.push('destination');}};
    document.querySelectorAll=selector=>selector==='.screen'?screens:selector==='.nav-button'?buttons:[];
    document.querySelector=selector=>selector==='#advanced-navigation'?group:selector.endsWith('.back-button')?destination:null;
    const noop=()=>{};
    const context={document,state:{originTraceStatus:'idle',sourceHooksOpen:false},investigationRevision:0,
      investigationBeforeScreen:name=>{current=name;},investigationScreen:()=>current,
      evidencePackagePanel:{setVisible:noop},sourceFactsPanel:{cancel:noop},float32Panel:{cancel:noop},
      evidenceWorkspace:{setVisible:noop},retireCanvasPreviews:noop,
      window:{matchMedia:()=>({matches:narrow})},requestAnimationFrame:callback=>frames.push(callback),selectedSource:()=>null,
      elements:{requestRows:{querySelectorAll:()=>[]},requestFilter:destination}};
    for(const name of ['renderFingerprintActivity','renderRuntimeHookTraffic','renderBacktrace','renderExperiment','renderApiCollection','refreshApiCollection','renderLocalAnalyst','refreshLocalAnalyst','renderTools','refreshDecoderEngine','renderDebugger','renderSources','renderMemory','renderVmLab'])context[name]=noop;
    const showScreen=runInNewContext(source+';showScreen',context);
    const flush=()=>{for(const callback of frames.splice(0))callback();};
    for(const name of ['traffic','backtraces','sources','tools','sources','backtrace','traffic','evidence']) {
      showScreen(name);flush();
      assert.equal(group.open,false,`${name}: linked navigation must not open or retain Advanced at ${narrow?'narrow':'wide'} widths`);
      assert.equal(screens.filter(screen=>!screen.hidden).length,1);
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
    const primary=buttons.find(button=>button.dataset.screen==='sources');
    group.open=true;document.activeElement=primary;focused.length=0;
    showScreen('sources',primary);flush();
    assert.equal(group.open,false);assert.equal(document.activeElement,primary);
    assert.deepEqual(focused,[],'Primary navigation must keep its own focus');
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

export async function checkInvestigationInteractions({evaluate,viewport,click,key,wheel,screenshot,dialog,typeText,fixture}) {
  const until=async(expression,message)=>{const start=Date.now();while(Date.now()-start<5000){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,25));}assert.fail(message);};
  const enter=()=>key('Enter','Enter',{windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});
  const closed=async label=>{
    assert.equal(await evaluate("document.querySelector('#advanced-navigation').open"),false,`${label}: Advanced must be dismissed`);
    assert.equal(await evaluate("Boolean(document.activeElement?.closest('#advanced-navigation .advanced-items'))"),false,`${label}: focus must not remain in the hidden chooser`);
  };
  const arrived=async(name,label)=>{
    await until(`investigationScreen()===${JSON.stringify(name)}`,`${label}: destination did not open`);
    await closed(label);
  };
  const paneClick=async selector=>{
    const delta=await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});const p=n?.closest('#source-sidebar .debug-panes, .trace-inspector, .decoder-column');if(!n)throw Error('Missing control');if(!p)return 0;const r=n.getBoundingClientRect(),b=p.getBoundingClientRect();return r.top<b.top?r.top-b.top:r.bottom>b.bottom?r.bottom-b.bottom:0})()`);
    if(delta){const parent=await evaluate(`(()=>{const p=document.querySelector(${JSON.stringify(selector)}).closest('#source-sidebar .debug-panes, .trace-inspector, .decoder-column');if(p.id)return '#'+p.id;return p.classList.contains('debug-panes')?'#source-sidebar .debug-panes':p.classList.contains('trace-inspector')?'.trace-inspector':'.decoder-column'})()`);await wheel(parent,delta);}
    await click(selector);
  };
  await until('state.requests.length===1 && state.artifacts.length===2','Synthetic request and sources did not load');
  await closed('Initial workspace');
  const derivedBefore=fixture.calls.filter(call=>call.path==='/api/deobfuscation').length;
  await click('.request-row'); await click('#request-evidence-toggle');
  const origin=await evaluate('({id:state.selectedRequestId,tab:state.inspectorTab})');
  await click('#trace-origin');
  await until('state.originTraceStatus===\'ready\'','Request trace did not load');
  await arrived('backtrace','Request to Backtrace');
  assert.match(await evaluate("document.querySelector('#trace-step-details').textContent"),/No value flow|Recorded event link|Recorded link/);
  await paneClick('[data-investigation-source]');
  await until('state.selectedArtifactId===\'7\' && selectedSource().content!==undefined','Trace source did not open');
  await arrived('sources','Backtrace to retained source');
  await click('#source-facts-toggle');
  await until("document.querySelectorAll('#source-facts-report .source-fact').length>0",'Facts did not render');
  await paneClick('.source-fact > button');
  await until("!document.querySelector('#investigation-decode-range').disabled",'Verified original range cannot be decoded');
  const sourcePosition=await evaluate("({top:document.querySelector('#source-sidebar .debug-panes').scrollTop,code:elements.sourceCodeWrap.scrollTop})");
  await screenshot('investigation-source-original');
  await click('#investigation-decode-range');
  await arrived('tools','Verified range to Decoder');
  assert.equal(await evaluate('toolsElements.inputEncoding.value'),'base64');
  assert.equal(await evaluate('toolsElements.input.value'),Buffer.from('雪').toString('base64'));
  assert.equal(await evaluate('state.decoderSteps.length'),0,'Opening Decoder must not run a transform');
  assert.match(await evaluate("document.querySelector('#investigation-decoder-origin').textContent"),/original bytes.*SHA-256/);
  await screenshot('investigation-decoder-evidence');
  await click('#investigation-back');
  await arrived('sources','Back to original source');
  assert.equal(await evaluate('state.selectedArtifactId'),'7');
  await until("document.activeElement.id==='investigation-decode-range'",'Source trigger focus was not restored');
  assert.equal(await evaluate("document.querySelector('#source-sidebar .debug-panes').scrollTop"),sourcePosition.top,'Source details scroll was not restored');
  assert.equal(await evaluate('elements.sourceCodeWrap.scrollTop'),sourcePosition.code,'Original source scroll was not restored');
  await click('#investigation-back');await arrived('backtrace','Back to trace');
  assert(await evaluate('Boolean(state.selectedTraceRow)'),'Trace selection was lost');
  await evaluate("document.querySelector('#investigation-back').focus()");await enter();await arrived('traffic','Keyboard Back to request');
  assert.equal(await evaluate('state.selectedRequestId'),origin.id);assert.equal(await evaluate('state.inspectorTab'),origin.tab);
  await until("document.activeElement.id==='trace-origin'",'Origin trigger focus was not restored after the return frame');
  assert.equal(await evaluate('document.activeElement.id'),'trace-origin','Origin trigger focus was not restored');
  assert.equal(await evaluate('toolsElements.input.value'),Buffer.from('雪').toString('base64'),'Decoder draft was lost on return');
  await screenshot('investigation-returned-request');
  // Native keyboard activation of the shared return controls.
  await click('#investigation-forward');await arrived('backtrace','Forward to trace');
  await key('ArrowLeft','ArrowLeft',{windowsVirtualKeyCode:37,modifiers:1});
  await arrived('traffic','Alt+Left');
  await key('ArrowRight','ArrowRight',{windowsVirtualKeyCode:39,modifiers:1});
  await arrived('backtrace','Alt+Right');
  await click('#investigation-forward');await arrived('sources','Forward to Sources');
  await click('#investigation-forward');await arrived('tools','Forward to Decoder');
  await click('#decoder-input');await key('a','KeyA',{windowsVirtualKeyCode:65,modifiers:process.platform==='darwin'?4:2});await key('Backspace','Backspace',{windowsVirtualKeyCode:8});await typeText('bmV3ZXI=');
  await until("toolsElements.input.value==='bmV3ZXI='",'Editing the Decoder draft through its control failed');
  assert.match(await evaluate("document.querySelector('#investigation-decoder-origin').textContent"),/Input changed/);
  await paneClick('#investigation-decoder-origin button');
  await until("investigationScreen()==='sources' && document.querySelector('#source-position').textContent.includes('Original UTF-8 bytes')",'Open original evidence did not reveal the verified range');
  await arrived('sources','Open original evidence');
  assert.equal(await evaluate('toolsElements.input.value'),'bmV3ZXI=','Origin navigation replaced a newer Decoder draft');
  const replace=async accept=>{
    const pending=paneClick('#investigation-decode-range');let clickError;pending.catch(error=>{clickError=error;});
    try {await dialog(accept);await pending;} catch(error) {await pending.catch(()=>{});throw clickError||error;}
  };
  await replace(false);await arrived('sources','Declined Decoder replacement');assert.equal(await evaluate('toolsElements.input.value'),'bmV3ZXI=');
  await replace(true);await arrived('tools','Confirmed Decoder replacement');
  assert.equal(await evaluate('toolsElements.input.value'),Buffer.from('雪').toString('base64'));
  assert.equal(await evaluate('state.decoderSteps.length'),0,'Replacement automatically executed a transformation');
  await screenshot('investigation-confirmed-replacement');
  for(let stop=0;stop<24 && await evaluate('investigationScreen()')!=='backtrace';stop++){await click('#investigation-back');await closed('Return after origin/replacement');}
  await until("investigationScreen()==='backtrace'",'Could not return to the exact trace after origin/replacement actions');
  assert.equal(fixture.calls.filter(call=>call.path==='/api/deobfuscation').length,derivedBefore,'Investigation pivots automatically requested derived analysis');
  // Synthetic delivery faults exercise production identity and cancellation gates.
  fixture.traceMode='foreign';await click('#trace-load');await until("state.originTraceStatus==='error'",'Foreign session trace was accepted');
  assert.match(await evaluate('state.originTraceError'),/different captured session/);
  fixture.traceMode='pending';await click('#trace-load');
  const start=Date.now();while(!fixture.tracePending.length&&Date.now()-start<5000)await new Promise(resolve=>setTimeout(resolve,25));
  assert(fixture.tracePending.length);await click('#investigation-back');fixture.traceMode='ready';fixture.releaseTrace();
  await new Promise(resolve=>setTimeout(resolve,100));await arrived('traffic','Leave pending trace');assert.notEqual(await evaluate('state.originTraceStatus'),'loading');
  fixture.artifactMode='missing';await evaluate('refreshArtifacts()');
  await click('#trace-origin');await until("state.originTraceStatus==='ready'",'Retry trace failed');await arrived('backtrace','Retry trace with missing source');
  assert(await evaluate("document.querySelector('[data-investigation-source]').disabled"));
  assert.match(await evaluate("document.querySelector('#trace-step-details').textContent"),/not retained/);
  fixture.artifactMode='ambiguous';await evaluate('refreshArtifacts();').then(()=>evaluate('renderBacktrace()'));
  assert.match(await evaluate("document.querySelector('#trace-step-details').textContent"),/Multiple retained artifacts/);
  fixture.artifactMode='ready';await evaluate('refreshArtifacts()');await evaluate('renderBacktrace()');
  await paneClick('[data-investigation-source]');await arrived('sources','Recovered retained source');
  // Console location is a search, never exact artifact navigation or byte offsets.
  const before=await evaluate('state.selectedArtifactId');
  await evaluate("document.dispatchEvent(new CustomEvent('reb-console-location',{detail:{url:'https://fixture.invalid/facts-8.js',line:999,unavailable:false}}))");
  assert.equal(await evaluate('state.selectedArtifactId'),before);
  assert.match(await evaluate("document.querySelector('#investigation-source-search').textContent"),/do not verify shared identity/);
  await click('#investigation-source-search button:last-child');await arrived('sources','Explicit unverified search candidate');
  // An old request identity cannot silently reopen a reused ID in a new session.
  fixture.session='12';await evaluate('refresh()');await until("state.events[0]?.session_id==='12'",'Session change did not load');
  await click('#advanced-navigation > summary');
  assert.equal(await evaluate("document.querySelector('#advanced-navigation').open"),true);
  await click('#investigation-back');assert.equal(await evaluate('investigationScreen()'),'sources');
  assert.equal(await evaluate("document.querySelector('#advanced-navigation').open"),true,'A refused return must not blanket-close a manually opened chooser');
  await click('#advanced-navigation > summary');await closed('Manual dismissal after refused return');
  assert.match(await evaluate("document.querySelector('#investigation-notice').textContent"),/Return unavailable/);
  for(const size of [[760,560],[360,740]]){
    await viewport(...size);await click('#investigation-navigation summary');
    if(!await evaluate("document.querySelector('#investigation-navigation details').open"))await click('#investigation-navigation summary');
    assert(await evaluate("(()=>{const b=document.querySelector('#investigation-back').getBoundingClientRect();return b.left>=0&&b.right<=innerWidth&&b.top>=0&&b.bottom<=innerHeight})()"));
    await closed(`Narrow stale return ${size[0]}`);
    await screenshot(`investigation-return-unavailable-${size[0]}`);
  }
  // Manual use stays native: genuine summary/item clicks and Enter/Tab/Escape,
  // never a test-only assignment to details.open or synthetic button.click().
  for(const size of [[1440,900],[760,560],[360,740]]) {
    await viewport(...size);
    const choices=size[0]===1440?['backtrace','memory','experiments','analyst','tools']:['tools'];
    for(const name of choices) {
      await click('#advanced-navigation > summary');
      await until("document.querySelector('#advanced-navigation').open",'Pointer did not open Advanced');
      await evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
      assert.equal(await evaluate("document.querySelector('#advanced-navigation').open"),true,'The manual chooser must stay open until a choice');
      if(name==='tools')await screenshot(`investigation-manual-chooser-${size[0]}`);
      await click(`#advanced-navigation .nav-button[data-screen="${name}"]`);
      await arrived(name,`Pointer Advanced → ${name} at ${size[0]}`);
      assert.equal(await evaluate("document.activeElement===document.querySelector('#advanced-navigation > summary')"),true,'Choosing a hidden menu item must return focus to summary');
    }
    await enter();await until("document.querySelector('#advanced-navigation').open",'Enter did not reopen Advanced');
    await key('Tab','Tab',{windowsVirtualKeyCode:9});
    assert.equal(await evaluate('document.activeElement.dataset.screen'),'backtrace','Tab must enter the chooser');
    await key('Escape','Escape',{windowsVirtualKeyCode:27});await closed('Escape from chooser');
    assert.equal(await evaluate("document.activeElement===document.querySelector('#advanced-navigation > summary')"),true);
    for(let repeat=0;repeat<2;repeat++) {
      await enter();await until("document.querySelector('#advanced-navigation').open",'Keyboard could not reopen Advanced');
      await key('Tab','Tab',{windowsVirtualKeyCode:9});await enter();
      await arrived('backtrace',`Keyboard choice ${repeat+1} at ${size[0]}`);
      assert.equal(await evaluate("document.activeElement===document.querySelector('#advanced-navigation > summary')"),true);
    }
    await screenshot(`investigation-keyboard-choice-${size[0]}`);
    await click('#advanced-navigation > summary');
    await click('.nav-button[data-screen="sources"]');await arrived('sources',`Primary choice at ${size[0]}`);
    assert.equal(await evaluate('document.activeElement.dataset.screen'),'sources','Primary choice must keep its own focus');
  }
  // Rebuild a real short-label return trail. With Back to Requests + Forward,
  // the old flex layout squeezed the open notice into a 150px right column.
  await viewport(360,740);
  const requestSetupReceipt=()=>evaluate("(()=>{const box=n=>{const r=n.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height,scrollTop:n.scrollTop,clientHeight:n.clientHeight,scrollHeight:n.scrollHeight};};return {screen:investigationScreen(),selected:state.selectedRequestId,notice:state.trafficSelectionNotice,detailOpen:state.trafficDetailOpen,refreshing:state.refreshing,requests:state.requests.map(r=>({id:r.id,identity:investigationRequestIdentity(r)})),pane:box(document.querySelector('#screen-traffic .request-pane')),list:box(elements.requestRows),rows:[...elements.requestRows.querySelectorAll('.request-row')].map(n=>{const r=n.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return {id:n.dataset.requestId,...box(n),ownsPoint:!!hit&&n.contains(hit),hit:hit?.id||hit?.tagName};})};})()");
  const requestSetup={before:await requestSetupReceipt()};
  // The previous refusal intentionally retired the selected session. Refresh a
  // new retained identity through the fixture route before constructing this trail.
  await until('!state.refreshing','Prior event refresh did not finish before phone setup');
  fixture.session='14';await evaluate('refresh()');
  await until("!state.refreshing&&state.events[0]?.session_id==='14'&&state.requests.length===1&&investigationRequestIdentity(state.requests[0])?.session==='14'",'Fresh phone request was not admitted through the broker fixture');
  if(!await evaluate("document.querySelector('#investigation-navigation details').open"))await click('#investigation-navigation summary');
  await click('#investigation-clear');
  await click('.nav-button[data-screen="traffic"]');await arrived('traffic','Prepare short-label request return');
  requestSetup.retained=await requestSetupReceipt();
  console.log('Investigation phone request setup before close',JSON.stringify(requestSetup));
  if(await evaluate('state.trafficDetailOpen'))await click('#request-detail-close');
  await until('!state.trafficDetailOpen','Obsolete request inspector did not close through its control');
  requestSetup.closed=await requestSetupReceipt();
  console.log('Investigation phone request setup after close',JSON.stringify(requestSetup.closed));
  const phoneRequestSelector=await evaluate("'#request-rows .request-row[data-request-id=\"'+CSS.escape(state.requests[0].id)+'\"]'");
  await until(`(()=>{const n=document.querySelector(${JSON.stringify(phoneRequestSelector)}),request=state.requests.find(r=>r.id===n?.dataset.requestId);if(!n||investigationRequestIdentity(request)?.session!=='14')return false;const r=n.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return r.width>0&&r.height>0&&r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight&&!!hit&&n.contains(hit);})()`,'Fresh retained phone row did not become visible and hit-testable after closing the obsolete inspector');
  requestSetup.ready=await requestSetupReceipt();
  console.log('Investigation phone request setup ready',JSON.stringify(requestSetup.ready));
  await click(phoneRequestSelector);
  await until("investigationRequestIdentity(state.requests.find(r=>r.id===state.selectedRequestId))?.session==='14'",'The native row click did not select the fresh exact request');
  requestSetup.selected=await requestSetupReceipt();
  console.log('Investigation phone request selected',JSON.stringify(requestSetup.selected));
  await click('.nav-button[data-screen="sources"]');await arrived('sources','Prepare short-label source destination');
  assert.equal(await evaluate("document.querySelector('#investigation-back').textContent"),'Back to Requests');
  assert.equal(await evaluate("document.querySelector('#investigation-forward').textContent"),'Forward');
  fixture.session='13';await evaluate('refresh()');await until("state.events[0]?.session_id==='13'",'Short-label session replacement did not load');
  const retainedView=()=>evaluate("({screen:investigationScreen(),request:state.selectedRequestId,artifact:state.selectedArtifactId,decoder:toolsElements.input.value,steps:state.decoderSteps.length,history:document.querySelector('#investigation-history-count').textContent})");
  const beforePhoneReturn=await retainedView();
  await click('#investigation-back');
  await until("document.querySelector('#investigation-navigation details').open&&document.querySelector('#investigation-notice').textContent.includes('Return unavailable:')",'Short-label stale return did not expose its warning');
  assert.deepEqual(await retainedView(),beforePhoneReturn,'Unavailable phone Back must preserve the workspace, selected evidence, draft and history position');
  await closed('Short-label unavailable phone return');
  const phoneContext=await evaluate("(()=>{const box=selector=>{const n=document.querySelector(selector),r=n.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height};};const bar=document.querySelector('#investigation-navigation');return {bar:box('#investigation-navigation'),controls:box('.investigation-controls'),details:box('#investigation-navigation details'),back:box('#investigation-back'),forward:box('#investigation-forward'),notice:box('#investigation-notice'),clear:box('#investigation-clear'),text:document.querySelector('#investigation-notice').textContent,overflow:getComputedStyle(bar).overflowY};})()");
  assert(phoneContext.details.left<=phoneContext.controls.left+1&&phoneContext.details.right>=phoneContext.controls.right-1&&phoneContext.details.top>=Math.max(phoneContext.back.bottom,phoneContext.forward.bottom),'Open phone context must use the full row below short Back/Forward labels');
  assert.match(phoneContext.text,/Return unavailable:.*Nothing was fetched or recaptured/);
  for(const item of [phoneContext.back,phoneContext.forward,phoneContext.notice,phoneContext.clear])assert(item.width>0&&item.height>0&&item.left>=phoneContext.bar.left&&item.right<=phoneContext.bar.right&&item.top>=phoneContext.bar.top&&item.bottom<=phoneContext.bar.bottom,'Phone warning and navigation controls must be visible inside their bar');
  assert(phoneContext.bar.height<=740*.35+1&&phoneContext.overflow==='auto','Phone navigation must remain a bounded independent scroller');
  await screenshot('investigation-short-label-unavailable-360');
  // A longer fixture explanation exercises the same production notice renderer,
  // then actual wheel input proves that only its navigation scroller moves.
  await evaluate("window.shortLinkContext=document.querySelector('#investigation-notice').textContent;investigationNotice(Array(12).fill(shortLinkContext).join(' '),'unavailable')");
  const scrollOwners=()=>evaluate("({page:document.scrollingElement.scrollTop,source:elements.sourceCodeWrap.scrollTop,details:document.querySelector('#source-sidebar .debug-panes').scrollTop})");
  const beforeContextScroll=await scrollOwners();
  const longContext=await evaluate("(()=>{const n=document.querySelector('#investigation-navigation');return {height:n.getBoundingClientRect().height,client:n.clientHeight,scroll:n.scrollHeight,top:n.scrollTop};})()");
  assert(longContext.height<=740*.35+1&&longContext.scroll>longContext.client,'Long phone context must overflow only its bounded navigation pane');
  await wheel('#investigation-navigation',longContext.scroll,true);
  assert(await evaluate("document.querySelector('#investigation-navigation').scrollTop>0"),'Actual wheel input must scroll the long context');
  assert.deepEqual(await scrollOwners(),beforeContextScroll,'Navigation scrolling must not move Sources or the page');
  assert(await evaluate("(()=>{const n=document.querySelector('#investigation-clear').getBoundingClientRect(),b=document.querySelector('#investigation-navigation').getBoundingClientRect();return n.top>=b.top&&n.bottom<=b.bottom;})()"),'History control must remain reachable at the end of long context');
  await screenshot('investigation-long-context-scroll-360');
  await evaluate("investigationNotice(shortLinkContext,'unavailable')");
  assert.deepEqual(await retainedView(),beforePhoneReturn,'Context reading must not navigate, replace drafts or change selected evidence');
  console.log('Investigation phone context geometry',JSON.stringify({normal:phoneContext,long:longContext}));
  assert.equal(fixture.calls.filter(call=>call.method!=='GET').length,0,'Investigation navigation issued an action request');
  return {status:'passed',path:'existing browser development driver',phoneContext,requestSetup,source:'original synthetic request + immutable UTF-8/BOM artifact + explicit synthetic trace/facts delivery',viewports:[[1440,900],[760,560],[360,740]],checks:['Advanced dismissed at every linked pivot and Back/Forward without hidden menu focus','manual pointer choices, Enter/Tab/Escape and repeated selection at all three widths','refused return preserves an explicitly open chooser','request → trace → exact session artifact → verified original UTF-8 range → Decoder evidence → Back','no derived-analysis request or automatic transform/send/capture/action','real Open original evidence click','native decline/confirm replacement dialogs preserve newer drafts','preserved request/trace/source selection, Decoder draft and trigger focus','keyboard Back/Forward','missing and ambiguous source','foreign-session trace rejection','interrupted trace delivery','Console URL search does not navigate','session-change stale return','bounded narrow controls']};
}

// These regressions exercise the production navigation and selection functions,
// including the independently reproduced same-workspace and retained-root races.
async function checkInvestigationReturns(root) {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const nav=await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
  const section=(a,b)=>app.slice(app.indexOf(a),app.indexOf(b));
  const selection=section('      function selectRequest(', '      function moveRequestSelection(');
  const artifactSelection=section('      function sourceArtifactIdentityMatches(', '      function selectScript(');
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
    const state={requests,artifacts,selectedRequestId:'request-2',selectedArtifactId:'7',selectedScriptId:null,selectedRuntimeHookRequest:null,originTrace:{steps:[]},originTraceGeneration:0,signalProfileGeneration:0,decoderSteps:[],openArtifactIds:[],inspectorTab:'evidence',fieldTab:'body',sourceFormatted:false,sourceDeobfuscated:false,sourceWasm:false};
    const globals={state,CSS:{escape:s=>s},Promise,URLSearchParams,AbortController,TextDecoder,setTimeout,clearTimeout,location:{protocol:'http:'},
      sourceFactsReadBytes:async response=>new TextEncoder().encode(JSON.stringify(await response.json())),
      document:{activeElement:trigger,querySelector:s=>s==='.screen:not([hidden])'?{id:`screen-${screen}`}:s==='#investigation-notice'?notice:s==='#investigation-navigation'?panel:s==='#investigation-back'?back:s.startsWith('#screen-')?rootNode:s==='#console-experiment-traffic'?consolePanel:null},
      requestAnimationFrame:fn=>raf.push(fn),integerText:(e,k)=>String(e[k]),sourceFactsPanel:{navigate:()=>null,cancel:()=>{cancelled++;}},
      selectedSource:()=>state.artifacts.find(a=>a.artifact_id===state.selectedArtifactId),liveSources:()=>[],runtimeHooksState:()=>null,
      renderInspector(){},renderRequests(){},renderEvidence(){},renderBacktrace(){},refreshRequestSignalProfile(){},updateSelectionSummary(){},renderRuntimeHookTraffic(){},
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
  {
    const t=setup();t.context.selectedSource=()=>({source_type:'script',script_id:'live-1',target_id:'target-1',hash:'x'.repeat(2*1024*1024)});
    const saved=t.run('investigationSnapshot()');assert.equal(saved.script.unavailable,true);assert.equal(Object.hasOwn(saved.script,'owner'),false);
    assert(JSON.stringify(saved).length<8192,'An oversized live owner must never be copied into history');
    t.context.entry=saved;assert.equal(t.run('restoreInvestigation(entry)'),false);assert.match(t.notice.textContent,/bounded navigation metadata/);
    assert.deepEqual(t.sourceReads,[],'Unavailable ownership must not degrade to a generic Sources return');
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
    const state={requests:[request],selectedRequestId:'native',selectedRuntimeHookRequest:null,inspectorTab:'evidence',fieldTab:'body',originTraceStatus:'ready',decoderSteps:[]};
    const noop=()=>{};
    document.querySelector=s=>s==='.screen:not([hidden])'?screens.find(screen=>!screen.hidden):s==='#advanced-navigation'?navigation:s==='#investigation-back'?back:s==='#investigation-notice'?notice:s==='#investigation-navigation'?bar:s==='#console-experiment-traffic'?consolePanel:screens.find(screen=>'#'+screen.id===s)??null;
    document.querySelectorAll=s=>s==='.screen'?screens:[];
    const context=createContext({document,state,CSS:{escape:s=>s},Promise,requestAnimationFrame:fn=>frames.push(fn),integerText:(e,k)=>String(e[k]),
      selectedSource:()=>null,sourceFactsPanel:{cancel:noop},float32Panel:{cancel:noop},evidenceWorkspace:{setVisible:noop},retireCanvasPreviews:noop,
      renderInspector:noop,renderRuntimeHookTraffic:noop,fieldSets:{body:[]},elements:{requestRows:{querySelectorAll:()=>[row]},requestFilter:row}});
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
