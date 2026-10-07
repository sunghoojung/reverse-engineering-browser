import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

// Authored local HTTP documents only. Reuse the Sources fixture's immutable and
// live readers; never substitute a product loader, cache, renderer or history.
export async function sourcesHistoryFixture(base) {
  const longText=Array.from({length:180},(_,i)=>`// history row ${i}: ${'inert text '.repeat(24)}`).join('\n');
  const target=await base.addSource('100',longText);
  const live=base.addLiveSource('history-live',longText);
  // Small metadata/document rows make the navigator genuinely scrollable at
  // both widths without megabyte fixtures or lowered production retention caps.
  for(let i=0;i<42;i++)base.addLiveSource(`history-nav-${String(i).padStart(2,'0')}`,`// navigator ${i}`);
  for(let i=0;i<42;i++)await base.addSource(String(1000+i),`// captured navigator ${i}`);
  const moduleBytes=Buffer.from([0,97,115,109,1,0,0,0]);
  assert(WebAssembly.validate(moduleBytes),'Authored module must be valid, never instantiated');
  const addWasm=async id=>{
    const source=await base.addSource(id,moduleBytes);
    Object.assign(source,{kind:'wasm',capture_origin:'webassembly_compile',mime_type:'application/wasm',url:`https://fixture.invalid/module-${id}.wasm`});
    return source;
  };
  const wasm=await addWasm('101');
  const report=source=>({schema:'wasm-inspection-v1',artifact_id:source.artifact_id,sha256:source.sha256,byte_size:source.byte_size,
    status:'decoded',sections:0,defined_functions:0,imported_functions:0,instructions:0,notice:'Static inspection of an authored empty module. Never executed.',omissions:[],rows:[]});
  const fixture={...base,target,live,wasm,longText,moduleBytes,report,addWasm,reads:[],gates:new Map(),catalogReads:0,nextId:200};
  fixture.hold=key=>{
    assert(!fixture.gates.has(key),'A route already has a pending hold');
    let release;const promise=new Promise(resolve=>{release=resolve;});
    const gate={promise,release,outcome:'ready',arrivals:0};fixture.gates.set(key,gate);return gate;
  };
  fixture.releaseRoute=(key,outcome='ready')=>{
    const gate=fixture.gates.get(key);assert(gate,'No held route to release');
    gate.outcome=outcome;fixture.gates.delete(key);gate.release();
  };
  fixture.handle=async(request,response)=>{
    const url=new URL(request.url,'http://127.0.0.1');
    if(url.pathname==='/api/artifacts')fixture.catalogReads++;
    const id=/^\/api\/artifacts\/([0-9]+)\/content$/.exec(url.pathname)?.[1];
    const key=id?`artifact:${id}`:url.pathname==='/api/debugger/source'?`live:${url.searchParams.get('script_id')}`
      :url.pathname==='/api/wasm'?`wasm:${url.searchParams.get('artifact_id')}`:null;
    if(!key)return base.handle(request,response);
    const entry={id:fixture.reads.length+1,key,method:request.method??'GET',status:'pending'};fixture.reads.push(entry);
    const gate=fixture.gates.get(key);
    if(gate){gate.arrivals++;await gate.promise;}
    const json=(status,value)=>{if(!response.destroyed){response.writeHead(status,{'Content-Type':'application/json'});response.end(JSON.stringify(value));}};
    if(gate?.outcome==='error'){
      entry.status='error';json(503,{error:`Authored ${key} reopen failure`});return true;
    }
    if(key.startsWith('wasm:')){
      const source=base.artifacts.find(value=>value.artifact_id===url.searchParams.get('artifact_id')&&value.kind==='wasm');
      entry.status=source?'ready':'missing';json(source?200:404,source?report(source):{error:'Authored module unavailable'});return true;
    }
    const handled=await base.handle(request,response);entry.status=handled?'ready':'missing';return handled;
  };
  fixture.release=()=>{for(const key of [...fixture.gates.keys()])fixture.releaseRoute(key);base.release();};
  return fixture;
}

export async function checkSourcesHistoryFixture(base,root) {
  const fixture=await sourcesHistoryFixture(base);
  const model=runInNewContext((await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8'))+';({isArtifactResponse,isDebuggerResponse,isWasmInspection})',{TextEncoder});
  const request=async url=>{
    const response={destroyed:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(body){this.body=body;}};
    assert(await fixture.handle({url,method:'GET'},response));return response;
  };
  assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)));
  assert(model.isDebuggerResponse(JSON.parse((await request('/api/debugger')).body)));
  assert(model.isWasmInspection(JSON.parse((await request('/api/wasm?artifact_id=101')).body),fixture.wasm));
  assert.deepEqual((await request('/api/artifacts/101/content')).body,fixture.moduleBytes);
  for(const [key,url,expected] of [
    ['artifact:100','/api/artifacts/100/content',fixture.longText],
    ['live:history-live','/api/debugger/source?script_id=history-live',fixture.longText],
    ['wasm:101','/api/wasm?artifact_id=101',null],
  ]) {
    const gate=fixture.hold(key);let completed=false;
    const held=request(url).then(value=>{completed=true;return value;});
    assert.equal(gate.arrivals,1);assert.equal(completed,false,'Held response escaped before explicit release');
    fixture.releaseRoute(key);const response=await held;assert.equal(response.status,200);
    if(expected)assert.equal(key.startsWith('live')?JSON.parse(response.body).source:response.body.toString('utf8'),expected);
    fixture.hold(key);const failed=request(url);fixture.releaseRoute(key,'error');assert.equal((await failed).status,503);
  }
  assert(fixture.reads.every(value=>value.status!=='pending'));
  assert(fixture.artifacts.reduce((sum,value)=>sum+value.byte_size,0)<64*1024,'Fixture payloads must remain small');
  assert.equal(fixture.rejectedWrites.length,0);
  console.log('PASS Sources-history HTTP fixture: small authored source/live/module admission, valid never-executed WASM, held replies and explicit failures (not rendered QA)');
}

export async function checkSourcesHistoryInteractions({evaluate,viewport,click:nativeClick,key:nativeKey,wheel,screenshot,fixture,operationObserver,waitForSettlement,record=()=>{}}) {
  const receipts=[],inputs=[];
  // These receipts wrap, rather than replace, the existing strict CDP helpers.
  // The driver still owns hit testing and actual native pointer/key dispatch.
  const input=value=>{inputs.push(value);assert(inputs.length<=2048,'Input receipt bound exceeded');};
  const click=async selector=>{await nativeClick(selector);input({type:'pointer',selector,focus:await evaluate('document.activeElement.id')});};
  const key=async(value,code,native)=>{await nativeKey(value,code,native);input({type:'key',key:value,code,modifiers:native?.modifiers??0,focus:await evaluate('document.activeElement.id')});};
  const receipt=(label,value)=>{const item={label,...value};receipts.push(item);record(item);};
  const until=async(predicate,label)=>{
    const deadline=Date.now()+7000;
    do {if(await (typeof predicate==='string'?evaluate(predicate):predicate()))return;await new Promise(resolve=>setTimeout(resolve,25));}while(Date.now()<deadline);
    assert.fail(label);
  };
  const frames=()=>evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
  const press=(value,modifiers=0)=>key(value,value,{windowsVirtualKeyCode:({ArrowRight:39,ArrowLeft:37,Tab:9,Enter:13})[value],modifiers,
    ...(value==='Enter'?{text:'\r',unmodifiedText:'\r'}:{})});
  const screen=async name=>{await until(`investigationScreen()===${JSON.stringify(name)}&&!investigationPendingReturn`,'Navigation did not settle: '+name);await frames();};
  const read=()=>evaluate(`({top:elements.sourceCodeWrap.scrollTop,left:elements.sourceCodeWrap.scrollLeft,tree:elements.sourceTree.scrollTop,focus:document.activeElement.id,screen:investigationScreen()})`);
  const count=route=>fixture.reads.filter(entry=>entry.key===route).length;
  const sourceExpr=kind=>kind==='live'?"liveSources().find(source=>source.script_id==='history-live')":"state.artifacts.find(source=>source.artifact_id==='100')";
  const targetReady=kind=>kind==='live'?"state.selectedScriptId==='history-live'":"state.selectedArtifactId==='100'&&state.selectedScriptId===null";
  const treeClick=async selector=>{
    // Reveal only in its real bounded navigator; no scrollIntoView, direct
    // scroll assignment, retry after a bad hit, or hidden ancestor movement.
    const delta=await evaluate(`(()=>{const node=document.querySelector(${JSON.stringify(selector)}),pane=elements.sourceTree;if(!node)throw Error('Missing history source');const r=node.getBoundingClientRect(),b=pane.getBoundingClientRect();return r.top<b.top+3?r.top-b.top-3:r.bottom>b.bottom-3?r.bottom-b.bottom+3:0;})()`);
    if(delta)await wheel('#source-tree',delta);
    await click(selector);
  };
  const open=async kind=>{
    if(await evaluate("investigationScreen()!=='sources'")){await click('.nav-button[data-screen="sources"]');await screen('sources');}
    await click(kind==='live'?'#source-tab-page':'#source-tab-captured');
    await treeClick(kind==='live'?'#source-tree [data-script-id="history-live"]':'#source-tree [data-artifact-id="100"]');
    await until(`${targetReady(kind)}&&selectedSource().content!==undefined&&!selectedSource().loading`,'Target preview failed to open');
  };
  const recordEntry=async(scroll=true)=>{
    // A pointer workspace switch initially loses editor focus. Back, then the
    // native Alt+Right shortcut from the editor, records its real focused state.
    await click('.nav-button[data-screen="traffic"]');await screen('traffic');
    await click('#investigation-back');await screen('sources');
    if(scroll){await wheel('#source-tree',240);await click('#source-code-wrap');await wheel('#source-code-wrap',600);
      for(let i=0;i<5;i++)await press('ArrowRight');
      await until('elements.sourceCodeWrap.scrollLeft>0','Native arrow input did not horizontally scroll the editor');
      // Wait on the actual scrolling animation, not an arbitrary delay.
      await evaluate(`new Promise((resolve,reject)=>{let prior='',stable=0;const start=performance.now();function frame(){if(performance.now()-start>5000){reject(Error('Editor native scrolling did not settle'));return;}const now=elements.sourceCodeWrap.scrollTop+':'+elements.sourceCodeWrap.scrollLeft;stable=now===prior?stable+1:0;prior=now;if(stable>=5)resolve();else requestAnimationFrame(frame);}requestAnimationFrame(frame);})`);
    }else await click('#source-code-wrap');
    const saved=await read();assert.equal(saved.focus,'source-code-wrap');
    if(scroll){assert(saved.top>0&&saved.left>0&&saved.tree>0,'Saved entry must have real nonzero editor and navigator scrolling');}
    const snapshot=await evaluate('investigationSnapshot()');assert.equal(snapshot.focus,'#source-code-wrap');
    await press('ArrowRight',1);await screen('traffic');
    await click('.nav-button[data-screen="sources"]');await screen('sources');
    return saved;
  };
  const pressure=async(wasm=false)=>{
    const ids=[];
    for(let i=0;i<(wasm?4:8);i++){
      const id=String(fixture.nextId++);ids.push(id);
      if(wasm)await fixture.addWasm(id);else await fixture.addSource(id,`// cache pressure ${id}`);
    }
    await evaluate('refreshArtifacts()');
    await until(`state.artifacts.some(value=>value.artifact_id===${JSON.stringify(ids.at(-1))})`,'Pressure catalog was not admitted');
    await click('#source-tab-captured');
    for(const id of ids){
      await treeClick(`#source-tree [data-artifact-id="${id}"]`);
      await until(`state.selectedArtifactId==='${id}'&&selectedSource().content!==undefined&&!selectedSource().loading`,'Pressure preview did not load');
      if(wasm){await click('#source-wasm');await until(`state.wasmCache.has(wasmKey(selectedSource()))&&!selectedSource().loading`,'Explicit pressure inspection did not finish');}
    }
    assert(await evaluate('state.artifacts.filter(value=>value.kind!==\'canvas_data_url\'&&value.content!==undefined).length+state.liveScriptContent.size<=8'),'Production preview bound was exceeded');
    await click('#investigation-back');await screen('traffic');
    return ids;
  };
  const installObserver=async()=>{
    await evaluate(`(()=>{const original={artifact:loadArtifactContent,live:loadScriptContent,wasm:loadWasmInspection};const observer=(${operationObserver.toString()})(original,sourceIdentity);globalThis.__historyQA={...observer,restore(){loadArtifactContent=original.artifact;loadScriptContent=original.live;loadWasmInspection=original.wasm;delete globalThis.__historyQA;}};loadArtifactContent=observer.wrappers.artifact;loadScriptContent=observer.wrappers.live;loadWasmInspection=observer.wrappers.wasm;})()`);
  };
  const pendingOperation=async(kind,identity)=>{
    await until(`__historyQA.pending(${JSON.stringify(kind)},${JSON.stringify(identity)}).length>0`,'Real loader did not expose its held receipt');
    const values=await evaluate(`__historyQA.pending(${JSON.stringify(kind)},${JSON.stringify(identity)})`);
    // Selection can call a guarded loader more than once. Only the operation
    // still awaiting this HTTP reply owns the real pending body/renderer.
    assert.equal(values.length,1,'Held response must have one pending loader owner');return values[0];
  };
  const settle=async operation=>{
    const terminal=await waitForSettlement(id=>evaluate(`__historyQA.read(${id})`),operation,7000);
    assert.equal(terminal.status,'fulfilled','Product loader escaped its own error handling');await frames();return terminal;
  };
  await until("state.artifacts.some(value=>value.artifact_id==='100')&&state.debuggerSession?.scripts.some(value=>value.script_id==='history-live')",'History fixture catalog did not load');
  await installObserver();
  try {
    for(const size of [[1440,900],[760,560]]){
      await viewport(...size);
      // The attached Debugger becomes an intentional overlay at narrow widths.
      // Dismiss it through its visible control before recording editor input;
      // keep the shared pointer helper's strict visibility/hit checks intact.
      if(await evaluate("getComputedStyle(elements.sourceSidebar).position==='absolute'&&!elements.sourceSidebar.hidden")){
        await click('#source-sidebar-toggle');
        await until('elements.sourceSidebar.hidden','Narrow Debugger overlay did not close');
        await frames();
      }
      for(const kind of ['artifact','live']){
        const route=kind==='live'?'live:history-live':'artifact:100';
        for(const scenario of ['restore','repeat','interaction','forward','failure']){
          await open(kind);const identity=await evaluate(`sourceIdentity(${sourceExpr(kind)})`),saved=await recordEntry();
          const pressureIds=await pressure();
          assert(await evaluate(`(${sourceExpr(kind)})?.content===undefined`),'Production pressure did not evict the saved preview');
          assert.equal(await evaluate(`sourceIdentity(${sourceExpr(kind)})`),identity,'Eviction changed the retained exact descriptor');
          const before=count(route),gate=fixture.hold(route);
          await click('#investigation-back');
          await until(()=>gate.arrivals===1,'Actual Back did not reach the held reopen route');
          const operation=await pendingOperation(kind,identity);
          await until('investigationPendingReturn?.ready&&selectedSource()?.loading','Back did not retain a ready pending return during loading');
          assert.match(await evaluate('elements.sourceCodeEmpty.textContent'),/Loading (immutable artifact bytes|live script source)/);
          assert.equal(await evaluate('elements.sourceCode.hidden'),true);
          await screenshot(`sources-history-${size[0]}-${kind}-${scenario}-held`);
          let newer;
          if(scenario==='interaction'){
            await wheel('#source-tree',120);await click('#source-code-wrap');await press('Tab',8);
            await until('investigationPendingReturn===null','Newer wheel/key input failed to cancel delayed return');
            newer=await read();assert.notEqual(newer.focus,saved.focus,'New keyboard focus must differ from the saved focus');
          }else if(scenario==='forward'){
            await click('#investigation-forward');await screen('traffic');await click('#request-filter');
            newer=await read();assert.equal(newer.screen,'traffic');assert.equal(newer.focus,'request-filter');
          }
          fixture.releaseRoute(route,scenario==='failure'?'error':'ready');const terminal=await settle(operation);
          assert.equal(count(route),before+1,'Back must perform exactly one immutable/live reopen');
          if(newer){assert.deepEqual(await read(),newer,'Late completion reclaimed a newer reading position or focus');}
          else if(scenario==='failure'){
            await screen('sources');
            assert.match(await evaluate('elements.sourceCodeEmpty.textContent'),/unavailable/);
            const fallback=await evaluate("({id:document.activeElement.id,enabled:!document.activeElement.disabled,visible:document.activeElement.getClientRects().length>0})");
            assert(fallback.enabled&&fallback.visible,'Failed reopen needs enabled visible fallback focus');
            await screenshot(`sources-history-${size[0]}-${kind}-failed`);
            const retry='#source-code-empty button';await click(retry);
            await until(`${targetReady(kind)}&&selectedSource().content!==undefined&&!selectedSource().loading`,'Explicit Retry source did not recover');
            assert.equal(count(route),before+2,'Only explicit Retry may issue the second read');
          }else{
            await screen('sources');assert.deepEqual(await read(),saved,'Owned render did not restore the saved reading/focus state');
            await click('#investigation-forward');await screen('traffic');
            await click('#investigation-back');await screen('sources');
            assert.equal(count(route),before+1,'Retained subsequent Back must not reread the preview');
          }
          receipt(`${size[0]}-${kind}-${scenario}`,{viewport:size,identity,pressureIds,saved,newer,nativeInputs:inputs.length,operation:terminal,reads:count(route)-before,after:await read()});
          await screenshot(`sources-history-${size[0]}-${kind}-${scenario}-settled`);
        }
      }
      // Four other explicit inspections evict the first report through the real
      // bounded cache. History and a changed catalog must remain passive.
      for(const outcome of ['ready','error']){
        if(await evaluate("investigationScreen()!=='sources'")){await click('.nav-button[data-screen="sources"]');await screen('sources');}
        await click('#source-tab-captured');await treeClick('#source-tree [data-artifact-id="101"]');
        await until("state.selectedArtifactId==='101'&&selectedSource().content!==undefined&&!selectedSource().loading",'WASM source did not open');
        await click('#source-wasm');await until('state.wasmCache.has(wasmKey(selectedSource()))','Initial explicit inspection failed');
        const saved=await recordEntry(false),pressureIds=await pressure(true),before=count('wasm:101');
        assert.equal(await evaluate("state.wasmCache.has(wasmKey(state.artifacts.find(value=>value.artifact_id==='101')))"),false,'Production report pressure did not evict the saved report');
        await click('#investigation-back');await screen('sources');
        const retry='#source-code-empty .wasm-inspection-error button';
        assert.match(await evaluate('elements.sourceViewKind.textContent'),/Inspection preview released/);
        assert.match(await evaluate('elements.sourceCodeEmpty.textContent'),/released.*bounded/);
        assert.equal(await evaluate(`document.querySelector(${JSON.stringify(retry)}).disabled`),false);
        assert.equal(count('wasm:101'),before,'Back must never automatically inspect an evicted report');
        const retryGeometry=await evaluate(`(()=>{const node=document.querySelector(${JSON.stringify(retry)}),r=node.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2);return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height,hit:node.contains(hit),enabled:!node.disabled,viewport:[innerWidth,innerHeight]};})()`);
        assert(retryGeometry.enabled&&retryGeometry.hit&&retryGeometry.width>0&&retryGeometry.height>0&&retryGeometry.left>=0&&retryGeometry.top>=0&&retryGeometry.right<=size[0]&&retryGeometry.bottom<=size[1],'Released Retry must be fully visible and hit-testable');
        await click('#investigation-forward');await screen('traffic');
        await click('#investigation-back');await screen('sources');
        assert.equal(count('wasm:101'),before,'Forward and another Back must remain passive');
        assert.match(await evaluate('elements.sourceViewKind.textContent'),/Inspection preview released/);
        const arrival=String(fixture.nextId++);await fixture.addSource(arrival,'// changed catalog after passive return');
        const catalogs=fixture.catalogReads;await evaluate('refreshArtifacts()');
        await until(`state.artifacts.some(value=>value.artifact_id==='${arrival}')`,'Changed passive catalog was not admitted');
        assert(fixture.catalogReads>catalogs);
        await frames();assert.equal(count('wasm:101'),before,'Changed catalog refresh must remain passive');
        await screenshot(`sources-history-${size[0]}-wasm-${outcome}-released`);
        const gate=fixture.hold('wasm:101'),identity=await evaluate('sourceIdentity(selectedSource())');
        // Tab from the focused editor reaches the enabled Retry in the empty
        // panel. Native Enter is the one explicit analysis authorization.
        await click('#source-code-wrap');await press('Tab');
        assert.equal(await evaluate(`document.activeElement===document.querySelector(${JSON.stringify(retry)})`),true,'Retry inspection must be keyboard reachable');
        await press('Enter');await until(()=>gate.arrivals===1,'Explicit keyboard Retry did not reach inspector');
        const operation=await pendingOperation('wasm',identity);
        assert.match(await evaluate('elements.sourceViewKind.textContent'),/Inspection pending/);
        assert.equal(await evaluate(`Boolean(document.querySelector(${JSON.stringify(retry)}))`),false,'Pending analysis must not expose a second Retry');
        await screenshot(`sources-history-${size[0]}-wasm-${outcome}-pending`);
        // Returning while that same explicit operation is held must wait for
        // its terminal render, with no duplicate analysis on Back.
        await click('.nav-button[data-screen="traffic"]');await screen('traffic');
        await click('#investigation-back');
        await until("investigationPendingReturn?.ready&&state.wasmRequests.get(wasmKey(selectedSource()))?.status==='loading'",'Back did not wait for the existing inspection');
        assert.equal(count('wasm:101'),before+1,'Back while inspecting must reuse the existing analysis');
        fixture.releaseRoute('wasm:101',outcome);const terminal=await settle(operation);
        await screen('sources');
        const fallback=await evaluate('({id:document.activeElement.id,enabled:!document.activeElement.disabled,visible:document.activeElement.getClientRects().length>0})');
        assert(fallback.enabled&&fallback.visible&&['investigation-back','investigation-forward'].includes(fallback.id),'Inspection terminal return must choose an enabled visible history fallback');
        assert.equal(count('wasm:101'),before+1,'Explicit Retry must issue exactly one inspection');
        if(outcome==='error'){
          assert.match(await evaluate('elements.sourceViewKind.textContent'),/Inspection failed/);
          assert.match(await evaluate('elements.sourceCodeEmpty.textContent'),/Authored wasm:101 reopen failure/);
          assert.equal(await evaluate(`document.querySelector(${JSON.stringify(retry)}).disabled`),false);
          await screenshot(`sources-history-${size[0]}-wasm-error`);
          await click(retry);await until('state.wasmCache.has(wasmKey(selectedSource()))','Explicit error Retry failed');
          assert.equal(count('wasm:101'),before+2,'Error recovery must perform exactly one additional explicit inspection');
        }
        assert.match(await evaluate('elements.sourceCode.textContent'),/Static inspection.*never executed/);
        assert.equal(await evaluate('isWasmInspection(state.wasmCache.get(wasmKey(selectedSource())),selectedSource())'),true);
        assert.equal(await evaluate('elements.sourceCode.hidden'),false);
        receipt(`${size[0]}-wasm-${outcome}`,{viewport:size,saved,pressureIds,retryGeometry,fallback,operation:terminal,reads:count('wasm:101')-before,catalogs:fixture.catalogReads,after:await read()});
        await screenshot(`sources-history-${size[0]}-wasm-${outcome}-report`);
      }
      assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),'History scenarios overflowed the viewport');
    }
    assert.equal(fixture.rejectedWrites.length,0,'Sources history must never execute debugger mutations');
    assert(fixture.reads.every(entry=>entry.method==='GET'),'History tests must remain read-only');
    assert.equal(await evaluate('__historyQA.failures().pending'),0,'A real source loader was left unsettled');
    return {status:'passed',path:'existing installed-Chrome driver; real native input and production cache/loader/renderer/history',viewports:[[1440,900],[760,560]],receipts,inputs,
      checks:['captured and live eviction/held Back/owned rendered scroll+focus restore','repeated eviction and retained Forward/Back','newer wheel/key and Forward exclude late restore','failed reopen and explicit source Retry','evicted WASM released state and passive changed-catalog refresh','native Enter Retry, pending, error and valid static report']};
  }finally{fixture.release();await evaluate('__historyQA.restore()');}
}
