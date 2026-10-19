// Real Chromium/native transport acceptance for the explicitly owned profile.
// Request rows and body availability are separate observations. Cross-site frame
// initial documents are measured honestly, never converted into a 100% claim.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {appendFileSync,writeFileSync} from 'node:fs';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {prepareCaptureDiagnosticTransport,readCaptureDiagnostics,captureFailureEvidence,captureFirstFixturePaths,createCaptureCaseStage} from './traffic-capture-diagnostics.mjs';
import {stopBrowserTestProcess} from './browser-test-process.mjs';

const script=fileURLToPath(import.meta.url),delay=ms=>new Promise(r=>setTimeout(r,ms));
const diagnosticEnum=(value,allowed)=>allowed.includes(value)?value:null;
const bodyState=row=>row?diagnosticEnum(row.response?.body?.state,['available','empty','missing','loading','error','disabled','unavailable']):'no-row';
if(process.argv[2]==='--browser-wrapper') {
  const directory=process.env.REB_CAPTURE_FIRST_BROWSER_FIXTURE;
  const args=process.argv.slice(3);
  writeFileSync(join(directory,'browser-args'),JSON.stringify(args));
  // Fixture-only settings permit script-created popups and force a cross-site
  // process boundary. No sandbox/security bypass is accepted or added.
  assert(!args.some(a=>a==='--no-sandbox'||a==='--disable-setuid-sandbox'));
  const browser=spawn(process.env.REB_CAPTURE_FIRST_REAL_BROWSER,[...args.slice(0,-1),'--disable-popup-blocking','--site-per-process','--disable-dev-shm-usage',args.at(-1)],{stdio:['ignore','ignore','pipe']});
  browser.stderr.on('data',chunk=>appendFileSync(join(directory,'browser-diagnostics'),chunk));
  browser.on('error',error=>{appendFileSync(join(directory,'browser-diagnostics'),error.message);process.exitCode=1;});
  browser.on('exit',(code,signal)=>process.exit(code??(signal?1:0)));
} else {
  const root=resolve(process.argv[2]??'.');
  const browser=process.env.ORIGIN_TRACE_TEST_BROWSER||process.env.REB_UI_CHROMIUM||'chromium';
  const binary=resolve(process.env.ORIGIN_TRACE_BACKEND||join(root,'apps/origin-trace-backend/target/debug/origin-trace-backend'));
  const transport=resolve(process.env.ORIGIN_TRACE_DEBUGGER_TRANSPORT||join(root,'build/reb-debugger-transport'));
  const directory=await mkdtemp(join(tmpdir(),'reb-capture-first-browser-'));
  const served=new Set(),servedCounts=new Map(),servedTimes=new Map(),observedPaths=new Set(),pending=new Map(),caseFailures=[];let sequence=1,socket,backend,failure;
  const fixture=createServer((request,response)=>{
    const url=new URL(request.url,`http://${request.headers.host}`);served.add(url.pathname);servedCounts.set(url.pathname,(servedCounts.get(url.pathname)??0)+1);if(!servedTimes.has(url.pathname))servedTimes.set(url.pathname,Date.now());
    response.setHeader('Access-Control-Allow-Origin','*');response.setHeader('Cache-Control','no-store');
    const html=script=>`<title>Authored capture-first fixture</title><link rel="icon" href="data:,"><script>${script}</script>`;
    let body=`synthetic:${request.url}`,type='text/plain';
    if(url.pathname==='/owned-open') {type='text/html';body=html("fetch('/owned-open-inline').then(response=>response.text());");}
    if(url.pathname==='/initial') {type='text/html';body=html("window.initialResponse=fetch('/initial-inline');");}
    if(url.pathname.startsWith('/early-tab/')) {
      type='text/html';body=html(`fetch('/early-inline/${url.pathname.split('/').at(-1)}');`);
    }
    if(url.pathname==='/popup') {type='text/html';body=html("fetch('/popup-inline',{keepalive:true});window.close();");}
    if(url.pathname==='/contexts') {
      type='text/html';body=html(`
        new Worker('/dedicated.js');
        const frame=document.createElement('iframe');frame.src=location.origin.replace('127.0.0.1','localhost')+'/outer-frame';document.documentElement.append(frame);
      `);
    }
    if(url.pathname==='/outer-frame') {
      type='text/html';body=html("fetch('/outer-inline');const frame=document.createElement('iframe');frame.src='/inner-frame';document.documentElement.append(frame);");
    }
    if(url.pathname==='/inner-frame') {type='text/html';body=html("fetch('/inner-inline');new Worker('/frame-worker.js');");}
    const workers={'/dedicated.js':'/dedicated-inline','/nested-worker.js':'/nested-inline','/frame-worker.js':'/frame-worker-inline'};
    if(workers[url.pathname]) {
      type='text/javascript';body=`fetch('${workers[url.pathname]}');setInterval(()=>{},1000);`;
      if(url.pathname==='/dedicated.js')body+="new Worker('/nested-worker.js');";
    }
    response.setHeader('Content-Type',type);response.end(body);
  });
  await new Promise(r=>fixture.listen(0,'127.0.0.1',r));
  const origin=`http://127.0.0.1:${fixture.address().port}`;
  const until=async(read,label,timeout=15000)=>{
    const deadline=Date.now()+timeout;
    while(Date.now()<deadline) {
      assert(backend.child.exitCode===null&&backend.child.signalCode===null,`${label}: backend/browser exited`);
      try{const value=await read();if(value)return value;}catch(error){if(error instanceof assert.AssertionError)throw error;}
      await delay(40);
    }
    assert.fail(`${label} timed out`);
  };
  try {
    await writeFile(join(directory,'browser-diagnostics'),'');
    const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
    await writeFile(join(directory,'browser-wrapper'),`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(script)} --browser-wrapper "$@"\n`,{mode:0o700});
    const diagnosticTransport=await prepareCaptureDiagnosticTransport(directory,transport);
    const child=spawn(binary,['--port','0','--endpoint-file',join(directory,'endpoint'),'--capture-first-browser',join(directory,'browser-wrapper'),'--capture-first-headless','--debugger-transport',diagnosticTransport,'--capture-network-content'],{cwd:directory,env:{...process.env,REB_CAPTURE_FIRST_REAL_BROWSER:browser,REB_CAPTURE_FIRST_BROWSER_FIXTURE:directory}});
    const closed=new Promise(r=>{child.once('close',r);child.once('error',()=>r());});backend={child,closed};
    for(const pipe of [child.stdout,child.stderr])pipe.resume();
    const args=await until(async()=>JSON.parse(await readFile(join(directory,'browser-args'),'utf8')),'Owned browser launch');
    assert.equal(args.at(-1),'about:blank');
    const profile=args.find(arg=>arg.startsWith('--user-data-dir=')).slice('--user-data-dir='.length);
    const lines=await until(async()=>{const lines=(await readFile(join(profile,'DevToolsActivePort'),'utf8')).trim().split('\n');return lines.length>=2&&lines;},'Owned Chrome DevTools readiness');
    const address=await until(async()=>(await readFile(join(directory,'endpoint'),'utf8')).trim(),'Backend endpoint');
    const state=async()=>{
      try {
        const response=await fetch(new URL('/api/debugger',address),{signal:AbortSignal.timeout(2000)});
        const value=await response.json();
        // Failure reporting summarizes this fresh state through a fixed allowlist.
        return value;
      } catch {throw Error('Backend snapshot unavailable');}
    };
    socket=new WebSocket(`ws://127.0.0.1:${lines[0]}${lines[1]}`);
    await new Promise((resolveOpen,reject)=>{
      const timer=setTimeout(()=>reject(Error('Fixture control socket startup timeout')),5000);
      socket.onopen=()=>{clearTimeout(timer);resolveOpen();};socket.onerror=error=>{clearTimeout(timer);reject(error);};
    });
    socket.onmessage=event=>{
      const m=JSON.parse(event.data),waiter=pending.get(m.id);
      if(waiter){pending.delete(m.id);clearTimeout(waiter.timer);m.error?waiter.reject(Error('Fixture control command failed')):waiter.resolve(m.result);}
    };
    const command=(method,params={},sessionId)=>new Promise((resolveCommand,reject)=>{
      const id=sequence++,timer=setTimeout(()=>{pending.delete(id);reject(Error(`${method} timeout`));},8000);
      pending.set(id,{resolve:resolveCommand,reject,timer});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
    });
    const version=await command('Browser.getVersion');
    console.log(`CAPTURE-FIRST browser version: ${JSON.stringify({product:version.product,revision:version.revision,protocolVersion:version.protocolVersion,jsVersion:version.jsVersion})}`);
    let caseStage=createCaptureCaseStage();
    const runCase=async(label,expectedPaths,run)=>{
      caseStage=createCaptureCaseStage();
      try{await run();console.log(`COMPLETED capture-first case: ${label}`);}
      catch(error){
        const evidence=await captureFailureEvidence({readState:state,expectedPaths,servedCounts,stage:caseStage.current()});
        const kind=error instanceof assert.AssertionError?'assertion-failed':'case-failed';
        caseFailures.push(new Error(`${label}: ${kind}`));
        console.error(`FAIL capture-first case: ${label}: ${kind}; fresh evidence: ${JSON.stringify(evidence)}`);
      }
    };
    // Installed Chrome may have ambient workers even in a fresh profile.
    // Identify the owned launch page directly; a global owner count is not
    // evidence that this exact page has completed Network initialization.
    const first=await until(async()=>{
      const pages=(await command('Target.getTargets')).targetInfos.filter(t=>t.type==='page'&&t.url==='about:blank');
      assert(pages.length<=1,'Owned launch must have exactly one blank page');
      return pages[0]?.targetId;
    },'Owned blank page identity');
    let snapshot=await until(async()=>{
      const s=await state(),capture=s.network?.capture_status;
      return s.state==='running'&&s.target?.id===first&&capture?.startup_mode==='capture-first'&&
        capture.attached_target_ids?.includes(first)&&s;
    },'Blank capture owner ready');
    assert.equal(snapshot.network.capture_status.startup_mode,'capture-first');
    assert.equal(served.size,0,'No authored URL may load before capture is armed');
    const rowFor=(s,path)=>s.network.requests.find(row=>{try{return new URL(row.url).pathname===path;}catch{return false;}});
    const reportRows=async(paths,label,{strict=true,requireBodies=false}={})=>{
      for(const path of paths)observedPaths.add(path);
      caseStage.mark('receipt-wait');
      await until(()=>paths.every(path=>served.has(path)),`${label}: fixture server received requests`);
      const deadline=Date.now()+10000;let current;
      do {
        caseStage.mark('backend-snapshot');
        current=await state();
        caseStage.mark('row-body-wait');
        if(paths.every(path=>{const row=rowFor(current,path);return row&&(!requireBodies||row.response.body.state==='available');}))break;
        await delay(50);
      }while(Date.now()<deadline);
      const observations=paths.map(path=>{const row=rowFor(current,path);return {path,server_count:servedCounts.get(path)??0,server_first_received_at:servedTimes.get(path)??null,request_row:!!row,response_body:bodyState(row),request_state:diagnosticEnum(row?.state,['pending','complete','failed']),status:Number.isFinite(row?.status)?row.status:null,has_body_reason:!!row?.response?.body?.reason,completion_source:diagnosticEnum(row?.timing_evidence?.completion_source,['none','loadingFinished','loadingFailed','redirectRequest']),has_target_id:!!row?.target_id};});
      console.log(`CAPTURE-FIRST ${label}: ${JSON.stringify(observations)}`);
      caseStage.mark('request-row-presence');
      if(strict)assert.deepEqual(observations.filter(o=>!o.request_row).map(o=>o.path),[],`${label}: expected request rows missing (server receipt independently confirmed)`);
      caseStage.mark('response-body-presence');
      if(requireBodies)assert.deepEqual(observations.filter(o=>o.response_body!=='available').map(o=>o.path),[],`${label}: expected stable response bodies missing`);
      return current;
    };
    const firstSession=(await command('Target.attachToTarget',{targetId:first,flatten:true})).sessionId;
    await runCase('controlled initial response',['/initial','/initial-inline'],async()=>{
      caseStage.mark('navigation');
      await command('Page.navigate',{url:origin+'/initial'},firstSession);
      snapshot=await reportRows(['/initial','/initial-inline'],'controlled initial rows before body consumption');
      const initialRow=rowFor(snapshot,'/initial-inline');
      caseStage.mark('receipt-multiplicity');
      assert.equal(servedCounts.get('/initial-inline'),1,'Startup response is requested exactly once before consumption');
      caseStage.mark('target-owner');
      assert.equal(initialRow.target_id,first,'Initial inline fetch retains the exact owned page');
      // A Fetch response is a stream: merely resolving its headers does not
      // consume its body. Drain the SAME startup response before requiring CDP
      // completion/body retrieval; no retry request or delayed startup is added.
      caseStage.mark('evaluation');
      const consumed=await command('Runtime.evaluate',{expression:'window.initialResponse.then(response=>response.text())',awaitPromise:true,returnByValue:true},firstSession);
      caseStage.mark('evaluation-exception');
      assert(!consumed.exceptionDetails,JSON.stringify(consumed));
      caseStage.mark('response-body-value');
      assert.equal(consumed.result?.value,'synthetic:/initial-inline','The original startup response is fully consumed');
      snapshot=await reportRows(['/initial','/initial-inline'],'controlled initial document and inline fetch',{requireBodies:true});
      caseStage.mark('receipt-multiplicity');
      assert.equal(servedCounts.get('/initial-inline'),1,'Consuming the original response must not replay the request');
      caseStage.mark('request-row-identity');
      assert.equal(rowFor(snapshot,'/initial-inline').id,initialRow.id,'Body completion must update the same captured startup row');
      caseStage.mark('response-body-value');
      assert.equal(rowFor(snapshot,'/initial-inline').response.body.text,'synthetic:/initial-inline','Captured original body bytes match the consumed response');
    });
    // All subsequent creations issue their first requests immediately. Do not
    // wait on per-target attachment counters or inject an extra resume command.
    await runCase('simultaneous direct navigation',Array.from({length:4},(_,i)=>`/early-tab/${i}`).concat(Array.from({length:4},(_,i)=>`/early-inline/${i}`)),async()=>{
      caseStage.mark('target-creation');
      const early=await Promise.all(Array.from({length:4},(_,i)=>command('Target.createTarget',{url:`${origin}/early-tab/${i}`})));
      snapshot=await reportRows(Array.from({length:4},(_,i)=>`/early-tab/${i}`).concat(Array.from({length:4},(_,i)=>`/early-inline/${i}`)),'simultaneous direct-navigation startup rows');
      caseStage.mark('target-owner');
      for(const [i,target] of early.entries())assert.equal(rowFor(snapshot,`/early-inline/${i}`).target_id,target.targetId,'Direct-navigation fetch retains exact tab identity');
    });
    await runCase('immediate popup',['/popup','/popup-inline'],async()=>{
      caseStage.mark('evaluation');
      const popup=await command('Runtime.evaluate',{expression:`window.open('${origin}/popup');'opened'`},firstSession);
      caseStage.mark('evaluation-exception');
      assert(!popup.exceptionDetails,JSON.stringify(popup));
      await reportRows(['/popup','/popup-inline'],'immediate window.open and keepalive fetch before self-close');
      caseStage.mark('popup-close');
      await until(async()=>!(await command('Target.getTargets')).targetInfos.some(t=>t.url===origin+'/popup'),'Popup actually closed');
    });
    let contexts;
    const workerPaths=['/dedicated-inline','/nested-inline','/frame-worker-inline'];
    await runCase('worker and frame startup',['/contexts','/dedicated.js','/dedicated-inline','/nested-worker.js','/nested-inline','/outer-inline','/inner-inline','/frame-worker.js','/frame-worker-inline'],async()=>{
      caseStage.mark('target-creation');
      contexts=(await command('Target.createTarget',{url:origin+'/contexts'})).targetId;
      snapshot=await reportRows(['/contexts','/dedicated.js','/dedicated-inline','/nested-worker.js','/nested-inline','/outer-inline','/inner-inline','/frame-worker.js','/frame-worker-inline'],'immediate dedicated/nested/frame worker and frame-script rows');
      caseStage.mark('target-owner');
      const workerIds=workerPaths.map(path=>rowFor(snapshot,path).target_id);
      assert(workerIds.every(id=>id&&id!==contexts),'Worker startup rows need independent target identity');
      caseStage.mark('distinct-targets');
      assert.equal(new Set(workerIds).size,workerPaths.length,'Distinct startup workers retain distinct targets');
    });
    await runCase('frame document measurement',['/outer-frame','/inner-frame'],async()=>{
      // OOPIF request emission can precede its new target's startup hold. Keep
      // both observed document rows in the log; neither presence nor absence is
      // extrapolated to general completeness across browser versions.
      snapshot=await reportRows(['/outer-frame','/inner-frame'],'OOPIF/nested-frame initial-document measurement',{strict:false});
      const missingFrameDocuments=['/outer-frame','/inner-frame'].filter(path=>!rowFor(snapshot,path));
      console.log(`COVERAGE LIMIT: initial cross-site frame documents missing=${JSON.stringify(missingFrameDocuments)}; startup holds alter timing and do not establish 100% capture. Body availability remains separately bounded.`);
    });
    // Stable post-startup bodies are a separate strict contract. Their readiness
    // must not retroactively stand in for the startup-row assertions above.
    for(const [i,path] of workerPaths.entries()) {
      await runCase(`worker ${i} stable body`,[`/worker-steady/${i}`],async()=>{
      caseStage.mark('authored-worker-lookup');
      const info=(await command('Target.getTargets')).targetInfos.find(t=>t.type==='worker'&&t.url===(i===2?origin.replace('127.0.0.1','localhost'):origin)+['/dedicated.js','/nested-worker.js','/frame-worker.js'][i]);
      assert(info,`Authored worker for ${path} exists`);
      const id=info.targetId;
      caseStage.mark('target-attachment');
      const session=(await command('Target.attachToTarget',{targetId:id,flatten:true})).sessionId;
      caseStage.mark('evaluation');
      const result=await command('Runtime.evaluate',{expression:`fetch('${origin}/worker-steady/${i}').then(r=>r.text())`,awaitPromise:true},session);
      caseStage.mark('evaluation-exception');
      assert(!result.exceptionDetails,JSON.stringify(result));
      const s=await reportRows([`/worker-steady/${i}`],`worker ${i} stable response body`,{requireBodies:true});
      caseStage.mark('target-owner');
      assert.equal(rowFor(s,`/worker-steady/${i}`).target_id,id);
      });
    }
    await runCase('final mode and focus',[...observedPaths],async()=>{
      caseStage.mark('backend-snapshot');
      snapshot=await state();
      caseStage.mark('capture-mode');
      assert.equal(snapshot.network.capture_status.startup_mode,'capture-first');
      console.log(`FINAL row/body observations: ${JSON.stringify([...observedPaths].map(path=>{const row=rowFor(snapshot,path);return {path,request_row:!!row,response_body:bodyState(row)};}))}`);
      caseStage.mark('debugger-focus');
      assert.equal(snapshot.target.id,first,'Capture-first background activity must not change debugger focus');
    });
    // Exercise the actual Experiment page action separately from adversarial
    // direct-URL creation above. The backend owns this opening barrier.
    await runCase('owned experiment page opening',['/owned-open','/owned-open-inline'],async()=>{
      const action=async(payload)=>{
        const response=await fetch(new URL('/api/debugger/actions',address),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),signal:AbortSignal.timeout(20000)});
        assert(response.ok,'Owned page product action succeeds');
        return response.json();
      };
      caseStage.mark('target-creation');
      await action({action:'create_request_interception_experiment'});
      try {
        const created=await action({action:'create_experiment_page',url:origin+'/owned-open'});
        const captured=await reportRows(['/owned-open','/owned-open-inline'],'owned Experiment initial document and inline response',{requireBodies:true});
        for(const path of ['/owned-open','/owned-open-inline']) {
          const row=rowFor(captured,path);
          assert.equal(servedCounts.get(path),1,'Owned opening sends each authored request once');
          assert.equal(row.target_id,created.target_id,'Initial requests retain the created page identity');
          assert.equal(row.state,'complete');
          assert.equal(row.timing_evidence?.completion_source,'loadingFinished');
        }
        assert.equal(rowFor(captured,'/owned-open-inline').response.body.text,'synthetic:/owned-open-inline');
      } finally {await action({action:'dispose_request_interception_experiment'});}
    });
    socket.close();socket=undefined;
    await runCase('owned shutdown',[],async()=>{
      caseStage.mark('owned-process-stop');
      await stopBrowserTestProcess(backend,7000);
      caseStage.mark('profile-removal');
      await assert.rejects(readFile(join(profile,'DevToolsActivePort')),{code:'ENOENT'},'Owned browser profile must be removed after shutdown');
    });
    if(caseFailures.length)throw new AggregateError(caseFailures,`${caseFailures.length} strict capture-first cases failed`);
    console.log('PASS real capture-first: initial/unsynchronized tab, immediate popup, dedicated/nested worker rows, independent stable bodies, explicit frame-document limits and owned shutdown');
  } catch(error) {failure=error instanceof AggregateError?error:new Error('Capture-first fixture setup or execution failed');throw failure;}
  finally {
    console.log(`CAPTURE-FIRST bounded lifecycle: ${await readCaptureDiagnostics(directory)}`);
    console.log(`CAPTURE-FIRST server counts: ${JSON.stringify(captureFirstFixturePaths.map(path=>({path,count:servedCounts.get(path)??0})))}`);
    const errors=[];
    for(const waiter of pending.values())clearTimeout(waiter.timer);
    try{socket?.close();}catch(error){errors.push(error);}
    if(backend)try{await stopBrowserTestProcess(backend,7000);}catch(error){errors.push(error);}
    try{await new Promise((resolveClose,reject)=>fixture.close(error=>error?reject(error):resolveClose()));}catch(error){errors.push(error);}
    try{await rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});}catch(error){errors.push(error);}
    if(errors.length){if(failure)console.error(`Cleanup also failed; original test failure preserved (${errors.length} cleanup errors)`);else throw new Error('Capture-first browser cleanup failed');}
  }
}
