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
import {stopBrowserTestProcess} from './browser-test-process.mjs';

const script=fileURLToPath(import.meta.url),delay=ms=>new Promise(r=>setTimeout(r,ms));
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
  const served=new Set(),observedPaths=new Set(),pending=new Map();let sequence=1,socket,backend,diagnostics='',failure;
  const fixture=createServer((request,response)=>{
    const url=new URL(request.url,`http://${request.headers.host}`);served.add(url.pathname);
    response.setHeader('Access-Control-Allow-Origin','*');response.setHeader('Cache-Control','no-store');
    const html=script=>`<title>Authored capture-first fixture</title><link rel="icon" href="data:,"><script>${script}</script>`;
    let body=`synthetic:${request.url}`,type='text/plain';
    if(url.pathname==='/initial') {type='text/html';body=html("fetch('/initial-inline');");}
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
  const browserDiagnostics=async()=>{try{return(await readFile(join(directory,'browser-diagnostics'),'utf8')).slice(-8192);}catch{return '';}};
  const until=async(read,label,timeout=15000)=>{
    const deadline=Date.now()+timeout;
    while(Date.now()<deadline) {
      assert(backend.child.exitCode===null&&backend.child.signalCode===null,`${label}: backend/browser exited: ${diagnostics}\n${await browserDiagnostics()}`);
      try{const value=await read();if(value)return value;}catch(error){if(error instanceof assert.AssertionError)throw error;}
      await delay(40);
    }
    assert.fail(`${label} timed out: ${diagnostics}\n${await browserDiagnostics()}`);
  };
  try {
    await writeFile(join(directory,'browser-diagnostics'),'');
    const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
    await writeFile(join(directory,'browser-wrapper'),`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(script)} --browser-wrapper "$@"\n`,{mode:0o700});
    const child=spawn(binary,['--port','0','--endpoint-file',join(directory,'endpoint'),'--capture-first-browser',join(directory,'browser-wrapper'),'--capture-first-headless','--debugger-transport',transport,'--capture-network-content'],{cwd:directory,env:{...process.env,REB_CAPTURE_FIRST_REAL_BROWSER:browser,REB_CAPTURE_FIRST_BROWSER_FIXTURE:directory}});
    const closed=new Promise(r=>{child.once('close',r);child.once('error',error=>{diagnostics+=error.message;r();});});backend={child,closed};
    for(const pipe of [child.stdout,child.stderr])pipe.on('data',chunk=>diagnostics=(diagnostics+chunk).slice(-8192));
    const args=await until(async()=>JSON.parse(await readFile(join(directory,'browser-args'),'utf8')),'Owned browser launch');
    assert.equal(args.at(-1),'about:blank');
    const profile=args.find(arg=>arg.startsWith('--user-data-dir=')).slice('--user-data-dir='.length);
    const lines=await until(async()=>{const lines=(await readFile(join(profile,'DevToolsActivePort'),'utf8')).trim().split('\n');return lines.length>=2&&lines;},'Owned Chrome DevTools readiness');
    const address=await until(async()=>(await readFile(join(directory,'endpoint'),'utf8')).trim(),'Backend endpoint');
    const state=async()=>(await fetch(new URL('/api/debugger',address),{signal:AbortSignal.timeout(2000)})).json();
    let snapshot=await until(async()=>{const s=await state();return s.state==='running'&&s.network.capture_status.attached_targets===1&&s;},'Blank capture owner ready');
    assert.equal(snapshot.network.capture_status.startup_mode,'capture-first');
    assert.equal(served.size,0,'No authored URL may load before capture is armed');
    const first=snapshot.target.id;
    socket=new WebSocket(`ws://127.0.0.1:${lines[0]}${lines[1]}`);
    await new Promise((resolveOpen,reject)=>{
      const timer=setTimeout(()=>reject(Error('Fixture control socket startup timeout')),5000);
      socket.onopen=()=>{clearTimeout(timer);resolveOpen();};socket.onerror=error=>{clearTimeout(timer);reject(error);};
    });
    socket.onmessage=event=>{
      const m=JSON.parse(event.data),waiter=pending.get(m.id);
      if(waiter){pending.delete(m.id);clearTimeout(waiter.timer);m.error?waiter.reject(Error(m.error.message)):waiter.resolve(m.result);}
    };
    const command=(method,params={},sessionId)=>new Promise((resolveCommand,reject)=>{
      const id=sequence++,timer=setTimeout(()=>{pending.delete(id);reject(Error(`${method} timeout`));},8000);
      pending.set(id,{resolve:resolveCommand,reject,timer});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
    });
    const rowFor=(s,path)=>s.network.requests.find(row=>{try{return new URL(row.url).pathname===path;}catch{return false;}});
    const reportRows=async(paths,label,{strict=true,requireBodies=false}={})=>{
      for(const path of paths)observedPaths.add(path);
      await until(()=>paths.every(path=>served.has(path)),`${label}: fixture server received requests`);
      const deadline=Date.now()+10000;let current;
      do {
        current=await state();
        if(paths.every(path=>{const row=rowFor(current,path);return row&&(!requireBodies||row.response.body.state==='available');}))break;
        await delay(50);
      }while(Date.now()<deadline);
      const observations=paths.map(path=>{const row=rowFor(current,path);return {path,request_row:!!row,response_body:row?.response?.body?.state??'no-row',target_id:row?.target_id??null};});
      console.log(`CAPTURE-FIRST ${label}: ${JSON.stringify(observations)}`);
      if(strict)assert.deepEqual(observations.filter(o=>!o.request_row).map(o=>o.path),[],`${label}: expected request rows missing (server receipt independently confirmed)`);
      if(requireBodies)assert.deepEqual(observations.filter(o=>o.response_body!=='available').map(o=>o.path),[],`${label}: expected stable response bodies missing`);
      return current;
    };
    const firstSession=(await command('Target.attachToTarget',{targetId:first,flatten:true})).sessionId;
    await command('Page.navigate',{url:origin+'/initial'},firstSession);
    await reportRows(['/initial','/initial-inline'],'controlled initial document and inline fetch',{requireBodies:true});
    // All subsequent creations issue their first requests immediately. Do not
    // wait on per-target attachment counters or inject an extra resume command.
    const early=await Promise.all(Array.from({length:4},(_,i)=>command('Target.createTarget',{url:`${origin}/early-tab/${i}`})));
    snapshot=await reportRows(Array.from({length:4},(_,i)=>`/early-tab/${i}`).concat(Array.from({length:4},(_,i)=>`/early-inline/${i}`)),'simultaneous direct-navigation startup rows');
    for(const [i,target] of early.entries())assert.equal(rowFor(snapshot,`/early-inline/${i}`).target_id,target.targetId,'Direct-navigation fetch retains exact tab identity');
    const popup=await command('Runtime.evaluate',{expression:`window.open('${origin}/popup');'opened'`},firstSession);
    assert(!popup.exceptionDetails,JSON.stringify(popup));
    await reportRows(['/popup','/popup-inline'],'immediate window.open and keepalive fetch before self-close');
    await until(async()=>!(await command('Target.getTargets')).targetInfos.some(t=>t.url===origin+'/popup'),'Popup actually closed');
    const contexts=(await command('Target.createTarget',{url:origin+'/contexts'})).targetId;
    snapshot=await reportRows(['/contexts','/dedicated.js','/dedicated-inline','/nested-worker.js','/nested-inline','/outer-inline','/inner-inline','/frame-worker.js','/frame-worker-inline'],'immediate dedicated/nested/frame worker and frame-script rows');
    const workerPaths=['/dedicated-inline','/nested-inline','/frame-worker-inline'];
    const workerIds=workerPaths.map(path=>rowFor(snapshot,path).target_id);
    assert(workerIds.every(id=>id&&id!==contexts),'Worker startup rows need independent target identity');
    assert.equal(new Set(workerIds).size,workerPaths.length,'Distinct startup workers retain distinct targets');
    // OOPIF request emission can precede its new target's startup hold. Keep
    // both observed document rows in the log; neither presence nor absence is
    // extrapolated to general completeness across browser versions.
    snapshot=await reportRows(['/outer-frame','/inner-frame'],'OOPIF/nested-frame initial-document measurement',{strict:false});
    const missingFrameDocuments=['/outer-frame','/inner-frame'].filter(path=>!rowFor(snapshot,path));
    console.log(`COVERAGE LIMIT: initial cross-site frame documents missing=${JSON.stringify(missingFrameDocuments)}; startup holds alter timing and do not establish 100% capture. Body availability remains separately bounded.`);
    // Stable post-startup bodies are a separate strict contract. Their readiness
    // must not retroactively stand in for the startup-row assertions above.
    for(const [i,id] of workerIds.entries()) {
      const session=(await command('Target.attachToTarget',{targetId:id,flatten:true})).sessionId;
      const result=await command('Runtime.evaluate',{expression:`fetch('${origin}/worker-steady/${i}').then(r=>r.text())`,awaitPromise:true},session);
      assert(!result.exceptionDetails,JSON.stringify(result));
      const s=await reportRows([`/worker-steady/${i}`],`worker ${i} stable response body`,{requireBodies:true});
      assert.equal(rowFor(s,`/worker-steady/${i}`).target_id,id);
    }
    snapshot=await state();
    assert.equal(snapshot.network.capture_status.startup_mode,'capture-first');
    console.log(`FINAL row/body observations: ${JSON.stringify([...observedPaths].map(path=>{const row=rowFor(snapshot,path);return {path,request_row:!!row,response_body:row?.response?.body?.state??'no-row'};}))}`);
    assert.equal(snapshot.target.id,first,'Capture-first background activity must not change debugger focus');
    socket.close();socket=undefined;
    await stopBrowserTestProcess(backend,7000);
    await assert.rejects(readFile(join(profile,'DevToolsActivePort')),{code:'ENOENT'},'Owned browser profile must be removed after shutdown');
    console.log('PASS real capture-first: initial/unsynchronized tab, immediate popup, dedicated/nested worker rows, independent stable bodies, explicit frame-document limits and owned shutdown');
  } catch(error) {failure=error;throw error;}
  finally {
    const errors=[];
    for(const waiter of pending.values())clearTimeout(waiter.timer);
    try{socket?.close();}catch(error){errors.push(error);}
    if(backend)try{await stopBrowserTestProcess(backend,7000);}catch(error){errors.push(error);}
    try{await new Promise((resolveClose,reject)=>fixture.close(error=>error?reject(error):resolveClose()));}catch(error){errors.push(error);}
    try{await rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});}catch(error){errors.push(error);}
    if(errors.length){if(failure)console.error('Cleanup also failed; original test failure preserved:',...errors);else throw new AggregateError(errors,'Capture-first browser cleanup failed');}
  }
}
