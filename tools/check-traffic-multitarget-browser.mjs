// Real Chromium + native transport regression against authored loopback pages.
// Baseline readiness checks are followed by deliberately unsynchronized target
// startup. Never wait for a capture owner before issuing those early requests.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {stopBrowserTestProcess, waitForClose} from './browser-test-process.mjs';
import {prepareCaptureDiagnosticTransport,readCaptureDiagnostics} from './traffic-capture-diagnostics.mjs';

const root=resolve(process.argv[2]??'.');
// Set to 1 for the requested lossless early-request acceptance gate. Passive
// attachment can expose gaps here; diagnostics must never be called complete.
const requireEarly=process.env.REB_TRAFFIC_REQUIRE_EARLY==='1';
const browser=process.env.ORIGIN_TRACE_TEST_BROWSER||process.env.REB_UI_CHROMIUM||'chromium';
const binary=resolve(process.env.ORIGIN_TRACE_BACKEND||join(root,'apps/origin-trace-backend/target/debug/origin-trace-backend'));
const transport=resolve(process.env.ORIGIN_TRACE_DEBUGGER_TRANSPORT||join(root,'build/reb-debugger-transport'));
const directory=await mkdtemp(join(tmpdir(),'reb-traffic-browser-'));
const children=[];let socket,sequence=1,diagnostics='',failure;const pending=new Map();
const served=new Set(),servedCounts=new Map(),heldResponses=new Map();
let lastCaptureSnapshot=null,lastCaptureReadError='',refreshFailureSnapshot;
let lastControlCommand=null;
const delay=ms=>new Promise(resolveDelay=>setTimeout(resolveDelay,ms));
const fixture=createServer((request,response)=>{
  const url=new URL(request.url,`http://${request.headers.host}`);
  served.add(url.pathname);
  servedCounts.set(url.pathname,(servedCounts.get(url.pathname)??0)+1);
  response.setHeader('Access-Control-Allow-Origin','*');
  response.setHeader('Cache-Control','no-store');
  const html=script=>`<title>Synthetic traffic page</title><link rel="icon" href="data:,"><script>${script}</script>`;
  let body=`synthetic:${request.url}`,type='text/plain';
  if(url.pathname.startsWith('/page')){type='text/html';body=html('');}
  if(url.pathname.startsWith('/early-tab/')) {
    type='text/html';body=html(`fetch('/early-fetch/${url.pathname.split('/').at(-1)}').then(response=>response.text());`);
  }
  if(url.pathname==='/popup') {
    type='text/html';body=html("fetch('/popup-immediate',{keepalive:true});window.close();");
  }
  if(url.pathname==='/contexts') {
    type='text/html';body=html(`
      new Worker('/dedicated.js');
      window.shared=new SharedWorker('/shared.js');window.shared.port.start();
      navigator.serviceWorker.register('/service.js').catch(e=>fetch('/fixture-error?service='+encodeURIComponent(e.message)));
      const f=document.createElement('iframe');f.src=location.origin.replace('127.0.0.1','localhost')+'/outer-frame';document.documentElement.append(f);
    `);
  }
  if(url.pathname==='/outer-frame') {
    type='text/html';body=html("fetch('/outer-frame-immediate').then(response=>response.text());const f=document.createElement('iframe');f.src='/inner-frame';document.documentElement.append(f);");
  }
  if(url.pathname==='/inner-frame') {
    type='text/html';body=html("fetch('/inner-frame-immediate').then(response=>response.text());new Worker('/frame-worker.js');");
  }
  const workerFetches={'/dedicated.js':'/dedicated-immediate','/shared.js':'/shared-immediate','/frame-worker.js':'/frame-worker-immediate','/nested-worker.js':'/nested-worker-immediate'};
  if(workerFetches[url.pathname]) {
    type='text/javascript';body=`fetch('${workerFetches[url.pathname]}').then(response=>response.text());setInterval(()=>{},1000);`;
    if(url.pathname==='/shared.js')body+='onconnect=e=>e.ports[0].start();';
    if(url.pathname==='/dedicated.js')body+="new Worker('/nested-worker.js');";
  }
  if(url.pathname==='/service.js') {
    type='text/javascript';body="self.addEventListener('install',event=>event.waitUntil(fetch('/service-immediate').then(response=>response.text()).then(()=>self.skipWaiting())));";
  }
  response.setHeader('Content-Type',type);
  if(url.pathname.startsWith('/overlap/')) {
    heldResponses.set(url.pathname,{response,body});
    response.once('close',()=>heldResponses.delete(url.pathname));
    return;
  }
  response.end(body);
});
await new Promise(resolveListen=>fixture.listen(0,'127.0.0.1',resolveListen));
const origin=`http://127.0.0.1:${fixture.address().port}`;
function start(executable,args) {
  const child=spawn(executable,args,{cwd:directory});
  const closed=new Promise(resolveClose=>child.once('close',resolveClose));
  child.once('error',error=>{diagnostics+=error.message;});
  for(const pipe of [child.stdout,child.stderr])pipe.on('data',chunk=>diagnostics=(diagnostics+chunk).slice(-16384));
  children.push({child,closed});return child;
}
async function until(read,label) {
  const deadline=Date.now()+15000;
  while(Date.now()<deadline) {
    assert(children.every(({child})=>child.exitCode===null&&child.signalCode===null),`${label}: process exited: ${diagnostics}`);
    try {const value=await read();if(value)return value;}catch(error){if(error instanceof assert.AssertionError)throw error;}
    await delay(50);
  }
  assert.fail(`${label} timed out: ${diagnostics}\nLast capture snapshot: ${JSON.stringify(lastCaptureSnapshot)?.slice(0,16384)}\nLast capture read error: ${lastCaptureReadError}`);
}
try {
  start(browser,['--headless=new','--disable-dev-shm-usage','--site-per-process','--disable-popup-blocking','--disable-background-networking','--no-first-run',
    '--remote-debugging-port=0',`--user-data-dir=${directory}/profile`,`${origin}/page-a`]);
  const active=join(directory,'profile/DevToolsActivePort');
  const lines=await until(async()=>{const lines=(await readFile(active,'utf8')).trim().split('\n');return lines.length>=2&&lines;},'Browser startup');
  socket=new WebSocket(`ws://127.0.0.1:${lines[0]}${lines[1]}`);
  await new Promise((resolveOpen,reject)=>{const timer=setTimeout(()=>reject(Error('Browser socket startup timeout')),5000);socket.onopen=()=>{clearTimeout(timer);resolveOpen();};socket.onerror=error=>{clearTimeout(timer);reject(error);};});
  socket.onmessage=event=>{
    const message=JSON.parse(event.data),waiter=pending.get(message.id);
    if(waiter){pending.delete(message.id);clearTimeout(waiter.timer);message.error?waiter.reject(Error(message.error.message)):waiter.resolve(message.result);}
  };
  const command=(method,params={},sessionId)=>new Promise((resolveCommand,reject)=>{
    lastControlCommand={method,session_id:sessionId??null};
    const id=sequence++,timer=setTimeout(()=>{pending.delete(id);reject(Error(`${method} timeout`));},5000);
    pending.set(id,{resolve:resolveCommand,reject,timer});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
  });
  const version=await command('Browser.getVersion');
  console.log('Fixture browser version:',JSON.stringify({product:version.product,protocolVersion:version.protocolVersion}).slice(0,512));
  const diagnosticTransport=await prepareCaptureDiagnosticTransport(directory,transport);
  const backend=start(binary,['--port','0','--endpoint-file',join(directory,'endpoint'),'--devtools-active-port',active,'--debugger-transport',diagnosticTransport,'--capture-network-content']);
  const address=await until(async()=>(await readFile(join(directory,'endpoint'),'utf8')).trim(),'Backend startup');
  const state=async()=>{
    try {
      const response=await fetch(new URL('/api/debugger',address),{signal:AbortSignal.timeout(2000)});
      const value=await response.json();
      // Authored loopback fixtures only; bound failure diagnostics and exclude
      // response bodies, source bytes, credentials and unrelated browser data.
      lastCaptureSnapshot={http_status:response.status,state:value.state,error:value.error,
        target:value.target&&{id:value.target.id,type:value.target.type},
        target_count:value.targets?.length,
        paused:value.paused?{reason:String(value.paused.reason??'').slice(0,128)}:null,
        targets:value.targets?.slice(0,32).map(target=>({id:target.id,type:target.type,
          fixture_path:typeof target.url==='string'&&target.url.startsWith(origin+'/')?new URL(target.url).pathname.slice(0,128):null})),
        capture_status:value.network?.capture_status};
      lastCaptureReadError='';
      return value;
    } catch(error) {lastCaptureReadError=String(error).slice(0,512);throw error;}
  };
  refreshFailureSnapshot=state;
  // Installed browsers may have unrelated service workers or background pages.
  // Assert our authored page is ready instead of assuming a global owner count.
  const a=await until(async()=>(await command('Target.getTargets')).targetInfos.find(t=>t.type==='page'&&t.url===origin+'/page-a')?.targetId,'Authored first page');
  let snapshot=await until(async()=>{const s=await state();return s.state==='running'&&s.target.id===a&&s.network.capture_status.attached_target_ids.includes(a)&&s;},'First capture owner');
  // Include about:blank -> navigation, a common new-tab lifecycle.
  const b=(await command('Target.createTarget',{url:'about:blank'})).targetId;
  await until(async()=>{const ids=(await state()).network.capture_status.attached_target_ids;return ids.includes(a)&&ids.includes(b);},'New blank tab owner');
  const sessionA=(await command('Target.attachToTarget',{targetId:a,flatten:true})).sessionId;
  const sessionB=(await command('Target.attachToTarget',{targetId:b,flatten:true})).sessionId;
  await command('Page.navigate',{url:origin+'/page-b'},sessionB);
  await until(async()=>{const result=await command('Runtime.evaluate',{expression:`location.href === '${origin}/page-b' && document.readyState === 'complete'`},sessionB);return result.result?.value===true;},'B navigation');
  for(const [session,suffix] of [[sessionA,'a'],[sessionB,'b']]) {
    const result=await command('Runtime.evaluate',{expression:`fetch('${origin}/request-${suffix}').then(r=>r.text())`,awaitPromise:true},session);
    assert(!result.exceptionDetails,JSON.stringify(result));
  }
  snapshot=await until(async()=>{const s=await state();return ['/request-a','/request-b'].every(path=>s.network.requests.some(row=>row.url===origin+path&&row.response.body.state==='available'))&&s;},'Both owner bodies');
  assert.equal(snapshot.target.id,a,'Capture must not change debugger focus');
  const rows=snapshot.network.requests.filter(row=>row.url.endsWith('/request-a')||row.url.endsWith('/request-b'));
  assert.equal(rows.find(row=>row.target_id===a).response.body.text,'synthetic:/request-a');
  assert.equal(rows.find(row=>row.target_id===b).response.body.text,'synthetic:/request-b');
  // Server-held responses establish real overlap, not merely ready owners.
  for(const [session,suffix] of [[sessionA,'a'],[sessionB,'b']]) {
    const result=await command('Runtime.evaluate',{expression:`globalThis.overlapBody=fetch('${origin}/overlap/${suffix}').then(r=>r.text());'started'`},session);
    assert(!result.exceptionDetails,JSON.stringify(result));
  }
  await until(()=>heldResponses.has('/overlap/a')&&heldResponses.has('/overlap/b'),'Both tab requests simultaneously outstanding at server');
  await until(async()=>(await state()).network.requests.filter(row=>row.url.startsWith(origin+'/overlap/')&&row.response.body.state==='loading').length===2,'Both overlapping owner rows retained before selection');
  // HTTP owners attach from browser events before the selected-debugger's
  // independently polled catalog necessarily exposes the page as selectable.
  await until(async()=>(await state()).targets.some(target=>target.id===b),'B appears in selectable debugger catalog');
  const selected=await fetch(new URL('/api/debugger/actions',address),{method:'POST',headers:{'Content-Type':'application/json',Origin:address},body:JSON.stringify({action:'select_target',target_id:b})});
  assert(selected.ok,await selected.text());
  await until(async()=>(await state()).target.id===b,'Focus B');
  await command('Runtime.evaluate',{expression:`fetch('${origin}/after-switch-a').then(r=>r.text())`,awaitPromise:true},sessionA);
  snapshot=await until(async()=>{const s=await state();return s.network.requests.some(row=>row.url===origin+'/after-switch-a'&&row.response.body.state==='available')&&s;},'Background A after focus switch');
  assert(heldResponses.has('/overlap/a')&&heldResponses.has('/overlap/b'),'Both original responses stay outstanding across selection and background activity');
  for(const row of rows)assert(snapshot.network.requests.some(retained=>retained.id===row.id),'Focus switch must retain earlier rows');
  await command('Target.closeTarget',{targetId:a});
  snapshot=await until(async()=>{const s=await state(),ids=s.network.capture_status.attached_target_ids;return !ids.includes(a)&&ids.includes(b)&&s;},'Closed A owner');
  const heldB=heldResponses.get('/overlap/b');assert(heldB,'B response remains outstanding when A closes');heldB.response.end(heldB.body);
  snapshot=await until(async()=>{const s=await state();return s.network.requests.some(row=>row.url===origin+'/overlap/b'&&row.response.body.state==='available')&&s.network.requests.some(row=>row.url===origin+'/overlap/a'&&row.response.body.state==='error')&&s;},'B completes while closed A retains explicit incomplete evidence');
  const overlapA=snapshot.network.requests.find(row=>row.url===origin+'/overlap/a');
  const overlapB=snapshot.network.requests.find(row=>row.url===origin+'/overlap/b');
  assert.equal(overlapA.target_id,a);assert.equal(overlapA.response.body.state,'error');
  assert.equal(overlapB.target_id,b);assert.equal(overlapB.response.body.text,'synthetic:/overlap/b');
  assert.notEqual(overlapA.id,overlapB.id,'Overlapping owners have distinct public row IDs');
  assert.equal(servedCounts.get('/overlap/a'),1);assert.equal(servedCounts.get('/overlap/b'),1);
  for(const row of rows)assert(snapshot.network.requests.some(retained=>retained.id===row.id),'Closing A must retain completed evidence');
  await command('Runtime.evaluate',{expression:`fetch('${origin}/after-close-b').then(r=>r.text())`,awaitPromise:true},sessionB);
  snapshot=await until(async()=>{const s=await state();return s.network.requests.some(row=>row.url===origin+'/after-close-b'&&row.response.body.state==='available')&&s;},'Surviving B captures after A closes');
  assert.equal(snapshot.network.requests.find(row=>row.url===origin+'/after-close-b').target_id,b);
  assert(snapshot.network.requests.some(row=>row.id===overlapA.id&&row.response.body.state==='error'),'Incomplete closed-owner history stays explicit');
  console.log('PASS real concurrent tabs: server-held requests overlap, selection switches while pending, closing A preserves its incomplete row and B exact body, survivor continues');
  console.log('PASS real Chromium/native transport: blank new tab navigation, both-page bodies, background capture after focus switch, history retention and target closure');
  // Early-traffic acceptance probe: these operations intentionally never wait
  // for per-target discovery, Network.enable, or a target attachment counter.
  const missing=[];
  async function expectCaptured(paths,label,{body=true}={}) {
    await until(()=>paths.every(path=>served.has(path)),`${label}: browser issued fixture requests`);
    const deadline=Date.now()+15000;
    let current;
    do {
      current=await state();
      if(paths.every(path=>current.network.requests.some(row=>new URL(row.url).pathname===path&&(!body||row.response.body.state==='available'))))break;
      await delay(50);
    } while(Date.now()<deadline);
    const absent=paths.filter(path=>!current.network.requests.some(row=>new URL(row.url).pathname===path&&(!body||row.response.body.state==='available')));
    if(absent.length){
      const evidence=absent.map(path=>{
        const row=current.network.requests.find(row=>new URL(row.url).pathname===path);
        return {path,server_requests:servedCounts.get(path)??0,request_row:Boolean(row),target_id:row?.target_id,body_state:row?.response.body.state,body_reason:row?.response.body.reason};
      });
      console.log(`Early capture evidence: ${JSON.stringify(evidence).slice(0,8192)}`);
      missing.push(`${label}: ${absent.join(', ')}`);console.log(`PARTIAL early capture: ${missing.at(-1)}`);
      assert.equal(current.network.capture_status.startup_mode,'passive','Observed early gaps must not be advertised as complete startup coverage');
    }
    else console.log(`PASS ${label}`);
    return current;
  }
  // Controlled navigation is a strict, usable first-request capture path.
  // Unlike the early probes below, blank target readiness is intentional here.
  const controlled=(await command('Target.createTarget',{url:'about:blank'})).targetId;
  await until(async()=>(await state()).network.capture_status.attached_target_ids.includes(controlled),'Controlled blank tab capture ready');
  const controlledSession=(await command('Target.attachToTarget',{targetId:controlled,flatten:true})).sessionId;
  await command('Page.navigate',{url:origin+'/early-tab/controlled'},controlledSession);
  snapshot=await expectCaptured(['/early-tab/controlled','/early-fetch/controlled'],'controlled navigation: initial document and first inline fetch');
  assert.equal(missing.length,0,'Controlled navigation must capture the first requests');
  for(const path of ['/early-tab/controlled','/early-fetch/controlled']) {
    assert.equal(servedCounts.get(path),1,'Controlled fixture must issue each request exactly once');
    assert.equal(snapshot.network.requests.find(row=>row.url===origin+path)?.target_id,controlled,'Controlled first request must retain exact owner identity');
  }
  assert.equal(snapshot.network.requests.find(row=>row.url===origin+'/early-fetch/controlled').response.body.text,'synthetic:/early-fetch/controlled','Controlled inline response bytes must match the single authored response');
  const earlyIds=await Promise.all(Array.from({length:10},(_,i)=>command('Target.createTarget',{url:`${origin}/early-tab/${i}`})));
  snapshot=await expectCaptured(Array.from({length:10},(_,i)=>`/early-fetch/${i}`),'ten simultaneous tabs: first inline-script fetches');
  await expectCaptured(Array.from({length:10},(_,i)=>`/early-tab/${i}`),'ten simultaneous tabs: initial document requests');
  for(let i=0;i<earlyIds.length;i++) {
    const row=snapshot.network.requests.find(row=>row.url===`${origin}/early-fetch/${i}`);
    if(row)assert.equal(row.target_id,earlyIds[i].targetId,'Early request must retain exact tab identity');
  }
  assert.equal(snapshot.target.id,b,'New tabs must not change debugger focus');
  await until(async()=>{
    const s=await state();
    return earlyIds.every(({targetId})=>s.network.capture_status.attached_target_ids.includes(targetId));
  },'All ten new tabs become capture owners');
  const beforeSteady=missing.length;
  // Exercise ten owners without overflowing the independent eight-body job cap.
  for(const [i,{targetId}] of earlyIds.entries()) {
    const session=(await command('Target.attachToTarget',{targetId,flatten:true})).sessionId;
    const result=await command('Runtime.evaluate',{expression:`fetch('${origin}/steady-tab/${i}').then(r=>r.text())`,awaitPromise:true},session);
    assert(!result.exceptionDetails,JSON.stringify(result));
    await expectCaptured([`/steady-tab/${i}`],`attached tab ${i}: response body`);
  }
  assert.equal(missing.length,beforeSteady,'More than eight attached tabs must all capture traffic');
  // Run after >8 tabs remain open, not after freeing the original owner limit.
  console.log('PHASE popup: issuing synchronous window.open on authored B');
  const popup=await command('Runtime.evaluate',{expression:`window.open('${origin}/popup');'opened'`},sessionB);
  console.log('PHASE popup: window.open evaluation returned');
  assert(!popup.exceptionDetails,JSON.stringify(popup));
  await expectCaptured(['/popup-immediate'],'short-lived window.open fetch + immediate close',{body:false});
  await until(async()=>!(await command('Target.getTargets')).targetInfos.some(t=>t.url===origin+'/popup'),'Popup really closed');
  const contexts=(await command('Target.createTarget',{url:origin+'/contexts'})).targetId;
  snapshot=await expectCaptured(['/dedicated-immediate','/shared-immediate','/service-immediate','/outer-frame-immediate','/inner-frame-immediate','/frame-worker-immediate','/nested-worker-immediate'],
    'dedicated/shared/service worker and nested cross-site frame startup');
  assert(!served.has('/fixture-error'),'Fixture worker registration failed');
  const workerRows=['/dedicated-immediate','/shared-immediate','/service-immediate','/frame-worker-immediate','/nested-worker-immediate']
    .map(path=>snapshot.network.requests.find(row=>new URL(row.url).pathname===path)).filter(Boolean);
  for(const row of workerRows) {
    assert(row.target_id&&row.target_id!==contexts,'Worker traffic must retain its own target identity');
  }
  assert.equal(new Set(workerRows.map(row=>row.target_id)).size,workerRows.length,'Distinct workers must not share target identity');
  // Worker support is a strict requirement even when early startup is only
  // measured. Do not downgrade unsupported targets to an early-race diagnostic.
  const workerScripts=['/dedicated.js','/shared.js','/service.js','/frame-worker.js','/nested-worker.js'];
  const workerTargets=await until(async()=>{
    const infos=(await command('Target.getTargets')).targetInfos;
    const targets=workerScripts.map(path=>{
      const url=(path==='/frame-worker.js'?origin.replace('127.0.0.1','localhost'):origin)+path;
      return infos.find(t=>['worker','shared_worker','service_worker'].includes(t.type)&&t.url===url);
    });
    return targets.every(Boolean)&&targets;
  },'All fixture worker targets exist');
  await until(async()=>{
    const status=(await state()).network.capture_status;
    return workerTargets.every(t=>status.attached_target_ids.includes(t.targetId));
  },'Dedicated, shared, service and nested-frame workers all captured');
  await Promise.all(workerTargets.map(async(target,i)=>{
    const session=(await command('Target.attachToTarget',{targetId:target.targetId,flatten:true})).sessionId;
    const url=new URL(`/steady-worker/${i}`,target.url).href;
    const result=await command('Runtime.evaluate',{expression:`fetch(${JSON.stringify(url)}).then(r=>r.text())`,awaitPromise:true},session);
    assert(!result.exceptionDetails,JSON.stringify(result));
  }));
  const beforeWorkers=missing.length;
  snapshot=await expectCaptured(workerTargets.map((_target,i)=>`/steady-worker/${i}`),'all attached worker types: response bodies');
  assert.equal(missing.length,beforeWorkers,'Worker traffic must be captured after attachment');
  for(let i=0;i<workerTargets.length;i++) {
    const row=snapshot.network.requests.find(row=>new URL(row.url).pathname===`/steady-worker/${i}`);
    assert.equal(row.target_id,workerTargets[i].targetId,'Worker response belongs to its exact target');
  }
  // Disconnect during a fresh target burst. A capture connection that holds
  // startup must release every target on teardown; the HTTP server, not CDP
  // evaluation or another runIfWaitingForDebugger call, proves execution.
  const shutdownCreates=Array.from({length:10},(_,i)=>command('Target.createTarget',{url:`${origin}/early-tab/shutdown-${i}`}));
  backend.kill('SIGTERM');
  await Promise.all(shutdownCreates);
  assert(await waitForClose(children.find(entry=>entry.child===backend).closed,5000),'Backend process must close after SIGTERM');
  assert(backend.exitCode!==null||backend.signalCode!==null,'Backend must terminate on SIGTERM');
  const shutdownDeadline=Date.now()+15000;
  while(!Array.from({length:10},(_,i)=>`/early-fetch/shutdown-${i}`).every(path=>served.has(path))&&Date.now()<shutdownDeadline)await delay(50);
  assert(Array.from({length:10},(_,i)=>`/early-fetch/shutdown-${i}`).every(path=>served.has(path)),
    'Backend shutdown must leave all concurrently created pages running');
  console.log('PASS backend shutdown during target creation leaves browser pages running');
  if(requireEarly)assert.deepEqual(missing,[],'Early request capture gaps (requests independently confirmed by fixture server)');
  else if(missing.length)console.log('PARTIAL: early-request completeness is NOT established; rerun REB_TRAFFIC_REQUIRE_EARLY=1 for strict acceptance');

} catch(error) {
  failure=error;
  // Snapshot again after the failed operation; the previous polling result can
  // predate a popup or renderer state transition by several seconds.
  try {await refreshFailureSnapshot?.();} catch {}
  console.error('Failed control command:',JSON.stringify(lastControlCommand));
  console.error('Popup fixture receipts:',JSON.stringify(['/popup','/popup-immediate'].map(path=>({path,server_requests:servedCounts.get(path)??0}))));
  console.error('Capture failure snapshot:',JSON.stringify(lastCaptureSnapshot)?.slice(0,16384));
  console.error('Capture read failure:',lastCaptureReadError);
  throw error;
} finally {
  console.log('Capture control lifecycle:',await readCaptureDiagnostics(directory));
  const cleanupErrors=[];
  for(const waiter of pending.values())clearTimeout(waiter.timer);
  // CDP shutdown lets Chrome finish profile writes before signal fallback.
  if(socket?.readyState===WebSocket.OPEN) {
    try {
      socket.send(JSON.stringify({id:sequence++,method:'Browser.close'}));
      await waitForClose(children[0].closed,3000);
    } catch(error) {cleanupErrors.push(error);}
  }
  try {socket?.close();} catch(error) {cleanupErrors.push(error);}
  let allClosed=true;
  for(const process of [...children].reverse()) {
    try {await stopBrowserTestProcess(process);}
    catch(error){allClosed=false;cleanupErrors.push(error);}
  }
  try {await new Promise((resolveClose,reject)=>fixture.close(error=>error?reject(error):resolveClose()));}
  catch(error) {cleanupErrors.push(error);}
  if(allClosed) {
    try {
      // Recursive rm retries only Node's transient filesystem errors, including
      // ENOTEMPTY from a final Chrome descendant write. It remains bounded.
      await rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});
    } catch(error) {cleanupErrors.push(error);}
  }
  if(cleanupErrors.length) {
    if(failure) console.error('Cleanup also failed; original test failure preserved:',...cleanupErrors);
    else throw new AggregateError(cleanupErrors,'Browser fixture cleanup failed');
  }
}
