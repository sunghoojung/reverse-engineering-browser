// Real Chromium + native transport regression against authored loopback pages.
// Fetches are issued only after capture readiness; this does not assert that
// requests preceding attachment can be recovered.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {stopBrowserTestProcess, waitForClose} from './browser-test-process.mjs';

const root=resolve(process.argv[2]??'.');
const browser=process.env.ORIGIN_TRACE_TEST_BROWSER||process.env.REB_UI_CHROMIUM||'chromium';
const binary=resolve(process.env.ORIGIN_TRACE_BACKEND||join(root,'apps/origin-trace-backend/target/debug/origin-trace-backend'));
const transport=resolve(process.env.ORIGIN_TRACE_DEBUGGER_TRANSPORT||join(root,'build/reb-debugger-transport'));
const directory=await mkdtemp(join(tmpdir(),'reb-traffic-browser-'));
const children=[];let socket,sequence=1,diagnostics='',failure;const pending=new Map();
const delay=ms=>new Promise(resolveDelay=>setTimeout(resolveDelay,ms));
const fixture=createServer((request,response)=>{
  response.setHeader('Access-Control-Allow-Origin','*');
  response.setHeader('Content-Type',request.url.startsWith('/page')?'text/html':'text/plain');
  response.end(request.url.startsWith('/page')?'<title>Synthetic traffic page</title><link rel="icon" href="data:,">':`synthetic:${request.url}`);
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
  assert.fail(`${label} timed out: ${diagnostics}`);
}
try {
  start(browser,['--headless=new','--no-sandbox','--disable-dev-shm-usage','--disable-background-networking','--no-first-run',
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
    const id=sequence++,timer=setTimeout(()=>{pending.delete(id);reject(Error(`${method} timeout`));},5000);
    pending.set(id,{resolve:resolveCommand,reject,timer});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
  });
  start(binary,['--port','0','--endpoint-file',join(directory,'endpoint'),'--devtools-active-port',active,'--debugger-transport',transport,'--capture-network-content']);
  const address=await until(async()=>(await readFile(join(directory,'endpoint'),'utf8')).trim(),'Backend startup');
  const state=async()=>await(await fetch(new URL('/api/debugger',address),{signal:AbortSignal.timeout(2000)})).json();
  let snapshot=await until(async()=>{const s=await state();return s.state==='running'&&s.network.capture_status.attached_targets===1&&s;},'First capture owner');
  const a=snapshot.target.id;
  // Include about:blank -> navigation, a common new-tab lifecycle.
  const b=(await command('Target.createTarget',{url:'about:blank'})).targetId;
  await until(async()=>(await state()).network.capture_status.attached_targets===2,'New blank tab owner');
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
  const selected=await fetch(new URL('/api/debugger/actions',address),{method:'POST',headers:{'Content-Type':'application/json',Origin:address},body:JSON.stringify({action:'select_target',target_id:b})});
  assert(selected.ok,await selected.text());
  await until(async()=>(await state()).target.id===b,'Focus B');
  await command('Runtime.evaluate',{expression:`fetch('${origin}/after-switch-a').then(r=>r.text())`,awaitPromise:true},sessionA);
  snapshot=await until(async()=>{const s=await state();return s.network.requests.some(row=>row.url===origin+'/after-switch-a'&&row.response.body.state==='available')&&s;},'Background A after focus switch');
  for(const row of rows)assert(snapshot.network.requests.some(retained=>retained.id===row.id),'Focus switch must retain earlier rows');
  await command('Target.closeTarget',{targetId:a});
  snapshot=await until(async()=>{const s=await state();return s.network.capture_status.attached_targets===1&&s;},'Closed A owner');
  for(const row of rows)assert(snapshot.network.requests.some(retained=>retained.id===row.id),'Closing A must retain completed evidence');
  console.log('PASS real Chromium/native transport: blank new tab navigation, both-page bodies, background capture after focus switch, history retention and target closure');
} catch(error) {
  failure=error;
  throw error;
} finally {
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
