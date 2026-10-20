// Synthetic CDP/HTTP lifecycle tests; no browser, external site, reload or pause.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {appendFileSync, existsSync, readFileSync, writeFileSync} from 'node:fs';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {stopBrowserTestProcess} from './browser-test-process.mjs';
const script=fileURLToPath(import.meta.url);
const delay=ms=>new Promise(r=>setTimeout(r,ms));
if(process.argv[2]==='--transport') {
  const directory=process.env.REB_CAPTURE_FIXTURE;
  const target=process.argv.at(-1).split('/').at(-1);
  const log=value=>appendFileSync(join(directory,'commands.jsonl'),JSON.stringify({...value,target,pid:process.pid})+'\n');
  const emit=value=>{const body=value===null?Buffer.alloc(0):Buffer.from(JSON.stringify(value));const header=Buffer.from([82,69,66,1,0,0,0,0]);header.writeUInt32BE(body.length,4);process.stdout.write(Buffer.concat([header,body]));};
  log({event:'open'});emit(null);
  let pending=Buffer.alloc(0), firstMethod, enabled=false;
  let cursor=readFileSync(join(directory,'events.jsonl'),'utf8').split('\n').filter(Boolean).length;
  process.stdin.on('data',chunk=>{
    pending=Buffer.concat([pending,chunk]);
    while(pending.length>=8&&pending.length>=8+pending.readUInt32BE(4)) {
      const size=pending.readUInt32BE(4),m=JSON.parse(pending.subarray(8,8+size));pending=pending.subarray(8+size);
      firstMethod??=m.method;log({event:'command',method:m.method,role:firstMethod==='Network.enable'?'capture':'focus'});
      if(firstMethod==='Inspector.enable'&&m.method===process.env.REB_INIT_FIXTURE_METHOD&&!existsSync(join(directory,'failed-once'))) {
        writeFileSync(join(directory,'failed-once'),'failed',{mode:0o600});
        if(process.env.REB_INIT_FIXTURE_MODE!=='timeout')emit({id:m.id,error:{code:-32000,message:'Synthetic initialization failure'}});
        continue;
      }
      if(firstMethod==='Network.enable'&&m.method==='Network.enable'&&target==='retry'&&!existsSync(join(directory,'failed-once'))) {
        writeFileSync(join(directory,'failed-once'),'failed',{mode:0o600});emit({id:m.id,error:{code:-32000,message:'Synthetic capture attach failure'}});continue;
      }
      if(m.method==='Network.getResponseBody') {
        const wait=m.params.requestId==='slow'?1200:0;
        setTimeout(()=>emit({id:m.id,result:{body:`body:${target}:${m.params.requestId}`,base64Encoded:false}}),wait);
      } else {emit({id:m.id,result:{}});}
      if(m.method==='Network.enable') {
        enabled=true;
        if(process.env.REB_INIT_FIXTURE_MODE)emit({method:'Network.requestWillBeSent',params:{requestId:'synthetic-request',timestamp:1,wallTime:1,type:'Fetch',request:{url:'http://localhost/synthetic',method:'GET',headers:{}}}});
      }
    }
  });
  setInterval(()=>{
    const lines=readFileSync(join(directory,'events.jsonl'),'utf8').split('\n').filter(Boolean);
    while(cursor<lines.length) {
      const event=JSON.parse(lines[cursor++]);
      if(event.target!==target||firstMethod!=='Network.enable'||!enabled)continue;
      if(event.disconnect)process.exit(0);
      emit({method:event.method,params:event.params});
    }
  },20);
} else {
  const root=resolve(process.argv[2]??'.');
  const binary=resolve(process.env.ORIGIN_TRACE_BACKEND||join(root,'apps/origin-trace-backend/target/debug/origin-trace-backend'));
  const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
  async function fixture(capture,run,initialization={}) {
    const directory=await mkdtemp(join(tmpdir(),'reb-traffic-multitarget-'));
    const targets=['a'];let discoveryFailure=false;let backend,closed,diagnostics='',address,discoveries=0;
    await writeFile(join(directory,'events.jsonl'),'');
    const server=createServer((_req,res)=>{
      discoveries++;
      if(discoveryFailure){res.writeHead(503);res.end('synthetic discovery failure');return;}
      res.setHeader('Content-Type','application/json');
      res.end(JSON.stringify(targets.map(id=>({id,type:'page',title:id,url:`http://localhost/${id}`,webSocketDebuggerUrl:`ws://127.0.0.1:${server.address().port}/devtools/page/${id}`}))));
    });
    await new Promise(r=>server.listen(0,'127.0.0.1',r));
    const send=(target,method,params)=>appendFileSync(join(directory,'events.jsonl'),JSON.stringify({target,method,params})+'\n');
    const disconnect=target=>appendFileSync(join(directory,'events.jsonl'),JSON.stringify({target,disconnect:true})+'\n');
    const get=async()=>{address??=(await readFile(join(directory,'endpoint'),'utf8')).trim();return await(await fetch(new URL('/api/debugger',address),{signal:AbortSignal.timeout(2000)})).json();};
    async function until(predicate,label,ms=15000) {
      const end=Date.now()+ms;let last;
      while(Date.now()<end) {
        assert.equal(backend.exitCode,null,diagnostics);
        try {last=await get();if(await predicate(last))return last;}catch(error){if(error instanceof assert.AssertionError)throw error;}
        await delay(40);
      }
      assert.fail(`${label}: ${JSON.stringify({state:last?.state,status:last?.network?.capture_status,rows:last?.network?.requests?.length})} ${diagnostics}`);
    }
    try {
      await writeFile(join(directory,'active'),`${server.address().port}\n/devtools/browser/fixture\n`,{mode:0o600});
      await writeFile(join(directory,'transport'),`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(script)} --transport "$@"\n`,{mode:0o700});
      backend=spawn(binary,['--port','0','--endpoint-file',join(directory,'endpoint'),'--devtools-active-port',join(directory,'active'),'--debugger-transport',join(directory,'transport'),...(capture?['--capture-network-content']:[])],{cwd:directory,env:{...process.env,REB_CAPTURE_FIXTURE:directory,REB_INIT_FIXTURE_METHOD:initialization.method||'',REB_INIT_FIXTURE_MODE:initialization.mode||''}});
      closed=new Promise(r=>backend.once('close',r));
      backend.once('error',e=>{diagnostics+=e.message;});
      for(const stream of [backend.stdout,backend.stderr])stream.on('data',chunk=>diagnostics=(diagnostics+chunk).slice(-16384));
      const select=async target=>{const response=await fetch(new URL('/api/debugger/actions',address),{method:'POST',headers:{'Content-Type':'application/json',Origin:address},body:JSON.stringify({action:'select_target',target_id:target})});assert(response.ok,await response.text());};
      await run({targets,send,disconnect,get,until,select,directory,discoveries:()=>discoveries,setDiscoveryFailure:value=>{discoveryFailure=value;}});
    } finally {
      try {if(backend)await stopBrowserTestProcess({child:backend,closed},5000);}
      finally {await new Promise(r=>server.close(r));}
      await rm(directory,{recursive:true,force:true});
    }
  }
  // Initialization and page capture share the same discovery/transport fixture.
  for(const {name,method='',mode='error',capture=true} of [
    {name:'successful initialization'},
    {name:'Network.enable error retry',method:'Network.enable'},
    {name:'early domain error retry',method:'Runtime.enable'},
    {name:'Network.enable timeout retry',method:'Network.enable',mode:'timeout'},
    {name:'restore settings error retry',method:'Debugger.setPauseOnExceptions'},
    {name:'disabled content capture',capture:false},
  ])await fixture(capture,async({until,directory,discoveries})=>{
    const state=await until(s=>s.state==='running',`${name}: initialization recovers`);
    assert.equal(state.error,null,`${name}: successful recovery clears error`);
    assert.equal(state.network.capture_enabled,capture);
    assert.equal(state.network.requests.length,capture?1:0);
    const before=discoveries();
    await until(()=>discoveries()>=before+2,`${name}: refresh remains live`);
    const commands=(await readFile(join(directory,'commands.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);
    const owners=commands.filter(command=>command.method==='Inspector.enable');
    const focused=new Set(owners.map(owner=>owner.pid));
    const focusedCommands=commands.filter(command=>focused.has(command.pid));
    assert.equal(owners.length,method?2:1,`${name}: exactly one retry, no reconnect loop`);
    if(method) {
      assert.equal(focusedCommands.filter(command=>command.method===method).length,2,`${name}: failed domain is retried`);
      assert.throws(()=>process.kill(owners[0].pid,0),{code:'ESRCH'},`${name}: failed transport must be reaped`);
      assert.equal(state.network.capture_epoch,2);
    }
    if(!capture)assert(!commands.some(command=>command.method==='Network.enable'),'Disabled content capture must never enable Network');
    console.log(`PASS debugger initialization: ${name}`);
  },{method,mode});
  const request=(id,url='synthetic')=>({requestId:id,timestamp:1,wallTime:1,type:'Fetch',request:{url:`http://localhost/${url}`,method:'GET',headers:{}}});
  const complete=(send,target,id,status=200)=>{send(target,'Network.responseReceived',{requestId:id,response:{status,headers:{}}});send(target,'Network.loadingFinished',{requestId:id,timestamp:2,encodedDataLength:10});};
  await fixture(true,async({targets,send,disconnect,get,until,select,directory,setDiscoveryFailure})=>{
    await until(s=>s.state==='running'&&s.network.capture_status.attached_targets===1,'initial owner');
    send('a','Network.requestWillBeSent',request('same'));
    // A pre-attachment event is deliberately unavailable, never replayed.
    send('b','Network.requestWillBeSent',request('before-attach'));
    targets.push('b');
    await until(s=>s.network.capture_status.attached_targets===2,'new tab owner');
    send('b','Network.requestWillBeSent',request('same'));
    complete(send,'a','same',201);complete(send,'b','same',202);
    let s=await until(s=>s.network.requests.filter(r=>r.response.body.state==='available').length===2,'same raw ID bodies');
    assert.equal(s.target.id,'a','Capture must not switch debugger focus');
    assert.equal(s.network.requests.length,2,'No fabricated pre-attachment request');
    const a=s.network.requests.find(r=>r.target_id==='a'),b=s.network.requests.find(r=>r.target_id==='b');
    assert.equal(a.status,201);assert.equal(b.status,202);assert.notEqual(a.id,b.id);
    assert.equal(a.response.body.text,'body:a:same');assert.equal(b.response.body.text,'body:b:same');
    send('a','Network.requestWillBeSent',request('slow'));complete(send,'a','slow');
    await until(s=>s.network.requests.some(r=>r.protocol_request_id==='slow'&&r.state==='complete'),'slow body started');
    const epoch=s.network.capture_epoch;await select('b');
    s=await until(s=>s.target.id==='b'&&s.network.requests.some(r=>r.protocol_request_id==='slow'&&r.response.body.state==='available'),'body survives focus switch');
    assert(s.network.capture_epoch>epoch);assert(s.network.requests.some(r=>r.id===a.id));assert(s.network.requests.some(r=>r.id===b.id));
    assert.equal(s.network.requests.find(r=>r.protocol_request_id==='slow').response.body.text,'body:a:slow');
    send('a','Network.requestWillBeSent',request('redirect'));
    send('a','Network.requestWillBeSent',{...request('redirect','final'),redirectResponse:{status:302,headers:{}}});complete(send,'a','redirect');
    s=await until(s=>s.network.requests.filter(r=>r.protocol_request_id==='redirect').length===2&&s.network.requests.some(r=>r.url==='http://localhost/final'&&r.response.body.state==='available'),'redirect hops');
    assert.equal(new Set(s.network.requests.map(r=>r.id)).size,s.network.requests.length);
    send('a','Network.requestWillBeSent',request('pending'));
    await until(s=>s.network.requests.some(r=>r.protocol_request_id==='pending'),'pending request');
    const oldOwner=s.network.requests.find(r=>r.target_id==='a').capture_owner;
    send('a','Network.requestWillBeSent',request('slow','retired-body'));complete(send,'a','slow');
    await until(s=>s.network.requests.some(r=>r.url==='http://localhost/retired-body'&&r.state==='complete'&&r.response.body.state==='loading'),'retired body retrieval started');
    const captureStarts=async()=> (await readFile(join(directory,'commands.jsonl'),'utf8')).trim().split('\n').map(JSON.parse).filter(c=>c.target==='a'&&c.role==='capture'&&c.method==='Network.enable').length;
    const previousStarts=await captureStarts();
    disconnect('a');
    await until(s=>s.network.capture_status.gaps>=1&&s.network.requests.some(r=>r.protocol_request_id==='pending'&&r.state==='failed'),'disconnect gap');
    await until(async s=>s.network.capture_status.attached_targets===2&&(await captureStarts())>previousStarts,'replacement owner ready');
    send('a','Network.requestWillBeSent',request('same','reconnected'));complete(send,'a','same');
    send('a','Network.requestWillBeSent',request('slow','replacement-body'));complete(send,'a','slow');
    s=await until(s=>s.network.requests.some(r=>r.url==='http://localhost/reconnected'&&r.response.body.state==='available'),'replacement owner');
    assert.notEqual(s.network.requests.find(r=>r.url==='http://localhost/reconnected').capture_owner,oldOwner);
    s=await until(s=>s.network.requests.some(r=>r.url==='http://localhost/replacement-body'&&r.response.body.state==='available'),'replacement body completed');
    const retired=s.network.requests.find(r=>r.url==='http://localhost/retired-body');
    assert.equal(retired.capture_owner,oldOwner);assert.equal(retired.response.body.state,'error');
    assert.match(retired.response.body.reason,/disconnected|closed/);
    assert.equal(s.network.requests.find(r=>r.url==='http://localhost/replacement-body').response.body.text,'body:a:slow');
    assert(s.network.requests.some(r=>r.id===a.id),'Completed old owner evidence retained');
    send('b','Network.requestWillBeSent',request('close-pending'));
    await until(s=>s.network.requests.some(r=>r.protocol_request_id==='close-pending'),'closed target pending');
    targets.splice(targets.indexOf('b'),1);
    s=await until(s=>s.network.capture_status.attached_targets===1&&s.network.requests.some(r=>r.protocol_request_id==='close-pending'&&r.state==='failed'),'closed target retained');
    assert(s.network.requests.some(r=>r.id===b.id));
    setDiscoveryFailure(true);
    await until(s=>s.network.capture_status.discovery_stale===true&&s.network.capture_status.state==='partial','discovery failure visible');
    send('a','Network.requestWillBeSent',request('during-discovery-failure'));complete(send,'a','during-discovery-failure');
    await until(s=>s.network.requests.some(r=>r.protocol_request_id==='during-discovery-failure'&&r.response.body.state==='available'),'healthy owner continues during discovery failure');
    setDiscoveryFailure(false);
    await until(s=>s.network.capture_status.discovery_stale===false,'discovery recovery');
    targets.push('retry');
    await until(s=>s.network.capture_status.failed_targets===1,'initialization retry reported');
    await until(s=>s.network.capture_status.attached_targets===2&&s.network.capture_status.failed_targets===0,'initialization retry recovers');
    targets.push(...Array.from({length:9},(_,i)=>`extra-${i}`));
    s=await until(s=>s.network.capture_status.attached_targets===8&&s.network.capture_status.eligible_targets===11,'bounded owners');
    assert.equal(s.network.capture_status.attached_target_ids.length,8);
    assert.equal(s.network.capture_status.unattached_targets.length,3);
    assert(s.network.capture_status.unattached_targets.every(t=>!s.network.capture_status.attached_target_ids.includes(t.id)));
    assert.equal(s.network.capture_status.target_overflow,3);assert.equal(s.network.capture_status.state,'partial');
    const commands=(await readFile(join(directory,'commands.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);
    assert(commands.filter(c=>c.role==='capture').every(c=>['Network.enable','Network.getResponseBody'].includes(c.method)),'Capture owners must never pause, reload, or enable debugger domains');
    console.log('PASS multi-target HTTP: automatic attach, exact owner bodies, focus retention, redirects, disconnect/replacement, closure, retries, capacity and explicit pre-attachment gaps');
  });
  await fixture(false,async({until,directory})=>{
    const s=await until(s=>s.state==='running','disabled capture');
    assert.equal(s.network.capture_status.state,'disabled');assert.equal(s.network.requests.length,0);
    const commands=(await readFile(join(directory,'commands.jsonl'),'utf8')).trim().split('\n').map(JSON.parse);
    assert(!commands.some(c=>c.method==='Network.enable'));
    console.log('PASS multi-target HTTP: metadata-only capture remains disabled');
  });
}
