// Deterministic browser-level flattened CDP lifecycle tests. No actual browser.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {appendFileSync,existsSync,readFileSync,writeFileSync} from 'node:fs';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const script=fileURLToPath(import.meta.url),delay=ms=>new Promise(r=>setTimeout(r,ms));
if(process.argv[2]==='--transport') {
  const directory=process.env.REB_CAPTURE_FIXTURE;
  const browser=process.argv.at(-1).includes('/devtools/browser/');
  const log=value=>appendFileSync(join(directory,'commands'),JSON.stringify({...value,browser,pid:process.pid,time:Date.now()})+'\n');
  const emit=value=>{const body=value===null?Buffer.alloc(0):Buffer.from(JSON.stringify(value));const header=Buffer.from([82,69,66,1,0,0,0,0]);header.writeUInt32BE(body.length,4);process.stdout.write(Buffer.concat([header,body]));};
  const targets=()=>JSON.parse(readFileSync(join(directory,'targets'),'utf8'));
  const options=JSON.parse(readFileSync(join(directory,'options'),'utf8'));
  const sessions=new Map(),alternates=new Map(),autoParents=new Set();let snapshots=0;let serial=0,pending=Buffer.alloc(0),discovering=false,delayedAdmission=false;
  let cursor=readFileSync(join(directory,'events'),'utf8').split('\n').filter(Boolean).length;
  function attach(info,parent) {
    if(sessions.has(info.targetId))return sessions.get(info.targetId);
    const sessionId=`${process.pid}:${++serial}:${info.targetId}`;sessions.set(info.targetId,sessionId);
    emit({method:'Target.attachedToTarget',params:{sessionId,targetInfo:info,waitingForDebugger:info.waiting===true},...(parent?{sessionId:parent}:{})});return sessionId;
  }
  // Parent detach invalidates descendant sessions without fabricating child
  // detach events. This is the lifecycle edge the production cascade must own.
  function invalidate(id) {
    for(const child of targets().filter(t=>t.parent===id))invalidate(child.targetId);
    sessions.delete(id);
  }
  log({event:'open'});emit(null);
  process.stdin.on('data',chunk=>{
    pending=Buffer.concat([pending,chunk]);
    while(pending.length>=8&&pending.length>=8+pending.readUInt32BE(4)) {
      const size=pending.readUInt32BE(4),m=JSON.parse(pending.subarray(8,8+size));pending=pending.subarray(8+size);
      log({event:'command',...m});
      const reply=result=>emit({id:m.id,result,...(m.sessionId?{sessionId:m.sessionId}:{})});
      const target=[...sessions].find(([,sid])=>sid===m.sessionId)?.[0];
      if(m.method==='Network.enable'&&(target==='reset-failure'||(target==='retry'&&!existsSync(join(directory,'failed-once'))))) {
        writeFileSync(join(directory,'failed-once'),'1');emit({id:m.id,sessionId:m.sessionId,error:{code:-32000,message:'synthetic initialization failure'}});continue;
      }
      if(browser&&m.method==='Target.setDiscoverTargets'&&options.unsupportedDiscovery&&!existsSync(join(directory,'discovery-supported'))) {log({event:'unsupported-discovery'});emit({id:m.id,error:{code:-32601,message:'synthetic unsupported browser discovery'}});}
      else if(m.method==='Target.setDiscoverTargets') {discovering=m.params.discover;reply({});}
      else if(browser&&m.method==='Target.getTargets'&&options.setupFailure) {
        if(options.setupFailure==='timeout')continue;
        if(options.setupFailure==='rejected')emit({id:m.id,error:{code:-32601,message:'synthetic setup rejection'}});
        else reply({targetInfos:null});
      }
      else if(m.method==='Target.getTargets') {
        const snapshot=targets().filter(t=>!options.snapshotRootsOnly||!t.parent);snapshots++;
        if(options.reconcileDestroy&&snapshots===2) {
          writeFileSync(join(directory,'targets'),JSON.stringify(snapshot.filter(t=>t.targetId!=='z509')));
          emit({method:'Target.targetDestroyed',params:{targetId:'z509'}});
          setTimeout(()=>{log({event:'stale-reconcile-reply'});reply({targetInfos:snapshot});},300);
        } else reply({targetInfos:snapshot});
        if(options.snapshotDestroy&&snapshot.some(t=>t.targetId==='ghost')) {
          writeFileSync(join(directory,'targets'),JSON.stringify(snapshot.filter(t=>t.targetId!=='ghost')));
          if(discovering)emit({method:'Target.targetDestroyed',params:{targetId:'ghost'}});
        }
      }
      else if(m.method==='Target.attachToTarget') {
        const info=targets().find(t=>t.targetId===m.params.targetId);
        if(options.slowReply&&info?.targetId==='slow-reply') {const sessionId=attach(info);setTimeout(()=>reply({sessionId}),2500);}
        else if(options.lateFailure&&info?.targetId==='doomed') {
          setTimeout(()=>emit({id:m.id,error:{code:-32000,message:'synthetic late attach failure'}}),400);
        } else if(options.slowAdmission&&info?.targetId==='slow-admission') {
          setTimeout(()=>reply({sessionId:attach(info)}),1500);
        } else if(options.delayedAdmission&&info?.targetId==='c'&&!delayedAdmission) {
          delayedAdmission=true;log({event:'reservation-race'});
          // The newer auto-attachment arrives before the reserved manual one.
          attach(targets().find(t=>t.targetId==='d'),sessions.get('b'));
          setTimeout(()=>reply({sessionId:attach(info)}),350);
        } else reply({sessionId:info?attach(info):'missing'});
      }
      else if(m.method==='Target.detachFromTarget'&&options.detachRace&&m.params.sessionId?.startsWith('alternate:race')) {
        const alternate=alternates.get(m.params.sessionId);
        if(options.detachRace==='transport') {log({event:'cleanup-transport-fault'});process.exit(0);}
        if(options.detachRace==='wrong-parent'&&alternate)emit({method:'Target.detachedFromTarget',params:{sessionId:m.params.sessionId,targetId:alternate.target},sessionId:'unrelated-parent-session'});
        if(options.detachRace==='destroyed'&&alternate){writeFileSync(join(directory,'targets'),JSON.stringify(targets().filter(t=>t.targetId!==alternate.target)));invalidate(alternate.target);alternates.delete(m.params.sessionId);emit({method:'Target.targetDestroyed',params:{targetId:alternate.target}});log({event:'confirmed-cleanup-destroyed'});}
        if(options.detachRace==='wrong-session'&&alternate)emit({method:'Target.detachedFromTarget',params:{sessionId:'unrelated-old-session',targetId:alternate.target},sessionId:alternate.parent});
        if((options.detachRace==='confirmed'||options.detachRace==='confirmed-transport')&&alternate) {
          alternates.delete(m.params.sessionId);
          emit({method:'Target.detachedFromTarget',params:{sessionId:m.params.sessionId,targetId:alternate.target},sessionId:alternate.parent});
          log({event:'confirmed-cleanup-detach'});
          if(options.detachRace==='confirmed-transport'){log({event:'cleanup-transport-fault'});setTimeout(()=>process.exit(0),50);continue;}
        }
        setTimeout(()=>{log({event:'cleanup-error-reply'});emit({id:m.id,...(m.sessionId?{sessionId:m.sessionId}:{}),error:{code:-32602,message:'No session with given id'}});},300);
        continue;
      }
      else if(m.method==='Target.detachFromTarget'&&options.slowDetach) {setTimeout(()=>{log({event:'delayed-detach-reply'});reply({});},800);}
      else if(m.method==='Network.getResponseBody')setTimeout(()=>reply({body:`body:${m.sessionId}:${m.params.requestId}`,base64Encoded:false}),m.params.requestId==='slow'?1500:0);
      else reply({});
      if(browser&&m.method==='Target.setAutoAttach'&&m.params.autoAttach) {
        if(m.sessionId)autoParents.add(m.sessionId);
        for(const info of targets().filter(t=>m.sessionId?t.parent===target:!t.parent))attach(info,m.sessionId);
      }
      if(browser&&m.method==='Target.detachFromTarget') {
        const alternate=alternates.get(m.params.sessionId);
        if(alternate){alternates.delete(m.params.sessionId);emit({method:'Target.detachedFromTarget',params:{sessionId:m.params.sessionId,targetId:alternate.target},sessionId:alternate.parent});continue;}
        const entry=[...sessions].find(([,sid])=>sid===m.params.sessionId);
        if(entry){invalidate(entry[0]);emit({method:'Target.detachedFromTarget',params:{sessionId:entry[1],targetId:entry[0]}});}
      }
    }
  });
  setInterval(()=>{
    const events=readFileSync(join(directory,'events'),'utf8').split('\n').filter(Boolean);
    while(cursor<events.length) {
      const event=JSON.parse(events[cursor++]);if(!browser)continue;
      if(event.disconnect)process.exit(0);
      if(event.duplicate){const targetInfo=targets().find(t=>t.targetId===event.duplicate),parent=sessions.get(event.parent),sessionId=`alternate:${event.key}`;alternates.set(sessionId,{target:event.duplicate,parent});emit({method:'Target.attachedToTarget',params:{sessionId,targetInfo,waitingForDebugger:false},sessionId:parent});if(event.gone){alternates.delete(sessionId);emit({method:'Target.detachedFromTarget',params:{sessionId,targetId:event.duplicate},sessionId:parent});log({event:'queued-cleanup-detached',sessionId});}continue;}
      if(event.add) {const info=targets().find(t=>t.targetId===event.add);emit({method:'Target.targetCreated',params:{targetInfo:info}});const parent=info.parent?sessions.get(info.parent):undefined;if(parent&&autoParents.has(parent))attach(info,parent);continue;}
      if(event.destroy){const sid=sessions.get(event.destroy);sessions.delete(event.destroy);emit({method:'Target.targetDestroyed',params:{targetId:event.destroy}});if(sid)emit({method:'Target.detachedFromTarget',params:{sessionId:sid,targetId:event.destroy}});continue;}
      if(event.detach){const sid=sessions.get(event.detach);invalidate(event.detach);emit({method:'Target.detachedFromTarget',params:{sessionId:sid,targetId:event.detach}});continue;}
      const sessionId=sessions.get(event.target);if(sessionId)emit({method:event.method,params:event.params,sessionId});
    }
  },15);
} else {
  const root=resolve(process.argv[2]??'.'),binary=resolve(process.env.ORIGIN_TRACE_BACKEND||join(root,'apps/origin-trace-backend/target/debug/origin-trace-backend'));
  const info=(id,type='page',parent)=>({targetId:id,type,title:id,url:`http://localhost/${id}`,...(parent?{parent}:{})});
  async function fixture(initial,options,run) {
    if(process.env.REB_EXTRA_STATUS_ONLY==='1'&&!options.extraStatus)return;
    if(process.env.REB_ENDPOINT_ONLY==='1'&&!options.endpointCase)return;
    if(process.env.REB_TERMINAL_HANDOFF_ONLY==='1'&&!options.terminalHandoff)return;
    if(process.env.REB_CLEANUP_REGRESSION_ONLY==='1'&&(options.terminalHandoff||options.endpointCase||options.extraStatus))return;
    const directory=await mkdtemp(join(tmpdir(),'reb-browser-sessions-'));let backend,exited,address,diagnostics='';let targets=initial;
    await writeFile(join(directory,'options'),JSON.stringify(options));
    const save=()=>writeFileSync(join(directory,'targets'),JSON.stringify(targets));save();await writeFile(join(directory,'events'),'');await writeFile(join(directory,'commands'),'');
    const server=createServer((_req,res)=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify(targets.filter(t=>t.type==='page').map(t=>({...t,id:t.targetId,webSocketDebuggerUrl:`ws://127.0.0.1:${server.address().port}/devtools/page/${t.targetId}`}))));});
    await new Promise(r=>server.listen(0,'127.0.0.1',r));
    const send=value=>appendFileSync(join(directory,'events'),JSON.stringify(value)+'\n');
    const commands=()=>readFileSync(join(directory,'commands'),'utf8').split('\n').filter(Boolean).map(JSON.parse);
    const state=async()=>{address??=(await readFile(join(directory,'endpoint'),'utf8')).trim();return(await fetch(new URL('/api/debugger',address),{signal:AbortSignal.timeout(2000)})).json();};
    async function until(predicate,label,timeout=15000) {
      const end=Date.now()+timeout;let last;
      while(Date.now()<end) {
        assert.equal(backend.exitCode,null,diagnostics);
        try{last=await state();if(await predicate(last))return last;}catch(error){if(error instanceof assert.AssertionError)throw error;}
        await delay(30);
      }
      assert.fail(`${label}: ${JSON.stringify(last?.network?.capture_status)} ${diagnostics}`);
    }
    try {
      const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
      if(options.endpointCase!=='missing')await writeFile(join(directory,'active'),options.endpointCase==='malformed'?'invalid\n':`${server.address().port}\n/devtools/browser/fixture\n`);
      await writeFile(join(directory,'transport'),`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(script)} --transport "$@"\n`,{mode:0o700});
      backend=spawn(binary,['--port','0','--endpoint-file',join(directory,'endpoint'),'--devtools-active-port',join(directory,'active'),'--debugger-transport',join(directory,'transport'),...(options.capture===false?[]:['--capture-network-content']),...(options.limit?['--capture-target-limit',String(options.limit)]:[])],{cwd:directory,env:{...process.env,REB_CAPTURE_FIXTURE:directory}});
      exited=new Promise(r=>{backend.once('exit',r);backend.once('error',e=>{diagnostics+=e.message;r();});});
      for(const stream of [backend.stdout,backend.stderr])stream.on('data',chunk=>diagnostics=(diagnostics+chunk).slice(-8192));
      await run({send,state,until,commands,publishEndpoint:()=>writeFile(join(directory,'active'),`${server.address().port}\n/devtools/browser/fixture\n`),supportDiscovery:()=>writeFile(join(directory,'discovery-supported'),'1'),forget:id=>{targets=targets.filter(t=>t.targetId!==id);save();},add:t=>{targets.push(t);save();send({add:t.targetId});},destroy:id=>{targets=targets.filter(t=>t.targetId!==id);save();send({destroy:id});}});
    } finally {
      if(backend?.exitCode===null&&backend.signalCode===null){backend.kill('SIGTERM');await Promise.race([exited,delay(3000)]);if(backend.exitCode===null&&backend.signalCode===null){backend.kill('SIGKILL');await exited;}}
      await new Promise(r=>server.close(r));await rm(directory,{recursive:true,force:true});
    }
  }
  const request=(send,target,id,path=id)=>send({target,method:'Network.requestWillBeSent',params:{requestId:id,timestamp:1,wallTime:1,type:'Fetch',request:{url:`http://localhost/${path}`,method:'GET',headers:{}}}});
  const finish=(send,target,id)=>{send({target,method:'Network.responseReceived',params:{requestId:id,response:{status:200,headers:{}}}});send({target,method:'Network.loadingFinished',params:{requestId:id,timestamp:2,encodedDataLength:10}});};
  for(const endpointCase of ['missing','malformed','unsupported'])await fixture([info('page'),info('worker','worker','page')],{endpointCase,snapshotRootsOnly:true,unsupportedDiscovery:endpointCase==='unsupported'},async({until,state,commands,publishEndpoint,supportDiscovery})=>{
    if(endpointCase==='missing') {
      await until(s=>s.state==='waiting'&&s.error==='Waiting for the authorized browser debugger','Missing endpoint observed by refresh');
      assert.equal(commands().filter(c=>c.event==='open'&&c.browser).length,0,'Absent endpoint cannot attempt browser transport');
      const published=Date.now();await publishEndpoint();
      const ready=await until(s=>s.network.capture_status.transport_mode==='browser-sessions'&&s.network.capture_status.attached_targets===2,'Published endpoint captures page and recursive worker without capability backoff',10000);
      assert.ok(Date.now()-published<10000,'Published endpoint must recover on normal refresh, before 30-second capability backoff');
      assert.ok(commands().some(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':worker')),'Recursive worker capture enabled');
      assert.equal(ready.network.capture_status.transport_mode,'browser-sessions');
      assert.equal(ready.network.capture_status.browser_setup_failure,null);
    } else {
      await until(s=>s.network.capture_status.transport_mode==='page-fallback'&&String(s.network.capture_status.last_error).includes(endpointCase==='malformed'?'endpoint is incomplete':'synthetic unsupported browser discovery'),`${endpointCase}: known capability failure observed`);
      const attempts=commands().filter(c=>c.event==='open'&&c.browser).length;
      assert.equal(attempts,endpointCase==='unsupported'?1:0,'Only published valid endpoint opens browser transport');
      if(endpointCase==='unsupported')await supportDiscovery();
      await publishEndpoint();
      // Cross two regular one-second refresh intervals without waiting 30 seconds.
      await delay(2200);
      const current=await state();
      assert.equal(commands().filter(c=>c.event==='open'&&c.browser).length,attempts,'Known endpoint/capability failure must retain browser retry backoff');
      assert.equal(current.network.capture_status.transport_mode,'page-fallback');
      assert.deepEqual(current.network.capture_status.browser_setup_failure,endpointCase==='malformed'?{stage:'endpoint',reason:'state-conflict'}:{stage:'discover-targets',reason:'command-rejected'});
    }
    console.log(`PASS endpoint startup: ${endpointCase}`);
  });
  for(const setupFailure of ['timeout','rejected','shape'])await fixture([info('page')],{endpointCase:'diagnostic',setupFailure},async({until,state})=>{
    const expected={stage:setupFailure==='shape'?'get-targets-shape':'get-targets',reason:setupFailure==='timeout'?'timeout':setupFailure==='rejected'?'command-rejected':'protocol-error'};
    await until(s=>s.network.capture_status.transport_mode==='page-fallback'&&s.network.capture_status.browser_setup_failure?.reason===expected.reason,`Structured setup diagnostic: ${setupFailure}`);
    await delay(1200);
    assert.deepEqual((await state()).network.capture_status.browser_setup_failure,expected,'Structured setup diagnostic survives fallback refresh');
    console.log(`PASS browser setup diagnostic: ${setupFailure}`);
  });
  await fixture([info('a'),info('b')],{extraStatus:true},async({send,until,commands})=>{
    await until(s=>s.network.capture_status.attached_targets===2,'ExtraInfo owners ready');
    const extra=(target,id,statusCode)=>send({target,method:'Network.responseReceivedExtraInfo',params:{requestId:id,statusCode,headers:{}}});
    const response=(target,id,status,fromDiskCache=false)=>send({target,method:'Network.responseReceived',params:{requestId:id,response:{status,fromDiskCache,headers:{}}}});
    let serial=0;
    const barrier=async()=>{const id=`extra-barrier-${++serial}`;request(send,'b',id);finish(send,'b',id);return until(s=>s.network.requests.some(r=>r.protocol_request_id===id&&r.response.body.state==='available'),'ExtraInfo processing barrier');};
    const rows=(s,id,target='a')=>s.network.requests.filter(r=>r.target_id===target&&r.protocol_request_id===id);
    const check=(s,id,status,status_source,wire_status,target='a')=>{const r=rows(s,id,target).at(-1);assert.ok(r,`${id}: retained row`);assert.deepEqual({status:r.status,status_source:r.status_source,wire_status:r.wire_status},{status,status_source,wire_status},id);};
    request(send,'a','fresh');check(await barrier(),'fresh',null,'unavailable',null);
    extra('a','before',201);request(send,'a','before');check(await barrier(),'before',201,'response-received-extra-info',201);
    request(send,'a','after');extra('a','after',202);check(await barrier(),'after',202,'response-received-extra-info',202);
    response('a','after',200);check(await barrier(),'after',200,'response-received',202);
    request(send,'a','cached');response('a','cached',200,true);extra('a','cached',304);check(await barrier(),'cached',200,'response-received',304);
    request(send,'a','only304');extra('a','only304',304);check(await barrier(),'only304',null,'unavailable',304);
    request(send,'a','duplicate');extra('a','duplicate',203);check(await barrier(),'duplicate',203,'response-received-extra-info',203);
    extra('a','duplicate',203);check(await barrier(),'duplicate',null,'unavailable',null);
    for(const [label,value] of [['zero',0],['low',99],['high',600],['fraction',200.5],['string','200'],['missing',undefined],['null',null]]){
      const id=`invalid-${label}`;request(send,'a',id);extra('a',id,200);extra('a',id,value);check(await barrier(),id,null,'unavailable',null);
    }
    for(const [label,value] of [['null',null],['string','200'],['missing',undefined]])for(const order of ['before','after']){
      const id=`malformed-response-${label}-${order}`;request(send,'a',id);
      if(order==='before')extra('a',id,200);
      response('a',id,value);
      if(order==='after')extra('a',id,200);
      check(await barrier(),id,null,'response-received',200);
    }
    for(const order of ['before','after']){
      const id=`nonobject-response-${order}`;request(send,'a',id);
      if(order==='before')extra('a',id,200);
      send({target:'a',method:'Network.responseReceived',params:{requestId:id,response:null}});
      if(order==='after')extra('a',id,200);
      check(await barrier(),id,null,'unavailable',200);
    }
    response('a','response-before-start',200);request(send,'a','response-before-start');extra('a','response-before-start',200);check(await barrier(),'response-before-start',null,'unavailable',200);
    extra('a','bad-before','200');extra('a','bad-before',200);request(send,'a','bad-before');check(await barrier(),'bad-before',null,'unavailable',null);
    extra('b','cross-owner',204);request(send,'a','cross-owner');check(await barrier(),'cross-owner',null,'unavailable',null);
    request(send,'b','cross-owner');check(await barrier(),'cross-owner',204,'response-received-extra-info',204,'b');
    request(send,'a','reuse');extra('a','reuse',205);await barrier();request(send,'a','reuse','reused');
    let s=await barrier();for(const r of rows(s,'reuse'))assert.deepEqual([r.status,r.status_source,r.wire_status],[null,'unavailable',null],'Raw ID reuse invalidates fallback on every retained hop');
    request(send,'a','redirect');extra('a','redirect',200);await barrier();
    send({target:'a',method:'Network.requestWillBeSent',params:{requestId:'redirect',timestamp:2,wallTime:2,type:'Fetch',request:{url:'http://localhost/redirected',method:'GET',headers:{}},redirectResponse:{status:302,headers:{}}}});
    s=await barrier();const redirected=rows(s,'redirect');assert.equal(redirected.length,2);assert.deepEqual([redirected[0].status,redirected[0].status_source,redirected[0].wire_status],[302,'redirect-response',null]);check(s,'redirect',null,'unavailable',null);
    request(send,'a','duplicate-response');response('a','duplicate-response',200);extra('a','duplicate-response',200);response('a','duplicate-response',200);check(await barrier(),'duplicate-response',200,'response-received',null);
    send({target:'a',method:'Network.requestWillBeSent',params:{requestId:'explicit-null-redirect',timestamp:1,wallTime:1,type:'Fetch',request:{url:'http://localhost/null-redirect',method:'GET',headers:{}},redirectResponse:null}});
    extra('a','explicit-null-redirect',200);check(await barrier(),'explicit-null-redirect',null,'unavailable',null);
    request(send,'a','authoritative');response('a','authoritative',206);extra('a','authoritative',206);extra('a','authoritative',206);check(await barrier(),'authoritative',206,'response-received',null);
    // A newly attached same-target session cannot consume the old owner's buffer.
    extra('a','replacement',207);await barrier();const old=commands().filter(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':a')).length;send({detach:'a'});
    await until(s=>s.network.capture_status.attached_targets===2&&commands().filter(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':a')).length>old,'Replacement owner ready');
    request(send,'a','replacement');check(await barrier(),'replacement',null,'unavailable',null);
    extra('a','connection-replacement',208);await barrier();const opens=commands().filter(c=>c.event==='open'&&c.browser).length;send({disconnect:true});
    await until(s=>s.network.capture_status.attached_targets===2&&commands().filter(c=>c.event==='open'&&c.browser).length>opens,'New connection owns distinct ExtraInfo namespace',45000);
    request(send,'a','connection-replacement');check(await barrier(),'connection-replacement',null,'unavailable',null);
    console.log('PASS ExtraInfo status provenance, order, cache, ambiguity, owner isolation and replacement');
  });
  await fixture([info('a')],{extraStatus:true},async({send,until})=>{
    await until(s=>s.network.capture_status.attached_targets===1,'ExtraInfo eviction owner ready');
    for(let i=0;i<999;i++)request(send,'a',`extra-eviction-${i}`);
    request(send,'a','retained-before-eviction');send({target:'a',method:'Network.responseReceivedExtraInfo',params:{requestId:'retained-before-eviction',statusCode:201,headers:{}}});
    await until(s=>s.network.requests.some(r=>r.protocol_request_id==='retained-before-eviction'&&r.status===201),'Valid fallback exists before history loss');
    request(send,'a','overflow-trigger');
    const overflow=await until(s=>s.network.dropped>0,'Evicted history is explicit');
    const prior=overflow.network.requests.find(r=>r.protocol_request_id==='retained-before-eviction');assert.ok(prior);assert.deepEqual([prior.status,prior.status_source,prior.wire_status],[null,'unavailable',null],'Unrelated history loss retracts retained fallback immediately');
    request(send,'a','post-eviction');send({target:'a',method:'Network.responseReceivedExtraInfo',params:{requestId:'post-eviction',statusCode:200,headers:{}}});
    request(send,'a','eviction-barrier');finish(send,'a','eviction-barrier');
    const s=await until(s=>s.network.requests.some(r=>r.protocol_request_id==='eviction-barrier'&&r.response.body.state==='available'),'Eviction event processing barrier');
    const r=s.network.requests.find(r=>r.protocol_request_id==='post-eviction');assert.deepEqual([r.status,r.status_source,r.wire_status],[null,'unavailable',null],'Lost history refuses ExtraInfo attribution');
    console.log('PASS ExtraInfo refuses dropped history');
  });
  await fixture([info('a')],{extraStatus:true},async({send,until})=>{
    await until(s=>s.network.capture_status.attached_targets===1,'ExtraInfo capacity owner ready');
    request(send,'a','before-capacity');send({target:'a',method:'Network.responseReceivedExtraInfo',params:{requestId:'before-capacity',statusCode:201,headers:{}}});
    await until(s=>s.network.requests.some(r=>r.protocol_request_id==='before-capacity'&&r.status===201),'Fallback established before tombstone saturation');
    for(let i=0;i<2048;i++)send({target:'a',method:'Network.responseReceivedExtraInfo',params:{requestId:`extra-capacity-${i}`,statusCode:200,headers:{}}});
    const saturated=await until(s=>s.network.capture_status.status_extra_info_overflow===true,'ExtraInfo identity capacity is visible');
    assert.equal(saturated.network.dropped,0,'Identity cap is separate from HTTP row eviction');
    const prior=saturated.network.requests.find(r=>r.protocol_request_id==='before-capacity');assert.deepEqual([prior.status,prior.status_source,prior.wire_status],[null,'unavailable',null]);
    request(send,'a','after-capacity');finish(send,'a','after-capacity');
    const s=await until(s=>s.network.requests.some(r=>r.protocol_request_id==='after-capacity'&&r.response.body.state==='available'),'Authoritative capture continues after identity cap');
    const r=s.network.requests.find(r=>r.protocol_request_id==='after-capacity');assert.deepEqual([r.status,r.status_source,r.wire_status],[200,'response-received',null]);assert.equal(s.network.capture_status.status_extra_info_overflow,true);
    console.log('PASS ExtraInfo identity capacity visible and authoritative capture unaffected');
  });
  const handoffCases=[
    ['iframe','Document','iframe',true],['worker','Script','worker',true],['shared-worker','Script','shared_worker',true],
    ['normal-collision','Document','iframe',false],['completed-collision','Document','iframe',false],['redirect-collision','Document','iframe',false],
    ['evicted-collision','Document','iframe',false],['malformed-parent','Document','iframe',false],['malformed-worker-parent','Script','worker',false],['empty-parent','Document','iframe',false],['oversized-parent','Document','iframe',false],
    ['wrong-frame','Document','iframe',false],['wrong-loader','Document','iframe',false],['wrong-parent','Document','iframe',false],
    ['wrong-url','Script','worker',false],['wrong-type','Fetch','iframe',false],['terminal-failed','Document','iframe',false],
    ['old-terminal-time','Document','iframe',false],['retired-source','Script','worker',false],['old-connection','Document','iframe',false],
  ];
  for(const [label,type,destinationType,positive] of handoffCases)await fixture([info('a'),info('other'),{...info('child',destinationType,label==='retired-source'?undefined:label==='wrong-parent'?'other':'a'),...(['malformed-parent','malformed-worker-parent'].includes(label)?{parentId:7}:label==='empty-parent'?{parentId:''}:label==='oversized-parent'?{parentId:'p'.repeat(4097)}:{})}],{terminalHandoff:true,snapshotRootsOnly:true},async({send,until,commands,destroy})=>{
    await until(s=>s.network.capture_status.attached_targets===3,`${label}: handoff owners ready`);
    const id=type==='Script'?'child':`main-${label}`;
    const destinationSession=()=>commands().filter(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':child')).at(-1)?.sessionId;
    const start={requestId:id,timestamp:10,wallTime:10,type,loaderId:type==='Script'?'':id,frameId:'child',request:{url:type==='Script'?'http://localhost/child':`http://localhost/main-${label}`,method:'GET',headers:{}}};
    if(label==='wrong-frame')start.frameId='other-frame';
    if(label==='wrong-loader')start.loaderId='other-loader';
    if(label==='wrong-url')start.request.url='http://localhost/unrelated-script';
    if(label==='normal-collision'||label==='completed-collision'){
      request(send,'other',id,'unrelated-collision');
      if(label==='completed-collision')finish(send,'other',id);
    }
    if(label==='evicted-collision'){
      request(send,'other',id,'evicted-original-collision');
      await until(s=>s.network.requests.some(r=>r.target_id==='other'&&r.protocol_request_id===id),'Earlier collision is admitted before eviction setup');
      // Exercise row-history eviction, not transport queue saturation. Wait for
      // each bounded batch to be consumed before sending the next batch.
      for(let i=0;i<1000;i++){
        request(send,'other',`eviction-${i}`);
        if((i+1)%50===0){
          const admitted=await until(s=>s.network.requests.some(r=>r.target_id==='other'&&r.protocol_request_id===`eviction-${i}`),'Eviction setup batch is admitted');
          assert.equal(admitted.network.capture_status.gaps,0,'Eviction setup must not lose transport events');
        }
      }
      await until(s=>s.network.dropped>0&&!s.network.requests.some(r=>r.protocol_request_id===id),'Earlier colliding row is evicted before candidate starts');
    }
    send({target:'a',method:'Network.requestWillBeSent',params:start});
    if(label==='redirect-collision')send({target:'a',method:'Network.requestWillBeSent',params:{...start,timestamp:10.5,redirectResponse:{status:302,headers:{},url:start.request.url,encodedDataLength:0}}});
    send({target:'a',method:'Network.responseReceived',params:{requestId:id,response:{status:200,headers:{},mimeType:'text/plain',url:start.request.url}}});
    let s=await until(s=>s.network.requests.some(r=>r.target_id==='a'&&r.protocol_request_id===id&&r.state==='pending'&&r.status===200),`${label}: source response retained`);
    const original=s.network.requests.filter(r=>r.target_id==='a'&&r.protocol_request_id===id).at(-1);
    if(label==='retired-source'){
      destroy('a');
      await until(s=>s.network.requests.find(r=>r.id===original.id)?.state!=='pending','Source retires before child completion');
      await until(s=>s.network.capture_status.attached_target_ids.includes('child'),'Child reattached after source retirement');
    }
    if(label==='old-connection'){
      const opens=commands().filter(c=>c.event==='open'&&c.browser).length;
      send({disconnect:true});
      await until(s=>commands().filter(c=>c.event==='open'&&c.browser).length>opens&&s.network.capture_status.attached_targets===3,'New connection cannot complete old resource',45000);
    }
    const terminalSession=destinationSession();
    send({target:'child',method:label==='terminal-failed'?'Network.loadingFailed':'Network.loadingFinished',params:{requestId:id,timestamp:label==='old-terminal-time'?9:11,encodedDataLength:10,errorText:'synthetic failure'}});
    if(positive){
      s=await until(s=>s.network.requests.find(r=>r.id===original.id)?.response.body.state==='available',`${label}: terminal handoff body available`);
      const row=s.network.requests.find(r=>r.id===original.id);
      assert.equal(row.capture_owner,original.capture_owner,'Handoff preserves original evidence owner');
      assert.equal(row.target_id,'a','Handoff preserves original initiating target');
      assert.equal(row.state,'complete','Observed child loadingFinished completes original row');
      const body=commands().filter(c=>c.method==='Network.getResponseBody'&&c.params.requestId===id);
      assert.equal(body.length,1,'A proven handoff retrieves exactly one body');
      assert.equal(body[0].sessionId,terminalSession,'Body retrieval uses exact destination session');
      assert.equal(row.response.body.text,`body:${terminalSession}:${id}`);
    }else{
      request(send,'other',`sentinel-${label}`);finish(send,'other',`sentinel-${label}`);
      s=await until(s=>s.network.requests.some(r=>r.protocol_request_id===`sentinel-${label}`&&r.response.body.state==='available'),`${label}: event barrier and healthy owner continue`);
      if(label==='evicted-collision')assert.equal(s.network.capture_status.gaps,0,'Eviction rejection must not rely on a transport reconnect');
      const row=s.network.requests.find(r=>r.id===original.id);
      assert.equal(row.state,['retired-source','old-connection'].includes(label)?'failed':'pending',`${label}: unsupported completion cannot adopt source row`);
      assert(!commands().some(c=>c.method==='Network.getResponseBody'&&c.params.requestId===id&&c.sessionId===terminalSession),`${label}: destination body is never borrowed without proof`);
    }
    console.log(`PASS terminal handoff: ${label} ${positive?'preserves source evidence and retrieves child body':'rejects unsafe adoption'}`);
  });
  // A negative detach reply is safe only when this exact session's lifetime
  // has already ended. Target identity alone must not retire a live owner.
  await fixture([info('service','service_worker'),info('page')],{detachRace:'confirmed'},async({send,until,commands})=>{
    await until(s=>s.network.capture_status.attached_targets===2,'Race owners ready');
    for(const target of ['service','page']){request(send,target,`before-${target}`);finish(send,target,`before-${target}`);}
    let s=await until(s=>s.network.requests.filter(r=>r.response.body.state==='available').length===2,'Initial race evidence');
    const owners=new Map(s.network.requests.map(r=>[r.target_id,r.capture_owner]));
    const opens=commands().filter(c=>c.event==='open'&&c.browser).length,gaps=s.network.capture_status.gaps;
    send({duplicate:'service',parent:'page',key:'race-reply'});
    await until(()=>commands().some(c=>c.event==='cleanup-error-reply'),'Confirmed session disappears before error reply');
    s=await until(s=>(s.network.capture_status.cleanup_already_gone??0)>0||s.network.capture_status.gaps>gaps||commands().filter(c=>c.event==='open'&&c.browser).length>opens,'Cleanup rejection processed');
    assert(commands().filter(c=>c.event==='open'&&c.browser).length===opens&&s.network.capture_status.gaps===gaps,'Confirmed redundant detach must not close whole transport');
    assert.equal(s.network.capture_status.cleanup_already_gone,1);
    assert.equal(s.network.capture_status.cleanup_failures??0,0);
    for(const target of ['service','page']){request(send,target,`after-${target}`);finish(send,target,`after-${target}`);}
    s=await until(s=>['service','page'].every(target=>s.network.requests.some(r=>r.protocol_request_id===`after-${target}`&&r.response.body.state==='available')),'Healthy owners capture after cleanup race');
    for(const target of ['service','page'])assert.equal(s.network.requests.find(r=>r.protocol_request_id===`after-${target}`).capture_owner,owners.get(target));
    assert.equal(commands().filter(c=>c.event==='open'&&c.browser).length,opens,'Confirmed redundant detach must not close whole transport');
    assert.equal(s.network.capture_status.gaps,gaps,'Confirmed alternate detach must not retire canonical same-target owner');
    console.log('PASS browser sessions: exact detached proof survives negative cleanup reply without losing healthy owners');
  });
  if(process.env.REB_CLEANUP_REGRESSION_ONLY==='1')process.exit(0);
  await fixture([info('service','service_worker'),info('page')],{detachRace:'confirmed'},async({send,until,commands})=>{
    await until(s=>s.network.capture_status.attached_targets===2,'Replacement race owners ready');
    request(send,'service','old-owner');finish(send,'service','old-owner');
    let s=await until(s=>s.network.requests.some(r=>r.protocol_request_id==='old-owner'&&r.response.body.state==='available'),'Old service owner recorded');
    const old=s.network.requests.find(r=>r.protocol_request_id==='old-owner').capture_owner;
    const opens=commands().filter(c=>c.event==='open'&&c.browser).length;
    const oldSessions=commands().filter(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':service')).length;
    send({duplicate:'service',parent:'page',key:'race-replacement'});
    await until(()=>commands().some(c=>c.event==='confirmed-cleanup-detach'),'Old alternate lifetime ends');
    send({detach:'service'});
    await until(s=>s.network.capture_status.attached_targets===2&&commands().filter(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':service')).length>oldSessions,'Same target receives fresh canonical session');
    await until(()=>commands().some(c=>c.event==='cleanup-error-reply'),'Old alternate cleanup reply received');
    await delay(300);
    request(send,'service','new-owner');finish(send,'service','new-owner');
    s=await until(s=>s.network.requests.some(r=>r.protocol_request_id==='new-owner'&&r.response.body.state==='available'),'Replacement owner retains body');
    assert.notEqual(s.network.requests.find(r=>r.protocol_request_id==='new-owner').capture_owner,old);
    assert.equal(commands().filter(c=>c.event==='open'&&c.browser).length,opens,'Stale cleanup must not retire same-target replacement');
    assert.equal(s.network.requests.find(r=>r.protocol_request_id==='old-owner').response.body.state,'available');
    console.log('PASS browser sessions: old alternate cleanup proof cannot retire a fresh owner of the same target');
  });
  await fixture([info('service','service_worker'),info('page')],{slowDetach:true},async({send,until,commands})=>{
    await until(s=>s.network.capture_status.attached_targets===2,'Queued race owners ready');
    const opens=commands().filter(c=>c.event==='open'&&c.browser).length;
    for(let i=0;i<4;i++)send({duplicate:'service',parent:'page',key:`blocker-${i}`});
    await until(()=>commands().filter(c=>c.method==='Target.detachFromTarget').length===4,'Four cleanup slots occupied before vanished fifth');
    send({duplicate:'service',parent:'page',key:'gone-before-command',gone:true});
    await until(()=>commands().some(c=>c.event==='queued-cleanup-detached'),'Queued alternate disappears');
    await until(()=>commands().filter(c=>c.event==='delayed-detach-reply').length===4,'Blocking cleanup drains');
    await delay(250);
    assert(!commands().some(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId==='alternate:gone-before-command'),'Already detached queued session requires no wire cleanup');
    request(send,'page','after-queued-detach');finish(send,'page','after-queued-detach');
    const queued=await until(s=>s.network.requests.some(r=>r.protocol_request_id==='after-queued-detach'&&r.response.body.state==='available'),'Page captures after vanished queued cleanup');
    assert.equal(queued.network.capture_status.cleanup_already_gone,1);
    assert.equal(queued.network.capture_status.cleanup_failures??0,0);
    assert.equal(commands().filter(c=>c.event==='open'&&c.browser).length,opens);
    console.log('PASS browser sessions: detached queued cleanup is skipped without changing active same-target owner');
  });
  await fixture([info('service','service_worker'),info('page')],{detachRace:'destroyed'},async({send,until,commands})=>{
    await until(s=>s.network.capture_status.attached_targets===2,'Destroyed race owners ready');
    const opens=commands().filter(c=>c.event==='open'&&c.browser).length;
    send({duplicate:'service',parent:'page',key:'race-destroyed'});
    await until(()=>commands().some(c=>c.event==='cleanup-error-reply'),'Destroyed target cleanup rejection arrives');
    let s=await until(s=>s.network.capture_status.cleanup_already_gone===1&&s.network.capture_status.attached_targets===1,'Exact target destruction proves cleanup complete');
    assert.equal(s.network.capture_status.cleanup_failures??0,0);
    assert.equal(commands().filter(c=>c.event==='open'&&c.browser).length,opens,'Destroyed child does not close healthy page transport');
    request(send,'page','after-target-destroyed');finish(send,'page','after-target-destroyed');
    await until(s=>s.network.requests.some(r=>r.protocol_request_id==='after-target-destroyed'&&r.response.body.state==='available'),'Healthy page survives destroyed alternate target');
    console.log('PASS browser sessions: exact target destruction proves cleanup without retiring unrelated page');
  });
  for(const detachRace of ['unknown','wrong-session','wrong-parent','transport','confirmed-transport'])await fixture([info('service','service_worker'),info('page')],{detachRace},async({send,state,until,commands})=>{
    await until(s=>s.network.capture_status.attached_targets===2,'Unproven cleanup owners ready');
    const opens=commands().filter(c=>c.event==='open'&&c.browser).length;
    send({duplicate:'service',parent:'page',key:`race-${detachRace}`});
    const recovered=await until(s=>commands().filter(c=>c.event==='open'&&c.browser).length>opens&&s.network.capture_status.attached_targets===2&&s.network.capture_status.gaps>0,'Unproven cleanup still closes and recovers',45000);
    if(['unknown','wrong-session','wrong-parent'].includes(detachRace)) {
      assert.equal(recovered.network.capture_status.cleanup_failures,1,'Fatal cleanup is counted once');
      assert.match(recovered.network.capture_status.last_error,/^Capture detach failed: /,'First fatal cleanup reason survives ensuing EOF');
      await delay(200);
      const stable=(await state()).network.capture_status;
      assert.equal(stable.cleanup_failures,1);
      assert.equal(stable.gaps,recovered.network.capture_status.gaps,'EOF does not double-retire failed cleanup');
      assert.equal(stable.last_error,recovered.network.capture_status.last_error);
    }
    request(send,'page',`recovered-${detachRace}`);finish(send,'page',`recovered-${detachRace}`);
    await until(s=>s.network.requests.some(r=>r.protocol_request_id===`recovered-${detachRace}`&&r.response.body.state==='available'),'Recovery after unproven cleanup');
    console.log(`PASS browser sessions: ${detachRace} cleanup failure remains fail-closed with explicit gap and recovery`);
  });
  await fixture([info('service','service_worker'),...Array.from({length:8},(_,i)=>info(`page${i}`))],{slowDetach:true},async({send,until,commands})=>{
    let s=await until(s=>s.network.capture_status.attached_targets===9,'Root service worker and eight parent pages ready');
    request(send,'service','before-duplicates');finish(send,'service','before-duplicates');
    s=await until(s=>s.network.requests.some(r=>r.protocol_request_id==='before-duplicates'&&r.response.body.state==='available'),'Canonical service worker evidence');
    const owner=s.network.requests.find(r=>r.protocol_request_id==='before-duplicates').capture_owner,opens=commands().filter(c=>c.event==='open'&&c.browser).length,gaps=s.network.capture_status.gaps;
    for(let round=0;round<2;round++){
      for(let i=0;i<8;i++){const event={duplicate:'service',parent:`page${i}`,key:`${round}:${i}`};send(event);send(event);}
      await until(()=>commands().some(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId===`alternate:${round}:0`),'Alternate session cleanup starts');
      request(send,'service',`during-duplicates-${round}`);finish(send,'service',`during-duplicates-${round}`);
      s=await until(s=>s.network.requests.some(r=>r.protocol_request_id===`during-duplicates-${round}`&&r.response.body.state==='available'),'Healthy owner captures during duplicate cleanup');
      const row=s.network.requests.find(r=>r.protocol_request_id===`during-duplicates-${round}`);
      assert.equal(row.capture_owner,owner);assert.equal(row.target_id,'service');
      assert(row.response.body.text.endsWith(`:service:during-duplicates-${round}`));
      await until(()=>commands().filter(c=>c.event==='delayed-detach-reply').length===(round+1)*8,'All distinct duplicate sessions cleaned once');
    }
    assert.equal(commands().filter(c=>c.event==='open'&&c.browser).length,opens,'Duplicate fan-out never reconnects');
    s=await until(s=>s.network.capture_status.attached_targets===9,'Canonical owners survive alternate detach events');assert.equal(s.network.capture_status.gaps,gaps);
    let active=0;for(const c of commands()){if(c.method==='Target.detachFromTarget')active++;if(c.event==='delayed-detach-reply')active--;assert(active<=4,'At most four cleanup commands in flight');}
    assert.equal(commands().filter(c=>c.method==='Target.detachFromTarget').length,16,'Repeated notifications deduplicate exact alternate sessions');
    console.log('PASS browser sessions: repeated multi-parent service-worker duplicate bursts preserve one owner and healthy capture');
  });
  await fixture([info('service','service_worker'),...Array.from({length:8},(_,i)=>info(`page${i}`))],{slowDetach:true},async({send,state,until,commands})=>{
    await until(s=>s.network.capture_status.attached_targets===9,'Owners before queued cleanup reconnect');
    const opens=commands().filter(c=>c.event==='open'&&c.browser).length;
    for(let i=0;i<8;i++)send({duplicate:'service',parent:`page${i}`,key:`retired:${i}`});
    await until(()=>commands().filter(c=>c.method==='Target.detachFromTarget').length===4,'Old generation cleanup has four active and four queued jobs');
    send({disconnect:true});
    await until(s=>commands().filter(c=>c.event==='open'&&c.browser).length>opens&&s.network.capture_status.attached_targets===9,'Replacement owners recover without old cleanup jobs');
    request(send,'service','after-cleanup-reconnect');finish(send,'service','after-cleanup-reconnect');
    const s=await until(s=>s.network.requests.some(r=>r.protocol_request_id==='after-cleanup-reconnect'&&r.response.body.state==='available'),'Replacement body remains available');
    const currentPid=commands().filter(c=>c.event==='open'&&c.browser).at(-1).pid;
    assert(!commands().some(c=>c.pid===currentPid&&c.method==='Target.detachFromTarget'),'Old queued session IDs never reach replacement connection');
    assert.equal(s.network.capture_status.attached_targets,9);
    const stable={gaps:s.network.capture_status.gaps,gone:s.network.capture_status.cleanup_already_gone??0,failures:s.network.capture_status.cleanup_failures??0,owners:s.network.capture_status.attached_target_ids};
    await delay(1200); // Beyond the old wire-command deadline; stale jobs must settle harmlessly.
    const later=(await state()).network.capture_status;
    assert.deepEqual({gaps:later.gaps,gone:later.cleanup_already_gone??0,failures:later.cleanup_failures??0,owners:later.attached_target_ids},stable,'Old cleanup completion cannot mutate replacement counters, gaps or owners');
    request(send,'service','after-stale-cleanup-settled');finish(send,'service','after-stale-cleanup-settled');
    await until(s=>s.network.requests.some(r=>r.protocol_request_id==='after-stale-cleanup-settled'&&r.response.body.state==='available'),'Replacement remains open after stale cleanup completion');
    console.log('PASS browser sessions: queued alternate cleanup cannot escape its original connection generation');
  });
  await fixture([info('a'),info('w','worker','a'),info('f','iframe','a'),info('shared','shared_worker'),info('service','service_worker'),...Array.from({length:6},(_,i)=>info(`extra${i}`))],{},async({send,until,commands,add})=>{
    let s=await until(s=>s.network.capture_status.attached_targets===11,'Eleven flattened owners');
    assert.equal(s.network.capture_status.target_limit,32);assert.equal(s.network.capture_status.startup_mode,'passive');assert.equal(s.network.capture_status.transport_mode,'browser-sessions');
    for(const target of ['a','w','f'])request(send,target,'same',target);
    for(const target of ['f','a','w'])finish(send,target,'same');
    s=await until(s=>s.network.requests.filter(r=>r.response.body.state==='available').length===3,'Session-qualified bodies');
    assert.equal(new Set(s.network.requests.map(r=>r.id)).size,3);
    for(const row of s.network.requests){assert.equal(row.url,`http://localhost/${row.target_id}`,'Identical raw IDs preserve exact owner/path mapping');const command=commands().find(c=>c.method==='Network.getResponseBody'&&c.sessionId?.endsWith(`:${row.target_id}`));assert(command);assert.equal(row.response.body.text,`body:${command.sessionId}:same`);}
    const retained=s.network.requests.map(r=>r.id);
    request(send,'w','slow','retired');finish(send,'w','slow');
    await until(s=>s.network.requests.some(r=>r.url.endsWith('/retired')&&r.response.body.state==='loading'),'Old body pending');
    send({detach:'w'});
    await until(s=>s.network.requests.some(r=>r.url.endsWith('/retired')&&r.response.body.state==='error'),'Detached body retired');
    await until(s=>s.network.capture_status.attached_target_ids.includes('w'),'Replacement worker');
    request(send,'w','slow','replacement');finish(send,'w','slow');
    s=await until(s=>s.network.requests.some(r=>r.url.endsWith('/replacement')&&r.response.body.state==='available'),'Replacement body');
    const retired=s.network.requests.find(r=>r.url.endsWith('/retired')),replacement=s.network.requests.find(r=>r.url.endsWith('/replacement'));
    assert.equal(retired.response.body.state,'error');assert.notEqual(retired.capture_owner,replacement.capture_owner);
    const replacementCommand=commands().filter(c=>c.method==='Network.getResponseBody'&&c.params.requestId==='slow'&&c.sessionId?.endsWith(':w')).at(-1);
    assert.equal(replacement.response.body.text,`body:${replacementCommand.sessionId}:slow`);
    add(info('retry','worker','a'));
    await until(s=>s.network.capture_status.failed_targets===1,'Initialization failure visible');
    await until(s=>s.network.capture_status.attached_target_ids.includes('retry'),'Initialization retry',20000);
    const failedDetach=commands().find(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId?.endsWith(':retry'));
    assert(failedDetach?.sessionId?.endsWith(':a'),'Nested target detach must route through its parent session');
    const attempts=commands().filter(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':retry'));assert(attempts.length>=2);assert(attempts[1].time-attempts[0].time>=4500,'Initialization failures need backoff');
    const previous=commands().filter(c=>c.event==='open'&&c.browser).length;send({disconnect:true});
    s=await until(s=>commands().filter(c=>c.event==='open'&&c.browser).length>previous&&s.network.capture_status.attached_targets===12,'Browser transport reconnect',45000);
    for(const id of retained)assert(s.network.requests.some(r=>r.id===id),'Reconnect retains evidence');
    request(send,'a','same','after-reconnect');finish(send,'a','same');
    s=await until(s=>s.network.requests.some(r=>r.url.endsWith('/after-reconnect')&&r.response.body.state==='available'),'New evidence after reconnect');
    const after=s.network.requests.find(r=>r.url.endsWith('/after-reconnect'));
    assert(!retained.includes(after.id),'Reconnect must never reuse public row identities');
    const capture=commands().filter(c=>c.browser&&c.event==='command');
    assert(capture.some(c=>c.method==='Target.setAutoAttach'&&c.sessionId?.endsWith(':a')),'Recursive attachment required');
    assert(capture.every(c=>!c.method.startsWith('Runtime.')&&!c.method.startsWith('Debugger.')&&!c.method.startsWith('Page.')),'Capture must stay passive');
    assert(capture.filter(c=>c.method==='Target.setAutoAttach').every(c=>c.params.waitForDebuggerOnStart===false),'Capture must never hold startup');
    console.log('PASS browser sessions: >8 owners, nested worker/frame, exact bodies, retired late body, initialization retry, reconnect and passive commands');
  });
  await fixture([info('a'),info('w','worker','a'),info('grandchild','worker','w')],{snapshotRootsOnly:true},async({send,until,commands})=>{
    await until(s=>s.network.capture_status.attached_targets===3,'Recursive three-level startup');
    const original=new Map(commands().filter(c=>c.method==='Network.enable').map(c=>[c.sessionId.split(':').at(-1),c.sessionId]));
    for(const target of ['w','grandchild']){request(send,target,'slow',`parent-retired-${target}`);finish(send,target,'slow');}
    await until(s=>s.network.requests.filter(r=>r.response.body.state==='loading').length===2,'Descendant body jobs pending');
    send({detach:'a'});
    await until(s=>['w','grandchild'].every(target=>s.network.requests.some(r=>r.url.endsWith(`/parent-retired-${target}`)&&r.response.body.state==='error')),'Parent-only detach retires descendants');
    await until(s=>s.network.capture_status.attached_targets===3&&['a','w','grandchild'].every(target=>commands().some(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(`:${target}`)&&c.sessionId!==original.get(target))),'Fresh descendant owners after parent detach');
    await delay(1600);
    let s=await until(s=>s.network.requests.filter(r=>r.response.body.state==='error').length===2,'Late descendant responses stay retired');
    assert.equal(s.network.requests.filter(r=>r.response.body.state==='error').length,2);
    console.log('PASS browser sessions: parent-only detach cascades transitively and late bodies stay retired');
  });
  for(const method of ['Target.targetCrashed','Inspector.targetCrashed']) {
    await fixture([info('a'),info('w','worker','a'),info('grandchild','worker','w')],{snapshotRootsOnly:true},async({send,until})=>{
      let s=await until(s=>s.network.capture_status.attached_targets===3,'Fresh nested tree for crash');
      const path=`crash-${method}`;request(send,'grandchild','slow',path);finish(send,'grandchild','slow');
      s=await until(s=>s.network.requests.some(r=>r.url.endsWith('/'+path)&&r.response.body.state==='loading'),'Crash descendant body pending');
      const owner=s.network.requests.find(r=>r.url.endsWith('/'+path)).capture_owner;
      send({target:'a',method,params:{targetId:'a',status:'crashed',errorCode:1}});
      await until(s=>s.network.requests.some(r=>r.url.endsWith('/'+path)&&r.response.body.state==='error'),'Crash-only event retires descendant body');
      await until(s=>s.network.capture_status.attached_targets===3&&s.network.capture_status.failed_targets===0,'Crashed target tree recovers',20000);
      request(send,'grandchild','same',path+'-new');finish(send,'grandchild','same');
      s=await until(s=>s.network.requests.some(r=>r.url.endsWith('/'+path+'-new')&&r.response.body.state==='available'),'Recovered descendant captures');
      assert.notEqual(s.network.requests.find(r=>r.url.endsWith('/'+path+'-new')).capture_owner,owner);
      assert.equal(s.network.requests.find(r=>r.url.endsWith('/'+path)).response.body.state,'error');
      console.log(`PASS browser sessions: ${method} retires descendant evidence and recovers`);
    });
  }
  await fixture([info('a'),info('reset-failure','worker','a')],{},async({send,until,commands,forget})=>{
    await until(s=>s.network.capture_status.failed_targets===1,'Failure recorded before reconnect');
    const opens=commands().filter(c=>c.event==='open'&&c.browser).length;
    forget('reset-failure');send({disconnect:true});
    const s=await until(s=>commands().filter(c=>c.event==='open'&&c.browser).length>opens&&s.network.capture_status.attached_targets===1&&s.network.capture_status.eligible_targets===1,'Replacement catalog without failed target',45000);
    assert.equal(s.network.capture_status.failed_targets,0,'Prior connection failures must not leak into replacement catalog');
    console.log('PASS browser sessions: failure map resets on reconnect without target-destroy notification');
  });
  await fixture(['a','b','c','d'].map(id=>info(id)),{limit:2},async({until,destroy})=>{
    let s=await until(s=>s.network.capture_status.attached_targets===2&&s.network.capture_status.eligible_targets===4,'Bounded owners');
    assert.deepEqual([...s.network.capture_status.attached_target_ids].sort(),['a','b']);assert.equal(s.network.capture_status.target_overflow,2);assert.equal(s.network.capture_status.state,'partial');
    destroy('a');s=await until(s=>s.network.capture_status.attached_target_ids.includes('c'),'First queued target promoted');
    assert(!s.network.capture_status.attached_target_ids.includes('d'));destroy('b');
    await until(s=>s.network.capture_status.attached_target_ids.includes('d'),'Second queued target promoted');
    console.log('PASS browser sessions: configurable capacity and fair overflow promotion');
  });
  await fixture([...['a','b','c'].map(id=>info(id)),info('d','iframe','b')],{limit:2,delayedAdmission:true},async({until,commands,destroy})=>{
    await until(s=>s.network.capture_status.attached_targets===2,'Reservation race baseline');
    destroy('a');
    let s=await until(s=>commands().some(c=>c.event==='reservation-race')&&s.network.capture_status.attached_target_ids.includes('c'),'Reserved FIFO target admitted');
    assert(!s.network.capture_status.attached_target_ids.includes('d'),'New auto-attachment must not steal a reserved FIFO slot');
    assert(!commands().some(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':d')),'Overflow auto-attachment must not enable Network');
    destroy('b');
    s=await until(s=>s.network.capture_status.attached_target_ids.includes('d'),'Rejected auto-attachment remains queued');
    assert(s.network.capture_status.attached_target_ids.includes('c'));
    console.log('PASS browser sessions: delayed manual admission reserves FIFO slot against newer auto-attachment');
  });
  await fixture([info('a'),info('ghost')],{snapshotDestroy:true},async({until,commands})=>{
    const s=await until(s=>s.network.capture_status.attached_targets===1&&s.network.capture_status.eligible_targets===1,'Destroyed snapshot target removed');
    assert.deepEqual(s.network.capture_status.attached_target_ids,['a']);
    assert.equal(s.network.capture_status.failed_targets,0);
    const browserCommands=commands().filter(c=>c.browser&&c.event==='command');
    assert(browserCommands.findIndex(c=>c.method==='Target.setDiscoverTargets')<browserCommands.findIndex(c=>c.method==='Target.getTargets'),'Discovery must precede initial snapshot');
    const ghostAttempts=()=>commands().filter(c=>c.method==='Target.attachToTarget'&&c.params.targetId==='ghost').length;
    const initialAttempts=ghostAttempts();
    assert(initialAttempts<=1,'At most one explicit attach may race the queued destruction event');
    await delay(5500);
    assert.equal(ghostAttempts(),initialAttempts,'Destroyed snapshot target must never be retried');
    await until(s=>s.network.capture_status.eligible_targets===1&&s.network.capture_status.failed_targets===0,'Destroyed target leaves no stale failure');
    console.log('PASS browser sessions: discovery subscription reconciles destruction during initial snapshot');
  });
  await fixture([info('a'),{...info('held'),waiting:true}],{},async({until,commands})=>{
    const s=await until(s=>s.network.capture_status.attached_target_ids.includes('a')&&s.network.capture_status.gaps>=1,'Externally waiting target visibly declined');
    assert.deepEqual(s.network.capture_status.attached_target_ids,['a']);
    assert.match(s.network.capture_status.last_error,/waiting for a debugger/);
    assert(!commands().some(c=>c.method==='Runtime.runIfWaitingForDebugger'),'Passive capture must not resume externally waiting targets');
    console.log('PASS browser sessions: externally waiting rejection is visible and never resumed');
  });
  await fixture([info('a')],{},async({until,commands,add})=>{
    await until(s=>s.network.capture_status.attached_target_ids.includes('a'),'Initial explicitly attached page');
    for(let i=0;i<12;i++)add(info(`burst${i}`));
    await until(s=>Array.from({length:12},(_,i)=>`burst${i}`).every(id=>s.network.capture_status.attached_target_ids.includes(id)),'Event-driven burst admitted without per-target polling delay',5000);
    const controls=commands().filter(c=>c.browser&&c.event==='command');
    assert(!controls.some(c=>c.method==='Target.setAutoAttach'&&!c.sessionId),'Passive browser root must never enable auto-attach');
    assert(controls.some(c=>c.method==='Target.setAutoAttach'&&c.sessionId),'Per-owner recursive attachment remains enabled');
    assert(!controls.some(c=>c.method==='Runtime.runIfWaitingForDebugger'),'Explicit passive admission never resumes targets');
    console.log('PASS browser sessions: discovery events promptly admit a bounded burst without browser-root auto-attach or resume');
  });
  await fixture([info('a')],{slowAdmission:true},async({until,commands,add,send})=>{
    await until(s=>s.network.capture_status.attached_target_ids.includes('a'),'Initial owner before slow admission');
    add(info('slow-admission'));
    await until(()=>commands().some(c=>c.method==='Target.attachToTarget'&&c.params.targetId==='slow-admission'),'Admission command is awaiting delayed reply');
    request(send,'a','while-admitting');finish(send,'a','while-admitting');
    await until(s=>s.network.requests.some(row=>row.protocol_request_id==='while-admitting'&&row.response.body.state==='available'),'Existing owner Network events progress during slow admission',1000);
    await until(s=>s.network.capture_status.attached_target_ids.includes('slow-admission'),'Delayed owner eventually admitted');
    console.log('PASS browser sessions: delayed target admission never blocks existing-owner Network events');
  });
  await fixture([info('a')],{lateFailure:true},async({until,commands,add,destroy})=>{
    await until(s=>s.network.capture_status.attached_target_ids.includes('a'),'Initial owner before destroyed admission');
    add(info('doomed'));
    await until(()=>commands().some(c=>c.method==='Target.attachToTarget'&&c.params.targetId==='doomed'),'Doomed attach in flight');
    destroy('doomed');await delay(600);
    await until(s=>s.network.capture_status.eligible_targets===1&&s.network.capture_status.failed_targets===0,'Late failure cannot resurrect destroyed target');
    await delay(5500);
    assert.equal(commands().filter(c=>c.method==='Target.attachToTarget'&&c.params.targetId==='doomed').length,1,'Destroyed target must not retry after late attach failure');
    console.log('PASS browser sessions: late admission error cannot resurrect destroyed target failures or retries');
  });
  for(const initialOverflow of [false,true]) {
    const initial=[info('a'),...Array.from({length:511},(_,i)=>info(`z${i}`)),...(initialOverflow?[info('!recover')]:[])];
    await fixture(initial,{limit:1},async({until,commands,add,destroy})=>{
      await until(s=>s.network.capture_status.attached_target_ids.includes('a'),'Healthy owner with full bounded catalog');
      if(!initialOverflow)add(info('!recover'));
      const full=await until(s=>s.network.capture_status.catalog_incomplete===true,'Catalog overflow remains explicitly incomplete');
      assert.equal(full.network.capture_status.eligible_targets,512);assert.equal(full.network.capture_status.state,'partial');
      destroy('z510');
      const recovered=await until(s=>s.network.capture_status.catalog_incomplete===false&&s.network.capture_status.unattached_targets.some(t=>t.id==='!recover'),'Omitted stable target recovered after catalog slot frees');
      assert.equal(recovered.network.capture_status.eligible_targets,512);
      assert(commands().filter(c=>c.method==='Target.getTargets').length>=2,'Overflow recovery requires an actual catalog reconciliation');
      console.log(`PASS browser sessions: ${initialOverflow?'initial':'incremental'}513-target catalog remains bounded and recovers omitted target`);
    });
  }
  await fixture([info('a'),...Array.from({length:511},(_,i)=>info(`z${i}`)),info('!recover')],{limit:1,reconcileDestroy:true},async({until,commands,destroy})=>{
    await until(s=>s.network.capture_status.catalog_incomplete===true,'Overflow before concurrent reconciliation');
    destroy('z510');
    await until(()=>commands().some(c=>c.event==='stale-reconcile-reply'),'Snapshot reply after target destruction');
    await until(s=>s.network.capture_status.catalog_incomplete===false&&s.network.capture_status.eligible_targets===511,'Fresh reconciliation excludes target destroyed during stale snapshot');
    assert(!commands().some(c=>c.method==='Target.attachToTarget'&&c.params.targetId==='z509'),'Destroyed queued target never becomes an owner');
    console.log('PASS browser sessions: concurrent destruction cannot be resurrected by catalog reconciliation');
  });
  await fixture([info('a')],{limit:1,slowDetach:true},async({until,commands,add,send})=>{
    await until(s=>s.network.capture_status.attached_target_ids.includes('a'),'Healthy owner before rejected teardown');
    add(info('overflow','worker','a'));
    await until(()=>commands().some(c=>c.method==='Target.detachFromTarget'),'Overflow detach awaiting delayed reply');
    request(send,'a','during-overflow-detach');finish(send,'a','during-overflow-detach');
    await until(s=>s.network.requests.some(row=>row.protocol_request_id==='during-overflow-detach'&&row.response.body.state==='available'),'Healthy traffic progresses during rejected cleanup',3000);
    const log=commands(),body=log.findIndex(c=>c.method==='Network.getResponseBody'&&c.params.requestId==='during-overflow-detach'),reply=log.findIndex(c=>c.event==='delayed-detach-reply');
    assert(body>=0&&(reply<0||body<reply),'Healthy owner body command precedes delayed rejected-session cleanup reply');
    console.log('PASS browser sessions: rejected-session cleanup never blocks healthy owner traffic');
  });
  await fixture([info('service','service_worker'),info('a')],{limit:2,slowDetach:true},async({until,commands,send})=>{
    await until(s=>s.network.capture_status.attached_targets===2,'Healthy owners before cleanup saturation');
    for(let i=0;i<500;i++)send({duplicate:'service',parent:'a',key:`overflow:${i}`});
    await until(()=>commands().filter(c=>c.method==='Target.detachFromTarget').length===4,'Four cleanup slots occupied');
    for(let i=500;i<513;i++)send({duplicate:'service',parent:'a',key:`overflow:${i}`});
    const s=await until(s=>String(s.network.capture_status.last_error).includes('cleanup capacity exceeded'),'Bounded cleanup saturation is explicit');
    assert.equal(s.network.capture_status.discovery_stale,true);
    assert.equal(s.network.capture_status.state,'partial');
    assert(s.network.capture_status.gaps>0);
    assert(commands().filter(c=>c.method==='Target.detachFromTarget').length<=4,'Cleanup tasks remain bounded');
    console.log('PASS browser sessions: cleanup saturation closes capture with a persistent explicit gap');
  });
  await fixture([info('a')],{slowReply:true},async({until,commands,add})=>{
    await until(s=>s.network.capture_status.attached_target_ids.includes('a'),'Initial owner before delayed ACK');
    add(info('slow-reply'));
    await until(s=>s.network.capture_status.attached_target_ids.includes('slow-reply'),'Event-established owner is ready before command ACK');
    await delay(2600);add(info('refresh-status'));
    const s=await until(s=>s.network.capture_status.attached_targets===3,'Status recomputed after delayed ACK timeout');
    assert.equal(s.network.capture_status.failed_targets,0,'Late command timeout cannot mark established owner failed');
    assert.equal(commands().filter(c=>c.method==='Target.attachToTarget'&&c.params.targetId==='slow-reply').length,1);
    console.log('PASS browser sessions: delayed attach ACK cannot poison established owner health');
  });
  await fixture([info('a')],{capture:false},async({until,commands})=>{
    const s=await until(s=>s.state==='running','Metadata-only debugger');assert.equal(s.network.capture_status.state,'disabled');
    assert(!commands().some(c=>c.browser||c.method==='Network.enable'),'Disabled capture must open no browser capture transport');
    console.log('PASS browser sessions: disabled capture creates no capture connection');
  });
}
