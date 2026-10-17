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
  const sessions=new Map();let serial=0,pending=Buffer.alloc(0),discovering=false,delayedAdmission=false;
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
      if(m.method==='Target.setDiscoverTargets') {discovering=m.params.discover;reply({});}
      else if(m.method==='Target.getTargets') {
        const snapshot=targets();reply({targetInfos:snapshot});
        if(options.snapshotDestroy&&snapshot.some(t=>t.targetId==='ghost')) {
          writeFileSync(join(directory,'targets'),JSON.stringify(snapshot.filter(t=>t.targetId!=='ghost')));
          if(discovering)emit({method:'Target.targetDestroyed',params:{targetId:'ghost'}});
        }
      }
      else if(m.method==='Target.attachToTarget') {
        const info=targets().find(t=>t.targetId===m.params.targetId);
        if(options.delayedAdmission&&info?.targetId==='c'&&!delayedAdmission) {
          delayedAdmission=true;log({event:'reservation-race'});
          // The newer auto-attachment arrives before the reserved manual one.
          attach(targets().find(t=>t.targetId==='d'));
          setTimeout(()=>reply({sessionId:attach(info)}),350);
        } else reply({sessionId:info?attach(info):'missing'});
      }
      else if(m.method==='Network.getResponseBody')setTimeout(()=>reply({body:`body:${m.sessionId}:${m.params.requestId}`,base64Encoded:false}),m.params.requestId==='slow'?1500:0);
      else reply({});
      if(browser&&m.method==='Target.setAutoAttach'&&m.params.autoAttach) {
        for(const info of targets().filter(t=>m.sessionId?t.parent===target:!t.parent))attach(info,m.sessionId);
      }
      if(browser&&m.method==='Target.detachFromTarget') {
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
      if(event.add) {const info=targets().find(t=>t.targetId===event.add);emit({method:'Target.targetCreated',params:{targetInfo:info}});attach(info,info.parent?sessions.get(info.parent):undefined);continue;}
      if(event.destroy){const sid=sessions.get(event.destroy);sessions.delete(event.destroy);emit({method:'Target.targetDestroyed',params:{targetId:event.destroy}});if(sid)emit({method:'Target.detachedFromTarget',params:{sessionId:sid,targetId:event.destroy}});continue;}
      if(event.detach){const sid=sessions.get(event.detach);invalidate(event.detach);emit({method:'Target.detachedFromTarget',params:{sessionId:sid,targetId:event.detach}});continue;}
      const sessionId=sessions.get(event.target);if(sessionId)emit({method:event.method,params:event.params,sessionId});
    }
  },15);
} else {
  const root=resolve(process.argv[2]??'.'),binary=resolve(process.env.ORIGIN_TRACE_BACKEND||join(root,'apps/origin-trace-backend/target/debug/origin-trace-backend'));
  const info=(id,type='page',parent)=>({targetId:id,type,title:id,url:`http://localhost/${id}`,...(parent?{parent}:{})});
  async function fixture(initial,options,run) {
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
      await writeFile(join(directory,'active'),`${server.address().port}\n/devtools/browser/fixture\n`);
      await writeFile(join(directory,'transport'),`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(script)} --transport "$@"\n`,{mode:0o700});
      backend=spawn(binary,['--port','0','--endpoint-file',join(directory,'endpoint'),'--devtools-active-port',join(directory,'active'),'--debugger-transport',join(directory,'transport'),...(options.capture===false?[]:['--capture-network-content']),...(options.limit?['--capture-target-limit',String(options.limit)]:[])],{cwd:directory,env:{...process.env,REB_CAPTURE_FIXTURE:directory}});
      exited=new Promise(r=>{backend.once('exit',r);backend.once('error',e=>{diagnostics+=e.message;r();});});
      for(const stream of [backend.stdout,backend.stderr])stream.on('data',chunk=>diagnostics=(diagnostics+chunk).slice(-8192));
      await run({send,state,until,commands,forget:id=>{targets=targets.filter(t=>t.targetId!==id);save();},add:t=>{targets.push(t);save();send({add:t.targetId});},destroy:id=>{targets=targets.filter(t=>t.targetId!==id);save();send({destroy:id});}});
    } finally {
      if(backend?.exitCode===null&&backend.signalCode===null){backend.kill('SIGTERM');await Promise.race([exited,delay(3000)]);if(backend.exitCode===null&&backend.signalCode===null){backend.kill('SIGKILL');await exited;}}
      await new Promise(r=>server.close(r));await rm(directory,{recursive:true,force:true});
    }
  }
  const request=(send,target,id,path=id)=>send({target,method:'Network.requestWillBeSent',params:{requestId:id,timestamp:1,wallTime:1,type:'Fetch',request:{url:`http://localhost/${path}`,method:'GET',headers:{}}}});
  const finish=(send,target,id)=>{send({target,method:'Network.responseReceived',params:{requestId:id,response:{status:200,headers:{}}}});send({target,method:'Network.loadingFinished',params:{requestId:id,timestamp:2,encodedDataLength:10}});};
  await fixture([info('a'),info('w','worker','a'),info('f','iframe','a'),info('shared','shared_worker'),info('service','service_worker'),...Array.from({length:6},(_,i)=>info(`extra${i}`))],{},async({send,until,commands,add})=>{
    let s=await until(s=>s.network.capture_status.attached_targets===11,'Eleven flattened owners');
    assert.equal(s.network.capture_status.target_limit,32);assert.equal(s.network.capture_status.startup_mode,'passive');assert.equal(s.network.capture_status.transport_mode,'browser-sessions');
    for(const target of ['a','w','f']){request(send,target,'same',target);finish(send,target,'same');}
    s=await until(s=>s.network.requests.filter(r=>r.response.body.state==='available').length===3,'Session-qualified bodies');
    assert.equal(new Set(s.network.requests.map(r=>r.id)).size,3);
    for(const row of s.network.requests){const command=commands().find(c=>c.method==='Network.getResponseBody'&&c.sessionId?.endsWith(`:${row.target_id}`));assert(command);assert.equal(row.response.body.text,`body:${command.sessionId}:same`);}
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
  await fixture([info('a'),info('w','worker','a'),info('grandchild','worker','w')],{},async({send,until,commands})=>{
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
    await fixture([info('a'),info('w','worker','a'),info('grandchild','worker','w')],{},async({send,until})=>{
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
  await fixture(['a','b','c','d'].map(id=>info(id)),{limit:2,delayedAdmission:true},async({until,commands,destroy})=>{
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
    assert(!browserCommands.some(c=>c.method==='Target.attachToTarget'&&c.params.targetId==='ghost'),'Destroyed snapshot target must not become a retry ghost');
    console.log('PASS browser sessions: discovery subscription reconciles destruction during initial snapshot');
  });
  await fixture([info('a'),{...info('held'),waiting:true}],{},async({until,commands})=>{
    const s=await until(s=>s.network.capture_status.attached_target_ids.includes('a')&&s.network.capture_status.gaps>=1,'Externally waiting target visibly declined');
    assert.deepEqual(s.network.capture_status.attached_target_ids,['a']);
    assert.match(s.network.capture_status.last_error,/waiting for a debugger/);
    assert(!commands().some(c=>c.method==='Runtime.runIfWaitingForDebugger'),'Passive capture must not resume externally waiting targets');
    console.log('PASS browser sessions: externally waiting rejection is visible and never resumed');
  });
  await fixture([info('a')],{capture:false},async({until,commands})=>{
    const s=await until(s=>s.state==='running','Metadata-only debugger');assert.equal(s.network.capture_status.state,'disabled');
    assert(!commands().some(c=>c.browser||c.method==='Network.enable'),'Disabled capture must open no browser capture transport');
    console.log('PASS browser sessions: disabled capture creates no capture connection');
  });
}
