// Fault-injected owned-browser startup tests. Synthetic loopback CDP only.
// A fixture release on disconnect is distinguished from an acknowledged resume.
// REB_CAPTURE_FIRST_CASES=worker-controller or malformed-attachments narrows review runs.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {appendFileSync,existsSync,mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {stopBrowserTestProcess,waitForClose} from './browser-test-process.mjs';

const script=fileURLToPath(import.meta.url),delay=ms=>new Promise(r=>setTimeout(r,ms));
const fixtureDirectory=process.env.REB_CAPTURE_FIRST_FIXTURE;
const log=value=>appendFileSync(join(fixtureDirectory,'commands'),JSON.stringify({...value,pid:process.pid,time:Date.now()})+'\n');
const records=path=>readFileSync(path,'utf8').split('\n').filter(Boolean).map(JSON.parse);
const targets=()=>JSON.parse(readFileSync(join(fixtureDirectory,'targets'),'utf8'));

if(process.argv[2]==='--browser') {
  const options=JSON.parse(readFileSync(join(fixtureDirectory,'options'),'utf8'));
  const args=process.argv.slice(3),profile=args.find(a=>a.startsWith('--user-data-dir='))?.split('=').slice(1).join('=');
  assert(profile,'Owned launch needs an explicit fresh profile');
  assert(args.includes('about:blank'),'Owned browser must start on an inert page');
  assert(!args.some(a=>/^https?:/.test(a)),'Owned launch must not race a network navigation');
  assert(!args.some(a=>a==='--no-sandbox'||a==='--disable-setuid-sandbox'),'No sandbox bypass in fixtures');
  mkdirSync(profile,{recursive:true});
  const descendant=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});
  log({event:'browser-launch',args,profile,descendant:descendant.pid});
  const server=createServer((_req,res)=>{
    res.setHeader('Content-Type','application/json');
    res.end(JSON.stringify(targets().filter(t=>t.type==='page'||options.experiment&&t.type==='worker').map(t=>({...t,id:t.targetId,webSocketDebuggerUrl:`ws://127.0.0.1:${server.address().port}/devtools/page/${t.targetId}`}))));
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  if(!options.noDevToolsFile)writeFileSync(join(profile,'DevToolsActivePort'),`${server.address().port}\n/devtools/browser/capture-first-fixture\n`);
  // Deliberately do not forward signals: only process-group ownership can stop
  // this descendant when the backend tears down the disposable browser.
  process.on('SIGTERM',()=>{log({event:'browser-stop'});server.close(()=>process.exit(0));});
} else if(process.argv[2]==='--transport') {
  const browser=process.argv.at(-1).includes('/devtools/browser/');
  const options=JSON.parse(readFileSync(join(fixtureDirectory,'options'),'utf8'));
  const emit=value=>{
    const body=value===null?Buffer.alloc(0):Buffer.from(JSON.stringify(value));
    const header=Buffer.from([82,69,66,1,0,0,0,0]);header.writeUInt32BE(body.length,4);
    process.stdout.write(Buffer.concat([header,body]));
  };
  const sessions=new Map(),held=new Set();let serial=0,pending=Buffer.alloc(0),rootHold=false,capturing=false,closed=false;
  let cursor=records(join(fixtureDirectory,'events')).length;
  function release(sessionId,reason) {
    if(held.delete(sessionId))log({event:'release',browser,sessionId,reason});
  }
  function close(reason) {
    if(closed)return;closed=true;
    for(const sessionId of held)release(sessionId,reason);
    log({event:'transport-close',browser,reason});process.exit(0);
  }
  function attach(info,parent,hold=rootHold) {
    if(!info)return 'missing';
    if(sessions.has(info.targetId))return sessions.get(info.targetId);
    const sessionId=`${process.pid}:${++serial}:${info.targetId}`;sessions.set(info.targetId,sessionId);
    if(hold)held.add(sessionId);
    log({event:'attached',browser,target:info.targetId,sessionId,parent,waiting:hold});
    emit({method:'Target.attachedToTarget',params:{sessionId,targetInfo:info,waitingForDebugger:hold},...(parent?{sessionId:parent}:{})});
    return sessionId;
  }
  function detach(id,reason) {
    for(const child of targets().filter(t=>t.parent===id))detach(child.targetId,reason);
    const sessionId=sessions.get(id);if(sessionId)release(sessionId,reason);sessions.delete(id);
  }
  log({event:'transport-open',browser});emit(null);
  process.stdin.on('end',()=>close('transport-eof'));
  process.on('SIGTERM',()=>close('transport-stop'));
  process.stdin.on('data',chunk=>{
    pending=Buffer.concat([pending,chunk]);
    while(pending.length>=8&&pending.length>=8+pending.readUInt32BE(4)) {
      const size=pending.readUInt32BE(4),m=JSON.parse(pending.subarray(8,8+size));pending=pending.subarray(8+size);
      log({event:'command',browser,...m});
      const reply=result=>{
        const message={id:m.id,result,...(m.sessionId?{sessionId:m.sessionId}:{})};
        const replyDelay=options.delayCaptureOnly&&!capturing?0:m.method==='Target.detachFromTarget'&&options.detachDelay?options.detachDelay:
          options.delays?.[m.method]&&m.sessionId?.endsWith(':'+options.delayTarget)?options.delays[m.method]:0;
        if(replyDelay)setTimeout(()=>emit(message),replyDelay);else emit(message);
      };
      const reject=message=>emit({id:m.id,error:{code:-32000,message},...(m.sessionId?{sessionId:m.sessionId}:{})});
      const target=[...sessions].find(([,sid])=>sid===m.sessionId)?.[0];
      if(browser&&target===options.failTarget&&m.method===options.failMethod) {
        if(options.failure==='error')reject('synthetic initialization failure');
        // Timeout deliberately never replies; production must bound it.
        if(options.failure==='error'||options.failure==='timeout')continue;
      }
      if(options.experiment&&m.method==='Target.createBrowserContext')reply({browserContextId:'owned-context'});
      else if(options.experiment&&m.method==='Target.createTarget')reply({targetId:'a'});
      else if(m.method==='Target.getTargets')reply({targetInfos:targets()});
      else if(m.method==='Target.attachToTarget')reply({sessionId:attach(targets().find(t=>t.targetId===m.params.targetId),undefined,false)});
      else if(m.method==='Runtime.runIfWaitingForDebugger') {
        release(m.sessionId,'acknowledged-resume');reply({});
      } else if(m.method==='Target.setAutoAttach') {
        reply({});
        if(browser&&!m.sessionId){capturing=m.params.autoAttach;rootHold=capturing&&m.params.waitForDebuggerOnStart;}
        if(browser&&m.params.autoAttach)for(const info of targets().filter(t=>m.sessionId?t.parent===target:!t.parent))attach(info,m.sessionId,m.params.waitForDebuggerOnStart);
      } else if(m.method==='Target.detachFromTarget') {
        const entry=[...sessions].find(([,sid])=>sid===m.params.sessionId);
        if(entry){detach(entry[0],'session-detach');emit({method:'Target.detachedFromTarget',params:{sessionId:entry[1],targetId:entry[0]}});}
        reply({});
      } else reply({});
    }
  });
  setInterval(()=>{
    const events=records(join(fixtureDirectory,'events'));
    while(cursor<events.length) {
      const event=events[cursor++];if(!browser||!capturing)continue;
      if(event.raw){emit(event.raw);continue;}
      if(event.disconnect)close('injected-disconnect');
      if(event.add) {
        const info=targets().find(t=>t.targetId===event.add);
        emit({method:'Target.targetCreated',params:{targetInfo:info}});
        attach(info,info.parent?sessions.get(info.parent):undefined,event.hold??rootHold);continue;
      }
      if(event.detach) {
        const sessionId=sessions.get(event.detach);detach(event.detach,'ancestor-detach');
        emit({method:'Target.detachedFromTarget',params:{sessionId,targetId:event.detach}});
      }
    }
  },15);
} else {
  const selected=process.env.REB_CAPTURE_FIRST_CASES;
  assert(!selected||['worker-controller','malformed-attachments'].includes(selected),'Unknown REB_CAPTURE_FIRST_CASES selector');
  const root=resolve(process.argv[2]??'.');
  const binary=resolve(process.env.ORIGIN_TRACE_BACKEND||join(root,'apps/origin-trace-backend/target/debug/origin-trace-backend'));
  const info=(id,type='page',parent)=>({targetId:id,type,title:id,url:type==='page'?'about:blank':`http://localhost/${id}.js`,...(parent?{parent}:{})});
  const alive=pid=>{try{process.kill(pid,0);return true;}catch(error){if(error.code==='ESRCH')return false;throw error;}};
  async function fixture(initial,options,run) {
    if(selected==='worker-controller'&&!options.experiment||selected==='malformed-attachments'&&!options.malformed)return;
    const directory=await mkdtemp(join(tmpdir(),'reb-capture-first-'));
    let owned,external,address,diagnostics='',failure;
    let catalog=initial;
    const save=()=>writeFileSync(join(directory,'targets'),JSON.stringify(catalog));save();
    await writeFile(join(directory,'options'),JSON.stringify(options));
    for(const name of ['events','commands'])await writeFile(join(directory,name),'');
    const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
    for(const kind of ['browser','transport'])await writeFile(join(directory,kind),`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(script)} --${kind} "$@"\n`,{mode:0o700});
    const commands=()=>records(join(directory,'commands'));
    const send=value=>appendFileSync(join(directory,'events'),JSON.stringify(value)+'\n');
    const start=(path,args,detached=false)=>{
      const child=spawn(path,args,{cwd:directory,detached,env:{...process.env,REB_CAPTURE_FIRST_FIXTURE:directory}});
      const closed=new Promise(r=>{child.once('close',r);child.once('error',e=>{diagnostics+=e.message;r();});});
      for(const pipe of [child.stdout,child.stderr])pipe.on('data',chunk=>diagnostics=(diagnostics+chunk).slice(-16384));
      return {child,closed};
    };
    const until=async(predicate,label,timeout=15000)=>{
      const end=Date.now()+timeout;let last;
      while(Date.now()<end) {
        if(owned&&!options.expectedExit)assert(owned.child.exitCode===null&&owned.child.signalCode===null,`${label}: backend exited: ${diagnostics}`);
        try{last=await predicate();if(last)return last;}catch(error){if(error instanceof assert.AssertionError)throw error;}
        await delay(30);
      }
      assert.fail(`${label} timed out: ${JSON.stringify(last)} ${diagnostics}`);
    };
    const state=async()=>{
      address??=(await readFile(join(directory,'endpoint'),'utf8')).trim();
      return(await fetch(new URL('/api/debugger',address),{signal:AbortSignal.timeout(2000)})).json();
    };
    const action=async(value)=>{
      address??=(await readFile(join(directory,'endpoint'),'utf8')).trim();
      const response=await fetch(new URL('/api/debugger/actions',address),{method:'POST',headers:{'Content-Type':'application/json',Origin:address},body:JSON.stringify(value),signal:AbortSignal.timeout(10000)});
      const body=await response.text();assert(response.ok,`Action failed: ${response.status} ${body}`);return JSON.parse(body);
    };
    const waitState=(predicate,label,timeout)=>until(async()=>{const s=await state();return predicate(s)&&s;},label,timeout);
    try {
      let mode=['--capture-first-browser',join(directory,'browser'),'--capture-first-headless'];
      if(options.passive) {
        const profile=join(directory,'baseline');
        external=start(join(directory,'browser'),['--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],true);
        await until(()=>existsSync(join(profile,'DevToolsActivePort')),'External browser startup');
        mode=['--devtools-active-port',join(profile,'DevToolsActivePort')];
      }
      owned=start(binary,['--port',String(options.port??0),'--endpoint-file',join(directory,'endpoint'),'--debugger-transport',join(directory,'transport'),'--capture-network-content',...mode,...(options.limit?['--capture-target-limit',String(options.limit)]:[])]);
      await run({commands,send,state,action,until,waitState,signal:name=>owned.child.kill(name),exited:async(timeout=10000)=>{
        assert(await waitForClose(owned.closed,timeout),`Backend did not exit: ${diagnostics}`);
        return {code:owned.child.exitCode,signal:owned.child.signalCode,diagnostics};
      },stop:async()=>{
        await stopBrowserTestProcess(owned,5000);owned=null;
      },add:(t,hold)=>{catalog.push(t);save();send({add:t.targetId,hold});}});
    } catch(error) {failure=error;throw error;}
    finally {
      const errors=[];
      if(owned)try{await stopBrowserTestProcess(owned,5000);}catch(error){errors.push(error);}
      if(external) {
        try{process.kill(-external.child.pid,'SIGTERM');await waitForClose(external.closed,3000);}catch(error){if(error.code!=='ESRCH')errors.push(error);}
      }
      const launched=commands().find(c=>c.event==='browser-launch');
      // Avoid leaving a fixture descendant behind even when the product check fails.
      if(launched)for(const pid of [launched.pid,launched.descendant])if(alive(pid))try{process.kill(pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')errors.push(error);}
      try{await rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});}catch(error){errors.push(error);}
      if(errors.length){if(failure)console.error('Cleanup also failed; original failure preserved:',...errors);else throw new AggregateError(errors,'Capture-first fixture cleanup failed');}
    }
  }
  const capture=commands=>commands().filter(c=>c.browser&&c.event==='command');
  const resumed=(commands,id)=>commands().find(c=>c.event==='release'&&c.reason==='acknowledged-resume'&&c.sessionId.endsWith(':'+id));
  const released=(commands,sessionId)=>commands().some(c=>c.event==='release'&&c.sessionId===sessionId)||!alive(Number(sessionId.split(':')[0]));
  async function assertResumeBeforeDetach(commands,id) {
    const deadline=Date.now()+3000;
    while(!capture(commands).some(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId?.endsWith(':'+id))&&Date.now()<deadline)await delay(20);
    const all=capture(commands),resume=all.findIndex(c=>c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId?.endsWith(':'+id));
    const detach=all.findIndex(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId?.endsWith(':'+id));
    assert(resume>=0&&detach>resume,`${id}: held target must receive resume before detach`);
  }
  await fixture([info('a'),info('worker','worker','a'),info('nested','worker','worker')],{},async({commands,waitState,until,stop})=>{
    const s=await waitState(s=>s.network.capture_status.attached_targets===3,'Owned nested owners');
    assert.equal(s.network.capture_status.startup_mode,'capture-first');
    for(const id of ['a','worker','nested']) {
      await until(()=>resumed(commands,id),`${id} acknowledged resume`);
      const all=capture(commands).filter(c=>c.sessionId?.endsWith(':'+id));
      const network=all.findIndex(c=>c.method==='Network.enable');
      const recurse=all.findIndex(c=>c.method==='Target.setAutoAttach'&&c.params.waitForDebuggerOnStart===true);
      const resume=all.findIndex(c=>c.method==='Runtime.runIfWaitingForDebugger');
      assert(network>=0&&recurse>network&&resume>recurse,`${id}: network and recursive hold must precede resume`);
    }
    assert(capture(commands).some(c=>c.method==='Target.setAutoAttach'&&!c.sessionId&&c.params.waitForDebuggerOnStart===true));
    const launched=commands().find(c=>c.event==='browser-launch');
    assert(launched.args.includes('--headless=new'));
    assert(!launched.args.includes('--no-sandbox'));
    await stop();
    await until(()=>!alive(launched.pid)&&!alive(launched.descendant),'Owned browser process group terminated');
    assert(!existsSync(launched.profile),'Owned fresh profile must be removed on shutdown');
    console.log('PASS capture-first: fresh blank browser, recursive startup hold, enable-before-resume, browser/process-group/profile cleanup');
  });
  async function assertOwnedCleanup(commands,until,label) {
    const launched=commands().find(c=>c.event==='browser-launch');
    assert(launched,`${label}: owned browser really launched`);
    await until(()=>!alive(launched.pid)&&!alive(launched.descendant),`${label}: browser leader and descendant terminated`);
    assert(!existsSync(launched.profile),`${label}: confirmed stopped browser profile must be removed`);
  }
  await fixture([info('a')],{noDevToolsFile:true,expectedExit:true},async({commands,exited,until})=>{
    const launch=await until(()=>commands().find(c=>c.event==='browser-launch'),'Nonready browser launched');
    const result=await exited(22000);
    assert.notEqual(result.code,0,'Missing DevToolsActivePort must fail startup');
    assert.equal(result.signal,null,'Startup failure must be returned, not caused by the test killing the backend');
    assert.match(result.diagnostics,/Disposable capture-first browser startup timed out/,'Cleanup must preserve the original startup-timeout error');
    assert(Date.now()-launch.time>=14000,'Timeout must exercise the production startup deadline');
    await assertOwnedCleanup(commands,until,'Startup timeout');
    console.log('PASS capture-first launcher: missing DevToolsActivePort times out, preserves the original error, and stops/removes its browser group/profile');
  });
  await fixture([info('a')],{noDevToolsFile:true,expectedExit:true},async({commands,signal,exited,until})=>{
    await until(()=>commands().find(c=>c.event==='browser-launch'),'Launch-pending SIGTERM browser exists');
    const started=Date.now();assert(signal('SIGTERM'),'Signal delivered to launch-pending backend');
    const result=await exited(10000);
    assert.equal(result.signal,null,'Launch cancellation must be handled rather than leave the owned browser orphaned');
    assert.notEqual(result.code,0,'Launch cancellation must return its Interrupted error');
    assert.match(result.diagnostics,/Interrupted.*Capture-first browser launch cancelled/s,'Cleanup must preserve the launch-cancellation diagnostic');
    assert(Date.now()-started<10000,'SIGTERM must cancel startup before its 15-second deadline');
    await assertOwnedCleanup(commands,until,'Launch-pending SIGTERM');
    console.log('PASS capture-first launcher: SIGTERM during startup promptly cleans its owned browser group/profile');
  });
  const occupied=createServer();await new Promise(r=>occupied.listen(0,'127.0.0.1',r));
  try {
    await fixture([info('a')],{port:occupied.address().port,expectedExit:true},async({commands,exited,until})=>{
      const result=await exited();
      assert.notEqual(result.code,0,'Occupied backend listener must fail startup');
      assert.equal(result.signal,null,'Bind failure must be returned, not caused by the test killing the backend');
      assert.match(result.diagnostics,/CAPTURE-FIRST EXPERIMENT/,'Browser must become ready before the deliberate bind failure');
      assert.match(result.diagnostics,/AddrInUse|Address already in use/i,'Cleanup must preserve the original bind error');
      await assertOwnedCleanup(commands,until,'Occupied listener');
      console.log('PASS capture-first launcher: bind failure after browser readiness preserves its error and stops/removes the browser group/profile');
    });
  } finally {await new Promise(r=>occupied.close(r));}
  await fixture([info('a')],{expectedExit:true},async({commands,waitState,exited,until})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Owned-browser death baseline ready');
    const launched=commands().find(c=>c.event==='browser-launch');process.kill(launched.pid,'SIGTERM');
    const result=await exited(12000);
    assert.equal(result.code,0,result.diagnostics);
    assert.match(result.diagnostics,/Capture-first owned browser exited; ending this experiment/);
    await assertOwnedCleanup(commands,until,'Owned browser death');
    console.log('PASS capture-first launcher: owned browser death ends the backend and cleans the surviving descendant/profile');
  });
  for(const [failMethod,failure] of [['Network.enable','error'],['Network.enable','timeout'],['Target.setAutoAttach','error']]) {
    await fixture([info('a'),info('fault','worker','a')],{failTarget:'fault',failMethod,failure},async({commands,waitState,until})=>{
      await until(()=>resumed(commands,'fault'),`${failure} ${failMethod} releases startup`,12000);
      await assertResumeBeforeDetach(commands,'fault');
      await waitState(s=>s.network.capture_status.failed_targets>=1,'Failed owner remains visible');
      console.log(`PASS capture-first: ${failMethod} ${failure} resumes before detach and reports a failed owner`);
    });
  }
  for(const failure of ['error','timeout']) {
    await fixture([info('a'),info('resume-fault','worker','a')],{failTarget:'resume-fault',failMethod:'Runtime.runIfWaitingForDebugger',failure},async({commands,until})=>{
      const held=await until(()=>commands().find(c=>c.event==='attached'&&c.target==='resume-fault'),'Resume-failure attachment');
      await until(()=>released(commands,held.sessionId),'Failed resume releases its transport',10000);
      const release=commands().find(c=>c.event==='release'&&c.sessionId===held.sessionId);
      assert.notEqual(release?.reason,'acknowledged-resume','An error/timeout cannot be reported as successful resume');
      assert(capture(commands).some(c=>c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId===held.sessionId));
      await until(()=>!alive(held.pid),'An uncertain resume must terminate its exact owning transport');
      console.log(`PASS capture-first: resume ${failure} retires the owning connection; release is not reported as acknowledged resume`);
    });
  }
  await fixture([info('a'),info('deadline','worker','a')],{delayTarget:'deadline',delays:{'Network.enable':2500,'Target.setAutoAttach':2500}},async({commands,waitState,until})=>{
    const held=await until(()=>commands().find(c=>c.event==='attached'&&c.target==='deadline'),'Watchdog attachment');
    const release=await until(()=>resumed(commands,'deadline'),'Independent startup watchdog releases slow initialization',10000);
    assert(release.time-held.time>=3500&&release.time-held.time<6500,'Startup hold must be independently bounded across consecutive initialization commands');
    await waitState(s=>s.network.capture_status.hold_timeouts>=1,'Hold timeout visible');
    console.log('PASS capture-first: cumulative initialization exceeds independent hold deadline; watchdog resumes and reports timeout');
  });
  await fixture([info('a'),...Array.from({length:8},(_,i)=>info(`queued-${i}`,'other'))],{detachDelay:900},async({commands,until,waitState})=>{
    const held=await until(()=>commands().find(c=>c.event==='attached'&&c.target==='queued-7'),'Attachment delivered behind slow event handlers');
    const release=await until(()=>resumed(commands,'queued-7'),'Ingress hold watchdog bypasses event-consumer backlog',8000);
    assert(release.time-held.time<5500,'Queued attachment hold must be timed from ingress, not eventual event handling');
    await waitState(s=>s.network.capture_status.hold_timeouts>=1,'Starved event-loop hold deadline visible');
    console.log('PASS capture-first: slow detach/event-consumer backlog cannot postpone ingress hold watchdog');
  });
  await fixture([info('a'),info('overflow'),info('rejected','other')],{limit:1},async({commands,waitState,until})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1&&s.network.capture_status.target_overflow===1,'Bounded capture owner');
    for(const id of ['overflow','rejected']) {
      await until(()=>resumed(commands,id),`${id} releases startup`);await assertResumeBeforeDetach(commands,id);
      assert(!capture(commands).some(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':'+id)),`${id} must not consume Network buffers`);
    }
    console.log('PASS capture-first: overflow and rejected target are resumed before detach without Network buffers');
  });
  await fixture([info('a'),info('pending','worker','a')],{failTarget:'pending',failMethod:'Network.enable',failure:'timeout'},async({commands,send,until})=>{
    await until(()=>capture(commands).some(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':pending')),'Nested initialization pending');
    const held=commands().find(c=>c.event==='attached'&&c.target==='pending');send({detach:'a'});
    await until(()=>released(commands,held.sessionId),'Cancelled descendant attachment released by ancestor detach');
    console.log('PASS capture-first: ancestor detach cancels a pending child; detached CDP session releases its startup hold');
  });
  for(const terminate of ['shutdown','disconnect']) {
    await fixture([info('a'),info('pending','worker','a')],{failTarget:'pending',failMethod:'Network.enable',failure:'timeout'},async({commands,send,until,stop})=>{
      await until(()=>capture(commands).some(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':pending')),'Initialization pending before teardown');
      const held=commands().filter(c=>c.event==='attached'&&c.waiting);
      if(terminate==='shutdown')await stop();else send({disconnect:true});
      await until(()=>held.every(c=>released(commands,c.sessionId)),`${terminate} releases every held session`);
      const reasons=held.map(c=>commands().find(r=>r.event==='release'&&r.sessionId===c.sessionId)?.reason??'transport-process-exited');
      console.log(`PASS capture-first: ${terminate} while initializing releases all held sessions (${[...new Set(reasons)].join(', ')})`);
    });
  }
  await fixture([info('a'),info('worker','worker','a')],{passive:true},async({commands,waitState,add,until})=>{
    const s=await waitState(s=>s.network.capture_status.attached_targets===2,'Passive baseline');
    assert.equal(s.network.capture_status.startup_mode,'passive');
    add(info('external-paused','worker','a'),true);
    await until(()=>capture(commands).some(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId?.endsWith(':external-paused')),'Passive session rejects an unexpected held target');
    assert(capture(commands).filter(c=>c.method==='Target.setAutoAttach').every(c=>c.params.waitForDebuggerOnStart===false));
    assert(!capture(commands).some(c=>c.method.startsWith('Runtime.')||c.method.startsWith('Debugger.')||c.method.startsWith('Page.')));
    console.log('PASS passive baseline: external browser remains observational with no startup holds or Runtime commands');
  });
  for(const passive of [false,true]) {
    const context=t=>({...t,browserContextId:'owned-context'});
    await fixture([context(info('a'))],{passive,experiment:true,delayTarget:'experiment-worker',delayCaptureOnly:true,delays:{'Network.enable':2500}},async({commands,action,waitState,until,add})=>{
      await waitState(s=>s.state==='running'&&s.network.capture_status.attached_targets===1,'Experiment baseline ready');
      await action({action:'create_request_interception_experiment'});
      await waitState(s=>s.request_interception.isolated===true&&s.request_interception.target_id==='a','Disposable context established through public action');
      const capturePid=capture(commands).find(c=>c.method==='Target.setAutoAttach'&&!c.sessionId&&c.params.autoAttach).pid;
      add(context(info('experiment-worker','worker','a')));
      const controller=await until(()=>capture(commands).find(c=>c.pid!==capturePid&&c.method==='Debugger.enable'&&c.sessionId?.endsWith(':experiment-worker')),'Independent experiment-worker controller initializes');
      const controlCommands=()=>capture(commands).filter(c=>c.pid===controller.pid&&c.sessionId===controller.sessionId);
      assert(controlCommands().some(c=>c.method==='Runtime.enable'),'Worker controller still enables Runtime');
      if(passive) {
        assert(controlCommands().some(c=>c.method==='Runtime.runIfWaitingForDebugger'),'Passive experiment-worker behavior must remain unchanged');
      } else {
        assert(!controlCommands().some(c=>c.method==='Runtime.runIfWaitingForDebugger'),'Independent worker controller must not bypass the owned capture startup hold');
        assert(!resumed(commands,'experiment-worker'),'Competing debugger must initialize while capture Network.enable is still pending');
        const resumedByCapture=await until(()=>resumed(commands,'experiment-worker'),'Capture owner resumes after its delayed Network setup');
        assert.equal(resumedByCapture.pid,capturePid,'Only the capture owner releases the startup hold');
        const network=capture(commands).find(c=>c.pid===capturePid&&c.method==='Network.enable'&&c.sessionId?.endsWith(':experiment-worker'));
        assert(resumedByCapture.time-network.time>=2400,'Startup resume must follow capture Network.enable acknowledgement');
        assert(!controlCommands().some(c=>c.method==='Runtime.runIfWaitingForDebugger'),'Controller stays free of competing resumes after capture readiness');
      }
      console.log(`PASS ${passive?'passive':'capture-first'} experiment: worker-controller initialization ${passive?'retains its original resume':'cannot bypass capture-owned startup hold'}`);
    });
  }
  for(const [label,params] of [
    ['non-object params',null],
    ['missing waiting state',{sessionId:'ambiguous',targetInfo:info('ambiguous','worker','a')}],
    ['non-boolean waiting state',{sessionId:'ambiguous',targetInfo:info('ambiguous','worker','a'),waitingForDebugger:'true'}],
  ]) {
    await fixture([info('a')],{malformed:true},async({commands,send,waitState,until})=>{
      await waitState(s=>s.network.capture_status.attached_targets===1,'Malformed-attachment baseline ready');
      const connection=capture(commands).find(c=>c.method==='Target.setAutoAttach'&&!c.sessionId&&c.params.autoAttach);
      send({raw:{method:'Target.attachedToTarget',params}});
      await until(()=>!alive(connection.pid),`${label}: close exact owned capture transport`,5000);
      assert(!capture(commands).some(c=>c.pid===connection.pid&&c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId==='ambiguous'),'Malformed waiting state must not authorize an ambiguous resume');
      console.log(`PASS capture-first: ${label} retires exact capture connection instead of leaving an unknown startup hold`);
    });
  }
  if(!selected)for(const args of [
    ['--capture-first-browser','/synthetic/not-launched'],
    ['--capture-network-content','--capture-first-browser','/synthetic/not-launched','--devtools-active-port','/synthetic/active'],
    ['--capture-first-headless'],
    ['--capture-first-owned'],
  ]) {
    const child=spawn(binary,args);let output='';
    for(const pipe of [child.stdout,child.stderr])pipe.on('data',chunk=>output+=chunk);
    const closed=new Promise(r=>child.once('close',r));
    assert(await waitForClose(closed,5000),'Invalid capture-first CLI must fail promptly');
    assert.notEqual(child.exitCode,0,`Invalid CLI unexpectedly succeeded: ${args.join(' ')} ${output}`);
  }
  if(!selected)console.log('PASS capture-first CLI: content-capture requirement, external-browser exclusion, and headless ownership requirement');
}
