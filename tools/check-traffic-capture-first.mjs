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
  const sessions=new Map(),held=new Set(),autoParents=new Set(),enableAfterResume=new Map();let serial=0,pending=Buffer.alloc(0),rootHold=false,rootAuto=false,capturing=false,closed=false;
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
        if(replyDelay)setTimeout(()=>{log({event:'delayed-reply',browser,method:m.method,sessionId:m.sessionId});emit(message);},replyDelay);else {if(options.ownedNavigation)log({event:'reply',browser,method:m.method,sessionId:m.sessionId});emit(message);}
      };
      const reject=message=>emit({id:m.id,error:{code:-32000,message},...(m.sessionId?{sessionId:m.sessionId}:{})});
      const target=[...sessions].find(([,sid])=>sid===m.sessionId)?.[0];
      if(browser&&options.orderedInit&&target==='ordered-worker'&&m.method==='Network.enable') {
        enableAfterResume.set(m.sessionId,()=>{
          if(options.enableOutcome==='timeout')return;
          const finish=()=>{log({event:'ordered-enable-reply',browser,sessionId:m.sessionId,outcome:options.enableOutcome??'success'});if(options.enableOutcome==='error')reject('synthetic ordered Network.enable failure');else reply({});};
          if(options.enableReplyDelay===0)finish();else setTimeout(finish,options.enableReplyDelay??600);
        });
        log({event:'ordered-enable-withheld',browser,sessionId:m.sessionId});
        continue;
      }
      if(browser&&target===options.failTarget&&m.method===options.failMethod) {
        if(options.orderedInit&&m.method==='Runtime.runIfWaitingForDebugger'){const finishEnable=enableAfterResume.get(m.sessionId);enableAfterResume.delete(m.sessionId);finishEnable?.();}
        if(options.failure==='error')reject('synthetic initialization failure');
        // Timeout deliberately never replies; production must bound it.
        if(options.failure==='error'||options.failure==='timeout')continue;
      }
      if(options.ownedNavigation&&capturing&&target==='navigation-new'&&m.method==='Network.enable'&&options.navigationFault==='timeout')continue;
      if(options.ownedNavigation&&m.method==='Target.createTarget') {
        if(!existsSync(join(fixtureDirectory,'experiment-created'))){writeFileSync(join(fixtureDirectory,'experiment-created'),'1');reply({targetId:'a'});}
        else if(options.navigationFault==='create-no-reply')continue;
        else if(options.navigationFault==='malformed-create-ID')reply({targetId:7});
        else if(options.navigationFault==='owner-readiness-timeout')reply({targetId:'navigation-new'});
        else {const targetInfo={targetId:'navigation-new',type:'page',title:'new',url:m.params.url,browserContextId:'owned-context'};writeFileSync(join(fixtureDirectory,'targets'),JSON.stringify([...targets(),targetInfo]));appendFileSync(join(fixtureDirectory,'events'),JSON.stringify({add:'navigation-new'})+'\n');reply({targetId:'navigation-new'});}
      }
      else if(options.ownedNavigation&&m.method==='Target.getTargetInfo'){const targetInfo=targets().find(t=>t.targetId===m.params.targetId);reply({targetInfo:options.navigationFault==='context-mismatch'?{...targetInfo,browserContextId:'different-context'}:targetInfo});}
      else if(options.ownedNavigation&&m.method==='Page.navigate'&&options.navigationFault==='navigate-no-reply')continue;
      else if(options.ownedNavigation&&m.method==='Page.navigate'&&options.navigationFault==='navigate-error')reply({errorText:'synthetic navigation rejected'});
      else if(options.ownedNavigation&&m.method==='Target.closeTarget') {
        writeFileSync(join(fixtureDirectory,'targets'),JSON.stringify(targets().filter(t=>t.targetId!==m.params.targetId)));appendFileSync(join(fixtureDirectory,'events'),JSON.stringify({raw:{method:'Target.targetDestroyed',params:{targetId:m.params.targetId}}})+'\n');reply({success:true});
      }
      else if(options.ownedNavigation&&m.method==='Target.disposeBrowserContext') {
        const removed=targets().filter(t=>t.browserContextId===m.params.browserContextId);writeFileSync(join(fixtureDirectory,'targets'),JSON.stringify(targets().filter(t=>t.browserContextId!==m.params.browserContextId)));for(const t of removed)appendFileSync(join(fixtureDirectory,'events'),JSON.stringify({raw:{method:'Target.targetDestroyed',params:{targetId:t.targetId}}})+'\n');reply({});
      }
      else if(options.experiment&&m.method==='Target.createBrowserContext')reply({browserContextId:'owned-context'});
      else if(options.experiment&&m.method==='Target.createTarget')reply({targetId:'a'});
      else if(m.method==='Target.setDiscoverTargets'){if(browser)capturing=m.params.discover;reply({});}
      else if(m.method==='Target.getTargets')reply({targetInfos:targets()});
      else if(m.method==='Target.attachToTarget')reply({sessionId:attach(targets().find(t=>t.targetId===m.params.targetId),undefined,false)});
      else if(m.method==='Runtime.runIfWaitingForDebugger') {
        release(m.sessionId,'acknowledged-resume');reply({});
        const finishEnable=enableAfterResume.get(m.sessionId);enableAfterResume.delete(m.sessionId);finishEnable?.();
      } else if(m.method==='Target.setAutoAttach') {
        reply({});
        if(browser&&!m.sessionId){rootAuto=m.params.autoAttach;capturing||=rootAuto;rootHold=rootAuto&&m.params.waitForDebuggerOnStart;}
        if(m.sessionId){if(m.params.autoAttach)autoParents.add(m.sessionId);else autoParents.delete(m.sessionId);}
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
      if(event.raw){
        const p=event.raw.params;
        if(event.raw.method==='Target.attachedToTarget'&&p?.waitingForDebugger===true&&typeof p.sessionId==='string')held.add(p.sessionId);
        emit(event.raw);continue;
      }
      if(event.disconnect)close('injected-disconnect');
      if(event.add) {
        const info=targets().find(t=>t.targetId===event.add);
        emit({method:'Target.targetCreated',params:{targetInfo:info}});
        const parent=info.parent?sessions.get(info.parent):undefined;
        if(rootAuto||autoParents.has(parent)||event.hold!==undefined)attach(info,parent,event.hold??rootHold);continue;
      }
      if(event.detach) {
        const sessionId=sessions.get(event.detach);detach(event.detach,'ancestor-detach');
        emit({method:'Target.detachedFromTarget',params:{sessionId,targetId:event.detach}});
      }
    }
  },15);
} else {
  const selected=process.env.REB_CAPTURE_FIRST_CASES;
  assert(!selected||['worker-controller','malformed-attachments','duplicate-owners','ordered-init','owned-navigation'].includes(selected),'Unknown REB_CAPTURE_FIRST_CASES selector');
  const root=resolve(process.argv[2]??'.');
  const binary=resolve(process.env.ORIGIN_TRACE_BACKEND||join(root,'apps/origin-trace-backend/target/debug/origin-trace-backend'));
  const info=(id,type='page',parent)=>({targetId:id,type,title:id,url:type==='page'?'about:blank':`http://localhost/${id}.js`,...(parent?{parent}:{})});
  const alive=pid=>{try{process.kill(pid,0);return true;}catch(error){if(error.code==='ESRCH')return false;throw error;}};
  async function fixture(initial,options,run) {
    if(selected==='owned-navigation'&&!options.ownedNavigation||selected&&selected!=='owned-navigation'&&options.ownedNavigation)return;
    if(selected==='ordered-init'&&!options.orderedInit||selected==='worker-controller'&&!options.experiment||selected==='malformed-attachments'&&!options.malformed||selected==='duplicate-owners'&&!options.duplicates)return;
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
    const actionResult=async(value)=>{
      address??=(await readFile(join(directory,'endpoint'),'utf8')).trim();
      const response=await fetch(new URL('/api/debugger/actions',address),{method:'POST',headers:{'Content-Type':'application/json',Origin:address},body:JSON.stringify(value),signal:AbortSignal.timeout(options.ownedNavigation?25000:10000)});
      const body=await response.text();return {ok:response.ok,status:response.status,body:JSON.parse(body)};
    };
    const action=async(value)=>{const result=await actionResult(value);assert(result.ok,`Action failed: ${result.status} ${JSON.stringify(result.body)}`);return result.body;};
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
      await run({commands,send,state,action,actionResult,until,waitState,signal:name=>owned.child.kill(name),exited:async(timeout=10000)=>{
        assert(await waitForClose(owned.closed,timeout),`Backend did not exit: ${diagnostics}`);
        return {code:owned.child.exitCode,signal:owned.child.signalCode,diagnostics};
      },stop:async()=>{
        await stopBrowserTestProcess(owned,5000);owned=null;
      },discover:t=>{catalog.push(t);save();send({raw:{method:'Target.targetCreated',params:{targetInfo:t}}});},remove:id=>{catalog=catalog.filter(t=>t.targetId!==id);save();send({raw:{method:'Target.targetDestroyed',params:{targetId:id}}});},add:(t,hold)=>{catalog.push(t);save();send({add:t.targetId,hold});}});
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
  for(const navigationFault of ['success','timeout','replacement','context-mismatch','navigate-error','disposal','passive']) {
    const passive=navigationFault==='passive';
    await fixture([{...info('a'),browserContextId:'owned-context'}],{ownedNavigation:true,experiment:true,passive,navigationFault,delayTarget:'navigation-new',delayCaptureOnly:true,delays:{'Network.enable':800,'Target.setAutoAttach':800}},async({commands,send,action,actionResult,waitState,until})=>{
      await waitState(s=>s.state==='running'&&s.network.capture_status.attached_targets===1,'Owned navigation baseline ready');
      await action({action:'create_request_interception_experiment'});
      await waitState(s=>s.request_interception.isolated===true,'Disposable context established');
      const wanted='http://localhost/owned-navigation-fixture';
      const pending=actionResult({action:'create_experiment_page',url:wanted});
      await until(()=>capture(commands).filter(c=>c.method==='Target.createTarget').length===2,'New page created once');
      const created=capture(commands).filter(c=>c.method==='Target.createTarget').at(-1);
      assert.equal(created.params.url,passive?wanted:'about:blank','Owned page creation must be inert before capture readiness');
      if(!passive){
        const enable=await until(()=>capture(commands).find(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':navigation-new')),'Exact new capture owner initializes');
        assert(!capture(commands).some(c=>c.method==='Page.navigate'&&c.params.url===wanted),'Navigation must wait for Network and recursive attach ACKs');
        if(navigationFault==='replacement'){await delay(100);send({detach:'navigation-new'});}
        if(navigationFault==='disposal'){await delay(100);const disposal=await actionResult({action:'dispose_request_interception_experiment'});assert.equal(disposal.status,409,'Concurrent disposal is rejected by the public action gate');assert.equal(disposal.body.code,'state_conflict');}
        const result=await pending;
        const navigations=capture(commands).filter(c=>c.method==='Page.navigate'&&c.params.url===wanted);
        if(navigationFault==='success'||navigationFault==='disposal'){
          assert(result.ok,JSON.stringify(result));assert.equal(result.body.target_id,'navigation-new');assert.equal(navigations.length,1);
          assert.equal(navigations[0].sessionId,enable.sessionId,'Page.navigate must use exact capture owner session');assert.equal(navigations[0].pid,enable.pid);
          const all=commands();
          // Compare stable command identity because each read creates fresh objects.
          const navIndex=all.findIndex(c=>c.event==='command'&&c.pid===navigations[0].pid&&c.id===navigations[0].id);
          for(const method of ['Network.enable','Target.setAutoAttach'])assert(all.findIndex(c=>c.event==='delayed-reply'&&c.method===method&&c.sessionId===enable.sessionId)<navIndex&&all.some(c=>c.event==='delayed-reply'&&c.method===method&&c.sessionId===enable.sessionId),'Both exact-session initialization ACKs precede navigation');
        }else{
          assert(!result.ok,`${navigationFault}: action must fail`);assert.equal(navigations.length,navigationFault==='navigate-error'?1:0,`${navigationFault}: no implicit navigation retry`);
          if(navigationFault!=='disposal'){const cleanup=await until(()=>capture(commands).find(c=>c.method==='Target.closeTarget'&&c.params.targetId==='navigation-new'),'Failed owned blank cleaned up');assert.equal(cleanup.pid,enable.pid,'Cleanup uses original capture connection');}
          assert(!capture(commands).some(c=>c.method==='Target.closeTarget'&&c.params.targetId!=='navigation-new'),'Failure cannot close unrelated page');
        }
      }else{assert((await pending).ok);assert(!capture(commands).some(c=>c.method==='Page.navigate'&&c.params.url===wanted),'Passive page creation remains direct');}
      if(navigationFault==='disposal')await action({action:'dispose_request_interception_experiment'});
      assert.equal(capture(commands).filter(c=>c.method==='Target.createTarget').length,2,'No implicit page creation retry');
      console.log(`PASS create_experiment_page product path: ${navigationFault}`);
    });
  }
  for(const navigationFault of ['create-no-reply','navigate-no-reply','malformed-create-ID','owner-readiness-timeout']) {
    await fixture([{...info('a'),browserContextId:'owned-context'}],{ownedNavigation:true,experiment:true,navigationFault},async({commands,action,actionResult,waitState,until})=>{
      await waitState(s=>s.state==='running'&&s.network.capture_status.attached_targets===1,'Uncertain navigation baseline ready');
      await action({action:'create_request_interception_experiment'});
      const wanted='http://localhost/uncertain-navigation-fixture',started=Date.now();
      const result=await actionResult({action:'create_experiment_page',url:wanted});
      assert(!result.ok,`${navigationFault}: action must fail`);
      const readiness=navigationFault==='owner-readiness-timeout';
      assert.equal(result.body.code,readiness?'timeout':'command_outcome_unknown',`${navigationFault}: outcome classification`);
      if(!readiness)assert.equal(result.body.details.cause,navigationFault==='malformed-create-ID'?'invalid_reply':'timeout');
      if(navigationFault!=='malformed-create-ID')assert(Date.now()-started>=14000&&Date.now()-started<23000,'Outer transaction deadline remains bounded');
      const creates=capture(commands).filter(c=>c.method==='Target.createTarget');assert.equal(creates.length,2,'No create retry after uncertain outcome');assert.equal(creates[1].params.url,'about:blank');
      const navigation=capture(commands).filter(c=>c.method==='Page.navigate'&&c.params.url===wanted);assert.equal(navigation.length,navigationFault==='navigate-no-reply'?1:0,'No navigation retry after uncertain outcome');
      if(navigationFault==='navigate-no-reply'||readiness)await until(()=>capture(commands).some(c=>c.method==='Target.closeTarget'),'Asynchronous known-target cleanup admitted',4000);
      const cleanup=capture(commands).filter(c=>c.method==='Target.closeTarget');
      if(navigationFault==='navigate-no-reply'||readiness){assert.equal(cleanup.length,1);assert.equal(cleanup[0].params.targetId,'navigation-new');assert.equal(cleanup[0].pid,creates[1].pid,'Known target cleanup uses exact original capture connection');}
      else assert.equal(cleanup.length,0,'Unknown created target identity cannot close unrelated targets');
      console.log(`PASS create_experiment_page outcome classification: ${navigationFault}`);
    });
  }
  await fixture([info('a')],{orderedInit:true,enableReplyDelay:1000},async({commands,waitState,until,add,state})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Owned page ready before ordered worker');
    add(info('ordered-worker','worker','a'));
    const enable=await until(()=>commands().find(c=>c.event==='ordered-enable-withheld'),'Worker enable waits for authorized release');
    await until(()=>resumed(commands,'ordered-worker'),'Ordered worker startup released without waiting for Network ACK',2500);
    const all=capture(commands).filter(c=>c.sessionId===enable.sessionId);
    const network=all.findIndex(c=>c.method==='Network.enable'),recurse=all.findIndex(c=>c.method==='Target.setAutoAttach'&&c.params.waitForDebuggerOnStart===true),resume=all.findIndex(c=>c.method==='Runtime.runIfWaitingForDebugger');
    assert(network>=0&&recurse>network&&resume>recurse,'Network command bytes precede recursive autoattach and exact owned startup release');
    assert(!commands().some(c=>c.event==='ordered-enable-reply'),'Release must occur before withheld Network.enable reply');
    assert(!(await state()).network.capture_status.attached_target_ids.includes('ordered-worker'),'Released worker remains unready until Network.enable acknowledgment');
    await until(()=>commands().some(c=>c.event==='ordered-enable-reply'),'Network ACK follows authorized release');
    await waitState(s=>s.network.capture_status.attached_target_ids.includes('ordered-worker'),'Delayed Network ACK completes owner readiness');
    assert.equal(capture(commands).filter(c=>c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId===enable.sessionId).length,1,'Initial exact hold is released once');
    console.log('PASS capture-first ordered initialization: enable bytes, recursive attach, owned release, delayed ACK, readiness');
  });
  for(const enableOutcome of ['error','timeout'])await fixture([info('a')],{orderedInit:true,enableOutcome,enableReplyDelay:100},async({commands,waitState,until,add})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Owned page before failing ordered worker');
    add(info('ordered-worker','worker','a'));
    const enable=await until(()=>commands().find(c=>c.event==='ordered-enable-withheld'),'Failing ordered enable sent');
    const resume=await until(()=>resumed(commands,'ordered-worker'),'Failing ordered worker hold released boundedly',5500);
    assert(resume.time-enable.time<5000,'Network ACK failure cannot strand authorized startup hold');
    const failed=await waitState(s=>s.network.capture_status.gaps>0&&s.network.capture_status.failed_targets>0,'Ordered ACK failure remains visible',6000);
    assert(!failed.network.capture_status.attached_target_ids.includes('ordered-worker'),'Failed ACK cannot mark released owner ready');
    await assertResumeBeforeDetach(commands,'ordered-worker');
    console.log(`PASS capture-first ordered initialization: ${enableOutcome} ACK leaves explicit failure after bounded owned release`);
  });
  for(const failure of ['error','timeout'])await fixture([info('a')],{orderedInit:true,enableReplyDelay:0,failTarget:'ordered-worker',failMethod:'Runtime.runIfWaitingForDebugger',failure},async({commands,waitState,until,add,state})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Page ready before ordered resume failure');
    add(info('ordered-worker','worker','a'));
    const enable=await until(()=>commands().find(c=>c.event==='ordered-enable-withheld'),'Ordered worker starts before resume failure');
    await until(()=>commands().some(c=>c.event==='ordered-enable-reply'),'Network ACK succeeds as resume is attempted');
    // Observe during the resume deadline, not only after asynchronous EOF retirement.
    await until(async()=>{
      const snapshot=await state();
      assert(!snapshot.network.capture_status.attached_target_ids.includes('ordered-worker'),'Failed authorized resume must never advertise its owner ready');
      return !alive(enable.pid);
    },'Failed ordered resume closes exact transport',6500);
    assert(!resumed(commands,'ordered-worker'),'Rejected or timed-out resume is never acknowledged');
    assert(released(commands,enable.sessionId),'Transport closure releases failed ordered hold');
    console.log(`PASS capture-first ordered initialization: Network ACK cannot make ${failure} resume owner ready`);
  });
  for(const passive of [false,true])await fixture([info('a')],{orderedInit:true,passive},async({commands,waitState,until,add})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Baseline owner before unowned startup');
    add(info('ordered-worker','worker','a'),false);
    const enable=await until(()=>commands().find(c=>c.event==='ordered-enable-withheld'),'Unheld worker enable sent');
    await waitState(s=>s.network.capture_status.failed_targets>0,'Unowned enable times out without a release',6000);
    assert(!capture(commands).some(c=>c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId===enable.sessionId),'Unheld or passive owner must never gain startup-release authority');
    if(passive)assert(!capture(commands).some(c=>c.method==='Runtime.runIfWaitingForDebugger'),'Passive capture never releases any target');
    console.log(`PASS ${passive?'passive':'owned unheld'} ordered initialization: no release without exact registered hold`);
  });
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
  for(const firstHeld of [false,true])await fixture([info('a')],{duplicates:true,delayTarget:'dup',delays:{'Network.enable':1500}},async({commands,waitState,until,add,send})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Initial owned owner');
    assert(!capture(commands).some(c=>c.method==='Target.attachToTarget'),'Owned initial discovery must not race root auto-attachment');
    send({raw:{method:'Target.targetCreated',params:{targetInfo:info('discovered-only')}}});
    add(info('dup'),firstHeld);
    const enable=await until(()=>capture(commands).find(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':dup')),'Delayed duplicate owner setup');
    const duplicate=`${enable.sessionId.split(':')[0]}:duplicate:dup`;
    send({raw:{method:'Target.attachedToTarget',params:{sessionId:duplicate,targetInfo:info('dup'),waitingForDebugger:!firstHeld}}});
    add(info('other'));
    await until(()=>resumed(commands,'other'),'Dispatcher progresses while duplicate owner initializes');
    const held=firstHeld?enable.sessionId:duplicate;
    if(!firstHeld)assert(!capture(commands).some(c=>c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId===held),'Held duplicate cannot resume before the exact existing owner is ready');
    if(firstHeld)await until(()=>capture(commands).some(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId===duplicate),'Nonwaiting duplicate detached');
    const resume=await until(()=>capture(commands).find(c=>c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId===held),'Held owner resumed after setup');
    if(!firstHeld)assert(resume.time-enable.time>=1400,'Delayed Network.enable must settle before held duplicate release');
    else assert(!commands().some(c=>c.event==='delayed-reply'&&c.method==='Network.enable'&&c.sessionId===held&&c.time<resume.time),'Initial exact held owner releases before delayed ACK, without granting duplicate authority');
    await waitState(s=>s.network.capture_status.attached_targets===3,'Exactly three independent owners remain');
    assert(!capture(commands).some(c=>c.method==='Target.attachToTarget'&&c.params.targetId==='discovered-only'),'Owned first-seen catalog must not enter explicit admission');
    assert.equal(capture(commands).filter(c=>c.method==='Network.enable'&&c.sessionId===duplicate).length,0,'Duplicate never becomes a second capture owner');
    if(!firstHeld)await until(()=>capture(commands).some(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId===duplicate),'Released duplicate detached');
    console.log(`PASS capture-first duplicate ownership: ${firstHeld?'held':'nonwaiting'} first, exact-owner setup barrier, independent dispatcher, no eager explicit race`);
  });
  await fixture([info('a')],{duplicates:true,failTarget:'dup',failMethod:'Network.enable',failure:'timeout'},async({commands,waitState,until,add,send})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Initial owner before failed duplicate');
    add(info('dup'),false);
    const enable=await until(()=>capture(commands).find(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':dup')),'Failing owner setup');
    const duplicate=`${enable.sessionId.split(':')[0]}:duplicate:dup`;
    send({raw:{method:'Target.attachedToTarget',params:{sessionId:duplicate,targetInfo:info('dup'),waitingForDebugger:true}}});
    const resume=await until(()=>capture(commands).find(c=>c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId===duplicate),'Failed exact-owner duplicate released',8000);
    assert(resume.time-enable.time>=2500,'Failure release must await failed setup rather than prematurely resume');
    await waitState(s=>s.network.capture_status.gaps>0,'Failed duplicate reports an evidence gap');
    await until(()=>capture(commands).some(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId===duplicate),'Failed duplicate detached');
    console.log('PASS capture-first duplicate failure: bounded exact-owner failure release and visible gap');
  });
  await fixture([info('a')],{duplicates:true,limit:1,detachDelay:800},async({commands,waitState,until,add,send})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Healthy owner before rejected hold');
    const sessionId=capture(commands).find(c=>c.method==='Network.enable'&&c.sessionId?.endsWith(':a')).sessionId;
    add(info('overflow'));
    await until(()=>capture(commands).some(c=>c.method==='Target.detachFromTarget'&&c.params.sessionId?.endsWith(':overflow')),'Rejected held session awaits detach');
    for(const [method,params] of [
      ['Network.requestWillBeSent',{requestId:'during-detach',request:{url:'http://localhost/during-detach',method:'GET',headers:{}},timestamp:1,type:'Fetch'}],
      ['Network.responseReceived',{requestId:'during-detach',response:{status:200,headers:{},mimeType:'text/plain'}}],
      ['Network.loadingFinished',{requestId:'during-detach',timestamp:2,encodedDataLength:10}],
    ])send({raw:{method,params,sessionId}});
    await until(()=>capture(commands).some(c=>c.method==='Network.getResponseBody'&&c.params.requestId==='during-detach'),'Healthy owner progresses during rejected hold cleanup');
    const rows=commands(),body=rows.findIndex(c=>c.method==='Network.getResponseBody'&&c.params?.requestId==='during-detach');
    const detached=rows.findIndex(c=>c.event==='delayed-reply'&&c.method==='Target.detachFromTarget');
    assert(body>=0&&(detached<0||body<detached),'Healthy body request must precede delayed rejected-session detach acknowledgment');
    await assertResumeBeforeDetach(commands,'overflow');
    console.log('PASS capture-first cleanup: rejected hold resumes before detach without blocking healthy-owner evidence');
  });
  await fixture([info('a')],{duplicates:true,limit:1},async({commands,waitState,until,add,discover,remove})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Owned owner before quiet catalog overflow');
    for(let i=0;i<511;i++)discover(info(`catalog-${i}`));
    await waitState(s=>s.network.capture_status.eligible_targets===512,'Owned catalog fills without eager explicit attachment');
    add(info('omitted'));
    await until(()=>resumed(commands,'omitted'),'Uncatalogued held target safely released');
    await waitState(s=>s.network.capture_status.catalog_incomplete===true,'Owned incomplete catalog visible');
    assert(!capture(commands).some(c=>c.method==='Target.attachToTarget'),'Initial/live discovery never races root hold authority');
    remove('a');
    await waitState(s=>s.network.capture_status.attached_target_ids.includes('omitted'),'Quiet reconciliation recovers omitted owned target',12000);
    assert(capture(commands).some(c=>c.method==='Target.attachToTarget'&&c.params.targetId==='omitted'),'Only reconciliation makes omitted target eligible for explicit recovery');
    assert(!capture(commands).some(c=>c.method==='Target.attachToTarget'&&c.params.targetId.startsWith('catalog-')),'Known first-seen targets do not leak into explicit recovery');
    console.log('PASS capture-first catalog: quiet overflow target is released, then explicitly recovered after catalog and owner capacity free');
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
    const release=await until(()=>resumed(commands,'deadline'),'Ordered startup releases overlapping slow initialization',10000);
    assert(release.time-held.time>=2400&&release.time-held.time<4500,'Ordered initialization overlaps ACK waits instead of accumulating startup delays');
    const ready=await waitState(s=>s.network.capture_status.attached_target_ids.includes('deadline'),'Overlapping initialization becomes ready');
    assert.equal(ready.network.capture_status.hold_timeouts??0,0,'Overlapping waits do not manufacture a watchdog timeout');
    console.log('PASS capture-first: ordered initialization overlaps Network and recursive attach ACK waits within startup bound');
  });
  await fixture([info('a'),...Array.from({length:24},(_,i)=>info(`queued-${i}`,'other'))],{detachDelay:900},async({commands,until,waitState})=>{
    const last=await until(()=>commands().find(c=>c.event==='attached'&&c.target==='queued-23'),'Held cleanup burst reaches transport');
    const held=commands().filter(c=>c.event==='attached'&&c.waiting&&c.pid===last.pid);
    await until(()=>held.every(c=>resumed(commands,c.target)),'Queued cleanup holds all acknowledged',8000);
    assert(held.every(c=>resumed(commands,c.target).time-c.time<5500),'Every queued startup hold stays bounded from ingress');
    await until(()=>commands().filter(c=>c.pid===last.pid&&c.event==='delayed-reply'&&c.method==='Target.detachFromTarget').length===24,'Queued cleanup acknowledges every rejected session',8000);
    let active=0,max=0;
    for(const row of commands().filter(c=>c.pid===last.pid)) {
      if(row.event==='command'&&row.method==='Target.detachFromTarget')max=Math.max(max,++active);
      if(row.event==='delayed-reply'&&row.method==='Target.detachFromTarget')active--;
    }
    assert(max<=4,'Only four queued cleanup commands may be in flight');
    assert(!commands().some(c=>c.event==='transport-close'&&c.pid===last.pid),'Ordinary duplicate fan-out must not close capture');
    await waitState(s=>s.network.capture_status.attached_targets===1&&s.network.capture_status.hold_timeouts>=1,'Healthy owner retained and queued hold watchdog visible');
    console.log('PASS capture-first: bounded cleanup FIFO drains fan-out while independent watchdog releases queued startup holds');
  });
  await fixture([info('a')],{duplicates:true,detachDelay:900,failTarget:'pending',failMethod:'Network.enable',failure:'timeout'},async({commands,until,waitState,add,send})=>{
    await waitState(s=>s.network.capture_status.attached_targets===1,'Healthy owner before true cleanup saturation');
    add(info('pending'));
    const held=await until(()=>commands().find(c=>c.event==='attached'&&c.target==='pending'),'Registered startup hold pending');
    await until(()=>capture(commands).some(c=>c.method==='Network.enable'&&c.sessionId===held.sessionId),'Held owner initialization pending');
    for(let start=0;start<520;start+=20) {
      for(let i=start;i<start+20;i++)send({raw:{method:'Target.attachedToTarget',params:{sessionId:`${held.pid}:overflow:${i}`,targetInfo:info(`unowned-${i}`,'other'),waitingForDebugger:false}}});
      await delay(20);
    }
    await until(()=>released(commands,held.sessionId),'True cleanup queue saturation releases exact pending hold',8000);
    const releasedAt=commands().find(c=>c.event==='release'&&c.sessionId===held.sessionId)?.time??Date.now();
    assert(releasedAt-held.time<5500,'Queue overflow cannot leave the registered startup hold suspended');
    await until(()=>commands().some(c=>c.event==='transport-close'&&c.pid===held.pid)||!alive(held.pid),'True saturation closes the exact owning transport');
    await waitState(s=>s.network.capture_status.gaps>0&&/cleanup.*capacity/i.test(s.network.capture_status.last_error),'Cleanup-capacity reason remains explicit');
    assert(!capture(commands).some(c=>c.method==='Runtime.runIfWaitingForDebugger'&&c.sessionId?.includes(':overflow:')),'Nonwaiting alternate sessions must never be resumed');
    let active=0,max=0;
    for(const row of commands().filter(c=>c.pid===held.pid)) {
      if(row.event==='command'&&row.method==='Target.detachFromTarget')max=Math.max(max,++active);
      if(row.event==='delayed-reply'&&row.method==='Target.detachFromTarget')active--;
    }
    assert(max<=4,'True queue overflow still bounds concurrent cleanup');
    console.log('PASS capture-first: true cleanup saturation closes exact client and releases its pending registered hold');
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
      const capturePid=capture(commands).find(c=>c.method==='Target.setDiscoverTargets'&&c.params.discover).pid;
      add(context(info('experiment-worker','worker','a')));
      const controller=await until(()=>capture(commands).find(c=>c.pid!==capturePid&&c.method==='Debugger.enable'&&c.sessionId?.endsWith(':experiment-worker')),'Independent experiment-worker controller initializes');
      const controlCommands=()=>capture(commands).filter(c=>c.pid===controller.pid&&c.sessionId===controller.sessionId);
      assert(controlCommands().some(c=>c.method==='Runtime.enable'),'Worker controller still enables Runtime');
      if(passive) {
        assert(controlCommands().some(c=>c.method==='Runtime.runIfWaitingForDebugger'),'Passive experiment-worker behavior must remain unchanged');
      } else {
        assert(!controlCommands().some(c=>c.method==='Runtime.runIfWaitingForDebugger'),'Independent worker controller must not bypass the owned capture startup hold');
        // The registered capture owner may release after its ordered send; the independent controller still has no release authority.
        const resumedByCapture=await until(()=>resumed(commands,'experiment-worker'),'Capture owner performs its authorized ordered startup release');
        assert.equal(resumedByCapture.pid,capturePid,'Only the capture owner releases the startup hold');
        const network=capture(commands).find(c=>c.pid===capturePid&&c.method==='Network.enable'&&c.sessionId?.endsWith(':experiment-worker'));
        const ordered=capture(commands).filter(c=>c.pid===capturePid&&c.sessionId===network.sessionId);
        assert(ordered.findIndex(c=>c.method==='Target.setAutoAttach')>ordered.findIndex(c=>c.method==='Network.enable'),'Capture enable bytes precede recursive autoattach');
        assert(ordered.findIndex(c=>c.method==='Runtime.runIfWaitingForDebugger')>ordered.findIndex(c=>c.method==='Target.setAutoAttach'),'Only capture releases after recursive attach');
        await waitState(s=>s.network.capture_status.attached_target_ids.includes('experiment-worker'),'Capture readiness still awaits delayed Network ACK');
        const ack=commands().find(c=>c.event==='delayed-reply'&&c.pid===capturePid&&c.method==='Network.enable'&&c.sessionId===network.sessionId);
        assert(ack&&ack.time>=resumedByCapture.time,'Initial ordered release precedes Network ACK');
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
