// Explicit opt-in only. No page scripts, interaction, challenges or raw exports.
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {stopBrowserTestProcess} from './browser-test-process.mjs';

export const targets=[['fingerprint','https://demo.fingerprint.com/playground'],['hcaptcha','https://accounts.hcaptcha.com/demo']];
const hosts=new Set(['demo.fingerprint.com','api.fpjs.io','eu.api.fpjs.io','ap.api.fpjs.io','fpjscdn.net','accounts.hcaptcha.com','api.hcaptcha.com','newassets.hcaptcha.com','js.hcaptcha.com','hcaptcha.com']);
const types=new Set(['Document','Stylesheet','Image','Media','Font','Script','TextTrack','XHR','Fetch','Prefetch','EventSource','WebSocket','Manifest','SignedExchange','Ping','CSPViolationReport','Preflight','Other']);
const count=value=>Number.isSafeInteger(value)&&value>=0?value:null;
export function summarize(snapshot) {
  const groups=new Map();
  for(const row of snapshot?.network?.requests??[]) {
    let host='other';try{const h=new URL(row.url).hostname;if(hosts.has(h))host=h;}catch{}
    const type=types.has(row.resource_type)?row.resource_type:'Other';
    const status=Number.isInteger(row.status)&&row.status>=100&&row.status<=599?row.status:'unavailable';
    const key=JSON.stringify([host,type,status]);groups.set(key,(groups.get(key)??0)+1);
  }
  const c=snapshot?.network?.capture_status??{};
  return {requests:[...groups].sort(([a],[b])=>a.localeCompare(b)).map(([key,n])=>{const [host,type,status]=JSON.parse(key);return {host,type,status,count:n};}),coverage:{transport:['browser-sessions','page-fallback'].includes(c.transport_mode)?c.transport_mode:'unknown',attached:count(c.attached_targets),eligible:count(c.eligible_targets),failed:count(c.failed_targets),overflow:count(c.target_overflow),gaps:count(c.gaps),dropped:count(snapshot?.network?.dropped),state:['waiting','ready','partial','disconnected'].includes(c.state)?c.state:'unknown',discovery_stale:typeof c.discovery_stale==='boolean'?c.discovery_stale:null},native_fingerprinting:'not-tested-stock-chrome',ui_display:'not-tested-backend-only',completeness:'bounded-passive-observation-not-lossless'};
}

export function summarizeTargets(snapshot, targetIds) {
  const rows=snapshot?.network?.requests??[];
  const results=targets.map(([label,url],index)=>{
    const own=rows.filter(row=>row.target_id===targetIds[index]);
    const main=own.some(row=>row.resource_type==='Document'&&row.url===url);
    return {target:label,outcome:main?'request-observed':'request-not-observed',requests:summarize({network:{requests:own}}).requests};
  });
  const {coverage,native_fingerprinting,ui_display,completeness}=summarize(snapshot);
  return {results,coverage,native_fingerprinting,ui_display,completeness,attribution:'exact-top-level-cdp-target-only-separate-child-worker-targets-not-attributed',unattributed_requests:rows.filter(row=>!targetIds.includes(row.target_id)).length};
}

async function visitTogether(root) {
  const dir=await mkdtemp(join(tmpdir(),'reb-public-smoke-'));
  const processes=[],pending=new Map();let ws,serial=0,stage='browser-startup',outcome;
  const start=(exe,args)=>{
    const child=spawn(exe,args,{cwd:dir,stdio:['ignore','ignore','ignore']});
    const item={child,closed:new Promise(r=>{child.once('close',r);child.once('error',r);})};processes.push(item);return item;
  };
  const delay=ms=>new Promise(r=>setTimeout(r,ms));
  const until=async fn=>{const end=Date.now()+30000;while(Date.now()<end){const v=await fn().catch(()=>null);if(v)return v;if(processes.some(p=>p.child.exitCode!==null||p.child.signalCode!==null))break;await delay(100);}throw Error('stage failed');};
  try {
    const browser=process.env.ORIGIN_TRACE_TEST_BROWSER;if(!browser)throw Error('missing browser');
    start(browser,['--headless=new','--disable-dev-shm-usage','--disable-background-networking','--no-first-run','--remote-debugging-port=0',`--user-data-dir=${dir}/profile`,'about:blank']);
    const active=join(dir,'profile/DevToolsActivePort');
    const lines=await until(async()=>{const a=(await readFile(active,'utf8')).trim().split('\n');return /^\d+$/.test(a[0])&&a[1]?.startsWith('/devtools/browser/')&&a;});
    stage='control-connection';ws=new WebSocket(`ws://127.0.0.1:${lines[0]}${lines[1]}`);
    await new Promise((res,rej)=>{const timer=setTimeout(()=>rej(Error('timeout')),5000);ws.onopen=()=>{clearTimeout(timer);res();};ws.onerror=()=>{clearTimeout(timer);rej(Error('socket'));};});
    ws.onmessage=e=>{const m=JSON.parse(e.data),p=pending.get(m.id);if(p){pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(Error('command')):p.resolve(m.result);}};
    const command=(method,params={},sessionId)=>new Promise((resolveCommand,reject)=>{const id=++serial,timer=setTimeout(()=>{pending.delete(id);reject(Error('command timeout'));},10000);pending.set(id,{resolve:resolveCommand,reject,timer});ws.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});
    stage='backend-startup';
    start(resolve(process.env.ORIGIN_TRACE_BACKEND||join(root,'apps/origin-trace-backend/target/debug/origin-trace-backend')),['--port','0','--endpoint-file',join(dir,'endpoint'),'--devtools-active-port',active,'--debugger-transport',resolve(process.env.ORIGIN_TRACE_DEBUGGER_TRANSPORT||join(root,'build/reb-debugger-transport')),'--capture-network-content']);
    const address=await until(async()=>{const a=(await readFile(join(dir,'endpoint'),'utf8')).trim();const parsed=new URL(a);return parsed.protocol==='http:'&&parsed.hostname==='127.0.0.1'&&a;});
    const state=async()=>{const r=await fetch(new URL('/api/debugger',address),{signal:AbortSignal.timeout(3000)});if(!r.ok)throw Error('state');return r.json();};
    stage='create-second-blank-target';
    const initial=(await command('Target.getTargets')).targetInfos.filter(t=>t.type==='page'&&t.url==='about:blank');
    if(initial.length!==1)throw Error('page count');
    const second=await command('Target.createTarget',{url:'about:blank'});
    const ids=[initial[0].targetId,second.targetId];
    if(!ids[1]||ids[0]===ids[1])throw Error('target identity');
    stage='capture-readiness';
    await until(async()=>{const s=await state();return s.state==='running'&&ids.every(id=>s.network?.capture_status?.attached_target_ids?.includes(id))&&s;});
    const sessions=[];
    for(const id of ids)sessions.push((await command('Target.attachToTarget',{targetId:id,flatten:true})).sessionId);
    stage='concurrent-single-navigation';
    await Promise.all(targets.map(([,url],i)=>command('Page.navigate',{url},sessions[i])));
    // Both remain open for the same bounded window. No page scripts or clicks.
    stage='overlapping-observation';await delay(15000);
    const snapshot=await state();
    outcome=summarizeTargets(snapshot,ids);
    const live=(await command('Target.getTargets')).targetInfos;
    outcome.simultaneous_targets_open=ids.every(id=>live.some(t=>t.targetId===id&&t.type==='page'));
    outcome.simultaneous_capture_ready=ids.every(id=>snapshot.network?.capture_status?.attached_target_ids?.includes(id));
  } catch {outcome={results:targets.map(([target])=>({target,outcome:'unavailable'})),stage,native_fingerprinting:'not-tested-stock-chrome',ui_display:'not-tested-backend-only'};}
  finally {
    for(const p of pending.values()){clearTimeout(p.timer);p.reject(Error('closed'));}pending.clear();ws?.close();
    let cleaned=true;for(const p of processes.reverse())try{await stopBrowserTestProcess(p);}catch{cleaned=false;}
    if(cleaned)try{await rm(dir,{recursive:true,force:true});}catch{cleaned=false;}
    if(!cleaned)outcome={...outcome,cleanup:'failed-private-profile-retained'};
  }
  return outcome;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if(process.env.REB_PUBLIC_DEMO_OPT_IN!=='passive-one-visit-per-demo') {
    console.error('Explicit REB_PUBLIC_DEMO_OPT_IN=passive-one-visit-per-demo is required.');process.exitCode=2;
  } else {
    const root=resolve(process.argv[2]??'.');let observation;
    try{observation=await visitTogether(root);}catch{observation={results:targets.map(([target])=>({target,outcome:'unavailable'})),stage:'private-session-setup'};}
    const report={schema:'reb-public-passive-summary-v2',...observation};
    try{await writeFile(resolve(process.env.REB_PUBLIC_DEMO_REPORT||'public-demo-summary.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});}catch{console.error('Aggregate report write failed.');process.exitCode=1;}
    console.log(JSON.stringify(report));
    if(report.results.some(r=>r.outcome!=='request-observed')||!report.simultaneous_targets_open||!report.simultaneous_capture_ready||report.cleanup)process.exitCode=1;
  }
}
