import assert from 'node:assert/strict';
import {inspect} from 'node:util';
import {mkdtemp,writeFile,readFile,rm,symlink,mkdir,stat,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {performance} from 'node:perf_hooks';
import {cookieDestination,parseCookieImport,readCookieImport,CookieImportError} from './cookie-import.mjs';
import {PrivateCookieContext,CookiePipe,launchCookieBrowser} from './cookie-import-browser.mjs';
import {runCookieImport} from './import-browser-cookies.mjs';

const origin='https://account.example.test',now=Date.now()/1000;
const name='synthetic_name_DO_NOT_REPORT',value='synthetic_value_DO_NOT_REPORT';
const row=overrides=>({domain:'account.example.test',hostOnly:true,httpOnly:true,name,path:'/',sameSite:'strict',secure:true,session:true,storeId:'0',value,...overrides});
const bytes=rows=>Buffer.from(JSON.stringify(rows));
const plan=(rows=[row()],format='chrome')=>parseCookieImport(bytes(rows),format,origin,30,now);
function safe(error){assert(error instanceof CookieImportError);assert(!String(error).includes(name));assert(!String(error).includes(value));return true;}

assert.deepEqual(cookieDestination(origin,30),{origin,host:'account.example.test',seconds:30});
for(const bad of ['http://account.example.test','https://account.example.test/','https://account.example.test/path','https://user:pass@account.example.test',
  'https://account.example.test?x=1','https://account.example.test#x','https://ACCOUNT.example.test','https://account.example.test.','https://localhost','https://127.0.0.1'])assert.throws(()=>cookieDestination(bad,30),safe);
for(const duration of [0,29,301,Infinity,30.5,'30'])assert.throws(()=>cookieDestination(origin,duration),safe);
for(const patch of [
  {domain:'.example.test'}, {domain:'other.example.test'}, {domain:'.account.example.test'}, {domain:'account.example.test.'}, {domain:'ACCOUNT.example.test'},
  {hostOnly:'true'}, {secure:1}, {httpOnly:null}, {session:'false'}, {name:''}, {name:'bad;name'}, {name:'bad=name'}, {name:'bad name'},
  {value:'line\nvalue'},{value:'quote"'},{value:'with space'},{value:'semicolon;'},{value:'comma,'},{value:'\\'}, {value:'雪'},{value:'x'.repeat(4097)},
  {path:'relative'},{path:'/bad;path'},{path:'/bad\\path'},{path:'/newline\n'},{path:'/'+'a'.repeat(1024)},
  {sameSite:'None'},{sameSite:'invented'},{sameSite:'no_restriction',secure:false},
  {session:true,expirationDate:now+100},{session:false},{session:false,expirationDate:now-1},{session:false,expirationDate:now+3},
  {session:false,expirationDate:now+401*86400},{session:false,expirationDate:Infinity},{session:false,expirationDate:'123'},
  {partitionKey:{}},{partitionKey:{topLevelSite:origin}},{partitionKey:{topLevelSite:origin,hasCrossSiteAncestor:true}},
  {firstPartyDomain:''},{storeId:'firefox-container-1'},{storeId:'2'},{unknown:'field'},
  {name:'__Secure-test',secure:false},{name:'__Host-test',hostOnly:false},{name:'__Host-test',path:'/other'},
  {name:'__Http-test',httpOnly:false},{name:'__Host-Http-test',httpOnly:false}
])assert.throws(()=>plan([row(patch)]),safe);
for(const rows of [[],Array.from({length:65},(_,n)=>row({name:'n'+n})),[row(),row()],[row(),row({name:'different',storeId:'1'})]])assert.throws(()=>plan(rows),safe);
assert.throws(()=>parseCookieImport(Buffer.alloc(262145),'chrome',origin,30,now),safe);
for(const bad of ['[{"domain":"a","domain":"b"}]','["bad"]','{"cookies":[]}','# Netscape HTTP Cookie File','[{"name":"\\ud800"}]','\ufeff[]'])assert.throws(()=>parseCookieImport(Buffer.from(bad),'chrome',origin,30,now),safe);
assert.throws(()=>parseCookieImport(Buffer.from([0xff]),'chrome',origin,30,now),safe);
assert.throws(()=>plan([row({storeId:'firefox-default'})],'firefox'),safe);
assert.throws(()=>plan([row({storeId:'firefox-default',firstPartyDomain:'example.test'})],'firefox'),safe);
assert.throws(()=>plan([row({storeId:'firefox-container-1',firstPartyDomain:''})],'firefox'),safe);
for(const sameSite of ['strict','lax','no_restriction','unspecified']) {
  const p=plan([row({sameSite,partitionKey:null})]);
  for(const output of [JSON.stringify(p),inspect(p),JSON.stringify(p.review())]){assert(!output.includes(name));assert(!output.includes(value));}
  assert.equal(p.review().cookies[0].same_site,sameSite);
}
assert.equal(plan([row({storeId:'firefox-default',firstPartyDomain:''})],'firefox').review().source_format,'firefox');
assert.equal(plan([row({hostOnly:false,domain:'.account.example.test'})]).review().cookies[0].scope,'host and subdomains');
console.log('PASS cookie export adapters: strict Chrome/Firefox subset, semantic refusals, bounds, duplicates and name/value-free inspection');

function fakeBrowser({mutate,failAt,empty=false,cleanup=true}={}) {
  const calls=[],jar=new Map();let stopped=0;
  const command=async(method,params={})=>{
    calls.push({method,params});
    if(failAt===method)throw new Error(value);
    if(method==='Target.createBrowserContext'){assert.deepEqual(params,{disposeOnDetach:true});jar.set('owned',[]);return {browserContextId:'owned'};}
    if(method==='Target.createTarget'){assert.equal(params.browserContextId,'owned');assert.equal(params.url,origin+'/');return {targetId:'owned-page'};}
    if(method==='Target.closeTarget')return {success:true};
    assert.equal(params.browserContextId,'owned','Every storage operation must name its owned nondefault context');
    if(method==='Browser.setDownloadBehavior'){assert.equal(params.behavior,'deny');return {};}
    if(method==='Storage.getCookies')return {cookies:structuredClone(jar.get('owned')??[])};
    if(method==='Storage.setCookies') {
      const cookies=params.cookies.map(c=>({name:c.name,value:c.value,domain:c.domain??'account.example.test',path:c.path,secure:c.secure,httpOnly:c.httpOnly,
        session:c.expires===undefined,expires:c.expires??-1,...(c.sameSite?{sameSite:c.sameSite}:{})}));
      if(mutate)mutate(cookies);jar.set('owned',empty?[]:cookies);return {};
    }
    if(method==='Storage.clearCookies'){jar.set('owned',[]);return {};}
    if(method==='Target.disposeBrowserContext'){jar.delete('owned');return {};}
    throw new Error('Unexpected test method');
  };
  const context=new PrivateCookieContext(command,async()=>{stopped++;return {processStopped:cleanup,profileRemoved:cleanup};},cookieDestination(origin,30));
  return {calls,jar,context,stopped:()=>stopped,command};
}
{
  const b=fakeBrowser(),p=plan([row(),row({name:'domain',hostOnly:false,session:false,expirationDate:now+60,path:'/account',sameSite:'lax'})]);
  assert.deepEqual(await b.context.import(p),{state:'verified',count:2});
  assert(!b.calls.some(c=>c.method==='Target.createTarget'),'Offline import must not open a page');
  await assert.rejects(p.applyAndVerify(b.command,'owned'),safe);
  await assert.rejects(b.context.import(plan()),safe);
  await b.context.openReviewedOrigin();
  await assert.rejects(b.context.openReviewedOrigin(),safe);
  const result=await b.context.dispose();assert.equal(result.state,'disposed');assert(result.cookies_cleared&&result.context_disposed);assert.equal(b.jar.size,0);
  assert.deepEqual(await b.context.dispose(),result);assert.equal(b.stopped(),1);
  await assert.rejects(b.context.openReviewedOrigin(),safe);
}
for(const mutate of [c=>c.pop(),c=>c.push(c[0]),c=>{c[0].value='wrong';},c=>{c[0].domain='.account.example.test';},c=>{c[0].path='/changed';},
  c=>{c[0].httpOnly=false;},c=>{c[0].secure=false;},c=>{c[0].sameSite='Lax';},c=>{c[0].session=false;},c=>{c[0].partitionKey={topLevelSite:origin};},c=>{c[0].partitionKeyOpaque=true;}]) {
  const b=fakeBrowser({mutate});await assert.rejects(b.context.import(plan()),safe);assert.equal(b.context.status().state,'disposed');assert.equal(b.jar.size,0);
}
for(const failAt of ['Target.createBrowserContext','Storage.setCookies','Storage.getCookies']) {
  const b=fakeBrowser({failAt});await assert.rejects(b.context.import(plan()),safe);assert.equal(b.stopped(),1);
}
{
  const b=fakeBrowser(),p=plan();
  let set=false;
  await assert.rejects(p.applyAndVerify(async method=>{if(method==='Storage.setCookies')set=true;return {cookies:[{name:'preexisting'}]};},'owned'),safe);
  assert.equal(set,false,'A nonempty destination must never be overwritten');await b.context.dispose();
}
{
  const b=fakeBrowser();await b.context.import(plan());const current=performance.now();
  try {Object.defineProperty(performance,'now',{value:()=>current+31000,configurable:true});await assert.rejects(b.context.openReviewedOrigin(),safe);}
  finally {delete performance.now;await b.context.dispose();}
  assert(!b.calls.some(c=>c.method==='Target.createTarget'),'Late OPEN cannot navigate');
}
for(const jump of [-86400000,86400000]) {
  const b=fakeBrowser();await b.context.import(plan());const saved=Date.now;
  try {Date.now=()=>saved()+jump;await b.context.openReviewedOrigin();assert.equal(b.context.status().state,'browsing');}
  finally {Date.now=saved;await b.context.dispose();}
}
{
  const original=setTimeout;let expire;
  try {
    globalThis.setTimeout=(callback,ms,...args)=>ms===30000?(expire=callback,original(()=>{},30000)):original(callback,ms,...args);
    const b=fakeBrowser();await b.context.import(plan());expire();
    const result=await b.context.finished;assert.equal(result.reason,'expired');assert.equal(result.state,'disposed');
    assert(!b.calls.some(c=>c.method==='Target.createTarget'));
  } finally {globalThis.setTimeout=original;}
}
{
  const b=fakeBrowser();let release;
  const waiting=new Promise(resolve=>{release=resolve;});
  const p=plan();let writes=0;
  const late=new PrivateCookieContext(async(method,params)=>{
    if(method==='Target.createBrowserContext'){await waiting;return {browserContextId:'owned'};}
    if(method==='Storage.setCookies')writes++;
    return b.command(method,params);
  },async()=>({processStopped:true,profileRemoved:true}),cookieDestination(origin,30));
  const pending=late.import(p);const disposal=await late.dispose('interrupted');release();await assert.rejects(pending,safe);
  assert.equal(disposal.state,'disposed');assert.equal(writes,0);await b.context.dispose();
}
for(const stage of ['create','before-read','set','after-read','open']) {
  const b=fakeBrowser();let release,entered,reads=0,paused=false,closed=false;
  const gate=new Promise(resolve=>{release=resolve;}),ready=new Promise(resolve=>{entered=resolve;});
  const context=new PrivateCookieContext(async(method,params)=>{
    if(closed)throw new Error(value);
    const result=await b.command(method,params);
    if(method==='Storage.getCookies')reads++;
    const match=stage==='create'&&method==='Target.createBrowserContext'||stage==='before-read'&&method==='Storage.getCookies'&&reads===1||
      stage==='set'&&method==='Storage.setCookies'||stage==='after-read'&&method==='Storage.getCookies'&&reads===2||stage==='open'&&method==='Target.createTarget';
    if(match&&!paused){paused=true;entered();await gate;}
    return result;
  },async()=>{closed=true;b.jar.clear();return {processStopped:true,profileRemoved:true};},cookieDestination(origin,30));
  let pending;
  if(stage==='open'){await context.import(plan());pending=context.openReviewedOrigin();}else pending=context.import(plan());
  await ready;await context.dispose('interrupted');release();await assert.rejects(pending,safe);
  assert.equal(context.status().state,'disposed');assert.equal(b.jar.size,0);
  assert(b.calls.filter(c=>c.method==='Storage.setCookies').length<=1,'An interrupted import never retries apply');
  await b.context.dispose();
}
{
  const b=fakeBrowser({cleanup:false});await b.context.import(plan());assert.equal((await b.context.dispose()).state,'cleanup-uncertain');
}
{
  const b=fakeBrowser({failAt:'Storage.clearCookies'});await b.context.import(plan());const r=await b.context.dispose();assert.equal(r.cookies_cleared,false);assert.equal(r.context_disposed,true);assert.equal(r.state,'disposed');
}
console.log('PASS private lifecycle: actual apply/verify command contract, isolation IDs, no navigation before OPEN, single use, strict readback, faults and clear/dispose');

const directory=await realpath(await mkdtemp(join(tmpdir(),'reb-cookie-import-check-')));
try {
  const source=join(directory,'selected.json'),content=bytes([row()]);await writeFile(source,content,{mode:0o600});
  const got=await readCookieImport(source,'chrome',origin,30);assert.equal(got.review().count,1);assert.deepEqual(await readFile(source),content);
  const link=join(directory,'linked.json');await symlink(source,link);await assert.rejects(readCookieImport(link,'chrome',origin,30),safe);
  await mkdir(join(directory,'inner'));await writeFile(join(directory,'inner','input.json'),content);await symlink(join(directory,'inner'),join(directory,'alias'));
  await assert.rejects(readCookieImport(join(directory,'alias','input.json'),'chrome',origin,30),safe);
  await assert.rejects(readCookieImport(directory,'chrome',origin,30),safe);
  await assert.rejects(readCookieImport('relative.json','chrome',origin,30),safe);
  await assert.rejects(readCookieImport(join(directory,'missing'),'chrome',origin,30),safe);
  // A synthetic executable pauses at startup; abort must stop it promptly,
  // without waiting for the five-second CDP deadline or leaving its profile.
  const sleeper=join(directory,'synthetic-browser.mjs'),marker=join(directory,'startup.json');
  await writeFile(sleeper,'#!/usr/bin/env node\nimport{writeFileSync}from"node:fs";writeFileSync('+JSON.stringify(marker)+',JSON.stringify({pid:process.pid,home:process.env.HOME}));setInterval(()=>{},1000);\n',{mode:0o700});
  const abort=new AbortController(),began=performance.now();
  const starting=launchCookieBrowser(sleeper,cookieDestination(origin,30),{headless:true,signal:abort.signal});
  let started;
  for(let n=0;n<100;n++){try{started=JSON.parse(await readFile(marker,'utf8'));break;}catch{await new Promise(resolve=>setTimeout(resolve,10));}}
  assert(started,'Synthetic startup fixture must run');abort.abort();await assert.rejects(starting,safe);
  assert(performance.now()-began<2000,'Startup interruption must not await the CDP timeout');
  await assert.rejects(stat(started.home),{code:'ENOENT'});
  assert.throws(()=>process.kill(started.pid,0),{code:'ESRCH'});
  for(const action of ['cancel','clear','open','open-failure']) {
    let reads=0,launches=0,opened=0,output='';
    const b=fakeBrowser({failAt:action==='open-failure'?'Target.createTarget':undefined});
    const replies=[source,'chrome',origin,'30',action==='cancel'?'CANCEL':'IMPORT',action==='open'||action==='open-failure'?'OPEN':'CLEAR',''];
    const code=await runCookieImport({argv:['--browser','/synthetic/browser'],interactive:true,ask:async()=>replies.shift(),output:t=>{output+=t;},
      read:async(...args)=>{reads++;return readCookieImport(...args);},launch:async()=>{launches++;const original=b.context.openReviewedOrigin.bind(b.context);b.context.openReviewedOrigin=async()=>{opened++;return original();};return b.context;}});
    assert.equal(code,action==='open-failure'?1:0);assert.equal(reads,1);assert.equal(launches,action==='cancel'?0:1);assert.equal(opened,action==='open'||action==='open-failure'?1:0);
    assert(!output.includes(name)&&!output.includes(value)&&!output.includes(source));assert.deepEqual(await readFile(source),content);
    if(action==='cancel')await b.context.dispose();
  }
  for(const args of [[],['--browser','/browser','--yes'],['--browser','/browser','--input',source]]) {
    let called=false;assert.equal(await runCookieImport({argv:args,interactive:true,output:()=>{},ask:()=>{called=true;}}),2);assert.equal(called,false);
  }
  assert.equal(await runCookieImport({argv:['--browser','/browser'],interactive:false,output:()=>{},ask:()=>{throw new Error('must not prompt');}}),2);
} finally {await rm(directory,{recursive:true,force:true});}
console.log('PASS user handoff flow: explicit IMPORT/OPEN, cancel, clear, repeated-state refusal, untouched source, hidden paths, no noninteractive flags');

// Private-pipe framing/error tests use synthetic values, not a browser store.
{
  const child=new EventEmitter();child.stdio=[null,null,null,new PassThrough(),new PassThrough()];
  const pipe=new CookiePipe(child),reply=pipe.command('Test.synthetic');
  child.stdio[4].write('{"id":1,"result":{"ok":true}}');child.stdio[4].write('\0');assert.deepEqual(await reply,{ok:true});
  const rejected=pipe.command('Test.synthetic');child.stdio[4].write(JSON.stringify({id:2,error:{message:value}})+'\0');await assert.rejects(rejected,safe);
  const disconnected=pipe.command('Test.synthetic');child.emit('exit',1);await assert.rejects(disconnected,safe);pipe.close();
}
console.log('PASS bounded private pipe: framing, sanitized protocol errors and disconnect');

if(process.argv[2]==='--browser') {
  const executable=process.argv[3];assert(executable,'Provide installed Chromium path');
  // Same product launch path, with only headless rendering substituted. No
  // --no-sandbox, security warning bypass, real credentials or target navigation.
  let browser;
  try {
    browser=await launchCookieBrowser(executable,cookieDestination(origin,30),{headless:true});
    const entries=['strict','lax','no_restriction','unspecified'].map((sameSite,n)=>row({sameSite,name:'synthetic_'+n,httpOnly:n%2===0,hostOnly:n%2===0,secure:n%2===0,
      domain:n%2===0?'account.example.test':'.account.example.test',session:n<2,...(n>=2?{expirationDate:Date.now()/1000+120}:{})}));
    assert.equal((await browser.import(plan(entries))).count,4);
    const result=await browser.dispose();assert.equal(result.cookies_cleared,true);assert.equal(result.context_disposed,true);assert.equal(result.process_stopped,true);assert.equal(result.profile_removed,true);
    console.log('PASS installed Chromium: private off-record set/get semantic equality and clear/get/dispose; no target navigation');
  } finally {await browser?.dispose();}
}
