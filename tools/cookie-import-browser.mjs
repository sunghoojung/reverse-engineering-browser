// Private CDP pipe owned exclusively by the local user-operated import tool.
// Never connect this process/context to REB's capture or public debugger API.
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, writeFile, rm, stat} from 'node:fs/promises';
import {join, isAbsolute} from 'node:path';
import {tmpdir} from 'node:os';
import {performance} from 'node:perf_hooks';
import {CookieImportError} from './cookie-import.mjs';

const failure=code=>new CookieImportError(code);
const delay=milliseconds=>new Promise(resolve=>setTimeout(resolve,milliseconds));

export class CookiePipe {
  #child; #pending=new Map(); #next=1; #buffer=Buffer.alloc(0); #closed=false;
  constructor(child) {
    this.#child=child;
    child.once('error',()=>this.#fail());
    child.once('exit',()=>this.#fail());
    child.stdio[3].on('error',()=>this.#fail());
    child.stdio[4].on('error',()=>this.#fail());
    child.stdio[4].on('end',()=>this.#fail());
    child.stdio[4].on('data',chunk=>this.#receive(chunk));
  }
  #fail() {
    this.#closed=true; this.#buffer=Buffer.alloc(0);
    for(const {reject,timer} of this.#pending.values()) {clearTimeout(timer);reject(failure('browser-disconnected'));}
    this.#pending.clear();
  }
  #receive(chunk) {
    if(this.#closed)return;
    if(this.#buffer.length+chunk.length>1048576) {this.#fail();return;}
    this.#buffer=Buffer.concat([this.#buffer,chunk]);
    for(;;) {
      const end=this.#buffer.indexOf(0);if(end<0)return;
      let reply;
      try {reply=JSON.parse(this.#buffer.toString('utf8',0,end));} catch {this.#fail();return;}
      this.#buffer=this.#buffer.subarray(end+1);
      if(!reply||typeof reply!=='object'||Array.isArray(reply)) {this.#fail();return;}
      // Unsolicited protocol events are discarded, never logged or collected.
      if(!Object.hasOwn(reply,'id'))continue;
      const pending=this.#pending.get(reply.id);if(!pending)continue;
      this.#pending.delete(reply.id);clearTimeout(pending.timer);
      if(reply.error||!reply.result||typeof reply.result!=='object'||Array.isArray(reply.result)) pending.reject(failure('browser-rejected'));
      else pending.resolve(reply.result);
    }
  }
  command(method,params={},sessionId) {
    if(this.#closed||this.#pending.size>=8)return Promise.reject(failure('browser-unavailable'));
    const id=this.#next++;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.#pending.delete(id);reject(failure('browser-timeout'));this.#fail();},5000);
      this.#pending.set(id,{resolve,reject,timer});
      this.#child.stdio[3].write(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})})+'\0',error=>{if(error)this.#fail();});
    });
  }
  close() {this.#fail();this.#child.stdio[3].destroy();this.#child.stdio[4].destroy();}
}

// Lifecycle is separately testable without exposing a cookie getter or exporter.
export class PrivateCookieContext {
  #command; #shutdown; #context=null; #target=null; #origin; #state='new'; #deadline; #expiresAt; #close=null; #timer;
  #finish; #finished;
  constructor(command,shutdown,destination) {
    this.#command=command;this.#shutdown=shutdown;this.#origin=destination.origin;
    this.#deadline=performance.now()+destination.seconds*1000;
    this.#expiresAt=Date.now()+destination.seconds*1000;
    this.#finished=new Promise(resolve=>{this.#finish=resolve;});
    this.#timer=setTimeout(()=>{void this.dispose('expired');},destination.seconds*1000);
  }
  status() {return Object.freeze({state:this.#state,expires_at:this.#expiresAt});}
  get finished() {return this.#finished;}
  #live() {if(this.#close||performance.now()>=this.#deadline)throw failure('session-expired');}
  async import(plan) {
    if(this.#state!=='new')throw failure('session-used');
    this.#state='importing';
    try {
      this.#live();
      const created=await this.#command('Target.createBrowserContext',{disposeOnDetach:true});
      if(typeof created?.browserContextId!=='string'||!created.browserContextId||created.browserContextId.length>256)throw failure('context-id');
      this.#context=created.browserContextId;this.#live();
      await this.#command('Browser.setDownloadBehavior',{behavior:'deny',browserContextId:this.#context});
      this.#live();
      const verified=await plan.applyAndVerify((...args)=>{this.#live();return this.#command(...args);},this.#context);
      this.#live();this.#state='verified';
      return verified;
    } catch {plan.discard();await this.dispose('import-failed');throw failure('import-failed');}
  }
  async openReviewedOrigin() {
    if(this.#state!=='verified')throw failure('navigation-state');
    this.#live();this.#state='opening';
    try {
      // First and only navigation issued by the importer, after local OPEN.
      // Subsequent browsing is user-operated and is NOT origin confined.
      const target=await this.#command('Target.createTarget',{url:this.#origin+'/',browserContextId:this.#context,newWindow:true});
      if(typeof target?.targetId!=='string'||!target.targetId)throw failure('target-id');
      this.#target=target.targetId;this.#live();this.#state='browsing';
      return Object.freeze({state:'browsing'});
    } catch {await this.dispose('open-failed');throw failure('open-failed');}
  }
  dispose(reason='cleared') {
    if(this.#close)return this.#close;
    clearTimeout(this.#timer);this.#state='disposing';
    this.#close=this.#dispose(reason);return this.#close;
  }
  async #dispose(reason) {
    let cookiesCleared=false,contextDisposed=false,processStopped=false,profileRemoved=false;
    // Cleanup must not extend the credential lifetime by several CDP timeouts.
    // Deadline expiry kills the owned process immediately; other exits allow a
    // one-second best-effort clear/verify/dispose before the same hard stop.
    const watchdog=setTimeout(()=>{void Promise.resolve().then(()=>this.#shutdown()).catch(()=>{});},reason==='expired'?0:1000);
    if(this.#context) {
      try {
        // Close the sole user window before clearing so no page can refresh a cookie.
        // Other user-created pages are ended by the authoritative context disposal.
        if(this.#target)await this.#command('Target.closeTarget',{targetId:this.#target});
        await this.#command('Storage.clearCookies',{browserContextId:this.#context});
        const result=await this.#command('Storage.getCookies',{browserContextId:this.#context});
        cookiesCleared=Array.isArray(result?.cookies)&&result.cookies.length===0;
      } catch { /* Generic outcome only; CDP errors can contain secret input. */ }
      try {await this.#command('Target.disposeBrowserContext',{browserContextId:this.#context});contextDisposed=true;} catch { /* no retry */ }
    }
    try {const result=await this.#shutdown();processStopped=result.processStopped===true;profileRemoved=result.profileRemoved===true;} catch { /* no raw errors */ }
    clearTimeout(watchdog);
    this.#context=null;this.#target=null;this.#state=processStopped&&profileRemoved?'disposed':'cleanup-uncertain';
    const result=Object.freeze({state:this.#state,reason,cookies_cleared:cookiesCleared,context_disposed:contextDisposed,process_stopped:processStopped,profile_removed:profileRemoved});
    this.#finish(result);return result;
  }
}

export async function launchCookieBrowser(executable,destination,{headless=false,signal}={}) {
  if(process.platform==='win32'||!isAbsolute(executable))throw failure('browser-path');
  try {if(!(await stat(executable)).isFile())throw failure('browser-path');} catch {throw failure('browser-path');}
  let directory,child,pipe,stopped;
  const shutdown=()=>stopped??=(async()=>{
    pipe?.close();let processStopped=!child?.pid;
    if(child?.pid) {
      try {process.kill(-child.pid,'SIGKILL');} catch(error) {if(error.code!=='ESRCH')return {processStopped:false,profileRemoved:false};}
      const until=Date.now()+3000;
      while(child.exitCode===null&&child.signalCode===null&&Date.now()<until)await delay(25);
      processStopped=child.exitCode!==null||child.signalCode!==null;
    }
    let profileRemoved=!directory;
    if(processStopped&&directory)try {await rm(directory,{recursive:true,force:true});profileRemoved=true;} catch { /* no secret path diagnostics */ }
    return {processStopped,profileRemoved};
  })();
  const cancel=()=>{void shutdown().catch(()=>{});};
  try {
    if(signal?.aborted)throw failure('cancelled');
    directory=await mkdtemp(join(tmpdir(),'reb-private-cookie-'));
    const profile=join(directory,'profile');await mkdir(join(profile,'Default'),{recursive:true,mode:0o700});
    await writeFile(join(profile,'Default','Preferences'),JSON.stringify({credentials_enable_service:false,profile:{password_manager_enabled:false},autofill:{profile_enabled:false,credit_card_enabled:false}}),{mode:0o600,flag:'wx'});
    // Do not inherit capture/session settings from a concurrently running REB.
    const inherited=new Set(['PATH','LANG','LC_ALL','LC_CTYPE','DISPLAY','WAYLAND_DISPLAY','XAUTHORITY','DBUS_SESSION_BUS_ADDRESS']);
    const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>inherited.has(key)));
    Object.assign(env,{HOME:directory,XDG_CONFIG_HOME:directory,XDG_CACHE_HOME:directory,TMPDIR:directory});
    const args=['--remote-debugging-pipe','--no-startup-window','--no-first-run','--no-default-browser-check','--disable-background-networking',
      '--disable-component-update','--disable-sync','--disable-extensions','--disable-breakpad','--disable-crash-reporter','--noerrdialogs',`--user-data-dir=${profile}`];
    if(headless)args.push('--headless=new');
    if(signal?.aborted)throw failure('cancelled');
    child=spawn(executable,args,{env,detached:true,stdio:['ignore','ignore','ignore','pipe','pipe']});
    pipe=new CookiePipe(child);
    signal?.addEventListener('abort',cancel,{once:true});
    await pipe.command('Browser.getVersion');
    if(signal?.aborted)throw failure('cancelled');
    return new PrivateCookieContext((...args)=>pipe.command(...args),shutdown,destination);
  } catch {const cleanup=await shutdown();throw failure(cleanup.processStopped&&cleanup.profileRemoved?'browser-startup':'cleanup-uncertain');}
  finally {signal?.removeEventListener('abort',cancel);}
}
