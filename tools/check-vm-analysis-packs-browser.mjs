#!/usr/bin/env node
// Production pack UI against the real local Rust backend; owned declarative fixtures.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm,mkdir,copyFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
// Track process close (including stdio), not just exit, before profile removal.
const closed = new WeakSet();
const track = child => { child.once('close', () => closed.add(child)); return child; };
async function stop(child) {
  for (const signal of ['SIGTERM', 'SIGKILL']) {
    if (closed.has(child)) return;
    try { if (process.platform !== 'win32' && child.pid) process.kill(-child.pid, signal); else child.kill(signal); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
    const deadline = Date.now() + 3000;
    while (!closed.has(child) && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 25));
  }
  if (!closed.has(child)) throw new Error('Owned test process did not close; retained its temporary profile.');
}
const root = new URL('..',import.meta.url).pathname;
const temporary = await mkdtemp(join(tmpdir(),'reb-pack-ui-'));
const uiDirectory=join(temporary,'ui');await mkdir(uiDirectory);
for(const name of ['evidence_package.js','vm_analysis_packs.js','app.css']) await copyFile(join(root,'apps/research-ui',name),join(uiDirectory,name));
await writeFile(join(uiDirectory,'index.html'),`<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/app.css"><body style="overflow:auto"><main style="padding:16px;max-width:1000px;margin:auto"><section id="packs"></section></main><script src="evidence_package.js"></script><script src="vm_analysis_packs.js"></script><script>globalThis.ui=mountVmAnalysisPacks(document.querySelector('#packs'));</script>`);
const binary=resolve(process.env.REB_PACK_BACKEND || join(process.env.CARGO_TARGET_DIR || 'apps/origin-trace-backend/target','debug/origin-trace-backend'));
const endpointFile=join(temporary,'endpoint');
const args=['--port','0','--endpoint-file',endpointFile,'--ui-directory',uiDirectory,'--analyst-runner',binary];
for(const [flag,name] of [['--store','events'],['--trace-store','traces'],['--signal-store','signals'],['--artifacts','artifacts'],['--api-collection','collection.json'],['--local-analyst','analyst.json']])args.push(flag,join(temporary,name));
const backend=track(spawn(binary,args,{detached:process.platform !== 'win32',stdio:['ignore','ignore','pipe']}));
let backendErrors='';backend.stderr.on('data',chunk=>{backendErrors=(backendErrors+chunk).slice(-4000);});
let base;const startup=Date.now();
try { while(!base){if(Date.now()-startup>15000 || backend.exitCode!==null)throw Error('Backend startup failed: '+backendErrors);try{base=(await readFile(endpointFile,'utf8')).trim();}catch{await new Promise(resolve=>setTimeout(resolve,20));}} }
catch(error){await stop(backend);await rm(temporary,{recursive:true,force:true,maxRetries:5,retryDelay:200});throw error;}
const browser=track(spawn(process.env.CHROME_BIN || '/usr/bin/chromium',['--headless=new','--no-sandbox','--disable-gpu','--remote-debugging-port=0',`--user-data-dir=${join(temporary,'profile')}`,'about:blank'],{detached:process.platform !== 'win32',stdio:['ignore','ignore','pipe']}));
let socket;
try {
 let stderr='';const endpoint=await new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(Error('Chromium startup deadline: '+stderr.slice(-2000))),15000);
  browser.stderr.on('data',chunk=>{stderr+=chunk;const match=stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(match){clearTimeout(timer);resolve(match[1]);}});
  browser.once('error',reject);
 });
 socket=new WebSocket(endpoint);await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
 let seq=0;const pending=new Map();
 socket.addEventListener('message',event=>{const message=JSON.parse(event.data);if(message.id){const request=pending.get(message.id);if(request){pending.delete(message.id);clearTimeout(request.timer);message.error?request.reject(Error(message.error.message)):request.resolve(message.result);}}});
 const send=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++seq;const timer=setTimeout(()=>{pending.delete(id);reject(Error(method+' deadline'));},10000);pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});
 const {targetId}=await send('Target.createTarget',{url:base});
 const {sessionId}=await send('Target.attachToTarget',{targetId,flatten:true});
 const command=(method,params={})=>send(method,params,sessionId);
 const evaluate=async expression=>{const result=await command('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw Error(result.exceptionDetails.text);return result.result.value;};
 const until=async expression=>{for(let i=0;i<100;i++){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,50));}throw Error('UI state timeout: '+expression);};
 await command('Page.enable');await until("Boolean(globalThis.ui)");
 const click=async selector=>{
  // Native scrolling + hit test and pointer events; no programmatic DOM click.
  const {root:doc}=await command('DOM.getDocument');const {nodeId}=await command('DOM.querySelector',{nodeId:doc.nodeId,selector});await command('DOM.scrollIntoViewIfNeeded',{nodeId});
  const box=await evaluate(`(()=>{const element=document.querySelector(${JSON.stringify(selector)}),r=element.getBoundingClientRect();const x=r.x+r.width/2,y=r.y+r.height/2;return {x,y,visible:r.width>0&&r.height>0&&x>=0&&x<innerWidth&&y>=0&&y<innerHeight&&element.contains(document.elementFromPoint(x,y))};})()`);
  assert(box.visible,selector+' must be visibly clickable');await command('Input.dispatchMouseEvent',{type:'mousePressed',x:box.x,y:box.y,button:'left',clickCount:1});await command('Input.dispatchMouseEvent',{type:'mouseReleased',x:box.x,y:box.y,button:'left',clickCount:1});
 };
 await click('[data-pack-inputs="compare"] > summary');
 for(const [label,name] of [['Analysis pack','pack.json'],['Left opcode workspace','build-a.workspace.json'],['Right opcode workspace','build-b.workspace.json']]){
  const {root:doc}=await command('DOM.getDocument');const {nodeId}=await command('DOM.querySelector',{nodeId:doc.nodeId,selector:`input[aria-label="${label}"]`});
  await command('DOM.setFileInputFiles',{nodeId,files:[join(root,'tools/fixtures/vm-analysis-packs',name)]});
  await until(`document.querySelector('input[aria-label="${label}"]').parentElement.textContent.includes('bytes')`);
 }
 assert(!await evaluate(`document.querySelector('[role="status"]').textContent.includes('ready')`));
 for(const side of ['left','right']){await click(`input[aria-label="${side} interpreter artifact ID"]`);await command('Input.insertText',{text:'1'});}
 // Keyboard activates Compare after focusing Apply, without invoking its action.
 await click('h2');await evaluate(`document.querySelectorAll('#packs button')[0].focus()`);
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
 assert.equal(await evaluate('document.activeElement.textContent'),'Compare builds');
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
 await until(`document.querySelector('[role="status"]').textContent.includes('ready')`);
 const report=JSON.parse(await evaluate(`document.querySelector('pre').textContent`));assert.equal(report.document_kind,'vm-instruction-set-comparison');assert.equal(report.behavioral_equivalence_proven,false);assert(report.rows.some(row=>row.status==='moved'));
 for(const width of [1180,760,390]){
  await command('Emulation.setDeviceMetricsOverride',{width,height:790,deviceScaleFactor:1,mobile:false});
  assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),`no horizontal overflow at ${width}`);
  assert(await evaluate(`(()=>{const status=document.querySelector('.vm-pack-status');return status.scrollWidth<=status.clientWidth;})()`),`complete status digest fits at ${width}`);
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.vm-pack-inputs label')).display`),'grid');
  const {data}=await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});await mkdir(join(root,'build/vm-pack-ui-qa'),{recursive:true});await writeFile(join(root,`build/vm-pack-ui-qa/packs-${width}.png`),Buffer.from(data,'base64'));
 }
 await click('input[aria-label="right interpreter artifact ID"]');await command('Input.insertText',{text:'2'});
 assert(await evaluate(`document.querySelectorAll('#packs button')[4].disabled`));
 await click('#packs button:nth-child(2)');await until(`document.querySelector('[role="status"]').textContent.includes('refused')`);
 await click('#packs button:nth-child(4)');assert.equal(await evaluate(`document.querySelector('pre').textContent`),'');
 console.log('PASS rendered pack UI: real Rust comparison, exact file inputs, keyboard action, stale report invalidation, bad identity refusal, Clear and 1180/760/390 layouts.');
} finally {
 socket?.close();
 const stopped = await Promise.allSettled([stop(browser), stop(backend)]);
 const failures = stopped.filter(result => result.status === 'rejected').map(result => result.reason);
 if (failures.length) throw new AggregateError(failures, 'Test processes failed to close; temporary files retained.');
 await rm(temporary,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
