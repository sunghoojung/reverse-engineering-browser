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
await writeFile(join(uiDirectory,'index.html'),`<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/app.css"><body style="overflow:auto"><main id="screen-vm" style="padding:16px;max-width:1000px;margin:auto"><section id="vm-packs-workspace"></section></main><script src="evidence_package.js"></script><script src="vm_analysis_packs.js"></script><script>globalThis.ui=mountVmAnalysisPacks(document.querySelector('#vm-packs-workspace'));</script>`);
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
 await click('h2');await evaluate(`document.querySelectorAll('#vm-packs-workspace button')[0].focus()`);
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
 assert.equal(await evaluate('document.activeElement.textContent'),'Compare builds');
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
 await until(`document.querySelector('[role="status"]').textContent.includes('ready')`);
 const report=JSON.parse(await evaluate(`document.querySelector('.vm-pack-output').textContent`));assert.equal(report.document_kind,'vm-instruction-set-comparison');assert.equal(report.behavioral_equivalence_proven,false);assert(report.rows.some(row=>row.status==='moved'));
 assert.equal(await evaluate(`document.querySelector('[data-pack-inputs="all"]').open`),false,'Successful report collapses imports');
 await click('.vm-tool-table tbody tr:first-child');
 assert(await evaluate(`document.querySelector('.vm-review-inspector').textContent.includes('Report row 1 of')`));
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
 assert.equal(await evaluate(`document.activeElement.getAttribute('data-pack-row')`),'1');
 await click('.vm-review-tabs button:nth-child(2)');
 assert(await evaluate(`document.querySelector('.vm-review-inspector').textContent.includes('Report identity and limitations')`));
 await click('.vm-review-tabs button:first-child');
 await click('input[aria-label="Filter pack report rows"]');await command('Input.insertText',{text:'contradicted'});
 assert(await evaluate(`document.querySelector('.vm-review-listing').textContent.includes('of '+${report.rows.length}+' rows')`));
 assert(await evaluate(`[...document.querySelectorAll('.vm-tool-table tbody tr')].every(row=>row.textContent.includes('contradicted'))`));
 await evaluate(`document.querySelector('input[type="search"]').value='';document.querySelector('input[type="search"]').dispatchEvent(new Event('input'))`);
 for(const width of [1180,760,390]){
  await command('Emulation.setDeviceMetricsOverride',{width,height:790,deviceScaleFactor:1,mobile:false});
  assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),`no horizontal overflow at ${width}`);
  assert(await evaluate(`(()=>{const status=document.querySelector('.vm-pack-status');return status.scrollWidth<=status.clientWidth;})()`),`complete status digest fits at ${width}`);
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.vm-pack-inputs label')).display`),'grid');
  const {data}=await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});await mkdir(join(root,'build/vm-pack-ui-qa'),{recursive:true});await writeFile(join(root,`build/vm-pack-ui-qa/packs-${width}.png`),Buffer.from(data,'base64'));
 }
 await click('[data-pack-inputs="all"] > summary');
 await click('input[aria-label="right interpreter artifact ID"]');await command('Input.insertText',{text:'2'});
 assert(await evaluate(`document.querySelectorAll('#vm-packs-workspace button')[4].disabled`));
 await click('#vm-packs-workspace button:nth-child(2)');await until(`document.querySelector('[role="status"]').textContent.includes('refused')`);
 await click('#vm-packs-workspace button:nth-child(4)');assert.equal(await evaluate(`document.querySelector('.vm-pack-output').textContent`),'');
 // Explicitly authored presentation response exercises access beyond the real
 // fixture's small report, without changing or making claims about the backend.
 await evaluate(`(() => {
   const root=document.querySelector('#vm-packs-workspace');root.innerHTML='';globalThis.ui=mountVmAnalysisPacks(root);
   const original=globalThis.fetch;
   globalThis.fetch=async (...args)=>args[0]==='/api/analysis/vm/packs/apply' ? new Response(JSON.stringify({
     contract_version:1,document_kind:'vm-pack-application',document_digest:'a'.repeat(64),
     rankings:Array.from({length:130},(_,index)=>({artifact_id:index+1,anti_bot_score:index%100,generic_anti_bot_score:20,
       labels:[{rule_id:'antibot.authored',label:'authored-row-'+index}]})),limitations:['Synthetic presentation test only.']
   })) : original(...args);
 })()`);
 for(const label of ['Analysis pack','VM analysis (apply)']) {
   const {root:doc}=await command('DOM.getDocument');const {nodeId}=await command('DOM.querySelector',{nodeId:doc.nodeId,selector:`input[aria-label="${label}"]`});
   await command('DOM.setFileInputFiles',{nodeId,files:[join(root,'tools/fixtures/vm-analysis-packs/pack.json')]});
   await until(`document.querySelector('input[aria-label="${label}"]').parentElement.textContent.includes('bytes')`);
 }
 await click('#vm-packs-workspace > .vm-tool-toolbar button:first-child');await until(`document.querySelector('.vm-pack-status').textContent.includes('ready')`);
 assert.equal(await evaluate(`document.querySelectorAll('.vm-tool-table tbody tr').length`),64);
 await click('.vm-review-listing .vm-tool-toolbar button:last-child');
 assert(await evaluate(`document.querySelector('.vm-review-inspector').textContent.includes('Report row 65 of 130')`));
 await click('.vm-review-listing .vm-tool-toolbar button:last-child');
 assert.equal(await evaluate(`document.querySelectorAll('.vm-tool-table tbody tr').length`),2);
 await click('.vm-tool-table tbody tr:last-child');
 assert(await evaluate(`document.querySelector('.vm-review-inspector').textContent.includes('authored-row-129')`));
 await click('input[aria-label="Filter pack report rows"]');await command('Input.insertText',{text:'authored-row-129'});
 assert.equal(await evaluate(`document.querySelectorAll('.vm-tool-table tbody tr').length`),1);
 assert.equal(await evaluate(`document.querySelector('.vm-tool-table tbody tr').getAttribute('data-pack-row')`),'129');
 for(const width of [1180,760,390]) {
   await command('Emulation.setDeviceMetricsOverride',{width,height:790,deviceScaleFactor:1,mobile:false});
   assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),`filtered workbench has no horizontal overflow at ${width}`);
   const {data}=await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});await writeFile(join(root,`build/vm-pack-ui-qa/packs-filtered-${width}.png`),Buffer.from(data,'base64'));
 }
 console.log('PASS rendered pack UI: real Rust comparison, exact file inputs, keyboard action, stale report invalidation, bad identity refusal, Clear, complete 130-row pagination, filtering, linked inspector and 1180/760/390 layouts.');
} finally {
 socket?.close();
 const stopped = await Promise.allSettled([stop(browser), stop(backend)]);
 const failures = stopped.filter(result => result.status === 'rejected').map(result => result.reason);
 if (failures.length) throw new AggregateError(failures, 'Test processes failed to close; temporary files retained.');
 await rm(temporary,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
