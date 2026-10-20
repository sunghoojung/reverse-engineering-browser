#!/usr/bin/env node
// Real Chromium File/pointer/keyboard tests of the production ledger editor.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import model from '../apps/research-ui/vm_opcode_ledger.js';
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
const temporary = await mkdtemp(join(tmpdir(),'reb-ledger-ui-'));
const assets = ['captured_client.js','vm_static.js','vm_opcode_ledger.js','vm_opcode_ledger_view.js'];
const harness = `<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="/app.css"><body style="overflow:auto"><main id="screen-vm" style="padding:16px;max-width:1100px;margin:auto"><section id="ledger"></section></main>${assets.map(name=>`<script src="/${name}"></script>`).join('')}<script>globalThis.ui=RebVmOpcodeLedgerView.mount(document.querySelector('#ledger'));</script>`;
const server=createServer(async(req,res)=>{
 if(req.url==='/'){res.setHeader('content-type','text/html');res.end(harness);return;}
 const name=req.url.slice(1);if(![...assets,'app.css'].includes(name)){res.writeHead(404).end();return;}
 res.setHeader('content-type',name.endsWith('.css')?'text/css':'text/javascript');res.end(await readFile(join(root,'apps/research-ui',name)));
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
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
 const {targetId}=await send('Target.createTarget',{url:`http://127.0.0.1:${server.address().port}/`});
 const {sessionId}=await send('Target.attachToTarget',{targetId,flatten:true});
 const command=(method,params={})=>send(method,params,sessionId);
 const evaluate=async expression=>{const result=await command('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw Error(result.exceptionDetails.text);return result.result.value;};
 const until=async expression=>{for(let i=0;i<100;i++){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,50));}throw Error('UI state timeout: '+expression+'; '+await evaluate('ui.notice.textContent'));};
 await command('Page.enable');await until("Boolean(globalThis.ui)");
 const click=async selector=>{
  // Native scrolling + hit test and pointer events; no programmatic DOM click.
  const {root:doc}=await command('DOM.getDocument');const {nodeId}=await command('DOM.querySelector',{nodeId:doc.nodeId,selector});await command('DOM.scrollIntoViewIfNeeded',{nodeId});
  const box=await evaluate(`(()=>{const element=document.querySelector(${JSON.stringify(selector)}),r=element.getBoundingClientRect();const x=r.x+r.width/2,y=r.y+r.height/2;return {x,y,visible:r.width>0&&r.height>0&&x>=0&&x<innerWidth&&y>=0&&y<innerHeight&&element.contains(document.elementFromPoint(x,y))};})()`);
  assert(box.visible,selector+' must be visibly clickable');await command('Input.dispatchMouseEvent',{type:'mousePressed',x:box.x,y:box.y,button:'left',clickCount:1});await command('Input.dispatchMouseEvent',{type:'mouseReleased',x:box.x,y:box.y,button:'left',clickCount:1});
 };
 const definition = JSON.stringify({format:'reb-vm-definition-v1',definition_id:'owned',architecture:'stack',opcode_bytes:1,operand_endianness:'little',register_count:0,
  opcodes:Array.from({length:40},(_,index)=>({code:index.toString(16).padStart(2,'0'),mnemonic:'UNKNOWN',operands:[],semantics:{operation:'unknown',args:[]},flow:{kind:'unknown'}}))});
 const ledger = await model.createLedger(definition);
 ledger.entries.push({opcode:'00',status:'inferred',meaning:'<img src=x onerror=alert(1)>',handler_location:null,operand_format:null,source_refs:[{artifact_id:'owned',event_id:null}],test_status:'not_run',test_refs:[],unresolved_questions:[]});
 ledger.entries.push({opcode:'27',status:'observed',meaning:'Final declared opcode meaning',handler_location:{artifact_id:'last-handler',byte_offset:4096},operand_format:'Unsigned operand note',source_refs:[{artifact_id:'last-source',event_id:'last-source-event'}],test_status:'failed',test_refs:[{artifact_id:'last-test',event_id:null}],unresolved_questions:['Last unresolved question?']});
 for (const [kind, text] of [['definition',definition],['ledger',JSON.stringify(ledger)]]) {
  const path=join(temporary,kind+'.json');await writeFile(path,text);
  const {root:doc}=await command('DOM.getDocument');const {nodeId}=await command('DOM.querySelector',{nodeId:doc.nodeId,selector:`input[aria-label="Import ${kind} JSON"]`});
  await command('DOM.setFileInputFiles',{nodeId,files:[path]});await until(`ui.editors.${kind}.value.length>0`);
 }
 // Pointer-focus the creation control, then Tab/Enter validates via native keyboard.
 await click('#ledger button:nth-child(1)');
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
 assert.equal(await evaluate('document.activeElement.textContent'),'Validate ledger');
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
 await until('!ui.download.disabled');
 assert.deepEqual(JSON.parse(await evaluate('ui.exportText()')),ledger);
 assert(await evaluate('ui.results.textContent.includes("<img src=x onerror=alert(1)>")'));
 assert.equal(await evaluate('document.querySelectorAll("#ledger img").length'),0);
 assert.equal(await evaluate('document.querySelector("[data-ledger-inputs]").open'),false);
 assert.equal(await evaluate('document.querySelectorAll("[data-ledger-opcode]").length'),32);
 await click('[aria-label="Next opcode coverage page"]');
 assert.equal(await evaluate('document.querySelectorAll("[data-ledger-opcode]").length'),8);
 assert.equal(await evaluate('document.activeElement.getAttribute("aria-label")'),'Inspect opcode 20','Page change moves focus to its selected row');
 await click('[aria-label="Inspect opcode 27"]');
 assert(await evaluate('document.querySelector(".vm-review-inspector").textContent.includes("last-handler")'));
 assert(await evaluate('document.querySelector(".vm-review-inspector").textContent.includes("Unsigned operand note")'));
 await click('.vm-review-tabs [role="tab"]:nth-child(2)');
 assert(await evaluate('document.querySelector(".vm-review-inspector").textContent.includes("last-source-event")'));
 assert(await evaluate('document.querySelector(".vm-review-inspector").textContent.includes("last-test")'));
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowRight',code:'ArrowRight',windowsVirtualKeyCode:39});
 await command('Input.dispatchKeyEvent',{type:'keyUp',key:'ArrowRight',code:'ArrowRight',windowsVirtualKeyCode:39});
 assert.equal(await evaluate('document.activeElement.textContent'),'Questions');
 assert(await evaluate('document.querySelector(".vm-review-inspector").textContent.includes("Last unresolved question?")'));
 await click('.vm-review-tabs [role="tab"]:nth-child(4)');
 assert(await evaluate(`document.querySelector('.vm-review-inspector').textContent.includes(${JSON.stringify(ledger.definition_source_sha256)})`));
 await evaluate('document.querySelector("#ledger").dispatchEvent(new CustomEvent("vm-workspace-search"))');
 assert.equal(await evaluate('document.activeElement.getAttribute("aria-label")'),'Filter opcode coverage');
 await command('Input.insertText',{text:'last-test'});
 assert.equal(await evaluate('document.querySelectorAll("[data-ledger-opcode]").length'),1);
 assert.equal(await evaluate('document.querySelector("[data-ledger-opcode]").getAttribute("data-ledger-opcode")'),'27');
 assert(await evaluate('ui.exportText()!==null'), 'Search does not invalidate the exact draft');
 await click('.vm-review-filter > button');
 await click('[aria-label="Inspect opcode 27"]');
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Home',code:'Home',windowsVirtualKeyCode:36});
 await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Home',code:'Home',windowsVirtualKeyCode:36});
 assert.equal(await evaluate('document.activeElement.getAttribute("aria-label")'),'Inspect opcode 00');
 await click('.vm-review-tabs [role="tab"]:nth-child(1)');
 await click('[data-ledger-action="edit-selected"]');
 assert.deepEqual(await evaluate('JSON.parse(ui.editors.ledger.value.slice(ui.editors.ledger.selectionStart,ui.editors.ledger.selectionEnd))'),ledger.entries[0]);
 assert(await evaluate('document.activeElement===ui.editors.ledger'));
 // Collapse the selected entry before inserting valid JSON whitespace. Ctrl+End
 // is platform dependent and can leave the entry selected on macOS.
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowRight',code:'ArrowRight',windowsVirtualKeyCode:39});await command('Input.dispatchKeyEvent',{type:'keyUp',key:'ArrowRight',code:'ArrowRight',windowsVirtualKeyCode:39});
 await command('Input.insertText',{text:' '});await until('ui.download.disabled');
 assert.match(await evaluate('ui.notice.textContent'),/stale/);
 for(const width of [1180,760,390]){
  await command('Emulation.setDeviceMetricsOverride',{width,height:790,deviceScaleFactor:1,mobile:false});
  await click('#ledger button:nth-child(2)');await until('!ui.download.disabled');
  assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),`no horizontal overflow at ${width}`);
  const {data}=await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
  await writeFile(join('/tmp',`reb-opcode-ledger-ui-${width}.png`),Buffer.from(data,'base64'));
 }
 await click('#ledger button:nth-child(4)');
 assert(await evaluate('ui.getReport()===null && ui.exportText()===null && document.activeElement===ui.files.definition'));
 console.log('PASS rendered opcode ledger workbench: browser File import, native pointer/keyboard validation, paging focus, complete inspector, search, keyboard selection/tabs, exact entry editing, inert markup, stale export guard, clear focus, 1180/760/390 layouts.');
} finally {
 socket?.close();
 try { await stop(browser); }
 finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
 await rm(temporary,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
