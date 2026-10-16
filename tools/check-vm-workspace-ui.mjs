// Render the shipped workspace coverage panel in an isolated local test browser.
// CDP here drives only this synthetic UI harness, never evidence collection.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const root = new URL('..',import.meta.url).pathname;
const temporary = await mkdtemp(join(tmpdir(),'reb-workspace-ui-browser-'));
const app = await readFile(join(root,'apps/research-ui/app.js'),'utf8');
const model = await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8');
const renderer = app.slice(app.indexOf('      function renderVmWorkspaceCoverage'), app.indexOf('      function renderVmWorkspaceUnknowns'));
const fixtures = await Promise.all(['complete','partial'].map(async name => JSON.parse(await readFile(join(root,`tests/research_ui/fixtures/vm-byte-coverage-${name}-v2.json`),'utf8'))));
const serialized = JSON.stringify(fixtures).replaceAll('<','\\u003c');
const harness=`<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/app.css"></head><body style="overflow:auto"><main style="padding:16px;max-width:900px;margin:auto"><h1>VM Laboratory</h1><button id="complete">Complete fixture</button><button id="partial">Partial fixture</button><button id="empty">No snapshot</button><button id="malformed">Malformed refresh</button><section id="workspace" class="vm-workspace"></section></main><script>
${model}
const fixtures = ${serialized};
const textElement = (tag, cls, text) => {const node=document.createElement(tag);node.className=cls;node.textContent=text;return node;};
${renderer}
let retained = null;
const render = document => {if(!isVmOpcodeWorkspaceDocument(document))return;retained=document;window.document.querySelector('#workspace').replaceChildren(renderVmWorkspaceCoverage(document.workspaces[0]));};
document.querySelector('#complete').onclick=()=>render(fixtures[0]);
document.querySelector('#partial').onclick=()=>render(fixtures[1]);
document.querySelector('#empty').onclick=()=>{const empty=JSON.parse(JSON.stringify(fixtures[0]));const workspace=empty.workspaces[0];workspace.snapshots=[];workspace.coverage={complete:false,handler_count:workspace.handlers.length,retained_snapshot_bytes:0,characterized_bytes:0,uncharacterized_bytes:0,attributions:[],omissions:[{reason:'snapshot-bytes-unavailable'}]};render(empty);};
document.querySelector('#malformed').onclick=()=>render({...fixtures[0],contract_version:1});
render(fixtures[0]);
</script></body></html>`;
const server=createServer(async(req,res)=>{
 if(req.url==='/'){res.setHeader('content-type','text/html');res.end(harness);return;}
 if(req.url==='/app.css'){res.setHeader('content-type','text/css');res.end(await readFile(join(root,'apps/research-ui/app.css')));return;}
 res.writeHead(404).end();
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const browser=spawn(process.env.CHROME_BIN || '/usr/bin/chromium',['--headless=new','--no-sandbox','--disable-gpu','--remote-debugging-port=0',`--user-data-dir=${join(temporary,'profile')}`,'about:blank'],{stdio:['ignore','ignore','pipe']});
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
 const until=async expression=>{for(let i=0;i<100;i++){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,50));}throw Error('UI state timeout: '+expression);};
 await command('Page.enable');await until("Boolean(document.querySelector('[role=progressbar]'))");
 const click=async selector=>{
  // Native scrolling + hit test and pointer events; no programmatic DOM click.
  const {root:doc}=await command('DOM.getDocument');const {nodeId}=await command('DOM.querySelector',{nodeId:doc.nodeId,selector});await command('DOM.scrollIntoViewIfNeeded',{nodeId});
  const box=await evaluate(`(()=>{const element=document.querySelector(${JSON.stringify(selector)}),r=element.getBoundingClientRect();const x=r.x+r.width/2,y=r.y+r.height/2;return {x,y,visible:r.width>0&&r.height>0&&x>=0&&x<innerWidth&&y>=0&&y<innerHeight&&element.contains(document.elementFromPoint(x,y))};})()`);
  assert(box.visible,selector+' must be visibly clickable');await command('Input.dispatchMouseEvent',{type:'mousePressed',x:box.x,y:box.y,button:'left',clickCount:1});await command('Input.dispatchMouseEvent',{type:'mouseReleased',x:box.x,y:box.y,button:'left',clickCount:1});
 };
 assert.equal(await evaluate("document.querySelector('[role=progressbar]').getAttribute('aria-valuenow')"),'100');
 await click('#partial');
 assert.equal(await evaluate("document.querySelector('[role=progressbar]').getAttribute('aria-valuenow')"),'75');
 assert((await evaluate("document.querySelector('#workspace').textContent")).includes('1 uncharacterized bytes'));
 await click('#malformed');
 assert.equal(await evaluate("document.querySelector('[role=progressbar]').getAttribute('aria-valuenow')"),'75');
 await click('#empty');
 assert.equal(await evaluate("document.querySelector('[role=progressbar]').getAttribute('aria-valuenow')"),'0');
 await click('#complete');
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
 await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
 assert.equal(await evaluate('document.activeElement.id'),'partial');
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});
 await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
 assert.equal(await evaluate("document.querySelector('[role=progressbar]').getAttribute('aria-valuenow')"),'75');
 for(const width of [1180,760,390]){
  await command('Emulation.setDeviceMetricsOverride',{width,height:790,deviceScaleFactor:1,mobile:false});
  assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),`no horizontal overflow at ${width}`);
  const {data}=await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
  await writeFile(join('/tmp',`reb-vm-workspace-ui-${width}.png`),Buffer.from(data,'base64'));
 }
 console.log('PASS rendered production coverage panel: complete/partial/no snapshot, exact byte fraction, malformed-refresh retention, pointer/keyboard controls, 1180/760/390 layouts. Isolated local UI harness, not native-app acceptance.');
} finally {
 socket?.close();browser.kill('SIGKILL');await new Promise(resolve=>(browser.exitCode!==null || browser.signalCode!==null)?resolve():browser.once('exit',resolve));server.closeAllConnections();server.close();await rm(temporary,{recursive:true,force:true});
}
