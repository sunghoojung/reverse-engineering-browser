// Render the production panel and controller with a synthetic local receipt.
// This checks browser File/keyboard/layout behavior, not real CDP fulfillment.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const root = new URL('..',import.meta.url).pathname;
const temporary = await mkdtemp(join(tmpdir(),'reb-override-ui-browser-'));
const markup = await readFile(join(root,'apps/research-ui/index.html'),'utf8');
const start=markup.indexOf('                <article class="experiment-card" id="local-override-manager">');
const panel=markup.slice(start,markup.indexOf('</article>',start)+10);
assert(panel.includes('data-override-file'));
const harness=`<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="/app.css"></head><body style="overflow:auto"><main style="padding:16px;max-width:620px;margin:auto">${panel}</main><script src="/local_override_manager.js"></script><script>
const session={state:'running',target:{id:'owned'},action_scope:{mode:'target',target_id:'owned'},request_interception:{isolated:true,state:'ready',target_id:'owned',experiment_id:7,rule:{mode:'continue'}}};
let calls=0;
RebLocalOverrideManager.install({root:document.querySelector('#local-override-manager'),getSession:()=>session,contextKey:()=> 'owned-lifetime',busy:()=>false,run:async action=>{
 calls++;
 const rule=action.mode==='continue'?{mode:'continue'}:{mode:'fulfill',method_filter:action.method_filter,response_code:200,response_body_bytes:new TextEncoder().encode(action.response_body).length,local_override:{...action.local_override,exact_url:action.local_override.exact_url.split('?')[0]}};
 session.request_interception.rule=rule;
 return {ok:true,experiment:session.request_interception};
}});
</script></body></html>`;
const server=createServer(async(req,res)=>{
 if(req.url==='/'){res.setHeader('content-type','text/html');res.end(harness);return;}
 const name=req.url.slice(1);if(!['app.css','local_override_manager.js'].includes(name)){res.writeHead(404).end();return;}
 res.setHeader('content-type',name.endsWith('.css')?'text/css':'text/javascript');res.end(await readFile(join(root,'apps/research-ui',name)));
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
 await command('Page.enable');await until("Boolean(document.querySelector('[data-override-file]'))");
 const click=async selector=>{
  // Native scrolling + hit test and pointer events; no programmatic DOM click.
  const {root:doc}=await command('DOM.getDocument');const {nodeId}=await command('DOM.querySelector',{nodeId:doc.nodeId,selector});await command('DOM.scrollIntoViewIfNeeded',{nodeId});
  const box=await evaluate(`(()=>{const element=document.querySelector(${JSON.stringify(selector)}),r=element.getBoundingClientRect();const x=r.x+r.width/2,y=r.y+r.height/2;return {x,y,visible:r.width>0&&r.height>0&&x>=0&&x<innerWidth&&y>=0&&y<innerHeight&&element.contains(document.elementFromPoint(x,y))};})()`);
  assert(box.visible,selector+' must be visibly clickable');await command('Input.dispatchMouseEvent',{type:'mousePressed',x:box.x,y:box.y,button:'left',clickCount:1});await command('Input.dispatchMouseEvent',{type:'mouseReleased',x:box.x,y:box.y,button:'left',clickCount:1});
 };
 const asset=join(temporary,'reviewed.js');await writeFile(asset,'globalThis.ownedFixture = "<script>inert preview</script>";\n');
 const {root:doc}=await command('DOM.getDocument');const {nodeId}=await command('DOM.querySelector',{nodeId:doc.nodeId,selector:'[data-override-file]'});
 await command('DOM.setFileInputFiles',{nodeId,files:[asset]});await until("document.querySelector('[data-override-facts]').textContent.includes('SHA-256')");
 assert.equal(await evaluate('calls'),0);
 await writeFile(asset,'changed on disk');
 assert.match(await evaluate("document.querySelector('[data-override-preview]').value"),/ownedFixture/);
 await click('[data-override-url]');await command('Input.insertText',{text:'http://127.0.0.1:17777/fixture.js?exact=1'});
 await click('[data-override-review]');
 // Tab to Prepare and activate with native keyboard events.
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Tab',code:'Tab',windowsVirtualKeyCode:9});
 assert(await evaluate("document.activeElement===document.querySelector('[data-override-prepare]')"));
 await command('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,text:'\r'});await command('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
 await until("!document.querySelector('[data-override-arm]').disabled");assert.equal(await evaluate('calls'),0);
 await click('[data-override-arm]');await until("document.querySelector('[data-override-status]').textContent.includes('Arm acknowledged')");assert.equal(await evaluate('calls'),1);
 await click('[data-override-disarm]');await until("document.querySelector('[data-override-status]').textContent.includes('Disarm acknowledged')");assert.equal(await evaluate('calls'),2);
 for(const width of [1180,760,390]){
  await command('Emulation.setDeviceMetricsOverride',{width,height:790,deviceScaleFactor:1,mobile:false});
  await click('[data-override-clear]');
  assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),`no horizontal overflow at ${width}`);
  const {data}=await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
  await writeFile(join('/tmp',`reb-local-override-ui-${width}.png`),Buffer.from(data,'base64'));
 }
 console.log('PASS rendered production override panel: browser File snapshot, file edit isolation, inert preview, keyboard prepare, explicit arm/disarm, 1180/760/390 layouts. Synthetic receipt only; no real browser-target fulfillment claimed.');
} finally {
 socket?.close();browser.kill('SIGKILL');await new Promise(resolve=>(browser.exitCode!==null || browser.signalCode!==null)?resolve():browser.once('exit',resolve));server.closeAllConnections();server.close();await rm(temporary,{recursive:true,force:true});
}
