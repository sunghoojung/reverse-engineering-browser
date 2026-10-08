// Real product acceptance uses only rendered controls for the investigation.
// CDP evaluation reads DOM/geometry; it never calls application actions or
// installs hidden source identities. All fixture content is synthetic and owned.
import assert from 'node:assert/strict';
import {mkdir, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

export const candidateFixtureSource = `// UTF-8 ownership fixture: 雪 😀\nfunction makePayload(input){\n  return "fixture-observed";\n}\ndocument.querySelector("#send-page").onclick=()=>fetch("/payload",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({payload:makePayload("owned-input")})});\nglobalThis.candidateWorker=new Worker("/candidate-worker.js");\ndocument.querySelector("#send-worker").onclick=()=>candidateWorker.postMessage("owned-input");\n`;
const workerSource = `function workerPayload(input){return "fixture-worker";}\nself.onmessage=e=>fetch("/payload",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({payload:workerPayload(e.data)})});\n`;
export function candidateFixtureRoute(req, res, receipts = []) {
  const path = new URL(req.url, 'http://127.0.0.1').pathname;
  if (['/candidate.js', '/candidate-changed.js', '/candidate-worker.js'].includes(path)) {
    res.setHeader('Content-Type', 'text/javascript');
    res.end(path === '/candidate-worker.js' ? workerSource : path === '/candidate-changed.js' ? candidateFixtureSource.replace('UTF-8 ownership', 'Changed UTF-8 ownership') : candidateFixtureSource);
    return true;
  }
  if (['/candidate-page', '/candidate-changed', '/candidate-duplicate'].includes(path)) {
    res.setHeader('Content-Type', 'text/html');
    res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Owned candidate bridge fixture</title><link rel="icon" href="data:,"><h1>Owned candidate bridge fixture</h1><p>Separate actions: Page never sends a Worker request.</p><button id="send-page">Send Page payload</button><button id="send-worker">Send Worker payload</button><script src="${path === '/candidate-changed' ? '/candidate-changed.js' : '/candidate.js'}"></script>${path === '/candidate-duplicate' ? '<script src="/candidate.js?second=1"></script>' : ''}</html>`);
    return true;
  }
  if (path === '/payload') {
    let body=''; req.on('data', chunk=>{body+=chunk;}); req.on('end',()=>{receipts.push({method:req.method,body});res.setHeader('Content-Type','application/json');res.end('{"accepted":true}');});
    return true;
  }
  return false;
}

export async function checkCandidateFixture() {
  const response = path => {let value, type;assert(candidateFixtureRoute({url:path},{setHeader:(_,v)=>{type=v;},end:v=>{value=v;}}));return {value,type};};
  const page=response('/candidate-page').value;
  assert.match(page, /id="send-page"/);assert.match(page, /id="send-worker"/);
  assert.match(candidateFixtureSource,/function makePayload\(input\)\{\n  return "fixture-observed";/);
  assert(!candidateFixtureSource.includes('input+'));
  assert.match(candidateFixtureSource,/body:JSON.stringify\(\{payload:makePayload\("owned-input"\)\}\)/);
  assert.equal(response('/candidate.js').value,response('/candidate.js?second=1').value);
  assert.notEqual(response('/candidate.js').value,response('/candidate-changed.js').value);
  assert.match(response('/candidate-duplicate').value,/candidate.js\?second=1/);
  const pageHandler=candidateFixtureSource.split('document.querySelector("#send-page").onclick=')[1].split('\n')[0];
  assert(!pageHandler.includes('postMessage'),'Page action must not also send Worker request');
  const buttons={'#send-page':{},'#send-worker':{}},requests=[],messages=[];
  const context={document:{querySelector:id=>buttons[id]},fetch:(url,options)=>{requests.push({url,...options});},Worker:class{postMessage(value){messages.push(value);}}};
  runInNewContext(candidateFixtureSource,context);
  assert.equal(requests.length,0);assert.equal(messages.length,0,'Fixture load is inert');
  buttons['#send-page'].onclick();assert.equal(requests.length,1);assert.equal(messages.length,0);
  assert.equal(requests[0].url,'/payload');assert.equal(requests[0].body,'{"payload":"fixture-observed"}');
  buttons['#send-worker'].onclick();assert.equal(requests.length,1);assert.deepEqual(messages,['owned-input']);
  console.log('PASS additive candidate fixture: literal synchronous value, UTF-8 bytes, separate Page/Worker actions, changed and duplicate sources (not rendered QA)');
}

export async function checkCandidateExperimentJourney({address, uiURL, fixtureURL, root, socketFactory, requestReceipts}) {
  const output=process.env.REB_UI_SCREENSHOTS || join(root,'build/candidate-bridge-ui-qa');
  await mkdir(output,{recursive:true});
  const socket=await socketFactory(address), pending=new Map(), receipts=[], runtimeErrors=[];
  let sequence=0, uiSession, phase='attach';
  socket.addEventListener('message',event=>{
    const message=JSON.parse(event.data);
    if(message.method==='Runtime.exceptionThrown')runtimeErrors.push(message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text);
    const request=pending.get(message.id);if(!request)return;
    pending.delete(message.id);clearTimeout(request.timer);
    if(message.error)request.reject(Error(JSON.stringify(message.error)));else request.resolve(message.result);
  });
  const command=(method,params={},sessionId=uiSession)=>new Promise((resolve,reject)=>{
    const id=++sequence,timer=setTimeout(()=>{pending.delete(id);reject(Error(`CDP timeout: ${method}`));},15000);
    pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
  });
  const evaluate=async(expression,session=uiSession)=>{
    const result=await command('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},session);
    if(result.exceptionDetails)throw Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  };
  const until=async(predicate,label,session=uiSession)=>{
    const deadline=Date.now()+20000;let last;
    while(Date.now()<deadline){try{last=await evaluate(predicate,session);if(last)return last;}catch(error){last=error.message;}await new Promise(resolve=>setTimeout(resolve,40));}
    throw Error(`${phase}: ${label}: ${JSON.stringify(last)}`);
  };
  const frame=()=>evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
  const key=async(key,session=uiSession,modifiers=0)=>{
    const code=key===' '?'Space':key;
    const windowsVirtualKeyCode={Enter:13,Tab:9,Escape:27,ArrowDown:40,Home:36,End:35,a:65}[key];
    await command('Input.dispatchKeyEvent',{type:'rawKeyDown',key,code,modifiers,windowsVirtualKeyCode},session);
    await command('Input.dispatchKeyEvent',{type:'keyUp',key,code,modifiers,windowsVirtualKeyCode},session);
  };
  // Reach offscreen controls by real wheel input into their nearest scroll owner.
  const reveal=async(selector,session=uiSession)=>{
    for(let attempt=0;attempt<30;attempt++){
      const position=await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});if(!n)return {missing:true};const r=n.getBoundingClientRect();if(!r.width||!r.height)return {hidden:true};const x=Math.max(1,Math.min(innerWidth-2,r.x+r.width/2)),y=Math.max(1,Math.min(innerHeight-2,r.y+r.height/2));if(r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight&&n.contains(document.elementFromPoint(x,y)))return {ready:true,x,y};for(let p=n.parentElement;p;p=p.parentElement){const s=getComputedStyle(p),b=p.getBoundingClientRect();if(['auto','scroll','overlay'].includes(s.overflowY)&&p.scrollHeight>p.clientHeight+1&&b.width&&b.height){const top=Math.max(0,b.top),bottom=Math.min(innerHeight,b.bottom);if(top>=bottom)continue;return {x:Math.min(innerWidth-2,Math.max(2,b.right-8)),y:(top+bottom)/2,delta:r.top<top?Math.max(-400,r.top-top-20):Math.min(400,r.bottom-bottom+20)};}}return {blocked:true,rect:{left:r.left,right:r.right,top:r.top,bottom:r.bottom}};})()`,session);
      if(position.ready)return position;
      assert(!position.missing&&!position.hidden&&!position.blocked,`Unavailable visible control ${selector}: ${JSON.stringify(position)}`);
      await command('Input.dispatchMouseEvent',{type:'mouseMoved',x:position.x,y:position.y},session);
      await command('Input.dispatchMouseEvent',{type:'mouseWheel',x:position.x,y:position.y,deltaX:0,deltaY:position.delta||180},session);
      await evaluate('new Promise(resolve=>setTimeout(resolve,80))',session);
    }
    throw Error(`Control did not become reachable: ${selector}`);
  };
  const click=async(selector,session=uiSession)=>{
    const point=await reveal(selector,session),startedAt=performance.now();
    await command('Input.dispatchMouseEvent',{type:'mousePressed',x:point.x,y:point.y,button:'left',clickCount:1},session);
    await command('Input.dispatchMouseEvent',{type:'mouseReleased',x:point.x,y:point.y,button:'left',clickCount:1},session);
    receipts.push({phase,kind:'pointer',selector});await evaluate('new Promise(resolve=>requestAnimationFrame(resolve))',session);return startedAt;
  };
  const byText=async(text,scope='body')=>evaluate(`(()=>{const root=document.querySelector(${JSON.stringify(scope)}),nodes=[...root.querySelectorAll('button')],n=nodes.find(n=>n.textContent.trim()===${JSON.stringify(text)}&&!n.disabled&&n.getClientRects().length);if(!n)return null;const path=[];let e=n;while(e&&e!==document.documentElement){if(e.id){path.unshift('#'+CSS.escape(e.id));break;}const siblings=[...e.parentElement.children];path.unshift(e.tagName.toLowerCase()+':nth-child('+(siblings.indexOf(e)+1)+')');e=e.parentElement;}return path.join(' > ');})()`);
  const clickText=async(text,scope)=>{const selector=await byText(text,scope);assert(selector,`Missing visible '${text}'`);await click(selector);};
  const fill=async(selector,value)=>{await click(selector);await key('a',uiSession,process.platform==='darwin'?4:2);await command('Input.insertText',{text:value});};
  const keyboardTo=async(selector)=>{
    await reveal(selector);
    for(let index=0;index<220;index++){
      if(await evaluate(`document.activeElement===document.querySelector(${JSON.stringify(selector)})&&document.activeElement.matches(':focus-visible')`)){receipts.push({phase,kind:'keyboard',selector,tabs:index});return;}
      await key('Tab');
    }
    throw Error(`Keyboard cannot reach ${selector}`);
  };
  const screenshot=async(name)=>{
    await frame();const shot=await command('Page.captureScreenshot',{format:'png'});await writeFile(join(output,`${name}.png`),Buffer.from(shot.data,'base64'));
  };
  const viewport=async(width,height)=>{await command('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});await frame();};
  const chooseTarget=async(kind)=>{
    const index=await evaluate(`(()=>{const s=document.querySelector('#candidate-experiment-target');return [...s.options].findIndex(o=>o.value&&o.textContent.trim().startsWith(${JSON.stringify(kind)}));})()`);
    assert(index>0,`Missing explicit ${kind} target option`);
    await click('#candidate-experiment-target');await key('Home');
    for(let i=0;i<index;i++)await key('ArrowDown');
    await key('Enter');
    await until("!!document.querySelector('#candidate-experiment-target').value",'Explicit target choice did not stick');
  };
  const readOnlyState=()=>fetch(uiURL+'/api/debugger').then(r=>{assert(r.ok);return r.json();});
  const quietState=async()=>{const state=await readOnlyState();return {isolated:state.runtime_hooks.isolated,definitions:state.runtime_hooks.definitions.length,armed:['arming','armed','handling','stopping'].includes(state.runtime_hooks.state),enabled:state.runtime_hooks.field_test.enabled,targets:state.action_scope.targets.map(t=>t.target_id??t.id)};};
  try {
    const original=(await command('Target.getTargets',{},null)).targetInfos.find(t=>t.url===fixtureURL+'/candidate-page');assert(original,'Owned original fixture target must exist');
    const originalSession=(await command('Target.attachToTarget',{targetId:original.targetId,flatten:true},null)).sessionId;
    const target=await command('Target.createTarget',{url:uiURL},null);
    uiSession=(await command('Target.attachToTarget',{targetId:target.targetId,flatten:true},null)).sessionId;
    await command('Page.enable');await command('Runtime.enable');await viewport(1440,900);
    await until("document.querySelector('#request-rows')&&document.querySelector('#capture-state').textContent!=='Connecting'",'Product did not load');
    phase='original Traffic field';await click('#send-page',originalSession);
    await until("[...document.querySelectorAll('.request-row')].some(n=>n.textContent.includes('/payload'))",'Owned Page payload did not reach Traffic');
    const row=await evaluate("(()=>{const n=[...document.querySelectorAll('.request-row')].find(n=>n.textContent.includes('/payload'));return '#'+CSS.escape(n.id)})()");
    // Rows may have no HTML id; select by the visible ledger position instead.
    const requestSelector=row==='#'?await evaluate("'.request-row:nth-child('+([...document.querySelectorAll('.request-row')].findIndex(n=>n.textContent.includes('/payload'))+1)+')'"):row;
    await click(requestSelector);await click('#inspector-tab-payload');
    await click('#exchange-inspector .exchange-options > summary');await clickText('JSON tree','#exchange-inspector');
    await until("[...document.querySelectorAll('#exchange-inspector .exchange-leaf')].some(n=>n.textContent.includes('fixture-observed'))",'Payload JSON field did not render');
    await click('#exchange-inspector .exchange-leaf');await clickText('Trace value','#exchange-inspector');
    await until("!document.querySelector('#screen-field-provenance').hidden",'Trace value did not open Field trace');
    await keyboardTo('#field-provenance-search');await key('Enter');
    await until("document.querySelectorAll('.field-provenance-test-candidate').length>0",'Literal search did not expose Test this candidate');
    await screenshot('01-original-field-candidate');
    const before=await quietState();
    await keyboardTo('.field-provenance-test-candidate');await key('Enter');
    await until("document.querySelector('#candidate-experiment-strip')&&!document.querySelector('#candidate-experiment-strip').hidden",'Candidate handoff did not expose bridge');
    assert.deepEqual(await quietState(),before,'Candidate handoff must not create, navigate, bind, capture or arm');
    assert.equal(await evaluate("document.querySelector('#hooks-field-confirm').checked||document.querySelector('#hooks-confirm').checked"),false);
    assert.equal(await evaluate("document.querySelector('#candidate-experiment-target').value"),'');
    phase='explicit disposable create/open';await click('#hooks-create');
    await until("!document.querySelector('#hooks-navigate').disabled",'Explicit create did not enable disposable navigation');
    const openDisposable=async(path)=>{
      await fill('#hooks-page-url',fixtureURL+path);await click('#hooks-navigate');
      await until("document.querySelector('#candidate-experiment-target').options.length>1&&!document.querySelector('#hooks-navigate').disabled",'Explicit open did not list targets');
      assert.equal(await evaluate("document.querySelector('#candidate-experiment-target').value"),'','Navigation must not choose target');
      assert.equal(await evaluate("document.querySelector('#hooks-field-confirm').checked||document.querySelector('#hooks-confirm').checked"),false,'Navigation must retire confirmations');
    };
    const refuseBind=async(label)=>{
      phase=label;const startedAt=await click('#candidate-experiment-bind');
      await until("/no exact|no match|multiple|ambiguous|changed|unavailable|unsupported|not found/i.test(document.querySelector('#candidate-experiment-status').textContent)&&!document.querySelector('#candidate-experiment-bind').disabled",label+' must fail visibly and allow explicit retry');
      receipts.push({phase,kind:'binding-roundtrip',measurement:'Native Bind activation to rendered refusal; UI plus backend roundtrip, not pure source-scan time',elapsed_ms:Math.round(performance.now()-startedAt),outcome:'refused'});
      const state=await quietState();assert.equal(state.definitions,0,label+' cannot add a hook');assert.equal(state.enabled,false);assert.equal(state.armed,false);
      await screenshot(label);
    };
    await openDisposable('/candidate-changed');await chooseTarget('Page');await refuseBind('negative-changed-full-source');
    await openDisposable('/candidate-duplicate');await chooseTarget('Page');await refuseBind('negative-duplicate-exact-source');
    await openDisposable('/candidate-page');
    await until("[...document.querySelector('#candidate-experiment-target').options].some(o=>o.textContent.trim().startsWith('Worker'))",'Owned worker target did not become visible');
    await chooseTarget('Worker');await refuseBind('negative-wrong-selected-worker');
    await chooseTarget('Page');
    phase='explicit exact-byte bind';await keyboardTo('#candidate-experiment-bind');const bindStartedAt=performance.now();await key('Enter');
    await until("/bound|ready/i.test(document.querySelector('#candidate-experiment-status').textContent)",'Exact byte binding did not finish');
    receipts.push({phase,kind:'binding-roundtrip',measurement:'Native Bind activation to rendered bound status; UI plus backend roundtrip, not pure source-scan time',elapsed_ms:Math.round(performance.now()-bindStartedAt),outcome:'bound'});
    const bound=await quietState();assert.equal(bound.definitions,1);assert.equal(bound.enabled,false);assert.equal(bound.armed,false);
    for(const [width,height] of [[1440,900],[760,560],[360,740]]){
      await viewport(width,height);await reveal('#candidate-experiment-return');
      assert(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),'Bridge must not force page horizontal overflow');
      await screenshot(`02-bound-${width}`);
    }
    await viewport(1440,900);
    phase='explicit capture and observation';await click('#hooks-field-confirm');await click('#hooks-field-configure');
    await until("/POST.*\\/payload.*Capturing/.test(document.querySelector('#hooks-field-status').textContent)",'Explicit value capture did not become ready');
    await click('#hooks-confirm');await click('#hooks-arm');
    await until("/^Armed/.test(document.querySelector('#source-hooks-notice').textContent)&&!document.querySelector('#hooks-disarm').disabled",'Explicit arm did not complete');
    const chosen=await evaluate("document.querySelector('#candidate-experiment-target').value");
    const disposable=(await command('Target.getTargets',{},null)).targetInfos.find(t=>t.targetId===chosen);
    assert(disposable&&disposable.targetId!==original.targetId,'Selected UI target must be a separate disposable page');
    const disposableSession=(await command('Target.attachToTarget',{targetId:disposable.targetId,flatten:true},null)).sessionId;
    const requestsBefore=requestReceipts.length;phase='owned disposable page action';await click('#send-page',disposableSession);
    await until("/matched baseline/i.test(document.querySelector('#candidate-experiment-status').textContent)",'Owned page action did not yield matched baseline');
    assert.equal(requestReceipts.length,requestsBefore+1,'Page button must issue exactly one Page request and no Worker request');
    await screenshot('03-matched-baseline');
    phase='return original evidence';const beforeReturn=await quietState();await keyboardTo('#candidate-experiment-return');await key('Enter');
    await until("!document.querySelector('#screen-field-provenance').hidden&&document.querySelector('#field-provenance-value').textContent.includes('fixture-observed')",'Return did not restore original selected field');
    assert.deepEqual(await quietState(),beforeReturn,'Return restores evidence without implicit capture, arm, target or definition changes');
    await screenshot('04-return-original-field');
    assert.equal(runtimeErrors.length,0,JSON.stringify(runtimeErrors));
    await writeFile(join(output,'receipt.json'),JSON.stringify({status:'passed',path:'real backend and installed Chromium native CDP input',phase,receipts,viewports:[[1440,900],[760,560],[360,740]],limitations:['Not native macOS WebKit acceptance.','No A/B/A comparison or persistence.']},null,2));
    console.log(`PASS original live-JS to disposable matched-baseline rendered journey; receipts: ${output}`);
  } catch(error) {
    try{await screenshot('failure');}catch{}
    await writeFile(join(output,'receipt.json'),JSON.stringify({status:'failed',phase,error:String(error.stack||error),receipts,runtimeErrors},null,2));throw error;
  } finally {for(const request of pending.values()){clearTimeout(request.timer);request.reject(Error('Journey closed'));}socket.close();}
}
