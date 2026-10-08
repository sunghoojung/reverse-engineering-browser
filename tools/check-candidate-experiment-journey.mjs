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
  if (['/candidate.js', '/candidate-worker.js'].includes(path)) {
    let changed=false;
    try{const referer=new URL(req.headers?.referer);changed=referer.origin===`http://${req.headers?.host}`&&/^127\.0\.0\.1:\d+$/.test(req.headers?.host)&&referer.pathname==='/candidate-changed';}catch{/* Missing or foreign Referer keeps original bytes. */}
    res.setHeader('Content-Type', 'text/javascript');res.setHeader('Cache-Control','no-store');
    res.end(path === '/candidate-worker.js' ? workerSource : changed ? candidateFixtureSource.replace('UTF-8 ownership', 'Changed UTF-8 ownership') : candidateFixtureSource);
    return true;
  }
  if (['/candidate-page', '/candidate-changed', '/candidate-duplicate'].includes(path)) {
    res.setHeader('Content-Type', 'text/html');
    res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Owned candidate bridge fixture</title><link rel="icon" href="data:,"><h1>Owned candidate bridge fixture</h1><p>Separate actions: Page never sends a Worker request.</p><button id="send-page">Send Page payload</button><button id="send-worker">Send Worker payload</button><script src="/candidate.js"></script>${path === '/candidate-duplicate' ? '<script src="/candidate.js?second=1"></script>' : ''}</html>`);
    return true;
  }
  if (path === '/payload') {
    let body=''; req.on('data', chunk=>{body+=chunk;}); req.on('end',()=>{receipts.push({method:req.method,body});res.setHeader('Content-Type','application/json');res.end('{"accepted":true}');});
    return true;
  }
  return false;
}

// Selecting a CDP session does not foreground its tab. Chromium may suspend
// requestAnimationFrame in background tabs; activate the owned target before
// every DOM read/paint wait rather than replacing paint with elapsed time.
export async function candidateSessionEvaluate(command, expression, session) {
  await command('Page.bringToFront',{},session);
  const result=await command('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},session);
  if(result.exceptionDetails)throw Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
  return result.result.value;
}

// Native buttons require the character-producing keyDown shape used by the
// shared Sources-tree driver. rawKeyDown alone exercises key listeners but is
// not an Enter/Space activation substitute.
export function candidateKeyEvents(key,modifiers=0) {
  const code=key===' '?'Space':key==='a'?'KeyA':key;
  const windowsVirtualKeyCode={Enter:13,' ':32,Tab:9,Escape:27,ArrowDown:40,ArrowUp:38,ArrowLeft:37,ArrowRight:39,Home:36,End:35,a:65}[key];
  const text=key==='Enter'?'\r':key===' '?' ':null;
  const common={key,code,modifiers,windowsVirtualKeyCode};
  return [{type:text!==null?'keyDown':'rawKeyDown',...common,...(text!==null?{text,unmodifiedText:text}:{})},{type:'keyUp',key,code,windowsVirtualKeyCode}];
}

// Titles are refreshed display metadata. Identity requires the exact selected
// ID, its current type, the product owner, and the same disposable lifetime.
export function candidateTargetSelectionMatches(expected, snapshot) {
  const rows=snapshot.options.filter(option=>option.value===expected.value);
  return snapshot.lifetime===expected.lifetime&&snapshot.selected===expected.value&&
    snapshot.ownerTarget===expected.value&&rows.length===1&&rows[0].type===expected.type;
}

export function candidateBindResponseMatches(params, actionURL) {
  if(params.request?.url!==actionURL || params.request?.method!=='POST' || !Number.isInteger(params.responseStatusCode))return false;
  try{return JSON.parse(params.request.postData).action==='bind_runtime_candidate';}catch{return false;}
}

export async function checkCandidateFixture() {
  for(const [key,text,code,vk] of [['Enter','\r','Enter',13],[' ',' ','Space',32]]){const events=candidateKeyEvents(key);assert.deepEqual(events,[{type:'keyDown',key,code,modifiers:0,windowsVirtualKeyCode:vk,text,unmodifiedText:text},{type:'keyUp',key,code,windowsVirtualKeyCode:vk}]);}
  for(const key of ['Tab','Escape','ArrowDown','ArrowUp','Home','End']){const [down,up]=candidateKeyEvents(key);assert.equal(down.type,'rawKeyDown');assert.equal(up.type,'keyUp');assert(!('text' in down));assert(!('text' in up));assert(Number.isInteger(down.windowsVirtualKeyCode));}
  assert.deepEqual(candidateKeyEvents('a',2),[{type:'rawKeyDown',key:'a',code:'KeyA',modifiers:2,windowsVirtualKeyCode:65},{type:'keyUp',key:'a',code:'KeyA',windowsVirtualKeyCode:65}]);
  const selected={value:'worker-A',type:'worker',lifetime:'session1/nav2'},targetSnapshot={selected:'worker-A',ownerTarget:'worker-A',lifetime:selected.lifetime,options:[{value:'worker-A',type:'worker',label:'Worker · updated title'}]};
  assert(candidateTargetSelectionMatches(selected,targetSnapshot),'Same exact worker may refresh its display title');
  for(const patch of [{selected:'worker-B'},{ownerTarget:'worker-B'},{lifetime:'session1/nav3'},{options:[]},{options:[{value:'worker-A',type:'page'}]},{options:[...targetSnapshot.options,...targetSnapshot.options]}])assert.equal(candidateTargetSelectionMatches(selected,{...targetSnapshot,...patch}),false,'Title independence must never weaken exact identity/type/owner/lifetime checks');
  const actionURL='http://127.0.0.1:1234/api/debugger/actions',owned={request:{url:actionURL,method:'POST',postData:JSON.stringify({action:'bind_runtime_candidate'})},responseStatusCode:200};
  assert(candidateBindResponseMatches(owned,actionURL));
  for(const changed of [{...owned,responseStatusCode:undefined},{...owned,request:{...owned.request,url:actionURL+'?foreign=1'}},{...owned,request:{...owned.request,method:'GET'}},{...owned,request:{...owned.request,postData:'{'}},{...owned,request:{...owned.request,postData:JSON.stringify({action:'arm_runtime_hooks'})}}])assert.equal(candidateBindResponseMatches(changed,actionURL),false,'Only genuine exact bind response is held');
  const activationCalls=[];
  const activate=async(method,params,session)=>{activationCalls.push({method,params,session});return method==='Runtime.evaluate'?{result:{value:session}}:{};};
  for(const session of ['original','ui','disposable','ui'])assert.equal(await candidateSessionEvaluate(activate,'document.visibilityState',session),session);
  assert.deepEqual(activationCalls.map(call=>[call.method,call.session]),['original','ui','disposable','ui'].flatMap(session=>[['Page.bringToFront',session],['Runtime.evaluate',session]]));
  assert(activationCalls.filter(call=>call.method==='Runtime.evaluate').every(call=>call.params.awaitPromise),'Foreground repair preserves native paint waits');
  await assert.rejects(candidateSessionEvaluate(async()=>{throw Error('activation refused');},'document.title','owned'),/activation refused/);
  const response = (path,headers={}) => {let value;const responseHeaders={};assert(candidateFixtureRoute({url:path,headers},{setHeader:(name,v)=>{responseHeaders[name]=v;},end:v=>{value=v;}}));return {value,headers:responseHeaders};};
  const page=response('/candidate-page').value;
  assert.match(page, /id="send-page"/);assert.match(page, /id="send-worker"/);
  assert.match(candidateFixtureSource,/function makePayload\(input\)\{\n  return "fixture-observed";/);
  assert(!candidateFixtureSource.includes('input+'));
  assert.match(candidateFixtureSource,/body:JSON.stringify\(\{payload:makePayload\("owned-input"\)\}\)/);
  assert.equal(response('/candidate.js').value,response('/candidate.js?second=1').value);
  const changedPage=response('/candidate-changed').value;assert.equal(page.match(/<script src="([^"]+)"/)[1],changedPage.match(/<script src="([^"]+)"/)[1],'Changed fixture must retain identical script URL');
  const changed=response('/candidate.js',{host:'127.0.0.1:1234',referer:'http://127.0.0.1:1234/candidate-changed'});
  assert.notEqual(response('/candidate.js').value,changed.value);assert.match(changed.value,/return "fixture-observed"/);assert.equal(changed.headers['Cache-Control'],'no-store');
  for(const referer of ['http://127.0.0.1:1234/candidate-page','http://127.0.0.1:9999/candidate-changed','https://foreign.invalid/candidate-changed','malformed'])assert.equal(response('/candidate.js',{host:'127.0.0.1:1234',referer}).value,candidateFixtureSource,'Only exact owned same-origin changed page varies bytes');
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
  const socket=await socketFactory(address), pending=new Map(), receipts=[], runtimeErrors=[], commandTrace=[];
  let lastForeground=null,bindHold=null,guardedTargetSession=null,guardedTargetEvaluations=0;
  const mutationRequests=[],interceptionErrors=[],dialogs=[];
  let sequence=0, uiSession, phase='attach';
  socket.addEventListener('message',event=>{
    const message=JSON.parse(event.data);
    if(message.sessionId===uiSession&&message.method==='Page.javascriptDialogOpening')dialogs.push({type:message.params.type,message:message.params.message});
    if(message.sessionId===uiSession&&message.method==='Network.requestWillBeSent'&&message.params.request.url===uiURL+'/api/debugger/actions'&&message.params.request.method==='POST'){try{mutationRequests.push(JSON.parse(message.params.request.postData).action);}catch{mutationRequests.push('unparsed-action');}}
    if(message.sessionId===uiSession&&message.method==='Fetch.requestPaused'){
      if(bindHold&&!bindHold.paused&&candidateBindResponseMatches(message.params,uiURL+'/api/debugger/actions'))bindHold.paused=message.params;
      else command('Fetch.continueResponse',{requestId:message.params.requestId}).catch(error=>interceptionErrors.push(String(error)));
    }
    if(message.method==='Runtime.exceptionThrown')runtimeErrors.push(message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text);
    const request=pending.get(message.id);if(!request)return;
    pending.delete(message.id);clearTimeout(request.timer);
    if(message.error)request.reject(Error(JSON.stringify(message.error)));else request.resolve(message.result);
  });
  const command=(method,params={},sessionId=uiSession)=>new Promise((resolve,reject)=>{
    if(method==='Runtime.evaluate'&&sessionId===guardedTargetSession){guardedTargetEvaluations++;reject(Error('Test attempted forbidden Runtime.evaluate in guarded disposable target'));return;}
    commandTrace.push({phase,method,session:sessionId,expression:method==='Runtime.evaluate'?params.expression.slice(0,180):undefined});if(commandTrace.length>64)commandTrace.shift();
    const id=++sequence,timer=setTimeout(()=>{pending.delete(id);reject(Error(`CDP timeout: ${method}`));},15000);
    pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
  });
  const evaluate=async(expression,session=uiSession)=>{
    const result=await candidateSessionEvaluate(command,expression,session);
    if(lastForeground!==session){receipts.push({phase,kind:'foreground',session});lastForeground=session;}
    return result;
  };
  const until=async(predicate,label,session=uiSession)=>{
    const deadline=Date.now()+20000;let last;
    while(Date.now()<deadline){assert.equal(dialogs.length,0,'Unexpected native dialog; no automatic acceptance: '+JSON.stringify(dialogs));try{last=await evaluate(predicate,session);if(last)return last;}catch(error){last=error.message;}await new Promise(resolve=>setTimeout(resolve,40));}
    throw Error(`${phase}: ${label}: ${JSON.stringify(last)}`);
  };
  const frame=()=>evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
  const key=async(key,session=uiSession,modifiers=0)=>{
    await command('Page.bringToFront',{},session);
    for(const event of candidateKeyEvents(key,modifiers))await command('Input.dispatchKeyEvent',event,session);
    receipts.push({phase,kind:'native-key',key,modifiers});
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
  const fill=async(selector,value)=>{await click(selector);await key('a',uiSession,process.platform==='darwin'?4:2);await command('Input.insertText',{text:value});assert(await evaluate(`document.activeElement===document.querySelector(${JSON.stringify(selector)})&&document.querySelector(${JSON.stringify(selector)}).value===${JSON.stringify(value)}`),'Native text replacement must retain focus and exact field value: '+selector);};
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
  const targetSnapshotExpression=`(()=>{const s=document.querySelector('#candidate-experiment-target'),session=state.debuggerSession,hooks=session?.runtime_hooks;return {selected:s?.value,ownerTarget:candidateExperiment?.target,lifetime:JSON.stringify([hooks?.session_id,session?.request_interception?.created_at_ms,session?.object_experiment?.navigation_id,hooks?.target_id,session?.target?.id]),documentURL:session?.object_experiment?.url,options:[...(s?.options??[])].slice(0,10).map((option,index)=>({index,value:option.value,label:option.textContent,type:option.value===hooks?.target_id?'page':hooks?.workers?.find(worker=>worker.id===option.value)?.type??null}))};})()`;
  const chooseTarget=async(kind)=>{
    phase='select disposable '+kind;
    const before=await evaluate(targetSnapshotExpression),type=kind.toLowerCase();
    const option=before.options.find(option=>option.value&&option.type===type&&option.label.trim().startsWith(kind));
    assert(option,`Missing explicit ${kind} target option`);
    const expected={...option,lifetime:before.lifetime};
    receipts.push({phase,kind:'target-choice-before',expected,snapshot:before});
    // Same native select sequence as the proven Console document driver.
    await click('#candidate-experiment-target');await key('Home');
    for(let i=0;i<option.index;i++)await key('ArrowDown');
    await key('Enter');
    try {
      await until(`(${candidateTargetSelectionMatches.toString()})(${JSON.stringify(expected)},${targetSnapshotExpression})`,'Exact explicit '+kind+' target ID/type/owner/lifetime did not stick');
    } finally {
      receipts.push({phase,kind:'target-choice-after',expected,snapshot:await evaluate(targetSnapshotExpression)});
    }
  };
  const readOnlyState=()=>fetch(uiURL+'/api/debugger').then(r=>{assert(r.ok);return r.json();});
  const quietState=async()=>{const state=await readOnlyState();return {isolated:state.runtime_hooks.isolated,definitions:state.runtime_hooks.definitions.length,armed:['arming','armed','handling','stopping'].includes(state.runtime_hooks.state),enabled:state.runtime_hooks.field_test.enabled,targets:state.action_scope.targets.map(t=>t.target_id??t.id)};};
  try {
    const original=(await command('Target.getTargets',{},null)).targetInfos.find(t=>t.url===fixtureURL+'/candidate-page');assert(original,'Owned original fixture target must exist');
    const originalSession=(await command('Target.attachToTarget',{targetId:original.targetId,flatten:true},null)).sessionId;
    const target=await command('Target.createTarget',{url:uiURL},null);
    uiSession=(await command('Target.attachToTarget',{targetId:target.targetId,flatten:true},null)).sessionId;
    await command('Page.enable');await command('Runtime.enable');await command('Network.enable',{maxPostDataSize:65536});await viewport(1440,900);
    await until("document.querySelector('#request-rows')&&document.querySelector('#capture-state').textContent!=='Connecting'",'Product did not load');
    const services=await fetch(uiURL+'/api/health',{signal:AbortSignal.timeout(5000)}).then(r=>{assert(r.ok);return r.json();});assert.equal(services.capture_mode,'live','Supported owned broker capture must be configured');assert.equal(services.broker_connected,true,'Actual owned broker socket must be ready');
    receipts.push({phase,kind:'service-readiness',capture_mode:services.capture_mode,broker_connected:services.broker_connected,native_event_producer:'not used; owned request evidence is captured through CDP'});
    const backendReady=await readOnlyState();assert.equal(backendReady.target?.id,original.targetId,'Live debugger must own original fixture target');assert.equal(backendReady.network?.capture_enabled,true,'Original fixture capture requires explicit launch consent');receipts.push({phase,kind:'capture-configuration',original_target:original.targetId,cdp_content_capture:backendReady.network.capture_enabled,consent:'Explicit synthetic-fixture launch flag; candidate field Capture and Arm remain separate visible actions'});
    await until("document.querySelector('#session-mode')?.dataset.kind==='live'",'Supported live capture setup is absent; do not inject capture mode');
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
      phase=label;const expected=label==='negative-duplicate-exact-source'?'Ambiguous candidate: identical bytes occur in multiple sources of this target.':'No exact candidate bytes in the selected target.';const startedAt=await click('#candidate-experiment-bind');
      await until(`document.querySelector('#candidate-experiment-status').textContent.includes(${JSON.stringify(expected)})&&!document.querySelector('#candidate-experiment-bind').disabled`,label+' must fail for the exact intended identity reason and allow explicit retry');
      receipts.push({phase,kind:'binding-roundtrip',measurement:'Native Bind activation to rendered refusal; UI plus backend roundtrip, not pure source-scan time',elapsed_ms:Math.round(performance.now()-startedAt),outcome:'refused'});
      const state=await quietState();assert.equal(state.definitions,0,label+' cannot add a hook');assert.equal(state.enabled,false);assert.equal(state.armed,false);
      await reveal('#candidate-experiment-strip');await screenshot(label);
    };
    await openDisposable('/candidate-changed');await chooseTarget('Page');await refuseBind('negative-changed-full-source');
    await openDisposable('/candidate-duplicate');await chooseTarget('Page');await refuseBind('negative-duplicate-exact-source');
    await openDisposable('/candidate-page');
    await until("[...document.querySelector('#candidate-experiment-target').options].some(o=>o.textContent.trim().startsWith('Worker'))",'Owned worker target did not become visible');
    await chooseTarget('Worker');await refuseBind('negative-wrong-selected-worker');
    await chooseTarget('Page');
    // DOM evaluation itself creates debugger scripts. Finish owned-page hit
    // testing before binding; never perturb the guarded target catalog while
    // observing the baseline. Later activation uses native input only.
    const chosen=await evaluate("document.querySelector('#candidate-experiment-target').value");
    const disposable=(await command('Target.getTargets',{},null)).targetInfos.find(t=>t.targetId===chosen);
    assert(disposable&&disposable.targetId!==original.targetId,'Selected UI target must be a separate disposable page');
    const disposableSession=(await command('Target.attachToTarget',{targetId:disposable.targetId,flatten:true},null)).sessionId;
    const ownedActionPoint=await reveal('#send-page',disposableSession);
    receipts.push({phase,kind:'owned-page-readiness',selector:'#send-page',target:disposable.targetId,before_binding:true});
    guardedTargetSession=disposableSession;
    // Delay only delivery of a genuine successful backend response. The real
    // bind executes, so Stop waiting cannot claim to undo its definition.
    phase='rendered Stop waiting on genuine bind response';
    await fill('#hooks-label','Retain owned hook draft');
    const draftBefore=await evaluate("JSON.stringify([document.querySelector('#hooks-label').value,document.querySelector('#hooks-field-url').value,document.querySelector('#hooks-field-pointer').value])");
    const bindsBefore=mutationRequests.filter(action=>action==='bind_runtime_candidate').length;
    bindHold={paused:null};
    await command('Fetch.enable',{patterns:[{urlPattern:uiURL+'/api/debugger/actions',requestStage:'Response'}]});
    await click('#candidate-experiment-bind');
    const responseDeadline=Date.now()+20000;
    while(!bindHold.paused&&Date.now()<responseDeadline)await new Promise(resolve=>setTimeout(resolve,25));
    assert(bindHold.paused,'Actual bind response did not reach the response-stage hold');
    assert.equal(bindHold.paused.responseStatusCode,200,'Cancellation case requires real successful backend binding');
    const heldBody=await command('Fetch.getResponseBody',{requestId:bindHold.paused.requestId});
    const actualResponse=JSON.parse(heldBody.base64Encoded?Buffer.from(heldBody.body,'base64').toString('utf8'):heldBody.body);
    assert(actualResponse.runtime_hooks?.definitions?.some(definition=>definition.candidate_guard),'Held response must contain the actual backend-added candidate definition');
    await until("!document.querySelector('#candidate-experiment-cancel').hidden",'Pending binding did not expose Stop waiting');
    await screenshot('02-pending-bind-before-stop');
    await keyboardTo('#candidate-experiment-cancel');await key('Enter');
    await until("/retired|changed|unknown/i.test(document.querySelector('#candidate-experiment-status').textContent)&&document.querySelector('#candidate-experiment-cancel').hidden",'Stop waiting did not retire acknowledgement ownership');
    let release='unchanged actual response released';
    try{await command('Fetch.continueResponse',{requestId:bindHold.paused.requestId});}
    catch(error){assert.match(String(error),/Invalid InterceptionId|Invalid requestId|Invalid .*id|No resource with given identifier|not found/i,'Unexpected response-release failure');release='Browser already aborted held delivery after Stop waiting';}
    await command('Fetch.disable');bindHold=null;
    await until("document.querySelectorAll('#hooks-definitions .hook-definition-row').length===1&&!document.querySelector('#hooks-definitions .hook-remove').disabled",'Actual added definition must be inspectable after cancellation');
    await frame();
    assert.equal(mutationRequests.filter(action=>action==='bind_runtime_candidate').length,bindsBefore+1,'Stop waiting and late delivery must not dispatch another binding');
    assert.equal(await evaluate("document.querySelector('#hooks-field-confirm').checked||document.querySelector('#hooks-confirm').checked"),false,'Late delivery cannot restore capture or arming consent');
    assert.equal(await evaluate("candidateExperiment?.bound===null"),true,'Cancelled question must not adopt late backend acknowledgement');
    assert(await evaluate("!document.querySelector('#candidate-experiment-target').disabled&&!/Observation hook bound|Matched baseline/.test(document.querySelector('#candidate-experiment-status').textContent)"),'Late delivery cannot restore bridge binding');
    assert.equal(await evaluate("JSON.stringify([document.querySelector('#hooks-label').value,document.querySelector('#hooks-field-url').value,document.querySelector('#hooks-field-pointer').value])"),draftBefore,'Stop waiting preserves visible drafts');
    const cancelledState=await quietState();assert.equal(cancelledState.definitions,1);assert.equal(cancelledState.enabled,false);assert.equal(cancelledState.armed,false);
    receipts.push({phase,kind:'rendered-response-cancellation',response:'Genuine owned backend HTTP200 and candidate definition verified before holding delivery',release,bind_dispatches:1,late_binding_restored:false,consents_restored:false,automatic_retry:false,drafts_retained:true,native_definition:'Added before cancellation; removed next by explicit visible control'});
    await screenshot('02-stop-waiting-late-response');
    await click('#hooks-definitions .hook-remove');
    await until("document.querySelectorAll('#hooks-definitions .hook-definition-row').length===0&&!document.querySelector('#candidate-experiment-bind').disabled",'Explicit Remove did not retire the backend-added definition');
    assert.equal((await quietState()).definitions,0);
    phase='explicit exact-byte bind';await keyboardTo('#candidate-experiment-bind');const bindStartedAt=performance.now();await key('Enter');
    await until("document.querySelector('#candidate-experiment-status').textContent.startsWith('Observation hook bound.')",'Exact byte binding did not finish');
    receipts.push({phase,kind:'binding-roundtrip',measurement:'Native Bind activation to rendered bound status; UI plus backend roundtrip, not pure source-scan time',elapsed_ms:Math.round(performance.now()-bindStartedAt),outcome:'bound'});
    const bound=await quietState();assert.equal(bound.definitions,1);assert.equal(bound.enabled,false);assert.equal(bound.armed,false);
    for(const [width,height] of [[1440,900],[760,560],[360,740]]){
      await viewport(width,height);await keyboardTo('#candidate-experiment-return');await reveal('#candidate-experiment-return');
      assert(await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),'Bridge must not force page horizontal overflow');
      await screenshot(`02-bound-${width}`);
    }
    await viewport(1440,900);
    phase='explicit capture and observation';await click('#hooks-field-confirm');await click('#hooks-field-configure');
    await until("/POST.*\\/payload.*Capturing/.test(document.querySelector('#hooks-field-status').textContent)",'Explicit value capture did not become ready');
    await click('#hooks-confirm');await click('#hooks-arm');
    await until("/^Armed/.test(document.querySelector('#source-hooks-notice').textContent)&&!document.querySelector('#hooks-disarm').disabled",'Explicit arm did not complete');
    assert.equal(await evaluate("document.querySelector('#candidate-experiment-target').value"),chosen,'Observation target must remain the explicitly selected page');
    const stillOwned=(await command('Target.getTargets',{},null)).targetInfos.find(t=>t.targetId===chosen);
    assert.equal(stillOwned?.url,disposable.url,'Prepared native action belongs to the same disposable document');
    const requestsBefore=requestReceipts.length;phase='owned disposable page action';
    await command('Page.bringToFront',{},disposableSession);
    await command('Input.dispatchMouseEvent',{type:'mousePressed',x:ownedActionPoint.x,y:ownedActionPoint.y,button:'left',clickCount:1},disposableSession);
    await command('Input.dispatchMouseEvent',{type:'mouseReleased',x:ownedActionPoint.x,y:ownedActionPoint.y,button:'left',clickCount:1},disposableSession);
    receipts.push({phase,kind:'pointer',selector:'#send-page',target:chosen,guarded_target_evaluation:false});
    await until("/matched baseline/i.test(document.querySelector('#candidate-experiment-status').textContent)",'Owned page action did not yield matched baseline');
    assert.equal(guardedTargetEvaluations,0,'Guarded baseline target must receive native input only, never test evaluation that changes its script catalog');
    receipts.push({phase,kind:'guarded-target-integrity',runtime_evaluations_after_binding_preparation:guardedTargetEvaluations});
    assert.equal(requestReceipts.length,requestsBefore+1,'Page button must issue exactly one Page request and no Worker request');
    await screenshot('03-matched-baseline');
    phase='return original evidence';const beforeReturn=await quietState();await keyboardTo('#candidate-experiment-return');await key('Enter');
    await until("!document.querySelector('#screen-field-provenance').hidden&&document.querySelector('#field-provenance-value').textContent.includes('fixture-observed')",'Return did not restore original selected field');
    assert.deepEqual(await quietState(),beforeReturn,'Return restores evidence without implicit capture, arm, target or definition changes');
    await screenshot('04-return-original-field');
    assert.equal(runtimeErrors.length,0,JSON.stringify(runtimeErrors));assert.equal(interceptionErrors.length,0,JSON.stringify(interceptionErrors));assert.equal(dialogs.length,0,JSON.stringify(dialogs));
    await writeFile(join(output,'receipt.json'),JSON.stringify({status:'passed',path:'real backend and installed Chromium native CDP input',phase,receipts,viewports:[[1440,900],[760,560],[360,740]],limitations:['Not native macOS WebKit acceptance.','No A/B/A comparison or persistence.','Return/Close/navigation/source-digest exhaustive late-ack races are controller-only; rendered interruption covers Stop waiting only.']},null,2));
    console.log(`PASS original live-JS to disposable matched-baseline rendered journey; receipts: ${output}`);
  } catch(error) {
    let targetFailure;try{targetFailure=await evaluate(targetSnapshotExpression);}catch(diagnosticError){targetFailure={error:String(diagnosticError)};}
    let uiFailure;try{uiFailure=await evaluate("(()=>({focus:{id:document.activeElement?.id,tag:document.activeElement?.tagName,text:document.activeElement?.textContent?.slice(0,100)},fieldSearch:typeof fieldProvenanceSelection==='undefined'?null:{searching:fieldProvenanceSelection?.searching,searched:fieldProvenanceSelection?.searched,error:fieldProvenanceSelection?.error,candidates:fieldProvenanceSelection?.candidates?.length,notice:document.querySelector('#field-provenance-notice')?.textContent,searchDisabled:document.querySelector('#field-provenance-search')?.disabled,renderedCandidates:document.querySelectorAll('.field-provenance-test-candidate').length},debuggerScripts:typeof state==='undefined'?null:state.debuggerSession?.scripts?.length}))()");}catch(diagnosticError){uiFailure={error:String(diagnosticError)};}
    let backendFailure;try{const snapshot=await fetch(uiURL+'/api/debugger',{signal:AbortSignal.timeout(5000)}).then(r=>r.json());backendFailure={state:snapshot.state,target:snapshot.target,network_capture_enabled:snapshot.network?.capture_enabled,requests:snapshot.network?.requests?.length,hooks_state:snapshot.runtime_hooks?.state};}catch(diagnosticError){backendFailure={error:String(diagnosticError)};}
    try{await screenshot('failure');}catch{}
    await writeFile(join(output,'receipt.json'),JSON.stringify({status:'failed',phase,error:String(error.stack||error),receipts,runtimeErrors,commandTrace,backendFailure,uiFailure,targetFailure,mutationRequests,interceptionErrors,dialogs},null,2));throw error;
  } finally {if(bindHold){try{await command('Fetch.disable');}catch{}}for(const request of pending.values()){clearTimeout(request.timer);request.reject(Error('Journey closed'));}socket.close();}
}
