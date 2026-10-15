// Rendered product journey: native input in the actual UI, real owned backend
// captures only. Evaluation reads the UI; never evaluates the disposable page.
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import element from '../apps/research-ui/element_screenshot.js';
import {candidateKeyEvents,candidateSessionEvaluate,candidateRevealGeometry,candidateFocusMargin,candidateGeometryStability} from './check-candidate-experiment-journey.mjs';
import {platformEditEvent} from './rendered-keyboard.mjs';
export function elementCaptureResponseMatches(params,url) {
  if(params.request?.url!==url || params.request?.method!=='POST' || !Number.isInteger(params.responseStatusCode)) return false;
  try {return JSON.parse(params.request.postData).action==='capture_element_screenshot';} catch {return false;}
}
// Keep every mode tab vertically inside the real scrollport, including when
// a horizontal scrollbar consumes part of the fixed-height strip.
export function assertElementModeTabGeometry({clip,tabs}) {
  assert(Number.isFinite(clip.top)&&Number.isFinite(clip.bottom)&&clip.bottom>clip.top,'Mode strip needs a positive vertical scrollport');
  assert(tabs.length>0,'Mode strip needs tabs');
  for(const rect of tabs) assert(Number.isFinite(rect.top)&&Number.isFinite(rect.bottom)&&rect.bottom>rect.top&&rect.top>=clip.top&&rect.bottom<=clip.bottom,'Mode tab must fit entirely inside its vertical scrollport');
}
// Follow the same visible chooser path as a researcher. Never force open the
// details node or relax the strict pointer reveal/hit-test helpers.
export async function enterElementExperiments({evaluate,click,until}) {
  if(!await evaluate("document.querySelector('#advanced-navigation').open")) {
    await click('#advanced-navigation > summary');
    await until("document.querySelector('#advanced-navigation').open",'Advanced chooser did not open');
  }
  await click('[data-screen="experiments"]');
  await until("!document.querySelector('#screen-experiments').hidden && !document.querySelector('#advanced-navigation').open",'Experiments navigation did not complete and close its chooser');
}
export async function checkElementScreenshotUI({address,uiURL,fixtureURL,root,socketFactory}) {
  const output=process.env.REB_UI_SCREENSHOTS || join(root,'build/element-screenshot-ui-qa');await mkdir(output,{recursive:true});
  const socket=await socketFactory(address),pending=new Map(),requests=new Map(),reads=new Set(),captures=[],receipts=[],errors=[];
  let sequence=0,session,target,phase='attach',hold=null,passed=false;
  const command=(method,params={},sessionId=session)=>new Promise((resolve,reject)=>{
    // Runtime reads are restricted to the UI session, never the fixture target.
    if(method==='Runtime.evaluate' && (!sessionId || sessionId!==session)) {reject(Error('Only UI DOM reads are allowed'));return;}
    const id=++sequence,timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP deadline: '+method));},20000);
    pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
  });
  socket.addEventListener('message',event=>{
    const message=JSON.parse(event.data),params=message.params;
    if(message.sessionId===session) {
      if(message.method==='Runtime.exceptionThrown') errors.push(params.exceptionDetails.exception?.description || params.exceptionDetails.text);
      if(message.method==='Page.javascriptDialogOpening') errors.push('Unexpected dialog; never accepted: '+params.type);
      if(message.method==='Network.requestWillBeSent' && params.request.url===uiURL+'/api/debugger/actions' && params.request.method==='POST') {
        const action=JSON.parse(params.request.postData).action;requests.set(params.requestId,{action,phase});
        receipts.push({phase,kind:'actual-product-action',action});
      }
      if(message.method==='Network.loadingFinished' && requests.get(params.requestId)?.action==='capture_element_screenshot') {
        const request=requests.get(params.requestId);requests.delete(params.requestId);
        const read=command('Network.getResponseBody',{requestId:params.requestId}).then(response=>{
          const body=JSON.parse(response.base64Encoded?Buffer.from(response.body,'base64').toString('utf8'):response.body);
          if(!body.ok) throw Error('Real capture refused: '+body.error);
          assert(element.captureValid(body.capture));const {image,document}=body.capture;
          assert.equal(createHash('sha256').update(Buffer.from(image.base64,'base64')).digest('hex'),image.sha256);
          // Metadata only; do not persist raw response bodies or product PNGs.
          captures.push({document,width:image.width,height:image.height,sha256:image.sha256});
          receipts.push({phase:request.phase,kind:'actual-product-png',width:image.width,height:image.height,sha256:image.sha256});
        }).catch(error=>{if(!request.phase.startsWith('retire-'))errors.push(String(error));}).finally(()=>reads.delete(read));reads.add(read);
      }
      if(message.method==='Fetch.requestPaused') {
        if(hold && !hold.paused && elementCaptureResponseMatches(params,uiURL+'/api/debugger/actions')) hold.paused=params;
        else command('Fetch.continueResponse',{requestId:params.requestId}).catch(error=>errors.push(String(error)));
      }
    }
    const request=pending.get(message.id);if(!request)return;pending.delete(message.id);clearTimeout(request.timer);
    message.error?request.reject(Error(JSON.stringify(message.error))):request.resolve(message.result);
  });
  const evaluate=expression=>candidateSessionEvaluate(command,expression,session);
  const until=async(expression,label)=>{
    const deadline=Date.now()+20000;let last;
    while(Date.now()<deadline){assert.equal(errors.length,0,JSON.stringify(errors));last=await evaluate(expression);if(last)return last;await new Promise(resolve=>setTimeout(resolve,40));}
    throw Error(`${phase}: ${label}: ${JSON.stringify(last)}`);
  };
  const frame=()=>evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
  const key=async(key,modifiers=0)=>{await command('Page.bringToFront');for(const event of candidateKeyEvents(key,modifiers))await command('Input.dispatchKeyEvent',platformEditEvent(event));await frame();};
  const settle=selector=>evaluate(`new Promise((resolve,reject)=>{const start=performance.now();let previous='',stable=0;function next(){const n=document.querySelector(${JSON.stringify(selector)});if(!n)return reject(Error('Missing control'));const r=n.getBoundingClientRect(),positions=[];for(let p=n.parentElement;p;p=p.parentElement)positions.push([p.scrollTop,p.scrollLeft]);const value=JSON.stringify([r.left,r.top,r.width,r.height,positions]);stable=(${candidateGeometryStability.toString()})(previous,value,stable);previous=value;if(stable>=3)return resolve();if(performance.now()-start>2500)return reject(Error('Moving geometry'));requestAnimationFrame(next);}requestAnimationFrame(next);})`);
  const reveal=async selector=>{
    await settle(selector);
    for(let attempt=0;attempt<30;attempt++) {
      const point=await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});if(!n)return {missing:true};const r=n.getBoundingClientRect();if(!r.width||!r.height)return {hidden:true};const nodes=[],ancestors=[];for(let p=n.parentElement;p;p=p.parentElement){const s=getComputedStyle(p),b=p.getBoundingClientRect();nodes.push(p);ancestors.push({left:b.left+p.clientLeft,right:b.left+p.clientLeft+p.clientWidth,top:b.top+p.clientTop,bottom:b.top+p.clientTop+p.clientHeight,clipX:['auto','scroll','hidden','clip'].includes(s.overflowX),clipY:['auto','scroll','hidden','clip'].includes(s.overflowY),scrollableY:['auto','scroll'].includes(s.overflowY)&&p.scrollHeight>p.clientHeight+1,scrollTop:p.scrollTop,maxScrollTop:p.scrollHeight-p.clientHeight});}const margin=(${candidateFocusMargin.toString()})(getComputedStyle(n)),plan=(${candidateRevealGeometry.toString()})({left:r.left,right:r.right,top:r.top,bottom:r.bottom},{left:0,right:innerWidth,top:0,bottom:innerHeight},ancestors,margin);if(plan.ready){const x=r.left+r.width/2,y=r.top+r.height/2;return {ready:n.contains(document.elementFromPoint(x,y)),blocked:!n.contains(document.elementFromPoint(x,y)),x,y,rect:{left:r.left,right:r.right,top:r.top,bottom:r.bottom},clip:plan.clip};}if(plan.blocked)return plan;const p=nodes[plan.owner],b=plan.visible;for(const x of [(b.left+b.right)/2,b.left+5,b.right-20])for(const y of [(b.top+b.bottom)/2,b.top+5,b.bottom-5]){const hit=document.elementFromPoint(x,y);if(!hit||!p.contains(hit))continue;let nested=false;for(let q=hit;q&&q!==p;q=q.parentElement){const s=getComputedStyle(q);if(['auto','scroll'].includes(s.overflowY)&&q.scrollHeight>q.clientHeight+1)nested=true;}if(!nested)return {x,y,delta:plan.delta};}return {blocked:true,reason:'No unobscured wheel point'};})()`);
      if(point.ready) {receipts.push({phase,kind:'unclipped-hit-test',selector,...point});return point;}
      assert(!point.missing&&!point.hidden&&!point.blocked,`Unreachable control ${selector}: ${JSON.stringify(point)}`);
      await command('Input.dispatchMouseEvent',{type:'mouseMoved',x:point.x,y:point.y});
      await command('Input.dispatchMouseEvent',{type:'mouseWheel',x:point.x,y:point.y,deltaX:0,deltaY:point.delta});await settle(selector);
    }
    throw Error('Control never became reachable: '+selector);
  };
  const click=async selector=>{
    const p=await reveal(selector);assert(await evaluate(`document.querySelector(${JSON.stringify(selector)}).disabled!==true`),'Disabled '+selector);
    await command('Input.dispatchMouseEvent',{type:'mouseMoved',x:p.x,y:p.y});
    for(const type of ['mousePressed','mouseReleased'])await command('Input.dispatchMouseEvent',{type,x:p.x,y:p.y,button:'left',clickCount:1});await frame();
  };
  const viewport=async(width,height)=>{
    const win=await command('Browser.getWindowForTarget',{targetId:target},null);
    await command('Browser.setWindowBounds',{windowId:win.windowId,bounds:{width,height,windowState:'normal'}},null);
    await command('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});await command('Emulation.setVisibleSize',{width,height});await frame();
  };
  const screenshot=async name=>{await frame();const result=await command('Page.captureScreenshot',{format:'png'});await writeFile(join(output,name+'.png'),Buffer.from(result.data,'base64'));};
  const modeTabGeometry=async()=>{
    const geometry=await evaluate("(()=>{const p=document.querySelector('.experiment-mode-tabs'),r=p.getBoundingClientRect();return {clip:{top:r.top+p.clientTop,bottom:r.top+p.clientTop+p.clientHeight},tabs:[...p.querySelectorAll('.experiment-mode-tab')].map(n=>{const r=n.getBoundingClientRect();return {top:r.top,bottom:r.bottom};})};})()");
    assertElementModeTabGeometry(geometry);receipts.push({phase,kind:'mode-tabs-vertical-fit',geometry});
  };
  const inspect=async()=>{
    await click('[data-element-inspect]');await until("!document.querySelector('[data-element-confirm]').disabled",'Inspection did not complete');
    assert(await evaluate("!document.querySelector('[data-element-confirm]').checked && document.querySelector('[data-element-capture]').disabled"),'Inspection must not authorize pixels');
    await click('[data-element-confirm]');await until("!document.querySelector('[data-element-capture]').disabled",'Explicit consent did not enable capture');
  };
  const capture=async()=>{
    const count=captures.length;await inspect();await click('[data-element-capture]');
    await until("(()=>{const n=document.querySelector('[data-element-stage] img');return n?.complete&&n.naturalWidth>0&&document.querySelectorAll('.element-screenshot-row').length>0;})()",'Real PNG/markup did not load');
    await Promise.all([...reads]);assert.equal(captures.length,count+1,'Exactly one actual backend PNG is required');return captures.at(-1);
  };
  const empty="document.querySelector('[data-element-stage]').children.length===0 && document.querySelector('[data-element-list]').children.length===0 && !document.querySelector('[data-element-confirm]').checked";
  try {
    target=(await command('Target.createTarget',{url:uiURL},null)).targetId;
    session=(await command('Target.attachToTarget',{targetId:target,flatten:true},null)).sessionId;
    await command('Page.enable');await command('Runtime.enable');await command('Network.enable',{maxPostDataSize:65536,maxTotalBufferSize:16000000,maxResourceBufferSize:8000000});await viewport(1440,900);
    await until("typeof state!=='undefined'&&state.debuggerSession?.state==='running'",'Product debugger did not load');
    phase='owned-setup';await enterElementExperiments({evaluate,click,until});await modeTabGeometry();await click('[data-experiment-mode="object"]');await click('#object-create');
    await until("!document.querySelector('#object-navigate').disabled",'Disposable owner was not created');await click('#object-page-url');
    await key('a',process.platform==='darwin'?4:2);await command('Input.insertText',{text:fixtureURL+'/element-capture/plain'});await click('#object-navigate');
    await until("state.debuggerSession?.object_experiment?.state==='loaded'&&state.debuggerSession?.request_interception?.pending_requests===0",'Authored fixture did not load');
    await click('[data-experiment-mode="screenshot"]');
    for(const [width,height] of [[1440,900],[600,800],[360,740]]) {
      phase='render-'+width;await viewport(width,height);await modeTabGeometry();const actual=await capture();
      const workspace=await evaluate(`(()=>{const screen=document.querySelector('#screen-experiments'),panel=document.querySelector('#element-screenshot-workspace'),s=screen.getBoundingClientRect(),p=panel.getBoundingClientRect(),style=getComputedStyle(screen),grid=getComputedStyle(panel),pad=key=>parseFloat(style[key])||0,headerBottom=Math.max(...[...screen.children].filter(n=>n.matches('.experiment-mode-tabs,.experiment-notice,.experiment-scope')&&!n.hidden).map(n=>n.getBoundingClientRect().bottom));return {columnStart:grid.gridColumnStart,columnEnd:grid.gridColumnEnd,row:grid.gridRowStart,panel:{left:p.left,top:p.top,bottom:p.bottom,width:p.width},content:{left:s.left+screen.clientLeft+pad('paddingLeft'),width:screen.clientWidth-pad('paddingLeft')-pad('paddingRight'),bottom:s.top+screen.clientTop+screen.clientHeight-pad('paddingBottom')},headerBottom};})()`);
      assert.equal(workspace.columnStart,'1');assert.equal(workspace.columnEnd,'-1');assert.equal(workspace.row,width<=1000?'4':'3');
      assert(Math.abs(workspace.panel.left-workspace.content.left)<=1 && Math.abs(workspace.panel.width-workspace.content.width)<=1,'Screenshot workspace spans the complete content width');
      assert(Math.abs(workspace.panel.bottom-workspace.content.bottom)<=1 && Math.abs(workspace.panel.top-workspace.headerBottom)<=1,'Screenshot workspace occupies the intended remaining content row');
      receipts.push({phase,kind:'full-content-workspace-placement',workspace});

      const box=actual.document.elements.find(box=>box.x===20&&box.y===30&&box.width===160&&box.height===80);assert(box,'Actual authored CSS box must exist');
      const overlay=`.element-screenshot-box[data-element-number="${box.number}"]`,row=`.element-screenshot-row[data-element-number="${box.number}"]`;
      const geometry=await evaluate(`(()=>{const image=document.querySelector('[data-element-stage] img'),i=image.getBoundingClientRect(),b=document.querySelector(${JSON.stringify(overlay)}).getBoundingClientRect();return {naturalWidth:image.naturalWidth,naturalHeight:image.naturalHeight,image:{x:i.x,y:i.y,width:i.width,height:i.height},box:{x:b.x,y:b.y,width:b.width,height:b.height},count:document.querySelectorAll('.element-screenshot-row').length,pageOverflow:document.documentElement.scrollWidth>innerWidth+1};})()`);
      assert.equal(geometry.naturalWidth,actual.width);assert.equal(geometry.naturalHeight,actual.height);assert.equal(geometry.count,actual.document.elements.length);assert(!geometry.pageOverflow,'No whole-page horizontal overflow');
      for(const [value,expected] of [[geometry.box.x,geometry.image.x+geometry.image.width*box.x/actual.document.viewport.width],[geometry.box.y,geometry.image.y+geometry.image.height*box.y/actual.document.viewport.height],[geometry.box.width,geometry.image.width*box.width/actual.document.viewport.width],[geometry.box.height,geometry.image.height*box.height/actual.document.viewport.height]])assert(Math.abs(value-expected)<=1.5,'Rendered overlay agrees with actual CSS viewport scaling');
      receipts.push({phase,kind:'actual-image-overlay-geometry',viewport:[width,height],geometry});
      await click(overlay);assert(await evaluate(`document.querySelector(${JSON.stringify(row)}).getAttribute('aria-pressed')==='true'`),'Overlay pointer selects matching row');await screenshot('element-screenshot-'+width+'-overlay');
      await click(row);assert(await evaluate(`document.querySelector(${JSON.stringify(overlay)}).getAttribute('aria-pressed')==='true'`),'Row pointer selects matching overlay');await key('Home');
      assert(await evaluate("document.activeElement===document.querySelector('.element-screenshot-row[data-element-number=\"1\"]')&&document.activeElement.matches(':focus-visible')"),'Home moves visible keyboard focus');
      await key('Tab');assert(await evaluate("document.activeElement.dataset.elementNumber==='2' && document.activeElement.classList.contains('element-screenshot-row')"),'Native Tab reaches the next element row');await key('Home');
      await key('ArrowDown');assert(await evaluate("document.activeElement.dataset.elementNumber==='2'&&document.activeElement.getAttribute('aria-pressed')==='true'"),'ArrowDown selects and focuses row 2');
      await key('ArrowUp');assert(await evaluate("document.activeElement.dataset.elementNumber==='1'"),'ArrowUp selects previous row');await key('ArrowRight');assert(await evaluate("document.activeElement.dataset.elementNumber==='2'"),'ArrowRight selects next row');await key('ArrowLeft');assert(await evaluate("document.activeElement.dataset.elementNumber==='1'"),'ArrowLeft selects previous row');
      await key('End');assert(await evaluate(`document.activeElement.dataset.elementNumber==='${actual.document.elements.length}'`),'End focuses last row');
      await key('Home');await key('Enter');await key(' ');
      assert(await evaluate("document.querySelector('.element-screenshot-box[data-element-number=\"1\"]').getAttribute('aria-pressed')==='true'"),'Native Enter/Space keep list and overlay synchronized');
      await reveal('.element-screenshot-row[data-element-number="1"]');assert(await evaluate("document.activeElement.matches(':focus-visible')&&getComputedStyle(document.activeElement).outlineStyle!=='none'&&parseFloat(getComputedStyle(document.activeElement).outlineWidth)>=2"),'Keyboard focus ring must remain visible');await screenshot('element-screenshot-'+width+'-keyboard');
      await click('[data-element-clear]');assert(await evaluate(empty),'Clear removes real PNG and markup');
    }
    await viewport(1440,900);
    for(const leave of [false,true]) {
      phase=leave?'retire-leave':'retire-clear';await inspect();hold={paused:null};
      await command('Fetch.enable',{patterns:[{urlPattern:uiURL+'/api/debugger/actions',requestStage:'Response'}]});
      await click('[data-element-capture]');
      const deadline=Date.now()+12000;while(!hold.paused&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,20));assert(hold.paused,'Must hold a genuine backend capture response');assert.equal(hold.paused.responseStatusCode,200);
      await click(leave?'[data-screen="traffic"]':'[data-element-clear]');assert(await evaluate(empty),'Pending capture retires immediately');
      const requestId=hold.paused.requestId;hold=null;
      // The user-visible abort may already have cancelled the paused network
      // request. Disable releases any surviving genuine response; never forge it.
      try {await command('Fetch.continueResponse',{requestId});} catch(error) {assert.match(String(error),/Invalid InterceptionId|Invalid interception|not found|No resource/i);}
      await command('Fetch.disable');await frame();
      // A genuine backend resize observation wakes the normal UI long poll.
      // This never evaluates the disposable page or injects application state.
      const current=await fetch(uiURL+'/api/debugger').then(r=>r.json());
      const disposable=(await command('Target.attachToTarget',{targetId:current.target.id,flatten:true},null)).sessionId;
      await command('Emulation.setDeviceMetricsOverride',{width:980+(leave?1:0),height:700,deviceScaleFactor:1,mobile:false},disposable);
      await command('Target.detachFromTarget',{sessionId:disposable},null);
      await until(`state.debuggerSession.element_document_epoch>${current.element_document_epoch}`,'Real lifecycle event did not reach UI polling');assert(await evaluate(empty),'Late real response must not attach PNG');
      if(leave){assert(await evaluate("document.querySelector('#element-screenshot-workspace').hidden && document.querySelector('#screen-experiments').hidden"),'Off-screen polling must not reactivate the screenshot workspace');await enterElementExperiments({evaluate,click,until});}
    }
    phase='dispose';await click('[data-experiment-mode="object"]');await click('#object-dispose');
    await until("state.debuggerSession?.object_experiment?.state==='disposed'",'Disposable context was not erased');assert.equal(errors.length,0,JSON.stringify(errors));passed=true;
    console.log('PASS rendered actual-product element screenshot: real PNG/geometry, explicit consent, pointer/list/key synchronization, clear/leave response retirement and 1440/600/360 layouts');
  } finally {
    if(session){try {await command('Fetch.disable');}catch{} if(!passed){try{await screenshot('failure');}catch{}}}
    await Promise.allSettled([...reads]);await writeFile(join(output,'element-screenshot-journey.json'),JSON.stringify({status:passed?'passed':'failed',phase,receipts,errors,source:'Actual product UI and backend; authored local fixture only. UI QA screenshots are not product-capture evidence.'},null,2));
    if(target){try{await command('Target.closeTarget',{targetId:target},null);}catch{}}
    for(const request of pending.values()){clearTimeout(request.timer);request.reject(Error('UI journey cleanup'));}socket.close();
  }
}
