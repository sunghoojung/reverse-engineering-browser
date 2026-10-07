import {assertFloat32Smoke} from './check-origin-trace-package.mjs';
// Feature checks extend the existing Origin Trace driver; no alternate browser runner.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {runInNewContext} from 'node:vm';
import {readFile,mkdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
export async function checkFloat32Model(root) {
  const ui=runInNewContext((await readFile(join(root,'apps/research-ui/evidence_package.js'),'utf8'))+'\n'+(await readFile(join(root,'apps/research-ui/float32_inspector.js'),'utf8'))+';({float32Bytes,float32ExpectedIdentity,isFloat32Report,createFloat32Controller,float32Unavailable})',
    {TextEncoder,TextDecoder,Uint8Array,DataView,crypto,atob,btoa,AbortController,setTimeout,clearTimeout,fetch});
  const fixture=JSON.parse(await readFile(join(root,'tools/fixtures/float32-v1.json'),'utf8')),request=fixture.request,report=fixture.result;
  const identities=await Promise.all([ui.float32ExpectedIdentity(request.input),ui.float32ExpectedIdentity(request.reference)]);
  assert(ui.isFloat32Report(report,request,identities));assert(ui.float32Unavailable('reb:'));assert.equal(ui.float32Unavailable('http:'),'');
  for(const key of Object.keys(report)){const bad=structuredClone(report);bad[key]=null;assert.equal(ui.isFloat32Report(bad,request,identities),false,key);}
  for(const side of ['input','reference'])for(const key of Object.keys(report[side])){const bad=structuredClone(report);bad[side][key]='different';assert.equal(ui.isFloat32Report(bad,request,identities),false,side+'.'+key);}
  for(const [path,value] of [[['detail','start'],1],[['detail','rows',0,'byte_offset'],4],[['detail','rows',0,'input','bits'],'<svg onload=alert(1)>'],[['detail','rows',3,'input','value'],null],[['detail','rows',4,'input','value'],5],[['comparison','all_bits_equal'],true],[['comparison','finite_pairs'],5],[['comparison','status'],'equal'],[['comparison','maximum_relative_delta'],Infinity]]) {
    const bad=structuredClone(report);let at=bad;for(const key of path.slice(0,-1))at=at[key];at[path.at(-1)]=value;
    // Infinity sample already has null. The finite-row mutation below covers null rejection.
    if(path.join('.')==='detail.rows.3.input.value')at[path.at(-1)]=42;
    assert.equal(ui.isFloat32Report(bad,request,identities),false,path.join('.'));
  }
  const bytes=ui.float32Bytes(request.input);assert.equal(bytes.length,20);assert.equal(new DataView(bytes.buffer).getUint32(4,true),0x80000000);
  assert.throws(()=>ui.float32Bytes({...request.input,frames:3}),/layout/);
  assert.throws(()=>ui.float32Bytes({...request.input,source:{kind:'bits',words:['nan']}}),/eight/);
  assert.throws(()=>ui.float32Bytes({...request.input,source:{kind:'bytes',base64:'AA'}}),/canonical/);
  const response=()=>new Response(JSON.stringify(report),{headers:{'Content-Type':'application/json'}});
  const controller=ui.createFloat32Controller({fetcher:async()=>response()});await controller.run(request);assert.equal(controller.snapshot().status,'ready');assert.equal(controller.snapshot().stale,false);
  controller.invalidate();assert.equal(controller.snapshot().stale,true);assert(controller.snapshot().report);
  const queue=[];const asyncController=ui.createFloat32Controller({fetcher:()=>new Promise(resolve=>queue.push(resolve))});
  const until=async check=>{const start=Date.now();while(!check()){assert(Date.now()-start<2000);await delay(2);}};
  const old=asyncController.run(request);await until(()=>queue.length===1);const newer=asyncController.run(request);await until(()=>queue.length===2);queue[1](response());await newer;const current=asyncController.snapshot();queue[0](response());await old;await delay(2);assert.equal(asyncController.snapshot().report,current.report);assert.equal(asyncController.snapshot().revision,current.revision);
  const held=asyncController.run(request);await until(()=>queue.length===3);asyncController.cancel();await held;assert.equal(asyncController.snapshot().status,'cancelled');assert.equal(asyncController.snapshot().stale,true);queue[2](response());await delay(2);assert.equal(asyncController.snapshot().status,'cancelled');
  asyncController.clear();assert.equal(asyncController.snapshot().report,null);
  const timeout=ui.createFloat32Controller({timeoutMs:15,fetcher:()=>new Promise(()=>{})});await timeout.run(request);assert.match(timeout.snapshot().message,/deadline/);assert.equal(timeout.snapshot().pending,false);
  for(const fetcher of [async()=>new Response('failure',{status:503}),async()=>new Response('{broken'),async()=>new Response(new Uint8Array(524289)),async()=>new Response(JSON.stringify({...report,profile:'other'}))]) {
    let fail=false;const c=ui.createFloat32Controller({fetcher:()=>fail?fetcher():response()});await c.run(request);const retained=c.snapshot().report;fail=true;await c.run(request);assert.equal(c.snapshot().status,'error');assert.equal(c.snapshot().report,retained);assert.equal(c.snapshot().stale,true);
  }
  await checkFloat32HostLifecycle(root,fixture);
  await checkFloat32NativeBridge(root);
  console.log('PASS Float32 exact identity, closed report shapes, finite/nonfinite display, stale/latest/cancel/deadline and bounded transport models (not rendered QA)');
}

export async function float32BrowserFixture(root,directory) {
  const store=join(directory,'float32-store');await mkdir(store);
  const backend=join(resolve(process.env.CARGO_TARGET_DIR||join(root,'apps/origin-trace-backend/target')),'debug/origin-trace-backend');
  const endpoint=join(store,'endpoint'),args=['--port','0','--endpoint-file',endpoint];
  for(const [flag,file] of [['store','events'],['trace-store','trace'],['signal-store','signals'],['artifacts','artifacts'],['api-collection','collection'],['local-analyst','analyst']])args.push('--'+flag,join(store,file));
  const fixture={mode:'normal',requests:[],reports:[],pending:[],diagnostics:{backend,args,output:''}};
  const child=spawn(backend,args,{cwd:root,stdio:['ignore','pipe','pipe']});let closed=false,startError;
  const exited=new Promise(resolve=>child.once('close',(code,signal)=>{closed=true;fixture.diagnostics.exit={code,signal};resolve();}));child.on('error',error=>{startError=error;});
  for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{fixture.diagnostics.output=(fixture.diagnostics.output+chunk.toString()).slice(-16384);});
  fixture.release=()=>{for(const send of fixture.pending.splice(0))send();};
  fixture.stop=async()=>{const cleanup=fixture.diagnostics.cleanup={exited:closed};fixture.release();try{if(!closed){child.kill('SIGTERM');await Promise.race([exited,delay(2000)]);}if(!closed){child.kill('SIGKILL');await Promise.race([exited,delay(2000)]);}assert(closed,'Owned Float32 backend did not stop');}finally{cleanup.exited=closed;}};
  // Publish ownership before readiness: outer cleanup retains live-process storage.
  fixture.ready=async()=>{
    let url;const start=Date.now();
    while(Date.now()-start<10000){if(startError)throw startError;assert(!closed,'Float32 backend exited before readiness');try{url=(await readFile(endpoint,'utf8')).trim();}catch(error){if(error.code!=='ENOENT')throw error;}if(url)break;await delay(25);}
    assert(url&&/^http:\/\/127\.0\.0\.1:\d+$/.test(url),'Float32 backend endpoint unavailable');
    fixture.url=url;
    fixture.handle=async(request,response)=>{
      if(new URL(request.url,'http://127.0.0.1').pathname!=='/api/float32/compare')return false;
      try{
        const chunks=[];let count=0;for await(const chunk of request){count+=chunk.length;assert(count<=2097152,'Float32 fixture input exceeded bound');chunks.push(Buffer.from(chunk));}
        const body=Buffer.concat(chunks),payload=JSON.parse(body),mode=fixture.mode;fixture.requests.push(payload);
        const result=await fetch(url+'/api/float32/compare',{method:'POST',headers:{'Content-Type':'application/json'},body,signal:AbortSignal.timeout(15000)});
        const bytes=new Uint8Array(await result.arrayBuffer());assert(bytes.length<=524288,'Float32 fixture output exceeded bound');
        if(result.ok)fixture.reports.push(JSON.parse(new TextDecoder().decode(bytes)));
        const send=()=>{if(response.destroyed)return;if(mode==='failure'){response.writeHead(503,{'Content-Type':'application/json'});response.end('{"error":"Synthetic transport failure"}');}else{response.writeHead(result.status,{'Content-Type':'application/json'});response.end(bytes);}};
        if(mode==='pending')fixture.pending.push(send);else send();
      }catch(error){fixture.diagnostics.request_error=String(error.message).slice(0,2048);if(!response.destroyed){response.writeHead(500,{'Content-Type':'application/json'});response.end('{"error":"Float32 QA fixture failed"}');}}return true;
    };
  };
  return fixture;
}
export async function checkFloat32Fixture(fixture,root) {
  const {request,result}=JSON.parse(await readFile(join(root,'tools/fixtures/float32-v1.json'),'utf8'));
  const response=await fetch(fixture.url+'/api/float32/compare',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request),signal:AbortSignal.timeout(5000)});
  assert.equal(response.status,200);assert.deepEqual(JSON.parse(JSON.stringify(await response.json())),JSON.parse(JSON.stringify(result)));
  await checkFloat32NativeBridge(root,fixture.url);
  console.log('PASS Float32 original fixture through the actual loopback backend (not rendered QA)');
}
export async function checkFloat32Interactions({evaluate,viewport,click,key,command,wheel,screenshot,fixture}) {
  const until=async(check,message)=>{const start=Date.now();while(!await(typeof check==='function'?check():evaluate(check))){assert(Date.now()-start<8000,message);await delay(25);}};
  const press=async(value,modifiers=0)=>{const codes={Enter:13,Home:36,End:35,ArrowDown:40,ArrowUp:38,ArrowRight:39,Tab:9,a:65};await key(value,value==='a'?'KeyA':value,{windowsVirtualKeyCode:codes[value],modifiers,...(value==='Enter'?{text:'\r',unmodifiedText:'\r'}:{})});};
  const reveal=async selector=>{
    for(let n=0;n<18;n++){
      const movement=await evaluate(`(()=>{const node=document.querySelector(${JSON.stringify(selector)}),r=node.getBoundingClientRect();for(let p=node.parentElement;p;p=p.parentElement){const s=getComputedStyle(p),b=p.getBoundingClientRect();if(!['auto','scroll'].includes(s.overflowY)||p.scrollHeight<=p.clientHeight+1)continue;const top=Math.max(0,b.top)+8,bottom=Math.min(innerHeight,b.bottom)-8;if(r.top<top||r.bottom>bottom)return {x:Math.max(1,Math.min(innerWidth-2,b.left+b.width/2)),y:Math.max(top,Math.min(bottom,(top+bottom)/2)),deltaY:r.top<top?r.top-top:r.bottom-bottom};}return null;})()`);
      if(!movement)return;await command('Input.dispatchMouseEvent',{type:'mouseWheel',deltaX:0,...movement});await delay(100);
    }assert.fail('Float32 control could not be reached through its owning scroll pane: '+selector);
  };
  const use=async selector=>{await reveal(selector);await click(selector);};
  const type=async(selector,text)=>{await use(selector);await press('a',process.platform==='darwin'?4:2);await command('Input.insertText',{text});await until(`document.querySelector(${JSON.stringify(selector)}).value===${JSON.stringify(text)}`,'Typed input did not stick');};
  const snapshot=()=>evaluate('float32Panel.controller.snapshot()');
  const compare=async()=>{const previous=fixture.requests.length;await use('#float32-run');await until(async()=>fixture.requests.length===previous+1&&!(await snapshot()).pending,'New Float32 operation did not finish');const s=await snapshot();assert.equal(s.status,'ready');assert.equal(s.stale,false);assert.deepEqual(JSON.parse(JSON.stringify(s.report)),JSON.parse(JSON.stringify(fixture.reports.at(-1))),'Visible result must match this actual backend operation; signed-zero identity is carried in raw bits and sign_bit');return s;};
  if (!await evaluate("document.querySelector('#advanced-navigation').open")) await use('#advanced-navigation > summary');
  await use('[data-screen="tools"]');await use('#tools-tab-float32');
  assert.equal(fixture.requests.length,0,'Opening inspector must not run analysis');
  await use('#float32-example');assert.equal(fixture.requests.length,0,'Loading synthetic input must not run analysis');
  const first=await compare();assert.equal(first.report.comparison.maximum_ulp_distance,1);assert.equal(first.report.input_summary.nan,1);assert.equal(first.report.input_summary.negative_zero,1);assert.equal(first.report.comparison.all_numeric_equal,false);
  await use('.float32-identity summary');assert.match(await evaluate("document.querySelector('#float32-result').textContent"),/SHA-256/);await screenshot('float32-wide-bits');
  await evaluate("window.float32RetainedDetails=document.querySelector('.float32-identity');window.float32RetainedRows=document.querySelector('.float32-rows');float32Panel.refresh()");
  assert(await evaluate("document.querySelector('.float32-identity')===float32RetainedDetails && float32RetainedDetails.open && document.querySelector('.float32-rows')===float32RetainedRows"),'Routine refresh replaced immutable report nodes/disclosures');
  const originalWords=await evaluate(`document.querySelector('[data-float32-input="input"]').value`);
  await type('[data-float32-input="input"]','not-hex');await use('#float32-run');await until("float32Panel.controller.snapshot().status==='error'",'Preflight failure did not enter controller state');
  const preflightMessage=(await snapshot()).message;assert.match(preflightMessage,/eight lowercase/);await use('#tools-tab-jwt');await use('#tools-tab-float32');assert.equal(await evaluate("document.querySelector('#float32-status').textContent"),preflightMessage,'Refresh erased the local preflight error');
  await type('[data-float32-input="input"]',originalWords);await compare();
  await type('#float32-ulps','1');assert.equal((await snapshot()).stale,true);const tolerant=await compare();assert.equal(tolerant.report.comparison.within_tolerance_pairs,3);assert.equal(tolerant.report.comparison.all_within_tolerance,null);
  fixture.mode='failure';await use('#float32-run');await until("float32Panel.controller.snapshot().status==='error'",'HTTP failure not visible');assert.equal((await snapshot()).report.input.sha256,tolerant.report.input.sha256);assert.equal((await snapshot()).stale,true);
  fixture.mode='pending';await use('#float32-run');await until(()=>fixture.pending.length===1,'Pending response not held');await use('#float32-cancel');assert.equal((await snapshot()).pending,false);fixture.release();await delay(100);assert.equal((await snapshot()).status,'cancelled');
  fixture.mode='pending';await use('#float32-run');await until(()=>fixture.pending.length===1,'Second pending response not held');await type('#float32-ulps','0');assert.equal((await snapshot()).pending,false);fixture.mode='normal';const newest=await compare();fixture.release();await delay(100);assert.equal((await snapshot()).revision,newest.revision);assert.deepEqual((await snapshot()).report,newest.report);
  fixture.mode='pending';await use('#float32-run');await until(()=>fixture.pending.length===1,'Navigation response not held');
  await use('#tools-tab-jwt');assert.equal((await snapshot()).pending,false);fixture.release();await delay(100);assert.equal((await snapshot()).status,'cancelled');
  await use('#tools-tab-float32');fixture.mode='normal';await compare();
  // Supply enough original raw words for real paged backend results.
  await type('[data-float32-input="input"]',Array(130).fill('3f800000').join(' '));await type('[data-float32-frames="input"]','130');
  await use('[data-float32-frames="reference"]');await press('a',process.platform==='darwin'?4:2);await key('Backspace','Backspace',{windowsVirtualKeyCode:8});
  assert.equal(await evaluate(`document.querySelector('[data-float32-frames="reference"]').value`),'');
  await use('#float32-reference-enabled');assert(await evaluate("document.querySelector('#float32-reference-fields').disabled"),'Inactive reference fields must not prevent native form submission');await compare();
  await use('#float32-next');await until("float32Panel.controller.snapshot().status==='ready' && float32Panel.controller.snapshot().report.detail.start===64",'Next sample window failed');assert.equal((await snapshot()).report.detail.rows[0].byte_offset,256);
  await use('#float32-previous');await until("float32Panel.controller.snapshot().status==='ready' && float32Panel.controller.snapshot().report.detail.start===0",'Previous window failed');
  // Keyboard tab selection uses the shared tablist behavior.
  await use('#tools-tab-jwt');await press('ArrowRight');await until("state.toolsTab==='float32'",'Keyboard Float32 tab selection failed');
  for(const [width,height] of [[600,800],[360,740]]){await viewport(width,height);await use('#float32-run');await until("!float32Panel.controller.snapshot().pending",'Narrow compare remained pending');assert.equal((await snapshot()).status,'ready');await reveal('.float32-receipt');assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),'Float32 causes horizontal page overflow');await screenshot(`float32-${width}-report`);await use('#float32-next');await until("float32Panel.controller.snapshot().report.detail.start===64 && !float32Panel.controller.snapshot().pending",'Narrow paging failed');}
  await use('#float32-clear');assert.equal((await snapshot()).report,null);await screenshot('float32-cleared');
  void wheel;
  return {status:'passed',path:'browser development UI with actual Rust backend',source:'original synthetic buffers; only held responses/503 are synthetic',viewports:[[1440,900],[600,800],[360,740]],checks:['explicit input and reference','actual backend result identity','exceptional values and signed zero','visible tolerances','stale/retry retention','cancel and late responses','newer result wins','sample pagination','keyboard tabs','narrow scrolling and pointer controls','clear']};
}

async function checkFloat32HostLifecycle(root, fixture) {
  // Narrow DOM adapter, executing the real mounted panel and host refresh path.
  // No pixel, native-form-validation or browser-interaction claim is made here.
  class Node {
    constructor(value='') { this._value=value;this.checked=false;this.disabled=false;this.hidden=false;this.dataset={};this.listeners={};this.children=[];this.textContent='';this.parent={hidden:false};this.className='';this.id='';this.optionValues=false; }
    get value(){return this._value;}
    set value(value){this._value=this.optionValues&&!this.children.some(node=>node.value===value)?'':value;}
    append(...nodes){this.children.push(...nodes);}
    replaceChildren(...nodes){this.children=nodes;if(this.optionValues)this.value=this._value;}
    add(node){this.children.push(node);}
    querySelector(selector){for(const node of this.children){if(selector.startsWith('.')&&node.className.split(' ').includes(selector.slice(1))||selector.startsWith('#')&&node.id===selector.slice(1))return node;const child=node.querySelector?.(selector);if(child)return child;}return null;}
    closest(){return this.parent;}
    setAttribute(){}
    addEventListener(name,callback){this.listeners[name]=callback;}
  }
  const nodes=new Map(),n=(selector,value='')=>{const node=new Node(value);nodes.set(selector,node);return node;};
  for(const selector of ['#float32-status','#float32-run','#float32-cancel','#float32-clear','#float32-example','#float32-reference-fields','#float32-reference-enabled','#float32-result','form'])n(selector);
  for(const selector of ['#float32-absolute','#float32-relative','#float32-ulps'])n(selector,'0');
  for(const side of ['input','reference'])for(const [field,value] of [['kind','bits'],['endian','float32-le'],['channels','1'],['frames','0'],['input',''],['artifact','']])n(`[data-float32-${field}="${side}"]`,value);
  const container=new Node();container.querySelector=selector=>nodes.get(selector)||nodes.get('#float32-result').querySelector(selector);
  const field=(side,name)=>nodes.get(`[data-float32-${name}="${side}"]`);
  for(const side of ['input','reference'])field(side,'artifact').optionValues=true;
  const screen=new Node(),state={toolsTab:'float32',artifacts:[],artifactEtag:null,artifactRefreshing:false,sessionMode:'live',openArtifactIds:[],selectedArtifactId:null};
  let catalog=[],catalogStatus=200,catalogValid=true,analysisCalls=0,hold=false;
  const held=[];
  const responseFor=request=>{
    const result=structuredClone(fixture.result);
    for(const side of ['input','reference'])if(request[side]?.source.kind==='artifact')Object.assign(result[side],{origin:'verified_artifact',session_id:request[side].source.session_id,artifact_id:request[side].source.artifact_id});
    if(!request.reference){result.reference=null;result.reference_summary=null;result.comparison=null;for(const row of result.detail.rows){row.reference=null;row.difference=null;}}
    return new Response(JSON.stringify(result));
  };
  const document={activeElement:null,createElement:()=>new Node(),querySelector:selector=>selector==='#tools-panel-float32'?container:selector==='#screen-tools'?screen:{hidden:true}};
  const env={TextEncoder,TextDecoder,Uint8Array,DataView,crypto,atob,btoa,AbortController,setTimeout,clearTimeout,location:{protocol:'http:'},document,
    Option:function(text,value){const option=new Node(value);option.textContent=text;return option;},state,isArtifactResponse:body=>body.valid!==false,
    renderShellStatus(){},renderSourceHealth(){},renderSources(){},loadArtifactContent(){},nativeCanvasCaptureDisplayLimit:20,evidencePackagePanel:{sync(){}},renderFingerprintActivity(){},
    fetch:async(url,options)=>{
      if(url.startsWith('/api/artifacts'))return {status:catalogStatus,ok:catalogStatus===200,headers:new Headers(),json:async()=>({artifacts:catalog,valid:catalogValid})};
      assert.equal(url,'/api/float32/compare');analysisCalls++;const request=JSON.parse(options.body);
      if(hold)return new Promise(resolve=>held.push(()=>resolve(responseFor(request))));return responseFor(request);
    }};
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const section=(start,end)=>{const first=app.indexOf(start),last=app.indexOf(end,first);assert(first>=0&&last>first);return app.slice(first,last);};
  const api=runInNewContext((await readFile(join(root,'apps/research-ui/source_facts.js'),'utf8'))+'\n'+(await readFile(join(root,'apps/research-ui/evidence_package.js'),'utf8'))+'\n'+(await readFile(join(root,'apps/research-ui/float32_inspector.js'),'utf8'))+'\n'+
    section('      function liveScriptIdentity(','      function liveSources(')+section('      const float32Panel =','      function renderTools()')+section('      async function refreshArtifacts()','      function showScreen(')+';({panel:float32Panel,refreshArtifacts,syncFloat32Panel})',env);
  const panel=api.panel,snapshot=panel.controller.snapshot,select=field('input','artifact');
  let refreshCalls=0;const refresh=panel.refresh;panel.refresh=()=>{refreshCalls++;refresh();};
  const update=async(artifacts,status=200,valid=true)=>{catalog=artifacts;catalogStatus=status;catalogValid=valid;await api.refreshArtifacts();};
  const until=async(check,message)=>{const start=Date.now();while(!check()){assert(Date.now()-start<2000,message);await delay(2);}};
  const edit=(side,name,value)=>{field(side,name).value=value;container.listeners.input({target:{matches:()=>true}});};
  const submit=async()=>{nodes.get('form').listeners.submit({preventDefault(){}});await until(()=>!snapshot().pending,'Panel submission did not settle');};
  const key=artifact=>JSON.stringify([artifact.session_id,artifact.artifact_id,artifact.sha256,artifact.byte_size]);
  const artifact={session_id:'11',artifact_id:'7',sha256:fixture.result.input.sha256,byte_size:20,kind:'response_body'};
  const second={...artifact,artifact_id:'8'};
  api.syncFloat32Panel();assert.equal(select.children.length,1);
  await update([artifact]);assert.equal(state.artifacts.length,1);assert.equal(select.children.length,2,'Ordinary host refresh must expose newly retained artifacts');assert.equal(analysisCalls,0);
  for(const side of ['input','reference']){field(side,'frames').value='5';field(side,'input').value=fixture.request[side].source.words.join(' ');}
  nodes.get('#float32-reference-enabled').checked=true;panel.controller.invalidate();await submit();assert.equal(snapshot().status,'ready');
  const priorReport=snapshot().report,details=nodes.get('#float32-result').querySelector('.float32-identity'),rows=nodes.get('#float32-result').querySelector('.float32-rows');details.open=true;rows.scrollTop=19;document.activeElement=select;
  edit('input','kind','artifact');edit('input','artifact',key(artifact));hold=true;nodes.get('form').listeners.submit({preventDefault(){}});await until(()=>held.length===1,'Artifact comparison not held');
  const pendingRevision=snapshot().revision;await update([artifact,second]);assert.equal(select.children.length,3);assert.equal(select.value,key(artifact));assert.equal(snapshot().revision,pendingRevision);assert(snapshot().pending,'An unrelated arrival cancelled exact unchanged input');
  for(const [status,valid] of [[200,true],[304,true],[503,true],[200,false]]){const children=select.children;await update(catalog,status,valid);assert.equal(select.children,children);assert.equal(snapshot().revision,pendingRevision);assert(snapshot().pending);}
  assert.equal(nodes.get('#float32-result').querySelector('.float32-identity'),details);assert(details.open);assert.equal(rows.scrollTop,19);assert.equal(document.activeElement,select);
  const changed={...artifact,sha256:'0'.repeat(64)};await update([changed,second]);assert.equal(select.value,'');assert.equal(snapshot().pending,false);assert.equal(snapshot().stale,true);assert.equal(snapshot().report,priorReport);
  held.shift()();await delay(4);assert.equal(snapshot().report,priorReport,'Changed artifact accepted a late result');
  // Reset to a valid selection, then verify an observed-empty catalog retires it.
  await update([artifact]);edit('input','artifact',key(artifact));nodes.get('form').listeners.submit({preventDefault(){}});await until(()=>held.length===1,'Second artifact comparison not held');await update([]);assert.equal(select.children.length,1);assert.equal(select.value,'');assert.equal(snapshot().pending,false);held.shift()();await delay(4);assert.equal(snapshot().report,priorReport);
  // An inactive remembered artifact must not cancel a newer raw-word draft/run.
  await update([artifact]);edit('input','artifact',key(artifact));edit('input','kind','bits');const draft=field('input','input').value;nodes.get('form').listeners.submit({preventDefault(){}});await until(()=>held.length===1,'Raw comparison not held');const draftRevision=snapshot().revision;
  await update([changed]);assert.equal(snapshot().revision,draftRevision);assert(snapshot().pending);assert.equal(field('input','input').value,draft);held.shift()();await until(()=>!snapshot().pending,'Raw comparison did not finish');assert.equal(snapshot().status,'ready');
  await update([artifact]);edit('reference','kind','artifact');edit('reference','artifact',key(artifact));nodes.get('#float32-reference-enabled').checked=false;panel.controller.invalidate();
  nodes.get('form').listeners.submit({preventDefault(){}});await until(()=>held.length===1,'Single-input comparison not held');const inactiveReferenceRevision=snapshot().revision;
  await update([]);assert.equal(snapshot().revision,inactiveReferenceRevision);assert(snapshot().pending,'An inactive reference cancelled a single-input run');held.shift()();await until(()=>!snapshot().pending,'Single-input comparison did not finish');assert.equal(snapshot().status,'ready');
  edit('reference','kind','bits');nodes.get('#float32-reference-enabled').checked=true;panel.controller.invalidate();
  // Neither another workspace nor another Tools tab should scan/rebuild this panel.
  const visibleRefreshes=refreshCalls;screen.hidden=true;await update([artifact]);assert.equal(refreshCalls,visibleRefreshes);screen.hidden=false;state.toolsTab='jwt';await update([second]);assert.equal(refreshCalls,visibleRefreshes);state.toolsTab='float32';api.syncFloat32Panel();assert.equal(refreshCalls,visibleRefreshes+1);assert.equal(select.children[1].value,key(second));
  hold=false;const retained=snapshot().report;
  for(const [name,value,pattern] of [['frames','1',/Byte length must match/],['input','not-hex',/eight lowercase/]]) {
    edit('input','frames','5');edit('input','input',draft);edit('input',name,value);const before=analysisCalls;await submit();assert.equal(analysisCalls,before);assert.equal(snapshot().status,'error');assert.match(snapshot().message,pattern);assert.equal(snapshot().report,retained);assert(snapshot().stale);
    const message=snapshot().message;for(const [status,valid] of [[200,true],[304,true],[503,true],[200,false]]){await update(catalog,status,valid);assert.equal(snapshot().message,message);assert.equal(nodes.get('#float32-status').textContent,message);}
    for(const changedCatalog of [[],[second]]){await update(changedCatalog);assert.equal(snapshot().message,message);assert.equal(nodes.get('#float32-status').textContent,message);}
    panel.refresh();assert.equal(snapshot().status,'error');assert.equal(nodes.get('#float32-status').textContent,message);
  }
  edit('input','frames','5');edit('input','input',draft);await submit();assert.equal(snapshot().status,'ready');assert.equal(snapshot().stale,false);
  // Preflight failure owns cancellation even if a caller changes DOM without an input event.
  hold=true;nodes.get('form').listeners.submit({preventDefault(){}});await until(()=>held.length===1,'Preflight cancellation comparison not held');field('input','frames').value='1';await submit();assert.equal(snapshot().status,'error');assert.match(snapshot().message,/Byte length must match/);const failed=snapshot();held.shift()();await delay(4);assert.equal(snapshot().revision,failed.revision);assert.equal(snapshot().status,'error');assert.equal(snapshot().report,failed.report);
  edit('input','kind','artifact');select.value='';await submit();assert.match(snapshot().message,/Choose one retained artifact/);panel.refresh();assert.equal(nodes.get('#float32-status').textContent,snapshot().message);
  assert(nodes.get('#float32-reference-fields').disabled===false);assert.equal(held.length,0);
  console.log('PASS Float32 mounted host new/changed/empty/unchanged/error catalogs, active-only cancellation, late ownership, hidden-panel gating, stable report DOM/drafts and persistent preflight/recovery (not rendered QA)');
}

// Exercise the exact JS embedded in the existing native smoke path. The model
// verifies mode/receipt ownership; with a URL the real controller and Rust API
// execute the fixed request. Neither result claims WebKit/native acceptance.
async function checkFloat32NativeBridge(root, backendURL=null) {
  const native=await readFile(join(root,'apps/research-ui/macos/OriginTraceApp.swift'),'utf8');
  const start=native.indexOf("          if (typeof mountFloat32Inspector !== 'function'"),end=native.indexOf('          const artifacts =',start);
  assert(start>=0&&end>start,'Native Float32 smoke block missing');const block=native.slice(start,end);
  const request={protocol_version:1,input:{representation:'float32-le',channels:1,frames:1,source:{kind:'bits',words:['80000000']}},reference:{representation:'float32-le',channels:1,frames:1,source:{kind:'bits',words:['00000000']}},tolerances:{absolute:0,relative:0,ulps:0},detail:{start:0,limit:1}};
  const hash=async bytes=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(bytes))),n=>n.toString(16).padStart(2,'0')).join('');
  const report={profile:'binary32-finite-steps-v1',input:{sha256:await hash([0,0,0,128])},reference:{sha256:await hash([0,0,0,0])},
    detail:{rows:[{input:{bits:'80000000',sign_bit:1,class:'zero'},reference:{bits:'00000000',sign_bit:0,class:'zero'},difference:{absolute_delta:0,relative_delta:0,ulp_distance:0}}]},
    comparison:{raw_bytes_equal:false,all_bits_equal:false,all_numeric_equal:true,all_within_tolerance:true,finite_pairs:1,excluded_nonfinite_pairs:0,rms_delta:0}};
  const prefix=(await readFile(join(root,'apps/research-ui/evidence_package.js'),'utf8'))+'\n'+(await readFile(join(root,'apps/research-ui/float32_inspector.js'),'utf8'));
  for(const mode of ['offline','demo','fallback','live']) {
    const live=mode==='live';let calls=0;
    const env={TextEncoder,TextDecoder,Uint8Array,DataView,crypto,atob,btoa,AbortController,setTimeout,clearTimeout,window:{},location:{protocol:live?'http:':'reb:'},document:{querySelector:()=>({disabled:!live})},
      fetch:async(path,options)=>{calls++;assert.equal(path,'/api/float32/compare');assert.deepEqual(JSON.parse(options.body),request);return fetch(backendURL+path,options);},
      fakeController:{run:async supplied=>{calls++;assert.deepEqual(JSON.parse(JSON.stringify(supplied)),request);},snapshot:()=>({pending:false,status:'ready',stale:false,report})}};
    const controller=backendURL?'createFloat32Controller()':'fakeController';
    const receipt=await runInNewContext(prefix+';const float32Panel={controller:'+controller+'};(async()=>{'+block+';return window.__rebSmokeFloat32;})()',env);
    const serialized=JSON.parse(JSON.stringify(receipt));assertFloat32Smoke(mode,serialized);assert.equal(calls,live?1:0);
    for(const bad of [{...serialized,module_ready:false},{...serialized,mode:live?'stored_native':'live_http'},{...serialized,run_disabled:live},{...serialized,output:live?{...serialized.output,input_bits:'00000000'}:{}}])assert.throws(()=>assertFloat32Smoke(mode,bad));
  }
  if(!backendURL) {
    for(const state of [{pending:true,status:'ready',stale:false,report},{pending:false,status:'error',stale:false,report},{pending:false,status:'ready',stale:true,report}]) {
      const env={TextEncoder,TextDecoder,Uint8Array,DataView,crypto,atob,btoa,AbortController,setTimeout,clearTimeout,fetch,window:{},location:{protocol:'http:'},document:{querySelector:()=>({disabled:false})},fakeController:{run:async()=>{},snapshot:()=>state}};
      await assert.rejects(runInNewContext(prefix+';const float32Panel={controller:fakeController};(async()=>{'+block+'})()',env),/did not complete/);
    }
  }
  console.log(backendURL?'PASS native-smoke JS projection through real controller/Rust API, exact signed-zero output; stored modes remain disabled (not WebKit)':'PASS native-smoke JS/receipt mode, module, completion, stale and wrong-output controls (not native runtime)');
}
