import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {deflateSync, inflateSync} from 'node:zlib';
import {runInNewContext} from 'node:vm';

// Authored HTTP evidence only. The production catalog, byte/hash reader,
// ownership, PNG admission, renderer and browser decoder remain in use.
export async function canvasBrowserFixture(root, {artifact, png, pngUrl, chunk}) {
  const pixels=Buffer.concat(Array.from({length:16},()=>Buffer.from([0,...Array.from({length:16},()=>[255,0,0,255]).flat()])));
  const valid=pngUrl(png({width:16,height:16,idat:[chunk('IDAT',deflateSync(pixels))]}));
  // A truncated zlib stream can load as a partial image in Chrome. Use a
  // complete one-row stream with an invalid PNG filter type instead: method 0
  // permits only 0..4 (https://www.w3.org/TR/png-3/ section 9.2). The browser
  // must produce the error event; production admission still checks structure.
  const invalidScanline=deflateSync(Buffer.from([255,255,0,0,255]));
  const documents=new Map([
    ['5',valid],
    ['4',pngUrl(png({width:100000,height:100000}))],
    ['3',valid.replace('image/png','image/webp')],
    ['2',pngUrl(png({idat:[chunk('IDAT',invalidScanline)]}))],
    ['1',valid],
  ]);
  const artifacts=await Promise.all([...documents].map(([id,text])=>artifact(id,text)));
  const events=artifacts.map(source=>({protocol_version:1,category:'canvas',type:'api_call',
    session_id:1,sequence_number:Number(source.creator_event_id),monotonic_time_ns:Number(source.creator_event_id),
    navigation_id:1,frame_id:1,artifact_id:Number(source.artifact_id),parent_event_id:0,process_id:1,thread_id:1,
    payload_encoding:'hex',payload:Buffer.from('canvas.toDataURL').toString('hex'),payload_size:16}));
  const debuggerState=JSON.parse(await readFile(join(root,'apps/origin-trace-backend/assets/debugger-empty.json'),'utf8'));
  const fixture={documents,artifacts,events,requests:[],pending:[],readError:true,hold:false,catalogError:false,revision:1,active:true};
  fixture.handle=async(request,response)=>{
    const url=new URL(request.url,'http://127.0.0.1'),path=url.pathname;
    const json=(status,value,headers={})=>{response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store',...headers});response.end(JSON.stringify(value));};
    if(!path.startsWith('/api/'))return false;
    if(request.method&&request.method!=='GET'){fixture.requests.push({path,method:request.method,status:405});json(405,{error:'Canvas QA never mutates a native capture'});return true;}
    if(path==='/api/debugger'){json(200,debuggerState);return true;}
    if(path==='/api/events'||path==='/api/artifacts'){
      const etag=`"canvas-${path}-${fixture.revision}"`;
      if(path==='/api/artifacts'&&fixture.catalogError){json(503,{error:'Authored catalog failure'});return true;}
      if(request.headers?.['if-none-match']===etag){response.writeHead(304);response.end();return true;}
      json(200,path==='/api/events'?{count:fixture.active?events.length:0,events:fixture.active?events:[],capture_mode:'live',broker_connected:true,capture_controls_available:false}
        :{count:fixture.active?artifacts.length:0,artifacts:fixture.active?artifacts:[],artifact_receiver_configured:true,artifact_receiver_connected:true},{ETag:etag});return true;
    }
    if(/^\/api\/artifacts\/[0-9]+\/content$/.test(path)){
      const id=path.split('/')[3],text=documents.get(id);
      if(!text){json(404,{error:'Unknown authored Canvas artifact'});return true;}
      const receipt={id,path,method:request.method??'GET',limit:url.searchParams.get('limit'),status:id==='1'&&fixture.readError?503:200,held:fixture.hold};fixture.requests.push(receipt);
      if(receipt.status===503){json(503,{error:'Authored retryable Canvas read failure'});return true;}
      const bytes=Buffer.from(text);
      response.writeHead(200,{'Content-Type':'application/octet-stream','X-Artifact-Total-Bytes':String(bytes.length),'X-Artifact-Truncated':'false'});
      if(fixture.hold){response.flushHeaders?.();await new Promise(resolve=>fixture.pending.push(resolve));}
      receipt.aborted=Boolean(response.destroyed);
      if(!response.destroyed)response.end(bytes);
      return true;
    }
    return false;
  };
  fixture.release=()=>{for(const resolve of fixture.pending.splice(0))resolve();};
  // Fail-closed test tripwire at the native DOM sink: refused giant/unsupported
  // fixtures must NEVER reach a decoder, even if production admission regresses.
  // Safe sources pass straight through to Chrome. No product function is patched.
  fixture.installObserver=`(() => {
    const known=new Map(${JSON.stringify([[documents.get('5'),'valid'],[documents.get('4'),'oversized'],[documents.get('3'),'unsupported'],[documents.get('2'),'decode-error']])});
    const safe=new Set(${JSON.stringify([documents.get('5'),documents.get('2')])});
    const receipt=window.canvasBrowserReceipt={assignments:[],blocked:[],loads:[],errors:[]};
    const observe=(image,value) => {
      const id=known.get(String(value));
      receipt.assignments.push({id:id??'unknown',safe:safe.has(String(value))});
      if(!safe.has(String(value))){receipt.blocked.push(id??'unknown');throw new Error('Unsafe Canvas QA source reached the native image sink');}
      image.addEventListener('load',()=>receipt.loads.push({id,width:image.naturalWidth,height:image.naturalHeight}),{once:true});
      image.addEventListener('error',()=>receipt.errors.push({id}),{once:true});
    };
    const source=Object.getOwnPropertyDescriptor(HTMLImageElement.prototype,'src');
    Object.defineProperty(HTMLImageElement.prototype,'src',{...source,set(value){observe(this,value);source.set.call(this,value);}});
    const attribute=Element.prototype.setAttribute;
    Element.prototype.setAttribute=function(name,value){if(this instanceof HTMLImageElement&&String(name).toLowerCase()==='src')observe(this,value);return attribute.call(this,name,value);};
  })()`;
  return fixture;
}

export async function checkCanvasFixture(fixture, models, inspect) {
  const response=async(url,options={})=>{
    const reply={destroyed:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(body){this.body=body;}};
    assert(await fixture.handle({url,...options},reply));return reply;
  };
  for(const [path,validator] of [['events',models.isBrokerResponse],['artifacts',models.isArtifactResponse]]){
    const reply=await response(`/api/${path}`);assert.equal(reply.status,200);assert(validator(JSON.parse(reply.body)));
    assert.equal((await response(`/api/${path}`,{headers:{'if-none-match':reply.headers.ETag}})).status,304);
  }
  assert(models.isDebuggerResponse(JSON.parse((await response('/api/debugger')).body)));
  assert.deepEqual({...inspect(fixture.documents.get('5'))},{width:16,height:16,pixels:256});
  assert.match(inspect(fixture.documents.get('4')).reason,/4096-pixel/);
  assert.match(inspect(fixture.documents.get('3')).reason,/only static PNG/);
  assert.equal(inspect(fixture.documents.get('2')).reason,undefined,'The small corrupt IDAT must reach the real decoder');
  const rejected=Buffer.from(fixture.documents.get('2').split(',')[1],'base64'),badOffset=rejected.indexOf(Buffer.from('IDAT'));
  assert.deepEqual({...inspect(fixture.documents.get('2'))},{width:1,height:1,pixels:1});
  assert.deepEqual([...inflateSync(rejected.subarray(badOffset+4,badOffset+4+rejected.readUInt32BE(badOffset-4)))],[255,255,0,0,255],
    'The rejection fixture is a complete five-byte RGBA scanline with invalid filter 255, not truncated compressed input');
  const valid=Buffer.from(fixture.documents.get('5').split(',')[1],'base64'),offset=valid.indexOf(Buffer.from('IDAT'));
  const scanlines=inflateSync(valid.subarray(offset+4,offset+4+valid.readUInt32BE(offset-4)));
  assert.equal(scanlines.length,16*(1+16*4));assert.deepEqual([...scanlines.subarray(1,5)],[255,0,0,255]);
  for(const source of fixture.artifacts){
    const bytes=Buffer.from(fixture.documents.get(source.artifact_id));assert.equal(bytes.length,source.byte_size);
    assert.equal(Buffer.from(await crypto.subtle.digest('SHA-256',bytes)).toString('hex'),source.sha256);
  }
  assert.equal((await response('/api/artifacts/1/content?limit=2097152')).status,503);
  fixture.readError=false;assert.equal((await response('/api/artifacts/1/content?limit=2097152')).body.toString(),fixture.documents.get('1'));
  fixture.hold=true;const pending=response('/api/artifacts/5/content?limit=2097152');await new Promise(resolve=>setImmediate(resolve));
  assert.equal(fixture.pending.length,1);fixture.release();assert.equal((await pending).body.toString(),fixture.documents.get('5'));fixture.hold=false;
  const nativeAssignments=[];
  class FixtureElement {setAttribute(name,value){nativeAssignments.push({name,value});}}
  class FixtureImage extends FixtureElement {set src(value){nativeAssignments.push({name:'src',value});}get src(){return '';}addEventListener(){}}
  const observer={window:{},HTMLImageElement:FixtureImage,Element:FixtureElement};
  runInNewContext(fixture.installObserver,observer);
  for(const id of ['4','3']){
    assert.throws(()=>{new FixtureImage().src=fixture.documents.get(id);},/Unsafe Canvas QA source/);
    assert.throws(()=>new FixtureImage().setAttribute('src',fixture.documents.get(id)),/Unsafe Canvas QA source/);
  }
  assert.equal(nativeAssignments.length,0,'The guard cannot forward a refused fixture to a native image sink');
  for(const id of ['5','2'])new FixtureImage().src=fixture.documents.get(id);
  assert.equal(nativeAssignments.length,2,'Only tiny decoder fixtures pass through unchanged');
  fixture.catalogError=true;assert.equal((await response('/api/artifacts')).status,503);fixture.catalogError=false;
  assert.equal((await response('/api/debugger/actions',{method:'POST'})).status,405);
  fixture.active=false;fixture.revision++;assert.equal(JSON.parse((await response('/api/artifacts')).body).count,0);
  console.log('PASS authored Canvas browser fixture routes, validators, hashes, bounded pixels, refusal/decode-error inputs, held body, retry and read-only boundary (not rendered QA)');
}

export async function checkCanvasInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture,record}) {
  const until=async(expression,message=expression)=>{
    const end=Date.now()+7000;
    while(Date.now()<end){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,25));}
    assert.fail(`Canvas UI did not settle: ${message}`);
  };
  const press=async(value)=>key(value,value,{windowsVirtualKeyCode:{Enter:13,Tab:9,ArrowRight:39,ArrowLeft:37}[value]});
  const card=id=>`#signal-render-list .signal-render-card:nth-child(${6-Number(id)})`;
  const text=id=>evaluate(`document.querySelector(${JSON.stringify(card(id))})?.textContent`);
  const settle=()=>until("!state.refreshing&&!state.artifactRefreshing&&!state.canvasPreviewReads?.size");
  const refresh=async()=>{await settle();await evaluate('refresh()');await settle();};
  const clean=async(label)=>{
    const value=await evaluate(`({owners:state.canvasPreviewOwners?.size??0,reads:state.canvasPreviewReads?.size??0,
      retained:state.artifacts.filter(a=>a.kind==='canvas_data_url'&&a.content!==undefined).length,
      images:document.querySelectorAll('#signal-render-list img[src]').length,
      detached:(window.canvasRetiredImages??[]).filter(image=>image.hasAttribute('src')).length,
      descriptors:state.artifacts.length,blocked:canvasBrowserReceipt.blocked})`);
    assert.deepEqual({...value,descriptors:0},{owners:0,reads:0,retained:0,images:0,detached:0,descriptors:0,blocked:[]},label);
    record({label,...value});
  };
  const retireSnapshot=()=>evaluate("window.canvasRetiredImages=[...document.querySelectorAll('#signal-render-list img')]");
  const decoded=()=>until("document.querySelector('#signal-render-list img')?.naturalWidth===16&&[...document.querySelectorAll('#signal-render-list img')].every(image=>image.complete&&image.naturalWidth===16)&&document.querySelector('#signal-render-list').textContent.includes('browser could not decode')");
  const open=async()=>{await click('.nav-button[data-screen="signals"]');await settle();await decoded();};
  const reveal=async(selector)=>{
    // Only the owned gallery scrolls. Never force a screen/ancestor offset.
    for(let attempt=0;attempt<12;attempt++){
      const delta=await evaluate(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect(),p=document.querySelector('#signal-panel-rendering').getBoundingClientRect();
        return r.top<p.top+6?r.top-p.top-6:r.bottom>p.bottom-6?r.bottom-p.bottom+6:0;})()`);
      if(Math.abs(delta)<1)return;
      await wheel('#signal-panel-rendering',Math.max(-500,Math.min(500,delta)),true);
    }
    assert.fail(`Canvas gallery could not reveal ${selector}`);
  };
  const geometry=async(label,selector)=>{
    const value=await evaluate(`(()=>{const node=document.querySelector(${JSON.stringify(selector)}),r=node.getBoundingClientRect(),p=document.querySelector('#signal-panel-rendering'),b=p.getBoundingClientRect();
      const hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2),style=getComputedStyle(node);
      return {viewport:[innerWidth,innerHeight],left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height,
        hit:!!node.contains(hit),panel:{top:b.top,bottom:b.bottom,client:p.clientWidth,scroll:p.scrollWidth,scrollTop:p.scrollTop},
        pageOverflow:document.documentElement.scrollWidth>innerWidth,screenScroll:document.querySelector('#screen-signals').scrollTop,
        focus:document.activeElement===node,focusVisible:node.matches(':focus-visible'),outline:style.outlineStyle,outlineWidth:style.outlineWidth};})()`);
    assert(value.width>0&&value.height>0&&value.left>=0&&value.right<=value.viewport[0]+1,label);
    assert(value.top>=0&&value.bottom<=value.viewport[1]+1&&value.hit,label);
    assert.equal(value.pageOverflow,false,label);assert(value.panel.scroll<=value.panel.client+1,label);assert.equal(value.screenScroll,0,label);
    record({label,...value});return value;
  };
  await until('state.artifacts.length===5&&!state.refreshing&&!state.artifactRefreshing');
  assert.equal(fixture.requests.length,0,'Hidden Canvas descriptors must not load content');await clean('initial hidden gallery');
  await screenshot('canvas-hidden');
  await open();
  await until("canvasBrowserReceipt.errors.some(item=>item.id==='decode-error')&&document.querySelector('#signal-render-list').textContent.includes('browser could not decode')");
  assert.match(await text('4'),/4096-pixel/);assert.match(await text('3'),/only static PNG/);
  assert.match(await text('2'),/browser could not decode this PNG/);assert.match(await text('1'),/503/);
  assert.equal(fixture.requests.length,5);assert(fixture.requests.every(request=>request.limit==='2097152'));
  const accepted=await evaluate(`(()=>{const image=document.querySelector(${JSON.stringify(card('5')+' img')}),canvas=document.createElement('canvas');
    canvas.width=canvas.height=1;const context=canvas.getContext('2d');context.drawImage(image,0,0);return {complete:image.complete,width:image.naturalWidth,height:image.naturalHeight,pixel:[...context.getImageData(0,0,1,1).data]};})()`);
  assert.deepEqual(accepted,{complete:true,width:16,height:16,pixel:[255,0,0,255]});record({label:'native decoder pixels',...accepted});
  assert(await evaluate(`state.artifacts.filter(a=>['2','3','4','5'].includes(a.artifact_id)).every(a=>a.contentVerified&&a.content===new Map(${JSON.stringify([...fixture.documents])}).get(a.artifact_id))`),'Exact captured text stays unchanged');
  assert.deepEqual(await evaluate('canvasBrowserReceipt.blocked'),[]);
  assert(await evaluate("canvasBrowserReceipt.assignments.every(item=>item.safe&&['valid','decode-error'].includes(item.id))"),'Only the tiny valid and corrupt PNG may reach src');
  for(let repeat=0;repeat<3;repeat++)await refresh();
  assert.equal(fixture.requests.length,5,'Refresh cannot retry failed or refused previews');
  await reveal(card('4')+' .signal-canvas-frame');await geometry('oversize refusal',card('4')+' .signal-canvas-frame');await screenshot('canvas-oversize-refused');
  await reveal(card('3')+' .signal-canvas-frame');await screenshot('canvas-unsupported');
  await reveal(card('2')+' .signal-canvas-frame');await screenshot('canvas-native-decode-error');
  fixture.readError=false;
  await reveal(card('1')+' button');await click(card('1')+' button');await settle();
  await until(`document.querySelector(${JSON.stringify(card('1')+' img')})?.naturalWidth===16`);
  assert.equal(fixture.requests.filter(request=>request.id==='1').length,2,'Retry is explicit and exact');await screenshot('canvas-retry-decoded');
  for(const [width,height] of [[1440,900],[600,800],[360,740]]){
    await viewport(width,height);
    await reveal(card('5')+' .signal-canvas-frame');await geometry(`decoded preview ${width}`,card('5')+' .signal-canvas-frame');await screenshot(`canvas-${width}-decoded`);
    const disclosure=card('5')+' details:first-of-type > summary';
    await reveal(disclosure);await click(disclosure);await press('Enter');await press('Enter');
    assert(await evaluate(`document.querySelector(${JSON.stringify(card('5')+' details')}).open`));
    await press('Tab');await key('Tab','Tab',{windowsVirtualKeyCode:9,modifiers:8});
    const focused=await geometry(`keyboard disclosure ${width}`,disclosure);
    assert(focused.focus&&focused.focusVisible&&focused.outline!=='none'&&parseFloat(focused.outlineWidth)>0);
    await screenshot(`canvas-${width}-keyboard`);await press('Enter');
    assert.equal(await evaluate(`document.querySelector(${JSON.stringify(card('5')+' details')}).open`),false);
    await click('#signal-view-rendering');await retireSnapshot();await press('ArrowRight');await settle();
    assert.equal(await evaluate('state.signalView'),'activity');assert.equal(await evaluate('document.activeElement.id'),'signal-view-activity');
    await clean(`Activity releases ${width}`);await screenshot(`canvas-${width}-activity`);
    await press('ArrowLeft');await settle();await decoded();
    assert.equal(await evaluate('document.activeElement.id'),'signal-view-rendering');
  }
  await viewport(1440,900);await retireSnapshot();await click('.nav-button[data-screen="traffic"]');await settle();await clean('navigation closes gallery');
  const closedReads=fixture.requests.length;await refresh();assert.equal(fixture.requests.length,closedReads,'Hidden refresh stays metadata-only');
  fixture.hold=true;await click('.nav-button[data-screen="signals"]');await until('state.canvasPreviewReads?.size===2');
  for(let attempt=0;attempt<200&&fixture.pending.length<2;attempt++)await new Promise(resolve=>setTimeout(resolve,25));
  assert.equal(fixture.pending.length,2);await screenshot('canvas-pending');await retireSnapshot();
  await click('.nav-button[data-screen="traffic"]');await settle();await clean('close aborts pending bodies');
  fixture.release();fixture.hold=false;await new Promise(resolve=>setTimeout(resolve,50));await clean('late bodies cannot repopulate');
  await open();await screenshot('canvas-reopened');
  await retireSnapshot();fixture.catalogError=true;await refresh();await clean('catalog failure releases gallery');
  assert.match(await text('5'),/catalog is unavailable/);await screenshot('canvas-catalog-error');
  fixture.catalogError=false;await refresh();await decoded();
  await retireSnapshot();fixture.active=false;fixture.revision++;await refresh();await clean('empty live catalog');
  assert.match(await evaluate("document.querySelector('#signal-render-list').textContent"),/No Canvas readback/);await screenshot('canvas-empty');
  const sink=await evaluate('canvasBrowserReceipt');assert.deepEqual(sink.blocked,[]);record({label:'native image sink receipts',...sink});
  assert(fixture.requests.every(request=>request.method==='GET'),'The UI must never mutate capture state');
  return {status:'passed',path:'installed Chrome, production Canvas UI with authored HTTP evidence',viewports:[[1440,900],[600,800],[360,740]],
    checks:['hidden metadata-only discovery','real 16x16 PNG decode and pixel readback','oversized/unsupported refused before native src','real 1x1 decoder error label','explicit read-error retry','stable refresh without refetch','keyboard disclosure and Activity/Overview tabs','wide/narrow gallery geometry','close and reopen','abort pending bodies and refuse late completion','catalog failure/recovery and empty cleanup'],
    limits:['Only authored tiny PNGs enter Chrome decoding. The giant-header sink tripwire must never fire.','No production admission or ownership functions are mocked. HTTP responses are synthetic; this is not native capture or backend acceptance.','Source removal and declared-pixel accounting do not measure decoder allocation, native caches, JavaScript heap or process RSS; no immediate native-memory reclamation claim.','Not macOS native-shell acceptance.']};
}
