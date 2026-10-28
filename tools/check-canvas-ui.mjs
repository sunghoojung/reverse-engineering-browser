import assert from 'node:assert/strict';
import {deflateSync, inflateSync} from 'node:zlib';
import {runInNewContext} from 'node:vm';

// Authored HTTP evidence only. The production catalog, byte/hash reader,
// ownership and PNG admission are checked offline; no browser driver is exported.
export async function canvasEvidenceFixture({artifact, png, pngUrl, chunk}) {
  const pixels=Buffer.concat(Array.from({length:16},()=>Buffer.from([0,...Array.from({length:16},()=>[255,0,0,255]).flat()])));
  const valid=pngUrl(png({width:16,height:16,idat:[chunk('IDAT',deflateSync(pixels))]}));
  // Chrome CI loaded both authored malformed scanlines without error events.
  // Exercise native load failure separately under an authored img-src policy;
  // the ordinary page uses only these valid tiny PNGs for decoder acceptance.
  const documents=new Map([
    ['5',valid],
    ['4',pngUrl(png({width:100000,height:100000}))],
    ['3',valid.replace('image/png','image/webp')],
    ['2',valid],
    ['1',valid],
  ]);
  const artifacts=await Promise.all([...documents].map(([id,text])=>artifact(id,text)));
  const events=artifacts.map(source=>({protocol_version:1,category:'canvas',type:'api_call',
    session_id:1,sequence_number:Number(source.creator_event_id),monotonic_time_ns:Number(source.creator_event_id),
    navigation_id:1,frame_id:1,artifact_id:Number(source.artifact_id),parent_event_id:0,process_id:1,thread_id:1,
    payload_encoding:'hex',payload:Buffer.from('canvas.toDataURL').toString('hex'),payload_size:16}));
  const fixture={documents,artifacts,events,requests:[],pending:[],readError:true,hold:false,catalogError:false,revision:1,active:true,phase:'normal'};
  fixture.documentHeaders=raw=>{
    const url=new URL(raw,'http://127.0.0.1');
    return url.pathname==='/'&&url.searchParams.get('canvas_policy')==='blocked'
      ? {'Content-Security-Policy':"img-src 'none'"} : {};
  };
  fixture.handle=async(request,response)=>{
    const url=new URL(request.url,'http://127.0.0.1'),path=url.pathname;
    const json=(status,value,headers={})=>{response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store',...headers});response.end(JSON.stringify(value));};
    if(!path.startsWith('/api/'))return false;
    if(request.method&&request.method!=='GET'){fixture.requests.push({path,method:request.method,status:405});json(405,{error:'Canvas QA never mutates a native capture'});return true;}
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
      const receipt={id,path,phase:fixture.phase,method:request.method??'GET',limit:url.searchParams.get('limit'),status:id==='1'&&fixture.readError?503:200,held:fixture.hold};fixture.requests.push(receipt);
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
    const known=new Map(${JSON.stringify([[documents.get('5'),'valid'],[documents.get('4'),'oversized'],[documents.get('3'),'unsupported']])});
    const safe=new Set(${JSON.stringify([documents.get('5')])});
    const receipt=window.canvasBrowserReceipt={assignments:[],blocked:[],loads:[],errors:[],violations:[]};
    window.addEventListener('securitypolicyviolation',event=>receipt.violations.push({directive:event.effectiveDirective,blockedURI:event.blockedURI,disposition:event.disposition}));
    const observe=(image,value) => {
      const id=known.get(String(value));
      receipt.assignments.push({id:id??'unknown',safe:safe.has(String(value))});
      if(!safe.has(String(value))){receipt.blocked.push(id??'unknown');throw new Error('Unsafe Canvas QA source reached the native image sink');}
      image.addEventListener('load',event=>receipt.loads.push({id,width:image.naturalWidth,height:image.naturalHeight,trusted:event.isTrusted}),{once:true});
      image.addEventListener('error',event=>receipt.errors.push({id,trusted:event.isTrusted}),{once:true});
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
  assert.deepEqual({...inspect(fixture.documents.get('5'))},{width:16,height:16,pixels:256});
  assert.match(inspect(fixture.documents.get('4')).reason,/4096-pixel/);
  assert.match(inspect(fixture.documents.get('3')).reason,/only static PNG/);
  assert.deepEqual({...inspect(fixture.documents.get('2'))},{width:16,height:16,pixels:256});
  assert.deepEqual(fixture.documentHeaders('/?canvas_images=1'),{});
  assert.deepEqual(fixture.documentHeaders('/?canvas_images=1&canvas_policy=blocked'),{'Content-Security-Policy':"img-src 'none'"});
  assert.deepEqual(fixture.documentHeaders('/api/artifacts?canvas_policy=blocked'),{},'Only the fresh HTML document carries the image policy');
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
  const observer={window:{addEventListener(){}},HTMLImageElement:FixtureImage,Element:FixtureElement};
  runInNewContext(fixture.installObserver,observer);
  for(const id of ['4','3']){
    assert.throws(()=>{new FixtureImage().src=fixture.documents.get(id);},/Unsafe Canvas QA source/);
    assert.throws(()=>new FixtureImage().setAttribute('src',fixture.documents.get(id)),/Unsafe Canvas QA source/);
  }
  assert.equal(nativeAssignments.length,0,'The guard cannot forward a refused fixture to a native image sink');
  for(const id of ['5','2'])new FixtureImage().src=fixture.documents.get(id);
  assert.equal(nativeAssignments.length,2,'Only tiny decoder fixtures pass through unchanged');
  fixture.catalogError=true;assert.equal((await response('/api/artifacts')).status,503);fixture.catalogError=false;
  assert.equal((await response('/api/artifacts',{method:'POST'})).status,405);
  fixture.active=false;fixture.revision++;assert.equal(JSON.parse((await response('/api/artifacts')).body).count,0);
  console.log('PASS authored Canvas browser fixture routes, validators, hashes, bounded pixels, refusal inputs and isolated image-policy header, held body, retry and read-only boundary (not rendered QA)');
}
