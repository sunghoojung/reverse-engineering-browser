import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

// Authored local HTTP documents only. Reuse the Sources fixture's immutable and
// live readers; never substitute a product loader, cache, renderer or history.
export async function sourcesHistoryFixture(base) {
  const longText=Array.from({length:180},(_,i)=>`// history row ${i}: ${'inert text '.repeat(24)}`).join('\n');
  const target=await base.addSource('100',longText);
  const live=base.addLiveSource('history-live',longText);
  // Small metadata/document rows make the navigator genuinely scrollable at
  // both widths without megabyte fixtures or lowered production retention caps.
  for(let i=0;i<42;i++)base.addLiveSource(`history-nav-${String(i).padStart(2,'0')}`,`// navigator ${i}`);
  for(let i=0;i<42;i++)await base.addSource(String(1000+i),`// captured navigator ${i}`);
  const moduleBytes=Buffer.from([0,97,115,109,1,0,0,0]);
  assert(WebAssembly.validate(moduleBytes),'Authored module must be valid, never instantiated');
  const addWasm=async id=>{
    const source=await base.addSource(id,moduleBytes);
    Object.assign(source,{kind:'wasm',capture_origin:'webassembly_compile',mime_type:'application/wasm',url:`https://fixture.invalid/module-${id}.wasm`});
    return source;
  };
  const wasm=await addWasm('101');
  const report=source=>({schema:'wasm-inspection-v1',artifact_id:source.artifact_id,sha256:source.sha256,byte_size:source.byte_size,
    status:'decoded',sections:0,defined_functions:0,imported_functions:0,instructions:0,notice:'Static inspection of an authored empty module. Never executed.',omissions:[],rows:[]});
  const fixture={...base,target,live,wasm,longText,moduleBytes,report,addWasm,reads:[],gates:new Map(),catalogReads:0,nextId:200};
  fixture.hold=key=>{
    assert(!fixture.gates.has(key),'A route already has a pending hold');
    let release;const promise=new Promise(resolve=>{release=resolve;});
    const gate={promise,release,outcome:'ready',arrivals:0};fixture.gates.set(key,gate);return gate;
  };
  fixture.releaseRoute=(key,outcome='ready')=>{
    const gate=fixture.gates.get(key);assert(gate,'No held route to release');
    gate.outcome=outcome;fixture.gates.delete(key);gate.release();
  };
  fixture.handle=async(request,response)=>{
    const url=new URL(request.url,'http://127.0.0.1');
    if(url.pathname==='/api/artifacts')fixture.catalogReads++;
    const id=/^\/api\/artifacts\/([0-9]+)\/content$/.exec(url.pathname)?.[1];
    const key=id?`artifact:${id}`:url.pathname==='/api/debugger/source'?`live:${url.searchParams.get('script_id')}`
      :url.pathname==='/api/wasm'?`wasm:${url.searchParams.get('artifact_id')}`:null;
    if(!key)return base.handle(request,response);
    const entry={id:fixture.reads.length+1,key,method:request.method??'GET',status:'pending'};fixture.reads.push(entry);
    const gate=fixture.gates.get(key);
    if(gate){gate.arrivals++;await gate.promise;}
    const json=(status,value)=>{if(!response.destroyed){response.writeHead(status,{'Content-Type':'application/json'});response.end(JSON.stringify(value));}};
    if(gate?.outcome==='error'){
      entry.status='error';json(503,{error:`Authored ${key} reopen failure`});return true;
    }
    if(key.startsWith('wasm:')){
      const source=base.artifacts.find(value=>value.artifact_id===url.searchParams.get('artifact_id')&&value.kind==='wasm');
      entry.status=source?'ready':'missing';json(source?200:404,source?report(source):{error:'Authored module unavailable'});return true;
    }
    const handled=await base.handle(request,response);entry.status=handled?'ready':'missing';return handled;
  };
  fixture.release=()=>{for(const key of [...fixture.gates.keys()])fixture.releaseRoute(key);base.release();};
  return fixture;
}

export async function checkSourcesHistoryFixture(base,root) {
  const fixture=await sourcesHistoryFixture(base);
  const model=runInNewContext((await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8'))+';({isArtifactResponse,isDebuggerResponse,isWasmInspection})',{TextEncoder});
  const request=async url=>{
    const response={destroyed:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(body){this.body=body;}};
    assert(await fixture.handle({url,method:'GET'},response));return response;
  };
  assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)));
  assert(model.isDebuggerResponse(JSON.parse((await request('/api/debugger')).body)));
  assert(model.isWasmInspection(JSON.parse((await request('/api/wasm?artifact_id=101')).body),fixture.wasm));
  assert.deepEqual((await request('/api/artifacts/101/content')).body,fixture.moduleBytes);
  for(const [key,url,expected] of [
    ['artifact:100','/api/artifacts/100/content',fixture.longText],
    ['live:history-live','/api/debugger/source?script_id=history-live',fixture.longText],
    ['wasm:101','/api/wasm?artifact_id=101',null],
  ]) {
    const gate=fixture.hold(key);let completed=false;
    const held=request(url).then(value=>{completed=true;return value;});
    assert.equal(gate.arrivals,1);assert.equal(completed,false,'Held response escaped before explicit release');
    fixture.releaseRoute(key);const response=await held;assert.equal(response.status,200);
    if(expected)assert.equal(key.startsWith('live')?JSON.parse(response.body).source:response.body.toString('utf8'),expected);
    fixture.hold(key);const failed=request(url);fixture.releaseRoute(key,'error');assert.equal((await failed).status,503);
  }
  assert(fixture.reads.every(value=>value.status!=='pending'));
  assert(fixture.artifacts.reduce((sum,value)=>sum+value.byte_size,0)<64*1024,'Fixture payloads must remain small');
  assert.equal(fixture.rejectedWrites.length,0);
  console.log('PASS Sources-history HTTP fixture: small authored source/live/module admission, valid never-executed WASM, held replies and explicit failures (not rendered QA)');
}
