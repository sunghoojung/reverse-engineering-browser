import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

// Authored catalogs and inert source bytes for offline model checks only.
export async function sourcesTreeFixture(base) {
  base.artifacts.splice(0);base.documents.clear();
  const text=Array.from({length:160},(_,i)=>`// tree needle ${i}: ${'retained text '.repeat(12)}`).join('\n');
  const target=await base.addSource('100',text);target.url='https://a.tree.invalid/shared/nested/entry.js';
  const other=await base.addSource('101','// same folder at another origin');other.url='https://b.tree.invalid/shared/nested/entry.js';
  const sibling=await base.addSource('102','// selected branch sibling');sibling.url='https://a.tree.invalid/shared/sibling.js';
  const hostile=await base.addSource('103','// inert malformed URL label');hostile.url='<img src=x onerror="globalThis.__sourceTreeExecuted=true">';
  const long=await base.addSource('104','// bounded long label');long.url=`https://a.tree.invalid/${'long-label-'.repeat(90)}.js`;
  const deep=await base.addSource('105','// bounded deep path');deep.url=`https://a.tree.invalid/${Array.from({length:80},(_,i)=>`deep-${i}`).join('/')}/entry.js`;
  for(let i=0;i<48;i++){
    const source=await base.addSource(String(2000+i),`// navigator ${i}`);
    source.url=`https://z.tree.invalid/scroll/file-${String(i).padStart(2,'0')}.js`;
  }
  const fixture={...base,target,other,sibling,hostile,long,deep,text,catalogs:{artifacts:0}};
  fixture.handle=async(request,response)=>{
    const path=new URL(request.url,'http://127.0.0.1').pathname;
    if(path==='/api/events'){
      // A genuinely empty live catalog must clear the UI; demo mode deliberately
      // preserves previous demo evidence when the catalog becomes empty.
      response.writeHead(200,{'Content-Type':'application/json'});
      response.end(JSON.stringify({count:0,events:[],capture_mode:'live',broker_connected:false,capture_controls_available:false}));return true;
    }
    if(path==='/api/artifacts')fixture.catalogs.artifacts++;
    return base.handle(request,response);
  };
  return fixture;
}

export async function checkSourcesTreeFixture(base,root) {
  const fixture=await sourcesTreeFixture(base);
  const model=runInNewContext((await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8'))+';({isBrokerResponse,isArtifactResponse})',{TextEncoder});
  const request=async url=>{
    const response={destroyed:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(body){this.body=body;}};
    assert(await fixture.handle({url,method:'GET'},response));assert.equal(response.status,200);return response;
  };
  assert(model.isBrokerResponse(JSON.parse((await request('/api/events')).body)));
  assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)));
  assert.equal((await request('/api/artifacts/100/content')).body.toString('utf8'),fixture.text);
  assert.equal(new URL(fixture.target.url).pathname,new URL(fixture.other.url).pathname);
  const payloadBytes=fixture.artifacts.reduce((sum,row)=>sum+row.byte_size,0);
  assert(fixture.artifacts.length<64&&payloadBytes<64*1024,'Tree catalogs and total authored source bytes must remain bounded');
  fixture.artifacts.reverse();assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)));
  fixture.artifacts.splice(0);assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)));
  const canvas=await fixture.addSource('4000','data:image/png;base64,');
  Object.assign(canvas,{kind:'canvas_data_url',capture_origin:'canvas_to_data_url',execution_context_id:'0',sensitive:true,mime_type:'text/plain',url:'https://canvas.tree.invalid/filtered'});
  assert(model.isArtifactResponse(JSON.parse((await request('/api/artifacts')).body)),'Filtered canvas-only catalog must still pass the real HTTP validator');
  assert.equal(fixture.rejectedWrites.length,0);fixture.release();
  console.log('PASS Sources-tree HTTP fixture: admitted captured catalogs, scoped same-path sources, inert hostile/deep/long labels, bounded bytes, reorder and empty catalog (not rendered QA)');
}
