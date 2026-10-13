import assert from 'node:assert/strict';
import {request} from 'node:http';
import {readFile,mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fixtureServer,selfTest} from './traffic-capture-qa.mjs';
const root=resolve(process.argv[2]||'.');
await selfTest(root);
const {server,change}=await fixtureServer(root);
function get(path,method='GET',host) {
  return new Promise((resolveResponse,reject)=>{
    const call=request({hostname:'127.0.0.1',port:server.address().port,path,method,headers:host?{Host:host}:{}},response=>{
      const chunks=[];response.on('data',chunk=>chunks.push(chunk));response.on('end',()=>resolveResponse({status:response.statusCode,body:Buffer.concat(chunks),headers:response.headers}));
    });call.on('error',reject);call.end();
  });
}
try {
  await new Promise((ready,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',ready);});
  for(const variant of ['baseline','epoch','instance','target','truncated','states','clear','off']) {
    change(variant);const response=await get('/api/debugger?wait_ms=25000'),data=JSON.parse(response.body);
    assert.equal(response.status,200);
    assert.equal(data.network.requests.length,['clear','off'].includes(variant)?0:variant==='truncated'?1:variant==='states'?4:3);
  }
  for (const [path,status] of [['/',200],['/?native=1',200],['/traffic_view.js',200],['/api/events',200],['/api/artifacts',200],['/api/unknown',503],['/analyst_runner_core.js',404],['/%69ndex.html',404],['//index.html',404],['/../index.html',404],['/index.html/extra',404]]) assert.equal((await get(path)).status,status,path);
  assert.deepEqual((await get('/traffic_view.js')).body,await readFile(join(root,'apps/research-ui/traffic_view.js')));
  change('disconnect');assert.equal((await get('/api/debugger')).status,503);
  change('malformed');assert.deepEqual(JSON.parse((await get('/api/debugger')).body),{malformed:true});
  change('baseline');assert.equal((await get('/api/debugger')).status,200);
  assert.equal((await get('/api/debugger','POST')).status,405);
  assert.equal((await get('/','GET','foreign.example')).status,400);
  console.log('PASS loopback HTTP variants, failure/recovery, exact public assets, rejected writes/foreign Host/private/encoded/ambiguous paths');
} finally {server.closeAllConnections();await new Promise(done=>server.close(done));}
const temporary=await mkdtemp(join(tmpdir(),'reb-qa-assets-'));
const original=process.env.REB_QA_ASSET_DIR;
try {
  process.env.REB_QA_ASSET_DIR=temporary;
  await writeFile(join(temporary,'index.html'),'Synthetic mismatched bundle');
  await assert.rejects(fixtureServer(root),/Bundle\/source mismatch: index.html|ENOENT/);
  console.log('PASS missing or mismatched packaged assets refuse fixture startup');
} finally {
  if(original===undefined)delete process.env.REB_QA_ASSET_DIR;else process.env.REB_QA_ASSET_DIR=original;
  await rm(temporary,{recursive:true,force:true});
}
