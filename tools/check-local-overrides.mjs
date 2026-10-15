#!/usr/bin/env node
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,symlink,stat,mkdir,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawn,spawnSync} from 'node:child_process';
import {createServer} from 'node:http';
import {readOverrideAsset,overrideAction,saveOverrideAction,applyOverride} from './local-overrides.mjs';
// Canonicalize only our authored fixture root; production still refuses symlinks.
const folder = await realpath(await mkdtemp(join(tmpdir(),'reb-local-overrides-')));
try {
  const path = join(folder,'fixture.js');
  const source = 'globalThis.fixtureMessage = "authored-only";\n';
  await writeFile(path,source);
  const asset = await readOverrideAsset(path);
  const options = {url:'http://127.0.0.1:17777/asset.js?version=1',targetId:'owned-target',experimentId:3,sha256:asset.sha256,contentType:'text/javascript; charset=utf-8'};
  const action = overrideAction(asset,options,1000);
  assert.equal(action.local_override.expires_at_ms,61000);
  assert.equal(action.response_body,source);
  assert.equal(action.local_override.exact_url,options.url);
  assert.equal(action.method_filter,'GET');
  for (const changed of [{url:'https://other.test'},{url:'http://user:pass@127.0.0.1/a'}, {url:options.url+'#'}, {url:options.url+'\n'},
    {method:'POST'}, {targetId:''}, {experimentId:0}, {experimentId:1.5}, {ttlMs:0}, {ttlMs:300001}, {sha256:'0'.repeat(64)},
    {contentType:'text/html'}, {contentType:'text/plain; charset=latin1'}]) assert.throws(()=>overrideAction(asset,{...options,...changed},1000));
  assert.throws(()=>overrideAction({...asset,body:source+'changed'},options,1000));
  await writeFile(path,source+'changed');
  assert.throws(()=>overrideAction({},options,1000));
  const changedAsset = await readOverrideAsset(path);
  assert.throws(()=>overrideAction(changedAsset,options,1000));
  await assert.rejects(()=>readOverrideAsset(join(folder,'missing')));
  await writeFile(path,Buffer.from([0xc3,0x28]));await assert.rejects(()=>readOverrideAsset(path));
  await writeFile(path,'x'.repeat(65537));await assert.rejects(()=>readOverrideAsset(path));
  await writeFile(path,'é'.repeat(32768));assert.equal((await readOverrideAsset(path)).bytes,65536);
  await writeFile(path,'');assert.equal((await readOverrideAsset(path)).bytes,0);
  await writeFile(path,'\ufeff'+source);assert.equal((await readOverrideAsset(path)).body,'\ufeff'+source);
  await writeFile(path,source);await symlink(path,join(folder,'alias'));await assert.rejects(()=>readOverrideAsset(join(folder,'alias')));
  await mkdir(join(folder,'real'));await writeFile(join(folder,'real','asset'),source);await symlink(join(folder,'real'),join(folder,'linked'));
  await assert.rejects(()=>readOverrideAsset(join(folder,'linked','asset')));
  await assert.rejects(()=>readOverrideAsset(folder));
  const output = join(folder,'action.json');await saveOverrideAction(output,action);
  assert.deepEqual(JSON.parse(await readFile(output,'utf8')),action);
  assert.equal((await stat(output)).mode & 0o777,0o600);
  await assert.rejects(()=>saveOverrideAction(output,action));
  const cli = args => spawnSync(process.execPath,['tools/prepare-local-override.mjs',...args],{encoding:'utf8'});
  let result = cli(['--file',path]);assert.equal(result.status,0,result.stderr);
  const preview=JSON.parse(result.stdout);assert.equal(preview.armed,false);assert.equal(preview.network_requests,0);assert.equal(preview.sha256,asset.sha256);assert(!result.stdout.includes(source.trim()));
  result=cli(['--file',path,'--output',join(folder,'prepared.json'),'--url',options.url,'--target-id',options.targetId,'--experiment-id','3','--sha256',asset.sha256]);
  assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).armed,false);
  const prepared=JSON.parse(await readFile(join(folder,'prepared.json'),'utf8'));assert.equal(prepared.response_body,source);
  result=cli(['--file',path,'--output',output,'--url',options.url,'--target-id',options.targetId,'--experiment-id','3','--sha256','0'.repeat(64)]);assert.notEqual(result.status,0);
  assert(!result.stderr.includes(source.trim()));
  const received=[];
  let mode='ok';
  let redirected=0;
  const redirectServer=createServer((_req,res)=>{redirected++;res.end('{}');});
  await new Promise(resolve=>redirectServer.listen(0,'127.0.0.1',resolve));
  const server=createServer(async(req,res)=>{
    const chunks=[];for await(const chunk of req)chunks.push(chunk);
    const body=JSON.parse(Buffer.concat(chunks));received.push(body);
    assert.equal(req.url,'/api/debugger/actions');assert.equal(req.headers.cookie,undefined);assert.equal(req.headers.authorization,undefined);
    res.setHeader('Content-Type','application/json');
    if(mode==='fail'){res.writeHead(503);res.end('{}');return;}
    if(mode==='redirect'){res.writeHead(307,{location:'http://127.0.0.1:'+redirectServer.address().port});res.end();return;}
    if(mode==='oversize'){res.end('x'.repeat(1048577));return;}
    if(mode==='invalid'){res.end('{');return;}
    if(mode==='disconnect'){req.socket.destroy();return;}
    if(mode==='non-json')res.setHeader('Content-Type','text/plain');
    if(mode==='encoded')res.setHeader('Content-Encoding','gzip');
    if(mode==='duplicate-type')res.setHeader('Content-Type',['application/json','application/json']);
    if(mode==='missing-type')res.removeHeader('Content-Type');
    const publicUrl=new URL(body.local_override?.exact_url ?? options.url);publicUrl.search='';
    const rule=body.mode==='continue'?{mode:'continue'}:{mode:'fulfill',method_filter:body.method_filter,response_code:200,
      response_body_bytes:Buffer.byteLength(body.response_body),local_override:{...body.local_override,exact_url:publicUrl.href}};
    if(mode==='wrong-owner')rule.local_override.target_id='unrelated-target';
    let receipt=JSON.stringify({ok:true,experiment:{target_id:'owned-target',experiment_id:3,rule}});
    if(mode==='duplicate-key')receipt='{"ok":false,'+receipt.slice(1);
    if(mode==='invalid-utf8'){res.end(Buffer.from([0xc3,0x28]));return;}
    res.end(receipt);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    const origin='http://127.0.0.1:'+server.address().port;
    const current=overrideAction(asset,options);
    const receipt=await applyOverride(origin,current);assert.equal(receipt.armed,true);assert.equal(received.length,1);
    assert.equal(received[0].response_body,source);assert(!JSON.stringify(receipt).includes(source.trim()));
    const disarmed=await applyOverride(origin,current,{disarm:true});assert.equal(disarmed.armed,false);assert.equal(received.length,2);
    assert.deepEqual(received[1].expected_local_override,{metadata:current.local_override,method_filter:'GET',content_type:options.contentType});
    await assert.rejects(()=>applyOverride(origin,action));assert.equal(received.length,2,'Expired action never dispatches');
    for(const bad of [origin+'/',origin+'/path','https://127.0.0.1','http://example.test',origin+'#','http://localhost:'+server.address().port])await assert.rejects(()=>applyOverride(bad,current));
    assert.equal(received.length,2);
    for(const malformed of [null,{}, {...current,response_body:source+'changed'}, {...current,unexpected:true},
      {...current,response_headers:{...current.response_headers,'set-cookie':'authored-only=1'}},
      {...current,local_override:{...current.local_override,unexpected:true}}]) {
      await assert.rejects(()=>applyOverride(origin,malformed),/No operation was sent/);
    }
    assert.equal(received.length,2,'Malformed actions never dispatch');
    for(const failure of ['fail','redirect','oversize','invalid','disconnect','wrong-owner','non-json','encoded','duplicate-type','missing-type','duplicate-key','invalid-utf8']) {
      mode=failure;const before=received.length;
      await assert.rejects(()=>applyOverride(origin,current),/Outcome may be unknown/);
      assert.equal(received.length,before+1,'Unconfirmed operations never retry');
    }
    assert.equal(redirected,0,'Backend redirects are never followed');
    mode='ok';
    const expired=structuredClone(current);expired.local_override.expires_at_ms=Date.now()-1000;
    const expiredDisarm=await applyOverride(origin,expired,{disarm:true});assert.equal(expiredDisarm.armed,false);
    const managePath=join(folder,'manage.json');await saveOverrideAction(managePath,current);
    const manage=async(args,env={})=>new Promise((resolve,reject)=>{
      const child=spawn(process.execPath,['tools/manage-local-override.mjs',...args],{env:{...process.env,...env}});
      let stdout='',stderr='';child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);
      child.on('error',reject);child.on('close',status=>resolve({status,stdout,stderr}));
    });
    // A configured proxy points only at our authored loopback fixture. Direct HTTP must ignore it.
    const proxy='http://127.0.0.1:'+redirectServer.address().port;
    result=await manage(['--arm',managePath,'--base-url',origin],{NODE_USE_ENV_PROXY:'1',HTTP_PROXY:proxy,HTTPS_PROXY:proxy,ALL_PROXY:proxy,NO_PROXY:'',http_proxy:proxy,https_proxy:proxy,all_proxy:proxy,no_proxy:''});
    assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).armed,true);assert.equal(redirected,0,'Ambient proxy is never contacted');
    result=await manage(['--disarm',managePath,'--base-url',origin]);assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).armed,false);
    const beforeInvalid=received.length;
    for(const content of ['{"action":1,"action":2}',Buffer.from([0xc3,0x28]),'x'.repeat(524289)]) {
      await writeFile(join(folder,'invalid.json'),content);
      result=await manage(['--arm',join(folder,'invalid.json'),'--base-url',origin]);assert.notEqual(result.status,0);
      assert(!result.stderr.includes(source.trim()));
    }
    await symlink(managePath,join(folder,'manage-link'));
    for(const file of [join(folder,'manage-link'),join(folder,'missing-action'),folder]) {
      result=await manage(['--arm',file,'--base-url',origin]);assert.notEqual(result.status,0);
    }
    assert.equal(received.length,beforeInvalid,'Invalid prepared files never dispatch');
  } finally {await new Promise(resolve=>server.close(resolve));await new Promise(resolve=>redirectServer.close(resolve));}
  console.log('PASS local override preview/preparation, exact digest/scope/expiry, UTF-8/bounds/symlink/duplicate-key rejection, private publication, explicit CLI arm/disarm, expired disarm, direct proxy-free loopback and bounded unknown-outcome/no-redirect/no-retry receipts');
} finally {await rm(folder,{recursive:true,force:true});}
