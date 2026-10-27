#!/usr/bin/env node
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,symlink,stat,mkdir,realpath} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawn,spawnSync} from 'node:child_process';
import {runInNewContext} from 'node:vm';
import {readOverrideAsset,overrideAction,saveOverrideAction} from './local-overrides.mjs';
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
  const manager = await readFile('tools/manage-local-override.mjs','utf8');
  assert.doesNotMatch(manager, /\bimport\b|require\s*\(/, 'Retired manager loads no transport or filesystem helpers');
  for (const args of [[], ['--arm', path, '--base-url', 'http://127.0.0.1:1'], ['--disarm', '/dev/stdin', '--base-url', 'http://127.0.0.1:1']]) {
    const fakeProcess = {argv:['node','manager',...args]};
    Object.defineProperty(fakeProcess, 'stdin', {get(){throw new Error('must not read input');}});
    let message = '';
    runInNewContext(manager, {process:fakeProcess, console:{error:value=>message=value,log(){throw new Error('unexpected output');}}});
    assert.equal(fakeProcess.exitCode,2);
    assert.match(message,/execution was removed/);
    // Keep stdin open: a CLI attempting to read it would hit the deadline.
    const stopped = await new Promise((resolve,reject)=>{
      const child=spawn(process.execPath,['tools/manage-local-override.mjs',...args],{stdio:['pipe','pipe','pipe']});
      let stderr='';child.stderr.on('data',chunk=>stderr+=chunk);
      const timer=setTimeout(()=>{child.kill();reject(new Error('Retired manager waited for input'));},3000);
      child.on('error',error=>{clearTimeout(timer);reject(error);});
      child.on('close',status=>{clearTimeout(timer);resolve({status,stderr});});
    });
    assert.equal(stopped.status,2,stopped.stderr);
    assert.match(stopped.stderr,/execution was removed/);
  }
  const help=spawnSync(process.execPath,['tools/manage-local-override.mjs','--help'],{encoding:'utf8'});
  assert.equal(help.status,0,help.stderr);assert.match(help.stdout,/no native override replacement/);
  console.log('PASS offline override validation, digest/scope/expiry, bounded UTF-8 files, private publication; retired manager rejects before input or transport');
} finally {await rm(folder,{recursive:true,force:true});}
