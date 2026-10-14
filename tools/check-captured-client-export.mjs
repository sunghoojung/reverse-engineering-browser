#!/usr/bin/env node
// End-to-end offline bridge checks. Every record is an authored fixture.
import assert from 'node:assert/strict';
import {mkdtemp, readFile, writeFile, mkdir, symlink, stat, readdir, rm} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
import {network} from './traffic-capture-qa.mjs';

const script = fileURLToPath(new URL('./export-captured-client.mjs',import.meta.url));
const directory = await mkdtemp(join(tmpdir(),'reb-offline-export-'));
const input = join(directory,'request.json'), output = join(directory,'project.zip');
const copy = value => JSON.parse(JSON.stringify(value));
const fixture = network(); const record = fixture.requests[0];
record.url='https://example.test/a%2Fb?x=1&%78=2&empty=&q=a+b&q=a%20b';
record.document_url=record.url;record.request.headers=[['Content-Type','application/json'],['X-Authored','synthetic-only']];
record.request.body.text='\ufeff雪\r\n{"inert":"${process.exit()} ` </script>","duplicate":1,"duplicate":2}';
record.error_text=''; record.started_monotonic_ms=123.00000000000003;
const document = {format:'reb-network-request-v1',source:{instance_id:fixture.instance_id,capture_epoch:fixture.capture_epoch,
  request_id:record.id,target_id:record.target_id,started_monotonic_ms:record.started_monotonic_ms},debugger_generation:42,request:record};
let receipts=0;
const server=createServer((_request,response)=>{receipts++;response.end('unexpected');});
await new Promise(done=>server.listen(0,'127.0.0.1',done));
function command(program,args,cwd=directory) {
  return new Promise((resolve,reject)=>{
    const child=spawn(program,args,{cwd,stdio:['ignore','pipe','pipe']}),out=[],err=[];
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('Offline export check timed out'));},15000);
    child.stdout.on('data',part=>out.push(part));child.stderr.on('data',part=>err.push(part));
    child.once('error',error=>{clearTimeout(timer);reject(error);});
    child.once('close',code=>{clearTimeout(timer);resolve({code,stdout:Buffer.concat(out).toString(),stderr:Buffer.concat(err).toString()});});
  });
}
const run=(...args)=>command(process.execPath,[script,...args]);
async function exportFixture(value,path=output,mode=null) {
  await writeFile(input,JSON.stringify(value));
  const result=await run('--input',input,'--output',path,...(mode?['--mode',mode]:[]));
  assert.equal(result.code,0,result.stderr);return JSON.parse(result.stdout);
}
async function archive(path) {
  const result=await command('python3',['-c',
    'import json,sys,zipfile\nwith zipfile.ZipFile(sys.argv[1]) as z:\n assert z.testzip() is None\n assert all(n.startswith("reb-client-project/") and ".." not in n.split("/") for n in z.namelist())\n print(json.dumps({n:z.read(n).decode("utf-8") for n in z.namelist()}))',path]);
  assert.equal(result.code,0,result.stderr);return JSON.parse(result.stdout);
}
const json=(files,path)=>JSON.parse(files['reb-client-project/'+path]);
try {
  // Some browser hosts provide a module-shaped shim without CommonJS require.
  // Only trusted repository source is evaluated here, never fixture content.
  const browserSource = (await Promise.all(['traffic_view.js','captured_client.js'].map(name =>
    readFile(new URL('../apps/research-ui/'+name,import.meta.url),'utf8')))).join('\n');
  for (const shim of [{},{module:null},{module:{exports:{}}}]) {
    const api=runInNewContext(browserSource+'\n;({trafficCaptureDocument,capturedClientSource,capturedClientProject})',
      {TextEncoder,TextDecoder,URL,Uint8Array,...shim});
    const capture=api.capturedClientSource({instance:'fixture',epoch:1,request:record.id,target:record.target_id,started:record.started_monotonic_ms},
      api.trafficCaptureDocument({captureRecord:record}));
    const project=api.capturedClientProject(capture,'raw');
    assert.equal(project.files.length,15);assert.deepEqual(json(Object.fromEntries(project.files.map(file=>[file.path,file.text])),'evidence/capture.json').record,record);
    if (shim.module) assert.deepEqual(shim.module.exports,{},'Browser module shim is not treated as CommonJS');
  }
  assert.equal((await run('--help')).code,0);
  const result=await exportFixture(document);
  assert.equal(result.mode,'raw');assert.equal(result.network_requests,0);assert.deepEqual(result.problems,[]);assert.equal(result.temporary_cleanup_pending,false);
  assert(!JSON.stringify(result).includes(record.url),'Summary never prints captured values');
  assert.equal((await stat(output)).mode & 0o777,0o600);
  const files=await archive(output), evidence=json(files,'evidence/capture.json');
  assert.deepEqual(evidence.record,record,'Entire raw retained row stays data');
  assert.equal(evidence.coverage.dropped,null);assert.equal(evidence.coverage.limits,null);
  assert.deepEqual(evidence.coverage.saved_response,{format:document.format,source:document.source,debugger_generation:42});
  assert.match(evidence.coverage.scope,/saved.*not rechecked/);
  assert.deepEqual(json(files,'provenance.json').source_identity,{instance:fixture.instance_id,epoch:fixture.capture_epoch,request:record.id,target:record.target_id,started:record.started_monotonic_ms});
  assert.equal(json(files,'requests/request-001.json').body,record.request.body.text);
  const repeat=join(directory,'repeat.zip');await exportFixture(document,repeat);
  assert.deepEqual(await readFile(output),await readFile(repeat),'Same saved response produces the same ZIP');
  assert.equal(await readFile(input,'utf8'),JSON.stringify(document));
  const redacted=join(directory,'redacted.zip');await exportFixture(document,redacted,'redacted_copy');
  const redactedFiles=await archive(redacted), redactedEvidence=json(redactedFiles,'evidence/capture.json');
  assert.equal(redactedEvidence.record.request.body.text,'');assert.equal(redactedEvidence.record.request.headers[1][1],'<redacted>');
  assert.equal(json(redactedFiles,'requests/request-001.json').url,'https://example.test/a%2Fb');
  assert.deepEqual(redactedEvidence.coverage.saved_response,evidence.coverage.saved_response);
  assert(!redactedFiles['reb-client-project/evidence/capture.json'].includes('synthetic-only'));

  // Extract only known fixed generator paths, then execute the generated dry run.
  const extracted=join(directory,'extracted');await mkdir(extracted);
  for(const [path,text] of Object.entries(files)) {const destination=join(extracted,path);await mkdir(dirname(destination),{recursive:true});await writeFile(destination,text);}
  const dry=await command(process.execPath,['examples/request-001.mjs'],join(extracted,'reb-client-project'));
  assert.equal(dry.code,0,dry.stderr);assert.equal(JSON.parse(dry.stdout).network_requests,0);
  const redactedSource=join(directory,'redacted-extracted');await mkdir(redactedSource);
  for(const [path,text] of Object.entries(redactedFiles)) {const destination=join(redactedSource,path);await mkdir(dirname(destination),{recursive:true});await writeFile(destination,text);}
  const dryRedacted=await command(process.execPath,['examples/request-001.mjs'],join(redactedSource,'reb-client-project'));
  assert.equal(dryRedacted.code,0,dryRedacted.stderr);assert.equal(JSON.parse(dryRedacted.stdout).ready,false);

  const unsupported=[
    ['missing body',v=>v.request.request.body.state='missing'],['loading body',v=>v.request.request.body.state='loading'],
    ['truncated body',v=>v.request.request.body.truncated=true],['truncated headers',v=>v.request.request.headers_truncated=true],
    ['truncated URL',v=>v.request.url_truncated=true],['binary body',v=>v.request.request.body.base64='AP8='],
    ['multipart',v=>v.request.request.headers[0][1]='multipart/form-data; boundary=synthetic'],
    ['credential header',v=>v.request.request.headers.push(['Cookie','synthetic-only'])],
    ['duplicate headers',v=>v.request.request.headers.push(['content-type','application/json'])],
  ];
  let index=0;
  for(const [label,mutate] of unsupported) {
    const value=copy(document);mutate(value);const path=join(directory,`unsupported-${index++}.zip`);
    const report=await exportFixture(value,path);assert(report.problems.length,label);
    assert.deepEqual(json(await archive(path),'evidence/capture.json').record,value.request,label+' never rewrites evidence');
  }
  const local=copy(document);local.request.url='http://127.0.0.1:'+server.address().port+'/never-send';
  await exportFixture(local,join(directory,'local.zip'));assert.equal(receipts,0,'Export has no network side effect');

  const malformed=[
    ['wrong format',v=>v.format='other'],['unknown envelope key',v=>v.extra=true],['missing selector',v=>delete v.source.instance_id],
    ['request mismatch',v=>v.source.request_id='different'],['target mismatch',v=>v.source.target_id='different'],
    ['timestamp mismatch',v=>v.source.started_monotonic_ms=123],['unsafe epoch',v=>v.source.capture_epoch=9007199254740992],
    ['malformed headers',v=>v.request.request.headers=[['X']]],['missing body state',v=>delete v.request.request.body.state],
    ['missing truncation flag',v=>delete v.request.url_truncated],['bad initiator',v=>v.request.initiator.sites={}],
    ['oversized header aggregate',v=>v.request.request.headers=Array.from({length:9},()=>['X','x'.repeat(8192)])],
  ];
  for(const [label,mutate] of malformed) {
    const value=copy(document);mutate(value);await writeFile(input,JSON.stringify(value));
    const path=join(directory,`invalid-${index++}.zip`), failure=await run('--input',input,'--output',path);
    assert.notEqual(failure.code,0,label);assert(!failure.stderr.includes(record.url),label+' diagnostic is capture-free');
    await assert.rejects(stat(path),{code:'ENOENT'});
  }
  for(const value of ['{"a":1,"a":2}',JSON.stringify(document).replace('"format":','"format":"duplicate","format":'),
    JSON.stringify(document).replace('synthetic-only','\\ud800'),
    JSON.stringify(document).replace('\"capture_epoch\":1','\"capture_epoch\":1e-400'),
    JSON.stringify(document).replace('\"debugger_generation\":42','\"debugger_generation\":42.000000000000001'),'{"value":'+ '['.repeat(66)+'0'+']'.repeat(66)+'}',
    Buffer.from([0xff]),'x'.repeat(1048577)]) {
    await writeFile(input,value);const path=join(directory,`invalid-${index++}.zip`);
    assert.notEqual((await run('--input',input,'--output',path)).code,0);await assert.rejects(stat(path),{code:'ENOENT'});
  }
  await writeFile(input,JSON.stringify(document));
  const bytes=await readFile(output);assert.notEqual((await run('--input',input,'--output',output)).code,0);assert.deepEqual(await readFile(output),bytes);
  assert.notEqual((await run('--input',input,'--output',input)).code,0);assert.equal(await readFile(input,'utf8'),JSON.stringify(document));
  const victim=join(directory,'victim'), outputLink=join(directory,'output-link');await writeFile(victim,'untouched');await symlink(victim,outputLink);
  assert.notEqual((await run('--input',input,'--output',outputLink)).code,0);assert.equal(await readFile(victim,'utf8'),'untouched');
  const inputLink=join(directory,'input-link');await symlink(input,inputLink);
  assert.notEqual((await run('--input',inputLink,'--output',join(directory,'link.zip'))).code,0);
  assert.notEqual((await run('--input',directory,'--output',join(directory,'dir.zip'))).code,0);
  assert.notEqual((await run('--input',input,'--output',directory)).code,0);
  assert.notEqual((await run('--input',input,'--output',join(directory,'absent','project.zip'))).code,0);
  for(const args of [[],['--input',input,'--output',output,'--send'],['--input',input,'--input',input,'--output',output],['--input',input,'--output','-'],['--input',input,'--output',output,'--mode','guess']]) assert.notEqual((await run(...args)).code,0);
  assert(!(await readdir(directory)).some(name=>name.startsWith('.reb-client-export-')),'No temporary archives remain');
  assert.equal(receipts,0);
  console.log('PASS offline exact-response export: shared Go/JS generator, deterministic raw/redacted ZIPs, exact identity and unknown coverage, generated dry runs, unsupported evidence, bounded inert input and no-overwrite output');
} finally {
  await new Promise(done=>server.close(done));await rm(directory,{recursive:true,force:true});
}
