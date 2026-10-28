#!/usr/bin/env node
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,stat,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {network} from './saved-traffic-fixture.mjs';
import {readCapture} from './captured-request-export.mjs';
import {harProject} from './har-project.mjs';
const available=value=>({state:'available',value}),unavailable=()=>({state:'unavailable'});
const fixture=network(),row=fixture.requests[0];
row.url='https://example.test/a?x=1&x=2&empty=&plus=a+b#fragment';row.protocol='h2';row.started_monotonic_ms=1000;
row.request.headers=[['Content-Type','application/json; note="synthetic-private"'],['Cookie','synthetic-private']];
row.response.headers=[['Content-Type','application/octet-stream'],['Set-Cookie','synthetic-private']];
row.timing_evidence={format:'reb-network-timing-v1',request_monotonic_seconds:available(1),request_wall_seconds:available(1700000000.123456),response_monotonic_seconds:available(1.06),completion_monotonic_seconds:available(1.1),
  response_observed:true,completion_observed:true,response_source:'responseReceived',completion_source:'loadingFinished',duplicate_response:false,duplicate_completion:false,response_after_completion:false,
  resource_timing:{state:'available',fields:{requestTime:available(1.005),proxyStart:unavailable(),proxyEnd:unavailable(),workerStart:unavailable(),dnsStart:available(1),dnsEnd:available(3),connectStart:available(4),connectEnd:available(10),sslStart:available(5),sslEnd:available(9),sendStart:available(12),sendEnd:available(15),receiveHeadersStart:available(40),receiveHeadersEnd:available(45)}}};
const document={format:'reb-network-request-v1',source:{instance_id:fixture.instance_id,capture_epoch:fixture.capture_epoch,request_id:row.id,target_id:row.target_id,started_monotonic_ms:row.started_monotonic_ms},debugger_generation:42,request:row};
const directory=await mkdtemp(join(tmpdir(),'reb-har-test-')),input=join(directory,'input.json'),output=join(directory,'output.har');
const script=new URL('./export-captured-har.mjs',import.meta.url).pathname;
// No wall-clock timeout: the CLI reads bounded local files and always exits, so
// the check waits for that exit. A timer only turned a machine stall into a
// failure; a real hang is bounded by the CI job timeout.
const run=(...args)=>spawnSync(process.execPath,[script,...args],{encoding:'utf8'});
const clone=value=>JSON.parse(JSON.stringify(value));
try {
  await writeFile(input,JSON.stringify(document));
  assert.equal(run('--help').status,0);
  const result=run('--input',input,'--output',output);assert.equal(result.status,0,result.stderr);
  assert.equal(JSON.parse(result.stdout).network_requests,0);assert(!result.stdout.includes('synthetic-private'));
  assert.equal((await stat(output)).mode&0o777,0o600);
  const har=JSON.parse(await readFile(output,'utf8')),entry=har.log.entries[0];
  assert.equal(har.log.version,'1.2');assert.equal(entry.startedDateTime,'2023-11-14T22:13:20.123Z');
  assert(Math.abs(entry.time-100)<1e-9);assert(Math.abs(entry.timings.blocked-9)<1e-9);
  assert.equal(entry.timings.dns,2);assert.equal(entry.timings.connect,6);assert.equal(entry.timings.ssl,4);assert.equal(entry.timings.send,3);assert.equal(entry.timings.wait,25);
  assert(Math.abs(entry.timings.receive-55)<1e-9);
  assert.equal(entry.response.content.encoding,'base64');assert.equal(entry.response.content.size,5);assert.equal(entry.response.content.text,'AP8BAgM=');
  assert.equal(entry.request.url,'https://example.test/a?x=1&x=2&empty=&plus=a+b');
  assert.deepEqual(entry.request.queryString,[{name:'x',value:'1'},{name:'x',value:'2'},{name:'empty',value:''},{name:'plus',value:'a b'}]);
  assert.equal(entry.request.bodySize,-1);assert.equal(entry.response.bodySize,-1);assert.equal(entry.request.headersSize,-1);
  assert.deepEqual(entry._reb.source_identity,{instance:fixture.instance_id,epoch:fixture.capture_epoch,request:row.id,target:row.target_id,started:1000});
  assert.equal(entry._reb.coverage.dropped,null);assert.deepEqual(entry._reb.timing_evidence,row.timing_evidence);
  assert.equal(entry.request.postData.text,row.request.body.text);assert.equal(entry.response.headers[1].value,'synthetic-private');
  const source=await readCapture(input),before=JSON.stringify(source);
  assert.deepEqual(harProject(source).document,har);assert.equal(JSON.stringify(source),before);
  const redacted=harProject(source,'redacted_copy');assert(!redacted.bytes.toString().includes('synthetic-private'));assert.equal(redacted.document.log.entries[0].request.queryString.length,0);
  assert(!Object.hasOwn(redacted.document.log.entries[0].response.content,'text'));assert.equal(JSON.stringify(source),before);
  assert.notEqual(run('--input',input,'--output',output).status,0);assert.deepEqual(JSON.parse(await readFile(output,'utf8')),har);
  const link=join(directory,'link.json');await symlink(input,link);assert.notEqual(run('--input',link,'--output',join(directory,'link.har')).status,0);
  const cases=[
    value=>delete value.timing_evidence,
    value=>value.timing_evidence.request_wall_seconds={state:'missing'},
    value=>value.timing_evidence.completion_monotonic_seconds=available(0.5),
    value=>value.timing_evidence.response_monotonic_seconds=available(1.01),
    value=>value.timing_evidence.resource_timing.fields.sendEnd=available(1),
    value=>value.timing_evidence.resource_timing.fields.sendStart={state:'missing'},
    value=>value.timing_evidence.resource_timing.fields.dnsStart={state:'missing'},
    value=>value.timing_evidence.resource_timing.fields.sslEnd=available(12),
    value=>value.timing_evidence.resource_timing.fields.workerStart=available(0),
    value=>value.timing_evidence.duplicate_completion=true,
    value=>value.timing_evidence.response_after_completion=true,
    value=>value.timing_evidence.completion_source='redirectRequest',
    value=>value.timing_evidence.request_monotonic_seconds=available(0),
    value=>value.state='failed',value=>value.state='pending',value=>value.from_disk_cache=true,value=>value.from_service_worker=true,
    value=>value.response.body.truncated=true,value=>value.response.body.state='missing',value=>value.response.headers_truncated=true,
    value=>value.response.body.base64='broken',value=>value.request.body.base64='eA==',value=>value.url='https://example.test/?bad=%FF',value=>value.protocol='unknown',
  ];
  for(const mutate of cases) {const changed=clone(source);mutate(changed.evidence.record);assert.throws(()=>harProject(changed),/HAR export unsupported/);}
  for(const mutate of [value=>value.extra=true,value=>value.request_wall_seconds.value=-1,value=>value.resource_timing.fields.future=available(1)]) {
    const changed=clone(document);mutate(changed.request.timing_evidence);await writeFile(input,JSON.stringify(changed));
    await assert.rejects(()=>readCapture(input));
  }
  const textual=clone(source);textual.evidence.record.response.body.base64='';textual.evidence.record.response.body.text='雪';
  for(const type of ['application/json','text/plain; charset="UTF-8"','application/json; note="a;b"; charset=utf8']) {
    textual.evidence.record.response.headers=[['Content-Type',type]];
    assert.equal(harProject(textual).document.log.entries[0].response.content.size,3);
  }
  for(const type of ['application/json; charset=','application/json; charset=utf-8; charset=','application/json; charset*=utf-16',
    'application/json; charset=utf-8; charset=utf8','text/plain; charset="utf-8','text/plain','text/plain; charset=utf-16']) {
    textual.evidence.record.response.headers=[['Content-Type',type]];
    assert.throws(()=>harProject(textual),/HAR export unsupported/);
  }
  const reused=clone(source);for(const field of ['dnsStart','dnsEnd','connectStart','connectEnd','sslStart','sslEnd'])reused.evidence.record.timing_evidence.resource_timing.fields[field]=unavailable();
  const reuse=harProject(reused).document.log.entries[0];assert.equal(reuse.timings.connect,-1);assert.equal(reuse.timings.ssl,-1);assert(Math.abs(reuse.time-100)<1e-9);
  console.log('PASS offline HAR CLI, exact identity, raw/redacted copies, binary content, disjoint phase accounting, TLS overlap, unavailable/reversed/duplicate timing refusals and atomic no-overwrite publication');
} finally {await rm(directory,{recursive:true,force:true});}
