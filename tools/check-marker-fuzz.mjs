import assert from 'node:assert/strict';
import {readFile,mkdtemp,writeFile,stat,symlink,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {markerPlan,validatePlan,digest,readMarkerFile,saveMarkerFile} from './marker-fuzz.mjs';
// A text patch can land in a similar brace context while remaining valid JSON.
// Verify semantic schema ownership and every local reference on the exact base.
const spec=JSON.parse(await readFile(new URL('../protocol/openapi.json',import.meta.url),'utf8'));
const schemas=spec.components.schemas;
for(const name of ['MarkerFuzzCaseGuard','MarkerFuzzExpectedExecution']){
  assert.equal(schemas[name]?.type,'object',`${name} must live in components.schemas`);
  assert(schemas[name].required.includes('instance_id'));
}
const actions=schemas.DebuggerAction.oneOf;
assert.equal(actions.find(v=>v.properties.action.const==='run_repeater_request').properties.marker_fuzz.$ref,'#/components/schemas/MarkerFuzzCaseGuard');
assert.equal(actions.find(v=>v.properties.action.const==='cancel_repeater_request').properties.expected_execution.$ref,'#/components/schemas/MarkerFuzzExpectedExecution');
function references(value){
  if(!value || typeof value!=='object')return;
  if(typeof value.$ref==='string' && value.$ref.startsWith('#/')){
    let target=spec;
    for(const key of value.$ref.slice(2).split('/'))target=target?.[key.replace(/~1/g,'/').replace(/~0/g,'~')];
    assert.notEqual(target,undefined,`Unresolved local OpenAPI reference: ${value.$ref}`);
  }
  for(const item of Object.values(value))references(item);
}
references(spec);

const clone=v=>structuredClone(v);
function input(){return {format:'reb-marker-fuzz-input-v1',source_id:'authored-loopback-fixture',scope:{instance_id:'backend-one',target_id:'fixture-target',experiment_id:1,session_id:1},
  request:{url:'http://127.0.0.1:8000/echo?q=REB_MARKER',method:'GET',headers:{accept:'*/*'},body:''},marker:{field:'query',literal:'REB_MARKER'},
  payloads:['','snow 雪 & next=1','{{literal}}'],limits:{interval_ms:250,request_timeout_ms:1000,deadline_ms:5000,max_request_bytes:65536}};}
const original=input(),plan=markerPlan(original);
assert.equal(plan.cases[1].request.url,'http://127.0.0.1:8000/echo?q=snow%20%E9%9B%AA%20%26%20next%3D1');
assert.equal(plan.cases[2].request.url,'http://127.0.0.1:8000/echo?q=%7B%7Bliteral%7D%7D');
assert.equal(plan.request_sha256,digest(original.request));assert.equal(validatePlan(plan,plan.plan_sha256).cases.length,3);
for(const mutate of [v=>v.payloads.push('changed'),v=>v.request.url+='&another=REB_MARKER',v=>v.request.url='http://127.0.0.1:8000/?REB_MARKER=x',
  v=>v.request.url='http://127.0.0.1:8000/REB_MARKER',v=>v.request.url='http://user@127.0.0.1:8000/?q=REB_MARKER',v=>v.request.url+='#',
  v=>v.request.url='http://127.0.0.1:8000/?q=%52EB_MARKER',v=>v.request.headers.cookie='synthetic',v=>v.request.body='GET body',
  v=>v.payloads=Array(17).fill('a'),v=>v.payloads=['a'.repeat(2049)],v=>v.payloads=['\ud800'],v=>v.limits.interval_ms=249,
  v=>v.limits.deadline_ms=60001,v=>v.limits.max_request_bytes=1,v=>v.scope.session_id=0]) {
  const value=clone(original);mutate(value);if(value.payloads.length===4)assert.throws(()=>validatePlan({...plan,input:value},plan.plan_sha256));else assert.throws(()=>markerPlan(value));
}
const body=clone(original);body.marker.field='body';body.request={url:'http://127.0.0.1:8000/echo',method:'POST',headers:{'content-type':'text/plain; charset=utf-8'},body:'雪😀:REB_MARKER:end'};
const literal=markerPlan(body);assert.deepEqual(literal.marker_range,{field:'body',start:8,end:18});assert.equal(literal.cases[2].request.body,'雪😀:{{literal}}:end');
const escaped=clone(body);escaped.payloads=Array(16).fill('\u0000'.repeat(2048));escaped.request.body='\u0000'.repeat(1900)+'REB_MARKER';assert.throws(()=>markerPlan(escaped));
const overlap=clone(body);overlap.marker.literal='ABA';overlap.request.body='ABABA';assert.throws(()=>markerPlan(overlap));
const wide=clone(body);wide.payloads=Array(16).fill('a'.repeat(2048));wide.request.body='a'.repeat(7000)+'REB_MARKER';assert.throws(()=>markerPlan(wide));

// Real CLI files prove private offline preparation and unconditional execution refusal.
const directory=await realpath(await mkdtemp(join(tmpdir(),'reb-marker-fuzz-test-')));
async function cli(name,args,env=process.env){return new Promise(resolve=>{const child=spawn(process.execPath,[new URL(name,import.meta.url).pathname,...args],{env,stdio:['ignore','pipe','pipe']});let out='',err='';child.stdout.on('data',v=>out+=v);child.stderr.on('data',v=>err+=v);child.on('close',code=>resolve({code,out,err}));});}
try{
  const authored=join(directory,'input.json'),prepared=join(directory,'plan.json'),reportPath=join(directory,'report.json');
  await writeFile(authored,JSON.stringify(original));let result=await cli('prepare-marker-fuzz.mjs',['--input',authored,'--output',prepared]);assert.equal(result.code,0,result.err);
  assert.equal((await stat(prepared)).mode&0o777,0o600);const saved=await readMarkerFile(prepared);assert.equal(saved.plan_sha256,plan.plan_sha256);
  await assert.rejects(()=>saveMarkerFile(prepared,plan));await symlink(authored,join(directory,'symlink.json'));await assert.rejects(()=>readMarkerFile(join(directory,'symlink.json')));
  await writeFile(join(directory,'duplicate.json'),'{"x":1,"x":2}');await assert.rejects(()=>readMarkerFile(join(directory,'duplicate.json')));
  // Preload tripwires run inside the CLI process, not the parent test launcher.
  // Any network, browser subprocess, or plan read attempt changes its exit status.
  const guard=join(directory,'no-effects.cjs');
  await writeFile(guard,`
const deny=()=>{process.exit(97);};
for(const [module,names] of [
  ['node:http',['request','get']],['node:https',['request','get']],
  ['node:net',['connect','createConnection']],['node:tls',['connect']],
  ['node:child_process',['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']],
  ['node:fs/promises',['open','readFile','writeFile']]
]){const api=require(module);for(const name of names)api[name]=deny;}
require('node:net').Socket.prototype.connect=deny;
globalThis.fetch=deny;
require('node:module').syncBuiltinESMExports();
`);
  const env={...process.env,NODE_OPTIONS:'',NODE_USE_ENV_PROXY:'1',HTTP_PROXY:'http://127.0.0.1:1'};
  for(const args of [[],['--help'],['--plan',prepared,'--arm',plan.plan_sha256,'--base-url','http://127.0.0.1:8765','--report',reportPath],
    ['--plan',join(directory,'missing.json'),'--arm','0'.repeat(64),'--base-url','http://127.0.0.1:8765']]){
    const result=await new Promise((resolve,reject)=>{
      const child=spawn(process.execPath,['--require',guard,new URL('run-marker-fuzz.mjs',import.meta.url).pathname,...args],{env,stdio:['ignore','pipe','pipe']});
      let out='',err='';child.stdout.on('data',v=>out+=v);child.stderr.on('data',v=>err+=v);child.on('error',reject);child.on('close',code=>resolve({code,out,err}));
    });
    assert.equal(result.code,1,result.err);assert.equal(result.out,'');
    assert.match(result.err,/Marker execution is unavailable/);assert.match(result.err,/no fallback/);
  }
  await assert.rejects(()=>stat(reportPath),{code:'ENOENT'});
}finally{await rm(directory,{recursive:true,force:true});}
console.log('PASS marker fuzz: offline literal/query/UTF-8 plans, limits, integrity, private/no-overwrite files, and immediate no-network/no-spawn execution refusal');
