#!/usr/bin/env node
// Authored loopback fixtures only. No captured credentials or external target requests.
import assert from 'node:assert/strict';
import {readFile, writeFile, mkdir, mkdtemp, rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join, resolve, dirname} from 'node:path';
import {runInNewContext} from 'node:vm';
import {network} from './traffic-capture-qa.mjs';

const root = resolve(new URL('..',import.meta.url).pathname);
const code = await Promise.all(['evidence_models.js','traffic_view.js','api_catalog.js','captured_client.js'].map(name=>readFile(join(root,'apps/research-ui',name),'utf8')));
const globals = {TextEncoder,TextDecoder,Uint8Array,URL,atob,btoa,AbortController,setTimeout,clearTimeout};
const api = runInNewContext(code.join('\n')+'\n;({requestsFromDebuggerNetwork,capturedClientCapture,capturedClientRun,capturedClientProject,capturedClientZip,capturedClientIssues,capturedClientSend})',globals);
const copy = value => JSON.parse(JSON.stringify(value));
const inputBody = '\ufeff雪\r\n{"duplicate":1,"duplicate":2,"inert":"${process.exit()} ` </script>"}';
function fixture(url = 'https://example.test/a%2Fb?x=1&%78=2&empty=&q=a+b&q=a%20b') {
  const value = network(); value.requests = value.requests.slice(0,1);
  const record = value.requests[0]; record.url=url;record.document_url=url;record.error_text='';
  record.request.headers=[['Content-Type','application/json; charset=utf-8'],['X-Authored','exact-value']];
  record.request.body.text=inputBody;record.response.body.base64='';record.response.body.text='response-secret';
  return value;
}
const requests = value => api.requestsFromDebuggerNetwork(value);
const capture = value => api.capturedClientCapture(requests(value)[0]);
const base = fixture(), original = JSON.stringify(base), source = capture(base);
assert.deepEqual(copy(source.input),{method:'POST',url:base.requests[0].url,headers:base.requests[0].request.headers,body:inputBody,timeout_ms:15000});
assert.equal(source.problems.length,0);assert.equal(source.templateProblems.length,0);
const raw = api.capturedClientProject(source,'raw'), redacted = api.capturedClientProject(source,'redacted_copy');
const file = (project,path) => project.files.find(item=>item.path==='reb-client-project/'+path).text;
assert.deepEqual(JSON.parse(file(raw,'evidence/capture.json')).record,base.requests[0]);
assert.deepEqual(JSON.parse(file(raw,'requests/request-001.json')),copy(source.input));
assert.deepEqual([...raw.bytes],[...api.capturedClientProject(source,'raw').bytes],'ZIP is deterministic');
assert.equal(JSON.stringify(base),original,'Export does not rewrite retained data');
assert(!file(redacted,'requests/request-001.json').includes('exact-value'));
assert(!file(redacted,'requests/request-001.json').includes('duplicate'));
assert.equal(JSON.parse(file(redacted,'requests/request-001.json')).url,'https://example.test/a%2Fb');
assert(!file(redacted,'evidence/capture.json').includes('response-secret'));
assert.equal(raw.files.length,15);assert(raw.files.some(item=>item.path==='reb-client-project/go/services/service001.go'));
assert(raw.files.every(item=>!item.path.includes('example.test')&&!item.path.includes('a%2F')));

const problems = [
  ['duplicate header',value=>value.requests[0].request.headers.push(['content-type','text/plain'])],
  ['Authorization',value=>value.requests[0].request.headers.push(['Authorization','synthetic-only'])],
  ['Accept-Charset',value=>value.requests[0].request.headers.push(['Accept-Charset','utf-8'])],
  ['legacy Cookie2',value=>value.requests[0].request.headers.push(['Cookie2','synthetic-only'])],
  ['method override',value=>value.requests[0].request.headers.push(['X-HTTP-Method-Override','POST, trace'])],
  ['Cookie',value=>value.requests[0].request.headers.push(['Cookie','synthetic-only'])],
  ['Host',value=>value.requests[0].request.headers.push(['Host','example.test'])],
  ['Content-Length',value=>value.requests[0].request.headers.push(['Content-Length','1'])],
  ['Transfer-Encoding',value=>value.requests[0].request.headers.push(['Transfer-Encoding','chunked'])],
  ['forbidden method',value=>value.requests[0].method='CONNECT'],
  ['non-byte header',value=>value.requests[0].request.headers.push(['X-Emoji','😀'])],
  ['header whitespace',value=>value.requests[0].request.headers.push(['X-Space',' value '])],
  ['multipart',value=>value.requests[0].request.headers[0][1]='multipart/form-data; boundary=synthetic'],
  ['non-UTF8 charset',value=>value.requests[0].request.headers[0][1]='text/plain; charset=iso-8859-1'],
  ['encoded body',value=>value.requests[0].request.headers.push(['Content-Encoding','gzip'])],
  ['unknown binary media',value=>value.requests[0].request.headers[0][1]='application/protobuf'],
  ['binary media',value=>value.requests[0].request.headers[0][1]='application/octet-stream'],
  ['binary body',value=>value.requests[0].request.body.base64='AP8='],
  ['inconsistent empty body',value=>value.requests[0].request.body.state='empty'],
  ['missing body',value=>value.requests[0].request.body.state='missing'],
  ['loading body',value=>value.requests[0].request.body.state='loading'],
  ['truncated body',value=>value.requests[0].request.body.truncated=true],
  ['truncated headers',value=>value.requests[0].request.headers_truncated=true],
  ['truncated method',value=>value.requests[0].method_truncated=true],
  ['truncated URL',value=>value.requests[0].url_truncated=true],
  ['GET body',value=>value.requests[0].method='GET'],
  ['mixed case method',value=>value.requests[0].method='pOsT'],
  ['userinfo URL',value=>value.requests[0].url='https://user:pass@example.test/a'],
  ['fragment URL',value=>value.requests[0].url='https://example.test/a#fragment'],
  ['WebSocket URL',value=>value.requests[0].url='wss://example.test/a'],
  ['body size',value=>value.requests[0].request.body.text='x'.repeat(65537)],
  ['unpaired surrogate',value=>value.requests[0].request.body.text='\ud800'],
];
for (const [name,mutate] of problems) {
  const value = fixture();mutate(value);const selected=capture(value);
  assert(selected.problems.length>0,name);
  assert.deepEqual(JSON.parse(file(api.capturedClientProject(selected,'raw'),'evidence/capture.json')).record,value.requests[0],name+' evidence stays exact');
}
for (const text of ['{{variable}}','{{=escaped}}']) {
  const value=fixture();value.requests[0].request.body.text=text;const selected=capture(value);
  assert.equal(selected.problems.length,0);assert.equal(selected.templateProblems.length,1);
  assert.equal(JSON.parse(file(api.capturedClientProject(selected,'raw'),'requests/request-001.json')).body,text);
}
for (const path of ['../escape','reb-client-project/../escape','reb-client-project/.','reb-client-project/a\\b','reb-client-project/a:stream','reb-client-project/trailing.','reb-client-project//empty']) {
  assert.throws(()=>api.capturedClientZip([{path,text:'x'}]),/Unsafe/,path);
}
assert.throws(()=>api.capturedClientZip([{path:'reb-client-project/a',text:'a'},{path:'reb-client-project/a',text:'b'}]),/repeated/);
assert.throws(()=>api.capturedClientZip(Array.from({length:17},(_,i)=>({path:'reb-client-project/'+i,text:''}))),/count/);
assert.throws(()=>api.capturedClientZip([{path:'reb-client-project/a',text:'x'.repeat(1048577)}]),/bound/);
assert.throws(()=>api.capturedClientProject(source,'other'),/Choose/);
const run={id:7,started_at_ms:123,request:{...copy(source.input),headers:source.input.headers.map(([name,value])=>({name,value}))},
  resolved_request:{...copy(source.input),headers:source.input.headers.map(([name,value])=>({name,value}))},
  response:{status:200,url:source.input.url,headers:[{name:'X-Response',value:'response-secret'}],body:'response-secret',body_sha256:'digest',error:'private-error'}};
const runSource=api.capturedClientRun(run,'isolated-context',{identity:source.identity,evidence:source.evidence,relation:'Reviewed draft source; client normalization applies.'});
const runRaw=api.capturedClientProject(runSource,'raw'),runCopy=api.capturedClientProject(runSource,'redacted_copy');
assert.deepEqual(JSON.parse(file(runRaw,'evidence/repeater-run.json')).run,copy(run));
assert.deepEqual(JSON.parse(file(runRaw,'evidence/capture.json')).record,base.requests[0]);
assert(!file(runCopy,'evidence/repeater-run.json').includes('response-secret'));
assert(!file(runCopy,'evidence/repeater-run.json').includes('private-error'));
assert.equal(api.capturedClientProject(api.capturedClientRun(run,'ctx'),'raw').provenance.capture_identity,null);
console.log('PASS exact capture/run evidence, structured project layout, redacted-copy immutability, unsupported input matrix and deterministic safe bounded ZIP');

await checkGeneratedProject();
await checkConfiguredProject();
if(process.argv.includes('--go')) await checkGeneratedGoProject();
if(process.argv.includes('--mimic')) await checkGeneratedMimicProject();
await checkController();
await checkRepeaterIntegration();

async function checkRepeaterIntegration() {
  const app=await readFile(join(root,'apps/research-ui/app.js'),'utf8');
  const section=(start,end)=>{const begin=app.indexOf(start),finish=app.indexOf(end,begin+start.length);assert(begin>=0&&finish>begin);return app.slice(begin,finish);};
  const state={requests:requests(fixture()),selectedRequestId:'synthetic-json',repeaterDraftDirty:true,repeaterDraftRevision:1,
    repeaterCaptureSource:{source,context:'ctx',importRevision:1}};
  const elements=Object.fromEntries(['Url','Method','Headers','Body','Timeout'].map(name=>['repeaterRequest'+name,{value:''}]));
  Object.assign(elements.repeaterRequestUrl,{value:source.input.url});Object.assign(elements.repeaterRequestMethod,{value:'POST'});
  Object.assign(elements.repeaterRequestHeaders,{value:JSON.stringify(Object.fromEntries(source.input.headers))});
  Object.assign(elements.repeaterRequestBody,{value:inputBody});Object.assign(elements.repeaterRequestTimeout,{value:'15000'});
  let textarea='';Object.defineProperty(elements.repeaterRequestBody,'value',{get:()=>textarea,set:value=>{textarea=value.replace(/\r\n?/g,'\n');}});
  elements.repeaterRequestBody.value=inputBody;state.repeaterBodyRepresentation={text:inputBody,display:elements.repeaterRequestBody.value};
  let execution=0;const payloads=[];
  const production=runInNewContext(section('      function prefillRepeaterRequest(', '      function setRepeaterEditorTab(')+
    section('      async function runRepeaterRequest()', '      async function compareRepeaterResponses()')+
    '\n;({prefillRepeaterRequest,loadRepeaterHistoryEntry,runRepeaterRequest})',{
    state,elements,URL,refreshRepeaterStructuredEditors(){},renderRepeaterVariableStatus(){},renderRepeater(){},renderExperiment(){},
    repeaterSubmissionKey:()=> 'submission',experimentContextKey:()=> 'ctx',repeaterState:()=>({history:execution?[{id:execution}]:[]}),
    currentExperimentReceipt:value=>value,applyRepeaterVariables:async()=>({}),parseExperimentHeaders:text=>Object.entries(JSON.parse(text)).map(([name,value])=>({name,value})),
    repeaterHeaderObject:headers=>Object.fromEntries(headers.map(({name,value})=>[name,value])),
    runExperimentAction:async payload=>{payloads.push(payload);return {repeater:{active_execution:{execution_id:++execution},history:[]}};}
  });
  await production.runRepeaterRequest();assert.equal(payloads.length,1);assert.equal(payloads[0].body,inputBody);
  assert.equal(state.repeaterDraftDirty,false);production.prefillRepeaterRequest();
  assert.equal(elements.repeaterRequestBody.value,inputBody.replace(/\r\n?/g,'\n'),'Textarea display uses normalized line endings');
  assert.equal(state.repeaterBodyRepresentation.text,inputBody,'Retained request preserves original CRLF');
  assert.equal(state.repeaterCaptureRuns.source,source);assert.equal(state.repeaterCaptureRuns.links[0].id,1);
  state.repeaterDraftRevision++;state.repeaterDraftDirty=true;await production.runRepeaterRequest();
  assert.equal(state.repeaterCaptureRuns.links.length,2);assert.match(state.repeaterCaptureRuns.links[1].relation,/edited after/);
  production.loadRepeaterHistoryEntry({...run,id:1});
  assert.equal(state.repeaterCaptureSource,null,'Selecting another draft retires its active import');
  production.prefillRepeaterRequest();assert.equal(elements.repeaterRequestBody.value,inputBody.replace(/\r\n?/g,'\n'),'History display is not overwritten by ordinary Traffic prefill');
  assert.equal(state.repeaterBodyRepresentation.text,inputBody);
  assert.equal(state.repeaterCaptureRuns.links.length,2,'Inspecting history retains established capture provenance');
  const getRunCapture=runInNewContext('('+section('        getRunCapture: (run,context) => {','        openRepeater:').trim().replace(/^getRunCapture: /,'').replace(/,$/, '')+')',{state});
  assert.equal(getRunCapture({id:1},'ctx').evidence,source.evidence);
  assert.equal(getRunCapture({id:2},'ctx').evidence,source.evidence);
  assert.equal(getRunCapture({id:3},'ctx'),null);assert.equal(getRunCapture({id:1},'replacement'),null);
  assert.match(section('      function clearExperimentLifetime()', '      function '),/state\.repeaterCaptureRuns = null/);
  state.repeaterBodyRepresentation=null;await production.runRepeaterRequest();
  assert.equal(payloads.at(-1).body,inputBody.replace(/\r\n?/g,'\n'),'Explicit body edit uses editor text rather than secretly restoring CRLF');
  console.log('PASS production Repeater Send/prefill/history integration: full draft preserved after Send, bounded per-run provenance retained and context mismatches refused');
}

async function command(command,args,cwd,options={}) {
  return new Promise((done,reject)=>{
    const child=spawn(command,args,{cwd,env:options.env ?? process.env,stdio:['ignore','pipe','pipe']}),parts=[],errors=[];
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('Bounded test command timed out'));},options.timeout ?? 15000);
    child.stdout.on('data',part=>parts.push(part));child.stderr.on('data',part=>errors.push(part));child.on('error',reject);
    child.on('close',code=>{clearTimeout(timer);done({code,stdout:Buffer.concat(parts).toString(),stderr:Buffer.concat(errors).toString()});});
  });
}
async function checkGeneratedProject() {
  const seen=[];
  const server=createServer(async (request,response)=>{
    let body='';for await(const part of request)body+=part.toString();seen.push({method:request.method,url:request.url,headers:request.headers,body});
    if(request.url==='/redirect') {response.writeHead(302,{Location:'/unexpected', 'Set-Cookie':'synthetic-only=1'});response.end();return;}
    if(request.url==='/slow') {setTimeout(()=>response.end('late'),250);return;}
    if(request.url==='/large'||request.url==='/exact-limit') {response.end('x'.repeat(request.url==='/large'?65537:65536));return;}
    response.writeHead(200,{'Content-Type':'application/json'});response.end('{"ok":true}');
  });
  await new Promise(done=>server.listen(0,'127.0.0.1',done));
  const origin='http://127.0.0.1:'+server.address().port, directory=await mkdtemp(join(tmpdir(),'reb-client-project-'));
  try {
    const local=capture(fixture(origin+'/a%2Fb?x=1&%78=2&empty=&q=a+b&q=a%20b'));
    const project=api.capturedClientProject(local,'raw');
    await writeFile(join(directory,'project.zip'),project.bytes);
    // Python's independent standard ZIP reader verifies names, stored sizes and CRCs.
    const unzip=await command('python3',['-c',
      'import sys,zipfile,pathlib\np=pathlib.Path(sys.argv[1])\nwith zipfile.ZipFile(p/"project.zip") as z:\n assert z.testzip() is None\n assert all(n.startswith("reb-client-project/") and ".." not in n.split("/") for n in z.namelist())\n z.extractall(p)\n print(len(z.namelist()))',directory],root);
    assert.equal(unzip.code,0,unzip.stderr);assert.equal(Number(unzip.stdout),project.files.length);
    const folder=join(directory,'reb-client-project');
    for(const item of project.files)assert.equal(await readFile(join(directory,item.path),'utf8'),item.text);
    for(const script of ['src/client.mjs','src/services/service-001.mjs','examples/request-001.mjs']) {
      const check=await command(process.execPath,['--check',script],folder);assert.equal(check.code,0,check.stderr);
    }
    const execute=(...args)=>command(process.execPath,['examples/request-001.mjs',...args],folder);
    let result=await execute();assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).dry_run,true);assert.equal(seen.length,0);
    result=await execute('--send');assert.notEqual(result.code,0);assert.match(result.stderr,/allowedOrigin/);assert.equal(seen.length,0);
    await writeFile(join(folder,'config.json'),JSON.stringify({allowedOrigin:origin}));
    result=await execute();assert.equal(result.code,0);assert.equal(seen.length,0,'Configuration alone never sends');
    result=await execute('--send');assert.equal(result.code,0,result.stderr);assert.equal(seen.length,1);
    assert.equal(seen[0].method,'POST');assert.equal(seen[0].url,'/a%2Fb?x=1&%78=2&empty=&q=a+b&q=a%20b');
    assert.equal(seen[0].headers['x-authored'],'exact-value');assert.equal(seen[0].headers['content-type'],'application/json; charset=utf-8');assert.equal(seen[0].body,inputBody);
    assert.equal(seen[0].headers.cookie,undefined);assert.equal(seen[0].headers.authorization,undefined);
    const override={...copy(local.input),method:'GET',body:'',headers:[],url:origin+'/redirect'};
    await writeFile(join(folder,'config.json'),JSON.stringify({allowedOrigin:origin,request:override}));
    result=await execute('--send');assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).status,302);assert.equal(seen.length,2,'Redirect never follows across any origin');
    for(const [path,expected] of [['/large','large'],['/exact-limit','exact'],['/slow','timeout']]) {
      await writeFile(join(folder,'config.json'),JSON.stringify({allowedOrigin:origin,request:{...override,url:origin+path,timeout_ms:100}}));
      result=await execute('--send');
      if(expected==='large'||expected==='exact'){assert.equal(result.code,0,result.stderr);const response=JSON.parse(result.stdout);assert.equal(response.body.length,65536);assert.equal(response.body_truncated,expected==='large');}
      else assert.notEqual(result.code,0,'Timeout is surfaced with no retry');
    }
    assert.equal(seen.length,5);
    await writeFile(join(folder,'config.json'),JSON.stringify({allowedOrigin:'https://wrong.test',request:override}));
    result=await execute('--send');assert.notEqual(result.code,0);assert.equal(seen.length,5);
    await writeFile(join(folder,'config.json'),JSON.stringify({allowedOrigin:origin,request:{...override,headers:[['Authorization','synthetic-only']]}}));
    result=await execute('--send');assert.notEqual(result.code,0);assert.equal(seen.length,5,'Credential/transport refusal happens before fetch');
    const redactedProject=api.capturedClientProject(local,'redacted_copy');
    for(const item of redactedProject.files)await writeFile(join(directory,item.path),item.text);
    await writeFile(join(folder,'config.json'),JSON.stringify({allowedOrigin:origin}));
    result=await execute();assert.equal(result.code,0);assert.equal(JSON.parse(result.stdout).ready,false);
    result=await execute('--send');assert.notEqual(result.code,0);assert.equal(seen.length,5,'Redacted inputs require a complete reviewed replacement');
    await writeFile(join(folder,'config.json'),JSON.stringify({allowedOrigin:origin,request:{...override,url:origin+'/configured'}}));
    result=await execute('--send');assert.equal(result.code,0,result.stderr);assert.equal(seen.length,6);
    const output=join(root,'build/client-project-qa');await mkdir(output,{recursive:true});
    await writeFile(join(output,'authored-example.zip'),raw.bytes);
    await writeFile(join(output,'validation.json'),JSON.stringify({status:'passed',fixture:'authored loopback only',requests:seen.length,checks:['ZIP CRC and extraction','generated syntax','default dry run','exact method/query/header/text body','origin gate','manual redirect','timeout without retry','bounded response','credential refusal','redacted explicit configuration']},null,2)+'\n');
  } finally {server.closeAllConnections();await new Promise(done=>server.close(done));await rm(directory,{recursive:true,force:true});}
  console.log('PASS generated project extracted by Python, Node syntax, no network until explicit Send, exact supported request values, redirect/origin/credential guards, timeout and response bound');
}

async function checkGeneratedGoProject() {
  const seen=[];
  const server=createServer(async(request,response)=>{
    const chunks=[];for await(const chunk of request)chunks.push(chunk);
    seen.push({method:request.method,url:request.url,headers:request.headers,body:Buffer.concat(chunks).toString('utf8')});
    if(request.url==='/redirect'){response.writeHead(302,{Location:'http://127.0.0.1:1/never-follow','Set-Cookie':'synthetic-only=1'});response.end();return;}
    if(request.url==='/slow'){setTimeout(()=>response.end('late'),250);return;}
    if(request.url==='/large'||request.url==='/exact-limit'){response.end('x'.repeat(request.url==='/large'?65537:65536));return;}
    response.end('{"ok":true}');
  });
  await new Promise(done=>server.listen(0,'127.0.0.1',done));
  const origin='http://127.0.0.1:'+server.address().port,directory=await mkdtemp(join(tmpdir(),'reb-go-project-'));
  const cwd=join(directory,'reb-client-project/go'),folder=join(directory,'reb-client-project');
  const source=capture(fixture(origin+'/a%2Fb?x=1&%78=2&empty=&q=a+b&q=a%20b'));
  const materialize=async(project)=>{for(const item of project.files){const path=join(directory,item.path);await mkdir(dirname(path),{recursive:true});await writeFile(path,item.text);}};
  const config=async value=>writeFile(join(folder,'config.json'),JSON.stringify(value));
  const environment={...process.env,GOTOOLCHAIN:'local',GOPROXY:'off',GOSUMDB:'off'};
  try {
    await materialize(api.capturedClientProject(source,'raw'));
    const compiler=await command('go',['version'],cwd,{env:environment});assert.equal(compiler.code,0,compiler.stderr);assert.match(compiler.stdout,/go version go1\./,'A real installed Go compiler is required');
    const build=await command('go',['build','-o','../request001','./cmd/request-001'],cwd,{env:environment,timeout:90000});assert.equal(build.code,0,build.stderr);
    await writeFile(join(cwd,'client/client_test.go'),await readFile(join(root,'tools/client-project-go_test.txt'),'utf8'));
    const tests=await command('go',['test','./...'],cwd,{env:environment,timeout:90000});assert.equal(tests.code,0,tests.stdout+tests.stderr);
    const vet=await command('go',['vet','./...'],cwd,{env:environment,timeout:90000});assert.equal(vet.code,0,vet.stderr);
    const execute=(...args)=>command(join(folder,'request001'),args,cwd);
    let result=await execute();assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).dry_run,true);assert.equal(seen.length,0);
    result=await execute('--send');assert.notEqual(result.code,0);assert.match(result.stderr,/allowedOrigin/);assert.equal(seen.length,0);
    result=await execute('--unexpected');assert.notEqual(result.code,0);assert.equal(seen.length,0);
    await config({allowedOrigin:origin});result=await execute();assert.equal(result.code,0);assert.equal(seen.length,0);
    result=await execute('--send');assert.equal(result.code,0,result.stderr);assert.equal(seen.length,1);
    assert.deepEqual(seen[0],{method:'POST',url:'/a%2Fb?x=1&%78=2&empty=&q=a+b&q=a%20b',
      headers:{host:origin.slice(7),'user-agent':'Go-http-client/1.1','content-length':String(Buffer.byteLength(inputBody)),
        'content-type':'application/json; charset=utf-8','x-authored':'exact-value',connection:'close'},body:inputBody});
    assert.equal(seen[0].headers.cookie,undefined);assert.equal(seen[0].headers.authorization,undefined);
    const override={...copy(source.input),method:'GET',body:'',headers:[],url:origin+'/redirect'};
    await config({allowedOrigin:origin,request:override});result=await execute('--send');assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).status,302);assert.equal(seen.length,2);
    for(const path of ['/large','/exact-limit','/slow']){
      await config({allowedOrigin:origin,request:{...override,url:origin+path,timeout_ms:100}});result=await execute('--send');
      if(path==='/slow'){assert.notEqual(result.code,0,'Timeout is reported without retry');assert.match(result.stderr,/check its state/);}
      else {assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).body.length,65536);assert.equal(JSON.parse(result.stdout).body_truncated,path==='/large');}
    }
    assert.equal(seen.length,5);
    for(const [name,mutate] of problems){
      const value=fixture(origin+'/blocked');mutate(value);await materialize(api.capturedClientProject(capture(value),'raw'));
      await config({allowedOrigin:origin});result=await execute('--send');assert.notEqual(result.code,0,name);assert.equal(seen.length,5,name+' must be refused before networking');
    }
    await materialize(api.capturedClientProject(source,'raw'));
    for(const request of [{...override,headers:[['X-Latin1','é']]},{...override,url:origin+'/雪'},
      {...override,headers:[['X-Null',null]]},{...override,headers:[[null,'value']]},{...override,headers:[null]},
      {...override,headers:[['X-Broken']]},{...override,timeout_ms:99},{...override,timeout_ms:30001},
      {...override,headers:[['Content-Type','text/plain; charset=utf-8; charset=ascii']]}]){
      await config({allowedOrigin:origin,request});result=await execute('--send');assert.notEqual(result.code,0,result.stderr);assert.equal(seen.length,5);
    }
    await writeFile(join(folder,'config.json'),' {"request":{"body":"\\ud800"}}');result=await execute();assert.notEqual(result.code,0);
    await config({allowedOrigin:'http://wrong.test',request:override});result=await execute('--send');assert.notEqual(result.code,0);assert.equal(seen.length,5);
    await materialize(api.capturedClientProject(source,'redacted_copy'));await config({allowedOrigin:origin});
    result=await execute();assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).ready,false);
    result=await execute('--send');assert.notEqual(result.code,0);assert.equal(seen.length,5);
    await config({allowedOrigin:origin,request:{...override,url:origin+'/configured',method:'PATCH',body:'😀\r\nexact'}});
    result=await execute('--send');assert.equal(result.code,0,result.stderr);assert.equal(seen.length,6);assert.equal(seen[5].method,'PATCH');assert.equal(seen[5].body,'😀\r\nexact');
    const output=join(root,'build/client-project-qa');await mkdir(output,{recursive:true});
    await writeFile(join(output,'go-validation.json'),JSON.stringify({status:'passed',compiler:compiler.stdout.trim(),fixture:'authored loopback only',requests:seen.length,
      checks:['go build/test/vet','cancellation and honest error accounting','TLS certificate verification','strict shared JSON decoding','default dry run','exact method/raw query/ASCII headers/UTF-8 CRLF body','no cookie/credential sharing','cross-origin redirects stopped','timeout/response bounds','unsupported capture matrix','explicit complete replacement']},null,2)+'\n');
  } finally {server.closeAllConnections();await new Promise(done=>server.close(done));await rm(directory,{recursive:true,force:true});}
  console.log('PASS generated Go build/test/vet and actual net/http loopback fidelity, explicit send/origin/configuration gates, unsupported matrix, redirects, timeout and response bounds');
}

async function checkController() {
  class Node {
    constructor(tag='div'){this.tagName=tag;this.children=[];this.events={};this.dataset={};this.text='';this.open=false;this.disabled=false;this.checked=false;}
    set textContent(value){this.text=String(value);this.children=[];}get textContent(){return this.text+this.children.map(child=>child.textContent).join('');}
    append(...children){this.children.push(...children);}replaceChildren(...children){this.children=children;this.text='';}
    addEventListener(type,handler){this.events[type]=handler;}click(){if(!this.disabled)return this.events.click?.({currentTarget:this});}
    focus(){}remove(){}showModal(){this.open=true;}close(){this.open=false;this.events.close?.();}
  }
  const selectors=['#captured-client-review','[data-client-review-content]','[data-client-review-status]','[data-client-apply]','[data-client-replace]','[data-client-replace-label]','[data-client-close]'];
  const nodes=new Map(selectors.map(selector=>[selector,new Node()]));
  const drafts=new Node(),exports=['raw','redacted_copy'].map(mode=>{const node=new Node();node.dataset.clientCapture=mode;return node;});
  const runExports=['raw','redacted_copy'].map(mode=>{const node=new Node();node.dataset.clientRunExport=mode;return node;});
  let native=false,bridgeMode='saved',bridgeCalls=0;
  const bridge={postMessage:async payload=>{bridgeCalls++;assert.equal(payload.format,'reb-client-project-save-v1');assert.equal(payload.mode,'raw');assert.equal(Buffer.from(payload.base64,'base64').readUInt32LE(0),0x04034b50);if(bridgeMode==='failed')throw new Error('authored save denial');return {status:bridgeMode};}};
  const document={querySelector:selector=>selector==='[data-client-capture="draft"]'?drafts:nodes.get(selector),
    querySelectorAll:selector=>selector==='[data-client-capture]'?[drafts,...exports]:selector==='[data-client-run-export]'?runExports:selector==='[data-client-export-support]'?[]:exports,
    createElement:tag=>new Node(tag),body:new Node(),documentElement:{classList:{contains:()=>native}},events:{},addEventListener(type,handler){this.events[type]=handler;}};
  const dialog=nodes.get('#captured-client-review');dialog.querySelector=selector=>nodes.get(selector);
  const install=runInNewContext(code.join('\n')+'\ninstallCapturedClientWorkflow',{...globals,document,Blob,webkit:{messageHandlers:{rebClientProjectExport:bridge}},URL:class extends URL {static createObjectURL(){downloads++;return 'blob:authored';}static revokeObjectURL(){}},setTimeout:()=>0});
  let current=requests(fixture()),selected=current[0],context='ctx',edit=0,dirty=false,prepared=0,written=0,opened=0,downloads=0,release=null,notice='',createNew=false;
  const options={getRequest:()=>selected,getRequests:()=>current,getRun:()=>null,contextKey:()=>context,editRevision:()=>edit,hasDraft:()=>dirty,
    prepareContext:async()=>{prepared++;if(release==='hold')await new Promise(done=>{release=done;});return {key:'ctx',created:createNew};},
    writeDraft:source=>{written++;assert.equal(source.input.body,inputBody);},openRepeater:()=>opened++,notice:message=>{notice=message;}};
  const workflow=install(options);
  const apply=nodes.get('[data-client-apply]'),replace=nodes.get('[data-client-replace]'),close=nodes.get('[data-client-close]'),status=nodes.get('[data-client-review-status]');
  assert.equal(prepared+written+downloads,0);workflow.sync();assert.equal(prepared+written+downloads,0);
  drafts.click();assert.equal(dialog.open,true);assert.equal(apply.disabled,false);assert.equal(prepared+written+downloads,0);
  assert(nodes.get('[data-client-review-content]').textContent.includes(inputBody));
  close.click();assert.equal(written,0);
  dirty=true;drafts.click();assert.equal(apply.disabled,true);replace.checked=true;replace.events.change();assert.equal(apply.disabled,false);
  await apply.click();assert.equal(prepared,1);assert.equal(written,1);assert.equal(opened,1);assert.equal(dialog.open,false);
  dirty=false;drafts.click();selected.captureRecord.request.body.text='changed';workflow.sync();assert.equal(apply.disabled,true);assert.match(status.textContent,/changed or expired/);close.click();
  current=requests(fixture());selected=current[0];drafts.click();current=[];await apply.click();assert.equal(written,1);close.click();
  current=[selected,{...selected}];drafts.click();assert.equal(dialog.open,false);assert.match(notice,/ambiguous/);
  current=[selected];
  for(const interruption of ['close','edit','context','expiry']) {
    context='ctx';current=[selected];release='hold';drafts.click();const pending=apply.click();assert.equal(apply.disabled,true);
    const before=written;
    if(interruption==='close')close.click();else if(interruption==='edit')edit++;else if(interruption==='context')context='replacement';else current=[];
    release();await pending;assert.equal(written,before,interruption+' rejects late draft write');close.click();
  }
  context='ctx';current=[selected];release=null;drafts.click();
  for(const key of [{key:'F8'},{key:'ArrowLeft',altKey:true},{key:'p',ctrlKey:true},{key:'j',metaKey:true}]) {
    let stopped=false,prevented=false;document.events.keydown({...key,preventDefault:()=>prevented=true,stopImmediatePropagation:()=>stopped=true});assert(stopped&&prevented);
  }
  close.click();exports[0].click();exports[1].click();assert.equal(downloads,2,'Only explicit export clicks create downloads');
  assert.equal(written,1);assert.equal(opened,1);
  createNew=true;
  for(const transition of ['cleared-by-create','new-selection','new-edit']) {
    current=[selected];workflow.sync();release='hold';drafts.click();const pending=apply.click(),before=written;
    if(transition==='new-selection') {current=requests(fixture());current[0].captureOwner=['new-owner',3];selected=current[0];}
    else {current=[];selected=null;if(transition==='new-edit')edit++;}
    release();await pending;
    assert.equal(written,before+(transition==='cleared-by-create'?1:0),transition+' only confirmed source reset can import');
    close.click();current=requests(fixture());selected=current[0];
  }
  createNew=false;release=null;
  native=true;install(options);
  for(const mode of ['saved','canceled','failed']) {bridgeMode=mode;await exports[0].click();assert.match(notice,mode==='saved'?/saved locally/:mode==='canceled'?/canceled.*No archive/:/failed.*authored save denial/);}
  assert.equal(bridgeCalls,3);assert.equal(downloads,2,'Native export never falls through to unsupported blob download');
  console.log('PASS capture review controller: explicit-only creation/export, dirty guard, changed/expired/ambiguous sources, canceled or edited late creation, context ownership and modal shortcut isolation');
}

async function checkConfiguredProject() {
  const seen=[];
  const responses={
    '/stock':[200,'application/json; charset=utf-8','{"sku":"fixture-001","availability":"in_stock","quantity":4,"store":{"a/b":{"~key":true}},"variants":[null]}'],
    '/login':[200,'text/html','<form>Authored login</form>'],
    '/unauthorized':[401,'application/json','{"error":"authored"}'],
    '/malformed':[200,'application/json','{"quantity":'],
    '/duplicate':[200,'application/json','{"quantity":4,"quantity":0}'],
    '/rounding':[200,'application/json','{"quantity":9007199254740991.4}'],
    '/underflow':[200,'application/json','{"quantity":1e-400}'],
    '/exponent':[200,'application/json','{"quantity":4e0}'],
    '/null':[200,'application/json','{"quantity":null}'],
    '/large':[200,'application/json',JSON.stringify({padding:'x'.repeat(65536)})],
    '/surrogate':[200,'application/json','{"quantity":"\\ud800"}'],
    '/redirect':[302,'text/plain',''],
  };
  const server=createServer(async(request,response)=>{
    for await(const chunk of request) { void chunk; }
    seen.push({url:request.url,headers:request.headers});
    if(request.url==='/slow'){setTimeout(()=>response.end('late'),250);return;}
    if(request.url==='/short'){response.writeHead(200,{'Content-Type':'application/json','Content-Length':'100'});response.end('{"part":');return;}
    if(request.url==='/partial-timeout'){response.writeHead(200,{'Content-Type':'application/json'});response.write('{"part":');setTimeout(()=>response.end('1}'),250);return;}
    if(request.url==='/invalid-utf8'){response.writeHead(200,{'Content-Type':'application/json'});response.end(Buffer.from([123,34,120,34,58,34,255,34,125]));return;}
    const [status,type,body]=responses[request.url]??responses['/stock'];
    response.writeHead(status,{'Content-Type':type,...(status===302?{Location:'/unexpected','Set-Cookie':'authored=1'}:{})});response.end(body);
  });
  await new Promise(done=>server.listen(0,'127.0.0.1',done));
  const origin='http://127.0.0.1:'+server.address().port,directory=await mkdtemp(join(tmpdir(),'reb-client-policy-'));
  try {
    const project=api.capturedClientProject(capture(fixture(origin+'/stock')),'raw');
    for(const item of project.files){const path=join(directory,item.path);await mkdir(dirname(path),{recursive:true});await writeFile(path,item.text);}
    const folder=join(directory,'reb-client-project');
    const {sendRequest,parseClientJSON,parseInputJSON}=await import(join(folder,'src/client.mjs'));
    const input={method:'GET',url:origin+'/stock',headers:[],body:'',timeout_ms:15000};
    const provenance={format:'reb-client-project-v1',mode:'raw',problems:[]};
    const valid={configVersion:'reb-client-config-v1',allowedOrigin:origin,transport:{mode:'standard',browserProfile:null},timeoutMs:500,redirectPolicy:'manual',cookiePolicy:'omit',responseChecks:{statuses:[200],contentType:'application/json',jsonFields:[
      {pointer:'/availability',type:'string',equals:'in_stock'},
      {pointer:'/quantity',type:'number',equals:4},
      {pointer:'/store/a~1b/~0key',type:'boolean',equals:true},
      {pointer:'/variants/0',type:'null',equals:null},
    ]}};
    const send=(config=valid,path='/stock',enabled=true)=>sendRequest({...input,url:origin+path},{config,provenance,send:enabled});
    const refuses=async(config,path,code)=>assert.rejects(()=>send(config,path),error=>error.code===code,code+' '+path);
    let result=await send(valid,'/stock',false);assert.equal(result.ready,true);assert.equal(seen.length,0);
    result=await send();assert.equal(result.validation.passed,true);assert.equal(result.network_requests,1);
    for(const [path,code] of [['/login','response_content_type'],['/unauthorized','response_status'],['/malformed','response_json'],['/duplicate','response_json'],['/invalid-utf8','response_json'],['/surrogate','response_json'],['/large','response_truncated']])await refuses(valid,path,code);
    const field=(pointer,type,equals)=>({...valid,responseChecks:{jsonFields:[{pointer,type,...(equals===undefined?{}:{equals})}]}});
    for(const [config,path,code] of [
      [field('/missing','number'),'/stock','response_field_missing'],[field('/quantity','string'),'/stock','response_field_type'],
      [field('/availability','string','out_of_stock'),'/stock','response_field_value'],[field('/quantity','number'),'/null','response_field_type'],
      [field('/quantity','number',9007199254740991),'/rounding','response_field_value'],[field('/quantity','number',0),'/underflow','response_field_value'],
      [field('/quantity','number',4),'/exponent','response_field_value'],[field('/variants/length','number'),'/stock','response_field_missing'],
      [field('/__proto__','object'),'/stock','response_field_missing'],[{...valid,timeoutMs:100},'/slow','timeout'],
    ])await refuses(config,path,code);
    for(const path of ['/short','/partial-timeout']){
      await assert.rejects(()=>send({...valid,timeoutMs:100},path),error=>{
        assert.equal(error.code,path==='/short'?'response_read':'timeout');assert.equal(error.result.network_requests,1);
        assert.equal(error.result.url,origin+path);assert.equal(error.result.status,200);assert.equal(error.result.body,'{"part":');assert.equal(error.result.body_truncated,true);return true;
      });
    }
    const manual={...valid,responseChecks:{}};
    result=await send(manual,'/redirect');assert.equal(result.status,302);assert.equal(result.validation.configured,false);assert.equal(result.validation.passed,false);
    await refuses({...manual,redirectPolicy:'error'},'/redirect','redirect_refused');
    assert(!seen.some(request=>request.url==='/unexpected'));
    await send();assert(seen.every(request=>!request.headers.cookie&&!request.headers.authorization));
    const count=seen.length;
    for(const config of [null,[],{...valid,unknown:true},{...valid,configVersion:'future'},{...valid,timeoutMs:99},{...valid,timeoutMs:30001},
      {...valid,cookiePolicy:'browser'},{...valid,redirectPolicy:'follow'}, {...valid,responseChecks:{statuses:[200,200]}},
      {...valid,responseChecks:{contentType:'application/json; charset=utf-8'}}, {...valid,responseChecks:{jsonFields:[{pointer:'/x~2',type:'string'}]}},
      {...valid,responseChecks:{jsonFields:[{pointer:'/x',type:'number',equals:1.5}]}}, {...valid,responseChecks:{jsonFields:[{pointer:'/x',type:'object',equals:{}}]}},
    ])await refuses(config,'/stock','invalid_config');
    await refuses({...valid,transport:{mode:'browser-profile',browserProfile:{browser:'chrome',version:'133.0.0.0',platform:'linux'}}},'/stock','unsupported_transport');
    await refuses({...valid,transport:{mode:'browser'}},'/stock','unsupported_transport');
    await refuses({...valid,transport:{mode:'standard',browserProfile:{browser:'chrome'}}},'/stock','unsupported_profile');
    await refuses({...valid,allowedOrigin:'https://wrong.test'},'/stock','wrong_origin');assert.equal(seen.length,count);
    for(const text of ['{"x":1,"x":2}','{"x":"\\ud800"}', '1 trailing','{"nested":{"x":1,"\\u0078":2}}'])assert.throws(()=>parseClientJSON(text));
    assert.equal(parseClientJSON('{"__proto__":{"inert":true}}').__proto__.inert,true);
    for(const text of ['{"timeoutMs":100.00000000000000001}','{"equals":9007199254740991.4}','{"equals":1e-400}'])assert.throws(()=>parseInputJSON(text));
    await writeFile(join(folder,'config.json'),JSON.stringify(valid));
    const ambient=await command(process.execPath,['examples/request-001.mjs','--send'],folder,{env:{...process.env,HTTP_PROXY:'http://127.0.0.1:1',HTTPS_PROXY:'http://127.0.0.1:1',ALL_PROXY:'http://127.0.0.1:1',NO_PROXY:'',no_proxy:'',NODE_USE_ENV_PROXY:'1'}});
    assert.equal(ambient.code,0,ambient.stderr);assert.equal(seen.length,count+1,'Explicit direct transport ignores ambient proxy routing');
    await writeFile(join(folder,'config.json'),'{"allowedOrigin":"'+origin+'","allowedOrigin":"'+origin+'"}');
    const duplicate=await command(process.execPath,['examples/request-001.mjs','--send'],folder);assert.notEqual(duplicate.code,0);assert.equal(seen.length,count+1);
    console.log('PASS configurable generated Node client: exact policy gates, authored stock result, status/media/JSON field errors, numeric precision, partial-response accounting, strict JSON, timeout, no redirects/cookies/proxy or implicit profile fallback');
  } finally {server.closeAllConnections();await new Promise(done=>server.close(done));await rm(directory,{recursive:true,force:true});}
}

async function checkGeneratedMimicProject() {
  // Explicit opt-in only: downloads the exact source pin into a temporary module.
  // Default --go remains dependency-free with downloads disabled.
  const directory=await mkdtemp(join(tmpdir(),'reb-mimic-project-'));
  const cwd=join(directory,'reb-client-project/go');
  const offline={...process.env,GOTOOLCHAIN:'local',GOPROXY:'off',GOSUMDB:'off'};
  try {
    const project=api.capturedClientProject(source,'raw');
    for(const item of project.files){const path=join(directory,item.path);await mkdir(dirname(path),{recursive:true});await writeFile(path,item.text);}
    const compiler=await command('go',['version'],cwd,{env:offline});assert.equal(compiler.code,0,compiler.stderr);assert.match(compiler.stdout,/go version go1\./);
    const pin='github.com/saucesteals/mimic@946a948a9b5a4360847b7f7d4b1f2e63f64ddc9e';
    const install=await command('go',['get',pin],cwd,{env:{...offline,GOPROXY:'https://proxy.golang.org',GOSUMDB:'sum.golang.org'},timeout:120000});assert.equal(install.code,0,install.stdout+install.stderr);
    await writeFile(join(cwd,'client/client_test.go'),await readFile(join(root,'tools/client-project-go_test.txt'),'utf8'));
    await writeFile(join(cwd,'client/mimic_test.go'),await readFile(join(root,'tools/client-project-mimic_test.txt'),'utf8'));
    for(const stage of ['build','test','vet']){
      const result=await command('go',[stage,'-tags','mimic','./...'],cwd,{env:offline,timeout:90000});assert.equal(result.code,0,result.stdout+result.stderr);
    }
    const modules=await command('go',['list','-m','all'],cwd,{env:offline});assert.equal(modules.code,0,modules.stderr);assert.match(modules.stdout,/github.com\/saucesteals\/mimic v1\.0\.2/);
    const output=join(root,'build/client-project-qa');await mkdir(output,{recursive:true});
    await writeFile(join(output,'mimic-validation.json'),JSON.stringify({status:'passed',compiler:compiler.stdout.trim(),pin,modules:modules.stdout.trim().split('\n'),
      checks:['tagged Go build/test/vet','owned HTTP loopback profile header coherence','dry-run/origin/profile gates','redirect/cookie boundaries','untrusted TLS rejection'],
      unverified:['successful owned HTTPS H1/H2','REFUSED_STREAM/GOAWAY wire-attempt count','browser-reference TLS/HTTP2 equivalence','HTTP3 unsupported','transitive license completeness']},null,2)+'\n');
    console.log('PASS optional pinned Mimic tagged build/test/vet and owned HTTP fixture; HTTPS/H2 compatibility and retry-fault measurements remain separate unverified gates');
  } finally {await rm(directory,{recursive:true,force:true});}
}
