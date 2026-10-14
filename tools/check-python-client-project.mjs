#!/usr/bin/env node
// Synthetic loopback fixtures only; providers are installed separately and explicitly.
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,mkdir,rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {createServer as createSecureServer} from 'node:https';
import {gzipSync} from 'node:zlib';
import {spawn} from 'node:child_process';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {network} from './traffic-capture-qa.mjs';

const directory=await mkdtemp(join(tmpdir(),'reb-python-client-'));
const script=fileURLToPath(new URL('./export-captured-client.mjs',import.meta.url));
const python=process.env.REB_PYTHON || 'python3';
const providers=process.argv.includes('--providers');
const seen=[];
const server=createServer(async(request,response)=>{
  const parts=[];for await(const part of request)parts.push(part);
  seen.push({method:request.method,url:request.url,headers:request.headers,body:Buffer.concat(parts).toString()});
  if(request.url==='/redirect') {response.writeHead(302,{Location:'/must-not-follow','Set-Cookie':'synthetic-only=1'});response.end('x'.repeat(100000));return;}
  if(request.url==='/compressed') {response.writeHead(200,{'Content-Type':'application/json','Content-Encoding':'gzip'});response.end(gzipSync('{\"ok\":true}'));return;}
  if(request.url==='/large') {response.end('x'.repeat(65537));return;}
  if(request.url==='/exact') {response.end('x'.repeat(65536));return;}
  if(request.url==='/slow') {setTimeout(()=>response.end('late'),350);return;}
  if(request.url==='/trickle') {response.writeHead(200,{'Content-Type':'text/plain'});let count=0;const timer=setInterval(()=>{response.write('x');if(++count===12){clearInterval(timer);response.end();}},30);response.on('close',()=>clearInterval(timer));return;}
  if(request.url==='/partial') {response.writeHead(200,{'Content-Length':'40'});response.write('partial');setTimeout(()=>response.destroy(),30);return;}
  const bodies={'/missing':'{}','/null':'{"ok":null}','/wrong-type':'{"ok":"true"}','/wrong-value':'{"ok":false}',
    '/duplicate':'{"ok":true,"ok":false}','/numeric-fraction':'{"n":4.0000000000000001}',
    '/numeric-exponent':'{"n":4e0}','/numeric-large':'{"n":9007199254740993}','/numeric':'{"n":4}',
    '/invalid-json':'not json','/pointer':'{"a/b":{"~":[true]}}','/inert':'{"ok":"${process.exit()} ` </script>"}'};
  if(request.url==='/invalid-utf8') {response.writeHead(200,{'Content-Type':'application/json'});response.end(Buffer.from([0xff]));return;}
  const headers={'Content-Type':request.url==='/wrong-media'?'text/html':'application/json; charset=utf-8','X-Repeat':['one','two']};
  response.writeHead(request.url==='/bad-status'?403:200,headers);response.end(bodies[request.url] || '{"ok":true}');
});
await new Promise(done=>server.listen(0,'127.0.0.1',done));
const origin='http://127.0.0.1:'+server.address().port;
const body='\ufeff雪\r\n{"inert":"${process.exit()} ` </script>","duplicate":1,"duplicate":2}';
const fixture=network(), record=fixture.requests[0];
record.url=origin+'/echo?x=1&x=2&empty=&q=a+b';record.document_url=record.url;
record.request.headers=[['Content-Type','application/json; charset=utf-8'],['X-Authored','synthetic-only']];record.request.body.text=body;
const document={format:'reb-network-request-v1',source:{instance_id:fixture.instance_id,capture_epoch:fixture.capture_epoch,
  request_id:record.id,target_id:record.target_id,started_monotonic_ms:record.started_monotonic_ms},debugger_generation:1,request:record};
let secureServer=null,secureOrigin='',secureReceipts=0;
const input=join(directory,'capture.json');await writeFile(input,JSON.stringify(document));
function command(program,args,cwd=directory,env=process.env) {
  return new Promise((resolve,reject)=>{const child=spawn(program,args,{cwd,env,stdio:['ignore','pipe','pipe']}),out=[],err=[];
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('Python fixture command timed out'));},15000);
    child.stdout.on('data',part=>out.push(part));child.stderr.on('data',part=>err.push(part));
    child.once('error',error=>{clearTimeout(timer);reject(error);});child.once('close',code=>{clearTimeout(timer);resolve({code,stdout:Buffer.concat(out).toString(),stderr:Buffer.concat(err).toString()});});});
}
const executeLibrary=`import json,client
try:
 result=client.send_request(client.read_json('requests/request-001.json',integers_only=True),config=client.read_json('config.json',integers_only=True),provenance=client.read_json('provenance.json'),send=True)
 print(json.dumps({'result':result}))
except client.ClientError as error:
 print(json.dumps({'error':error.code,'result':error.result}))
`;
try {
  if(providers) {
    const cert=await command('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(directory,'key.pem'),'-out',join(directory,'cert.pem'),'-subj','/CN=localhost','-days','1']);
    assert.equal(cert.code,0,cert.stderr);
    secureServer=createSecureServer({key:await readFile(join(directory,'key.pem')),cert:await readFile(join(directory,'cert.pem'))},(_request,response)=>{secureReceipts++;response.end('unexpected');});
    await new Promise(done=>secureServer.listen(0,'127.0.0.1',done));secureOrigin='https://127.0.0.1:'+secureServer.address().port;
  }
  for(const provider of ['requests','httpx']) {
    const providerStart=seen.length;
    const zip=join(directory,provider+'.zip');
    let result=await command(process.execPath,[script,'--input',input,'--output',zip,'--python-client',provider]);
    assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).python_client,provider);assert.equal(seen.length,providerStart);
    const repeat=join(directory,provider+'-repeat.zip');const second=await command(process.execPath,[script,'--input',input,'--output',repeat,'--python-client',provider]);
    assert.equal(second.code,0,second.stderr);assert.deepEqual(await readFile(zip),await readFile(repeat),'Python archive is deterministic');
    const folder=join(directory,provider);await mkdir(folder);
    result=await command(python,['-c','import sys,zipfile\nwith zipfile.ZipFile(sys.argv[1]) as z:\n assert z.testzip() is None\n assert all(n.startswith("reb-client-project/") and ".." not in n.split("/") for n in z.namelist())\n z.extractall(sys.argv[2])',zip,folder]);
    assert.equal(result.code,0,result.stderr);
    const cwd=join(folder,'reb-client-project'), code=await readFile(join(cwd,'client.py'),'utf8');
    assert(!code.includes('synthetic-only'));assert(!code.includes(record.url));assert(!code.includes('${process.exit()}'));
    const req=JSON.parse(await readFile(join(cwd,'requests/request-001.json'),'utf8'));
    const provenance=JSON.parse(await readFile(join(cwd,'provenance.json'),'utf8'));
    assert.equal(req.body,body);assert.equal(provenance.client_capabilities.overall_deadline,false);
    assert(!provenance.limitations.some(value=>/Default Go|Mimic|Both clients/.test(value)));
    assert(provenance.limitations.some(value=>value.includes('Retained CDP')));assert(provenance.limitations.some(value=>value.includes('truncated request')));assert(provenance.limitations.some(value=>value.includes('sensitive')));
    assert.equal(provenance.client_capabilities.http_client,provider);assert.equal(provenance.client_capabilities.timeout_scope,'per-operation');
    result=await command(python,['-m','py_compile','client.py'],cwd);assert.equal(result.code,0,result.stderr);
    result=await command(python,['-S','client.py'],cwd);assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).network_requests,0);
    result=await command(python,['client.py','--send'],cwd);assert.notEqual(result.code,0);assert.match(result.stderr,/invalid_config/);assert.equal(seen.length,providerStart);
    result=await command(python,['client.py','--unknown'],cwd);assert.notEqual(result.code,0);
    const base=JSON.parse(await readFile(join(cwd,'config.example.json'),'utf8'));base.allowedOrigin=origin;
    assert.equal(base.configVersion,'reb-python-client-config-v1');
    const configure=async value=>writeFile(join(cwd,'config.json'),JSON.stringify(value));
    await configure(base);result=await command(python,['client.py'],cwd);assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).ready,true);assert.equal(seen.length,providerStart);
    result=await command(python,['-S','client.py','--send'],cwd);assert.match(result.stderr,/missing_dependency/);assert.equal(seen.length,providerStart);
    result=await command(python,['-S','-c',"import client\nr=client.read_json('requests/request-001.json',integers_only=True);c=client.read_json('config.json',integers_only=True);p=client.read_json('provenance.json')\nfor value in [None,False,0,1,'false',{},[]]:\n result=client.send_request(r,config=c,provenance=p,send=value)\n assert result['dry_run'] and result['network_requests']==0"],cwd);assert.equal(result.code,0,result.stderr);assert.equal(seen.length,providerStart);
    await configure({...base,configVersion:'reb-client-config-v1'});result=await command(python,['client.py','--send'],cwd);assert.match(result.stderr,/invalid_config/);assert.equal(seen.length,providerStart);
    for(const config of [{...base,transport:{mode:'browser-profile',browserProfile:{browser:'chrome',version:'133.0.0.0',platform:'linux'}}},
      {...base,cookiePolicy:'include'},{...base,allowedOrigin:'http://example.test'},{...base,unknown:true},
      {...base,request:{...req,headers:[['Authorization','synthetic-only']]}},
      {...base,timeoutMs:true},{...base,responseChecks:{statuses:[200,200]}},{...base,responseChecks:{statuses:[true]}},
      {...base,responseChecks:{contentType:'Application/json'}},{...base,responseChecks:{jsonFields:[{pointer:'/bad~x',type:'string'}]}},
      {...base,responseChecks:{jsonFields:[{pointer:'',type:'object',equals:{}}]}},
      {...base,request:{...req,headers:[['X',null]]}},{...base,request:{...req,method:'GET'}},
      {...base,request:{...req,url:'https://synthetic:synthetic@example.test/'}},
      {...base,request:{...req,url:origin+'/雪'}},{...base,request:{...req,body:'\ud800'}}]) {
      await configure(config);result=await command(python,['client.py','--send'],cwd);assert.notEqual(result.code,0);assert.equal(seen.length,providerStart);
    }
    for(const contentType of ['text/plain; charset=utf-8; charset=utf-16','text/plain; charset=" utf-16"','text/plain; charset=',
      'text/plain; charset=""','text/plain; charset="utf-8','text/plain; charset=utf-8; CHARSET=UTF8','text/plain; charset*=utf-16',
      'text/plain; charset=utf-8 junk','text/plain; note="ok"; charset="utf-16"','text/plain; note="unfinished']) {
      await configure({...base,request:{...req,headers:[['Content-Type',contentType]]}});
      result=await command(python,['-S','client.py','--send'],cwd);assert.match(result.stderr,/invalid_input/,contentType);assert.equal(seen.length,providerStart);
    }
    for(const contentType of ['text/plain; charset="UTF-8"','text/plain; note="a;b"; charset=utf8','text/plain; note="a;\\\"b"; charset="utf\\-8"']) {
      await configure({...base,request:{...req,headers:[['Content-Type',contentType]]}});
      result=await command(python,['-S','client.py'],cwd);assert.equal(result.code,0,result.stderr);assert.equal(JSON.parse(result.stdout).ready,true,contentType);assert.equal(seen.length,providerStart);
    }
    await writeFile(join(cwd,'config.json'),JSON.stringify(base).replace('"allowedOrigin":','"allowedOrigin":"duplicate","allowedOrigin":'));
    result=await command(python,['client.py','--send'],cwd);assert.notEqual(result.code,0);assert.equal(seen.length,providerStart);
    await writeFile(join(cwd,'config.json'),JSON.stringify({...base,timeoutMs:100}).replace('\"timeoutMs\":100','\"timeoutMs\":100.0'));
    result=await command(python,['client.py','--send'],cwd);assert.notEqual(result.code,0);assert.equal(seen.length,providerStart);
    const redactedZip=join(directory,provider+'-redacted.zip');
    result=await command(process.execPath,[script,'--input',input,'--output',redactedZip,'--python-client',provider,'--mode','redacted_copy']);assert.equal(result.code,0,result.stderr);
    const redactedEvidence=await command(python,['-c','import json,sys,zipfile\nwith zipfile.ZipFile(sys.argv[1]) as z:\n print(z.read("reb-client-project/evidence/capture.json").decode())',redactedZip]);
    assert.equal(redactedEvidence.code,0,redactedEvidence.stderr);assert(!redactedEvidence.stdout.includes('synthetic-only'));assert.equal(JSON.parse(redactedEvidence.stdout).record.request.body.text,'');
    const originalProvenance=await readFile(join(cwd,'provenance.json'),'utf8');
    await writeFile(join(cwd,'provenance.json'),JSON.stringify({...provenance,mode:'redacted_copy'}));await configure(base);
    result=await command(python,['client.py','--send'],cwd);assert.match(result.stderr,/invalid_input/);assert.equal(seen.length,providerStart);
    await writeFile(join(cwd,'provenance.json'),originalProvenance);
    if(!providers) continue;
    const dependency=await command(python,['-c',`import ${provider};print(${provider}.__version__)`],cwd);assert.equal(dependency.code,0,dependency.stderr);
    assert.equal(dependency.stdout.trim(),provider==='requests'?'2.34.2':'0.28.1','Explicit provider lane uses the exact direct dependency pin');
    const netrc=join(directory,'netrc');await writeFile(netrc,'machine 127.0.0.1 login synthetic password synthetic\n');
    const environment={...process.env,HTTP_PROXY:'http://127.0.0.1:1',HTTPS_PROXY:'http://127.0.0.1:1',ALL_PROXY:'http://127.0.0.1:1',NO_PROXY:'',NETRC:netrc};
    const invoke=async config=>{await configure(config);const value=await command(python,['-c',executeLibrary],cwd,environment);assert.equal(value.code,0,value.stderr);return JSON.parse(value.stdout);};
    await configure(base);const mismatch=await command(python,['-c',`import ${provider};${provider}.__version__='unreviewed'\n`+executeLibrary],cwd,environment);assert.equal(JSON.parse(mismatch.stdout).error,'missing_dependency');assert.equal(seen.length,providerStart);
    let count=seen.length;
    result=await invoke(base);assert.equal(result.error,undefined,JSON.stringify(result));assert.equal(result.result.status,200);assert.deepEqual(result.result.validation,{configured:false,passed:false});assert.equal(seen.length,++count);
    assert.equal(seen.at(-1).url,'/echo?x=1&x=2&empty=&q=a+b');assert.equal(seen.at(-1).body,body);assert.equal(seen.at(-1).headers.cookie,undefined);assert.equal(seen.at(-1).headers.authorization,undefined);
    assert.deepEqual(result.result.headers.filter(([name])=>name.toLowerCase()==='x-repeat').map(([,value])=>value),['one','two']);
    const request=path=>({...req,method:'GET',headers:[],body:'',url:origin+path});
    result=await invoke({...base,request:request('/redirect')});assert.equal(result.result.status,302);assert.equal(result.result.body_truncated,true);assert.equal(seen.length,++count);assert(!seen.some(row=>row.url==='/must-not-follow'));
    result=await invoke({...base,request:request('/redirect'),redirectPolicy:'error'});assert.equal(result.error,'redirect_refused');assert.equal(seen.length,++count);
    for(const [path,expected] of [['/large',true],['/exact',false]]) {result=await invoke({...base,request:request(path)});assert.equal(result.result.body.length,65536);assert.equal(result.result.body_truncated,expected);assert.equal(seen.length,++count);}
    result=await invoke({...base,request:request('/slow'),timeoutMs:100});assert.equal(result.error,'timeout',JSON.stringify(result));assert.equal(result.result.network_requests,null);assert.equal(seen.length,++count);
    const start=Date.now();result=await invoke({...base,request:request('/trickle'),timeoutMs:100});assert.equal(result.error,undefined,JSON.stringify(result));assert(Date.now()-start>250,'Per-operation timeout is not presented as an overall deadline');assert.equal(seen.length,++count);
    result=await invoke({...base,request:request('/partial')});assert.equal(result.error,'response_read');assert.equal(result.result.status,200);assert.equal(result.result.body_truncated,true);assert.equal(result.result.body,'partial','Retain bytes received before an incomplete response');assert.equal(seen.length,++count);
    const checks={statuses:[200],contentType:'application/json',jsonFields:[{pointer:'/ok',type:'boolean',equals:true}]};
    for(const [path,error] of [['/ok',undefined],['/bad-status','response_status'],['/wrong-media','response_content_type'],['/missing','response_field_missing'],['/null','response_field_type'],['/wrong-type','response_field_type'],['/wrong-value','response_field_value'],['/duplicate','response_json'],['/invalid-json','response_json'],['/invalid-utf8','response_json'],['/large','response_content_type']]) {
      result=await invoke({...base,request:request(path),responseChecks:checks});assert.equal(result.error,error,provider+' '+path+' '+JSON.stringify(result));assert.equal(seen.length,++count);
    }
    for(const [path,error] of [['/numeric',undefined],['/numeric-fraction','response_field_value'],['/numeric-exponent','response_field_value'],['/numeric-large','response_field_value']]) {
      result=await invoke({...base,request:request(path),responseChecks:{jsonFields:[{pointer:'/n',type:'number',equals:4}]}});assert.equal(result.error,error,JSON.stringify(result));assert.equal(seen.length,++count);
    }
    result=await invoke({...base,request:request('/pointer'),responseChecks:{jsonFields:[{pointer:'/a~1b/~0/0',type:'boolean',equals:true}]}});assert.equal(result.result.validation.passed,true);assert.equal(seen.length,++count);
    result=await invoke({...base,request:request('/compressed'),responseChecks:{jsonFields:[{pointer:'/ok',type:'boolean',equals:true}]}});assert.equal(result.error,'response_json');assert.equal(result.result.body_invalid_utf8,true);assert.equal(seen.length,++count);
    result=await invoke({...base,allowedOrigin:secureOrigin,request:{...request('/tls'),url:secureOrigin+'/tls'}});assert.equal(result.error,'network');assert.equal(secureReceipts,0,'Untrusted TLS certificate is rejected before an HTTP request');
    await configure(base);const keylog=join(directory,provider+'-tls-keys');const keylogResult=await command(python,['-c',executeLibrary],cwd,{...environment,SSLKEYLOGFILE:keylog});
    assert.equal(JSON.parse(keylogResult.stdout).error,'unsupported_environment');assert.equal(seen.length,count);await assert.rejects(readFile(keylog),{code:'ENOENT'});
    const before=seen.length;result=await invoke({...base,request:request('/%78?%78=1')});
    if(provider==='requests') {assert.equal(result.error,'invalid_input');assert.equal(seen.length,before,'Normalization is refused before send');} else {assert.equal(seen.length,before+1);assert.equal(seen.at(-1).url,'/%78?%78=1');}
    assert(seen.every(row=>row.headers.cookie===undefined&&row.headers.authorization===undefined),'No cookies/auth are acquired or carried to later calls');
    console.log('PASS '+provider+' pinned-provider loopback: exact supported values, no ambient credentials/proxy/redirect/retry, raw bounded bodies, partial outcomes, response checks and explicit per-operation timeout behavior');
  }
  console.log('PASS Python-only export: shared captured data/config/evidence, deterministic fixed source, strict inputs, dry runs, explicit version/timeout capabilities and no export-side effects');
} finally {if(secureServer) await new Promise(done=>secureServer.close(done));await new Promise(done=>server.close(done));await rm(directory,{recursive:true,force:true});}
