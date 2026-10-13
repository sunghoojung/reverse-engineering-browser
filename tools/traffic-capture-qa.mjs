#!/usr/bin/env node
// Synthetic-only retained Traffic runtime fixture. No product source, captures, or profiles are modified.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {createInterface} from 'node:readline';
import {resolve, join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';

export const rawUrl = 'https://synthetic-user:synthetic-pass@example.test/path?token=synthetic-query#synthetic-fragment';
export const jsonText = '{"password":"synthetic-json","n":9007199254740993,"dup":1,"dup":2}';
export const formText = 'token=synthetic-form&token=second+value';
export const plainText = '\ufeff雪\r\n<script>synthetic-plain</script>';
export const limits = {requests:1000, body_bytes:131072, headers:128, header_bytes:65536};
const omission = 'Body content omitted from this explicitly redacted copy.';
const variants = new Set(['baseline','epoch','instance','target','truncated','states','clear','off']);
const body = (text = '', base64 = '', state = 'available') => ({state,mime:'application/json',text,base64,truncated:false,reason:''});
const copy = value => JSON.parse(JSON.stringify(value));
export function records(variant = 'baseline') {
  assert(variants.has(variant), `Unknown fixture variant: ${variant}`);
  if (['clear','off'].includes(variant)) return [];
  const record = (name, text) => ({
    id:`synthetic-${name}`,protocol_request_id:`synthetic-${name}`,target_id:'synthetic-target',target_title:'Synthetic title',
    url:rawUrl,document_url:rawUrl,url_truncated:false,document_url_truncated:false,method:'POST',method_truncated:false,
    resource_type:'Fetch',started_monotonic_ms:100,wall_time_ms:1700000000000,state:'complete',status:200,status_text:'OK',
    protocol:'HTTP/1.1',mime_type:'application/octet-stream',duration_ms:1,encoded_data_length:5,
    from_disk_cache:false,from_service_worker:false,error_text:'Synthetic diagnostic text',
    initiator:{sites:[{script_id:'synthetic-script',target_id:'synthetic-target',source:rawUrl,source_truncated:false,
      function:'synthetic_function',line:0,column:0}],gaps:[]},
    request:{headers:[['Authorization','Bearer synthetic-auth'],['Cookie','synthetic-cookie'],
      ['Proxy-Authorization','synthetic-proxy'],['X-Custom-Token','synthetic-custom']],headers_truncated:false,body:body(text)},
    response:{headers:[['Set-Cookie','synthetic-response-cookie']],headers_truncated:false,body:body('','AP8BAgM=')},
  });
  const values = [record('json',jsonText),record('form',formText),record('plain',plainText)];
  if (['epoch','instance','target'].includes(variant)) {
    values[0].request.body.text = `{"owner":"synthetic-${variant}"}`;
    if (variant === 'target') for (const item of values) {
      item.target_id='synthetic-target-2';item.initiator.sites[0].target_id=item.target_id;
    }
  }
  if (variant === 'states') return ['missing','loading','error','empty'].map(state => {
    const item = record(state,'');item.request.body=body('','',state);item.request.body.reason=`Synthetic ${state} limitation`;
    item.response.body=copy(item.request.body);return item;
  });
  if (variant === 'truncated') {
    const item = record('truncated','x'.repeat(limits.body_bytes));
    const prefix = 'https://synthetic-user:synthetic-pass@example.test/';
    item.url=prefix+'x'.repeat(65536-prefix.length);item.document_url=item.url;
    item.url_truncated=item.document_url_truncated=item.method_truncated=true;item.method='M'.repeat(32);
    item.request.headers=[['X-Synthetic-Long','雪'.repeat(2730)]];
    item.request.headers_truncated=item.response.headers_truncated=true;
    item.request.body.truncated=true;item.request.body.reason='Synthetic retained 128 KiB prefix';
    item.initiator.sites[0].source='https://example.test/'+'x'.repeat(8192-'https://example.test/'.length);
    item.initiator.sites[0].source_truncated=true;
    return [item];
  }
  return values;
}
export function network(variant = 'baseline') {
  return {capture_enabled:variant!=='off',instance_id:variant==='instance'?'synthetic-instance-2':'synthetic-instance-1',
    capture_epoch:variant==='epoch'?2:1,target_id:variant==='target'?'synthetic-target-2':'synthetic-target',
    requests:records(variant),dropped:variant==='clear'?8:7,limits:copy(limits)};
}
function redactExpected(item) {
  // Independent fixture oracle, deliberately no call into the production exporter.
  const expected = copy(item);
  const source = item.initiator.sites[0].source;
  expected.url = item.url === rawUrl ? 'https://example.test/path' : item.url.replace('synthetic-user:synthetic-pass@','');
  expected.document_url=expected.url;expected.target_title='<redacted>';expected.error_text='<redacted>';
  expected.initiator.sites[0].source=source===rawUrl?'https://example.test/path':source;
  for (const side of [expected.request,expected.response]) {
    side.headers=side.headers.map(([name])=>[name,'<redacted>']);
    if(side.body.state==='available')side.body.state='redacted';
    side.body.text='';side.body.base64='';side.body.reason=omission;
  }
  return expected;
}
export function verify(value, mode, id, variant = 'baseline') {
  assert(['raw','redacted_copy'].includes(mode),'Mode must be raw or redacted_copy');
  const expected = records(variant).find(item=>item.id===id);
  assert(expected,`No ${id} in variant ${variant}`);
  assert.equal(value.format,'reb-traffic-capture-v1');assert.equal(value.mode,mode);
  assert.equal(value.representation,'Retained CDP strings/base64, not original HTTP wire bytes.');
  assert.equal(value.coverage.dropped,network(variant).dropped);assert.deepEqual(value.coverage.limits,limits);
  assert.match(value.coverage.scope,/selected record.*ephemeral.*not a durable session archive/);
  assert.match(value.coverage.headers,/Primary CDP.*extra-info.*not guaranteed/);
  assert.match(value.coverage.storage,/Reconnect.*target change.*process exit.*retention eviction/);
  assert.deepEqual(value.record,mode==='raw'?expected:redactExpected(expected));
  assert.match(value.warning,mode==='raw'?/Raw local capture may contain credentials/:/Paths, header names and other metadata may contain secrets/);
  return {status:'passed',mode,id,variant,request_text_utf8_bytes:Buffer.byteLength(value.record.request.body.text),
    response_base64_bytes:Buffer.from(value.record.response.body.base64,'base64').length};
}
async function loadProduct(root) {
  const model = await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8');
  const traffic = await readFile(join(root,'apps/research-ui/traffic_view.js'),'utf8');
  const api=runInNewContext(model+'\n'+traffic+'\n;({isDebuggerResponse,isBrokerResponse,requestsFromDebuggerNetwork,trafficCaptureDocument})',
    {TextEncoder,TextDecoder,Uint8Array,URL,atob});
  const empty=JSON.parse(await readFile(join(root,'apps/origin-trace-backend/assets/debugger-empty.json'),'utf8'));
  return {api,empty};
}
function snapshot(empty,variant,generation=1) {
  const result=copy(empty);result.state='running';result.generation=generation;
  result.network=network(variant);result.target={id:result.network.target_id,type:'page',title:'Synthetic fixture only',url:'https://example.test/'};
  result.targets=[result.target];result.live_tab_count=1;return result;
}
const events = {count:0,events:[],capture_mode:'live',broker_connected:false,capture_controls_available:false};
export async function selfTest(root) {
  const {api,empty}=await loadProduct(root);assert(api.isBrokerResponse(events));let documents=0;
  for (const variant of variants) {
    const state=snapshot(empty,variant);assert(api.isDebuggerResponse(state),variant);
    const requests=api.requestsFromDebuggerNetwork(state.network,[]);
    for(const request of requests) {
      const before=JSON.stringify(state);
      for(const mode of ['raw','redacted_copy']) {
        const value=copy(api.trafficCaptureDocument(request,mode));verify(value,mode,request.id,variant);documents++;
        const corrupted=copy(value);corrupted.record.url='https://wrong.example.test/';
        assert.throws(()=>verify(corrupted,mode,request.id,variant));
      }
      assert.equal(JSON.stringify(state),before,'Exports must not mutate the original');
    }
  }
  const bounds=records('truncated')[0];assert.equal(Buffer.byteLength(bounds.url),65536);
  assert.equal(Buffer.byteLength(bounds.request.headers[0][1]),8190);assert.equal(Buffer.byteLength(bounds.request.body.text),131072);
  assert.equal(Buffer.byteLength(bounds.initiator.sites[0].source),8192);
  assert.deepEqual([...Buffer.from('AP8BAgM=','base64')],[0,255,1,2,3]);
  console.log(JSON.stringify({status:'passed',layer:'fixture contract and independent export oracle; not rendered/native runtime',variants:variants.size,documents}));
}
export async function fixtureServer(root) {
  const {api,empty}=await loadProduct(root);let variant='baseline',generation=1,mode='ready';
  const html=await readFile(join(root,'apps/research-ui/index.html'),'utf8');
  const assets=new Set(['index.html',...[...html.matchAll(/(?:src|href)="([^"/]+\.(?:js|css))"/g)].map(match=>match[1])]);
  const assetDirectory=process.env.REB_QA_ASSET_DIR?resolve(process.env.REB_QA_ASSET_DIR):join(root,'apps/research-ui');
  const bodies=new Map(await Promise.all([...assets].map(async name=>{
    const bytes=await readFile(join(assetDirectory,name));
    if(process.env.REB_QA_ASSET_DIR)assert.deepEqual(bytes,await readFile(join(root,'apps/research-ui',name)),`Bundle/source mismatch: ${name}`);
    return [name,bytes];
  })));
  console.log(`UI asset directory: ${assetDirectory}${process.env.REB_QA_ASSET_DIR?' (every public asset byte-checked against source)':''}`);
  function change(command) {
    if (['disconnect','malformed'].includes(command)) mode=command;
    else {assert(variants.has(command),`Use: ${[...variants,'disconnect','malformed','quit'].join(', ')}`);variant=command;mode='ready';}
    generation++;return {variant,mode,generation};
  }
  const server=createServer((request,response)=>{
    const reply=(status,value,type='application/json')=>{response.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});response.end(type==='application/json'?JSON.stringify(value):value);};
    const localHost=`127.0.0.1:${server.address().port}`;
    if(request.headers.host!==localHost){reply(400,{error:'Synthetic fixture requires exact loopback Host'});return;}
    if(request.method!=='GET'){reply(405,{error:'Synthetic fixture is read-only; use terminal controls'});return;}
    const path=request.url.split('?')[0];
    if(path==='/api/debugger') {
      if(mode==='disconnect'){reply(503,{error:'Synthetic debugger disconnection'});return;}
      if(mode==='malformed'){reply(200,{malformed:true});return;}
      const value=snapshot(empty,variant,generation);assert(api.isDebuggerResponse(value));reply(200,value);return;
    }
    if(path==='/api/events'){reply(200,events);return;}
    if(path==='/api/artifacts'){reply(200,{count:0,artifacts:[]});return;}
    if(path.startsWith('/api/')){reply(503,{error:'Unavailable in synthetic Traffic-only QA fixture'});return;}
    const name=path==='/'?'index.html':path.slice(1);
    if(!/^\/?[a-z][a-z0-9_]*\.(?:html|css|js)$/.test(name)||!assets.has(name)){reply(404,{error:'Not a public UI asset'});return;}
    reply(200,bodies.get(name),name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':'text/html');
  });
  return {server,change};
}
async function main() {
  const [action,arg,...args]=process.argv.slice(2);
  if(action==='verify') {
    const [id,variant='baseline']=args;const file=arg;
    // The mode comes from the explicit environment option, never from an untrusted file.
    const mode=process.env.REB_QA_EXPECT_MODE;
    assert(mode,'Set REB_QA_EXPECT_MODE=raw or redacted_copy');
    console.log(JSON.stringify(verify(JSON.parse(await readFile(file,'utf8')),mode,id,variant)));return;
  }
  assert(['self-test','serve'].includes(action)&&arg,
    'Usage: node traffic-capture-qa.mjs self-test|serve REPO; REB_QA_EXPECT_MODE=raw|redacted_copy node traffic-capture-qa.mjs verify FILE ID [VARIANT]');
  const root=resolve(arg);await selfTest(root);if(action==='self-test')return;
  const {server,change}=await fixtureServer(root);
  server.on('error',error=>{console.error(error.message);process.exitCode=1;});
  await new Promise((resolveReady,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolveReady);});
  const url=`http://127.0.0.1:${server.address().port}/`;
  console.log(`Synthetic Traffic-only fixture: ${url}\nNative launch: REB_DISABLE_AUTOMATIC_LIVE_SESSION=1 "${join(root,'build/Origin Trace.app/Contents/MacOS/OriginTrace')}" --ui-url "${url}"\nTerminal controls: ${[...variants,'disconnect','malformed','quit'].join(', ')}\nNo browser is launched, captured content fetched, export initiated, or OS clipboard touched by this server.`);
  const input=createInterface({input:process.stdin,output:process.stdout});
  const stop=()=>{input.close();server.closeAllConnections();server.close();};
  input.on('line',line=>{const command=line.trim();if(command==='quit'){stop();return;}try{console.log(JSON.stringify(change(command)));}catch(error){console.error(error.message);}});
  process.once('SIGINT',stop);process.once('SIGTERM',stop);
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
