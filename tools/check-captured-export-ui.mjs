#!/usr/bin/env node
// Real dialog/controller routes with authored evidence and an in-memory DOM.
// Rendered coverage lives in the API-catalog browser lane, not this model.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import {network} from './traffic-capture-qa.mjs';
import formats from '../apps/research-ui/captured_export_formats.js';
const code=(await Promise.all(['evidence_models.js','traffic_view.js','api_catalog.js','captured_client.js','captured_export_formats.js'].map(name=>readFile(new URL('../apps/research-ui/'+name,import.meta.url),'utf8')))).join('\n');
const schema={data:{__schema:{queryType:{name:'Query'},mutationType:null,subscriptionType:null,types:[{kind:'SCALAR',name:'String',description:null},{kind:'OBJECT',name:'Query',description:'synthetic schema',interfaces:[],fields:[{name:'hello',description:null,args:[],type:{kind:'SCALAR',name:'String',ofType:null},isDeprecated:false,deprecationReason:null}]}],directives:[]}}};
class Node {
  constructor(dataset={}){this.dataset=dataset;this.events={};this.children=[];this.disabled=false;this.files=[];this.options=[];this.textContent='';this.open=false;this.focused=false;}
  set value(value){this._value=value;if(this.isFile&&value==='')this.files=[];}get value(){return this._value;}
  addEventListener(event,handler){this.events[event]=handler;}
  click(){if(!this.disabled)return this.events.click?.({currentTarget:this});}
  append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}remove(){}focus(){this.focused=true;}
  close(){this.open=false;this.events.close?.();}showModal(){this.open=true;}
  querySelector(selector){return this.options.find(option=>selector==='[value="'+option.value+'"]');}
}
function harness(native=false){
  const fields=Object.fromEntries(['format','provider','source','file','policy','destination','submit','close','cancel','note','status','provider-field','policy-field','source-field','file-field'].map(name=>[name,new Node()]));fields.file.isFile=true;
  fields.source.options=['capture','file'].map(value=>({value}));fields.format.options=['json','client','har','sdl'].map(value=>({value}));fields.destination.options=['save','copy'].map(value=>({value}));
  const dialog=new Node(),title=new Node(),context=new Node(),triggers={capture:new Node({exportOpen:'capture'}),run:new Node({exportOpen:'run'})};
  dialog.querySelector=selector=>fields[selector.slice(13,-1)];
  const downloads=[],clips=[],bridges=[],notices=[],filenames=[];let bridgeResult={status:'saved'},clipboardError=false,bridgeWait=null;
  const document={querySelector:key=>({'#captured-export-dialog':dialog,'#captured-export-title':title,'#captured-export-context':context})[key],querySelectorAll:key=>key==='[data-export-open]'?Object.values(triggers):[],createElement:()=>{const link=new Node();link.click=()=>filenames.push(link.download);return link;},body:new Node(),documentElement:{classList:{contains:()=>native}},events:{},addEventListener(name,handler){this.events[name]=handler;}};
  const globals={TextEncoder,TextDecoder,Uint8Array,URL:class extends URL{static createObjectURL(blob){downloads.push(blob);return 'blob:authored';}static revokeObjectURL(){}},Blob,atob,btoa,setTimeout:()=>0,document,navigator:{clipboard:{writeText:async text=>{if(clipboardError)throw Error('authored clipboard denial');clips.push(text);}}},webkit:{messageHandlers:{rebClientProjectExport:{postMessage:async payload=>{bridges.push(payload);if(bridgeWait)await bridgeWait;return bridgeResult;}}}}};
  const api=runInNewContext(code+'\n;({installCapturedExportDialog,requestsFromDebuggerNetwork,capturedClientCapture,capturedClientRun})',globals);
  const fixture=network(),row=fixture.requests[0];row.protocol='h2';row.started_monotonic_ms=1000;
  row.request.headers=[['X-Private','synthetic-secret']];row.response.headers=[['Content-Type','application/json']];row.response.body.base64='';row.response.body.text=JSON.stringify(schema);
  const a=value=>({state:'available',value}),u=()=>({state:'unavailable'});
  row.timing_evidence={format:'reb-network-timing-v1',request_monotonic_seconds:a(1),request_wall_seconds:a(1700000000),response_monotonic_seconds:a(1.06),completion_monotonic_seconds:a(1.1),response_observed:true,completion_observed:true,response_source:'responseReceived',completion_source:'loadingFinished',duplicate_response:false,duplicate_completion:false,response_after_completion:false,resource_timing:{state:'available',fields:{requestTime:a(1.005),proxyStart:u(),proxyEnd:u(),workerStart:u(),dnsStart:a(1),dnsEnd:a(3),connectStart:a(4),connectEnd:a(10),sslStart:a(5),sslEnd:a(9),sendStart:a(12),sendEnd:a(13),receiveHeadersStart:a(40),receiveHeadersEnd:a(45)}}};
  let selected=api.requestsFromDebuggerNetwork(fixture)[0];const captured=api.capturedClientCapture(selected);
  const run={id:7,started_at_ms:123,request:{...captured.input,headers:captured.input.headers.map(([name,value])=>({name,value}))},response:{status:200,headers:[],body:'synthetic-secret'}};run.resolved_request=run.request;
  const options={getCaptureRequest:()=>{if(!selected)throw Error('Expired capture');return selected;},getRun:()=>run,getRunCapture:()=>null,contextKey:()=> 'ctx',notice:message=>notices.push(message)};
  const workflow=api.installCapturedExportDialog(options);
  const set=(name,value)=>{fields[name].value=value;fields[name].events.change();};
  const open=(kind='capture')=>{if(dialog.open)workflow.close();triggers[kind].click();assert(dialog.open);};
  return {api,captured,selected,fields,dialog,triggers,downloads,clips,bridges,notices,filenames,workflow,document,set,open,
    expire(){selected=null;workflow.sync();},setBridge(value){bridgeResult=value;},setClipboardError(value){clipboardError=value;},holdBridge(promise){bridgeWait=promise;}};
}
for(const native of [false,true]){
  const h=harness(native),f=h.fields,before=JSON.stringify(h.selected.captureRecord);
  const count=()=>h.downloads.length+h.clips.length+h.bridges.length;
  h.open();assert.equal(count(),0);assert.equal(f.policy.value,'redacted_copy');assert.equal(f.format.value,'json');assert(f['provider-field'].hidden);assert(f['source-field'].hidden);assert.equal(f.destination.value,native?'copy':'save');
  await f.submit.click();let text=native?h.clips.at(-1):await h.downloads.at(-1).text();assert(!text.includes('synthetic-secret'));
  h.set('policy','raw');await f.submit.click();text=native?h.clips.at(-1):await h.downloads.at(-1).text();assert(text.includes('synthetic-secret'));
  if(!native){h.set('destination','copy');await f.submit.click();assert(h.clips.at(-1).includes('synthetic-secret'));}
  h.workflow.close();assert(h.triggers.capture.focused);
  for(const provider of ['standard','requests','httpx'])for(const mode of ['raw','redacted_copy']){
    h.open();h.set('format','client');h.set('provider',provider);h.set('policy',mode);assert(!f['provider-field'].hidden);assert.equal(f.destination.value,'save');assert(f.destination.options[1].disabled);
    await f.submit.click();const bytes=native?Buffer.from(h.bridges.at(-1).base64,'base64'):Buffer.from(await h.downloads.at(-1).arrayBuffer());
    const expected=provider==='standard'?null:formats.pythonProject(h.captured,mode,provider);if(expected)assert.deepEqual(bytes,Buffer.from(expected.bytes));else assert(bytes.includes(Buffer.from('src/client.mjs')));
    h.open('run');assert.equal(f.format.value,'client');assert(f.format.options.filter(option=>option.value!=='client').every(option=>option.disabled));h.set('provider',provider);h.set('policy',mode);await f.submit.click();
    const runBytes=native?Buffer.from(h.bridges.at(-1).base64,'base64'):Buffer.from(await h.downloads.at(-1).arrayBuffer());assert(runBytes.includes(Buffer.from('evidence/repeater-run.json')));
  }
  for(const mode of ['raw','redacted_copy']){h.open();h.set('format','har');h.set('policy',mode);await f.submit.click();text=native?h.clips.at(-1):await h.downloads.at(-1).text();assert.equal(JSON.parse(text).log.entries[0]._reb.mode,mode);if(mode==='redacted_copy')assert(!text.includes('synthetic-secret'));}
  h.open();h.set('format','sdl');assert(f['policy-field'].hidden);assert(!f['source-field'].hidden);await f.submit.click();text=native?h.clips.at(-1):await h.downloads.at(-1).text();assert.match(text,/type Query/);assert.match(text,/# Saved REB identity:/);
  assert.equal(JSON.stringify(h.selected.captureRecord),before,'Export never rewrites retained data');
  let previous=count();h.selected.captureRecord.response.body.truncated=true;h.open();h.set('format','sdl');await f.submit.click();assert.equal(count(),previous);assert.match(f.status.textContent,/complete retained HTTP 200/);h.selected.captureRecord.response.body.truncated=false;
  const timing=JSON.parse(JSON.stringify(h.selected.captureRecord.timing_evidence));
  for(const mutate of [t=>t.response_observed='false',t=>t.duplicate_response=0,t=>t.extra=true,t=>delete t.completion_observed,t=>t.request_wall_seconds.value='1700000000',t=>t.resource_timing.fields.sendStart.value=Infinity]){
    h.selected.captureRecord.timing_evidence=JSON.parse(JSON.stringify(timing));mutate(h.selected.captureRecord.timing_evidence);h.open();h.set('format','har');await f.submit.click();assert.equal(count(),previous);assert.match(f.status.textContent,/HAR export unsupported/);
  }
  h.selected.captureRecord.timing_evidence=timing;
  let reads=0;
  function selectFile(text,size){const bytes=new TextEncoder().encode(text);f.file.files=[{name:'../../ignored.graphql',size:size??bytes.length,arrayBuffer:async()=>{reads++;return bytes.buffer;}}];return f.file.events.change();}
  h.open();h.set('format','sdl');h.set('source','file');assert(f.submit.disabled);await selectFile(JSON.stringify(schema));assert.equal(count(),previous,'File choice prepares locally but never exports');assert.equal(reads,1);await f.submit.click();assert.equal(count(),++previous);assert.equal(reads,1);if(!native)assert.equal(h.filenames.at(-1),'schema.graphql');
  for(const invalid of ['{}','{"a":1,"a":2}','{"data":',JSON.stringify({...schema,errors:[{message:'partial'}]})]){await selectFile(invalid);await f.submit.click();assert.equal(count(),previous);assert.match(f.status.textContent,/Local file failed/);}
  await selectFile('{}',1048577);assert(f.submit.disabled);await f.submit.click();assert.equal(count(),previous);assert.match(f.status.textContent,/1 MiB/);
  let release;f.file.files=[{size:2,arrayBuffer:()=>new Promise(done=>{release=done;})}];const pending=f.file.events.change();assert(f.submit.disabled);await f.submit.click();assert.equal(count(),previous);f.cancel.click();assert(!h.dialog.open);release(new TextEncoder().encode(JSON.stringify(schema)).buffer);await pending;assert.equal(count(),previous,'Cancel discards late file reads');assert(h.triggers.capture.focused);
  h.open();h.selected.captureRecord.request.body.text+='changed';h.workflow.sync();assert(f.submit.disabled);assert.match(f.status.textContent,/changed or expired/);await f.submit.click();assert.equal(count(),previous);
  h.open();let prevented=false;h.dialog.events.cancel({preventDefault(){prevented=true;}});assert(prevented&&!h.dialog.open);assert(h.triggers.capture.focused);
  if(native){h.open();h.set('format','client');let done;h.holdBridge(new Promise(resolve=>{done=resolve;}));const saving=f.submit.click();assert(f.cancel.disabled&&f.close.disabled);h.workflow.close();assert(h.dialog.open,'Cannot claim cancellation after native handoff');h.setBridge({status:'canceled'});done();await saving;assert.match(f.status.textContent,/canceled/);h.holdBridge(null);}
  h.open();h.set('format','json');h.set('destination','copy');h.setClipboardError(true);await f.submit.click();assert.match(f.status.textContent,/authored clipboard denial/);h.setClipboardError(false);
  previous=count();h.expire();assert(f.submit.disabled&&!h.triggers.capture.disabled);h.set('format','sdl');h.set('source','file');await selectFile(JSON.stringify(schema));await f.submit.click();assert.equal(count(),++previous);h.open();assert.equal(f.format.value,'sdl');assert.equal(f.source.value,'file');assert(f.submit.disabled,'Closing clears prepared schema');assert(f.format.options.filter(o=>o.value!=='sdl').every(o=>o.disabled));await selectFile(JSON.stringify(schema));await f.submit.click();assert.equal(count(),++previous);assert.equal(h.notices.length,0,'Export status stays in the dialog, not unrelated navigation');
}
const html=await readFile(new URL('../apps/research-ui/index.html',import.meta.url),'utf8');
for(const token of ['data-export-open="capture"','data-export-open="run"','data-export-format','data-export-policy','data-export-file','captured_export_formats.js'])assert(html.includes(token));
console.log('PASS compact export dialog: redacted default, explicit modes and destinations, runtime/capture/run parity, local file preparation without automatic output, exact-source invalidation, strict timing/schema/size bounds, cancel and focus return, native handoff and clipboard failure');
