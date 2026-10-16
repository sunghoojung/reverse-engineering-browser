#!/usr/bin/env node
// Actual UI handlers and shared generators, with authored data and in-memory DOM only.
// The rendered API-catalog lane separately covers real pointer/keyboard/download actions.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import {network} from './traffic-capture-qa.mjs';
import formats from '../apps/research-ui/captured_export_formats.js';
const code=(await Promise.all(['evidence_models.js','traffic_view.js','api_catalog.js','captured_client.js','captured_export_formats.js'].map(name=>readFile(new URL('../apps/research-ui/'+name,import.meta.url),'utf8')))).join('\n');
const schema={data:{__schema:{queryType:{name:'Query'},mutationType:null,subscriptionType:null,types:[{kind:'SCALAR',name:'String',description:null},{kind:'OBJECT',name:'Query',description:'synthetic schema',interfaces:[],fields:[{name:'hello',description:null,args:[],type:{kind:'SCALAR',name:'String',ofType:null},isDeprecated:false,deprecationReason:null}]}],directives:[]}}};
class Node {
  constructor(dataset={}){this.dataset=dataset;this.events={};this.children=[];this.disabled=false;this.value='standard';this.textContent='Export';this.parentNode={firstChild:{textContent:''}};}
  addEventListener(event,handler){this.events[event]=handler;}
  click(){if(!this.disabled)return this.events.click?.({currentTarget:this});}
  append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;}remove(){}focus(){}
  close(){this.open=false;this.events.close?.();}showModal(){this.open=true;}
}
function harness(native=false){
  const nodes=new Map(['#captured-client-review','[data-client-review-content]','[data-client-review-status]','[data-client-apply]','[data-client-replace]','[data-client-replace-label]','[data-client-close]','[data-format-export-support]','[data-sdl-file]'].map(key=>[key,new Node()]));
  const providers={capture:new Node(),run:new Node()},draft=new Node({clientCapture:'draft'});
  const projects=['raw','redacted_copy'].map(mode=>new Node({clientCapture:mode}));
  const runs=['raw','redacted_copy'].map(mode=>new Node({clientRunExport:mode}));
  const buttons=[new Node({captureFormat:'har',exportMode:'redacted_copy'}),new Node({captureFormat:'har',exportMode:'raw'}),new Node({captureFormat:'sdl'})];
  const groups={'[data-client-capture]':[draft,...projects],'[data-client-run-export]':runs,'[data-capture-format]':buttons,'[data-client-provider], [data-sdl-file]':[...Object.values(providers),nodes.get('[data-sdl-file]')],'[data-client-capture="raw"], [data-client-capture="redacted_copy"]':projects};
  const downloads=[],clips=[],bridges=[],notices=[];
  const document={querySelector:key=>key==='[data-client-capture="draft"]'?draft:key==='[data-client-provider="capture"]'?providers.capture:key==='[data-client-provider="run"]'?providers.run:nodes.get(key),querySelectorAll:key=>groups[key]??[],createElement:()=>new Node(),body:new Node(),documentElement:{classList:{contains:()=>native}},addEventListener(){}};
  nodes.get('#captured-client-review').querySelector=key=>nodes.get(key);
  const globals={TextEncoder,TextDecoder,Uint8Array,URL:class extends URL{static createObjectURL(blob){downloads.push(blob);return 'blob:authored';}static revokeObjectURL(){}},Blob,atob,btoa,setTimeout:()=>0,document,navigator:{clipboard:{writeText:async text=>clips.push(text)}},webkit:{messageHandlers:{rebClientProjectExport:{postMessage:async payload=>{bridges.push(payload);return {status:'saved'};}}}}};
  const api=runInNewContext(code+'\n;({installCapturedClientWorkflow,requestsFromDebuggerNetwork,capturedClientCapture,capturedClientRun,capturedExportFormats})',globals);
  const fixture=network(),row=fixture.requests[0];row.protocol='h2';row.started_monotonic_ms=1000;
  row.request.headers=[['X-Private','synthetic-secret']];row.response.headers=[['Content-Type','application/json']];row.response.body.base64='';row.response.body.text=JSON.stringify(schema);
  const a=value=>({state:'available',value}),u=()=>({state:'unavailable'});
  row.timing_evidence={format:'reb-network-timing-v1',request_monotonic_seconds:a(1),request_wall_seconds:a(1700000000),response_monotonic_seconds:a(1.06),completion_monotonic_seconds:a(1.1),response_observed:true,completion_observed:true,response_source:'responseReceived',completion_source:'loadingFinished',duplicate_response:false,duplicate_completion:false,response_after_completion:false,resource_timing:{state:'available',fields:{requestTime:a(1.005),proxyStart:u(),proxyEnd:u(),workerStart:u(),dnsStart:a(1),dnsEnd:a(3),connectStart:a(4),connectEnd:a(10),sslStart:a(5),sslEnd:a(9),sendStart:a(12),sendEnd:a(13),receiveHeadersStart:a(40),receiveHeadersEnd:a(45)}}};
  let requests=api.requestsFromDebuggerNetwork(fixture),selected=requests[0];
  const source=api.capturedClientCapture(selected);
  const run={id:7,started_at_ms:123,request:{...source.input,headers:source.input.headers.map(([name,value])=>({name,value}))},response:{status:200,headers:[],body:'synthetic-secret'}};
  run.resolved_request=run.request;
  const options={getRequest:()=>selected,getRequests:()=>requests,getRun:()=>run,getRunCapture:()=>null,contextKey:()=> 'ctx',hasDraft:()=>false,notice:message=>notices.push(message)};
  const workflow=api.installCapturedClientWorkflow(options);
  return {api,source,row,selected,projects,runs,buttons,providers,nodes,downloads,clips,bridges,notices,workflow,expire(){requests=[];selected=null;workflow.sync();}};
}
for(const native of [false,true]){
  const h=harness(native),before=JSON.stringify(h.selected.captureRecord);
  assert.equal(h.downloads.length+h.clips.length+h.bridges.length,0,'Opening and syncing do not export');
  for(const provider of ['requests','httpx'])for(const mode of ['raw','redacted_copy']){
    h.providers.capture.value=provider;await h.projects[mode==='raw'?0:1].click();
    const bytes=native?Buffer.from(h.bridges.at(-1).base64,'base64'):Buffer.from(await h.downloads.at(-1).arrayBuffer());
    const expected=formats.pythonProject(h.source,mode,provider);
    assert.deepEqual(bytes,Buffer.from(expected.bytes));
    h.providers.run.value=provider;await h.runs[mode==='raw'?0:1].click();
    const runBytes=native?Buffer.from(h.bridges.at(-1).base64,'base64'):Buffer.from(await h.downloads.at(-1).arrayBuffer());
    assert(runBytes.includes(Buffer.from('evidence/repeater-run.json')));
    assert(runBytes.includes(Buffer.from(provider+'==')));
  }
  for(const button of h.buttons){
    await button.click();const text=native?h.clips.at(-1):await h.downloads.at(-1).text();
    if(button.dataset.captureFormat==='sdl'){assert.match(text,/type Query/);assert.match(text,/# Saved REB identity:/);}
    else {const har=JSON.parse(text);assert.equal(har.log.entries.length,1);if(button.dataset.exportMode==='redacted_copy')assert(!text.includes('synthetic-secret'));}
  }
  assert.equal(JSON.stringify(h.selected.captureRecord),before,'Exports never mutate retained data');
  const count=()=>h.downloads.length+h.clips.length+h.bridges.length;
  let previous=count();h.selected.captureRecord.response.body.truncated=true;await h.buttons[2].click();assert.equal(count(),previous);assert.match(h.notices.at(-1),/complete retained HTTP 200/);h.selected.captureRecord.response.body.truncated=false;
  const timing=JSON.parse(JSON.stringify(h.selected.captureRecord.timing_evidence));
  for(const mutate of [t=>t.response_observed='false',t=>t.duplicate_response=0,t=>t.extra=true,t=>delete t.completion_observed,t=>t.request_wall_seconds.value='1700000000',t=>t.resource_timing.fields.sendStart.value=Infinity,t=>t.resource_timing.fields.sendStart.extra=1]) {
    h.selected.captureRecord.timing_evidence=JSON.parse(JSON.stringify(timing));mutate(h.selected.captureRecord.timing_evidence);
    await h.buttons[0].click();assert.equal(count(),previous);assert.match(h.notices.at(-1),/HAR export unsupported/);
  }
  delete h.selected.captureRecord.timing_evidence;await h.buttons[0].click();assert.equal(count(),previous);assert.match(h.notices.at(-1),/HAR export unsupported/);
  const input=h.nodes.get('[data-sdl-file]');
  async function select(text,size){const bytes=new TextEncoder().encode(text);input.files=[{size:size??bytes.length,arrayBuffer:async()=>bytes.buffer}];await input.events.change();}
  await select(JSON.stringify(schema));assert.equal(count(),++previous);
  for(const invalid of ['{}','{"a":1,"a":2}','{"data":',JSON.stringify({...schema,errors:[{message:'partial'}]})]){await select(invalid);assert.equal(count(),previous);assert.match(h.notices.at(-1),/SDL export failed/);}
  await select('{}',1048577);assert.equal(count(),previous);assert.match(h.notices.at(-1),/1 MiB/);
  let release;input.files=[{size:2,arrayBuffer:()=>new Promise(done=>{release=done;})}];const pending=input.events.change();assert(input.disabled);await h.buttons[1].click();assert.equal(count(),previous);h.workflow.close();release(new TextEncoder().encode(JSON.stringify(schema)).buffer);await pending;assert.equal(count(),previous,'Canceled file read cannot save late');
  h.expire();assert(h.buttons.every(button=>button.disabled));await h.projects[0].click();assert.equal(count(),previous);
  assert.equal(native?h.downloads.length:h.clips.length,0,'Native never uses Blob download; browser never copies implicitly');
}
const html=await readFile(new URL('../apps/research-ui/index.html',import.meta.url),'utf8');
for(const token of ['data-client-provider="capture"','data-client-provider="run"','data-capture-format="har"','data-capture-format="sdl"','data-sdl-file','captured_export_formats.js'])assert(html.includes(token));
console.log('PASS UI export actions: both Python providers/modes, capture and retained-run routes, CLI byte parity, HAR/SDL local outputs, native bridge/clipboard, redaction immutability, invalid/partial JSON, size bounds, cancellation and expired selection; no target network');
