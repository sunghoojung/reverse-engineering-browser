// Literal, reviewed marker cases; only the explicitly armed runner uses the local API.
import {constants} from 'node:fs';
import {open,realpath} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {createHash} from 'node:crypto';
import {request as httpRequest} from 'node:http';
import {performance} from 'node:perf_hooks';
import client from '../apps/research-ui/captured_client.js';
import {saveArchive} from './captured-request-export.mjs';

const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v,keys) => object(v) && Object.keys(v).length === keys.length && keys.every(k=>Object.hasOwn(v,k));
const integer = (v,min,max) => Number.isSafeInteger(v) && v>=min && v<=max;
const bytes = v => Buffer.byteLength(v,'utf8');
const text = (v,max,empty=true) => typeof v==='string' && (empty || v.length>0) && bytes(v)<=max &&
  ![...v].some(c=>c.length===1 && c.charCodeAt(0)>=0xd800 && c.charCodeAt(0)<=0xdfff);
export function canonical(value) {
  if (Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
  if (object(value)) return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
}
export const digest = value => createHash('sha256').update(typeof value==='string'?value:canonical(value)).digest('hex');
const fail = message => {throw new Error(message);};
function scope(value) {
  if (!exact(value,['instance_id','target_id','experiment_id','session_id']) || !text(value.instance_id,128,false) || /[\x00-\x20\x7f]/.test(value.instance_id) || !text(value.target_id,4096,false) || /[\x00-\x20\x7f]/.test(value.target_id) ||
      !integer(value.experiment_id,1,Number.MAX_SAFE_INTEGER) || !integer(value.session_id,1,Number.MAX_SAFE_INTEGER)) fail('Select one exact disposable target, experiment and Repeater session.');
}
function request(value) {
  if (!exact(value,['url','method','headers','body']) || !text(value.url,8192,false) || !text(value.body,8192) ||
      !['GET','HEAD','POST'].includes(value.method) || ['GET','HEAD'].includes(value.method) && value.body!=='') fail('Use a bounded literal GET, HEAD or POST request; GET and HEAD cannot have a body.');
  let url;try {url=new URL(value.url);} catch {fail('Request URL is invalid.');}
  if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.hash || value.url.includes('#') || url.href!==value.url || /[^\x21-\x7e]/.test(value.url)) fail('Request URL must be canonical, credential-free HTTP(S), without a fragment.');
  if (!object(value.headers) || Object.entries(value.headers).some(([key,val])=> !(
    key==='accept' && val==='*/*' || key==='content-type' && val==='text/plain; charset=utf-8'))) fail('Marker requests allow only accept: */* and content-type: text/plain; charset=utf-8.');
  const size=bytes(value.url)+bytes(value.method)+bytes(value.body)+Object.entries(value.headers).reduce((n,[k,v])=>n+bytes(k)+bytes(v),0);
  if (size>8192) fail('One request exceeds the 8 KiB authored-field budget.');
  return {origin:url.origin,size};
}
export function markerPlan(input) {
  if (!exact(input,['format','source_id','scope','request','marker','payloads','limits']) || input.format!=='reb-marker-fuzz-input-v1' ||
      !text(input.source_id,128,false) || /[\x00-\x1f\x7f]/.test(input.source_id)) fail('Use a complete reb-marker-fuzz-input-v1 authored input.');
  scope(input.scope);const base=request(input.request),m=input.marker,l=input.limits;
  if (!exact(m,['field','literal']) || !['body','query'].includes(m.field) || !text(m.literal,64,false) || !/^[A-Za-z0-9_-]+$/.test(m.literal)) fail('Choose one literal ASCII marker in body or query.');
  if (!exact(l,['interval_ms','request_timeout_ms','deadline_ms','max_request_bytes']) || !integer(l.interval_ms,250,5000) ||
      !integer(l.request_timeout_ms,100,5000) || !integer(l.deadline_ms,1000,60000) || !integer(l.max_request_bytes,1,65536)) fail('Invalid count, rate, timeout or byte budget.');
  if (!Array.isArray(input.payloads) || !integer(input.payloads.length,1,16) || !input.payloads.every(v=>text(v,2048))) fail('Supply 1–16 authored literal payloads, each at most 2 KiB UTF-8.');
  const field=m.field==='body'?'body':'url',source=input.request[field],at=source.indexOf(m.literal);
  if (at<0 || source.indexOf(m.literal,at+1)>=0) fail('The selected field must contain exactly one marker; duplicate and overlapping occurrences are ambiguous.');
  if (m.field==='query') {
    const start=source.indexOf('?'),previous=source.lastIndexOf('&',at),equals=source.indexOf('=',Math.max(start,previous)+1),end=source.indexOf('&',at);
    if (start<0 || at<=start || equals<0 || equals>=at || end>=0 && equals>=end) fail('The query marker must occur literally inside one query value, after its equals sign.');
  }
  const cases=input.payloads.map((payload,index)=>{
    const replacement=m.field==='query'?encodeURIComponent(payload).replace(/[!'()*]/g,c=>'%'+c.charCodeAt(0).toString(16).toUpperCase()):payload;
    const resolved={...input.request,headers:{...input.request.headers},[field]:source.slice(0,at)+replacement+source.slice(at+m.literal.length)};
    const checked=request(resolved);if(checked.origin!==base.origin || resolved.method!==input.request.method) fail('A marker case changed the reviewed origin or method.');
    return {index,payload,payload_sha256:digest(payload),request:resolved,request_sha256:digest(resolved),request_bytes:checked.size};
  });
  const total=cases.reduce((n,c)=>n+c.request_bytes,0);
  if (total>l.max_request_bytes || (cases.length-1)*l.interval_ms>=l.deadline_ms) fail('Cases exceed the aggregate request-byte budget or minimum dispatch schedule.');
  const plan={format:'reb-marker-fuzz-plan-v1',input,source_sha256:digest(input),request_sha256:digest(input.request),
    marker_range:{field:m.field,start:bytes(source.slice(0,at)),end:bytes(source.slice(0,at+m.literal.length))},
    exact_origin:base.origin,exact_method:input.request.method,total_request_bytes:total,cases};
  const output={...plan,plan_sha256:digest(plan)};
  if(bytes(JSON.stringify(output,null,2)+'\n')>262144)fail('The full previewed plan exceeds its 256 KiB JSON-file budget.');
  return output;
}
export function validatePlan(plan,arm) {
  const checked=markerPlan(plan?.input);
  if (canonical(plan)!==canonical(checked) || !/^[a-f0-9]{64}$/.test(arm??'') || checked.plan_sha256!==arm) fail('Plan changed or does not match the explicitly reviewed --arm SHA-256. Preview it again.');
  return checked;
}
export async function readMarkerFile(path) {
  let file;
  try {
    const absolute=resolve(path);if(await realpath(dirname(absolute))!==dirname(absolute)) throw new Error();
    file=await open(absolute,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const before=await file.stat({bigint:true});if(!before.isFile() || before.size>262144n) throw new Error();
    const buffer=Buffer.alloc(262145);let size=0;
    while(size<buffer.length){const {bytesRead}=await file.read(buffer,size,buffer.length-size,null);if(!bytesRead)break;size+=bytesRead;}
    const after=await file.stat({bigint:true});
    if(size>262144 || before.size!==after.size || before.mtimeNs!==after.mtimeNs || before.ctimeNs!==after.ctimeNs) throw new Error();
    return client.capturedClientJSON(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(buffer.subarray(0,size)),new Map());
  } catch {fail('Read an unchanged regular UTF-8 JSON file of at most 256 KiB, without symlinks, duplicate keys or malformed Unicode.');}
  finally {await file?.close();}
}
export async function saveMarkerFile(path,value) {
  return saveArchive(path,Buffer.from(JSON.stringify(value,null,2)+'\n'));
}
export function backendOrigin(base) {
  let u;try {u=new URL(base);} catch {fail('Use an explicit literal HTTP loopback backend origin.');}
  if (u.protocol!=='http:' || !['127.0.0.1','[::1]'].includes(u.hostname) || u.origin!==base || u.username || u.password || u.pathname!=='/' || u.search || u.hash) fail('Use an explicit literal HTTP loopback backend origin.');
  return u.origin;
}
export async function backendCall(base,action) {
  const origin=backendOrigin(base);
  // node:http uses this literal loopback host directly: no ambient proxy, cookie,
  // credential or redirect behavior. A failed call is never retried.
  return new Promise((resolveResult,reject)=>{
    const body=action?JSON.stringify(action):null;
    const req=httpRequest(origin+(action?'/api/debugger/actions':'/api/debugger'),{
      method:action?'POST':'GET',agent:false,headers:action?{'content-type':'application/json','content-length':Buffer.byteLength(body)}:{}
    },res=>{
      const headers=res.rawHeaders??[],counts=new Map();
      for(let i=0;i<headers.length;i+=2){const key=headers[i].toLowerCase();counts.set(key,(counts.get(key)??0)+1);}
      if(!/^application\/json(?:;\s*charset=utf-8)?$/i.test(res.headers['content-type']??'') ||
          counts.get('content-type')!==1 || counts.get('content-encoding')>1 ||
          res.headers['content-encoding'] && res.headers['content-encoding']!=='identity') {
        req.destroy(new Error('Backend response encoding is unsupported.'));return;
      }
      let size=0;const chunks=[];
      res.on('data',chunk=>{size+=chunk.length;if(size>4194304)req.destroy(new Error('Backend response exceeds its bound.'));else chunks.push(chunk);});
      res.on('error',reject);res.on('end',()=>{
        if(res.statusCode!==200){reject(new Error('Backend did not confirm the operation.'));return;}
        try {resolveResult(client.capturedClientJSON(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(Buffer.concat(chunks)),new Map()));} catch {reject(new Error('Backend response is malformed.'));}
      });
    });
    const timer=setTimeout(()=>req.destroy(new Error('Backend response deadline expired.')),2000);
    req.on('error',reject);req.on('close',()=>clearTimeout(timer));req.end(body);
  });
}
const pause = ms => new Promise(resolve=>setTimeout(resolve,ms));
function snapshotScope(s,plan) {
  const wanted=plan.input.scope,r=s?.repeater,e=s?.request_interception;
  return s?.network?.instance_id===wanted.instance_id && s?.target?.id===wanted.target_id && e?.target_id===wanted.target_id && e?.experiment_id===wanted.experiment_id &&
    r?.session_id===wanted.session_id && ['running','paused'].includes(s.state) && e.state==='ready' && e.rule?.mode==='continue';
}
function matching(value,guard) {return object(value) && canonical(value)===canonical(guard);}
function repeaterShape(r) {
  return object(r) && integer(r.session_id,1,Number.MAX_SAFE_INTEGER) && Array.isArray(r.history) && r.history.length<=24 &&
    r.history.every(e=>object(e) && integer(e.id,1,Number.MAX_SAFE_INTEGER)) &&
    (r.active_execution===null || object(r.active_execution) && integer(r.active_execution.execution_id,1,Number.MAX_SAFE_INTEGER));
}
function resultShape(result) {
  return object(result) && result.protocol_version===1 && typeof result.ok==='boolean' &&
    integer(result.status,0,599) && integer(result.duration_ms,0,35000) &&
    ['body_truncated','headers_truncated','cancelled','timed_out'].every(k=>typeof result[k]==='boolean') &&
    !(result.cancelled&&result.timed_out) && !(result.ok&&(result.cancelled||result.timed_out)) &&
    /^[a-f0-9]{64}$/.test(result.body_sha256??'') && text(result.body,8192) && digest(result.body)===result.body_sha256;
}
function lastId(r) {return Math.max(0,...r.history.map(v=>v.id));}
export async function runMarkerPlan(plan,{arm,baseUrl,signal,call=backendCall}={}) {
  plan=validatePlan(plan,arm);backendOrigin(baseUrl);
  const started=Date.now(),monotonicStart=performance.now(),deadline=monotonicStart+plan.input.limits.deadline_ms,wallDeadline=started+plan.input.limits.deadline_ms;
  const report={format:'reb-marker-fuzz-report-v1',plan_sha256:plan.plan_sha256,source_sha256:plan.source_sha256,
    scope:plan.input.scope,started_at_ms:started,completed_at_ms:null,state:'running',attempted_cases:0,confirmed_executions:0,cases:[],
    evidence:'Hashes and bounded metadata only. Raw potentially private responses remain in ephemeral Repeater history; no automatic export.'};
  let active=null,previous=null,lastDispatch=-Infinity;
  const stop=state=>{report.state=state;};
  async function cancel() {
    if (!active) return;
    const expected={...plan.input.scope,execution_id:active.id,plan_sha256:plan.plan_sha256,case_index:active.index};
    try {const ack=await call(baseUrl,{action:'cancel_repeater_request',expected_execution:expected});if(ack?.ok!==true || !repeaterShape(ack.repeater) || ack.repeater.session_id!==expected.session_id)throw new Error();active.evidence.cancellation='requested';}
    catch {active.evidence.cancellation='unconfirmed';}
  }
  try {
    for (const item of plan.cases) {
      if(signal?.aborted || performance.now()>=deadline){stop(signal?.aborted?'cancelled':'deadline');break;}
      const nextDispatch=lastDispatch+plan.input.limits.interval_ms;
      // Monotonic, rechecked waits enforce spacing despite early timers or wall
      // clock changes, while keeping Ctrl-C responsive without issuing requests.
      while(performance.now()<nextDispatch && !signal?.aborted && performance.now()<deadline)
        await pause(Math.min(50,Math.max(1,Math.ceil(nextDispatch-performance.now()))));
      if(signal?.aborted || performance.now()>=deadline){stop(signal?.aborted?'cancelled':'deadline');break;}
      const s=await call(baseUrl);
      if(!snapshotScope(s,plan) || !repeaterShape(s.repeater) || s.repeater.active_execution!==null || previous!==null && lastId(s.repeater)!==previous){stop('scope_changed');break;}
      if(previous===null)previous=lastId(s.repeater);
      if(signal?.aborted || performance.now()+100>=deadline){stop(signal?.aborted?'cancelled':'deadline');break;}
      const guard={version:1,plan_sha256:plan.plan_sha256,case_index:item.index,case_count:plan.cases.length,...plan.input.scope,
        exact_origin:plan.exact_origin,exact_method:plan.exact_method,request_sha256:item.request_sha256,expires_at_ms:wallDeadline};
      const evidence={index:item.index,request_sha256:item.request_sha256,payload_sha256:item.payload_sha256,state:'unknown',execution_id:null};
      report.cases.push(evidence);report.attempted_cases++;lastDispatch=performance.now();
      const response=await call(baseUrl,{action:'run_repeater_request',...item.request,timeout_ms:Math.min(plan.input.limits.request_timeout_ms,Math.floor(deadline-performance.now())),marker_fuzz:guard});
      if(response.ok!==true || !repeaterShape(response.repeater) || response.repeater?.session_id!==plan.input.scope.session_id) {stop('unknown');break;}
      let r=response.repeater;
      let completed=r.history?.find(v=>matching(v.marker_fuzz,guard));
      const running=r.active_execution;
      const id=completed?.id ?? (matching(running?.marker_fuzz,guard)?running.execution_id:null);
      if(!integer(id,previous+1,Number.MAX_SAFE_INTEGER)){stop('unknown');break;}
      evidence.execution_id=id;report.confirmed_executions++;active={id,index:item.index,evidence};
      while(!completed) {
        if(signal?.aborted || performance.now()>=deadline) {await cancel();evidence.state='unknown';stop(signal?.aborted?'cancelled':'deadline');break;}
        await pause(50);const state=await call(baseUrl);
        if(!snapshotScope(state,plan) || !repeaterShape(state.repeater)){stop('unknown');break;}
        r=state.repeater;completed=r.history?.find(v=>v.id===id && matching(v.marker_fuzz,guard));
        if(!completed && (r.active_execution?.execution_id!==id || !matching(r.active_execution?.marker_fuzz,guard))){stop('unknown');break;}
      }
      if(report.state!=='running')break;
      const result=completed?.response;
      if(completed?.resolved_request?.url!==item.request.url || completed?.resolved_request?.method!==item.request.method ||
          completed?.resolved_request?.body!==item.request.body ||
          !resultShape(result)) {stop('unknown');break;}
      evidence.state=result.ok?'complete':result.cancelled?'cancelled':result.timed_out?'timed_out':'error';
      Object.assign(evidence,{http_status:result.status,duration_ms:result.duration_ms,body_sha256:result.body_sha256,
        body_truncated:result.body_truncated,headers_truncated:result.headers_truncated});
      previous=id;active=null;
      if(!result.ok){stop(evidence.state);break;}
    }
    if(report.state==='running')report.state=report.cases.length===plan.cases.length?'complete':'stopped';
  } catch {stop('unknown');if(active)await cancel();}
  report.completed_at_ms=Math.max(started,Date.now());
  report.elapsed_ms=Math.max(0,Math.round(performance.now()-monotonicStart));
  report.not_attempted_cases=plan.cases.length-report.attempted_cases;
  return report;
}
