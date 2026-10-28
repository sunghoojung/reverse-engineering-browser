// Offline literal marker planning only. No browser or backend execution transport.
import {constants} from 'node:fs';
import {open,realpath} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {createHash} from 'node:crypto';
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
