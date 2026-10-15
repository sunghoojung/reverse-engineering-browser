// Explicit local-file snapshots for the existing disposable interception API.
import {constants} from 'node:fs';
import {open,realpath} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {createHash} from 'node:crypto';
import {request} from 'node:http';
import {saveArchive} from './captured-request-export.mjs';
import client from '../apps/research-ui/captured_client.js';

const maximum = 65536;
const media = new Set(['text/plain; charset=utf-8','text/javascript; charset=utf-8','application/json; charset=utf-8','text/css; charset=utf-8']);
export async function readOverrideAsset(path) {
  let file;
  try {
    const absolute = resolve(path);
    if (await realpath(dirname(absolute)) !== dirname(absolute)) throw new Error();
    file = await open(absolute,constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = await file.stat({bigint:true});
    if (!before.isFile() || before.size > BigInt(maximum)) throw new Error();
    const buffer = Buffer.alloc(maximum + 1); let size = 0;
    while (size <= maximum) {
      const {bytesRead} = await file.read(buffer,size,buffer.length-size,null);
      if (!bytesRead) break;
      size += bytesRead;
    }
    const after = await file.stat({bigint:true});
    if (size > maximum || BigInt(size) !== before.size || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) throw new Error();
    const bytes = buffer.subarray(0,size);
    const body = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
    if (!Buffer.from(body).equals(bytes)) throw new Error();
    return {body,bytes:size,sha256:createHash('sha256').update(bytes).digest('hex')};
  } catch {
    throw new Error('Override asset must be an unchanged regular UTF-8 file of at most 64 KiB. Symlink files and parent directories, pipes and devices are refused.');
  } finally { await file?.close(); }
}

export function overrideAction(asset,options,now = Date.now()) {
  const {url,targetId,experimentId,sha256,contentType = 'text/plain; charset=utf-8',method = 'GET',ttlMs = 60000} = options;
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error('A canonical credential-free HTTP(S) URL is required.'); }
  if (typeof url !== 'string' || Buffer.byteLength(url) > 2048 || /[^\x21-\x7e]/.test(url) || parsed.href !== url ||
      !['http:','https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash || url.includes('#')) throw new Error('A canonical credential-free HTTP(S) URL without a fragment is required.');
  if (typeof targetId !== 'string' || !targetId || Buffer.byteLength(targetId) > 4096 || /[\x00-\x1f\x7f]/.test(targetId) ||
      !Number.isSafeInteger(experimentId) || experimentId < 1 || !Number.isSafeInteger(ttlMs) || ttlMs < 1000 || ttlMs > 300000 ||
      !Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(now + ttlMs) || !['GET','HEAD'].includes(method) || !media.has(contentType)) throw new Error('Invalid target, experiment, method, lifetime or content type.');
  if (!/^[0-9a-f]{64}$/.test(sha256 ?? '') || sha256 !== asset.sha256 ||
      Buffer.byteLength(asset.body) !== asset.bytes || asset.bytes > maximum || createHash('sha256').update(asset.body).digest('hex') !== sha256) throw new Error('Asset differs from the explicitly reviewed SHA-256. Preview and review it again before arming.');
  return {action:'configure_request_interception',mode:'fulfill',url_pattern:'*',method_filter:method,response_code:200,
    response_headers:{'content-type':contentType},response_body:asset.body,
    local_override:{version:1,exact_url:url,target_id:targetId,experiment_id:experimentId,expires_at_ms:now + ttlMs,asset_sha256:sha256}};
}

// Shared writer creates a private sibling, publishes without overwrite, then removes it.
export async function saveOverrideAction(output,action) {
  return saveArchive(output,Buffer.from(JSON.stringify(action)+'\n'));
}

export async function applyOverride(baseUrl,action,{disarm = false} = {}) {
  let endpoint;
  try { endpoint = new URL(baseUrl); } catch { throw new Error('Use an explicit loopback backend origin.'); }
  if (endpoint.protocol !== 'http:' || !['127.0.0.1','[::1]'].includes(endpoint.hostname) || endpoint.username || endpoint.password ||
      endpoint.pathname !== '/' || endpoint.search || endpoint.hash || endpoint.origin !== baseUrl) throw new Error('Use an explicit numeric HTTP loopback backend origin without a path, credentials, query or fragment.');
  let local, checked;
  try {
    local = action.local_override;
    const asset = {body:action.response_body,bytes:Buffer.byteLength(action.response_body),sha256:local?.asset_sha256};
    // Revalidate complete prepared actions without extending their original expiry.
    // The artificial check instant permits exact guarded disarm after expiry.
    const checkTime = disarm ? Math.max(0,local.expires_at_ms - 60000) : Date.now();
    checked = overrideAction(asset,{url:local.exact_url,targetId:local.target_id,experimentId:local.experiment_id,sha256:local.asset_sha256,
      method:action.method_filter,contentType:action.response_headers?.['content-type'],ttlMs:local.expires_at_ms-checkTime},checkTime);
    if (JSON.stringify(Object.keys(action).sort()) !== JSON.stringify(Object.keys(checked).sort()) ||
        Object.keys(checked).some(key=>JSON.stringify(action[key]) !== JSON.stringify(checked[key]))) throw new Error();
  } catch {
    throw new Error('Prepared override action is malformed, changed or expired. No operation was sent.');
  }
  const operation = disarm ? {action:'configure_request_interception',mode:'continue',url_pattern:'*',
    expected_local_override:{metadata:local,method_filter:checked.method_filter,content_type:checked.response_headers['content-type']}} : checked;
  try {
    // Direct HTTP deliberately avoids fetch's optional environment-proxy dispatcher.
    // No redirects, retries, cookie jar, auth agent or proxy settings are consulted.
    const result = await sendLoopbackAction(endpoint,operation);
    const publicUrl=new URL(local.exact_url);publicUrl.search='';
    const expectedMetadata={...local,exact_url:publicUrl.href};
    const rule=result.experiment?.rule;
    if(result.ok!==true || result.experiment?.target_id!==local.target_id || result.experiment?.experiment_id!==local.experiment_id ||
        rule?.mode!==(disarm?'continue':'fulfill') ||
        !disarm && (Object.entries(expectedMetadata).some(([key,value])=>rule.local_override?.[key]!==value) ||
          rule.method_filter!==checked.method_filter || rule.response_code!==200 || rule.response_body_bytes!==Buffer.byteLength(checked.response_body))) throw new Error();
    return {format:'reb-local-override-receipt-v1',armed:!disarm,target_id:local.target_id,experiment_id:local.experiment_id,expires_at_ms:disarm?null:local.expires_at_ms,
      instruction:disarm?'Exact local override disarmed.':'Exact local override armed in the disposable target until expiry. Baseline tabs are not overridden.'};
  } catch {
    throw new Error('Backend did not confirm this override operation. Outcome may be unknown; inspect the local Experiment before any retry. No automatic retry was sent.');
  }
}

function sendLoopbackAction(endpoint,operation) {
  return new Promise((resolve,reject)=>{
    const body = Buffer.from(JSON.stringify(operation));
    const req = request(endpoint.origin+'/api/debugger/actions',{method:'POST',agent:false,maxHeaderSize:16384,
      headers:{'content-type':'application/json','content-length':body.length}},response=>{
      const contentTypes=[],encodings=[];
      for(let index=0;index<response.rawHeaders.length;index+=2) {
        const name=response.rawHeaders[index].toLowerCase();
        if(name==='content-type')contentTypes.push(response.rawHeaders[index+1]);
        if(name==='content-encoding')encodings.push(response.rawHeaders[index+1]);
      }
      if(contentTypes.length!==1 || !/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(contentTypes[0]) || encodings.length) {
        req.destroy(new Error('Backend receipt must be unencoded UTF-8 JSON'));return;
      }
      let size=0;const chunks=[];
      response.on('data',chunk=>{
        size+=chunk.length;
        if(size>1048576){req.destroy(new Error('Oversized backend receipt'));return;}
        chunks.push(chunk);
      });
      response.on('error',reject);
      response.on('end',()=>{
        try {
          if(response.statusCode<200 || response.statusCode>=300)throw new Error();
          resolve(client.capturedClientJSON(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks))));
        } catch {reject(new Error('Invalid backend receipt'));}
      });
    });
    const timer=setTimeout(()=>req.destroy(new Error('Backend receipt deadline')),5000);
    req.on('error',reject);
    req.on('close',()=>clearTimeout(timer));
    req.end(body);
  });
}
