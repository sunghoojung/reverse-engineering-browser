// Offline historical override snapshots; no browser execution or backend transport.
import {constants} from 'node:fs';
import {open,realpath} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {createHash} from 'node:crypto';
import {saveArchive} from './captured-request-export.mjs';

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
