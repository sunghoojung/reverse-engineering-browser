// Private, bounded adapters for explicitly exported WebExtensions cookies.
// This module never discovers profiles, reads OS stores, or publishes values.
import {constants} from 'node:fs';
import {open, lstat, realpath} from 'node:fs/promises';
import {resolve, dirname, parse as parsePath, isAbsolute} from 'node:path';
import {inspect} from 'node:util';
import client from '../apps/research-ui/captured_client.js';

export const cookieImportLimits = Object.freeze({bytes:262144, cookies:64, lifetimeMin:30, lifetimeMax:300});
const fail = code => { throw new CookieImportError(code); };
export class CookieImportError extends Error {
  constructor(code) { super(`Cookie import refused (${code}). No source values are included in this diagnostic.`); this.code=code; }
}
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const printable = (value,max) => typeof value === 'string' && value.length <= max && /^[\x20-\x7e]*$/.test(value);
const required = ['domain','hostOnly','httpOnly','name','path','sameSite','secure','session','storeId','value'];
const sameSites = Object.freeze({unspecified:undefined,no_restriction:'None',lax:'Lax',strict:'Strict'});

export function cookieDestination(origin,seconds) {
  if (typeof origin !== 'string' || origin.length > 300 || !Number.isSafeInteger(seconds) || seconds < 30 || seconds > 300) fail('destination');
  let url; try { url=new URL(origin); } catch { fail('destination'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash ||
      origin !== url.origin || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(url.hostname) ||
      /^[0-9.]+$/.test(url.hostname)) fail('destination');
  return Object.freeze({origin:url.origin,host:url.hostname,seconds});
}

function normalize(row,format,destination,now) {
  const optional = ['expirationDate','partitionKey',...(format === 'firefox' ? ['firstPartyDomain'] : [])];
  if (!object(row) || required.some(key=>!Object.hasOwn(row,key)) || Object.keys(row).some(key=>!required.includes(key)&&!optional.includes(key))) fail('fields');
  if (['hostOnly','httpOnly','secure','session'].some(key=>typeof row[key] !== 'boolean')) fail('flags');
  // Chrome has numeric stores; Firefox's container stores have distinct semantics.
  if (format === 'chrome' ? !['0','1'].includes(row.storeId) : !['firefox-default','firefox-private'].includes(row.storeId)) fail('store');
  if (Object.hasOwn(row,'partitionKey') && row.partitionKey !== null) fail('partition');
  if (format === 'firefox' && !Object.hasOwn(row,'firstPartyDomain')) fail('first-party-domain');
  if (Object.hasOwn(row,'firstPartyDomain') && row.firstPartyDomain !== '') fail('first-party-domain');
  if (!Object.hasOwn(sameSites,row.sameSite)) fail('same-site');
  if (!printable(row.domain,253) || row.domain.toLowerCase() !== row.domain || row.domain.endsWith('.') ||
      (row.hostOnly && row.domain.startsWith('.')) || row.domain.replace(/^\./,'') !== destination.host) fail('domain');
  if (!printable(row.name,256) || !row.name || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(row.name)) fail('name');
  if (!printable(row.value,4096) || !/^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/.test(row.value) || row.name.length+row.value.length > 4096) fail('value');
  if (!printable(row.path,1024) || !row.path.startsWith('/') || /[;\\]/.test(row.path)) fail('path');
  if (row.sameSite === 'no_restriction' && !row.secure) fail('same-site-secure');
  if (row.name.startsWith('__Secure-') && !row.secure || row.name.startsWith('__Host-') && (!row.secure || !row.hostOnly || row.path !== '/') ||
      row.name.startsWith('__Http-') && (!row.secure || !row.httpOnly) || row.name.startsWith('__Host-Http-') && (!row.secure || !row.httpOnly || !row.hostOnly || row.path !== '/')) fail('prefix');
  if (row.session ? Object.hasOwn(row,'expirationDate') : typeof row.expirationDate !== 'number' || !Number.isFinite(row.expirationDate) ||
      row.expirationDate <= now+5 || row.expirationDate > now+400*86400) fail('expiry');
  // Preserve the exact reviewed scope and flags in the offline normalization.
  const param={name:row.name,value:row.value,domain:(row.hostOnly?'':'.')+destination.host,path:row.path,secure:row.secure,httpOnly:row.httpOnly};
  if (sameSites[row.sameSite]) param.sameSite=sameSites[row.sameSite];
  if (!row.session) param.expires=row.expirationDate;
  return {param,session:row.session,hostOnly:row.hostOnly,sameSite:row.sameSite};
}

// The only ordinary serialization/inspection surface is the name/value-free review.
// JS strings cannot be securely zeroed. Dropping references is not secure erasure.
export class CookieImportPlan {
  #review;
  constructor(rows,format,destination,now) {
    const seen=new Set();
    if(rows.some(row=>row?.storeId!==rows[0]?.storeId))fail('mixed-stores');
    const cookies=rows.map(row=>normalize(row,format,destination,now));
    for(const {param} of cookies) {
      const key=JSON.stringify([param.domain??destination.host,param.path,param.name]);
      if(seen.has(key)) fail('duplicate-cookie'); seen.add(key);
    }
    this.#review=Object.freeze({format:'reb-private-cookie-import-v1',source_format:format,destination, count:rows.length,
      cookies:Object.freeze(cookies.map(({param,session,hostOnly,sameSite},index)=>Object.freeze({row:index+1,domain:destination.host,
        scope:hostOnly?'exact host':'host and subdomains',path:param.path,secure:param.secure,http_only:param.httpOnly,
        same_site:sameSite,expiry:session?'session':param.expires}))) });
  }
  review() { return this.#review; }
  toJSON() { return this.review(); }
  [inspect.custom]() { return this.review(); }
}

export function parseCookieImport(bytes,format,origin,seconds,now=Date.now()/1000) {
  if(!['chrome','firefox'].includes(format) || !(bytes instanceof Uint8Array) || !bytes.length || bytes.length>cookieImportLimits.bytes || !Number.isFinite(now)) fail('input');
  const destination=cookieDestination(origin,seconds);
  let rows;
  try { rows=client.capturedClientJSON(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes)); }
  catch { fail('json'); }
  if(!Array.isArray(rows)||rows.length===0||rows.length>cookieImportLimits.cookies) fail('count');
  return new CookieImportPlan(rows,format,destination,now);
}

export async function readCookieImport(path,format,origin,seconds) {
  let handle,bytes;
  try {
    if(typeof path!=='string'||!isAbsolute(path)||path.length>4096||path.includes('\0')) fail('file');
    const absolute=resolve(path);
    // Reject links in every selected path component, not just the leaf.
    for(let current=absolute;;current=dirname(current)) {
      if((await lstat(current)).isSymbolicLink()) fail('file');
      if(current===parsePath(current).root) break;
    }
    if(await realpath(absolute)!==absolute) fail('file');
    handle=await open(absolute,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    const before=await handle.stat();
    if(!before.isFile()||before.size===0||before.size>cookieImportLimits.bytes) fail('file');
    bytes=Buffer.alloc(cookieImportLimits.bytes+1);let used=0;
    while(used<bytes.length) {const {bytesRead}=await handle.read(bytes,used,bytes.length-used,null);if(!bytesRead)break;used+=bytesRead;}
    const after=await handle.stat();
    if(used!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||used>cookieImportLimits.bytes) fail('file-changed');
    return parseCookieImport(bytes.subarray(0,used),format,origin,seconds);
  } catch(error) { if(error instanceof CookieImportError) throw error; fail('file'); }
  finally { bytes?.fill(0); await handle?.close(); }
}
