/* One observed operation, explicit local copies, no automatic target requests.
 * Capture evidence and runnable inputs remain separate representations. */
// The offline command uses the same exporter, without loading the UI or a browser.
const capturedClientTrafficDocument = typeof module === 'object' && module?.exports && typeof require === 'function'
  ? require('./traffic_view.js').trafficCaptureDocument : (...args) => trafficCaptureDocument(...args);

function capturedClientIssues(request) {
  const problems = [], bytes = value => typeof value === 'string' ? new TextEncoder().encode(value).length : Infinity;
  const wellFormed = value => typeof value === 'string' && !Array.from(value).some(character => {
    const code = character.codePointAt(0); return code >= 0xd800 && code <= 0xdfff;
  });
  if (!request || typeof request !== 'object') return ['Request input is unavailable.'];
  if (typeof request.method !== 'string' || !/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/.test(request.method)) problems.push('Method is not an exact supported uppercase HTTP token.');
  if (['CONNECT','TRACE','TRACK'].includes(request.method)) problems.push('This method is forbidden by the Fetch HTTP client.');
  try {
    const url = new URL(request.url);
    if (typeof request.url !== 'string' || bytes(request.url) > 8192 || !wellFormed(request.url) || request.url.trim() !== request.url || /[\u0000-\u0020\u007f]/.test(request.url) ||
        !['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.hash) throw new Error();
  } catch { problems.push('URL must be complete HTTP(S), at most 8 KiB, without credentials, fragments or controls.'); }
  const forbidden = new Set(['authorization','proxy-authorization','cookie','cookie2','set-cookie','host','content-length','connection','transfer-encoding',
    'accept-charset','accept-encoding','access-control-request-headers','access-control-request-method','date','dnt','expect','keep-alive','origin','referer','te','trailer','upgrade','user-agent','via']);
  const seen = new Set(); let total = 0;
  if (!Array.isArray(request.headers) || request.headers.length > 64) problems.push('At most 64 complete header pairs are supported.');
  else for (const pair of request.headers) {
    if (!Array.isArray(pair) || pair.length !== 2 || pair.some(value => !wellFormed(value))) { problems.push('A header pair is malformed.'); continue; }
    const [name,value] = pair, lower = name.toLowerCase(); total += bytes(name) + bytes(value);
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || bytes(name) > 128 || bytes(value) > 2048 || /[\u0000-\u001f\u007f\u0100-\uffff]/.test(value) || value.trim() !== value) problems.push('A header exceeds supported token, value or control-character limits.');
    if (seen.has(lower)) problems.push('Duplicate header names cannot be represented faithfully by Repeater.');
    seen.add(lower);
    if (forbidden.has(lower) || lower.startsWith('sec-') || lower.startsWith('proxy-')) problems.push('A credential, transport or browser-controlled header requires explicit manual editing; it is not silently removed.');
    if (['x-http-method','x-http-method-override','x-method-override'].includes(lower) && value.split(',').some(method => ['CONNECT','TRACE','TRACK'].includes(method.trim().toUpperCase()))) problems.push('This method-override header is forbidden by browser Fetch.');
    if (lower === 'content-encoding') problems.push('Encoded request bodies require manual reconstruction from original bytes.');
    if (lower === 'content-type') {
      const type = value.split(';')[0].trim().toLowerCase();
      if (!/^(?:text\/[a-z0-9.+-]+|application\/(?:json|[a-z0-9.-]+\+json|xml|[a-z0-9.-]+\+xml|x-www-form-urlencoded|graphql|x-ndjson|ndjson))$/.test(type)) problems.push('Multipart, binary and unrecognized media types are unsupported in this text-only client.');
      // Consume every parameter; a first-match charset regex misses conflicts
      // and treats malformed declarations as if no charset were supplied.
      const parameter = /\s*;\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*=\s*(?:([!#$%&'*+.^_`|~0-9A-Za-z-]+)|"((?:[^"\\]|\\.)*)")\s*(?=;|$)/y;
      let position = value.split(';',1)[0].length, charsetSeen = false;
      while (position < value.length) {
        parameter.lastIndex = position;
        const match = parameter.exec(value);
        if (!match) { problems.push('Malformed Content-Type parameters are unsupported.'); break; }
        position = parameter.lastIndex;
        const name = match[1].toLowerCase();
        if (name === 'charset') {
          const charset = match[2] ?? match[3].replace(/\\(.)/g,'$1');
          if (charsetSeen || !/^utf-?8$/i.test(charset)) problems.push('Exactly one UTF-8 charset declaration is supported.');
          charsetSeen = true;
        } else if (name.startsWith('charset*')) problems.push('Extended or segmented charset declarations are unsupported.');
      }
    }
  }
  if (total > 16384) problems.push('Header text exceeds 16 KiB.');
  if (!wellFormed(request.body) || bytes(request.body) > 65536) problems.push('A complete UTF-8 text body of at most 64 KiB is required.');
  if (['GET','HEAD'].includes(request.method) && request.body !== '') problems.push('GET and HEAD bodies cannot be replayed by this HTTP client.');
  if (!Number.isInteger(request.timeout_ms) || request.timeout_ms < 100 || request.timeout_ms > 30000) problems.push('Timeout must be between 100 and 30000 ms.');
  return [...new Set(problems)];
}

/* Exact identity of a saved Traffic capture wrapper ({captureRecord, captureOwner}).
 * Never derive identity from a displayed URL, rounded timestamps or a reusable
 * protocol request ID. Live native Traffic rows carry no captureRecord. */
function capturedRequestIdentity(request) {
  const record = request?.captureRecord, owner = request?.captureOwner;
  const bounded = (value, max) => typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= max;
  if (!record || !Array.isArray(owner) || owner.length !== 2 || request.id !== record.id || request.tabId !== record.target_id ||
      !bounded(owner[0], 128) || !Number.isSafeInteger(owner[1]) || owner[1] < 0 ||
      !bounded(record.id, 8192) || !bounded(record.target_id, 4096) ||
      typeof record.started_monotonic_ms !== 'number' || !Number.isFinite(record.started_monotonic_ms) || record.started_monotonic_ms < 0) return null;
  return {instance: owner[0], epoch: owner[1], request: record.id, target: record.target_id, started: record.started_monotonic_ms};
}

function capturedClientCapture(request) {
  const identity = capturedRequestIdentity(request);
  if (!identity) throw new TypeError('A saved capture with an exact identity is required.');
  return capturedClientSource(identity, capturedClientTrafficDocument(request, 'raw'));
}

function capturedClientSource(identity, evidence) {
  const record = evidence.record;
  if (new TextEncoder().encode(JSON.stringify(evidence)).length > 786432) throw new TypeError('This capture exceeds the 768 KiB project evidence limit. Use the existing raw capture export.');
  const body = record.request.body;
  const input = {method:record.method,url:record.url,headers:record.request.headers.map(pair => [...pair]),
    body:body.state === 'empty' ? '' : body.state === 'available' && !body.base64 ? body.text : null,timeout_ms:15000};
  const problems = capturedClientIssues(input);
  if (record.method_truncated || record.url_truncated || record.request.headers_truncated) problems.push('Method, URL or request headers are truncated.');
  if (body.state === 'empty' && (body.text || body.base64)) problems.push('An empty-body marker conflicts with retained body content.');
  if (body.truncated || !['available','empty'].includes(body.state) || body.base64) problems.push('Request body is missing, incomplete, binary or unavailable. Original evidence is retained separately.');
  const templateProblems = Object.values(input).filter(value => typeof value === 'string').concat(input.headers.flat())
    .some(value => value.includes('{{')) ? ['Literal template delimiters require manual editing before Repeater import; raw project export preserves them.'] : [];
  return {kind:'capture',identity,input,evidence,problems:[...new Set(problems)],templateProblems};
}

function capturedClientRun(entry, context, capture = null) {
  if (!entry?.resolved_request || !Number.isSafeInteger(entry.id) || entry.id < 1 || typeof context !== 'string' || !context) throw new TypeError('Choose a retained Repeater run.');
  const resolved = entry.resolved_request;
  const input = {method:resolved.method,url:resolved.url,headers:resolved.headers.map(({name,value}) => [name,value]),body:resolved.body,timeout_ms:resolved.timeout_ms};
  const evidence = JSON.parse(JSON.stringify(entry));
  if (new TextEncoder().encode(JSON.stringify(evidence)).length > 786432) throw new TypeError('This run exceeds the project evidence limit.');
  return {kind:'repeater',identity:{context,execution_id:entry.id,started_at_ms:entry.started_at_ms},input,evidence,
    capture:capture ? JSON.parse(JSON.stringify(capture)) : null,problems:capturedClientIssues(input),templateProblems:[]};
}

function capturedClientRedactUrl(value) {
  try { const url = new URL(value); if (!['http:','https:','ws:','wss:'].includes(url.protocol)) return '<redacted>';
    url.username = ''; url.password = ''; url.search = ''; url.hash = ''; return url.href; } catch { return '<redacted>'; }
}
function capturedClientRedactInput(input) {
  return {...input,url:capturedClientRedactUrl(input.url),headers:input.headers.map(([name]) => [name,'<redacted>']),body:'<redacted>'};
}
function capturedClientCaptureCopy(document, mode) {
  const copy = capturedClientTrafficDocument({captureRecord:document.record},mode);
  // Preserve explicitly unknown window coverage and saved-snapshot provenance.
  copy.coverage = JSON.parse(JSON.stringify(document.coverage));
  return copy;
}

// Stored ZIP records, CRC-32 and UTF-8 names; no compression/encryption/ZIP64.
// Format reference: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
function capturedClientZip(files) {
  if (!Array.isArray(files) || !files.length || files.length > 16) throw new TypeError('Project file count exceeds its bound.');
  const encoder = new TextEncoder(), names = new Set(), locals = [], central = []; let offset = 0, directorySize = 0;
  const crc = bytes => { let value = 0xffffffff; for (const byte of bytes) { value ^= byte; for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ (value & 1 ? 0xedb88320 : 0); } return (value ^ 0xffffffff) >>> 0; };
  for (const file of files) {
    if (typeof file.path !== 'string' || !file.path.startsWith('reb-client-project/') || file.path.split('/').some(part => !/^[A-Za-z0-9_.-]+$/.test(part) || part === '.' || part === '..' || part.endsWith('.')) || names.has(file.path)) throw new TypeError('Unsafe or repeated project path.');
    names.add(file.path); const name = encoder.encode(file.path), body = encoder.encode(file.text);
    if (typeof file.text !== 'string' || body.length > 1048576 || offset + body.length + name.length + 30 > 2097152) throw new TypeError('Project exceeds its 2 MiB bound.');
    const checksum = crc(body), local = new Uint8Array(30 + name.length + body.length), l = new DataView(local.buffer);
    l.setUint32(0,0x04034b50,true); l.setUint16(4,20,true); l.setUint16(6,0x800,true); l.setUint16(12,33,true);
    l.setUint32(14,checksum,true); l.setUint32(18,body.length,true); l.setUint32(22,body.length,true); l.setUint16(26,name.length,true);
    local.set(name,30); local.set(body,30+name.length); locals.push(local);
    const record = new Uint8Array(46+name.length), c = new DataView(record.buffer);
    c.setUint32(0,0x02014b50,true); c.setUint16(4,20,true); c.setUint16(6,20,true); c.setUint16(8,0x800,true); c.setUint16(14,33,true);
    c.setUint32(16,checksum,true); c.setUint32(20,body.length,true); c.setUint32(24,body.length,true); c.setUint16(28,name.length,true); c.setUint32(42,offset,true);
    record.set(name,46); central.push(record); offset += local.length; directorySize += record.length;
  }
  const end = new Uint8Array(22), e = new DataView(end.buffer);
  e.setUint32(0,0x06054b50,true); e.setUint16(8,files.length,true); e.setUint16(10,files.length,true); e.setUint32(12,directorySize,true); e.setUint32(16,offset,true);
  const output = new Uint8Array(offset+directorySize+end.length); let cursor=0;
  for (const part of [...locals,...central,end]) { output.set(part,cursor); cursor += part.length; }
  if (output.length > 2097152) throw new TypeError('Project exceeds its 2 MiB bound.');
  return output;
}

function capturedClientFailure(code, message, result = null) {
  const error = new Error(message); error.name = 'ClientError'; error.code = code; error.result = result; return error;
}

// Shared configuration describes supported policies, never captured browser state.
function capturedClientConfig(config, request) {
  const fail = message => { throw capturedClientFailure('invalid_config',message); };
  const object = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => keys.includes(key));
  if (!object(config,['configVersion','allowedOrigin','request','transport','timeoutMs','redirectPolicy','cookiePolicy','responseChecks'])) fail('Unknown or malformed client configuration.');
  if (config.configVersion !== undefined && config.configVersion !== 'reb-client-config-v1') fail('Unsupported configVersion.');
  const transport = config.transport ?? {mode:'standard',browserProfile:null};
  if (!object(transport,['mode','browserProfile']) || typeof transport.mode !== 'string') fail('transport requires a supported mode.');
  if (transport.mode !== 'standard') throw capturedClientFailure('unsupported_transport','JavaScript supports standard HTTP only; browser-profile transport requires the optional Go Mimic build. No fallback was attempted.');
  if (transport.browserProfile != null) throw capturedClientFailure('unsupported_profile','Standard HTTP does not accept a browser profile.');
  const timeoutMs = config.timeoutMs ?? request?.timeout_ms;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) fail('timeoutMs must be 100–30000 ms.');
  const redirectPolicy = config.redirectPolicy ?? 'manual', cookiePolicy = config.cookiePolicy ?? 'omit';
  if (!['manual','error'].includes(redirectPolicy)) fail('redirectPolicy must be manual or error; redirects are never followed.');
  if (cookiePolicy !== 'omit') fail('cookiePolicy must be omit; browser cookies are never acquired.');
  const checks = config.responseChecks ?? {statuses:[],contentType:null,jsonFields:[]};
  if (!object(checks,['statuses','contentType','jsonFields'])) fail('Malformed responseChecks.');
  const statuses = checks.statuses ?? [], contentType = checks.contentType ?? null, jsonFields = checks.jsonFields ?? [];
  if (!Array.isArray(statuses) || statuses.length > 32 || statuses.some(value => !Number.isInteger(value) || value < 100 || value > 599) || new Set(statuses).size !== statuses.length) fail('statuses must be at most 32 distinct HTTP status integers.');
  if (contentType !== null && (typeof contentType !== 'string' || contentType.length > 128 || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(contentType))) fail('contentType must be a lowercase media type without parameters.');
  if (!Array.isArray(jsonFields) || jsonFields.length > 32) fail('At most 32 JSON field checks are supported.');
  for (const field of jsonFields) {
    if (!object(field,['pointer','type','equals']) || typeof field.pointer !== 'string' || new TextEncoder().encode(field.pointer).length > 1024 || (field.pointer !== '' && !field.pointer.startsWith('/')) || /~(?![01])/.test(field.pointer) || field.pointer.split('/').length > 33) fail('Each JSON field requires a bounded RFC 6901 pointer.');
    if (!['null','boolean','number','string','array','object'].includes(field.type)) fail('Each JSON field requires an explicit supported type.');
    if (Object.hasOwn(field,'equals') && !(field.equals === null && field.type === 'null' || typeof field.equals === 'string' && field.type === 'string' && new TextEncoder().encode(field.equals).length <= 2048 || typeof field.equals === 'boolean' && field.type === 'boolean' || Number.isSafeInteger(field.equals) && field.type === 'number')) fail('equals supports matching scalar types and safe integer numbers only.');
  }
  return {transport,timeoutMs,redirectPolicy,cookiePolicy,responseChecks:{statuses,contentType,jsonFields}};
}

// JSON.parse alone silently accepts duplicate keys. Scan bounded response JSON
// first, then use its ordinary parser; this scanner never evaluates input.
function capturedClientJSON(text, numberLexemes = null) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > 1048576) throw new SyntaxError('JSON exceeds 1 MiB.');
  let index = 0;
  const fail = () => { throw new SyntaxError('Malformed, duplicate-key or excessively nested JSON.'); };
  const space = () => { while (/[\x20\t\r\n]/.test(text[index] ?? '\0')) index++; };
  const string = () => {
    const start = index++; let escaped = false;
    while (index < text.length) {
      const character = text[index++];
      if (!escaped && character === '"') { const decoded = JSON.parse(text.slice(start,index)); if (Array.from(decoded).some(part => part.codePointAt(0) >= 0xd800 && part.codePointAt(0) <= 0xdfff)) fail(); return decoded; }
      if (!escaped && character === '\\') escaped = true; else escaped = false;
    }
    fail();
  };
  const value = (depth,path = '') => {
    if (depth > 64) fail(); space();
    if (text[index] === '"') { string(); return; }
    const opening = text[index];
    if (opening === '{' || opening === '[') {
      index++; space(); const end = opening === '{' ? '}' : ']', keys = new Set();
      if (text[index] === end) { index++; return; }
      let element = 0;
      for (;;) {
        let key = String(element++);
        if (opening === '{') { if (text[index] !== '"') fail(); key = string(); if (keys.has(key)) fail(); keys.add(key); space(); if (text[index++] !== ':') fail(); }
        value(depth+1,path+'/'+key.replace(/~/g,'~0').replace(/\//g,'~1')); space(); if (text[index] === end) { index++; return; }
        if (text[index++] !== ',') fail(); space();
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(index));
    if (!token) fail(); if (numberLexemes && /^-?[0-9]/.test(token[0])) numberLexemes.set(path,token[0]); index += token[0].length;
  };
  value(0); space(); if (index !== text.length) fail(); return JSON.parse(text);
}

function capturedClientInputJSON(text) {
  const numbers = new Map(), value = capturedClientJSON(text,numbers);
  for (const token of numbers.values()) if (!/^-?(0|[1-9][0-9]*)$/.test(token) || !Number.isSafeInteger(Number(token))) throw new SyntaxError('Request/config numbers must be exact safe integer tokens.');
  return value;
}

function capturedClientValidateResponse(result, policy) {
  const fail = (code,message) => { throw capturedClientFailure(code,message,result); };
  const checks = policy.responseChecks;
  result.validation = {configured:!!(checks.statuses.length || checks.contentType || checks.jsonFields.length),passed:false};
  if (policy.redirectPolicy === 'error' && result.status >= 300 && result.status <= 399) fail('redirect_refused','Redirect response refused; no redirect was followed.');
  if (checks.statuses.length && !checks.statuses.includes(result.status)) fail('response_status','Response status does not match the configured accepted statuses.');
  const contentTypes = result.headers.filter(([name]) => name.toLowerCase() === 'content-type');
  const contentType = contentTypes[0]?.[1].split(';')[0].trim().toLowerCase();
  if (checks.contentType && (contentTypes.length !== 1 || contentType !== checks.contentType)) fail('response_content_type','Response Content-Type does not match the configured media type.');
  if (result.validation.configured && result.body_truncated) fail('response_truncated','A bounded or incomplete response cannot pass configured response checks.');
  if (checks.jsonFields.length) {
    const numberLexemes = new Map();
    let body; try { if (result.body_invalid_utf8) throw new SyntaxError(); body = capturedClientJSON(result.body,numberLexemes); } catch { fail('response_json','Response is not complete valid JSON with unique keys.'); }
    for (const field of checks.jsonFields) {
      let value = body;
      const parts = field.pointer === '' ? [] : field.pointer.slice(1).split('/').map(part => part.replace(/~1/g,'/').replace(/~0/g,'~'));
      for (const part of parts) {
        if (value === null || typeof value !== 'object' || Array.isArray(value) && !/^(0|[1-9][0-9]*)$/.test(part) || !Object.hasOwn(value,part)) fail('response_field_missing','A configured JSON pointer is absent from the response.');
        value = value[part];
      }
      const type = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
      if (type !== field.type || type === 'number' && !Number.isFinite(value)) fail('response_field_type','A configured JSON field has the wrong type.');
      if (Object.hasOwn(field,'equals') && field.type === 'number' && (!/^-?(0|[1-9][0-9]*)$/.test(numberLexemes.get(field.pointer) ?? '') || BigInt(numberLexemes.get(field.pointer)) !== BigInt(field.equals))) fail('response_field_value','Numeric equals requires an exact safe integer JSON token, without fractions or exponent notation.');
      if (Object.hasOwn(field,'equals') && value !== field.equals) fail('response_field_value','A configured JSON field has an unexpected value.');
    }
  }
  result.validation.passed = result.validation.configured;
  return result;
}

async function capturedClientSend(input, {config = {},send = false,provenance = {}} = {}) {
  const request = config?.request ?? input;
  const issues = capturedClientIssues(request); let policy, configurationError;
  if (request && Object.keys(request).some(key => !['method','url','headers','body','timeout_ms'].includes(key))) issues.push('Unknown or incorrectly cased request key.');
  try { policy = capturedClientConfig(config,request); } catch (error) { configurationError = error; issues.push(error.message); }
  if (!config?.request && (provenance.format !== 'reb-client-project-v1' || provenance.mode !== 'raw' || provenance.problems?.length)) issues.push('Provide a complete reviewed config.request; the exported evidence is redacted or unsupported.');
  if (!send) return {dry_run:true,network_requests:0,ready:issues.length === 0,problems:issues,method:request?.method,policy,
    instruction:'Review evidence and config.json, set allowedOrigin, then explicitly run the example with --send.'};
  if (configurationError) throw configurationError;
  if (issues.length) throw capturedClientFailure('invalid_input',issues.join(' '));
  if (typeof config.allowedOrigin !== 'string' || new URL(request.url).origin !== config.allowedOrigin) throw capturedClientFailure('wrong_origin','config.allowedOrigin must exactly match the reviewed request origin.');
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(),policy.timeoutMs);
  let result = {network_attempted:true,network_requests:null,instruction:'The server may have processed this request; check its state before deciding whether another send is safe. No automatic retry occurred.'};
  try {
    // Generated projects use Node's built-in direct transport, independent of
    // ambient Fetch dispatchers, HTTP_PROXY and NODE_USE_ENV_PROXY.
    const {request:sendRequest} = await import(new URL(request.url).protocol === 'https:' ? 'node:https' : 'node:http');
    result = await new Promise((resolve,reject) => {
      const outbound = sendRequest(request.url,{method:request.method,headers:Object.fromEntries(request.headers),agent:false,rejectUnauthorized:true,signal:controller.signal},response => {
        const chunks = []; let count = 0;
        const headers = []; for (let index=0;index<response.rawHeaders.length;index+=2) headers.push([response.rawHeaders[index],response.rawHeaders[index+1]]);
        const snapshot = truncated => {
          const bytes = new Uint8Array(count); let offset = 0; for (const chunk of chunks) { bytes.set(chunk,offset); offset+=chunk.length; }
          let body, invalidUTF8 = false; try { body = new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes); } catch { body = new TextDecoder('utf-8',{ignoreBOM:true}).decode(bytes); invalidUTF8 = true; }
          return {...result,network_requests:1,status:response.statusCode,url:request.url,redirect_followed:false,headers,body,body_invalid_utf8:invalidUTF8,body_truncated:truncated};
        };
        result = snapshot(false);
        response.on('data',chunk => { const remaining = 65536-count; chunks.push(chunk.subarray(0,remaining)); count += Math.min(remaining,chunk.length); result = snapshot(false); if (chunk.length > remaining) { resolve(snapshot(true)); response.destroy(); } });
        response.on('end',() => resolve(snapshot(false)));
        response.on('error',error => reject(capturedClientFailure(controller.signal.aborted ? 'timeout' : 'response_read',controller.signal.aborted ? 'Request deadline expired; no automatic retry occurred.' : 'Response body could not be read completely.',snapshot(true))));
      });
      outbound.on('error',error => reject(error));
      outbound.end(request.body);
    });
    return capturedClientValidateResponse(result,policy);
  } catch (error) {
    if (error.name === 'ClientError') throw error;
    if (result.status) result.body_truncated = true;
    throw capturedClientFailure(controller.signal.aborted ? 'timeout' : result.status ? 'response_read' : 'network',controller.signal.aborted ? 'Request deadline expired; no automatic retry occurred.' : 'Transport failed; the server outcome may be unknown.',result);
  } finally { clearTimeout(timer); }
}

// Fixed standard-library Go project; captured inputs remain shared JSON data.
function capturedClientGoFiles() {
  return {
    "go/go.mod":"module reb.local/observed\n\ngo 1.23.0\n",
    "go/client/mimic.go":String.raw`//go:build mimic

// Optional transport, pinned to github.com/saucesteals/mimic v1.0.2
// (946a948a9b5a4360847b7f7d4b1f2e63f64ddc9e), MIT.
// Enable only after the explicit dependency/review steps in README.md.
// This is a named compatibility candidate, not captured-browser equivalence.
package client

import (
    "context"
    "errors"
    "net"
    "net/http"
    "strings"
    "sync/atomic"
    "time"

    fhttp "github.com/saucesteals/fhttp"
    "github.com/saucesteals/mimic"
)

func init() { browserProfileSend=sendMimic }

func sendMimic(ctx context.Context,input Request,profile BrowserProfile) (*http.Response,func(),error) {
    if profile.Browser!="chrome" || profile.Version!="133.0.0.0" || profile.Platform!="linux" {
        return nil,nil,errors.New("unsupported browser profile")
    }
    deadline:=time.Duration(input.TimeoutMS)*time.Millisecond
    // fhttp's H2 stack can retry REFUSED_STREAM/GOAWAY. Single-use connections
    // plus one transport dial invocation refuse another stream/connection for this send.
    // Keep the transport fresh per operation; never share it or add a proxy.
    var dialed atomic.Bool
    base:=&fhttp.Transport{Proxy:nil,DisableKeepAlives:true,DisableCompression:true,
        ForceAttemptHTTP2:true,MaxResponseHeaderBytes:65536,TLSHandshakeTimeout:deadline,
        DialContext:func(ctx context.Context,network,address string)(net.Conn,error){
            if !dialed.CompareAndSwap(false,true) { return nil,errors.New("additional transport connection refused; review server state before another send") }
            return (&net.Dialer{}).DialContext(ctx,network,address)
        }}
    transport,err:=mimic.NewTransport(mimic.TransportOptions{Version:profile.Version,
        Brand:mimic.BrandChrome,Platform:mimic.PlatformLinux,Transport:base})
    if err!=nil { return nil,nil,err }
    cleanup:=transport.CloseIdleConnections
    if base.TLSNextProto["h2"]==nil { cleanup();return nil,nil,errors.New("pinned HTTP/2 profile initialization is unavailable") }
    request,err:=fhttp.NewRequestWithContext(ctx,input.Method,input.URL,strings.NewReader(*input.Body))
    if err!=nil { cleanup();return nil,nil,err }
    // Prevent body replay where the underlying transport checks GetBody. Empty
    // bodies are additionally protected by the single-dial-invocation/single-use boundary.
    request.GetBody=nil
    for _,pair:=range input.Headers { request.Header.Set(pair[0],pair[1]) }
    client:=&fhttp.Client{Transport:transport,Timeout:deadline,
        CheckRedirect:func(*fhttp.Request,[]*fhttp.Request)error{return fhttp.ErrUseLastResponse}}
    response,err:=client.Do(request)
    if err!=nil { cleanup();return nil,nil,err }
    standardRequest,err:=http.NewRequestWithContext(ctx,input.Method,input.URL,nil)
    if err!=nil { response.Body.Close();cleanup();return nil,nil,err }
    // TLS state types differ; do not invent a crypto/tls observation or cast it.
    return &http.Response{Status:response.Status,StatusCode:response.StatusCode,
        Proto:response.Proto,ProtoMajor:response.ProtoMajor,ProtoMinor:response.ProtoMinor,
        Header:http.Header(response.Header),Body:response.Body,ContentLength:response.ContentLength,
        Close:response.Close,Uncompressed:response.Uncompressed,Trailer:http.Header(response.Trailer),
        Request:standardRequest},cleanup,nil
}
`,
    "go/client/client.go":String.raw`// Package client sends only a complete, explicitly reviewed text request.
// It uses standard net/http HTTP/1.1, not the captured browser's TLS profile.
package client

import (
    "context"
    "crypto/tls"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "mime"
    "strconv"
    "net"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "sort"
    "strings"
    "time"
    "unicode/utf8"
)

type Request struct {
    Method string ${'`'}json:"method"${'`'}
    URL string ${'`'}json:"url"${'`'}
    Headers HeaderPairs ${'`'}json:"headers"${'`'}
    Body *string ${'`'}json:"body"${'`'}
    TimeoutMS int ${'`'}json:"timeout_ms"${'`'}
}
// Header pairs reject JSON nulls rather than silently converting them to empty strings.
type HeaderPairs [][]string
func (headers *HeaderPairs) UnmarshalJSON(data []byte) error {
    if strings.TrimSpace(string(data)) == "null" { return errors.New("Header pairs cannot be null") }
    var pairs []json.RawMessage
    if err:=json.Unmarshal(data,&pairs);err!=nil { return err }
    if len(pairs)>64 { return errors.New("At most 64 header pairs are supported") }
    result:=make(HeaderPairs,0,len(pairs))
    for _,raw:=range pairs {
        var members []json.RawMessage
        if err:=json.Unmarshal(raw,&members);err!=nil { return err }
        if len(members)!=2 { return errors.New("Each header must contain exactly two strings") }
        pair:=make([]string,2)
        for i,member:=range members {
            value:=strings.TrimSpace(string(member))
            if len(value)<2 || value[0]!='"' { return errors.New("Header names and values must be strings, never null") }
            if err:=json.Unmarshal(member,&pair[i]);err!=nil { return err }
        }
        result=append(result,pair)
    }
    *headers=result
    return nil
}
type Config struct {
    ConfigVersion string ${'`'}json:"configVersion"${'`'}
    AllowedOrigin string ${'`'}json:"allowedOrigin"${'`'}
    Request *Request ${'`'}json:"request"${'`'}
    Transport *TransportConfig ${'`'}json:"transport"${'`'}
    TimeoutMS *int ${'`'}json:"timeoutMs"${'`'}
    RedirectPolicy *string ${'`'}json:"redirectPolicy"${'`'}
    CookiePolicy *string ${'`'}json:"cookiePolicy"${'`'}
    ResponseChecks *ResponseChecks ${'`'}json:"responseChecks"${'`'}
}
type TransportConfig struct {
    Mode string ${'`'}json:"mode"${'`'}
    BrowserProfile *BrowserProfile ${'`'}json:"browserProfile"${'`'}
}
type BrowserProfile struct {
    Browser string ${'`'}json:"browser"${'`'}
    Version string ${'`'}json:"version"${'`'}
    Platform string ${'`'}json:"platform"${'`'}
}
type ResponseChecks struct {
    Statuses []int ${'`'}json:"statuses"${'`'}
    ContentType *string ${'`'}json:"contentType"${'`'}
    JSONFields []JSONField ${'`'}json:"jsonFields"${'`'}
}
type JSONField struct {
    Pointer string ${'`'}json:"pointer"${'`'}
    Type string ${'`'}json:"type"${'`'}
    Equals json.RawMessage ${'`'}json:"equals,omitempty"${'`'}
}
type Validation struct {
    Configured bool ${'`'}json:"configured"${'`'}
    Passed bool ${'`'}json:"passed"${'`'}
}
type Policy struct {
    Transport TransportConfig ${'`'}json:"transport"${'`'}
    TimeoutMS int ${'`'}json:"timeoutMs"${'`'}
    RedirectPolicy string ${'`'}json:"redirectPolicy"${'`'}
    CookiePolicy string ${'`'}json:"cookiePolicy"${'`'}
    ResponseChecks ResponseChecks ${'`'}json:"responseChecks"${'`'}
}
type ClientError struct { Code string; Message string }
func (err *ClientError) Error() string { return err.Code+": "+err.Message }
func failure(code,message string) error { return &ClientError{Code:code,Message:message} }

func strictObject(data []byte, allowed, required []string) error {
    fields,err:=exactFields(data,allowed,required);if err!=nil { return err }
    for _,key:=range required { if string(fields[key])=="null" { return errors.New("Required configuration fields cannot be null") } }
    return nil
}
func (value *TransportConfig) UnmarshalJSON(data []byte) error {
    if err:=strictObject(data,[]string{"mode","browserProfile"},[]string{"mode"});err!=nil { return err }
    type plain TransportConfig;var parsed plain
    if err:=json.Unmarshal(data,&parsed);err!=nil { return err };*value=TransportConfig(parsed);return nil
}
func (value *BrowserProfile) UnmarshalJSON(data []byte) error {
    keys:=[]string{"browser","version","platform"}
    if err:=strictObject(data,keys,keys);err!=nil { return err }
    type plain BrowserProfile;var parsed plain
    if err:=json.Unmarshal(data,&parsed);err!=nil { return err };*value=BrowserProfile(parsed);return nil
}
func (value *ResponseChecks) UnmarshalJSON(data []byte) error {
    if err:=strictObject(data,[]string{"statuses","contentType","jsonFields"},nil);err!=nil { return err }
    type plain ResponseChecks;var parsed plain
    if err:=json.Unmarshal(data,&parsed);err!=nil { return err };*value=ResponseChecks(parsed);return nil
}
func (value *JSONField) UnmarshalJSON(data []byte) error {
    if err:=strictObject(data,[]string{"pointer","type","equals"},[]string{"pointer","type"});err!=nil { return err }
    type plain JSONField;var parsed plain
    if err:=json.Unmarshal(data,&parsed);err!=nil { return err };*value=JSONField(parsed);return nil
}

var mediaType = regexp.MustCompile("^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
var pointerEscape = regexp.MustCompile("~[^01]|~$")
var arrayIndex = regexp.MustCompile("^(0|[1-9][0-9]*)$")
var integerToken = regexp.MustCompile("^-?(0|[1-9][0-9]*)$")
// The optional build-tag adapter registers one audited profile implementation.
// Missing adapters are explicit errors, never a downgrade to standard HTTP.
var browserProfileSend func(context.Context,Request,BrowserProfile) (*http.Response,func(),error)
func configure(config Config,input Request) (Policy,error) {
    policy:=Policy{Transport:TransportConfig{Mode:"standard"},TimeoutMS:input.TimeoutMS,RedirectPolicy:"manual",CookiePolicy:"omit"}
    if config.ConfigVersion!="" && config.ConfigVersion!="reb-client-config-v1" { return policy,failure("invalid_config","Unsupported configVersion") }
    if config.Transport!=nil { policy.Transport=*config.Transport }
    if config.TimeoutMS!=nil { policy.TimeoutMS=*config.TimeoutMS }
    if config.RedirectPolicy!=nil { policy.RedirectPolicy=*config.RedirectPolicy }
    if config.CookiePolicy!=nil { policy.CookiePolicy=*config.CookiePolicy }
    if config.ResponseChecks!=nil { policy.ResponseChecks=*config.ResponseChecks }
    invalid:=func(message string)(Policy,error){return policy,failure("invalid_config",message)}
    if policy.TimeoutMS<100 || policy.TimeoutMS>30000 { return invalid("timeoutMs must be 100-30000 ms") }
    if policy.RedirectPolicy!="manual" && policy.RedirectPolicy!="error" { return invalid("redirectPolicy must be manual or error; redirects are never followed") }
    if policy.CookiePolicy!="omit" { return invalid("cookiePolicy must be omit; browser cookies are never acquired") }
    switch policy.Transport.Mode {
    case "standard":
        if policy.Transport.BrowserProfile!=nil { return policy,failure("unsupported_profile","Standard HTTP does not accept a browser profile") }
    case "browser-profile":
        profile:=policy.Transport.BrowserProfile
        if profile==nil || profile.Browser!="chrome" || profile.Version!="133.0.0.0" || profile.Platform!="linux" {
            return policy,failure("unsupported_profile","Only the pinned chrome 133.0.0.0 linux profile is supported; version/platform substitution is refused")
        }
        if browserProfileSend==nil { return policy,failure("unsupported_transport","Browser-profile transport requires the optional Go Mimic build; no fallback was attempted") }
    default: return policy,failure("unsupported_transport","Unknown transport mode; no browser execution or automatic fallback is implemented")
    }
    checks:=policy.ResponseChecks
    if len(checks.Statuses)>32 { return invalid("At most 32 accepted statuses are supported") }
    seen:=map[int]bool{}
    for _,status:=range checks.Statuses { if status<100 || status>599 || seen[status] { return invalid("statuses must contain distinct HTTP status integers") };seen[status]=true }
    if checks.ContentType!=nil && (len(*checks.ContentType)>128 || !mediaType.MatchString(*checks.ContentType)) { return invalid("contentType must be a lowercase media type without parameters") }
    if len(checks.JSONFields)>32 { return invalid("At most 32 JSON field checks are supported") }
    for _,field:=range checks.JSONFields {
        if len(field.Pointer)>1024 || field.Pointer!="" && !strings.HasPrefix(field.Pointer,"/") || pointerEscape.MatchString(field.Pointer) || len(strings.Split(field.Pointer,"/"))>33 {
            return invalid("Each JSON field requires a bounded RFC 6901 pointer")
        }
        if field.Type!="null" && field.Type!="boolean" && field.Type!="number" && field.Type!="string" && field.Type!="object" && field.Type!="array" { return invalid("Each JSON field requires an explicit supported type") }
        if field.Equals!=nil {
            var value any
            if err:=json.Unmarshal(field.Equals,&value);err!=nil { return invalid("Invalid equals value") }
            valid:=false
            switch value:=value.(type) {
            case nil: valid=field.Type=="null"
            case bool: valid=field.Type=="boolean"
            case string: valid=field.Type=="string" && len(value)<=2048
            case float64:
                token:=strings.TrimSpace(string(field.Equals));integer,err:=strconv.ParseInt(token,10,64)
                valid=field.Type=="number" && integerToken.MatchString(token) && err==nil && integer>=-9007199254740991 && integer<=9007199254740991 && value==float64(integer)
            }
            if !valid { return invalid("equals supports matching scalar types and safe integer numbers only") }
        }
    }
    return policy,nil
}
func ValidateResponse(result *Result,policy Policy) error {
    checks:=policy.ResponseChecks
    result.Validation=&Validation{Configured:len(checks.Statuses)>0 || checks.ContentType!=nil || len(checks.JSONFields)>0}
    if policy.RedirectPolicy=="error" && result.Status>=300 && result.Status<=399 { return failure("redirect_refused","Redirect response refused; no redirect was followed") }
    if len(checks.Statuses)>0 {
        matched:=false;for _,status:=range checks.Statuses { if status==result.Status { matched=true } }
        if !matched { return failure("response_status","Response status does not match the configured accepted statuses") }
    }
    if checks.ContentType!=nil {
        actual:="";count:=0;for _,header:=range result.Headers { if strings.EqualFold(header[0],"content-type") { count++;actual=strings.ToLower(strings.TrimSpace(strings.SplitN(header[1],";",2)[0])) } }
        if count!=1 || actual!=*checks.ContentType { return failure("response_content_type","Response Content-Type does not match the configured media type") }
    }
    if result.Validation.Configured && result.BodyTruncated { return failure("response_truncated","A bounded or incomplete response cannot pass configured response checks") }
    if len(checks.JSONFields)>0 {
        decoder:=json.NewDecoder(strings.NewReader(result.Body));decoder.UseNumber()
        if err:=unicodeJSON([]byte(result.Body));err!=nil { return failure("response_json","Response contains invalid Unicode escapes") }
        if result.BodyInvalidUTF8 { return failure("response_json","Response is not valid UTF-8 JSON") }
        if err:=uniqueJSON(decoder,0);err!=nil { return failure("response_json","Response is not complete valid JSON with unique keys") }
        if _,err:=decoder.Token();err!=io.EOF { return failure("response_json","Response contains trailing JSON data") }
        var body any
        decoder=json.NewDecoder(strings.NewReader(result.Body));decoder.UseNumber()
        if err:=decoder.Decode(&body);err!=nil { return failure("response_json","Response is malformed JSON") }
        for _,field:=range checks.JSONFields {
            value:=body
            if field.Pointer!="" {
                for _,part:=range strings.Split(field.Pointer[1:],"/") {
                    part=strings.ReplaceAll(strings.ReplaceAll(part,"~1","/"),"~0","~")
                    var found bool
                    switch container:=value.(type) {
                    case map[string]any: value,found=container[part]
                    case []any:
                        if arrayIndex.MatchString(part) { index,err:=strconv.Atoi(part);if err==nil && index<len(container) { value=container[index];found=true } }
                    }
                    if !found { return failure("response_field_missing","A configured JSON pointer is absent from the response") }
                }
            }
            kind:="null"
            switch value.(type) { case bool:kind="boolean";case string:kind="string";case json.Number:kind="number";case []any:kind="array";case map[string]any:kind="object" }
            if number,ok:=value.(json.Number);ok { if _,err:=number.Float64();err!=nil { return failure("response_field_type","Response number is outside the supported finite range") } }
            if kind!=field.Type { return failure("response_field_type","A configured JSON field has the wrong type") }
            if field.Equals!=nil {
                var expected any;if err:=json.Unmarshal(field.Equals,&expected);err!=nil { return failure("invalid_config","Invalid equals value") }
                actual:=value
                if number,ok:=value.(json.Number);ok {
                    if !integerToken.MatchString(number.String()) { return failure("response_field_value","Numeric equals requires an exact safe integer JSON token without fractions or exponent notation") }
                    converted,err:=number.Int64();if err!=nil || converted < -9007199254740991 || converted > 9007199254740991 { return failure("response_field_value","Response number cannot match a safe integer") };actual=float64(converted)
                }
                if actual!=expected { return failure("response_field_value","A configured JSON field has an unexpected value") }
            }
        }
    }
    result.Validation.Passed=result.Validation.Configured
    return nil
}

type Provenance struct {
    Format string ${'`'}json:"format"${'`'}
    Mode string ${'`'}json:"mode"${'`'}
    Problems []string ${'`'}json:"problems"${'`'}
}
type Result struct {
    DryRun bool ${'`'}json:"dry_run"${'`'}
    NetworkRequests *int ${'`'}json:"network_requests"${'`'}
    NetworkAttempted bool ${'`'}json:"network_attempted"${'`'}
    Ready bool ${'`'}json:"ready"${'`'}
    Problems []string ${'`'}json:"problems,omitempty"${'`'}
    Instruction string ${'`'}json:"instruction,omitempty"${'`'}
    Status int ${'`'}json:"status,omitempty"${'`'}
    URL string ${'`'}json:"url,omitempty"${'`'}
    RedirectFollowed bool ${'`'}json:"redirect_followed"${'`'}
    Headers [][]string ${'`'}json:"headers,omitempty"${'`'}
    Body string ${'`'}json:"body"${'`'}
    BodyTruncated bool ${'`'}json:"body_truncated"${'`'}
    BodyInvalidUTF8 bool ${'`'}json:"body_invalid_utf8,omitempty"${'`'}
    Validation *Validation ${'`'}json:"validation,omitempty"${'`'}
    Policy *Policy ${'`'}json:"policy,omitempty"${'`'}
}

// Reject duplicate keys before decoding: Go's usual last-value/merge behavior
// would disagree with the JavaScript client and could change a reviewed method.
func uniqueJSON(decoder *json.Decoder, depth int) error {
    if depth>64 { return errors.New("JSON nesting exceeds 64 levels") }
    value,err:=decoder.Token()
    if err!=nil { return err }
    delimiter,container:=value.(json.Delim)
    if !container { return nil }
    switch delimiter {
    case '{':
        seen:=map[string]bool{}
        for decoder.More() {
            key,err:=decoder.Token();if err!=nil { return err }
            name,ok:=key.(string);if !ok || seen[name] { return errors.New("Duplicate or malformed JSON object key") }
            seen[name]=true
            if err:=uniqueJSON(decoder,depth+1);err!=nil { return err }
        }
    case '[':
        for decoder.More() { if err:=uniqueJSON(decoder,depth+1);err!=nil { return err } }
    default: return errors.New("Unexpected JSON delimiter")
    }
    _,err=decoder.Token()
    return err
}
func exactFields(data []byte, allowed, required []string) (map[string]json.RawMessage,error) {
    var fields map[string]json.RawMessage
    if err:=json.Unmarshal(data,&fields);err!=nil { return nil,err }
    if fields==nil { return nil,errors.New("A JSON object is required") }
    permitted:=map[string]bool{};for _,key:=range allowed { permitted[key]=true }
    if allowed!=nil { for key:=range fields { if !permitted[key] { return nil,errors.New("Unknown or incorrectly cased request/configuration key") } } }
    for _,key:=range required { if _,ok:=fields[key];!ok { return nil,errors.New("A complete request object is required") } }
    return fields,nil
}
func (request *Request) UnmarshalJSON(data []byte) error {
    keys:=[]string{"method","url","headers","body","timeout_ms"}
    if _,err:=exactFields(data,keys,keys);err!=nil { return err }
    type plain Request
    var value plain
    if err:=json.Unmarshal(data,&value);err!=nil { return err }
    *request=Request(value)
    return nil
}
func (config *Config) UnmarshalJSON(data []byte) error {
    fields,err:=exactFields(data,[]string{"configVersion","allowedOrigin","request","transport","timeoutMs","redirectPolicy","cookiePolicy","responseChecks"},nil);if err!=nil { return err }
    if raw,ok:=fields["configVersion"];ok { var version string;if err:=json.Unmarshal(raw,&version);err!=nil || version!="reb-client-config-v1" { return errors.New("Unsupported configVersion") } }
    type plain Config
    var value plain
    if err:=json.Unmarshal(data,&value);err!=nil { return err }
    *config=Config(value)
    return nil
}
func (provenance *Provenance) UnmarshalJSON(data []byte) error {
    fields,err:=exactFields(data,nil,[]string{"format","mode","problems"});if err!=nil { return err }
    // Other provenance fields are extensible data, never case-folded aliases.
    if err:=json.Unmarshal(fields["format"],&provenance.Format);err!=nil { return err }
    if err:=json.Unmarshal(fields["mode"],&provenance.Mode);err!=nil { return err }
    return json.Unmarshal(fields["problems"],&provenance.Problems)
}

func unicodeJSON(data []byte) error {
    // A JSON escape starts at an unescaped backslash. Surrogates must pair.
    for i := 0; i < len(data); i++ {
        if data[i] != '\\' { continue }
        i++
        if i >= len(data) || data[i] != 'u' { continue }
        if i+4 >= len(data) { return errors.New("incomplete Unicode escape") }
        var code uint16
        if _, err := fmt.Sscanf(string(data[i+1:i+5]), "%04x", &code); err != nil { return err }
        i += 4
        if code >= 0xdc00 && code <= 0xdfff { return errors.New("unpaired Unicode surrogate") }
        if code < 0xd800 || code > 0xdbff { continue }
        if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' { return errors.New("unpaired Unicode surrogate") }
        var low uint16
        if _, err := fmt.Sscanf(string(data[i+3:i+7]), "%04x", &low); err != nil || low < 0xdc00 || low > 0xdfff { return errors.New("unpaired Unicode surrogate") }
        i += 6
    }
    return nil
}

// ReadJSON bounds local inputs and rejects invalid Unicode instead of accepting
// encoding/json's replacement characters. Unknown provenance fields are data.
func ReadJSON(path string, target any) error {
    file, err := os.Open(path)
    if err != nil { return err }
    defer file.Close()
    data, err := io.ReadAll(io.LimitReader(file, 1048577))
    if err != nil { return err }
    if len(data) > 1048576 || !utf8.Valid(data) { return errors.New("JSON exceeds 1 MiB or contains invalid UTF-8") }
    if err:=unicodeJSON(data);err!=nil { return err }
    decoder:=json.NewDecoder(strings.NewReader(string(data)));decoder.UseNumber()
    if err:=uniqueJSON(decoder,0);err!=nil { return err }
    if _,err:=decoder.Token();err!=io.EOF { return errors.New("Unexpected trailing JSON data") }
    return json.Unmarshal(data, target)
}

var token = regexp.MustCompile("^[!#$%&'*+.^_${'`'}|~0-9A-Za-z-]+$")
var method = regexp.MustCompile("^[A-Z][A-Z0-9!#$%&'*+.^_${'`'}|~-]{0,31}$")
var textMedia = regexp.MustCompile("^(text/[a-z0-9.+-]+|application/(json|[a-z0-9.-]+\\+json|xml|[a-z0-9.-]+\\+xml|x-www-form-urlencoded|graphql|x-ndjson|ndjson))$")
var forbidden = map[string]bool{
    "authorization":true, "proxy-authorization":true, "cookie":true, "cookie2":true, "set-cookie":true,
    "host":true, "content-length":true, "connection":true, "transfer-encoding":true,
    "accept-charset":true, "accept-encoding":true, "access-control-request-headers":true,
    "access-control-request-method":true, "date":true, "dnt":true, "expect":true,
    "keep-alive":true, "origin":true, "referer":true, "te":true, "trailer":true,
    "upgrade":true, "user-agent":true, "via":true, "content-encoding":true,
}
func printableASCII(value string) bool {
    for _, character := range value { if character < 32 || character > 126 { return false } }
    return true
}
func forbiddenMethod(value string) bool { return value == "CONNECT" || value == "TRACE" || value == "TRACK" }
func requestURL(value string) (*url.URL, error) {
    parsed, err := url.Parse(value)
    if err != nil || len(value)>8192 || !printableASCII(value) || strings.ContainsAny(value," \\#") ||
        !(strings.HasPrefix(value,"http://") || strings.HasPrefix(value,"https://")) ||
        parsed.Hostname()=="" || parsed.User!=nil || parsed.Opaque!="" || strings.Contains(parsed.Host,"%") {
        return nil, errors.New("Go requires a complete ASCII HTTP(S) URL without credentials, fragment, whitespace or escapes in its host; original evidence is unchanged")
    }
    return parsed,nil
}
func origin(parsed *url.URL) string {
    host, port := strings.ToLower(parsed.Hostname()),parsed.Port()
    if port == "80" && parsed.Scheme == "http" || port == "443" && parsed.Scheme == "https" { port = "" }
    if port != "" { host = net.JoinHostPort(host,port) } else if strings.Contains(host,":") { host = "["+host+"]" }
    return parsed.Scheme+"://"+host
}
func Issues(input Request) []string {
    problems := []string{}
    if !method.MatchString(input.Method) || forbiddenMethod(input.Method) { problems=append(problems,"Unsupported uppercase HTTP method") }
    if _,err:=requestURL(input.URL);err!=nil { problems=append(problems,err.Error()) }
    if input.Headers==nil || len(input.Headers)>64 { problems=append(problems,"At most 64 complete header pairs are required") }
    seen,total:=map[string]bool{},0
    for _,pair:=range input.Headers {
        if len(pair)!=2 { problems=append(problems,"Malformed header pair");continue }
        name,value:=pair[0],pair[1];lower:=strings.ToLower(name);total+=len(name)+len(value)
        if !token.MatchString(name) || len(name)>128 || len(value)>2048 || !printableASCII(value) || strings.TrimSpace(value)!=value { problems=append(problems,"Go supports only bounded ASCII header values without surrounding whitespace or controls") }
        if seen[lower] { problems=append(problems,"Duplicate header names are unsupported") };seen[lower]=true
        if forbidden[lower] || strings.HasPrefix(lower,"sec-") || strings.HasPrefix(lower,"proxy-") { problems=append(problems,"Credential, transport, browser-controlled or encoded-body header requires manual reconstruction") }
        if lower=="x-http-method" || lower=="x-http-method-override" || lower=="x-method-override" {
            for _,part:=range strings.Split(value,",") { if forbiddenMethod(strings.ToUpper(strings.TrimSpace(part))) { problems=append(problems,"Unsupported method override") } }
        }
        if lower=="content-type" {
            media,params,err:=mime.ParseMediaType(value)
            if err!=nil || !textMedia.MatchString(media) { problems=append(problems,"Only complete recognized text media types are supported") }
            charset:=strings.ToLower(params["charset"])
            if charset!="" && charset!="utf-8" && charset!="utf8" { problems=append(problems,"Only UTF-8 request bodies are supported") }
        }
    }
    if total>16384 { problems=append(problems,"Headers exceed 16 KiB") }
    if input.Body==nil || !utf8.ValidString(*input.Body) || len(*input.Body)>65536 { problems=append(problems,"Complete UTF-8 body of at most 64 KiB is required") }
    if (input.Method=="GET" || input.Method=="HEAD") && input.Body!=nil && *input.Body!="" { problems=append(problems,"GET/HEAD bodies are unsupported") }
    if input.TimeoutMS<100 || input.TimeoutMS>30000 { problems=append(problems,"Timeout must be 100-30000 ms") }
    return problems
}

// Send performs no network access unless send is true and all review gates pass.
func Send(ctx context.Context, input Request, config Config, provenance Provenance, send bool) (Result,error) {
    if config.Request!=nil { input=*config.Request }
    problems:=Issues(input)
    policy,configurationError:=configure(config,input)
    if configurationError!=nil { problems=append(problems,configurationError.Error()) }
    if config.Request==nil && (provenance.Format!="reb-client-project-v1" || provenance.Mode!="raw" || len(provenance.Problems)>0) {
        problems=append(problems,"Provide a complete reviewed config.request for redacted, unknown or unsupported evidence")
    }
    zero,one:=0,1
    result:=Result{DryRun:!send,NetworkRequests:&zero,Ready:len(problems)==0,Problems:problems,Policy:&policy,Instruction:"Review evidence/config.json, set allowedOrigin, then explicitly run with --send"}
    if !send { return result,nil }
    if configurationError!=nil { return result,configurationError }
    if len(problems)>0 { return result,failure("invalid_input",strings.Join(problems,"; ")) }
    parsed,_:=requestURL(input.URL)
    if config.AllowedOrigin!=origin(parsed) { return result,failure("wrong_origin","config.allowedOrigin must exactly match the reviewed request origin") }
    if err:=ctx.Err();err!=nil { return result,failure("canceled",err.Error()) }
    input.TimeoutMS=policy.TimeoutMS
    request,err:=http.NewRequestWithContext(ctx,input.Method,input.URL,strings.NewReader(*input.Body))
    if err!=nil { return result,err }
    for _,pair:=range input.Headers { request.Header.Set(pair[0],pair[1]) }
    // A fresh HTTP/1.1 transport avoids pooled-connection replay and ambient
    // proxies/cookies. TLS verification stays enabled. Header order/casing and
    // framing remain net/http's, not captured wire evidence.
    transport:=&http.Transport{DisableKeepAlives:true,DisableCompression:true,MaxResponseHeaderBytes:65536,
        TLSNextProto:map[string]func(string,*tls.Conn)http.RoundTripper{}}
    defer transport.CloseIdleConnections()
    client:=&http.Client{Transport:transport,Timeout:time.Duration(input.TimeoutMS)*time.Millisecond,
        CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
    // Errors before receiving a response cannot prove whether the server saw it.
    result.NetworkAttempted=true
    result.Instruction="The server may have processed this request; check its state before deciding whether another send is safe. No application retry or fallback was requested."
    result.NetworkRequests=nil
    var response *http.Response
    if policy.Transport.Mode=="browser-profile" {
        var cleanup func()
        response,cleanup,err=browserProfileSend(ctx,input,*policy.Transport.BrowserProfile)
        if cleanup!=nil { defer cleanup() }
    } else { response,err=client.Do(request) }
    if err!=nil {
        code:="network";var networkError net.Error
        if errors.Is(err,context.Canceled) { code="canceled" } else if errors.As(err,&networkError) && networkError.Timeout() || errors.Is(err,context.DeadlineExceeded) { code="timeout" }
        return result,failure(code,"Transport failed; the server outcome may be unknown")
    }
    result.NetworkRequests=&one
    result.Status=response.StatusCode
    result.URL=response.Request.URL.String()
    defer response.Body.Close()
    headers:=[][]string{};names:=make([]string,0,len(response.Header))
    for name:=range response.Header { names=append(names,name) };sort.Strings(names)
    for _,name:=range names { for _,value:=range response.Header[name] { headers=append(headers,[]string{name,value}) } }
    result.Headers=headers
    body,err:=io.ReadAll(io.LimitReader(response.Body,65537))
    if err!=nil {
        if len(body)>65536 { body=body[:65536] }
        result.Body=strings.ToValidUTF8(string(body),"\ufffd")
        result.BodyTruncated=true
        code:="response_read";var networkError net.Error
        if errors.Is(err,context.Canceled) { code="canceled" } else if errors.As(err,&networkError) && networkError.Timeout() { code="timeout" }
        return result,failure(code,"Response body could not be read completely")
    }
    truncated:=len(body)>65536;if truncated { body=body[:65536] }
    result=Result{Ready:true,NetworkAttempted:true,NetworkRequests:&one,Policy:&policy,Instruction:result.Instruction,Status:response.StatusCode,URL:response.Request.URL.String(),
        Headers:headers,Body:strings.ToValidUTF8(string(body),"\ufffd"),BodyTruncated:truncated,BodyInvalidUTF8:!utf8.Valid(body)}
    validationError:=ValidateResponse(&result,policy)
    return result,validationError
}
`,
    "go/services/service001.go":String.raw`// Package services contains only the one observed operation; names imply no API schema.
package services

import (
    "context"
    "errors"
    "os"
    "path/filepath"
    "reb.local/observed/client"
)

func Request001(ctx context.Context, root string, send bool) (client.Result,error) {
    var input client.Request
    var provenance client.Provenance
    var config client.Config
    if err:=client.ReadJSON(filepath.Join(root,"requests","request-001.json"),&input);err!=nil { return client.Result{},err }
    if err:=client.ReadJSON(filepath.Join(root,"provenance.json"),&provenance);err!=nil { return client.Result{},err }
    if err:=client.ReadJSON(filepath.Join(root,"config.json"),&config);err!=nil && !errors.Is(err,os.ErrNotExist) { return client.Result{},err }
    return client.Send(ctx,input,config,provenance,send)
}
`,
    "go/cmd/request-001/main.go":String.raw`package main

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "reb.local/observed/services"
)

func main() {
    send:=false
    if len(os.Args)==2 && os.Args[1]=="--send" { send=true } else if len(os.Args)!=1 {
        fmt.Fprintln(os.Stderr,"Usage: from go/, go run ./cmd/request-001 [--send]");os.Exit(2)
    }
    result,err:=services.Request001(context.Background(),"..",send)
    if err!=nil {
        fmt.Fprintln(os.Stderr,err)
        if result.NetworkAttempted { fmt.Fprintln(os.Stderr,result.Instruction) }
        os.Exit(1)
    }
    encoder:=json.NewEncoder(os.Stdout);encoder.SetIndent("","  ")
    if err:=encoder.Encode(result);err!=nil { fmt.Fprintln(os.Stderr,err);os.Exit(1) }
}
`,
  };
}

function capturedClientReadme(mode) {
  return String.raw`# One observed API operation

This project contains one reviewed request representation, not a discovered API specification or SDK. Neutral service/operation names imply no business schema. Captured inputs and evidence are data, never executable source.

## Start with Go

Use Go 1.23+ for the dependency-free standard transport. From go/, run:

    go run ./cmd/request-001

This is a dry run and sends nothing. Review the shared root request, provenance and evidence. Copy config.example.json to config.json and set allowedOrigin to the exact authorized origin. Only an explicit send performs a request:

    go run ./cmd/request-001 --send

Run from go/ so shared JSON paths resolve to the parent folder. For redacted or unsupported exports, supply a complete reviewed config.request with method, url, headers (pairs), body and timeout_ms. Evidence files remain unchanged. Never paste credentials into this credential-omitting client. Mutating methods can change server state.

## Shared configuration and response checks

configVersion is reb-client-config-v1. An omitted version supports older local configs; a different version is rejected. Unknown keys and duplicate JSON keys are rejected. Request/config numeric tokens must be exact safe integers, without exponent or fractional notation.

- transport: {"mode":"standard","browserProfile":null} works in both clients. Optional browser-profile is Go-only; see below.
- timeoutMs: null inherits the request timeout; an integer 100–30000 overrides it for the entire send, including response reading.
- redirectPolicy: manual returns the first response; error returns redirect_refused for 3xx. Neither follows any redirect.
- cookiePolicy: omit is the only supported value. No browser cookies, cookie jar or saved login is acquired.
- responseChecks: opt-in accepted statuses, media type and explicit JSON pointer checks. No schema is inferred from one capture.

For an authored stock fixture, replace responseChecks with:

    {
      "statuses": [200],
      "contentType": "application/json",
      "jsonFields": [
        {"pointer":"/availability","type":"string","equals":"in_stock"},
        {"pointer":"/quantity","type":"number","equals":4}
      ]
    }

A missing quantity never becomes zero. Null, missing, wrong type and wrong value stay distinct. Empty statuses/jsonFields and null contentType disable their respective checks. With no checks, validation.configured and validation.passed are both false: an HTTP 200 is not proof of a valid business result. Choose checks for your actual operation; the example intentionally accepts only in-stock quantity four.

JSON pointers use RFC 6901: empty pointer selects the root, ~1 means slash and ~0 means tilde; array indexes are canonical nonnegative integers. Types are null, boolean, number, string, object and array. equals accepts matching string/boolean/null or safe-integer values only. Numeric response equality requires a bare integer JSON token, without fractions or exponents, to avoid rounded or underflowed matches. Duplicate keys, invalid UTF-8/Unicode, malformed JSON and nesting deeper than 64 fail JSON checks. At most 32 status values and 32 JSON fields are accepted. MIME checks compare one media type case-insensitively, ignoring parameters; repeated Content-Type fields fail.

Errors have distinct codes: invalid_input, invalid_config, unsupported_transport, unsupported_profile, wrong_origin, network, timeout (and canceled in Go), response_read, redirect_refused, response_status, response_content_type, response_truncated, response_json, response_field_missing, response_field_type and response_field_value. Go returns *client.ClientError with the partial Result; JavaScript errors expose code and result. Input file parsing can also fail before Send. After a network error the server outcome can be unknown; inspect its state before another deliberate send. No tool automatically falls back or resends. A response body is limited to 64 KiB; configured checks never pass a truncated body. Partial-response failures preserve known status, URL, headers and bounded body.

## Optional pinned Go browser-profile transport (experimental)

The optional go/client/mimic.go adapter uses exactly github.com/saucesteals/mimic v1.0.2, source commit 946a948a9b5a4360847b7f7d4b1f2e63f64ddc9e. It is experimental, source-only and excluded from ordinary builds. Standard Go and JavaScript clients remain available without this dependency.

Before setup: fhttp v1.0.1's applicable license grant and notice chain remain unresolved. Its pinned repository has no LICENSE/COPYING/NOTICE file; Go-derived headers do not establish permissions for all fork changes. See the [upstream license issue](https://github.com/useflyent/fhttp/issues/19). Resolve applicable permissions and notice obligations before enabling or distributing this optional dependency. The export contains no third-party source or binary.

After resolving those requirements, with Go 1.24+ already installed, run from go/:

    GOTOOLCHAIN=local go get github.com/saucesteals/mimic@946a948a9b5a4360847b7f7d4b1f2e63f64ddc9e
    GOTOOLCHAIN=local go build -tags mimic ./...
    GOTOOLCHAIN=local go vet -tags mimic ./...

Review and retain the resulting go.mod and go.sum. Do not use an unpinned/latest Mimic version: later API generations differ. The standard project contains no downloaded dependency or binary. Mimic is MIT; its pinned dependencies include fhttp v1.0.1 and uTLS v1.7.4-0.20250519154908-0557f61cb0b8.

Select exactly:

    "transport": {
      "mode": "browser-profile",
      "browserProfile": {
        "browser": "chrome",
        "version": "133.0.0.0",
        "platform": "linux"
      }
    }

Then dry-run with go run -tags mimic ./cmd/request-001; append --send only after authorization/review. Other browser/version/platform combinations fail before I/O. The version is a named Chromium-133 compatibility target, not a claim that the capture used this build. This upstream pin maps versions >=133 to the same HelloChrome_133; REB refuses newer labels rather than implying corresponding newer handshakes. User-Agent and low-entropy Client Hints come from the same allowlisted profile, never copied credential-bearing/browser-controlled headers.

The adapter configures direct HTTP/HTTP2/TLS, verified certificates, no proxy/jar, no decompression and stopped redirects. Each deliberate operation has a fresh single-use transport and permits one transport dial invocation, blocking retry connections; upstream's internal HTTP2 retry paths are not application-level permission to resend.

The repository's explicit --mimic validation lane builds/tests/vets the tagged module and checks authored HTTP plus certificate rejection. Its owned HTTPS fixtures require ALPN HTTP/1.1 and HTTP/2 success for GET, empty POST and text-body POST, using an ephemeral CA only in an isolated test subprocess without disabling certificate verification. H2 fault cases inject REFUSED_STREAM or GOAWAY(last-stream=0) after the complete request body and END_STREAM, then count every connection/request stream; unguarded empty-POST controls must demonstrate a second complete request. Treat these bounded runtime checks as unverified until the lane passes at the exact revision under review. Other fault timings and browser equivalence remain separate gates. The repository writes verbose test output and a scoped package/test dependency receipt under build/client-project-qa; this export does not contain a passing acceptance receipt.

No perfect browser fingerprint is promised. Header order is upstream-generated, not recovered wire evidence; TLS randomness, session/resumption, HTTP2, Client Hints policy, JavaScript/browser state and route can differ. JA3 alone cannot establish equivalence. HTTP3/QUIC and standalone real-browser execution/fallback are unsupported. JavaScript rejects browser-profile selection without a silent downgrade.

Source: https://github.com/saucesteals/mimic/tree/946a948a9b5a4360847b7f7d4b1f2e63f64ddc9e

## JavaScript

Use Node.js 22+; no packages or installation are needed. Run node examples/request-001.mjs for dry-run, or append --send after the same review. The direct built-in Node HTTP(S) transport does not use Fetch dispatchers or ambient proxy variables, does not decompress responses, and explicitly keeps TLS certificate verification enabled. It sends one request with no redirects/cookies. It is not a browser or its TLS/HTTP2 profile.

## Layout

- go/go.mod: dependency-free default module; explicit optional setup records pinned dependencies here
- go/client/client.go: standard HTTP/1.1 client, shared configuration and response validation
- go/client/mimic.go: optional build-tag profile adapter
- go/services/service001.go and go/cmd/request-001/main.go: one operation and dry-run/send CLI
- src/client.mjs and src/services/service-001.mjs: standard Node transport and one operation
- examples/request-001.mjs: explicit JavaScript dry-run/send CLI
- requests/request-001.json: reviewed request data
- config.example.json: shared policy/check placeholders; local config.json is ignored
- provenance.json: exact source references, unresolved problems and limitations
- evidence/: retained raw evidence or an explicitly labeled best-effort redacted copy

## Fidelity and privacy

Export mode: ${mode}. Raw capture/run evidence remains unchanged even when it cannot be replayed. Retained CDP strings/base64 are not original HTTP wire bytes. Duplicate wire headers, casing/order, framing, extra-info headers and state may be absent. Binary, multipart, encoded or truncated requests remain evidence-only until deliberately reconstructed. No automatic credential extraction occurs. Go's standard lane requires ASCII URLs/headers; Unicode originals remain evidence. TypeScript and Python generators are not included.

Raw values stay raw in this explicit export and can include credentials/personal data. Redacted copies remove header values and bodies and strip URL credentials/query/fragment; names, paths, identifiers and arbitrary secrets can remain. This best-effort export never rewrites local evidence. Review before sharing. .gitignore excludes config, request data, evidence and provenance; it is not a security boundary.
`;
}

function capturedClientProject(source, mode) {
  if (!['raw','redacted_copy'].includes(mode)) throw new TypeError('Choose raw or explicitly redacted project export.');
  const raw = mode === 'raw', input = raw ? source.input : capturedClientRedactInput(source.input);
  let origin = null; try { origin = new URL(input.url).origin; } catch { /* Explicit unknown. */ }
  const provenance = {format:'reb-client-project-v1',mode,operation:'request-001',service:'service-001',observed_origin:origin,
    source_kind:source.kind,source_identity:source.identity,problems:source.problems,
    capture_identity:source.kind === 'capture' ? source.identity : source.capture?.identity ?? null,
    capture_relation:source.kind === 'capture' ? 'Exact selected retained capture snapshot.' : source.capture ? source.capture.relation : 'No exact source-capture linkage is retained for this run; none was guessed.',
    limitations:['One observed operation only; no endpoint discovery or generated service schema.',
      'Retained CDP representations are not original HTTP wire bytes; duplicate wire headers, original casing/order and extra-info headers may be absent.',
      'HTTP clients normalize URLs and headers. TLS, compression, CORS, storage and cookies differ from the original browser.',
      'Default Go uses standard HTTP/1.1; an optional pinned Mimic build has one explicit Chrome133/Linux profile, with unverified browser equivalence. No ambient proxy, cookie jar, certificate bypass or automatic decompression.',
      'Both clients omit credentials and stop redirects; optional response checks must be configured explicitly. Repeater follows redirects.',
      'Missing, binary, multipart or truncated request representations require explicit configuration; no prefix is claimed complete.',
      'Raw files can contain credentials or personal data. Redacted names, paths and provenance can still be sensitive. Review before sharing.']};
  const files = [], add = (path,text) => files.push({path:'reb-client-project/'+path,text}), json = value => JSON.stringify(value,null,2)+'\n';
  add('provenance.json',json(provenance));
  if (source.kind === 'capture') add('evidence/capture.json',json(capturedClientCaptureCopy(source.evidence,mode)));
  else {
    const evidence = JSON.parse(JSON.stringify(source.evidence));
    if (!raw) {
      for (const request of [evidence.request,evidence.resolved_request]) if (request) {
        request.url = capturedClientRedactUrl(request.url); request.body = '<redacted>';
        request.headers = request.headers.map(header => ({...header,value:'<redacted>'}));
      }
      if (evidence.response) { evidence.response.url = capturedClientRedactUrl(evidence.response.url); evidence.response.body = '<redacted>'; evidence.response.body_sha256 = null;
        evidence.response.headers = evidence.response.headers.map(header => ({...header,value:'<redacted>'})); if (evidence.response.error) evidence.response.error = '<redacted>'; }
    }
    add('evidence/repeater-run.json',json({format:'reb-client-run-evidence-v1',mode,run:evidence}));
    if (source.capture) add('evidence/capture.json',json(capturedClientCaptureCopy(source.capture.evidence,mode)));
  }
  add('requests/request-001.json',json(input));
  add('config.example.json',json({configVersion:'reb-client-config-v1',allowedOrigin:'',request:null,transport:{mode:'standard',browserProfile:null},timeoutMs:null,redirectPolicy:'manual',cookiePolicy:'omit',responseChecks:{statuses:[],contentType:null,jsonFields:[]}}));
  for (const [path,text] of Object.entries(capturedClientGoFiles())) add(path,text);
  add('.gitignore','config.json\n.env*\nrequests/*.json\nevidence/\nprovenance.json\n');
  add('package.json',json({name:'reb-observed-client',private:true,type:'module',engines:{node:'>=22'},scripts:{example:'node examples/request-001.mjs',send:'node examples/request-001.mjs --send'}}));
  add('src/client.mjs',`// Generated local client. Inputs are data, never evaluated code.\n${capturedClientIssues.toString()}\n${capturedClientFailure.toString()}\n${capturedClientConfig.toString()}\n${capturedClientJSON.toString()}\n${capturedClientInputJSON.toString()}\n${capturedClientValidateResponse.toString()}\n${capturedClientSend.toString()}\nexport {capturedClientSend as sendRequest,capturedClientJSON as parseClientJSON,capturedClientInputJSON as parseInputJSON};\n`);
  add('src/services/service-001.mjs',"import {readFile} from 'node:fs/promises';\nimport {sendRequest,parseClientJSON,parseInputJSON} from '../client.mjs';\nconst read = async (path,strict=false) => (strict?parseInputJSON:parseClientJSON)(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await readFile(new URL(path,import.meta.url))));\nexport async function request001(options = {}) {\n  const [input,provenance] = await Promise.all([read('../../requests/request-001.json',true),read('../../provenance.json')]);\n  return sendRequest(input,{...options,provenance});\n}\n");
  add('examples/request-001.mjs',"import {readFile} from 'node:fs/promises';\nimport {request001} from '../src/services/service-001.mjs';\nimport {parseInputJSON} from '../src/client.mjs';\nconst args = process.argv.slice(2);\nif(args.some(arg=>arg!=='--send') || args.length>1) throw new Error('Usage: node examples/request-001.mjs [--send]');\nlet config = {};\ntry {config=parseInputJSON(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await readFile(new URL('../config.json',import.meta.url))));} catch(error) {if(error.code!=='ENOENT')throw error;}\ntry { console.log(JSON.stringify(await request001({config,send:args.includes('--send')}),null,2)); } catch(error) { console.error((error.code ?? 'client_error')+': '+error.message); if(error.result?.network_attempted) console.error(error.result.instruction); process.exitCode=1; }\n");
  add('README.md',capturedClientReadme(mode));
  return {files,provenance,bytes:capturedClientZip(files)};
}

// A single deliberate local export. The dialog never sends a target request.
function installCapturedExportDialog(options) {
  const dialog = document.querySelector('#captured-export-dialog');
  if (!dialog) return {sync() {},close() {}};
  const query = name => dialog.querySelector('[data-export-'+name+']');
  const fields = Object.fromEntries(['format','provider','source','file','policy','destination','submit','close','cancel','note','status'].map(name=>[name,query(name)]));
  const native = document.documentElement.classList.contains('native-shell');
  const bridge = globalThis.webkit?.messageHandlers?.rebClientProjectExport;
  const triggers = [...document.querySelectorAll('[data-export-open]')];
  let kind = 'capture', snapshot = null, opener = null, revision = 0, busy = false, outputStarted = false, fileRevision = 0, preparedFile = null;
  const fileMode = () => fields.format.value === 'sdl' && fields.source.value === 'file';
  const source = () => {
    if (kind === 'run') {
      const run = options.getRun(), context = options.contextKey();
      return capturedClientRun(run,context,options.getRunCapture(run,context));
    }
    const request = options.getCaptureRequest?.() ?? null;
    return {request,identity:capturedRequestIdentity(request),evidence:capturedClientTrafficDocument(request,'raw')};
  };
  const fingerprint = value => JSON.stringify(kind === 'run' ? value : [value.identity,value.evidence]);
  const current = () => { try { return snapshot !== null && fingerprint(source()) === snapshot; } catch { return false; } };
  const status = (message,failed=false) => { fields.status.textContent = message; fields.status.hidden = !message; fields.status.dataset.kind = failed ? 'error' : 'result'; };
  function sync() {
    for (const trigger of triggers) {
      let available = false;
      try { available = trigger.dataset.exportOpen === 'run' ? Boolean(options.getRun()) : true; } catch { /* Expired selection. */ }
      trigger.disabled = busy || !available;
    }
    if (!dialog.open) return;
    const project = fields.format.value === 'client', sdl = fields.format.value === 'sdl';
    // Unavailable modes are removed from the choice, not offered disabled.
    for (const option of fields.format.options) option.hidden = option.disabled = kind === 'run' ? option.value !== 'client' : snapshot === null && option.value !== 'sdl';
    const fromCapture = fields.source.querySelector('[value="capture"]');
    fromCapture.hidden = fromCapture.disabled = snapshot === null;
    // Without a saved capture only local-file SDL works: show no choice at all.
    const fileOnly = kind === 'capture' && snapshot === null;
    query('format-field').hidden = fileOnly;
    query('provider-field').hidden = !project;
    query('policy-field').hidden = sdl;
    query('source-field').hidden = !sdl || fileOnly;
    query('file-field').hidden = !fileMode();
    const save = fields.destination.querySelector('[value="save"]'), copy = fields.destination.querySelector('[value="copy"]');
    save.disabled = native && !project; copy.disabled = project;
    save.textContent = native ? 'macOS Save dialog' : 'Download file';
    if (native && !project) fields.destination.value = 'copy';
    if (project) fields.destination.value = 'save';
    for (const name of ['format','provider','source','file','policy','destination']) fields[name].disabled = busy;
    fields.close.disabled = fields.cancel.disabled = outputStarted;
    const unavailable = project && native && !bridge;
    const validFile = preparedFile && fields.file.files?.length === 1 && preparedFile.file === fields.file.files[0];
    fields.submit.disabled = busy || unavailable || (fileMode() ? !validFile : !current());
    const privacy = sdl ? 'Schema descriptions and identifiers may be private. SDL is exported as raw text.'
      : fields.policy.value === 'raw' ? 'Raw output includes retained private values. Review before sharing.'
      : 'Header values, bodies and URL credentials/query are removed. Paths and metadata can still be private.';
    const limit = project ? (fields.provider.value === 'standard' ? 'Dry-run clients; sending requires separate explicit configuration.' : 'Python uses per-operation timeouts, not an overall deadline.')
      : fields.format.value === 'har' ? 'Requires complete source timing; unsupported captures are refused.'
      : sdl ? 'Uses retained or local JSON only; no introspection query is sent.' : 'One retained request; original evidence stays unchanged.';
    fields.note.textContent = privacy+' '+limit;
    if (unavailable) status('Update the native app to enable project saving.',true);
    else if (!busy && !fileMode() && !current()) status('The selected evidence changed or expired. Close and open Export again.',true);

  }
  function close() {
    if (outputStarted) { status('Finish the active save or clipboard operation first.'); return; }
    revision++; fileRevision++; preparedFile = null; busy = false; snapshot = null; fields.file.value = '';
    if (dialog.open) dialog.close();
    opener?.focus({preventScroll:true}); sync();
  }
  for (const trigger of triggers) trigger.addEventListener('click',() => {
    if (trigger.disabled || busy || dialog.open) return;
    try {
      kind = trigger.dataset.exportOpen;
      if (!['capture','run'].includes(kind)) throw new TypeError('Unknown export source.');
      snapshot = null;
      try { snapshot = fingerprint(source()); } catch (error) { if (kind === 'run') throw error; }
      opener = trigger; revision++; fileRevision++; preparedFile = null;
      fields.format.value = kind === 'run' ? 'client' : snapshot === null ? 'sdl' : 'json'; fields.provider.value = 'standard';
      fields.source.value = snapshot === null ? 'file' : 'capture'; fields.policy.value = 'redacted_copy'; fields.destination.value = native && kind === 'capture' ? 'copy' : 'save';
      fields.file.value = ''; status('');
      document.querySelector('#captured-export-title').textContent = kind === 'run' ? 'Export retained run' : snapshot === null ? 'Export GraphQL schema' : 'Export capture';
      // Native Traffic rows carry no captureRecord: their headers and bodies are
      // not captured, so only conversion of a local introspection file can work.
      document.querySelector('#captured-export-context').textContent = kind === 'run' ? 'One retained Repeater run'
        : snapshot === null ? 'Native Traffic rows retain no request or response headers or bodies, so capture JSON, client project and HAR exports are unavailable here. Convert a local GraphQL introspection JSON file to SDL.'
          : 'One selected Traffic request';
      // Return focus to the exact toolbar action when dismissed.
      dialog.showModal(); sync(); fields.format.focus({preventScroll:true});
    } catch (error) { options.notice(error.message); }
  });
  for (const name of ['format','provider','source','policy','destination']) fields[name].addEventListener('change',() => { status(''); sync(); });
  fields.file.addEventListener('change',async () => {
    const owner = ++fileRevision, file = fields.file.files?.length === 1 ? fields.file.files[0] : null;
    preparedFile = null; status(''); sync();
    if (!file || !dialog.open) return;
    try {
      if (file.size > 1048576) throw new TypeError('Choose a JSON file up to 1 MiB.');
      status('Checking local JSON…');
      const buffer = await file.arrayBuffer();
      if (owner !== fileRevision || !dialog.open) return;
      if (buffer.byteLength > 1048576) throw new TypeError('Choose a JSON file up to 1 MiB.');
      const text = capturedExportFormats.introspectionSDL(capturedClientJSON(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(buffer),new Map())).text;
      preparedFile = {file,text};
      if (fileMode()) status('Local schema ready. Choose Export to save or copy.');
    } catch (error) { if (owner === fileRevision && dialog.open && fileMode()) status('Local file failed: '+error.message,true); }
    finally { if (owner === fileRevision) sync(); }
  });
  fields.close.addEventListener('click',close); fields.cancel.addEventListener('click',close);
  dialog.addEventListener('cancel',event => { event.preventDefault(); close(); });
  dialog.addEventListener('close',() => {
    // close() queues this event; a new opening may already own the dialog.
    if (dialog.open) return;
    revision++; fileRevision++; preparedFile = null; snapshot = null; busy = false; fields.file.value = '';
  });
  document.addEventListener('keydown',event => {
    if (!dialog.open) return;
    if (event.key === 'F8' || event.altKey && ['ArrowLeft','ArrowRight'].includes(event.key) ||
        (event.ctrlKey || event.metaKey) && ['p','j'].includes(event.key.toLowerCase())) { event.preventDefault(); event.stopImmediatePropagation(); }
  },true);
  fields.submit.addEventListener('click',async () => {
    sync(); if (fields.submit.disabled || busy) return;
    const owner = ++revision, format = fields.format.value, mode = format === 'sdl' ? 'raw' : fields.policy.value;
    const destination = fields.destination.value, provider = fields.provider.value, localFile = fileMode() ? fields.file.files[0] : null;
    busy = true; sync(); status('Preparing local export…');
    try {
      if (!['json','client','har','sdl'].includes(format) || kind === 'run' && format !== 'client' || !['raw','redacted_copy'].includes(mode)) throw new TypeError('Choose a supported export format and policy.');
      if (!['save','copy'].includes(destination) || format === 'client' && destination !== 'save' || native && format !== 'client' && destination !== 'copy') throw new TypeError('This destination is unavailable for the selected format.');
      let bytes, text, filename, type;
      if (localFile) {
        if (!preparedFile || preparedFile.file !== localFile) throw new TypeError('Choose and validate a local schema first.');
        text = preparedFile.text;
        filename = 'schema.graphql'; type = 'text/plain';
      } else {
        const selected = source();
        if (fingerprint(selected) !== snapshot) throw new TypeError('The selected evidence changed. Reopen Export.');
        if (format === 'json') {
          text = JSON.stringify(capturedClientTrafficDocument(selected.request,mode),null,2)+'\n';
          filename = 'selected.reb-traffic.'+(mode === 'raw' ? 'raw' : 'redacted')+'.json'; type = 'application/json';
        } else {
          const captured = kind === 'run' ? selected : capturedClientSource(selected.identity,selected.evidence);
          if (format === 'client') {
            const project = provider === 'standard' ? capturedClientProject(captured,mode) : capturedExportFormats.pythonProject(captured,mode,provider);
            bytes = project.bytes; filename = 'reb-client-project.'+(mode === 'raw' ? 'raw' : 'redacted')+'.zip'; type = 'application/zip';
          } else if (format === 'har') {
            text = new TextDecoder().decode(capturedExportFormats.harProject(captured,mode).bytes);
            filename = 'selected.'+(mode === 'raw' ? 'raw' : 'redacted')+'.har'; type = 'application/json';
          } else { text = capturedExportFormats.capturedSDL(captured).text; filename = 'selected.graphql'; type = 'text/plain'; }
        }
      }
      if (owner !== revision || !dialog.open) return;
      outputStarted = true; sync();
      if (native && format === 'client') {
        if (!bridge) throw new TypeError('Native project saving is unavailable.');
        let binary = ''; for (let offset=0;offset<bytes.length;offset+=16384) binary += String.fromCharCode(...bytes.subarray(offset,offset+16384));
        const result = await bridge.postMessage({format:'reb-client-project-save-v1',mode,base64:btoa(binary)});
        if (!result || !['saved','canceled'].includes(result.status)) throw new TypeError('The native save result could not be confirmed.');
        status(result.status === 'saved' ? 'Project saved locally.' : 'Save canceled. No archive was written.');
      } else if (destination === 'copy') {
        if (!navigator.clipboard?.writeText) throw new TypeError('Clipboard access is unavailable.');
        await navigator.clipboard.writeText(text); status('Copied locally. Review before sharing.');
      } else {
        const url = URL.createObjectURL(new Blob([bytes ?? text],{type}));
        const link = document.createElement('a'); link.href = url; link.download = filename; link.hidden = true; document.body.append(link);
        try { link.click(); } finally { link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000); }
        status('Download requested. Check your local downloads.');
      }
    } catch (error) { if (owner === revision && dialog.open) status('Export failed: '+error.message,true); }
    finally { if (owner === revision) { busy = false; outputStarted = false; sync(); } }
  });
  sync(); return {sync,close};
}

// CommonJS entry point for the offline exporter; browser script behavior is unchanged.
if (typeof module === 'object' && module?.exports && typeof require === 'function') module.exports = {capturedClientSource,capturedClientProject,capturedClientJSON,capturedClientZip};
