/* One observed operation, explicit local copies, no automatic target requests.
 * Capture evidence and runnable inputs remain separate representations. */
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
      const charset = value.match(/;\s*charset\s*=\s*"?([^;"\s]+)/i)?.[1];
      if (charset && !/^utf-?8$/i.test(charset)) problems.push('Only UTF-8 request text is supported; the declared charset differs.');
    }
  }
  if (total > 16384) problems.push('Header text exceeds 16 KiB.');
  if (!wellFormed(request.body) || bytes(request.body) > 65536) problems.push('A complete UTF-8 text body of at most 64 KiB is required.');
  if (['GET','HEAD'].includes(request.method) && request.body !== '') problems.push('GET and HEAD bodies cannot be replayed by this HTTP client.');
  if (!Number.isInteger(request.timeout_ms) || request.timeout_ms < 100 || request.timeout_ms > 30000) problems.push('Timeout must be between 100 and 30000 ms.');
  return [...new Set(problems)];
}

function capturedClientCapture(request) {
  const identity = apiCatalogRequestIdentity(request);
  if (!identity) throw new TypeError('Select an exact retained CDP capture.');
  const evidence = trafficCaptureDocument(request, 'raw'), record = evidence.record;
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
  return trafficCaptureDocument({captureRecord:document.record,captureLimits:document.coverage.limits,captureDropped:document.coverage.dropped},mode);
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

async function capturedClientSend(input, {config = {},send = false,provenance = {}} = {}) {
  const request = config.request ?? input;
  const issues = capturedClientIssues(request);
  if (!config.request && (provenance.mode !== 'raw' || provenance.problems?.length)) issues.push('Provide a complete reviewed config.request; the exported evidence is redacted or unsupported.');
  if (!send) return {dry_run:true,network_requests:0,ready:issues.length === 0,problems:issues,method:request?.method,
    instruction:'Review evidence and config.json, set allowedOrigin, then explicitly run the example with --send.'};
  if (issues.length) throw new TypeError(issues.join(' '));
  if (typeof config.allowedOrigin !== 'string' || new URL(request.url).origin !== config.allowedOrigin) throw new TypeError('config.allowedOrigin must exactly match the reviewed request origin.');
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(),request.timeout_ms);
  try {
    const response = await fetch(request.url,{method:request.method,headers:request.headers,body:request.body === '' ? undefined : request.body,
      credentials:'omit',cache:'no-store',redirect:'manual',referrerPolicy:'no-referrer',signal:controller.signal});
    const reader = response.body?.getReader(), chunks = []; let count = 0, truncated = false;
    if (reader) for (;;) {
      const {done,value} = await reader.read(); if (done) break;
      const remaining = 65536-count; chunks.push(value.subarray(0,remaining)); count += Math.min(remaining,value.length);
      if (value.length > remaining) { truncated = true; await reader.cancel(); break; }
    }
    const bytes = new Uint8Array(count); let offset = 0; for (const part of chunks) { bytes.set(part,offset); offset += part.length; }
    return {status:response.status,url:response.url,redirect_followed:false,headers:[...response.headers],body:new TextDecoder().decode(bytes),body_truncated:truncated};
  } finally { clearTimeout(timer); }
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
      'This example omits credentials, blocks unsupported headers and uses manual redirects. Repeater follows redirects.',
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
  add('config.example.json',json({allowedOrigin:'',request:null}));
  add('.gitignore','config.json\n.env*\nrequests/*.json\nevidence/\nprovenance.json\n');
  add('package.json',json({name:'reb-observed-client',private:true,type:'module',engines:{node:'>=22'},scripts:{example:'node examples/request-001.mjs',send:'node examples/request-001.mjs --send'}}));
  add('src/client.mjs',`// Generated local client. Inputs are data, never evaluated code.\n${capturedClientIssues.toString()}\n${capturedClientSend.toString()}\nexport {capturedClientSend as sendRequest};\n`);
  add('src/services/service-001.mjs',"import {readFile} from 'node:fs/promises';\nimport {sendRequest} from '../client.mjs';\nconst read = async path => JSON.parse(await readFile(new URL(path,import.meta.url),'utf8'));\nexport async function request001(options = {}) {\n  const [input,provenance] = await Promise.all([read('../../requests/request-001.json'),read('../../provenance.json')]);\n  return sendRequest(input,{...options,provenance});\n}\n");
  add('examples/request-001.mjs',"import {readFile} from 'node:fs/promises';\nimport {request001} from '../src/services/service-001.mjs';\nconst args = process.argv.slice(2);\nif(args.some(arg=>arg!=='--send') || args.length>1) throw new Error('Usage: node examples/request-001.mjs [--send]');\nlet config = {};\ntry {config=JSON.parse(await readFile(new URL('../config.json',import.meta.url),'utf8'));} catch(error) {if(error.code!=='ENOENT')throw error;}\nconsole.log(JSON.stringify(await request001({config,send:args.includes('--send')}),null,2));\n");
  add('README.md',`# One observed API operation\n\nThis project contains one reviewed request representation, not a discovered API specification or SDK. service-001 groups only the observed origin in provenance.json; the neutral filenames contain no captured paths or secrets.\n\n## Run deliberately\n\n1. Use Node.js 22 or newer. No packages or install step are required.\n2. Run \`node examples/request-001.mjs\` for a dry run. It never sends a request.\n3. Review requests/request-001.json and evidence/. Copy config.example.json to config.json and set allowedOrigin to the exact authorized origin.\n4. For a redacted or unsupported export, supply a complete reviewed request object in config.request, using the request file's method/url/headers/body/timeout_ms shape. Headers are pairs, not an object. Never paste credentials into a request intended for this credential-omitting client.\n5. Only when authorized, run \`node examples/request-001.mjs --send\`. This can change server data for mutating methods. It sends once, without retries, and does not follow redirects.\n\n## Layout\n\n- src/client.mjs: bounded HTTP client and input checks\n- src/services/service-001.mjs: the one observed operation\n- requests/request-001.json: data, never executable source\n- examples/request-001.mjs: explicit dry-run/send entry point\n- config.example.json: local configuration placeholders\n- provenance.json: capture/run identity, unresolved problems and limitations\n- evidence/: retained original evidence in raw mode, or its explicitly labeled redacted copy\n\n## Fidelity and privacy\n\nExport mode: ${mode}. Raw evidence is preserved even when the client cannot faithfully replay it. Unsupported headers, duplicate header names, multipart, binary and truncated bodies are never silently rewritten into a claimed complete request. Review provenance.json before use. HTTP client header order/casing, automatic headers, URL normalization, cookies, redirects, TLS, compression and CORS behavior can differ. A successful response is not proof that an API operation is equivalent or authorized. Response text is limited to 64 KiB and its truncation is reported.\n\nRaw values stay raw in this explicit export. Redacted copies remove header values and bodies and strip URL credentials/query/fragment; names, paths and identifiers can still be sensitive. Do not publish these files without review. The included .gitignore excludes local configuration, request data, evidence and provenance.\n`);
  return {files,provenance,bytes:capturedClientZip(files)};
}

function installCapturedClientWorkflow(options) {
  const dialog = document.querySelector('#captured-client-review');
  if (!dialog) return {sync() {}};
  const content = dialog.querySelector('[data-client-review-content]'), status = dialog.querySelector('[data-client-review-status]');
  const apply = dialog.querySelector('[data-client-apply]'), replace = dialog.querySelector('[data-client-replace]');
  const replaceLabel = dialog.querySelector('[data-client-replace-label]');
  const nativeShell = document.documentElement.classList.contains('native-shell');
  const nativeExporter = globalThis.webkit?.messageHandlers?.rebClientProjectExport;
  const exportUnavailable = nativeShell && !nativeExporter;
  document.querySelectorAll('[data-client-export-support]').forEach(node => {
    node.textContent = exportUnavailable ? 'Project export is unavailable in this older native shell. Update the packaged app; Copy raw capture remains available.' : nativeShell ? 'Choose a local ZIP destination in the macOS Save dialog. Raw evidence can contain secrets; review before sharing.' : 'Download a local ZIP. Raw evidence can contain secrets; review before sharing.';
  });
  let reviewed = null, revision = 0, busy = false, opener = null;
  const currentCapture = () => {
    const selected = options.getRequest();
    const identity = selected && apiCatalogRequestIdentity(selected);
    if (!identity || !apiCatalogResolveSource(identity,options.getRequests()).record) throw new TypeError('The exact selected capture is unavailable or ambiguous.');
    return capturedClientCapture(selected);
  };
  const stillCurrent = () => {
    try { const current = currentCapture(); return JSON.stringify([current.identity,current.evidence]) === JSON.stringify([reviewed.identity,reviewed.evidence]); } catch { return false; }
  };
  const note = (message, parent = content, tag = 'p') => { const node = document.createElement(tag); node.textContent = message; parent.append(node); return node; };
  const close = () => { revision++; busy = false; reviewed = null; if (dialog.open) dialog.close(); opener?.focus({preventScroll:true}); };
  dialog.querySelector('[data-client-close]').addEventListener('click',close);
  dialog.addEventListener('cancel',event => { event.preventDefault(); close(); });
  dialog.addEventListener('close',() => { revision++; reviewed = null; busy = false; });
  document.addEventListener('keydown',event => {
    if (!dialog.open) return;
    if (event.key === 'F8' || event.altKey && ['ArrowLeft','ArrowRight'].includes(event.key) ||
        (event.ctrlKey || event.metaKey) && ['p','j'].includes(event.key.toLowerCase())) { event.preventDefault(); event.stopImmediatePropagation(); }
  },true);
  const sync = () => {
    let capture = false; try { capture = Boolean(options.getRequest()?.captureRecord); } catch { /* No retained selection. */ }
    document.querySelectorAll('[data-client-capture]').forEach(button => { button.disabled = !capture || busy || exportUnavailable && button.dataset.clientCapture !== 'draft'; });
    document.querySelectorAll('[data-client-run-export]').forEach(button => { button.disabled = !options.getRun() || busy || exportUnavailable; });
    if (!dialog.open || !reviewed) return;
    const matches = busy || stillCurrent();
    apply.disabled = busy || !matches || reviewed.problems.length > 0 || reviewed.templateProblems.length > 0 || options.hasDraft() && !replace.checked;
    if (!busy && !matches) status.textContent = 'The capture changed or expired. Close and review the current record again. Nothing was sent.';
  };
  replace.addEventListener('change',sync);
  document.querySelector('[data-client-capture="draft"]').addEventListener('click',event => {
    try {
      reviewed = currentCapture(); revision++; opener = event.currentTarget; busy = false; content.replaceChildren(); replace.checked = false;
      replaceLabel.hidden = !options.hasDraft();
      note(`${reviewed.input.method} ${reviewed.input.url}`,content,'pre');
      note('Review the retained request values below. This is a CDP representation, not original wire bytes. Header casing/order, cookies, redirects and browser-controlled fields limit replay fidelity.');
      const problems = [...reviewed.problems,...reviewed.templateProblems];
      if (problems.length) { note('Cannot create a faithful supported Repeater draft. Original values remain available through raw capture or raw project export.'); const list = document.createElement('ul'); content.append(list); problems.forEach(problem=>note(problem,list,'li')); }
      for (const [label,value] of [['Request headers',JSON.stringify(reviewed.input.headers,null,2)],['Request body',reviewed.input.body ?? '(unavailable; see original evidence)']]) {
        const details = document.createElement('details'); note(label,details,'summary'); note(value,details,'pre'); content.append(details);
      }
      status.textContent = 'Confirmation copies this reviewed snapshot and, if needed, creates an isolated blank page. Creating that page can clear live Traffic; the confirmed source snapshot is retained with the draft. It never sends the target request. Use Repeater Send separately.';
      dialog.showModal(); sync(); dialog.querySelector('[data-client-close]').focus();
    } catch (error) { options.notice(error.message); }
  });
  apply.addEventListener('click',async () => {
    if (apply.disabled || !reviewed || !stillCurrent()) { sync(); return; }
    const source = reviewed, owner = ++revision, editRevision = options.editRevision(); busy = true; sync();
    status.textContent = 'Preparing the isolated draft. No target request is being sent.';
    try {
      const prepared = await options.prepareContext();
      if (!prepared?.key || owner !== revision || !dialog.open) return;
      const context = prepared.key;
      // A confirmed new disposable page may clear Traffic. Existing contexts may
      // not import a capture that expired or changed during the async boundary.
      const expectedReset = prepared.created && !options.getRequest() && !apiCatalogResolveSource(source.identity,options.getRequests()).record;
      if (!stillCurrent() && !expectedReset) throw new TypeError('The reviewed capture changed or expired. Close and review the current record again.');
      if (options.contextKey() !== context || options.editRevision() !== editRevision) throw new TypeError('The disposable context or draft changed. Review again; no draft was overwritten.');
      options.writeDraft(source,context);
      close(); options.openRepeater();
      options.notice('Reviewed capture copied to an editable Repeater draft. No request was sent. Original evidence is retained separately for project export.');
    } catch (error) { if (owner === revision && dialog.open) status.textContent = `${error.message} Context creation may already have completed; no target request was sent.`; }
    finally { if (owner === revision) busy = false; sync(); }
  });
  const download = async (source,mode) => {
    if (busy) return;
    if (exportUnavailable) throw new TypeError('Update the native app to enable the client-project Save dialog.');
    const project = capturedClientProject(source,mode);
    busy = true; sync();
    try {
      if (nativeShell) {
        let binary = '';
        for (let offset=0;offset<project.bytes.length;offset+=16384) binary += String.fromCharCode(...project.bytes.subarray(offset,offset+16384));
        const result = await nativeExporter.postMessage({format:'reb-client-project-save-v1',mode,base64:btoa(binary)});
        if (!result || !['saved','canceled'].includes(result.status)) throw new TypeError('The native save result could not be confirmed.');
        options.notice(result.status === 'saved' ? `Client project saved locally (${mode}). Review its evidence and configuration before explicitly sending or sharing.` : 'Project save canceled. No archive was written.');
      } else {
        const url = URL.createObjectURL(new Blob([project.bytes],{type:'application/zip'}));
        const link = document.createElement('a'); link.href = url; link.download = mode === 'raw' ? 'reb-client-project.raw.zip' : 'reb-client-project.redacted.zip';
        link.hidden = true; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
        options.notice(`Project download requested (${mode}). Check browser downloads. It contains one operation, a dry-run example and explicit provenance; review before sharing.`);
      }
    } finally { busy = false; sync(); }
  };
  for (const button of document.querySelectorAll('[data-client-capture="raw"], [data-client-capture="redacted_copy"]')) button.addEventListener('click',async () => {
    if (button.disabled || busy) return;
    try { await download(currentCapture(),button.dataset.clientCapture); } catch (error) { options.notice(`Project save failed: ${error.message}`); }
  });
  for (const button of document.querySelectorAll('[data-client-run-export]')) button.addEventListener('click',async () => {
    if (button.disabled || busy) return;
    try {
      const run = options.getRun(), context = options.contextKey();
      await download(capturedClientRun(run,context,options.getRunCapture(run,context)),button.dataset.clientRunExport);
    } catch (error) { options.notice(`Project save failed: ${error.message}`); }
  });
  sync(); return {sync,close};
}
