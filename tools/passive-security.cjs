// Offline interpretation only. No source strings enter the report's output vocabulary.
const passiveSecurityLimits = Object.freeze({source_bytes:1048576,body_bytes:131072,header_pairs:128,header_bytes:65536,rows:512,matches_per_location:100});
const passiveSecurityReferences = Object.freeze({
  hsts:'https://www.rfc-editor.org/rfc/rfc6797#section-8.1',
  csp:'https://www.w3.org/TR/CSP3/#policy-delivery',
  nosniff:'https://fetch.spec.whatwg.org/#x-content-type-options-header',
  referrer:'https://www.w3.org/TR/referrer-policy/#parse-referrer-policy-from-header'
});
const passiveBytes = value => new TextEncoder().encode(value).length;
const passiveText = (value,limit) => typeof value === 'string' && value.isWellFormed() && passiveBytes(value) <= limit;
const passiveObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const passiveOWS = value => value.replace(/^[\t ]+|[\t ]+$/g,'');
function passiveIdentity(identity,record) {
  if (!passiveObject(identity) || !passiveText(identity.instance,128) || !identity.instance || !Number.isSafeInteger(identity.epoch) || identity.epoch < 0 ||
      !passiveText(identity.request,8192) || !identity.request || !passiveText(identity.target,4096) || !identity.target ||
      !Number.isFinite(identity.started) || identity.started < 0 || identity.request !== record?.id || identity.target !== record?.target_id || identity.started !== record?.started_monotonic_ms) throw Error('Select a bounded capture with exact source identity.');
  return JSON.stringify([identity.instance,identity.epoch,identity.request,identity.target,identity.started]);
}
function passiveValidate(record,identity) {
  const identityText=passiveIdentity(identity,record);
  if (!passiveText(record.url,65536) || typeof record.url_truncated !== 'boolean' || !['pending','complete','failed'].includes(record.state) ||
      !(record.status === null || Number.isInteger(record.status) && record.status >= 0 && record.status <= 999) ||
      typeof record.from_disk_cache !== 'boolean' || typeof record.from_service_worker !== 'boolean') throw Error('Unsupported retained capture fields.');
  for (const side of [record.request,record.response]) {
    if (!passiveObject(side) || !Array.isArray(side.headers) || side.headers.length > 128 || typeof side.headers_truncated !== 'boolean') throw Error('Unsupported retained headers.');
    let total=0;
    for (const pair of side.headers) {
      if (!Array.isArray(pair) || pair.length !== 2 || !passiveText(pair[0],128) || !passiveText(pair[1],8192)) throw Error('Unsupported retained headers.');
      total+=passiveBytes(pair[0])+passiveBytes(pair[1]);
    }
    if (total>65536) throw Error('Retained headers exceed report limits.');
    const body=side.body;
    if (!passiveObject(body) || !['available','empty','missing','loading','error'].includes(body.state) || typeof body.truncated !== 'boolean' ||
        !passiveText(body.text,131072) || !passiveText(body.base64,174764)) throw Error('Unsupported retained body.');
  }
  return identityText;
}
function passiveHeaders(record,prefix) {
  const headers=record.response.headers;
  const matching=name=>headers.flatMap(([key,value],index)=>key.toLowerCase()===name?[{value,location:`${prefix}/response/headers/${index}/1`}]:[]);
  const incomplete=record.response.headers_truncated || record.status === null || record.status < 100 || record.state !== 'complete';
  const observation=(id,name,reference)=>{
    const items=matching(name);
    return {items,result:{rule_id:`${id}-v1`,locations:items.map(item=>item.location),outcome:incomplete?'unknown':items.length?'observed':'not_observed',
      reason:incomplete?'incomplete_response_headers':items.length?'retained_header_present':'absent_from_retained_headers',reference}};
  };
  const out=[];
  const hsts=observation('hsts','strict-transport-security',passiveSecurityReferences.hsts);
  let url;try {url=new URL(record.url);} catch { /* Context stays unknown. */ }
  if (!incomplete) {
    if (record.url_truncated || !url || !['http:','https:'].includes(url.protocol)) Object.assign(hsts.result,{outcome:'unknown',reason:'transport_context_unknown'});
    else if (url.protocol==='http:') Object.assign(hsts.result,{outcome:'not_applicable',reason:'hsts_ignored_on_http'});
    else if (url.hostname.startsWith('[') || /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname)) Object.assign(hsts.result,{outcome:'not_applicable',reason:'hsts_ip_literal'});
    else if (hsts.items.length>1) Object.assign(hsts.result,{outcome:'unknown',reason:'duplicate_header_order_not_wire_evidence'});
    else if (hsts.items.length===1) {
      // Deliberately recognize a small grammar subset. Quoted/extension syntax
      // outside it is unknown, not an assertion that a browser rejects it.
      const directives=hsts.items[0].value.split(';').map(passiveOWS).filter(Boolean),seen=new Set();
      let age=null,include=false,unsupported=false;
      for (const directive of directives) {
        const match=/^([!#$%&'*+.^_`|~0-9A-Za-z-]+)(?:[\t ]*=[\t ]*(.*))?$/.exec(directive);
        if (!match) {unsupported=true;break;}
        const name=match[1].toLowerCase();
        if (seen.has(name)) {unsupported=true;break;} seen.add(name);
        if (name==='max-age') {
          const value=match[2];
          if (typeof value!=='string' || !/^(?:[0-9]+|"[0-9]+")$/.test(value)) {unsupported=true;break;}
          age=/^["0]+$/.test(value)?'zero':'positive';
        } else if (name==='includesubdomains' && match[2]===undefined) include=true;
        else {unsupported=true;break;}
      }
      Object.assign(hsts.result,unsupported || age===null?{outcome:'unknown',reason:'unsupported_or_ambiguous_hsts_syntax'}:
        {reason:age==='zero'?'max_age_zero_observed':'max_age_positive_observed',include_subdomains_observed:include});
    }
  }
  out.push(hsts.result);
  const csp=observation('csp','content-security-policy',passiveSecurityReferences.csp),reportOnly=matching('content-security-policy-report-only');
  csp.result.report_only_header_count=reportOnly.length;
  csp.result.report_only_locations=reportOnly.map(item=>item.location);
  if (!incomplete) {
    if (csp.items.some(item=>passiveOWS(item.value).length)) csp.result.reason='enforcing_header_present_policy_not_evaluated';
    else if(csp.items.length) Object.assign(csp.result,{outcome:'unknown',reason:'empty_enforcing_header'});
    else if(reportOnly.length) csp.result.reason='report_only_does_not_enforce';
  }
  out.push(csp.result);
  const nosniff=observation('nosniff','x-content-type-options',passiveSecurityReferences.nosniff);
  if(!incomplete && nosniff.items.length) {
    if(nosniff.items.length>1) Object.assign(nosniff.result,{outcome:'unknown',reason:'duplicate_header_order_not_wire_evidence'});
    else if(/["\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\uffff]/.test(nosniff.items[0].value)) Object.assign(nosniff.result,{outcome:'unknown',reason:'unsupported_header_syntax'});
    else nosniff.result.reason=passiveOWS(nosniff.items[0].value.split(',')[0]).toLowerCase()==='nosniff'?'first_nosniff_token_observed':'first_token_not_nosniff';
  }
  out.push(nosniff.result);
  const referrer=observation('referrer','referrer-policy',passiveSecurityReferences.referrer);
  if(!incomplete && referrer.items.length) {
    const known=new Set(['no-referrer','no-referrer-when-downgrade','same-origin','origin','strict-origin','origin-when-cross-origin','strict-origin-when-cross-origin','unsafe-url']);
    if(referrer.items.length>1) Object.assign(referrer.result,{outcome:'unknown',reason:'duplicate_header_order_not_wire_evidence'});
    else if(/["\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\uffff]/.test(referrer.items[0].value)) Object.assign(referrer.result,{outcome:'unknown',reason:'unsupported_header_syntax'});
    else {
      const recognized=referrer.items[0].value.split(',').map(passiveOWS).filter(value=>known.has(value));
      Object.assign(referrer.result,recognized.length?{reason:'last_recognized_policy_observed',policy:recognized.at(-1)}:{outcome:'unknown',reason:'no_recognized_policy'});
    }
  }
  out.push(referrer.result);
  return out;
}
function passiveSecrets(record,prefix) {
  const findings=[],coverage=[];let omitted=0;
  const add=(category,location,count,capped=false)=>{
    if(!count)return;
    if(findings.length>=512){omitted++;return;}
    findings.push({category,location,count,count_is_lower_bound:capped,confidence:'heuristic'});
  };
  const count=(expression,text)=>{expression.lastIndex=0;let count=0;while(expression.exec(text)) {if(++count===100)return {count,capped:true};}return {count,capped:false};};
  const scan=(text,location)=>{
    for(const [category,pattern] of [
      ['private-key-marker',/-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g],
      ['jwt-shaped',/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
      ['secret-assignment',/(?:^|[^A-Za-z0-9_])(?:["']?)(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)["']?[\t ]*[:=][\t ]*["']?[A-Za-z0-9_+\/.=-]{8,}/gi]
    ]) {const result=count(pattern,text);add(category,location,result.count,result.capped);}
  };
  const keyPattern=/^(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|token|authorization)$/i;
  try {
    const url=new URL(record.url);
    if(!['http:','https:','ws:','wss:'].includes(url.protocol)) throw Error();
    if(url.username || url.password)add('url-userinfo',`${prefix}/url`,1);
    let parameters=0;for(const [key,value] of url.searchParams)if(keyPattern.test(key)&&value)parameters++;
    add('credential-parameter',`${prefix}/url`,Math.min(parameters,100),parameters>100);
    scan(record.url,`${prefix}/url`);
    coverage.push({location:`${prefix}/url`,state:record.url_truncated?'partial':'scanned',reason:record.url_truncated?'retained_prefix':'url_text_and_query_names_only'});
  } catch {coverage.push({location:`${prefix}/url`,state:'unknown',reason:'unsupported_url'});}
  for(const side of ['request','response']) {
    const data=record[side],base=`${prefix}/${side}`;
    for(const [index,[name,value]] of data.headers.entries()) {
      if(value.trim()) {
        if(/^(authorization|proxy-authorization|x-api-key|api-key|x-auth-token|x-access-token)$/i.test(name))add('credential-header',`${base}/headers/${index}/1`,1);
        if(/^(cookie|set-cookie)$/i.test(name))add('cookie-header',`${base}/headers/${index}/1`,1);
      }
      scan(name,`${base}/headers/${index}/0`);scan(value,`${base}/headers/${index}/1`);
    }
    coverage.push({location:`${base}/headers`,state:data.headers_truncated?'partial':'scanned',reason:data.headers_truncated?'retained_prefix':'retained_pairs_only'});
    const body=data.body,location=`${base}/body`;
    if(body.state==='empty' && !body.text && !body.base64 && !body.truncated)coverage.push({location,state:'scanned',reason:'retained_empty_marker'});
    else if(body.state!=='available')coverage.push({location,state:'unknown',reason:'body_unavailable_or_inconsistent'});
    else if(body.base64)coverage.push({location,state:'unknown',reason:body.text?'ambiguous_body_representations':'base64_not_analyzed'});
    else {
      scan(body.text,`${location}/text`);
      coverage.push({location,state:body.truncated?'partial':'scanned',reason:body.truncated?'retained_prefix':'text_patterns_only'});
    }
  }
  return {rule_set:'reb-secret-shapes-v1',findings,coverage,omitted_finding_rows:omitted,
    limitation:'Shape/name matches can be examples, public data or false positives. No validity, ownership, exploitability or secret-free claim. Values are never decoded, extracted or returned.'};
}
async function passiveSecurityReport(record,identity,sourceText,sourceKind='retained-selection') {
  if(!['retained-selection','saved-exact-request'].includes(sourceKind) || !passiveText(sourceText,1048576))throw Error('Unsupported report source.');
  const identityText=passiveValidate(record,identity),prefix=sourceKind==='saved-exact-request'?'/request':'/record';
  let source;try{source=JSON.parse(sourceText);}catch{throw Error('Unsupported report source JSON.');}
  const sourceRecord=sourceKind==='saved-exact-request'?source.request:source.record;
  const sourceIdentity=sourceKind==='saved-exact-request'?{instance:source.source?.instance_id,epoch:source.source?.capture_epoch,request:source.source?.request_id,target:source.source?.target_id,started:source.source?.started_monotonic_ms}:source.identity;
  if(source.format!==(sourceKind==='saved-exact-request'?'reb-network-request-v1':'reb-passive-security-selection-v1') ||
      JSON.stringify(sourceRecord)!==JSON.stringify(record) || passiveIdentity(sourceIdentity,record)!==identityText)throw Error('Report source does not match the selected evidence.');
  // All analysis happens before the first await, binding interpretation to the
  // immutable caller snapshot rather than a later live request revision.
  const headers=passiveHeaders(record,prefix),secrets=passiveSecrets(record,prefix);
  const context={request_state:record.state,response_observed:record.status!==null&&record.status>=100,
    from_disk_cache:record.from_disk_cache,from_service_worker:record.from_service_worker};
  const sha=async text=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text))),byte=>byte.toString(16).padStart(2,'0')).join('');
  const [sourceHash,identityHash]=await Promise.all([sha(sourceText),sha(identityText)]);
  return {format:'reb-passive-security-report-v1',rule_set:'reb-security-headers-v1',mode:'offline-passive',network_requests:0,
    source:{kind:sourceKind,sha256:sourceHash,identity_sha256:identityHash,identity_projection:'JSON array: instance, epoch, request, target, unrounded started',record_pointer:prefix},
    context,limits:{...passiveSecurityLimits},headers,secrets,
    coverage:{complete:false,scope:'One selected retained CDP record. Not original wire evidence; not a site-wide audit.',
      limitations:['Header casing, ordering, duplicate wire lines and extra-info headers may be unavailable. Absence is only in retained evidence.',
        'Header observations do not prove browser enforcement, transport trust, application security or the absence of vulnerabilities.',
        'CSP values, meta policies, framing policy and browser policy state are not evaluated. HSTS preload and inherited policies are not known.',
        'Only URL/query text, retained header pairs and unambiguous retained text bodies are examined. Other metadata, fragments as parameters, encodings, binary/base64 bodies, compression and obfuscation are not analyzed.',
        'Source and identity hashes link local evidence; they are not authenticity attestations. Reports are local metadata, not a sharing permission.',
        'Active probes, target requests, credential checks, remediation and external lookups are not implemented.']}};
}
if(typeof module==='object'&&module?.exports&&typeof require==='function')module.exports={passiveSecurityReport};
