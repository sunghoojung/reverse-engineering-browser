#!/usr/bin/env node
// Synthetic local evidence only. Never load a private capture or contact targets.
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,stat,symlink,mkdir,rm} from 'node:fs/promises';
import {checkedSpawnSync as spawnSync} from './checked-spawn-sync.mjs';
import {createHash,webcrypto} from 'node:crypto';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {network} from './saved-traffic-fixture.mjs';
import passive from './passive-security.cjs';
const copy=value=>JSON.parse(JSON.stringify(value));
const identity={instance:'synthetic-instance',epoch:1,request:'synthetic-json',target:'synthetic-target',started:100};
function record() {
  const value=network().requests[0];value.url='https://example.test/path';value.request.headers=[];value.response.headers=[];
  for(const side of [value.request,value.response])side.body={state:'available',mime:'text/plain',text:'Ordinary authored example',base64:'',truncated:false,reason:''};
  return value;
}
function source(value,id=identity) {return JSON.stringify({format:'reb-passive-security-selection-v1',identity:id,record:value});}
const report=value=>passive.passiveSecurityReport(value,identity,source(value));
const rule=(report,id)=>report.headers.find(item=>item.rule_id===id+'-v1');
const base=record(),before=JSON.stringify(base),result=await report(base);
assert.equal(JSON.stringify(base),before);assert.deepEqual(await report(base),result);
assert.equal(result.source.sha256,createHash('sha256').update(source(base)).digest('hex'));
assert.equal(result.source.identity_sha256,createHash('sha256').update(JSON.stringify(Object.values(identity))).digest('hex'));
assert.equal(result.coverage.complete,false);assert.equal(result.network_requests,0);assert.equal(result.secrets.findings.length,0);
assert(result.headers.every(item=>item.outcome==='not_observed'));
async function headers(pairs,change=()=>{}) {const value=record();value.response.headers=pairs;change(value);return report(value);}
for(const [value,reason] of [['max-age=300','max_age_positive_observed'],['MAX-AGE="000"; includeSubDomains','max_age_zero_observed'],[' max-age = 1 ; includeSubDomains ;','max_age_positive_observed']]) {
  const item=rule(await headers([['Strict-Transport-Security',value]]),'hsts');assert.equal(item.reason,reason);assert.equal(item.outcome,'observed');
}
for(const value of ['max-age=1; max-age=2','max-age=-1','max-age=1, max-age=2','max-age=1; preload','max-age="1\\2"','includeSubDomains','max-age=1; includesubdomains=x','max-age=1\n'])assert.equal(rule(await headers([['strict-transport-security',value]]),'hsts').outcome,'unknown',value);
for(const [url,reason] of [['http://example.test/','hsts_ignored_on_http'],['https://127.0.0.1/','hsts_ip_literal'],['https://[::1]/','hsts_ip_literal']])assert.equal(rule(await headers([['strict-transport-security','max-age=1']],r=>r.url=url),'hsts').reason,reason);
assert.equal(rule(await headers([],r=>r.url_truncated=true),'hsts').outcome,'unknown');
assert.equal(rule(await headers([['strict-transport-security','max-age=1'],['Strict-Transport-Security','max-age=0']]),'hsts').outcome,'unknown');
const multiple=await headers([['Content-Security-Policy',"default-src 'none'"],['Content-Security-Policy',"script-src 'self', frame-ancestors 'none'"],['Content-Security-Policy-Report-Only',"default-src *"]]);
assert.equal(rule(multiple,'csp').locations.length,2);assert.equal(rule(multiple,'csp').report_only_header_count,1);assert.equal(rule(multiple,'csp').reason,'enforcing_header_present_policy_not_evaluated');
assert.equal(rule(await headers([['content-security-policy-report-only',"default-src 'none'"]]),'csp').reason,'report_only_does_not_enforce');
assert.equal(rule(await headers([['content-security-policy','']]),'csp').outcome,'unknown');
for(const [value,reason] of [['NoSnIfF','first_nosniff_token_observed'],['nosniff, unknown','first_nosniff_token_observed'],['unknown, nosniff','first_token_not_nosniff'],['"nosniff"','unsupported_header_syntax']])assert.equal(rule(await headers([['X-Content-Type-Options',value]]),'nosniff').reason,reason);
assert.equal(rule(await headers([['x-content-type-options','nosniff'],['X-Content-Type-Options','unknown']]),'nosniff').outcome,'unknown');
assert.equal(rule(await headers([['referrer-policy','no-referrer, unknown, unsafe-url, future-policy']]),'referrer').policy,'unsafe-url');
assert.equal(rule(await headers([['referrer-policy','ORIGIN']]),'referrer').outcome,'unknown');
assert.equal(rule(await headers([['referrer-policy','origin'],['referrer-policy','no-referrer']]),'referrer').outcome,'unknown');
for(const mutate of [r=>r.response.headers_truncated=true,r=>r.state='pending',r=>r.state='failed',r=>r.status=null,r=>r.status=0])assert((await headers([['X-Content-Type-Options','nosniff']],mutate)).headers.every(item=>item.outcome==='unknown'));
const sensitive=record();
sensitive.url='https://authored-user:authored-password@example.test/?access_token=AUTHORED_QUERY_SECRET&token=SECOND_QUERY_SECRET';
sensitive.request.headers=[['Authorization','Bearer AUTHORED_AUTH_SECRET'],['Cookie','AUTHORED_COOKIE_SECRET'],['X-Api-Key','AUTHORED_API_SECRET']];
sensitive.response.headers=[['Set-Cookie','AUTHORED_RESPONSE_SECRET']];
sensitive.request.body.text='password="AUTHORED_PASSWORD_SECRET" api_key: "AUTHORED_KEY_SECRET"\n' + ['-----BEGIN RSA','PRIVATE KEY-----'].join(' ') + '\nAUTHORED_KEY_BYTES\n-----END RSA PRIVATE KEY-----\neyJhbGciOiJub25lIn0.eyJzdWIiOiJhdXRob3JlZCJ9.c3ludGhldGlj';
const secrets=await report(sensitive),encoded=JSON.stringify(secrets);
for(const value of ['AUTHORED_','authored-user','authored-password','synthetic-json','synthetic-target','example.test','Bearer','eyJhbGci','BEGIN RSA'])assert(!encoded.includes(value),value);
assert.deepEqual(new Set(secrets.secrets.findings.map(item=>item.category)),new Set(['url-userinfo','credential-parameter','credential-header','cookie-header','secret-assignment','private-key-marker','jwt-shaped']));
assert.equal(secrets.secrets.findings.find(item=>item.category==='credential-parameter').count,2);
assert(secrets.secrets.findings.every(item=>Object.keys(item).sort().join(',')==='category,confidence,count,count_is_lower_bound,location'));
const falsePositives=record();falsePositives.request.body.text='password = ""; const password; password: 1; SHA256=abcdef1234567890; id=12345678901234567890; public function password() {}';
assert.equal((await report(falsePositives)).secrets.findings.length,0);
falsePositives.request.body.text='password="example-not-live"';assert.equal((await report(falsePositives)).secrets.findings[0].confidence,'heuristic','Examples can match, never claimed as confirmed credentials');
for(const [body,reason,state] of [
 [{state:'missing'},'body_unavailable_or_inconsistent','unknown'],[{state:'loading'},'body_unavailable_or_inconsistent','unknown'],[{state:'error'},'body_unavailable_or_inconsistent','unknown'],
 [{base64:'cGFzc3dvcmQ9U0VDUkVUVkFMVUU=',text:''},'base64_not_analyzed','unknown'],[{base64:'eA=='},'ambiguous_body_representations','unknown'],
 [{state:'empty'},'body_unavailable_or_inconsistent','unknown'],[{state:'empty',text:''},'retained_empty_marker','scanned'],[{truncated:true},'retained_prefix','partial']
]) {
  const value=record();Object.assign(value.response.body,body);const item=(await report(value)).secrets.coverage.find(item=>item.location.endsWith('/response/body'));
  assert.equal(item.reason,reason);assert.equal(item.state,state);
}
const capped=record();capped.request.body.text=('password=AUTHORED_SECRET\n').repeat(101);
assert.equal((await report(capped)).secrets.findings[0].count,100);assert.equal((await report(capped)).secrets.findings[0].count_is_lower_bound,true);
for(const side of ['request','response'])capped[side].headers=Array.from({length:128},()=>['password=AUTHORED_SECRET','password=AUTHORED_SECRET']);
assert.equal((await report(capped)).secrets.findings.length,512);assert((await report(capped)).secrets.omitted_finding_rows>0);
for(const change of [r=>r.request.headers.push(['X','x'.repeat(8193)]),r=>r.response.body.text='x'.repeat(131073),r=>r.url='x'.repeat(65537),r=>r.target_id='wrong',r=>r.response.body.state='redacted',r=>r.url='\ud800']) {
  const value=record();change(value);await assert.rejects(report(value));
}
await assert.rejects(passive.passiveSecurityReport(base,identity,source(sensitive)));
console.log('PASS deterministic provenance, four versioned header rules, primary-standard edge cases, privacy vocabulary, false positives, unknown coverage and bounds');
const directory=await mkdtemp(join(tmpdir(),'reb-passive-check-'));
try {
  const input=join(directory,'source.json'),output=join(directory,'report.json');
  const saved={format:'reb-network-request-v1',source:{instance_id:identity.instance,capture_epoch:identity.epoch,request_id:identity.request,target_id:identity.target,started_monotonic_ms:identity.started},debugger_generation:17,request:sensitive};
  const text=JSON.stringify(saved);await writeFile(input,text);
  // Bound a local child hang while allowing heavily loaded developer machines.
const cli=(path=input,destination=output)=>spawnSync(process.execPath,['tools/report-passive-security.mjs','--input',path,'--output',destination],{encoding:'utf8'});
  const success=cli();assert.equal(success.status,0,success.stderr);assert(!success.stdout.includes('AUTHORED'));assert.equal(JSON.parse(success.stdout).network_requests,0);
  const document=JSON.parse(await readFile(output,'utf8'));assert.equal(document.source.sha256,createHash('sha256').update(text).digest('hex'));assert.equal(document.source.record_pointer,'/request');
  assert(document.secrets.findings.every(item=>item.location.startsWith('/request/')));assert.equal((await stat(output)).mode&0o777,0o600);
  assert.equal(cli().status,1);assert.equal(JSON.parse(await readFile(output,'utf8')).source.sha256,document.source.sha256);
  const link=join(directory,'link.json');await symlink(input,link);assert.equal(cli(link,join(directory,'new.json')).status,1);
  const outLink=join(directory,'outlink.json');await symlink(input,outLink);assert.equal(cli(input,outLink).status,1);assert.equal(await readFile(input,'utf8'),text);
  await mkdir(join(directory,'folder'));assert.equal(cli(join(directory,'folder')).status,1);
  for(const malformed of ['{"format":"x","format":"y"}',text.replace('"capture_epoch":1','"capture_epoch":1.0'),text.replace('"capture_epoch":1','"capture_epoch":9007199254740993'),' '.repeat(1048577),'{"value":"\\ud800"}',JSON.stringify({...saved,source:{...saved.source,request_id:'wrong'}})]) {
    const bad=join(directory,'bad.json');await writeFile(bad,malformed);const failed=cli(bad,join(directory,'unused.json'));assert.equal(failed.status,1);assert(!failed.stderr.includes('AUTHORED'));assert(!failed.stdout);
  }
  const bad=join(directory,'bad.json');await writeFile(bad,Buffer.from([0xc0,0xaf]));assert.equal(cli(bad,join(directory,'unused.json')).status,1);
  console.log('PASS real CLI, source-byte hash, fixed source locations, private atomic no-overwrite, symlink/size/UTF-8/duplicate/identity/numeric refusal and content-free errors');
} finally {await rm(directory,{recursive:true,force:true});}
