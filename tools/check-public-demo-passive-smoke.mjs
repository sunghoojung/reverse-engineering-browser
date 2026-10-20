import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {summarize,summarizeTargets,targets,boundedJson} from './public-demo-passive-smoke.mjs';
const secret='DO_NOT_EXPORT';
const rows=[{url:`https://demo.fingerprint.com/path?token=${secret}#${secret}`,resource_type:'Fetch',status:200,request:{headers:[secret],body:secret},response:{body:secret},target_title:secret},{url:`https://${secret}.example.test/`,resource_type:secret,status:secret},{url:'malformed',resource_type:'Fetch',status:200}];
const report=summarize({network:{requests:rows,dropped:3,capture_status:{attached_targets:2,pending_targets:secret,failed_targets:-1,dropped_requests:3,error:secret}}});
assert(!JSON.stringify(report).includes(secret));assert.equal(report.requests.reduce((a,r)=>a+r.count,0),3);assert.deepEqual(report.coverage,{transport:'unknown',attached:2,eligible:null,failed:null,overflow:null,gaps:null,dropped:3,state:'unknown',discovery_stale:null});
assert.equal(summarize({}).requests.length,0);assert.deepEqual(targets,[['fingerprint','https://demo.fingerprint.com/playground'],['hcaptcha','https://accounts.hcaptcha.com/demo'],['httpbin-redirect','https://httpbin.org/redirect/2'],['playwright-api','https://demo.playwright.dev/api-mocking/'],['mdn-worker','https://mdn.github.io/dom-examples/web-workers/simple-web-worker/']]);
const source=readFileSync(new URL('./public-demo-passive-smoke.mjs',import.meta.url),'utf8');
assert.equal((source.match(/command\('Page.navigate'/g)||[]).length,1);
assert(!source.includes("command('Runtime.evaluate'"));assert(!source.includes('--no-sandbox'));
assert.deepEqual([...new Set([...source.matchAll(/command\('([^']+)'/g)].map(m=>m[1]))].sort(),['Browser.getVersion','Page.navigate','Target.attachToTarget','Target.createTarget','Target.getTargets']);
const env={...process.env};delete env.REB_PUBLIC_DEMO_OPT_IN;
const refused=spawnSync(process.execPath,[new URL('./public-demo-passive-smoke.mjs',import.meta.url).pathname],{env,encoding:'utf8'});assert.equal(refused.status,2);assert.match(refused.stderr,/Explicit/);
console.log('PASS public-demo fixed targets, explicit opt-in, single-navigation contract, aggregate privacy and no raw diagnostic output');

const concurrent=summarizeTargets({network:{requests:[{target_id:'a',url:targets[0][1],resource_type:'Document',status:200},{target_id:'b',url:targets[1][1],resource_type:'Document',status:201},{target_id:'worker-secret',url:targets[0][1],resource_type:'Fetch',status:202}]}},['a','b']);
assert.equal(concurrent.results[0].requests[0].status,200);assert.equal(concurrent.results[1].requests[0].status,201);
assert(concurrent.results.slice(0,2).every(r=>r.outcome==='request-observed'));assert(concurrent.results.slice(2).every(r=>r.outcome==='request-not-observed'));assert.equal(concurrent.unattributed_requests,1);
assert(!JSON.stringify(concurrent).includes('worker-secret'));
assert.equal(summarizeTargets({network:{requests:[{target_id:'b',url:targets[0][1],resource_type:'Document',status:200}]}},['a','b']).results[0].outcome,'request-not-observed');
console.log('PASS simultaneous top-level target aggregate separation, unknown child/worker attribution, no cross-target success');

const expanded=summarizeTargets({network:{requests:[
  {target_id:'c',url:targets[2][1],resource_type:'Document',status:302,state:'complete'},
  {target_id:'c',url:'https://httpbin.org/relative-redirect/1',resource_type:'Document',status:302,state:'complete'},
  {target_id:'d',url:`https://demo.playwright.dev/api-mocking/api/v1/fruits?token=${secret}`,resource_type:'Fetch',state:'failed',error_text:secret},
  {target_id:'e',url:'https://mdn.github.io/dom-examples/web-workers/simple-web-worker/worker.js',resource_type:'Script',state:'pending'},
  {target_id:'unknown-worker',url:'https://mdn.github.io/dom-examples/web-workers/simple-web-worker/worker.js',resource_type:'Script',state:'complete'},
]}},['a','b','c','d','e']);
assert.equal(expanded.results[2].expected_feature.count,2);
assert.equal(expanded.results[3].expected_feature.count,1);
assert.equal(expanded.results[4].expected_feature.count,1);
assert.deepEqual(expanded.results[3].completion,{complete:0,failed:1,pending_or_unknown:0});
assert.deepEqual(expanded.results[4].completion,{complete:0,failed:0,pending_or_unknown:1});
assert.equal(expanded.unattributed_requests,1);
assert.equal(expanded.independent_comparison,'not-run');
assert(!JSON.stringify(expanded).includes(secret));
assert(!JSON.stringify(expanded).includes('unknown-worker'));
console.log('PASS expanded fixed sites, observed feature counts, failure/pending distinction and no false recorder comparison');

assert.equal(expanded.results[2].expected_feature.outcome,'evidence-observed');
assert.equal(concurrent.results[2].expected_feature.outcome,'evidence-not-observed');
assert.equal(summarizeTargets({network:{requests:[{url:targets[2][1],resource_type:'Document'}]}},[]).results[2].outcome,'request-not-observed');

const workflow=readFileSync(new URL('../.github/workflows/public-demo-passive-smoke.yml',import.meta.url),'utf8');
assert.match(workflow,/branches: \[qa\/public-matrix-20261018\]/);
assert.match(workflow,/github\.event\.created == true && github\.run_attempt == 1/);
assert.match(workflow,/github\.ref == 'refs\/heads\/qa\/public-matrix-20261018'/);
assert(!/pull_request:|schedule:/.test(workflow));
assert.equal(targets.length,5);
console.log('PASS exact one-shot bootstrap branch guard and five-target scope');

assert.deepEqual(await boundedJson(new Response('{"ok":true}'),32),{ok:true});
await assert.rejects(boundedJson(new Response('x'.repeat(33)),32),/state limit/);
await assert.rejects(boundedJson(new Response('invalid'),32));
assert.match(workflow,/persist-credentials: false/);
assert.match(workflow,/CARGO_BUILD_JOBS: 1/);
console.log('PASS bounded response parsing and credential-free bounded CI build');
