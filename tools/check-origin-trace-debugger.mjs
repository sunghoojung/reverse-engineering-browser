import {checkConsoleDOM, createConsoleFixture, checkConsoleInteractions} from './check-console-workspace.mjs';
import { spawn } from "node:child_process";
import { runInNewContext } from "node:vm";
import {
  readFile,
  readdir,
  open,
  rm,
  mkdtemp,
  mkdir,
  writeFile,
  appendFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import assert from "node:assert/strict";
import {checkCollectionController, collectionBrowserFixture, checkCollectionInteractions} from "./check-origin-trace-collection.mjs";
import {checkInvestigationCore, investigationFixture, checkInvestigationInteractions} from "./check-investigation-navigation.mjs";
const investigationBrowser = process.argv[2] === "--investigation-ui-browser";
const collectionBrowser = process.argv[2] === "--collection-ui-browser";
const consoleBrowser = process.argv[2] === "--console-ui-browser";
const trafficBrowser = process.argv[2] === "--traffic-ui-browser";
const sourceFactsBrowser = process.argv[2] === "--source-facts-ui-browser";
const evidenceBrowser = process.argv[2] === "--evidence-ui-browser";
const fieldsOnly = process.argv[2] === "--field-provenance-only";
const root = process.argv[fieldsOnly || investigationBrowser || trafficBrowser || sourceFactsBrowser || evidenceBrowser || consoleBrowser || collectionBrowser ? 3 : 2] || new URL("..", import.meta.url).pathname;
await checkConsoleDOM(root);
await checkCollectionController(root);
await checkInvestigationCore(root);
// Facts are UI projections over the already validated Rust contract. These
// fixtures exercise identity and stale/cancelled request ownership, not JS execution.
const sourceFactsUI = runInNewContext(
  (await readFile(join(root, 'apps/research-ui/source_facts.js'), 'utf8')) +
  ';({sourceFactsFields,sourceFactsIdentity,sourceFactsUnavailable,isSourceFactsReport,sourceFactsPosition,sourceFactsReadBytes,createSourceFactsController})',
  {TextEncoder, TextDecoder, Uint8Array, AbortController, setTimeout, clearTimeout, fetch, crypto},
);
const factsBytes = new TextEncoder().encode('\ufeffconst 雪 = "😀";\n雪++;');
const factsHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', factsBytes)), byte => byte.toString(16).padStart(2, '0')).join('');
const factsArtifact = {source_type:'artifact', protocol_version:1, artifact_id:'7', session_id:'11', navigation_id:'13', frame_id:'17', parent_artifact_id:'0', creator_event_id:'19', execution_context_id:'23', capture_origin:'dynamic_javascript', kind:'javascript', url:'https://fixture.invalid/facts.js', mime_type:'text/javascript', byte_size:factsBytes.length, sha256:factsHash, sensitive:false};
const factsFixture = source => ({schema:'reb-javascript-source-facts-v1', profile:'lexical-effects-v1', offset_unit:'utf-8-byte', source_bytes:source.byte_size, ok:true,
  source:Object.fromEntries(Object.entries(source).filter(([key]) => key !== 'source_type')),
  scopes:[{id:0,parent_id:null,range:{start:0,end:source.byte_size},kind:'program'}], bindings:[], callables:[], regions:[{id:0,parent_id:null,callable_id:null,range:{start:0,end:source.byte_size},kind:'program',entry_order:0}], operations:[],
  coverage:{status:'complete',truncated:false,frontiers:[],diagnostics:[]}, limits:{max_source_bytes:4194304,max_ast_nodes:32768,max_facts:16384,max_frontiers:256,max_binding_candidates:64,preflight_depth:128,preflight_nodes:500000}});
assert.equal(sourceFactsUI.sourceFactsUnavailable(factsArtifact, 'http:'), '');
assert.match(sourceFactsUI.sourceFactsUnavailable(factsArtifact, 'reb:'), /stored-evidence native mode/);
assert.match(sourceFactsUI.sourceFactsUnavailable({...factsArtifact,source_type:'script'}, 'http:'), /captured JavaScript/);
for (const source of [{...factsArtifact,artifact_id:'07'},{...factsArtifact,session_id:'18446744073709551616'},{...factsArtifact,byte_size:4194305}]) assert(sourceFactsUI.sourceFactsUnavailable(source, 'http:'));
const factsReport = factsFixture(factsArtifact);
assert(sourceFactsUI.isSourceFactsReport(factsReport, factsArtifact));
for (const field of Object.keys(factsReport.source)) {
  const foreign = structuredClone(factsReport); foreign.source[field] = null;
  assert.equal(sourceFactsUI.isSourceFactsReport(foreign, factsArtifact), false, field);
}
for (const update of [{offset_unit:'utf-16'}, {source_bytes:0}, {ok:false}, {bindings:Array(16385).fill({})},
  {scopes:[{...factsReport.scopes[0],range:{start:0,end:factsBytes.length+1}}]},
  {scopes:[factsReport.scopes[0],factsReport.scopes[0]]},
  {scopes:[{...factsReport.scopes[0],kind:'executed'}]},
  {coverage:{status:'complete',truncated:true,frontiers:[],diagnostics:[]}},
  {coverage:{status:'partial',truncated:false,frontiers:Array(257).fill({}),diagnostics:[]}}]) {
  assert.equal(sourceFactsUI.isSourceFactsReport({...factsReport,...update}, factsArtifact), false);
}
const partialFacts = {...factsReport, coverage:{status:'partial',truncated:true,frontiers:[{range:{start:0,end:0},reason:'fact-limit'}],diagnostics:['Bounded coverage']}};
assert(sourceFactsUI.isSourceFactsReport(partialFacts, factsArtifact));
const unavailableFacts = {...factsReport,ok:false,scopes:[],regions:[],coverage:{status:'unavailable',truncated:false,frontiers:[],diagnostics:['Malformed source']}};
assert(sourceFactsUI.isSourceFactsReport(unavailableFacts, factsArtifact));
assert.equal(sourceFactsUI.isSourceFactsReport({...unavailableFacts,scopes:factsReport.scopes}, factsArtifact), false);
const snowOffset = new TextEncoder().encode('\ufeffconst ').length;
const snowPosition = sourceFactsUI.sourceFactsPosition(factsBytes,{start:snowOffset,end:snowOffset+3});
assert.equal(snowPosition.line,0); assert.equal(snowPosition.column,7); assert.equal(snowPosition.length,1);
assert.throws(() => sourceFactsUI.sourceFactsPosition(factsBytes,{start:snowOffset+1,end:snowOffset+3}));
assert.equal(sourceFactsUI.sourceFactsPosition(factsBytes,{start:0,end:factsBytes.length}).multiline,true);
assert.equal(sourceFactsUI.sourceFactsPosition(new Uint8Array(),{start:0,end:0}).column,0);
await assert.rejects(sourceFactsUI.sourceFactsReadBytes(new Response(new Uint8Array(5)),4), /byte limit/);
// Response storage owns one bounded byte buffer, never a retained chunk list.
const factsReaderFixture = (read, cancel = async () => {}) => {
  const counts = {reads:0,cancels:0,releases:0};
  return {counts, response:{body:{getReader:()=>({
    read:()=>{counts.reads++;return read(counts.reads);},
    cancel:()=>{counts.cancels++;return cancel();},
    releaseLock:()=>{counts.releases++;},
  })}}};
};
const factsFragmented = (count, width) => factsReaderFixture(async index => index>count
  ? {done:true} : {done:false,value:new Uint8Array(width).fill(index%251)});
for (const [count,width] of [[0,0],[65536,0],[65536,1]]) {
  const fixture=factsFragmented(count,width);
  const result=await sourceFactsUI.sourceFactsReadBytes(fixture.response,count*width);
  assert.equal(result.length,count*width);assert.equal(result.buffer.byteLength,count*width);
  if(width) for(let index=0;index<result.length;index++) assert.equal(result[index],(index+1)%251);
  assert.deepEqual(fixture.counts,{reads:count+1,cancels:0,releases:1});
}
for (const width of [0,1]) {
  const fixture=factsFragmented(65537,width);
  await assert.rejects(sourceFactsUI.sourceFactsReadBytes(fixture.response,65537),/stream chunk limit/);
  assert.deepEqual(fixture.counts,{reads:65537,cancels:1,releases:1});
}
const oversizedFacts=factsFragmented(1,5);
await assert.rejects(sourceFactsUI.sourceFactsReadBytes(oversizedFacts.response,4),/byte limit/);
assert.deepEqual(oversizedFacts.counts,{reads:1,cancels:1,releases:1});
const nonbyteFacts=factsReaderFixture(async()=>({done:false,value:[1]}));
await assert.rejects(sourceFactsUI.sourceFactsReadBytes(nonbyteFacts.response,4),/non-byte chunk/);
assert.equal(nonbyteFacts.counts.cancels,1);assert.equal(nonbyteFacts.counts.releases,1);
const reusedFactsChunk=new Uint8Array(1024*1024);
const aliasedFacts=factsReaderFixture(async index=>{
  if(index>factsBytes.length)return {done:true};
  reusedFactsChunk[17]=factsBytes[index-1];
  return {done:false,value:reusedFactsChunk.subarray(17,18)};
});
const ownedFactsBytes=await sourceFactsUI.sourceFactsReadBytes(aliasedFacts.response,factsBytes.length);
assert.deepEqual(ownedFactsBytes,factsBytes,'Copy each fragmented UTF-8/BOM byte before its producer reuses the backing store');
assert.equal(ownedFactsBytes.buffer.byteLength,factsBytes.length);
assert.notEqual(ownedFactsBytes.buffer,reusedFactsChunk.buffer);
const cancelledFactsSignal=new AbortController();cancelledFactsSignal.abort();
const preCancelledFacts=factsFragmented(1,1);
await assert.rejects(sourceFactsUI.sourceFactsReadBytes(preCancelledFacts.response,1,cancelledFactsSignal.signal),/cancelled/);
assert.deepEqual(preCancelledFacts.counts,{reads:0,cancels:1,releases:1});
const fragmentedFactsSignal=new AbortController();
const interruptibleFacts=factsFragmented(65537,1);
const interruptFactsTimer=setTimeout(()=>fragmentedFactsSignal.abort(),0);
try {
  await assert.rejects(sourceFactsUI.sourceFactsReadBytes(interruptibleFacts.response,65537,fragmentedFactsSignal.signal),/cancelled/);
} finally {clearTimeout(interruptFactsTimer);}
assert(interruptibleFacts.counts.reads<=256,'Fragmented streams must yield to cancellation/deadline tasks');
assert.equal(interruptibleFacts.counts.cancels,1);assert.equal(interruptibleFacts.counts.releases,1);
const stalledFactsSignal=new AbortController();let stalledFactsCancelled=0;
const stalledFactsResponse=new Response(new ReadableStream({cancel(){stalledFactsCancelled++;return new Promise(()=>{});}}));
const stalledFactsRead=sourceFactsUI.sourceFactsReadBytes(stalledFactsResponse,4,stalledFactsSignal.signal);
stalledFactsSignal.abort();
let stalledFactsWatchdog;
try {
  await assert.rejects(Promise.race([stalledFactsRead,new Promise((_,reject)=>{stalledFactsWatchdog=setTimeout(()=>reject(new Error('Stalled reader did not cancel promptly')),1000);})]),/cancelled/);
} finally {clearTimeout(stalledFactsWatchdog);}
assert.equal(stalledFactsCancelled,1);assert.equal(stalledFactsResponse.body.locked,false);
console.log('PASS Sources owned response bytes, exact byte/chunk limits, empty/fragmented/aliased streams and cancellation despite stalled producer cleanup');
let selectedFactsArtifact = factsArtifact;
let factsPending = [];
let factsNavigations = [];
const factsController = sourceFactsUI.createSourceFactsController({getSource:()=>selectedFactsArtifact,protocol:'http:',onChange:()=>{},onNavigate:(...args)=>factsNavigations.push(args),cryptoApi:crypto,
  fetcher:(url,options)=>new Promise(resolve=>factsPending.push({url,options,resolve}))});
const deliverFacts = (entry, source = selectedFactsArtifact) => entry.resolve(Response.json(factsFixture(source)));
factsController.sync(selectedFactsArtifact);
const firstFactsLoad = factsController.load();
assert.equal(factsPending.length,1); assert.match(factsPending[0].url,/session_id=11&artifact_id=7$/);
await factsController.load(); assert.equal(factsPending.length,1,'Repeated load shares one in-flight request');
factsController.cancel(); assert.equal(factsPending[0].options.signal.aborted,true);
const secondFactsLoad = factsController.load();
deliverFacts(factsPending[1]); await secondFactsLoad;
const retainedFactsReport = factsController.model.report;
deliverFacts(factsPending[0]); await firstFactsLoad;
assert.equal(factsController.model.report,retainedFactsReport,'A cancelled older response cannot replace current facts');
const staleFactsLoad = factsController.load();
selectedFactsArtifact = {...factsArtifact,session_id:'12'}; factsController.sync(selectedFactsArtifact);
deliverFacts(factsPending[2],factsArtifact); await staleFactsLoad;
assert.equal(factsController.model.report,null,'Switching source clears facts and rejects delayed responses');
selectedFactsArtifact = factsArtifact; factsController.sync(selectedFactsArtifact);
const matchingFactsLoad = factsController.load(); deliverFacts(factsPending[3]); await matchingFactsLoad;
const nav = factsController.navigate({start:snowOffset,end:snowOffset+3});
assert.match(factsPending[4].url,/artifact[s]\/7\/content\?offset=0&limit=2097152$/);
factsPending[4].resolve(new Response(factsBytes,{headers:{'X-Artifact-Total-Bytes':String(factsBytes.length),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}})); await nav;
assert.equal(factsNavigations.length,1); assert.equal(factsNavigations[0][2].column,7);
assert.equal(factsController.original(factsArtifact),'\ufeffconst 雪 = "😀";\n雪++;');
await factsController.navigate({start:0,end:0}); assert.equal(factsPending.length,5,'Repeated navigation reuses verified original bytes');
selectedFactsArtifact = {...factsArtifact,sha256:'b'.repeat(64)}; factsController.sync(selectedFactsArtifact);
assert.equal(factsController.original(selectedFactsArtifact),undefined,'Changed hash invalidates original bytes');
const mismatchedFactsLoad = factsController.load(); deliverFacts(factsPending[5],factsArtifact); await mismatchedFactsLoad;
assert.equal(factsController.model.status,'error'); assert.equal(factsController.model.report,null);
for (const body of [new Response(factsBytes,{headers:{'X-Artifact-Truncated':'1'}}),new Response(new Uint8Array(factsBytes.length),{headers:{'X-Artifact-Total-Bytes':String(factsBytes.length),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}})]) {
  const attempt = factsController.navigate({start:0,end:0}); factsPending.at(-1).resolve(body); await attempt;
  assert.equal(factsController.model.status,'error'); assert.equal(factsController.original(selectedFactsArtifact),undefined);
}
selectedFactsArtifact = factsArtifact;
let timeoutNavigations = 0;
const slowFacts = sourceFactsUI.createSourceFactsController({getSource:()=>selectedFactsArtifact,protocol:'http:',deadline:5,onChange:()=>{},onNavigate:()=>timeoutNavigations++,cryptoApi:crypto,
  fetcher:async(_url,{signal})=>new Response(new ReadableStream({start(stream){signal.addEventListener('abort',()=>stream.error(new DOMException('Aborted','AbortError')),{once:true});}}))});
await slowFacts.load(); assert.match(slowFacts.model.error,/timed out/); assert.equal(timeoutNavigations,0);
assert.equal(slowFacts.model.report,null);
for (const mode of ['facts','source']) {
  let cancelledBody=0, bodyChunks=0;
  const fragmentedController=sourceFactsUI.createSourceFactsController({getSource:()=>factsArtifact,protocol:'http:',deadline:5,onChange:()=>{},onNavigate:()=>{throw new Error('Timed-out fragmented source navigated');},cryptoApi:crypto,
    fetcher:async()=>new Response(new ReadableStream({
      pull(stream){bodyChunks++;stream.enqueue(new Uint8Array());},
      cancel(){cancelledBody++;return new Promise(()=>{});},
    }),{headers:{'X-Artifact-Total-Bytes':String(factsBytes.length),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}})});
  const operation=mode==='facts'?fragmentedController.load():fragmentedController.navigate({start:0,end:0});
  let watchdog;
  try {
    await Promise.race([operation,new Promise((_,reject)=>{watchdog=setTimeout(()=>reject(new Error('Fragmented controller deadline stalled')),2000);})]);
  } finally {clearTimeout(watchdog);}
  assert.match(fragmentedController.model.error,/timed out/);assert.equal(fragmentedController.model.status,'error');
  assert.equal(fragmentedController.model.report,null);assert.equal(fragmentedController.model.original,null);
  assert.equal(cancelledBody,1);assert(bodyChunks<65536,'Body deadlines must run before exhausting the chunk budget');
}
let finishFactsDigest, factsDigestArrived, factsDigestTimedOut;
const digestArrival = new Promise(resolve=>{factsDigestArrived=resolve;});
const digestTimeout = new Promise(resolve=>{factsDigestTimedOut=resolve;});
const digestFacts = sourceFactsUI.createSourceFactsController({getSource:()=>factsArtifact,protocol:'http:',deadline:100,onChange:model=>{if(model.status==='error') factsDigestTimedOut();},onNavigate:()=>{throw new Error('Late digest navigated');},
  cryptoApi:{subtle:{digest:()=>new Promise(resolve=>{finishFactsDigest=resolve;factsDigestArrived();})}},
  fetcher:async()=>new Response(factsBytes,{headers:{'X-Artifact-Total-Bytes':String(factsBytes.length),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}})});
const digestNavigation = digestFacts.navigate({start:0,end:0});
let digestWatchdog;
try { await Promise.race([Promise.all([digestArrival,digestTimeout]),new Promise((_,reject)=>{digestWatchdog=setTimeout(()=>reject(new Error('Digest timeout fixture did not reach both states')),2000);})]); }
finally { clearTimeout(digestWatchdog); }
assert.equal(digestFacts.model.status,'error','Deadline ends busy state while non-abortable digest is pending');
assert.match(digestFacts.model.error,/timed out/);
finishFactsDigest(await crypto.subtle.digest('SHA-256',factsBytes)); await digestNavigation;
assert.equal(digestFacts.model.status,'error'); assert.equal(digestFacts.model.original,null);
console.log('PASS Sources facts identity, UTF-8/BOM ranges, bounded streams, repeated loads, cancellation, stale responses, hash checks and timeout');

// Native capabilities must not depend on callers remembering a URL flag.
// Execute the actual JS consumer; Swift normalization itself is tested by the
// compiled app during macOS app-build, not by a JS translation here.
const nativeStateMarker=(await readFile(join(root,'apps/research-ui/app_state.js'),'utf8')).split('\n')[0];
for(const [search,expected] of [['',false],['?x=a%2Bb&x=c%26d',false],['?native=1',true],['?native=0&native=2',true],['?%6Eative=1',true],['?Native=1',false]]){
  let native=false;runInNewContext(nativeStateMarker,{location:{search},URLSearchParams,document:{documentElement:{classList:{add(name){assert.equal(name,'native-shell');native=true;}}}}});assert.equal(native,expected);
}
const nativeAppSource=await readFile(join(root,'apps/research-ui/macos/OriginTraceApp.swift'),'utf8');
assert.match(nativeAppSource,/return nativeUIURL\(arguments\[urlFlag \+ 1\]\)/);
assert.match(nativeAppSource,/let nativeURL = nativeUIURL\(liveURL\.absoluteString\)/);
assert.match(nativeAppSource,/webView\.load\(URLRequest\(url: nativeURL\)\)/);
assert.match(nativeAppSource,/webView\.load\(URLRequest\(url: requestedUIURL \?\? localApplicationURL\)\)/);
assert.match(nativeAppSource,/webView\.load\(URLRequest\(url: localApplicationURL\)\)/);
assert.match(nativeAppSource,/self\.localApplicationURL = localApplicationURL/);
assert.match(nativeAppSource,/URL\(string: "reb:\/\/app\/index\.html\?native=1"\)/);
assert.equal((nativeAppSource.match(/webView\.load\(URLRequest\(url:/g)??[]).length,3,'Review every new native entry path');
assert.match(nativeAppSource,/components\.percentEncodedQuery = \(retained \+ \["native=1"\]\)\.joined/);
assert.match(nativeAppSource,/name\.removingPercentEncoding != "native"/);
assert.match(nativeAppSource,/contains\("--check-native-ui-url"\) \{\s+checkNativeUIURLs\(\)\s+return/);
assert.match(await readFile(join(root,'scripts/build-research-app.sh'),'utf8'),/"\$\{macos_path\}\/OriginTrace" --check-native-ui-url/);
console.log('PASS native entry-path wiring and actual JS query consumer (Swift helper execution requires macOS app-build)');

// Exact-byte package workflow: the real HTTP validator remains authoritative.
const packageUI = runInNewContext(
  (await readFile(join(root, 'apps/research-ui/evidence_package.js'), 'utf8')) +
  ';({evidencePackageKey,evidencePackageKeyText,evidencePackageSelectionKey,evidencePackageUnavailable,evidencePackageReadBytes,evidencePackageValidationResult,evidencePackageView,createEvidencePackageController})',
  {TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout,clearTimeout,fetch},
);
const packageGoldenBytes = new Uint8Array(await readFile(join(root,'apps/origin-trace-backend/assets/evidence-packages/golden-v1.json')));
const packageGolden = JSON.parse(new TextDecoder().decode(packageGoldenBytes));
const packageValid = {protocol_version:1,status:'valid',package_id:packageGolden.package_id,origin:'untrusted_input',authenticity:'not_established',artifact_bytes:'not_present_not_reverified',
  checks:{structure:'passed',semantic_digest:'passed',references:'passed',metadata_profile:'passed'},issues:[],issues_truncated:false};
const packageInvalid = {...packageValid,status:'invalid',package_id:null,checks:{...packageValid.checks,structure:'failed'},issues:[{code:'duplicate_json_key',section:'document',index:null}]};
assert(packageUI.evidencePackageValidationResult(packageValid));
for (const value of [{...packageValid,authenticity:'verified'}, {...packageValid,artifact_bytes:'verified'}, {...packageValid,checks:{...packageValid.checks,references:'not_run'}},
  {...packageValid,issues:packageInvalid.issues}, {...packageValid,package_id:null}, {...packageValid,issues_truncated:true}]) assert.equal(packageUI.evidencePackageValidationResult(value),false);
assert.equal(packageUI.evidencePackageKey('event',{session_id:'18446744073709551615',process_id:4294967295,sequence_number:'18446744073709551615'}).sequence_number,'18446744073709551615');
for (const key of [{session_id:7,process_id:42,sequence_number:'1'}, {session_id:'07',process_id:42,sequence_number:'1'}, {session_id:'7',process_id:0,sequence_number:'1'},
  {session_id:'7',process_id:42,sequence_number:'18446744073709551616'}, {session_id:'7',process_id:42,sequence_number:'0'}]) assert.equal(packageUI.evidencePackageKey('event',key),null);
assert.equal(packageUI.evidencePackageKey('artifact',{session_id:'7',artifact_id:'9',payload:'secret'}).payload,undefined);
assert.notEqual(packageUI.evidencePackageKeyText('event',{session_id:'7',process_id:42,sequence_number:'1'}),packageUI.evidencePackageKeyText('event',{session_id:'8',process_id:42,sequence_number:'1'}));
assert.match(packageUI.evidencePackageUnavailable('reb:'),/stored-evidence native mode/);
assert.match(packageUI.evidencePackageUnavailable('file:'),/browser development UI/);
assert.equal(packageUI.evidencePackageUnavailable('http:'),'');
assert.equal(packageUI.evidencePackageView(packageGolden,packageValid).package_id,packageValid.package_id);
assert.throws(()=>packageUI.evidencePackageView({...packageGolden,package_id:'different'},packageValid));
await assert.rejects(packageUI.evidencePackageReadBytes(new Response(new Uint8Array(5)),4),/byte limit/);
// Transport fragmentation cannot create an unbounded retained chunk array.
let fragmentIndex=0;
const fragmented=new Response(new ReadableStream({pull(stream){if(fragmentIndex===8192)stream.close();else stream.enqueue(new Uint8Array([fragmentIndex++%251]));}}));
const fragmentedBytes=await packageUI.evidencePackageReadBytes(fragmented,8192);
assert.equal(fragmentedBytes.length,8192);assert.equal(fragmentedBytes.buffer.byteLength,8192);
assert(fragmentedBytes.every((byte,index)=>byte===index%251));
let fragmentedCancelled=false;
await assert.rejects(packageUI.evidencePackageReadBytes(new Response(new ReadableStream({pull(stream){stream.enqueue(new Uint8Array());},cancel(){fragmentedCancelled=true;}})),4),/transport chunk limit/);
assert.equal(fragmentedCancelled,true);
// Real streams close pending reads before their producer's cancellation cleanup
// settles; a never-settling cancel hook must not defeat limits or UI deadlines.
const packageWithinDeadline=async promise=>{let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Package reader did not retire within the fixture deadline')),2000);})]);}finally{clearTimeout(timer);}};
for(const empty of [false,true]){
  let cancelled=0;
  const response=new Response(new ReadableStream({pull(stream){stream.enqueue(new Uint8Array(empty?0:5));},cancel(){cancelled++;return new Promise(()=>{});}}));
  await packageWithinDeadline(assert.rejects(packageUI.evidencePackageReadBytes(response,4),empty?/transport chunk limit/:/byte limit/));
  assert.equal(cancelled,1);assert.equal(response.body.locked,false);
}
const packageAbort=new AbortController();let cancelledPending=0;
const pendingBody=new Response(new ReadableStream({cancel(){cancelledPending++;return new Promise(()=>{});}}));
const pendingRead=packageUI.evidencePackageReadBytes(pendingBody,4,packageAbort.signal);
packageAbort.abort();await packageWithinDeadline(assert.rejects(pendingRead,/cancelled/));assert.equal(cancelledPending,1);assert.equal(pendingBody.body.locked,false);
const packageSharedChunk=new Uint8Array(1024*1024);let packageSharedIndex=0;
const sharedResponse=new Response(new ReadableStream({pull(stream){if(packageSharedIndex===16)stream.close();else{packageSharedChunk[17]=packageSharedIndex++;stream.enqueue(packageSharedChunk.subarray(17,18));}}},{highWaterMark:0}));
const sharedBytes=await packageUI.evidencePackageReadBytes(sharedResponse,16);assert.deepEqual([...sharedBytes],Array.from({length:16},(_,i)=>i));assert.equal(sharedBytes.buffer.byteLength,16);
for(const width of [0,1,64]) {
  let fragmentedTimeoutCancels=0;
  const fragmentDeadline=packageUI.createEvidencePackageController({getSelection:()=>packageGolden.selection,protocol:'http:',onChange:()=>{},deadline:5,
    fetcher:async()=>new Response(new ReadableStream({pull(stream){stream.enqueue(new Uint8Array(width));},cancel(){fragmentedTimeoutCancels++;return new Promise(()=>{});}}))});
  await packageWithinDeadline(fragmentDeadline.export());assert.equal(fragmentDeadline.model.status,'error');assert.match(fragmentDeadline.model.message,/timed out/);assert.equal(fragmentedTimeoutCancels,1);
}
const packageRequests=[];
let packageSelection=structuredClone(packageGolden.selection);
const packageController=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:async(url,options)=>{
  packageRequests.push({url,options}); return url.endsWith('/export') ? new Response(packageGoldenBytes) : Response.json(packageValid);
}});
await packageController.export();
assert.equal(packageRequests.length,2);
assert.equal(packageRequests[0].url,'/api/evidence/packages/export');
assert.equal(packageRequests[1].url,'/api/evidence/packages/validate');
assert.deepEqual(JSON.parse(new TextDecoder().decode(packageRequests[0].options.body)),{protocol_version:1,profile:'reb-metadata-only-v1',selection:packageSelection});
assert.deepEqual(packageRequests[1].options.body,packageGoldenBytes,'Export validation must preserve exact bytes');
assert.equal(packageController.model.status,'ready');
assert.deepEqual(packageController.model.bytes,packageGoldenBytes);
packageController.clear(); assert.equal(packageController.model.bytes,null);
// Duplicate members, invalid UTF-8, whitespace and BOM survive the client boundary.
for (const bytes of [new TextEncoder().encode('{"format":"a","format":"b"}'),new Uint8Array([0xef,0xbb,0xbf,0x7b,0xff,0x7d]),new TextEncoder().encode('  {"x":1}\n')]) {
  let received;
  const control=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:async(url,options)=>{
    assert.equal(url,'/api/evidence/packages/validate'); received=options.body; return Response.json(packageInvalid);
  }});
  await control.validate({size:bytes.length,arrayBuffer:async()=>bytes.buffer});
  assert.deepEqual(received,bytes,'Never parse or reserialize input before server validation');
  assert.equal(control.model.status,'invalid'); assert.equal(control.model.bytes,null); assert.equal(control.model.document,null);
}
let packagePending=[];
const delayedPackage=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:(url,options)=>new Promise(resolve=>packagePending.push({url,options,resolve}))});
const packageFirst=delayedPackage.export(); await delayedPackage.export(); assert.equal(packagePending.length,1,'Double export starts only one operation');
delayedPackage.cancel(); assert.equal(packagePending[0].options.signal.aborted,true);
packagePending[0].resolve(new Response(packageGoldenBytes)); await packageFirst;
assert.equal(packagePending.length,1,'Cancelled export cannot begin validation'); assert.equal(delayedPackage.model.document,null);
const packageSecond=delayedPackage.export(); packagePending[1].resolve(new Response(packageGoldenBytes));
while(packagePending.length<3) await new Promise(resolve=>setTimeout(resolve,0));
delayedPackage.clear(); packagePending[2].resolve(Response.json(packageValid)); await packageSecond;
assert.equal(delayedPackage.model.bytes,null,'Changed selection/close cannot accept delayed validation');
let packageFileResolve;
const packageSlowFile=delayedPackage.validate({size:packageGoldenBytes.length,arrayBuffer:()=>new Promise(resolve=>{packageFileResolve=resolve;})});
delayedPackage.cancel(); packageFileResolve(packageGoldenBytes.buffer); await packageSlowFile;
assert.equal(packagePending.length,3,'A cancelled file read cannot send a request');
for (const status of [400,404,408,409,413,422,503]) {
  let calls=0;
  const rejected=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:async()=>{calls++;return new Response('{}',{status});}});
  await rejected.export(); assert.equal(calls,1,'Rejected export must not auto-retry or validate'); assert.equal(rejected.model.status,'error'); assert.equal(rejected.model.bytes,null);
  if(status===409) assert.match(rejected.model.message,/No writer was stopped/);
  if(status===503) assert.match(rejected.model.message,/legacy stores are unsupported/);
}
const packageOffline=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'reb:',onChange:()=>{},fetcher:()=>{throw new Error('Offline must not fetch');}});
await packageOffline.export(); assert.equal(packageOffline.model.status,'error');
let oversizedRead=false;
await packageController.validate({size:4194305,arrayBuffer:async()=>{oversizedRead=true;return new ArrayBuffer(0);}});
assert.equal(oversizedRead,false,'File size checked before allocation/read');
const packageWrongSelection=packageUI.createEvidencePackageController({getSelection:()=>({events:packageSelection.events.slice(0,1),artifacts:[]}),protocol:'http:',onChange:()=>{},
  fetcher:async url=>url.endsWith('/export')?new Response(packageGoldenBytes):Response.json(packageValid)});
await packageWrongSelection.export(); assert.equal(packageWrongSelection.model.status,'error'); assert.equal(packageWrongSelection.model.bytes,null);
let packageTimeoutChanges=0;
const packageSlow=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',deadline:5,onChange:()=>packageTimeoutChanges++,
  fetcher:async(_url,{signal})=>new Response(new ReadableStream({start(stream){signal.addEventListener('abort',()=>stream.error(new DOMException('Aborted','AbortError')),{once:true});}}))});
await packageSlow.export(); assert.equal(packageSlow.model.status,'error'); assert.match(packageSlow.model.message,/timed out/); assert.equal(packageSlow.model.bytes,null); assert(packageTimeoutChanges>=2);
console.log('Evidence package exact-byte, selection, bounds and interruption contracts passed');
// Canonical backend JSON sorts object members; identity is order-independent.
const reorderedPackage = structuredClone(packageGolden);
for (const kind of ['events', 'artifacts']) {
  reorderedPackage.selection[kind] = reorderedPackage.selection[kind].map(key => Object.fromEntries(Object.entries(key).sort())).reverse();
}
assert.equal(packageUI.evidencePackageSelectionKey(reorderedPackage.selection), packageUI.evidencePackageSelectionKey(packageGolden.selection));
const orderedBytes = new TextEncoder().encode(JSON.stringify(reorderedPackage));
const orderedControl = packageUI.createEvidencePackageController({getSelection:()=>packageGolden.selection,protocol:'http:',onChange:()=>{},
  fetcher:async url=>url.endsWith('/export')?new Response(orderedBytes):Response.json(packageValid)});
await orderedControl.export(); assert.equal(orderedControl.model.status,'ready'); assert.deepEqual(orderedControl.model.bytes,orderedBytes);
await orderedControl.validate({size:4194305}); assert.equal(orderedControl.model.bytes,null,'An invalid new file cannot leave an older package downloadable');
let selectionReply;
const changingControl = packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},
  fetcher:()=>new Promise(resolve=>{selectionReply=resolve;})});
const changedSelectionRun = changingControl.export(); packageSelection = {events:[],artifacts:[]};
selectionReply(new Response(packageGoldenBytes)); await changedSelectionRun;
assert.equal(changingControl.model.bytes,null); assert.equal(changingControl.model.status,'idle');
packageSelection = structuredClone(packageGolden.selection);
let timeoutFileResolve, timeoutFileCalls = 0;
const timeoutFile = packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',deadline:5,onChange:()=>{},fetcher:()=>{timeoutFileCalls++;}});
const timeoutFileRun = timeoutFile.validate({size:packageGoldenBytes.length,arrayBuffer:()=>new Promise(resolve=>{timeoutFileResolve=resolve;})});
await new Promise(resolve=>setTimeout(resolve,15)); assert.equal(timeoutFile.model.status,'error');
timeoutFileResolve(packageGoldenBytes.buffer); await timeoutFileRun;
assert.equal(timeoutFileCalls,0,'A file read completing after timeout cannot send original bytes');
for (const status of ['invalid','unsupported']) {
  const control=packageUI.createEvidencePackageController({getSelection:()=>packageSelection,protocol:'http:',onChange:()=>{},fetcher:async()=>Response.json({...packageInvalid,status})});
  await control.validate({size:packageGoldenBytes.length,arrayBuffer:async()=>packageGoldenBytes.buffer});
  assert.equal(control.model.status,status); assert.equal(control.model.bytes,null);
}
console.log('PASS package canonical-key order, direct stale selection, unsupported response and non-abortable file deadline');


const complete = runInNewContext(
  (await readFile(join(root, "apps/research-ui/source_syntax.js"), "utf8")) +
    (await readFile(join(root, "apps/research-ui/native_console_completion.js"), "utf8")) +
    ";nativeConsoleSuggestions",
);
const suggestions = text => complete(text, text.length)?.items.map(item => item.name) ?? [];
assert.deepEqual(Array.from(suggestions("document.que")), ["querySelector", "querySelectorAll"]);
for (const text of ["document.querySelector", "document.querySelectorAll", "window", "Math.log", "document.body"]) {
  assert.equal(complete(text, text.length), null, text);
  assert.equal(complete(text, text.length, true).items[0].name, text.split(".").at(-1), text);
}
const longerIdentifier = "document.querySelectorAll";
assert.ok(complete(longerIdentifier, "document.querySelector".length).items.some(item => item.name === "querySelector"));
assert.ok(suggestions('window.document.querySelector("main").classList.').includes("toggle"));
assert.ok(suggestions('document.querySelector(document.querySelector("a")).sty').includes("style"));
assert.ok(suggestions("window?.navigator.clipboard.re").includes("readText"));
assert.ok(suggestions("new Map().").includes("get"));
assert.ok(suggestions("[1, 2].ma").includes("map"));
assert.ok(suggestions('"snow 雪".toU').includes("toUpperCase"));
assert.ok(suggestions("Promise.resolve(1).th").includes("then"));
for (const text of ['"document.que', "'document.que", "`document.que", "// document.que", "/* document.que", "/document.que", "const pattern = /document.que", "customPageObject.", "window[pageGetter()]."]) {
  assert.equal(complete(text, text.length), null, text);
}
assert.ok(suggestions("/* inert */ document.que").includes("querySelector"));
assert.ok(suggestions("// inert\nMath.ra").includes("random"));
const middle = complete('"雪"; document.querySelectorAll("main")', 19);
assert.equal(middle.start, 14);
assert.equal(middle.end, 30);
assert.ok(middle.items.some(item => item.name === "querySelector"));
assert.equal(complete("a".repeat(8193), 8193), null);
assert.ok(complete("", 0, true).items.length <= 24);
assert.equal(complete("document.", -1), null);
const completionQuery = runInNewContext(
  (await readFile(join(root, "apps/research-ui/source_syntax.js"), "utf8")) +
  (await readFile(join(root, "apps/research-ui/native_console_completion.js"), "utf8")) +
  ";nativeConsoleCompletionQuery",
);
assert.deepEqual(Array.from(completionQuery("customPageObject.method", 23).path), ["customPageObject"]);
for (const text of ['"customPageObject.', "// obj.", "/* obj.", "/obj.", "const pattern = /obj.", "obj[pageGetter()].", "obj.method()."]) assert.equal(completionQuery(text, text.length), null, text);
assert.equal(completionQuery("a".repeat(8193), 8193), null);
assert.equal(completionQuery("window.", -1), null);
assert.equal(completionQuery("a".repeat(129) + ".", 130), null);
console.log("PASS bounded local console completions, lexical exclusions, property chains and UTF-16 replacement");
const ui = runInNewContext(
  (await readFile(join(root, "apps/research-ui/evidence_models.js"), "utf8")) +
    ";({isDebuggerResponse,isRequestInterception,isActionScope,isObjectExperiment,isRuntimeHooks,isAutomationRecipes,isRepeater,isWasmInspection})",
  { TextEncoder, URL },
);
// Reject foreign, malformed and unbounded binary listings before rendering them.
const wasmSource = {artifact_id: "1", sha256: "a".repeat(64), byte_size: 32};
const wasmReport = {schema: "wasm-inspection-v1", ...wasmSource, status: "decoded",
  sections: 1, defined_functions: 1, imported_functions: 0, instructions: 1,
  notice: "Static only", omissions: [], rows: [{kind: "instruction", byte_offset: 12,
    byte_end: 14, function_index: 0, text: "i32.const {value: 7}", text_truncated: false}]};
assert.equal(ui.isWasmInspection(wasmReport, wasmSource), true);
for (const patch of [{sha256: "b".repeat(64)}, {artifact_id: "2"}, {byte_size: 33},
  {status: "confirmed"}, {rows: Array(8193).fill(wasmReport.rows[0])},
  {rows: [{...wasmReport.rows[0], byte_end: 33}]},
  {rows: [{...wasmReport.rows[0], byte_offset: -1}]},
  {rows: [{...wasmReport.rows[0], text: "x".repeat(541)}]},
  {rows: [{...wasmReport.rows[0], text: "import e\nv"}]},
  {rows: [{...wasmReport.rows[0], text: "import e\rv"}]},
  {rows: [{...wasmReport.rows[0], text: "import e\u2028v"}]},
  {rows: [{...wasmReport.rows[0], text: "import e\u2029v"}]},
  {omissions: [null]}, {instructions: NaN}]) {
  assert.equal(ui.isWasmInspection({...wasmReport, ...patch}, wasmSource), false);
}
console.log("PASS WASM inspection identity, coordinate and resource bounds");
// Count the expensive operations deterministically instead of setting timing
// thresholds that depend on the host. These fixtures never contact a browser.
let networkUrlCalls = 0;
let networkBodyDecodes = 0;
const networkModels = runInNewContext(
  (await readFile(join(root, "apps/research-ui/evidence_models.js"), "utf8")) +
  (await readFile(join(root, "apps/research-ui/traffic_view.js"), "utf8")) +
  ";({requestsFromDebuggerNetwork,isDebuggerNetwork,trafficSearchRequests})",
  {TextEncoder, TextDecoder, Uint8Array,
    URL: class extends URL {constructor(...args) {networkUrlCalls += 1; super(...args);}},
    atob(value) {networkBodyDecodes += 1; return atob(value);}},
);
const emptyNetworkBody = () => ({state: "empty", mime: "", text: "", base64: "", truncated: false, reason: ""});
const networkRecord = (id, patch = {}) => ({
  id, protocol_request_id: id, target_id: "target", target_title: "Fixture",
  url: "http://fixture.invalid/path", url_truncated: false, method: "GET", method_truncated: false,
  resource_type: "Fetch", document_url: "http://fixture.invalid/", started_monotonic_ms: 100,
  wall_time_ms: 100, state: "complete", status: 200, status_text: "OK", protocol: "HTTP/1.1",
  mime_type: "text/plain", duration_ms: 1, encoded_data_length: 0,
  from_disk_cache: false, from_service_worker: false, error_text: "",
  request: {headers: [], body: emptyNetworkBody()}, response: {headers: [], body: emptyNetworkBody()}, ...patch,
});
const networkSnapshot = requests => ({capture_enabled: true, target_id: "target", requests, dropped: 0,
  limits: {requests: 1000, body_bytes: 128 * 1024, headers: 128, header_bytes: 64 * 1024}});
const nativeRequest = (id, time, path = "fixture.invalid", method = "GET") => ({
  id, path, method, firstTimestamp: BigInt(time) * 1_000_000n, event: {id}, events: [{id}],
});
// The reference intentionally uses the old stable-sort selection, including
// native order for equal distances and the inclusive ten-second cutoff.
function referenceNativeIds(records, native) {
  const claimed = new Set();
  return records.map(record => {
    const host = new URL(record.url).host;
    const match = native.filter(candidate => {
      let domain;
      try {domain = new URL(candidate.path).host;} catch {domain = candidate.path.replace(/^\/\//, "").split("/")[0];}
      return !claimed.has(candidate.id) && candidate.method === record.method && domain === host;
    }).sort((left, right) => Math.abs(Number(left.firstTimestamp) / 1e6 - record.started_monotonic_ms) -
      Math.abs(Number(right.firstTimestamp) / 1e6 - record.started_monotonic_ms))[0];
    if (!match || Math.abs(Number(match.firstTimestamp) / 1e6 - record.started_monotonic_ms) > 10_000) return null;
    claimed.add(match.id);
    return match.id;
  });
}
const correlationNative = [nativeRequest("tie-first", 110), nativeRequest("tie-second", 90),
  nativeRequest("post", 100, "fixture.invalid", "POST"), nativeRequest("other-host", 100, "other.invalid")];
const correlationRecords = [networkRecord("first"), networkRecord("second"), networkRecord("third"),
  networkRecord("post", {method: "POST"}), networkRecord("other", {url: "http://other.invalid/redirect"})];
const nativeIds = (records, native) => Array.from(networkModels.requestsFromDebuggerNetwork(networkSnapshot(records), native), request => request.event?.id ?? null);
assert.deepEqual(nativeIds(correlationRecords, correlationNative), ["tie-first", "tie-second", null, "post", "other-host"]);
assert.deepEqual(nativeIds([networkRecord("limit", {started_monotonic_ms: 10_100}), networkRecord("past", {started_monotonic_ms: 10_100.001})],
  [nativeRequest("one", 100), nativeRequest("two", 100)]), ["one", null]);
const variedNative = Array.from({length: 250}, (_, i) => nativeRequest(`native-${i}`, i * 7,
  `${i % 2 ? "http://" : ""}host-${i % 9}.invalid`, i % 3 ? "GET" : "POST"));
const variedRecords = Array.from({length: 125}, (_, i) => networkRecord(`cdp-${i}`, {
  url: `http://host-${i % 11}.invalid/path`, method: i % 4 ? "GET" : "POST", started_monotonic_ms: i * 13,
}));
assert.deepEqual(nativeIds(variedRecords, variedNative), referenceNativeIds(variedRecords, variedNative));
const beforeNative = structuredClone(variedNative);
const beforeRecords = structuredClone(variedRecords);
nativeIds(variedRecords, variedNative);
assert.deepEqual(variedNative, beforeNative);
assert.deepEqual(variedRecords, beforeRecords);
const unmatchedNative = Array.from({length: 1000}, (_, i) => nativeRequest(`native-${i}`, i, `http://native-${i % 50}.invalid`));
const unmatchedRecords = Array.from({length: 500}, (_, i) => networkRecord(`cdp-${i}`, {url: `http://other-${i % 50}.invalid/path`}));
networkUrlCalls = 0;
assert(nativeIds(unmatchedRecords, unmatchedNative).every(id => id === null));
assert.equal(networkUrlCalls, 1500);

const binaryBody = text => ({...emptyNetworkBody(), state: "available", mime: "text/plain",
  base64: Buffer.from(text).toString("base64")});
const binaryNetwork = networkSnapshot([networkRecord("binary", {
  request: {headers: [["authorization", "<redacted>"]], body: binaryBody("request text")},
  response: {headers: [["content-type", "text/plain"]], body: binaryBody("response marker")},
})]);
assert.equal(networkModels.isDebuggerNetwork(binaryNetwork), true);
const binaryOriginal = structuredClone(binaryNetwork);
const bodyCache = new Map();
networkBodyDecodes = 0;
let projected = networkModels.requestsFromDebuggerNetwork(binaryNetwork, [], bodyCache);
assert.equal(networkBodyDecodes, 2);
const firstRequestBytes = projected[0].exchange.request.bytes;
const firstResponseBytes = projected[0].exchange.response.bytes;
const repeatedNetwork = structuredClone(binaryNetwork);
repeatedNetwork.requests[0].response.headers.push(["x-new-header", "latest"]);
repeatedNetwork.requests[0].response.body.truncated = true;
projected = networkModels.requestsFromDebuggerNetwork(repeatedNetwork, [nativeRequest("arrived", 100)], bodyCache);
assert.equal(networkBodyDecodes, 2);
assert.equal(projected[0].exchange.request.bytes, firstRequestBytes);
assert.equal(projected[0].exchange.response.bytes, firstResponseBytes);
assert.equal(projected[0].exchange.response.truncated, true);
assert.equal(projected[0].exchange.response.headers.at(-1)[1], "latest");
assert.equal(projected[0].event.id, "arrived");
assert.equal(networkModels.trafficSearchRequests(projected, "marker", true).matches.get("binary").side, "Response");
assert.equal(networkModels.trafficSearchRequests(projected, "marker", false).matches.size, 0);
repeatedNetwork.requests[0].response.body = binaryBody("changed response");
projected = networkModels.requestsFromDebuggerNetwork(repeatedNetwork, [], bodyCache);
assert.equal(networkBodyDecodes, 3);
assert.equal(projected[0].exchange.request.bytes, firstRequestBytes);
assert.notEqual(projected[0].exchange.response.bytes, firstResponseBytes);
repeatedNetwork.requests[0].response.body = {...emptyNetworkBody(), state: "loading"};
projected = networkModels.requestsFromDebuggerNetwork(repeatedNetwork, [], bodyCache);
assert.equal(projected[0].exchange.response.bytes, undefined);
assert.equal(projected[0].exchange.response.state, "loading");
assert.equal(bodyCache.get("binary").response.bytes, undefined);
assert.deepEqual(binaryNetwork, binaryOriginal);
for (let i = 0; i < 100; i += 1) {
  const window = networkSnapshot([networkRecord(`window-${i}`, {response: {headers: [], body: binaryBody("bounded")}})]);
  networkModels.requestsFromDebuggerNetwork(window, [], bodyCache);
  assert.deepEqual([...bodyCache.keys()], [`window-${i}`]);
}
networkModels.requestsFromDebuggerNetwork(networkSnapshot([]), [], bodyCache);
assert.equal(bodyCache.size, 0);
networkModels.requestsFromDebuggerNetwork(binaryNetwork, [], bodyCache);
assert.equal(networkModels.requestsFromDebuggerNetwork({...binaryNetwork, capture_enabled: false}, [], bodyCache).length, 0);
assert.equal(bodyCache.size, 0);
console.log("PASS indexed Traffic correlation, stable ties, body reuse, current-window eviction, capture-off and content search");

// A minimal DOM verifies the real reconciliation code and bounded state, not
// pixels. --traffic-ui-browser below is the separate rendered interaction path.
class TrafficFixtureNode {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.attributes = new Map();
    this.listeners = new Map(); this.className = ""; this._text = ""; this.value = ""; this.scrollTop = 0; this.parentNode = null;
    this.classList = {add: name => {if (!this.className.split(" ").includes(name)) this.className += ` ${name}`;},
      remove: name => {this.className = this.className.split(" ").filter(value => value !== name).join(" ");},
      toggle: (name, active) => active ? this.classList.add(name) : this.classList.remove(name),
      contains: name => this.className.split(" ").includes(name)};
  }
  set textContent(value) {this._text = String(value); this.children.forEach(node => {node.parentNode = null;}); this.children = [];}
  get textContent() {return this._text + this.children.map(node => node.textContent).join("");}
  get lastElementChild() {return this.children.at(-1);}
  get offsetTop() {return Math.max(0, this.parentNode?.children.indexOf(this) ?? 0) * 28;}
  get offsetHeight() {return 28;}
  get isConnected() {return true;}
  setAttribute(key, value) {this.attributes.set(key, String(value));}
  getAttribute(key) {return this.attributes.get(key) ?? null;}
  removeAttribute(key) {this.attributes.delete(key);}
  addEventListener(key, callback) {this.listeners.set(key, [...(this.listeners.get(key) ?? []), callback]);}
  append(...nodes) {for (const node of nodes) this.insertBefore(node, null);}
  insertBefore(node, next) {node.remove(); node.parentNode = this; const index = next ? this.children.indexOf(next) : -1; this.children.splice(index < 0 ? this.children.length : index, 0, node);}
  replaceChildren(...nodes) {this._text = ""; this.children.forEach(node => {node.parentNode = null;}); this.children = []; this.append(...nodes);}
  remove() {if (this.parentNode) {if (this.contains(trafficDocument.activeElement)) trafficDocument.activeElement = null; const index = this.parentNode.children.indexOf(this); this.parentNode.children.splice(index, 1); this.parentNode = null;}}
  contains(node) {return node === this || this.children.some(child => child.contains(node));}
  matches(selector) {return selector[0] === "." ? this.classList.contains(selector.slice(1)) : selector === "[aria-pressed]" ? this.attributes.has("aria-pressed") : this.tagName.toLowerCase() === selector;}
  querySelectorAll(selector) {return this.children.flatMap(node => [...(node.matches(selector) ? [node] : []), ...node.querySelectorAll(selector)]);}
  querySelector(selector) {return this.querySelectorAll(selector)[0] ?? null;}
  focus() {trafficDocument.activeElement = this;}
  click() {for (const callback of this.listeners.get("click") ?? []) callback({target: this, currentTarget: this});}
}
const trafficDocument = {activeElement: null, createElement: tag => new TrafficFixtureNode(tag), createTextNode: text => {
  const node = new TrafficFixtureNode("text"); node.textContent = text; return node;
}};
// Minimal DOM tests exercise the actual panel's event listeners and ownership.
// They are not rendered, pointer-hit-test, native WebKit or visual QA.
const packageSource = await readFile(join(root, 'apps/research-ui/evidence_package.js'), 'utf8');
function packagePanelFixture(native = false) {
  let copyResolve, downloadBlob, downloads = 0, copies = 0;
  const packageDocument = {activeElement:null,body:null};
  class PackageNode extends TrafficFixtureNode {
    focus() {packageDocument.activeElement=this;}
    remove() {if(this.parentNode) {if(this.contains(packageDocument.activeElement)) packageDocument.activeElement=null;this.parentNode.children.splice(this.parentNode.children.indexOf(this),1);this.parentNode=null;}}
    replaceChildren(...nodes) {if(this.contains(packageDocument.activeElement)) packageDocument.activeElement=null;super.replaceChildren(...nodes);}
    async emit(type, fields = {}) {await Promise.all((this.listeners.get(type)??[]).map(callback=>callback({target:this,currentTarget:this,...fields})));}
    click() {if(this.tagName==='A') downloads++;return this.emit('click');}
  }
  packageDocument.createElement=tag=>new PackageNode(tag);
  packageDocument.body=new PackageNode('body'); packageDocument.documentElement=new PackageNode('html');
  if(native) packageDocument.documentElement.classList.add('native-shell');
  const names=['scope','candidates','selection','selected','notice','report','file','export','validate','cancel','download','copy','save-note','page','previous','next','clear','context'];
  const host=new PackageNode('section');
  const nodes=Object.fromEntries(names.map(name=>[name,new PackageNode(name==='scope'?'select':name==='file'?'input':'div')]));
  host.append(...Object.values(nodes)); packageDocument.body.append(host);
  host.querySelector=selector=>nodes[/^\[data-package-(.+)\]$/.exec(selector)?.[1]];
  packageDocument.querySelector=()=>host; nodes.scope.value='request'; nodes.scope.selectedOptions=[{textContent:'Selected request native events'}]; nodes.file.files=[];
  let context={requestId:'fixture',events:packageGolden.records.events.map(row=>({...row,...row.key})),artifacts:packageGolden.records.artifacts.map(row=>({...row,...row.key})),eventsLimited:false};
  context.requestEvents=context.events;
  let pending = null;
  const calls=[];
  const fetcher=async(url,options)=>{calls.push({url,options});if(pending) return new Promise(resolve=>pending.push({resolve,options}));return url.endsWith('/export')?new Response(packageGoldenBytes):Response.json(packageValid);};
  const create = runInNewContext(packageSource+';createEvidencePackagePanel', {document:packageDocument,location:{protocol:'http:'},fetch:fetcher,
    TextEncoder,TextDecoder,Uint8Array,AbortController,setTimeout,clearTimeout,Blob,
    URL:{createObjectURL:blob=>{downloadBlob=blob;return 'blob:synthetic';},revokeObjectURL(){}},
    navigator:{clipboard:{writeText:()=>{copies++;return new Promise(resolve=>{copyResolve=resolve;});}}}});
  const panel=create({getContext:()=>context}); panel.setVisible(true);
  return {panel,nodes,host,document:packageDocument,calls,get context(){return context;},set context(value){context=value;},
    defer(){pending=[];return pending;},resume(){pending=null;},resolveCopy(){copyResolve();},get copies(){return copies;},get downloads(){return downloads;},get blob(){return downloadBlob;}};
}
const panel = packagePanelFixture();
const choosePackageRow = async (fixture,index=0,checked=true) => {const input=fixture.nodes.candidates.querySelectorAll('input')[index];input.checked=checked;await input.emit('change');return input;};
for(let index=0;index<4;index++) await choosePackageRow(panel,index);
panel.nodes.scope.value='artifacts'; await panel.nodes.scope.emit('change');
for(let index=0;index<2;index++) await choosePackageRow(panel,index);
await panel.nodes.export.emit('click');
assert.equal(panel.panel.controller.model.status,'ready'); assert.equal(panel.downloads,0); assert.equal(panel.copies,0,'Validation must never copy automatically');
assert.match(panel.nodes.report.textContent,/Authenticity.*not established/); assert.match(panel.nodes.report.textContent,/Unknown historical facts/);
assert.match(panel.nodes.report.textContent,/markers.*overlap/i); assert.match(panel.nodes.report.textContent,/time 10 ns/);
await panel.nodes.download.emit('click'); assert.equal(panel.downloads,1); assert.deepEqual(new Uint8Array(await panel.blob.arrayBuffer()),packageGoldenBytes);
const staleCopy=panel.nodes.copy.emit('click'); assert.equal(panel.copies,1); await panel.nodes.clear.emit('click');
const clearedNotice=panel.nodes.notice.textContent;panel.resolveCopy();await staleCopy;assert.equal(panel.nodes.notice.textContent,clearedNotice);
// Repeated clipboard actions share the active explicit write, and leaving/reopening retires its notice.
await panel.panel.controller.validate({size:packageGoldenBytes.length,arrayBuffer:async()=>packageGoldenBytes.buffer});
const copy=panel.nodes.copy.emit('click');await panel.nodes.copy.emit('click');assert.equal(panel.copies,2);
panel.panel.setVisible(false);panel.panel.setVisible(true);const reopenedNotice=panel.nodes.notice.textContent;panel.resolveCopy();await copy;
assert.equal(panel.nodes.notice.textContent,reopenedNotice);
const nativePanel=packagePanelFixture(true);
await nativePanel.panel.controller.validate({size:packageGoldenBytes.length,arrayBuffer:async()=>packageGoldenBytes.buffer});
assert.equal(nativePanel.nodes.download.disabled,true);assert.match(nativePanel.nodes['save-note'].textContent,/Download is unavailable in the native app/);
await nativePanel.nodes.download.emit('click');assert.equal(nativePanel.downloads,0);assert.equal(nativePanel.nodes.copy.disabled,false);
const nativeCopy=nativePanel.nodes.copy.emit('click');nativePanel.resolveCopy();await nativeCopy;assert.match(nativePanel.nodes.notice.textContent,/copied/);
// The focused identity and scroll survive an artifact-only catalog refresh.
panel.nodes.scope.value='artifacts';await panel.nodes.scope.emit('change');
const focused=await choosePackageRow(panel,0);focused.focus();panel.nodes.candidates.scrollTop=42;
panel.context={...panel.context,artifacts:[...panel.context.artifacts,{...panel.context.artifacts[0],artifact_id:'10'}]};panel.panel.sync();
assert.equal(panel.document.activeElement.dataset.packageKey,focused.dataset.packageKey);assert.equal(panel.nodes.candidates.scrollTop,42);
const selectedDisclosure=panel.nodes.selected.children[0];selectedDisclosure.open=true;panel.panel.sync();assert.equal(panel.nodes.selected.children[0],selectedDisclosure);
panel.context={...panel.context,artifacts:[]};panel.panel.sync();assert.equal(panel.nodes.candidates.children.length,0);
assert.equal(panel.document.activeElement,panel.nodes.candidates);assert.match(panel.nodes.selected.textContent,/session 7 \/ artifact 9/,'Eviction keeps exact selection visible');
// Late export and validation cannot win after Escape, another request, or leaving the screen.
panel.nodes.scope.value='request';await panel.nodes.scope.emit('change');await choosePackageRow(panel,0);
let pending=panel.defer();const escaped=panel.nodes.export.emit('click');assert.equal(pending.length,1);assert.equal(panel.document.activeElement,panel.nodes.cancel);
await panel.host.emit('keydown',{key:'Escape',preventDefault(){},stopPropagation(){}});assert.equal(pending[0].options.signal.aborted,true);
pending[0].resolve(new Response(packageGoldenBytes));await escaped;assert.equal(panel.panel.controller.model.status,'cancelled');
const switched=panel.nodes.export.emit('click');assert.equal(pending.length,2);panel.context={...panel.context,requestId:'other'};panel.panel.sync();
pending[1].resolve(new Response(packageGoldenBytes));await switched;assert.equal(panel.panel.controller.model.bytes,null);assert.match(panel.nodes.selection.textContent,/0 \/ 1,024/);
await choosePackageRow(panel,0);const leaving=panel.nodes.export.emit('click');panel.panel.setVisible(false);pending[2].resolve(new Response(packageGoldenBytes));await leaving;
assert.equal(panel.panel.controller.model.bytes,null);panel.panel.setVisible(true);panel.resume();
// Candidate mounting is bounded, paging never selects new rows, and the artifact cap holds across pages.
panel.context={...panel.context,artifacts:Array.from({length:65},(_,index)=>({...packageGolden.records.artifacts[0],session_id:'7',artifact_id:String(index+1)}))};
panel.nodes.scope.value='artifacts';await panel.nodes.scope.emit('change');assert.equal(panel.nodes.candidates.children.length,50);
await panel.nodes.clear.emit('click');for(let index=0;index<50;index++) await choosePackageRow(panel,index);
await panel.nodes.next.emit('click');assert.equal(panel.nodes.candidates.children.length,15);for(let index=0;index<15;index++) await choosePackageRow(panel,index);
assert.match(panel.nodes.selection.textContent,/64 \/ 64/);assert.equal(panel.nodes.candidates.querySelectorAll('input')[14].checked,false);assert.match(panel.nodes.notice.textContent,/Selection limit/);
assert.equal(panel.nodes.selected.children[0].querySelectorAll('li').length,50);
await panel.nodes.clear.emit('click');
panel.context={...panel.context,requestEvents:Array.from({length:1025},(_,index)=>({...packageGolden.records.events[0],session_id:'7',process_id:42,sequence_number:String(index+1)}))};
panel.nodes.scope.value='request';await panel.nodes.scope.emit('change');
for(let page=0;page<21;page++) {
  assert(panel.nodes.candidates.children.length<=50);
  for(let index=0;index<panel.nodes.candidates.children.length;index++) await choosePackageRow(panel,index);
  if(page<20) await panel.nodes.next.emit('click');
}
assert.match(panel.nodes.selection.textContent,/1024 \/ 1,024/);assert.equal(panel.nodes.candidates.querySelectorAll('input')[24].checked,false);
console.log('PASS package panel explicit actions, exact download bytes, native fallback, clipboard ownership, keyed refresh focus, eviction, caps, paging, Escape/navigation and stale selection (DOM fixture; not rendered QA)');

const trafficSource = await readFile(join(root, "apps/research-ui/traffic_view.js"), "utf8");
const trafficUI = runInNewContext(trafficSource + ";({trafficSortedRequests,trafficWindow,renderTrafficRows,renderTrafficDetails,trafficPaneSignature,trafficTableTypeLabel,TRAFFIC_ROW_LIMIT})", {
  document: trafficDocument, URL, TextEncoder, TextDecoder, Uint8Array, queueMicrotask,
  navigator: {clipboard: {writeText: async () => {}}}, setTimeout: () => 0,
  createSourceTokenizer: () => ({}), sourceSyntaxTokens: text => [{type: "plain", text}],
});
const uiRequest = (id, patch = {}) => ({id, path: `https://fixture.invalid/${id}`, method: "GET", status: "pending",
  time: "pending", type: "xhr", origin: "live", tabId: "fixture-tab", operation: "cdp_pending", events: [],
  exchange: {request: {state: "empty", headers: []}, response: {state: "loading", headers: []}}, ...patch});
const retainedTraffic = Array.from({length: 5000}, (_, index) => uiRequest(String(index), {time: index % 20}));
assert.equal(trafficUI.TRAFFIC_ROW_LIMIT, 500);
for (const type of ["constructor", "__proto__", null]) assert.equal(trafficUI.trafficTableTypeLabel(type), "Other");
assert.equal(trafficUI.trafficWindow(retainedTraffic, 0).rows.length, 500);
assert.equal(trafficUI.trafficWindow(retainedTraffic, 5000).start, 4500);
assert.equal(trafficUI.trafficWindow(retainedTraffic.slice(30), 300, "300").start, 270);
for (const direction of [1, -1]) {
  const sorted = trafficUI.trafficSortedRequests(retainedTraffic, "time", direction);
  assert.equal(sorted[0].time, direction === 1 ? 0 : 19);
  assert.equal(sorted[0].id, direction === 1 ? "0" : "19");
}
assert.equal(trafficUI.trafficSortedRequests([uiRequest("pending"), uiRequest("done", {time: 2})], "time", -1)[0].id, "done");
assert.deepEqual(Array.from(trafficUI.trafficSortedRequests([uiRequest("native", {time: "12.300 ms"}), uiRequest("cdp", {time: 2})], "time"), request => request.id), ["cdp", "native"]);
const ledger = new TrafficFixtureNode();
const rowOptions = {selectedId: "3", newIds: new Set(["3"]), onSelect() {}, onKey() {}};
trafficUI.renderTrafficRows(ledger, retainedTraffic.slice(0, 500), rowOptions);
assert.equal(ledger.children[0].children[1].textContent, "Pending");
assert.equal(ledger.children[0].children[2].textContent, "XHR/F");
assert.equal(ledger.children[0].children[2].title, "Fetch/XHR");
const selectedRow = ledger.children[3];
selectedRow.focus(); ledger.scrollTop = 84;
assert(selectedRow.classList.contains("is-new"));
for (const callback of selectedRow.listeners.get("animationend")) callback();
const pendingName = selectedRow.children[0];
trafficUI.renderTrafficRows(ledger, retainedTraffic.slice(0, 500), rowOptions);
assert.equal(ledger.children[3], selectedRow);
assert.equal(selectedRow.children[0], pendingName);
assert(!selectedRow.classList.contains("is-new"));
for (const patch of [{status: 200, time: 4}, {status: 503, failed: true, time: 6}]) {
  const changed = retainedTraffic.slice(0, 500); changed[3] = {...changed[3], ...patch};
  trafficUI.renderTrafficRows(ledger, changed, rowOptions);
  assert.equal(ledger.children[3], selectedRow);
  assert.equal(trafficDocument.activeElement, selectedRow);
  assert.equal(ledger.scrollTop, 84);
  assert(!selectedRow.classList.contains("is-new"));
}
assert.equal(selectedRow.children[1].textContent, "Failed");
trafficUI.renderTrafficRows(ledger, retainedTraffic.slice(1, 501), rowOptions);
assert.equal(ledger.children[2], selectedRow);
assert.equal(ledger.scrollTop, 56, "Retained-window eviction preserves the first visible row anchor");
assert.equal(trafficDocument.activeElement, selectedRow);
trafficUI.renderTrafficRows(ledger, retainedTraffic.slice(4, 504), rowOptions);
assert.equal(trafficDocument.activeElement, ledger.children[0]);
assert.equal(ledger.children.length, 500);
const details = new TrafficFixtureNode();
let selectedTraffic = uiRequest("inspect", {exchange: {request: {state: "empty", headers: []}, response: {state: "available", mime: "text/plain", text: "first", headers: [["x-version", "one"]]}}});
trafficUI.renderTrafficDetails(details, selectedTraffic, "response", () => {}, () => {});
const responsePane = details.querySelector(".exchange-pane");
const responseViewer = responsePane.querySelector(".exchange-content");
const responseSearch = responsePane.querySelector(".exchange-search");
responseSearch.focus(); responseViewer.scrollTop = 28;
selectedTraffic = {...selectedTraffic, exchange: {...selectedTraffic.exchange, response: {...selectedTraffic.exchange.response, text: "other"}}};
trafficUI.renderTrafficDetails(details, selectedTraffic, "response", () => {}, () => {});
await Promise.resolve();
assert.equal(details.querySelector(".exchange-pane"), responsePane);
assert.match(responseViewer.textContent, /other/);
assert.equal(responseViewer.scrollTop, 28);
assert.equal(trafficDocument.activeElement, responseSearch);
trafficUI.renderTrafficDetails(details, selectedTraffic, "headers", () => {}, () => {});
assert.match(details.textContent, /x-versionone/);
selectedTraffic.exchange.response.headers = [["x-version", "two"]];
trafficUI.renderTrafficDetails(details, selectedTraffic, "headers", () => {}, () => {});
assert.match(details.textContent, /x-versiontwo/);
for (const [state, expected] of [["loading", /Loading response/], ["error", /could not be loaded/], ["empty", /No response body/], ["missing", /not captured/], ["redacted", /redacted/]]) {
  selectedTraffic.exchange.response = {state, headers: []};
  trafficUI.renderTrafficDetails(details, selectedTraffic, "response", () => {}, () => {});
  assert.match(details.textContent, expected);
}
selectedTraffic.exchange.response = {state: "available", mime: "application/json", text: "{malformed", headers: []};
trafficUI.renderTrafficDetails(details, selectedTraffic, "preview", () => {}, () => {});
assert.match(details.textContent, /Invalid JSON/);
assert.match(details.textContent, /malformed/);
trafficUI.renderTrafficDetails(details, null, "headers", () => {}, () => {}, null, "Selected request left the retained window.");
assert.match(details.textContent, /left the retained window/);
console.log("PASS Traffic 500-row paging, sorting, anchored eviction, stable lifecycle focus, one-shot arrivals, equal-length body/header updates, and explicit capture states (DOM fixture; not rendered QA)");

// Run the actual source load/refresh lifecycle with rendering and transport
// stubbed. This verifies retention and races, not browser interaction or pixels.
const appSource = await readFile(join(root, "apps/research-ui/app.js"), "utf8");
function appSection(start, end) {
  const offset = appSource.indexOf(start);
  const boundary = appSource.indexOf(end, offset);
  assert(offset >= 0 && boundary > offset, `Missing fixture boundary: ${start}`);
  return appSource.slice(offset, boundary);
}
// Additive machine-readable failure reasons must not make the bundled UI
// reject its existing application result envelope. Exercise the actual validators.
const applicationResults = runInNewContext(
  (await readFile(join(root, "apps/research-ui/evidence_models.js"), "utf8")) +
  appSection("      const analystExactKeys =", "      function isLocalAnalystWorkspace") +
  appSection("      function isLocalAnalystResult", "      function analystFolder(") +
  appSection("      function isJwtInspection", "      function decoderBytesToBase64") +
  ";({isLocalAnalystResult,isJwtInspection,isJwtCreation})", {TextEncoder},
);
const analystResult = {protocol_version: 1, run_id: 1, script_id: 1, library_generation: 1,
  ok: false, outcome: "failed", result_type: "error", result_text: "", result_truncated: false,
  logs: [], logs_truncated: false, duration_ms: 1, error: "Synthetic failure"};
for (const [outcome, code] of [["failed", "application_failed"], ["cancelled", "cancelled"], ["timed_out", "timeout"]]) {
  const legacy = {...analystResult, outcome};
  const annotated = {...legacy, code, details: {phase: "worker"}};
  assert(applicationResults.isLocalAnalystResult(legacy, legacy));
  assert(applicationResults.isLocalAnalystResult(annotated, legacy));
  for (const patch of [{code: "invented"}, {details: {}}, {details: {phase: "worker", raw: "private"}}, {details: {phase: "command_exchange"}}]) {
    assert.equal(applicationResults.isLocalAnalystResult({...annotated, ...patch}, legacy), false);
  }
}
const completedAnalyst = {...analystResult, ok: true, outcome: "completed", error: ""};
assert(applicationResults.isLocalAnalystResult(completedAnalyst, completedAnalyst));
assert.equal(applicationResults.isLocalAnalystResult({...completedAnalyst, code: "application_failed", details: {phase: "worker"}}, completedAnalyst), false);
const jwtCommon = {protocol_version: 1, ok: false, error: "Synthetic failure", duration_us: 1};
for (const [validate, legacy] of [
  [applicationResults.isJwtInspection, {...jwtCommon, algorithm: "", signature_status: "invalid", header_json: "", payload_json: "", token_bytes: 0, signature_bytes: 0}],
  [applicationResults.isJwtCreation, {...jwtCommon, token: ""}],
]) {
  assert(validate(legacy));
  const annotated = {...legacy, code: "application_failed", details: {}};
  assert(validate(annotated));
  for (const patch of [{code: "invented"}, {details: {raw: "private"}}, {code: undefined}, {details: undefined}, {ok: true}]) {
    assert.equal(validate({...annotated, ...patch}), false);
  }
  assert(validate({...legacy, ok: true, error: ""}));
}
console.log("PASS legacy and annotated Analyst/JWT failures, unchanged successes and bounded reason rejection");

// An unchanged event ETag must not prevent artifact-only updates reaching Evidence.
const packageRefreshState = {artifactRefreshing:false,artifactEtag:null,artifactCatalogSignature:null,artifacts:[],openArtifactIds:[],selectedArtifactId:null,sessionMode:'live'};
let packageRefreshBody={artifacts:packageGolden.records.artifacts.map(row=>({...row,...row.key}))}, packageRefreshSyncs=0;
const packageArtifactRefresh=runInNewContext(appSection('      function liveScriptIdentity(', '      function liveSources(') + appSection('      async function refreshArtifacts()', '      function showScreen(')+';refreshArtifacts',{
  sourceFactsFields:sourceFactsUI.sourceFactsFields, sourceFactsIdentity:sourceFactsUI.sourceFactsIdentity, state:packageRefreshState,location:{protocol:'http:'},fetch:async()=>Response.json(packageRefreshBody),isArtifactResponse:()=>true,
  renderShellStatus(){},renderSourceHealth(){},renderSources(){},renderFingerprintActivity(){},loadArtifactContent(){},loadWasmInspection(){},
  nativeCanvasCaptureDisplayLimit:10,document:{querySelector:()=>({hidden:true})},evidenceWorkspace:{sync(){}},evidencePackagePanel:{sync(){packageRefreshSyncs++;}}
});
await packageArtifactRefresh();assert.equal(packageRefreshState.artifacts.length,2);assert.equal(packageRefreshSyncs,1);
packageRefreshBody={artifacts:[]};await packageArtifactRefresh();assert.equal(packageRefreshState.artifacts.length,0);assert.equal(packageRefreshSyncs,2);
console.log('PASS artifact-only and empty-catalog refresh synchronize the Evidence panel');

// Background request eviction also happens outside Traffic; it must retire an
// Evidence operation immediately rather than waiting for the next view render.
const packageResetState={selectedRequestId:'evicted',originTraceGeneration:0,signalProfileGeneration:0};let packageResetContext;
const packageReset=runInNewContext(appSection('      function resetRequestSelection()', '      function renderRequestCount(')+';resetRequestSelection',{
  state:packageResetState,evidencePackagePanel:{sync(){packageResetContext=packageResetState.selectedRequestId;}}
});packageReset();assert.equal(packageResetContext,null);

// Every inspector render must refresh the strip from the same current request;
// lifecycle callers must not be able to leave a stale pending/status badge.
const summaryState = {selectedRequestId: "current", requests: [uiRequest("current")], inspectorTab: "headers",
  trafficDetailOpen: true, trafficSelectionNotice: null};
const summaryElements = {};
for (const name of ["selectedMethod", "selectedStatus", "selectedUrl", "requestCopyUrl", "requestCollectionPivot", "requestInspector", "requestSearchScope", "requestFilter"]) summaryElements[name] = new TrafficFixtureNode();
summaryElements.requestSearchScope.value = "url";
const summaryNodes = new Map(["#exchange-inspector", ".traffic-grid", ".detail-pane", "#request-evidence-toggle", "#request-package-entry"].map(key => [key, new TrafficFixtureNode()]));
let renderedSummaryRequest;
const summaryInspector = runInNewContext(
  appSection("      function updateSelectionSummary(", "      function selectRequest(") +
  appSection("      function renderInspector()", "      function renderEvidence()") + ";renderInspector", {
    state: summaryState, elements: summaryElements, evidencePackagePanel: {sync() {}},
    document: {querySelectorAll: () => [], querySelector: selector => summaryNodes.get(selector)},
    renderTrafficDetails: (_container, request) => {renderedSummaryRequest = request;}, openFieldProvenance() {},
  });
for (const [status, failed] of [["pending", false], [200, false], ["failed", true]]) {
  summaryState.requests = [{...summaryState.requests[0], status, failed}];
  summaryInspector();
  assert.equal(summaryElements.selectedStatus.textContent, String(status));
  assert.equal(summaryElements.selectedStatus.classList.contains("status-error"), failed);
  assert.equal(renderedSummaryRequest, summaryState.requests[0]);
}
summaryState.requests = [{...summaryState.requests[0], method: "POST", path: "https://fixture.invalid/new-path"}];
summaryInspector();
assert.equal(summaryElements.selectedMethod.textContent, "POST");
assert.equal(summaryElements.selectedUrl.textContent, "https://fixture.invalid/new-path");
summaryState.requests = []; summaryState.selectedRequestId = null;
summaryInspector();
assert.equal(summaryElements.selectedStatus.textContent, "-");
assert.equal(summaryElements.requestCopyUrl.disabled, true);
console.log("PASS selected strip and inspector share current pending/response/failed/empty request metadata");

// Exercise the actual production listeners: selecting a tab is idempotent,
// whereas the shortcut deliberately toggles Evidence back to Headers.
const stickyInspectorState={inspectorTab:'evidence',fieldTab:'body',requests:[],selectedRequestId:null};
const explicitEvidenceTab=new TrafficFixtureNode('button');explicitEvidenceTab.dataset.inspectorTab='evidence';
const evidenceShortcut=new TrafficFixtureNode('button');
runInNewContext(appSection("      document.querySelectorAll('.inspector-tab').forEach(button => button.addEventListener('click'", "      enableTabKeyboardNavigation('.inspector-tab');"), {
  state:stickyInspectorState,document:{querySelectorAll:()=>[explicitEvidenceTab],querySelector:()=>evidenceShortcut},
  renderInspector(){},renderEvidence(){},refreshRequestSignalProfile(){}
});
explicitEvidenceTab.click();assert.equal(stickyInspectorState.inspectorTab,'evidence');
evidenceShortcut.click();assert.equal(stickyInspectorState.inspectorTab,'headers');
explicitEvidenceTab.click();assert.equal(stickyInspectorState.inspectorTab,'evidence');
explicitEvidenceTab.click();assert.equal(stickyInspectorState.inspectorTab,'evidence');
evidenceShortcut.click();assert.equal(stickyInspectorState.inspectorTab,'headers');
console.log('PASS explicit Evidence tab selection preserves sticky selection while its shortcut deliberately toggles to Headers');


const pivotProfile = {signals: [{category: "canvas", event_count: "1", confidence: "observed", relation: "parent_chain"}]};
const pivotState = {requests: [uiRequest("selected")], selectedRequestId: "selected", signalProfile: pivotProfile,
  signalProfileStatus: "ready", trafficDetailOpen: false, inspectorTab: "headers"};
const pivotElements = {signalRequestProfile: new TrafficFixtureNode(), signalDetail: new TrafficFixtureNode()};
const signalTab = new TrafficFixtureNode("button");
let pivotScreen;
let pivotInspectorOpen = false;
const signalPivots = runInNewContext(appSection("      function renderSignalRequestProfile()", "      function signalTabKey(") +
  ";({renderSignalRequestProfile,renderFingerprintDetail})", {
  state: pivotState, elements: pivotElements, document: {...trafficDocument, querySelector: () => signalTab},
  textElement: (tag, className, text) => {const node = new TrafficFixtureNode(tag); node.className = className; node.textContent = text; return node;},
  fingerprintSignalLabels: new Map([["canvas", "Canvas"]]), signalCoverageLabel: () => "Bounded",
  decodePayload: () => "getImageData", signalTypeLabel: value => value, signalTabKey: () => "tab",
  matchingSignalProfileFamily: () => pivotProfile.signals[0], signalEventKey: () => "event", integerText: () => "1",
  showScreen: screen => {pivotScreen = screen;}, renderInspector: () => {pivotInspectorOpen = pivotState.trafficDetailOpen;},
  refreshRequestSignalProfile() {}, requestAnimationFrame: callback => callback(),
});
for (const render of [() => signalPivots.renderSignalRequestProfile(), () => signalPivots.renderFingerprintDetail({category: "canvas", type: "api_call", thread_id: 1})]) {
  pivotState.trafficDetailOpen = false; pivotInspectorOpen = false; render();
  const root = pivotElements.signalDetail.children.length ? pivotElements.signalDetail : pivotElements.signalRequestProfile;
  root.querySelector("button").click();
  assert.equal(pivotScreen, "traffic");
  assert.equal(pivotInspectorOpen, true, "Explicit fingerprint pivots reopen a previously dismissed inspector");
  assert.equal(pivotState.inspectorTab, "signals");
  assert.equal(pivotState.signalProfile, pivotProfile, "Pivots retain the already loaded signal profile");
}
console.log("PASS Fingerprinting request-profile and event-detail pivots reopen dismissed Traffic details without resetting evidence");

const sourceState = {liveScriptContent: new Map(), staleScriptIds: new Set(), openScriptIds: [], openArtifactIds: [],
  debuggerRefreshing: false, debuggerEtag: null, debuggerSession: null, selectedScriptId: null,
  editingBreakpointId: null, selectedRequestId: null, requests: []};
const sourceSnapshot = scripts => ({target: {id: "target"}, scripts, breakpoints: [], state: "running"});
let sourceReply;
let catalogReply;
let catalogFailure = false;
let sourceLoads = 0;
let sourceRenders = 0;
let sourceVisible = false;
let sourceHeadersStalled = false;
let sourceTimerId = 0;
const sourceTimers = new Map();
const activeSourceRequests = new Set();
const sourceSandbox = {state: sourceState, location: {protocol: "http:"},
  sourceFactsReadBytes: sourceFactsUI.sourceFactsReadBytes, TextDecoder, TextEncoder,
  AbortController,
  setTimeout(callback, delay) {const id = ++sourceTimerId; sourceTimers.set(id, {callback, delay}); return id;},
  clearTimeout(id) {sourceTimers.delete(id);},
  document: {hidden: false, querySelector: selector => ({hidden: selector !== "#screen-sources" || !sourceVisible})},
  isPlainObject: value => value !== null && typeof value === "object" && !Array.isArray(value),
  isDebuggerResponse: value => value.valid !== false,
  selectedSource: () => sourceState.debuggerSession.scripts.find(script => script.script_id === sourceState.selectedScriptId),
  sourceDisplayName: script => script.script_id,
  fetch: async (url, options) => {
    if (url.startsWith("/api/debugger/source")) {
      sourceLoads += 1;
      const id = sourceLoads;
      const reply = sourceReply;
      const signal = options.signal;
      assert(signal instanceof AbortSignal, "Source transport must receive the cancellation signal");
      activeSourceRequests.add(id);
      const abortable = value => new Promise((resolve, reject) => {
        const settle = (handler, value) => {
          activeSourceRequests.delete(id);
          signal.removeEventListener("abort", aborted);
          handler(value);
        };
        const aborted = () => settle(reject, new DOMException("Synthetic transport aborted", "AbortError"));
        if (signal.aborted) {aborted(); return;}
        signal.addEventListener("abort", aborted, {once: true});
        Promise.resolve(value).then(value => settle(resolve, value), error => settle(reject, error));
      });
      return sourceHeadersStalled ? abortable(new Promise(() => {})) : {ok: true, body: {getReader() {
        let delivered = false;
        return {async read() {if (delivered) return {done:true}; delivered=true;
          return {done:false, value:new TextEncoder().encode(JSON.stringify(await abortable(reply)))};},
          cancel() {activeSourceRequests.delete(id); return Promise.resolve();}, releaseLock() {}};
      }}};
    }
    if (catalogFailure) throw new Error("Synthetic refresh disconnected");
    return {status: 200, ok: true, headers: {get: () => null}, json: async () => catalogReply};
  }};
for (const name of ["renderSources", "rebuildTrafficRequests", "applyMemoryOriginTrace", "renderLiveBrowserTabCount",
  "renderDebugger", "renderShellStatus", "renderNetworkNotice", "renderMemory", "renderFieldProvenance", "scheduleDebuggerRefresh",
  "renderSourceTree", "renderSourceTabs", "updateSourceDecorations"]) {
  sourceSandbox[name] = () => {};
}
sourceSandbox.renderSources = () => {sourceRenders += 1;};
const sourceLifecycle = runInNewContext(
  appSection("      function liveScriptIdentity(", "      function liveSources(") +
  appSection("      function markLiveSourceStale(", "      function selectedSource(") +
  appSection("      async function loadScriptContent(", "      async function toggleLineBreakpoint(") +
  appSection("      function debuggerScriptCatalogSignature(", "      function scheduleDebuggerRefresh(") +
  appSection("      async function refreshDebugger(", "      async function refreshArtifacts(") +
  ";({loadScriptContent,refreshDebugger,markLiveSourceStale})", sourceSandbox,
);
const fixtureScript = (id, patch = {}) => ({script_id: id, target_id: "target", hash: id, kind: "javascript", ...patch});
const fixtureSource = (script, source = "retained source") => ({protocol_version: 1, script_id: script.script_id, source, truncated: false});
async function updateCatalog(snapshot) {
  catalogReply = snapshot;
  await sourceLifecycle.refreshDebugger();
}
for (let i = 0; i < 100; i += 1) {
  const script = fixtureScript(`navigation-${i}`);
  await updateCatalog(sourceSnapshot([script]));
  sourceReply = fixtureSource(script, `/* ${i} */` + "x".repeat(256 * 1024));
  await sourceLifecycle.loadScriptContent(script);
  assert.equal(sourceState.liveScriptContent.size, 1);
  await updateCatalog(sourceSnapshot([]));
  assert.equal(sourceState.liveScriptContent.size, 0);
}
const retainedScript = fixtureScript("retained");
await updateCatalog(sourceSnapshot([retainedScript]));
sourceReply = fixtureSource(retainedScript);
await sourceLifecycle.loadScriptContent(retainedScript);
const retainedEntry = sourceState.liveScriptContent.get("retained");
await updateCatalog({...sourceSnapshot([]), valid: false});
assert.equal(sourceState.liveScriptContent.get("retained"), retainedEntry);
assert.equal(sourceState.debuggerRefreshFailed, true);
await updateCatalog(sourceSnapshot([retainedScript]));
assert.equal(sourceState.liveScriptContent.get("retained"), retainedEntry);
catalogFailure = true;
await updateCatalog(sourceSnapshot([]));
assert.equal(sourceState.liveScriptContent.get("retained"), retainedEntry);
catalogFailure = false;
await updateCatalog(sourceSnapshot([{...retainedScript, hash: "new-hash"}]));
assert.equal(sourceState.liveScriptContent.size, 0);

let finishOldSource;
const delayedScript = fixtureScript("delayed");
await updateCatalog(sourceSnapshot([delayedScript]));
sourceReply = new Promise(resolve => {finishOldSource = resolve;});
const delayedLoad = sourceLifecycle.loadScriptContent(delayedScript);
await Promise.resolve();
await updateCatalog(sourceSnapshot([]));
assert.equal(sourceState.liveScriptContent.size, 0);
await updateCatalog(sourceSnapshot([delayedScript]));
sourceReply = fixtureSource(delayedScript, "newer load");
await sourceLifecycle.loadScriptContent(delayedScript);
finishOldSource(fixtureSource(delayedScript, "obsolete load"));
await delayedLoad;
assert.equal(sourceState.liveScriptContent.get("delayed").content, "newer load");
await updateCatalog(sourceSnapshot([{...delayedScript, target_id: "other-target"}]));
assert.equal(sourceState.liveScriptContent.size, 0);
const priorLoads = sourceLoads;
await sourceLifecycle.loadScriptContent(delayedScript);
assert.equal(sourceLoads, priorLoads);
const failedScript = fixtureScript("failed-source");
await updateCatalog(sourceSnapshot([failedScript]));
sourceReply = Promise.reject(new Error("Synthetic source failure"));
await sourceLifecycle.loadScriptContent(failedScript);
assert.match(sourceState.liveScriptContent.get(failedScript.script_id).loadError, /Synthetic source failure/);
assert.equal(sourceState.liveScriptContent.get(failedScript.script_id).loading, false);
sourceReply = fixtureSource(failedScript, "recovered source");
await sourceLifecycle.loadScriptContent(failedScript);
assert.equal(sourceState.liveScriptContent.get(failedScript.script_id).content, "recovered source");
let failDetachedSource;
const failedPendingScript = fixtureScript("failed-pending");
await updateCatalog(sourceSnapshot([failedPendingScript]));
sourceReply = new Promise((resolve, reject) => {failDetachedSource = reject;});
const pendingFailure = sourceLifecycle.loadScriptContent(failedPendingScript);
await Promise.resolve();
await updateCatalog(sourceSnapshot([]));
await updateCatalog(sourceSnapshot([failedPendingScript]));
sourceReply = fixtureSource(failedPendingScript, "newer successful source");
await sourceLifecycle.loadScriptContent(failedPendingScript);
failDetachedSource(new Error("Obsolete load failed"));
await pendingFailure;
assert.equal(sourceState.liveScriptContent.get(failedPendingScript.script_id).content, "newer successful source");
sourceState.staleScriptIds.add(failedPendingScript.script_id);
const loadsBeforeStale = sourceLoads;
await sourceLifecycle.loadScriptContent(failedPendingScript);
assert.equal(sourceLoads, loadsBeforeStale);
// Selected/open IDs can survive navigation while their source identity changes.
// The editor must replace its old bytes without requiring another click.
sourceVisible = true;
const selectedScript = fixtureScript("selected");
await updateCatalog(sourceSnapshot([selectedScript]));
sourceState.selectedScriptId = selectedScript.script_id;
sourceState.openScriptIds = [selectedScript.script_id];
sourceState.sourceCollection = "page";
sourceReply = fixtureSource(selectedScript, "old selected source");
await sourceLifecycle.loadScriptContent(selectedScript);
for (const changedScript of [{...selectedScript, hash: "changed-hash"}, {...selectedScript, target_id: "changed-target"}]) {
  const priorRenders = sourceRenders;
  const priorLoads = sourceLoads;
  sourceReply = fixtureSource(changedScript, `new source ${changedScript.hash}:${changedScript.target_id}`);
  await updateCatalog(sourceSnapshot([changedScript]));
  await new Promise(resolve => setImmediate(resolve));
  assert(sourceRenders > priorRenders);
  assert.equal(sourceLoads, priorLoads + 1);
  assert.equal(sourceState.selectedScriptId, "selected");
  assert.equal(sourceState.openScriptIds[0], "selected");
  assert.equal(sourceState.liveScriptContent.get("selected").content, sourceReply.source);
}
sourceVisible = false;
sourceState.selectedScriptId = null;
sourceState.openScriptIds = [];
const stalledScript = fixtureScript("stalled");
const noticeBeforeCancellation = sourceState.sourceNotice;
for (let i = 0; i < 25; i += 1) {
  await updateCatalog(sourceSnapshot([stalledScript]));
  sourceHeadersStalled = Boolean(i % 2);
  sourceReply = new Promise(() => {});
  const pendingLoad = sourceLifecycle.loadScriptContent(stalledScript);
  await Promise.resolve();
  const pending = sourceState.liveScriptContent.get(stalledScript.script_id);
  assert.equal(activeSourceRequests.size, 1);
  await updateCatalog(sourceSnapshot([]));
  await pendingLoad;
  assert.equal(pending.controller.signal.aborted, true);
  assert.equal(activeSourceRequests.size, 0);
  assert.equal(sourceTimers.size, 0);
  assert.equal(sourceState.liveScriptContent.size, 0);
  assert.equal(sourceState.sourceNotice, noticeBeforeCancellation);
}
for (const headersStalled of [false, true]) {
  const script = fixtureScript(`timeout-${headersStalled}`);
  await updateCatalog(sourceSnapshot([script]));
  sourceHeadersStalled = headersStalled;
  sourceReply = new Promise(() => {});
  const timedOutLoad = sourceLifecycle.loadScriptContent(script);
  await Promise.resolve();
  assert.equal(sourceTimers.size, 1);
  const deadline = [...sourceTimers.values()][0];
  assert.equal(deadline.delay, 15000);
  deadline.callback();
  await timedOutLoad;
  assert.match(sourceState.liveScriptContent.get(script.script_id).loadError, /timed out after 15 seconds/);
  assert.equal(activeSourceRequests.size, 0);
  assert.equal(sourceTimers.size, 0);
  sourceHeadersStalled = false;
  sourceReply = fixtureSource(script, "source after timeout retry");
  await sourceLifecycle.loadScriptContent(script);
  assert.equal(sourceState.liveScriptContent.get(script.script_id).content, sourceReply.source);
  assert.equal(sourceTimers.size, 0);
}
const replacedPending = fixtureScript("replace-pending");
await updateCatalog(sourceSnapshot([replacedPending]));
sourceReply = new Promise(() => {});
const replacedLoad = sourceLifecycle.loadScriptContent(replacedPending);
await Promise.resolve();
const replacedController = sourceState.liveScriptContent.get(replacedPending.script_id).controller;
const replacingScript = {...replacedPending, hash: "replacement"};
sourceState.debuggerSession = sourceSnapshot([replacingScript]);
sourceReply = fixtureSource(replacingScript, "replacement source");
await sourceLifecycle.loadScriptContent(replacingScript);
await replacedLoad;
assert.equal(replacedController.signal.aborted, true);
assert.equal(sourceState.liveScriptContent.get(replacingScript.script_id).content, "replacement source");
assert.equal(activeSourceRequests.size, 0);
assert.equal(sourceTimers.size, 0);
const stalePending = fixtureScript("mark-stale-pending");
await updateCatalog(sourceSnapshot([stalePending]));
sourceReply = new Promise(() => {});
const markedLoad = sourceLifecycle.loadScriptContent(stalePending);
await Promise.resolve();
sourceLifecycle.markLiveSourceStale(stalePending.script_id);
await markedLoad;
assert.equal(sourceState.liveScriptContent.size, 0);
assert.equal(activeSourceRequests.size, 0);
assert.equal(sourceTimers.size, 0);
console.log("PASS live source eviction, validated refresh retention, identity changes, abort/timeout cleanup and load races");
// Adversarial Sources ownership tests run production functions, not a second
// controller. Transport/DOM fixtures are inert and are not rendered acceptance.
function sourceProductionFunction(name) {
  const start = appSource.search(new RegExp(`^      (?:async )?function ${name}\\(`, 'm'));
  assert(start >= 0, name);
  const end = /^      }$/m.exec(appSource.slice(start));
  assert(end, name);
  return appSource.slice(start, start + end.index + end[0].length);
}
const ownershipFunctionNames = ['liveScriptIdentity', 'sourceIdentity', 'sourceIsCurrent', 'sourceReference', 'setSourceCursor', 'sourceCursorFor',
  'retireSourceAnalysis', 'releaseSourcePreview', 'boundSourcePreviews', 'boundSourceAnalysis',
  'liveSources', 'capturedSources', 'selectedSource', 'deobfuscationKey', 'sourceOwnedLiveText', 'validateSourceAnalysis', 'loadDeobfuscation',
  'sourceDisplayView', 'sourceViewLabel', 'sourceDerivedView', 'loadArtifactContent', 'refreshArtifacts',
  'closeSource', 'loadScriptContent', 'sourceRuntimeLine', 'sourceRuntimeColumn', 'prefillHookFromSource',
  'sourceDisplayName', 'sourceIcon', 'renderSourceTabs', 'retrySourcePreview', 'renderSourceContent', 'updateSourceDecorations', 'breakpointLinesForSource',
  'revealRuntimeHookHit', 'sourceArtifactIdentityMatches', 'selectArtifact', 'selectScript', 'sourceFormattedView', 'textElement', 'deobfuscationRow', 'deobfuscationOwner', 'cancelDeobfuscation', 'retryDeobfuscation', 'retireDeobfuscationReveal',
  'updateDeobfuscationView', 'setDeobfuscationDisclosure', 'revealDeobfuscationChange', 'deobfuscationButton', 'deobfuscationDisclosure', 'renderDeobfuscationReport'];
const ownershipModels = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const ownershipSyntax = await readFile(join(root, 'apps/research-ui/source_syntax.js'), 'utf8');
const ownershipProvenance = await readFile(join(root, 'apps/research-ui/field_provenance.js'), 'utf8');
const ownershipProvenanceSite = ownershipProvenance.slice(ownershipProvenance.indexOf('function revealProvenanceSite('), ownershipProvenance.indexOf('\nfunction provenanceSourceURL('));
const ownershipHash = async text => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',
  typeof text === 'string' ? new TextEncoder().encode(text) : text)), byte => byte.toString(16).padStart(2, '0')).join('');
const ownedArtifact = async (id, text = 'const a = 1;', session = '1') => ({protocol_version:1, artifact_id:id, session_id:session,
  navigation_id:'1', frame_id:'1', parent_artifact_id:'0', creator_event_id:'0', kind:'javascript',
  url:`https://fixture.invalid/${id}.js`, mime_type:'text/javascript', byte_size:Buffer.byteLength(text), sha256:await ownershipHash(text), sensitive:false});
const ownedPayload = (source, text) => ({schema:'deobfuscation-analysis-v1', engine:'rust-oxc', mode:'derived', source_truncated:false,
  artifact_id:source.source_type === 'script' ? null : source.artifact_id,
  script_id:source.source_type === 'script' ? source.script_id : null, original_source:text,
  analysis:{source:{sha256:source.sha256 ?? source.hash,byte_size:Buffer.byteLength(text)},assumptions:[]},
  representation:{text,offset_unit:'utf-8-byte',segments:text ? [{kind:'verbatim',original_start:0,original_end:Buffer.byteLength(text),derived_start:0,derived_end:Buffer.byteLength(text)}] : []}});
function ownedContext(patch = {}) {
  const state = {artifacts:[], openArtifactIds:[], openScriptIds:[], selectedArtifactId:null, selectedScriptId:null,
    liveScriptContent:new Map(), staleScriptIds:new Set(), deobfuscationRequests:new Map(), deobfuscationCache:new Map(),
    sourceFormatCache:new Map(), wasmRequests:new Map(), wasmCache:new Map(),
    sourceDeobfuscated:false, sourceFormatted:false, sourceWasm:false, sessionMode:'live', ...patch.state};
  const sandbox = {console, state, TextEncoder, TextDecoder, Uint8Array, crypto, AbortController, setTimeout, clearTimeout,
    sourceFactsFields:sourceFactsUI.sourceFactsFields, sourceFactsIdentity:sourceFactsUI.sourceFactsIdentity, sourceFactsUnavailable:sourceFactsUI.sourceFactsUnavailable, sourceFactsReadBytes:sourceFactsUI.sourceFactsReadBytes,
    sourceFactsPanel:{original:()=>undefined,cancel(){}}, investigationBeforeSelection(){}, location:{protocol:'http:'}, document:{querySelector:()=>({hidden:true})},
    renderSources(){}, renderSourceHealth(){}, renderShellStatus(){}, renderFingerprintActivity(){},
    runtimeHooksState:()=>({workers:[], isolated:true, target_id:state.debuggerSession?.target?.id}),
    sourceName:source=>source.url, nativeCanvasCaptureDisplayLimit:4, evidencePackagePanel:{sync(){}}, evidenceWorkspace:{sync(){}},
    ...patch, state};
  return {state, sandbox, api:runInNewContext(ownershipModels + ownershipSyntax + ownershipProvenanceSite + ownershipFunctionNames.map(sourceProductionFunction).join('\n') +
    `;({${ownershipFunctionNames.join(',')},revealProvenanceSite})`, sandbox)};
}
const sourceOwnershipReceipt = [];
const ownedDeferred = () => {let resolve; const promise = new Promise(done=>{resolve=done;}); return {promise,resolve};};
{
  const artifact=await ownedArtifact('1'), added=await ownedArtifact('2'), held=ownedDeferred(); let reads=0;
  const {state,api}=ownedContext({state:{artifacts:[artifact],openArtifactIds:['1'],selectedArtifactId:'1'},
    fetch:async url=>url.startsWith('/api/artifacts?') ? Response.json({count:2,artifacts:[{...artifact,loading:undefined},added]}) : (reads++,held.promise)});
  const pending=api.loadArtifactContent(artifact); assert(artifact.loading);
  await api.refreshArtifacts(); assert.equal(state.artifacts[0],artifact,'Refresh must preserve its pending owner');
  held.resolve(new Response('const a = 1;')); await pending;
  assert.equal(state.artifacts[0].content,'const a = 1;'); assert.equal(artifact.loading,false); assert.equal(reads,1);
  sourceOwnershipReceipt.push({test:'pending_refresh_owner',status:'passed',contentReads:reads});
}
{
  const old=await ownedArtifact('1'), newer=await ownedArtifact('1','const newer = 2;','2');
  const held=ownedDeferred(); let signal, reads=0;
  const {state,api}=ownedContext({state:{artifacts:[old],openArtifactIds:['1'],selectedArtifactId:'1'}, fetch:async (url,options)=>{
    if(url.startsWith('/api/artifacts?')) return Response.json({count:1,artifacts:[newer]});
    reads++; if(reads===1){signal=options.signal;return held.promise;} return new Response('const newer = 2;');
  }});
  const pending=api.loadArtifactContent(old); await api.refreshArtifacts(); assert(signal.aborted);
  held.resolve(new Response('const a = 1;')); await pending;
  await new Promise(resolve=>setImmediate(resolve));
  // The newly selected owner may still be in WebCrypto; await only that owner.
  for(let i=0;i<50 && state.artifacts[0].loading;i++) await new Promise(resolve=>setTimeout(resolve,1));
  assert.equal(state.artifacts[0].session_id,'2'); assert.equal(state.artifacts[0].content,'const newer = 2;');
  assert.equal(old.content,undefined); assert.equal(reads,2);
  sourceOwnershipReceipt.push({test:'session_reuse_retires_late_preview',status:'passed'});
}
{
  const artifact=await ownedArtifact('1'); let reads=0, bytes='const b = 1;';
  const {state,api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},fetch:async()=>{reads++;return new Response(bytes);}});
  await api.loadArtifactContent(artifact); assert.match(artifact.loadError,/SHA-256/); assert.equal(artifact.content,undefined);
  await api.loadArtifactContent(artifact); assert.equal(reads,1,'No implicit retry');
  bytes='const a = 1;'; await api.loadArtifactContent(artifact,{retry:true}); assert.equal(artifact.content,bytes);
  api.closeSource({...artifact,source_type:'artifact'}); assert.equal(artifact.content,undefined);
  assert.equal(artifact.sha256,await ownershipHash(bytes)); assert.equal(state.artifacts.length,1);
  sourceOwnershipReceipt.push({test:'wrong_preview_hash_explicit_retry_preserves_descriptor',status:'passed'});
}
{
  const original='\ufeffconst 雪 = "😀";\r\n雪;'; const artifact=await ownedArtifact('1',original); artifact.content=original;
  let payload=ownedPayload(artifact,original);
  const {state,api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},fetch:async()=>Response.json(payload)});
  await api.loadDeobfuscation(api.selectedSource()); const key=api.deobfuscationKey(api.selectedSource());
  assert.equal(state.deobfuscationRequests.get(key).status,'ready'); const successful=state.deobfuscationCache.get(key);
  const malformed = [value=>{value.artifact_id='999';}, value=>{value.analysis.source.sha256='b'.repeat(64);},
    value=>{value.original_source=original.replace('const','throw');}, value=>{value.analysis.source.byte_size++;},
    value=>{value.mode='analysis';}, value=>{value.source_truncated=true;}, value=>{value.analysis.assumptions=['standard-intrinsics'];},
    value=>{value.representation.segments[0].original_start=1;}, value=>{value.representation.segments=[];},
    value=>{value.representation.text='other';}, value=>{value.analysis.omissions={};},
    value=>{value.analysis.classification={evidence:[null]};},value=>{value.analysis.string_tables=[null];}];
  for(const corrupt of malformed) {
    payload=structuredClone(successful);corrupt(payload); await api.loadDeobfuscation(api.selectedSource(),{retry:true});
    assert.equal(state.deobfuscationRequests.get(key).status,'error'); assert.equal(state.deobfuscationCache.get(key),successful);
    assert.equal(api.sourceDisplayView(api.selectedSource()).content,original); assert.match(api.sourceViewLabel(api.selectedSource()),/Original evidence preview/);
  }
  // Even a forged cache cannot replace the original-mode preview.
  state.deobfuscationCache.set(key,{...successful,original_source:'forged evidence'});
  assert.equal(api.sourceDisplayView(api.selectedSource()).content,original);
  sourceOwnershipReceipt.push({test:'deob_identity_hash_assumptions_map_original_separation',status:'passed',rejections:malformed.length});
}
{
  const text='const worker = 1;'; const script={script_id:'worker:7:1',target_id:'worker-7',target_type:'worker',hash:await ownershipHash(text),language:'JavaScript',length:text.length};
  const held=ownedDeferred(); let waiting=false, signal;
  const {state,api}=ownedContext({state:{debuggerSession:{target:{id:'page-1'},scripts:[script]},selectedScriptId:script.script_id,openScriptIds:[script.script_id]},
    fetch:async(url,options)=>{signal=options.signal;return url.startsWith('/api/debugger/source')
      ? Response.json({protocol_version:1,script_id:script.script_id,source:text,truncated:false})
      : waiting ? held.promise : Response.json(ownedPayload(api.liveSources()[0],text));}});
  await api.loadScriptContent({...script,source_type:'script',kind:'javascript'});
  await api.loadDeobfuscation(api.liveSources()[0]); assert.equal(api.liveSources()[0].deobfuscation.original_source,text);
  waiting=true;const pending=api.loadDeobfuscation(api.liveSources()[0],{retry:true});
  const payload=ownedPayload(api.liveSources()[0],text); api.closeSource(api.liveSources()[0]); assert(signal.aborted);
  held.resolve(Response.json(payload)); await pending; assert.equal(state.deobfuscationCache.size,0);
  assert.equal(state.deobfuscationRequests.size,0);
  sourceOwnershipReceipt.push({test:'worker_target_analysis_and_closed_reply_retirement',status:'passed'});
}
{
  const artifact=await ownedArtifact('1'); const held=ownedDeferred(); const {state,api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},fetch:async()=>held.promise});
  const pending=api.loadDeobfuscation(api.selectedSource());
  state.artifacts=[{...artifact,session_id:'99'}];
  held.resolve(Response.json(ownedPayload(artifact,'const a = 1;'))); await pending;
  assert.equal(state.deobfuscationCache.size,0);
  sourceOwnershipReceipt.push({test:'late_analysis_new_session_same_id_hash_rejected',status:'passed'});
}
{
  const source={script_id:'7',target_id:'new-page',hash:'b'.repeat(64),source_type:'script',start_line:0,start_column:0,url:'fixture.js'};
  const elements=Object.fromEntries(['hooksScript','hooksEntryMode','hooksLine','hooksColumn','hooksLabel'].map(key=>[key,{value:''}]));
  const {state,api}=ownedContext({state:{debuggerSession:{target:{id:'new-page'},scripts:[source]},sourceCursor:{scriptId:'7',line:90,column:31}},elements});
  const variants=[{scriptId:'7',line:90,column:31}, {identity:api.sourceIdentity({...source,target_id:'old-page'}),representation:'original',line:90,column:31},
    {identity:api.sourceIdentity({...source,hash:'a'.repeat(64)}),representation:'original',line:90,column:31},
    {identity:api.sourceIdentity(source),representation:'derived',line:90,column:31}];
  for(const cursor of variants){state.sourceCursor=cursor;assert(api.prefillHookFromSource(source));assert.equal(elements.hooksLine.value,'1');assert.equal(elements.hooksColumn.value,'1');}
  state.sourceCursor={identity:api.sourceIdentity(source),representation:'original',line:90,column:31};
  assert(api.prefillHookFromSource(source));assert.equal(elements.hooksLine.value,'91');
  sourceOwnershipReceipt.push({test:'cursor_target_hash_representation_binding',status:'passed',rejections:variants.length});
}
{
  const artifacts=await Promise.all(Array.from({length:25},(_,index)=>ownedArtifact(String(index+1))));
  for(const artifact of artifacts) artifact.content='const a = 1;';
  const {state,api}=ownedContext({state:{artifacts,openArtifactIds:artifacts.map(value=>value.artifact_id),selectedArtifactId:'25'},fetch:async()=>new Response('const a = 1;')});
  for(const artifact of artifacts) api.closeSource({...artifact,source_type:'artifact'});
  assert.equal(state.openArtifactIds.length,0); assert.equal(artifacts.filter(value=>value.content!==undefined).length,0);
  assert.equal(artifacts.length,25);assert(artifacts.every(value=>value.sha256));
  const script={script_id:'7',target_id:'page-1',hash:'a'.repeat(64),language:'JavaScript',kind:'javascript',source_type:'script'};
  const held=ownedDeferred();let signal; const live=ownedContext({state:{debuggerSession:{target:{id:'page-1'},scripts:[script]},openScriptIds:['7'],selectedScriptId:'7'},
    fetch:async(url,options)=>{signal=options.signal;return held.promise;}});
  const pending=live.api.loadScriptContent(script); live.api.closeSource(script); assert(signal.aborted);
  held.resolve(Response.json({protocol_version:1,script_id:'7',source:'closed-source retained',truncated:false})); await pending;
  assert.equal(live.state.liveScriptContent.size,0);
  sourceOwnershipReceipt.push({test:'close_25_previews_and_pending_live_read',status:'passed',retainedPreviews:0,retainedDescriptors:25});
}
{
  const text='x'.repeat(2097152), artifacts=await Promise.all(Array.from({length:12},(_,index)=>ownedArtifact(String(index+1),text)));
  const {state,api}=ownedContext({state:{artifacts,openArtifactIds:artifacts.map(value=>value.artifact_id)},fetch:async()=>new Response(text)});
  for(const artifact of artifacts){state.selectedArtifactId=artifact.artifact_id;await api.loadArtifactContent(artifact);}
  const loaded=artifacts.filter(value=>value.content!==undefined), characters=loaded.reduce((sum,value)=>sum+value.content.length,0);
  assert(loaded.length<=8 && characters<=8*1024*1024); assert.equal(artifacts[0].content,undefined);
  state.selectedArtifactId='1';await api.loadArtifactContent(artifacts[0]);assert.equal(artifacts[0].content,text);
  const binary=new Uint8Array(2097152);const wasm={...await ownedArtifact('99'),kind:'wasm',mime_type:'application/wasm',byte_size:binary.length,sha256:await ownershipHash(binary)};
  const hex=ownedContext({state:{artifacts:[wasm],selectedArtifactId:'99'},fetch:async()=>new Response(binary)});
  await hex.api.loadArtifactContent(wasm); assert(wasm.content.split('\n').length<=20003);assert(wasm.content.length<2*1024*1024);assert(wasm.contentTruncated);
  sourceOwnershipReceipt.push({test:'preview_byte_budget_and_bounded_hex',status:'passed',retainedPreviews:loaded.length,retainedUTF16TextBytes:characters*2,hexRows:wasm.content.split('\n').length});
}
{
  const artifact=await ownedArtifact('1');artifact.content='const a = 1;';let reads=0;
  const {state,api}=ownedContext({state:{artifacts:[artifact]},fetch:async()=>{reads++;return new Response('const a = 1;');}});
  const identity={type:'captured-artifact',session:artifact.session_id,artifact:'1',sha256:artifact.sha256,bytes:artifact.byte_size};
  for(const wrong of [{...identity,session:'2'},{...identity,sha256:'b'.repeat(64)},{...identity,bytes:1}]) {
    assert.equal(api.selectArtifact('1',null,{passive:true,identity:wrong}),false);assert.equal(state.selectedArtifactId,null);
  }
  assert.equal(api.selectArtifact('1',null,{passive:true,identity}),true);assert.equal(state.selectedArtifactId,'1');assert.equal(reads,0);
  state.artifacts.push({...artifact,session_id:'2'});assert.equal(api.selectArtifact('1',null,{identity}),false);
  assert.equal(api.selectedSource(),null);assert.equal(reads,0);
  sourceOwnershipReceipt.push({test:'exact_passive_artifact_entry_and_global_ambiguity',status:'passed'});
}
{
  const artifact=await ownedArtifact('1'), held=ownedDeferred(),timers=new Map();let sequence=0,reads=0,signal;
  const {api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},
    setTimeout(callback,delay){const id=++sequence;timers.set(id,{callback,delay});return id;},clearTimeout(id){timers.delete(id);},
    fetch:async(url,options)=>{reads++;signal=options.signal;return reads===1?held.promise:new Response('const a = 1;');}});
  const old=api.loadArtifactContent(artifact);const timer=[...timers.values()][0];assert.equal(timer.delay,10000);timer.callback();
  assert(signal.aborted);assert.equal(artifact.loading,false);assert.match(artifact.loadError,/timed out/);
  await api.loadArtifactContent(artifact,{retry:true});assert.equal(artifact.content,'const a = 1;');
  held.resolve(new Response('old wrong content'));await old;assert.equal(artifact.content,'const a = 1;');assert.equal(timers.size,0);
  sourceOwnershipReceipt.push({test:'preview_deadline_late_headers_explicit_retry',status:'passed'});
}
{
  const artifact=await ownedArtifact('1');artifact.content='const a = 1;';
  const digest=ownedDeferred(),timers=new Map();let sequence=0,hashes=0;
  const realHash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(artifact.content));
  const {state,api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},
    crypto:{subtle:{digest(){hashes++;return hashes===1?digest.promise:Promise.resolve(realHash);}}},
    setTimeout(callback,delay){const id=++sequence;timers.set(id,{callback,delay});return id;},clearTimeout(id){timers.delete(id);},
    fetch:async()=>Response.json(ownedPayload(artifact,'const a = 1;'))});
  const old=api.loadDeobfuscation(api.selectedSource());for(let i=0;i<50&&!hashes;i++)await new Promise(resolve=>setImmediate(resolve));assert.equal(hashes,1);
  const key=api.deobfuscationKey(api.selectedSource());[...timers.values()][0].callback();
  assert.equal(state.deobfuscationRequests.get(key).status,'error');assert.match(state.deobfuscationRequests.get(key).error,/timed out/);
  await api.loadDeobfuscation(api.selectedSource(),{retry:true});const newer=state.deobfuscationCache.get(key);assert(newer);
  digest.resolve(realHash);await old;assert.equal(state.deobfuscationCache.get(key),newer);assert.equal(timers.size,0);
  sourceOwnershipReceipt.push({test:'analysis_deadline_late_crypto_cannot_replace_retry',status:'passed'});
}
{
  const artifact=await ownedArtifact('1'); const {api}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:'1'},
    fetch:async()=>new Response(new Uint8Array(2097153))});
  await api.loadArtifactContent(artifact);assert.equal(artifact.content,undefined);assert.match(artifact.loadError,/byte limit/);
  sourceOwnershipReceipt.push({test:'preview_reader_rejects_oversized_body_before_decode',status:'passed'});
}
{
  const text='const snow = "雪😀";'; const utf8=await ownershipHash(text),utf16=await ownershipHash(Buffer.from(text,'utf16le'));
  assert.notEqual(utf8,utf16);
  const script={script_id:'worker:hash:1',target_id:'worker-hash',target_type:'worker',hash:utf16,language:'JavaScript',length:text.length,source_type:'script',kind:'javascript'};
  const payload=ownedPayload(script,text);payload.analysis.source.sha256=utf8;
  const {state,api}=ownedContext({state:{debuggerSession:{target:{id:'page'},scripts:[script]},selectedScriptId:script.script_id},
    fetch:async url=>url.startsWith('/api/deobfuscation')?Response.json(payload):Response.json({protocol_version:1,script_id:script.script_id,source:text,truncated:false})});
  await api.loadScriptContent(script);assert.equal(state.liveScriptContent.get(script.script_id).content,text);
  await api.loadDeobfuscation(api.selectedSource());assert.equal(api.selectedSource().deobfuscation.original_source,text);
  assert.equal(api.selectedSource().hash,utf16);assert.equal(api.selectedSource().deobfuscation.analysis.source.sha256,utf8);
  sourceOwnershipReceipt.push({test:'opaque_cdp_owner_and_analyzer_utf8_hashes_remain_distinct',status:'passed'});
}
{
  const artifact=await ownedArtifact('1');const source={...artifact,source_type:'artifact',content:'retained preview',deobfuscation:{original_source:'retained analysis'},controller:new AbortController()};
  const {api}=ownedContext();const reference=api.sourceReference(source);
  assert.equal(api.sourceIdentity(reference),api.sourceIdentity(source));
  for(const field of ['content','deobfuscation','controller'])assert.equal(Object.hasOwn(reference,field),false);
  sourceOwnershipReceipt.push({test:'ui_source_references_do_not_retain_evicted_payloads',status:'passed'});
}
{
  const text='const hook = 1;',script={script_id:'7',target_id:'page-1',hash:await ownershipHash(text),language:'JavaScript',length:text.length,start_line:0,start_column:0,url:'https://fixture.invalid/same.js'};
  let focused=0;const callbacks=[];
  const {state,api}=ownedContext({state:{debuggerSession:{target:{id:'page-1'},scripts:[script]}},
    showScreen(){},openSourceHooks(){},renderRuntimeHooks(){},requestAnimationFrame(callback){callbacks.push(callback);},
    document:{querySelector:()=>({hidden:false})},elements:{sourcePosition:{},sourceCodeWrap:{focus(){focused++;}}},
    fetch:async()=>Response.json({protocol_version:1,script_id:'7',source:text,truncated:false})});
  api.revealRuntimeHookHit({target_id:'page-1',source:script.url,line:90,column:31});
  assert.equal(state.selectedScriptId,null);assert.match(state.experimentError,/URL match cannot/);assert.equal(state.sourceCursor,undefined);
  api.revealRuntimeHookHit({target_id:'page-1',script_id:'7',source_hash:script.hash,line:2,column:3});
  assert.equal(state.selectedScriptId,'7');assert.equal(state.sourceCursor.identity,api.sourceIdentity(api.selectedSource()));
  state.selectedScriptId=null;callbacks[0]();assert.equal(focused,0);
  sourceOwnershipReceipt.push({test:'hook_hit_requires_target_script_hash_and_late_focus_owner',status:'passed'});
}
// Minimal DOM fixture checks identity-stable remount avoidance and actual tab
// handlers. Real keyboard, hit-testing and geometry remain the browser gate.
{
  let active=null, searches=0, renders=0;let api;
  class Node {
    constructor(tag='div'){this.tagName=tag;this.children=[];this.attributes={};this.listeners={};this.dataset={};this.scrollLeft=0;this.scrollTop=0;this.textContent='';this.hidden=false;this.classList={contains:()=>false,add(){},toggle(){}};}
    setAttribute(key,value){this.attributes[key]=value;}getAttribute(key){return this.attributes[key];}
    append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.children=nodes;renders++;}
    contains(node){return this===node || this.children.some(child=>child.contains?.(node));}
    addEventListener(key,callback){(this.listeners[key]??=[]).push(callback);}getBoundingClientRect(){return{left:0,right:500};}
    focus(){active=this;}querySelector(selector){return selector==='[aria-selected="true"]'?this.children.find(node=>node.attributes['aria-selected']==='true'):null;}
  }
  const artifact=await ownedArtifact('1','a\nb\nc'),second=await ownedArtifact('2','second');artifact.content='a\nb\nc';second.content='second';
  const elements=Object.fromEntries(['sourceLanguage','sourceCode','sourceCodeEmpty','sourceCodeWrap','sourceEditorTabs','sourceTree'].map(key=>[key,new Node()]));
  const doc={createElement:tag=>new Node(tag),querySelector:()=>({hidden:false}),get activeElement(){return active;}};
  const context=ownedContext({state:{artifacts:[artifact,second],openArtifactIds:['1','2'],selectedArtifactId:'1'},elements,document:doc,
    renderSources(){api?.renderSourceTabs();},updateSourceDecorations(){},appendSourceSyntax(node,tokens){node.textContent=tokens.map(value=>value.text).join('');},
    applySourceSearch(){searches++;},memoryOriginTraceActive:()=>false,fetch:async()=>new Response('a\nb\nc')});api=context.api;
  const source=api.selectedSource();api.renderSourceContent(source,{content:source.content,lineMap:null});const row=elements.sourceCode.children[0];
  elements.sourceCodeWrap.scrollTop=713;elements.sourceCodeWrap.scrollLeft=143;context.state.sourceSearchIndex=3;const oldRenders=renders,oldSearches=searches;
  api.renderSourceContent(api.selectedSource(),{content:source.content,lineMap:null});assert.equal(elements.sourceCode.children[0],row);
  assert.equal(elements.sourceCodeWrap.scrollTop,713);assert.equal(elements.sourceCodeWrap.scrollLeft,143);assert.equal(context.state.sourceSearchIndex,3);
  assert.equal(renders,oldRenders);assert.equal(searches,oldSearches);
  api.renderSourceTabs();elements.sourceEditorTabs.children[0].focus();
  const press=key=>active.listeners.keydown[0]({key,preventDefault(){}});
  press('ArrowRight');assert.equal(context.state.selectedArtifactId,'2');assert.equal(active.getAttribute('aria-selected'),'true');
  press('Home');assert.equal(context.state.selectedArtifactId,'1');press('End');assert.equal(context.state.selectedArtifactId,'2');
  press('Delete');assert.equal(context.state.openArtifactIds.length,1);assert.equal(context.state.selectedArtifactId,'1');assert.equal(second.content,undefined);
  sourceOwnershipReceipt.push({test:'same_view_scroll_find_dom_retained_keyboard_tabs',status:'passed',scrollTop:713,findOccurrence:3});
}
// Corrective integration regressions from independent review. These use the
// actual renderer, decoration updater, cursor receiver and Field trace pivot.
class SourceReviewNode {
  constructor(tag='div',doc){this.tagName=tag;this.doc=doc;this.children=[];this.attributes={};this.listeners={};this.dataset={};this.scrollLeft=0;this.scrollTop=0;this.hidden=false;this._text='';this.classes=new Set();this.classList={add:value=>this.classes.add(value),contains:value=>this.classes.has(value),toggle:(value,on)=>on?this.classes.add(value):this.classes.delete(value)};this.style={setProperty(){}};}
  set className(value){this.classes=new Set(value.split(' '));}get className(){return [...this.classes].join(' ');}
  get textContent(){return this._text+this.children.map(node=>node.textContent??'').join('');}set textContent(value){this._text=value;this.children=[];}
  setAttribute(key,value){this.attributes[key]=value;}getAttribute(key){return this.attributes[key];}
  append(...nodes){for(let node of nodes){if(typeof node==='string')node=this.doc.createTextNode(node);node.parent=this;this.children.push(node);}}replaceChildren(...nodes){this._text='';this.children=[];this.append(...nodes);}
  contains(node){return this===node||this.children.some(child=>child.contains?.(node));}addEventListener(key,callback){(this.listeners[key]??=[]).push(callback);}
  getBoundingClientRect(){return {left:0,right:500};}focus(){this.doc.activeElement=this;}scrollIntoView(){}
  matches(selector){if(selector==='[data-deob-control]')return this.dataset.deobControl!==undefined;if(selector==='[aria-selected="true"]')return this.attributes['aria-selected']==='true';if(selector==='.source-line[data-line]')return this.classes.has('source-line')&&this.dataset.line!==undefined;if(selector==='.source-line.current')return this.classes.has('source-line')&&this.classes.has('current');if(selector.startsWith('.'))return this.classes.has(selector.slice(1));return this.tagName===selector;}
  querySelectorAll(selector){return this.children.flatMap(node=>[...(node.matches?.(selector)?[node]:[]),...(node.querySelectorAll?.(selector)??[])]);}querySelector(selector){return this.querySelectorAll(selector)[0]??null;}closest(selector){return this.matches(selector)?this:this.parent?.closest(selector);}
}
function sourceReviewDOM() {
  const document={activeElement:null,querySelector:()=>({hidden:false})};
  document.createElement=tag=>new SourceReviewNode(tag,document);
  document.createTextNode=text=>{const node=new SourceReviewNode('text',document);node.textContent=text;return node;};
  const elements=Object.fromEntries(['sourceLanguage','sourceCode','sourceCodeEmpty','sourceCodeWrap','sourceEditorTabs','sourceTree','sourcePosition','deobfuscationReport','deobfuscationIntrinsics'].map(key=>[key,new SourceReviewNode('div',document)]));
  return {document,elements};
}
{
  const original='const a=1; const b=2;',artifact=await ownedArtifact('map-complete',original);
  const {api}=ownedContext();
  for(const [text,segments] of [
    ['const b=2;',[{kind:'verbatim',original_start:11,original_end:21,derived_start:0,derived_end:10}]],
    ['const a=1;',[{kind:'verbatim',original_start:0,original_end:10,derived_start:0,derived_end:10}]],
    ['(3)',[{kind:'replacement',original_start:0,original_end:0,derived_start:0,derived_end:3}]],
  ]) {
    const payload=ownedPayload(artifact,original);payload.representation.text=text;payload.representation.segments=segments;
    await assert.rejects(api.validateSourceAnalysis(payload,{...artifact,source_type:'artifact'},false),/source map/);
  }
  sourceOwnershipReceipt.push({test:'deob_complete_original_map_no_implicit_deletion_or_zero_width_replacement',status:'passed'});
}
// Changed-span inspection uses production admission, controller and DOM code.
// These fixtures never execute analyzed JavaScript and are not rendered QA.
function ownedDerivedPayload(source, original, replacements) {
  const payload=ownedPayload(source,original), segments=[];let cursor=0,derived='';
  const append=(kind,start,end,text)=>{const begin=Buffer.byteLength(derived);derived+=text;segments.push({kind,original_start:Buffer.byteLength(original.slice(0,start)),original_end:Buffer.byteLength(original.slice(0,end)),derived_start:begin,derived_end:Buffer.byteLength(derived)});};
  for(const [before,after] of replacements){const start=original.indexOf(before,cursor);assert(start>=cursor);if(start>cursor)append('verbatim',cursor,start,original.slice(cursor,start));append('replacement',start,start+before.length,after);cursor=start+before.length;}
  if(cursor<original.length)append('verbatim',cursor,original.length,original.slice(cursor));
  payload.representation={text:derived,offset_unit:'utf-8-byte',segments,truncated:false};
  payload.analysis.representation={status:'derived',derived_bytes:Buffer.byteLength(derived),segment_count:segments.length,truncated:false,transformations:replacements.map((_,index)=>({id:`fixture-family-${index}`,kind:'rewrite',count:1,detail:'Authored aggregate fixture; no per-change rule.'}))};
  return payload;
}
{
  const original='\ufeffconst 雪="😀";'+Array.from({length:7},(_,i)=>`const v${i}=1+${i};`).join('');
  const artifact=await ownedArtifact('inspector',original);artifact.content=original;
  let payload=ownedDerivedPayload(artifact,original,Array.from({length:7},(_,i)=>[`1+${i}`,`(${i+1})`]));
  payload.analysis.omissions=['Generic unsupported operations remain unresolved.'];
  payload.analysis.limits={max_source_bytes:4194304,max_transformations:4096};
  payload.analysis.classification={label:'minified',confidence:95,evidence:[{id:'fixture-signal',detail:'Heuristic fixture signal'}]};
  payload.analysis.string_tables=Array.from({length:5},(_,i)=>({kind:`table-${i+1}`,offset:0,entry_count:8,encodings:['literal'],decoded_preview:'<script>inert</script>'}));
  const {document,elements}=sourceReviewDOM();let api;
  const ctx=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id,sourceDeobfuscated:true},document,elements,
    formatByteSize:value=>`${value} bytes`,renderSources(){api?.renderDeobfuscationReport(api.selectedSource());},fetch:async()=>Response.json(payload)});api=ctx.api;
  await api.loadDeobfuscation(api.selectedSource());const source=api.selectedSource(),key=api.deobfuscationKey(source),good=ctx.state.deobfuscationCache.get(key),report=elements.deobfuscationReport;
  assert.equal(ctx.state.deobfuscationRequests.get(key).status,'ready');
  assert.equal(good.sourceInspection.changes.length,7);assert.equal(good.sourceInspection.changes[0].original_start,original.indexOf('1+0'));
  assert.match(report.textContent,/7 changed spans/);assert.match(report.textContent,/7 reported rewrites/);assert(!report.textContent.includes('confidence 95'));
  assert.match(report.textContent,/Recovered tables \(5\)/);assert(report.textContent.includes('table-4'));assert(!report.textContent.includes('table-5'));
  assert.equal(report.querySelectorAll('script').length,0);assert(report.textContent.includes('<script>inert</script>'));
  const control=key=>report.querySelectorAll('[data-deob-control]').find(node=>node.dataset.deobControl===key);
  const click=async key=>{const node=control(key);assert(node && !node.disabled,key);node.focus();await node.listeners.click[0]();};
  const originalNode=report.querySelectorAll('pre')[0];originalNode.scrollLeft=77;report.scrollTop=43;originalNode.focus();
  api.renderDeobfuscationReport(api.selectedSource());assert.equal(report.querySelectorAll('pre')[0],originalNode);assert.equal(originalNode.scrollLeft,77);assert.equal(document.activeElement,originalNode);
  const tables=report.querySelectorAll('details').find(node=>node.querySelector('summary').textContent.startsWith('Recovered tables'));
  tables.open=true;await click('tables-next'); // Native toggle delivery may still be queued.
  assert(report.textContent.includes('table-5'));assert(!report.textContent.includes('table-1'));
  assert.equal(report.querySelectorAll('details').find(node=>node.querySelector('summary').textContent.startsWith('Recovered tables')).open,true);
  tables.open=false;tables.listeners.toggle[0]({currentTarget:tables});assert.equal(good.inspectorView.open.tables,true,'Detached queued toggle must not overwrite the current disclosure');
  await click('transformations-next');assert(report.textContent.includes('fixture-family-6'));assert(!report.textContent.includes('fixture-family-0'));
  await click('change-next');assert.match(report.textContent,/Change 2 of 7/);assert.equal(document.activeElement.dataset.deobControl,'change-next');assert.equal(report.scrollTop,43);
  for(let i=0;i<5;i++)await click('change-next');assert.equal(document.activeElement.dataset.deobControl,'change-previous');
  ctx.state.deobfuscationRequests.set(key,{status:'error',error:'Authored retry failure'});api.renderDeobfuscationReport(api.selectedSource());
  assert.match(report.textContent,/Authored retry failure/);assert.match(report.textContent,/Last successful report remains below/);assert.equal(report.querySelectorAll('pre').length,2);
  assert.equal(api.sourceDisplayView(api.selectedSource()).content,good.representation.text);
  const corruptions=[
    value=>{value.representation.segments.shift();value.representation.text=value.representation.text.slice(good.sourceInspection.changes[0].derived_start);},
    value=>{const last=value.representation.segments.pop();value.representation.text=value.representation.text.slice(0,last.derived_start);},
    value=>{value.representation.segments[1].original_end=value.representation.segments[1].original_start;},
    value=>{value.analysis.representation.transformations[0].count++;},
    value=>{value.representation.transformations=[{id:'claimed',count:9999,detail:'Untrusted claim'}];},
    value=>{value.analysis.limits={max_source_bytes:'unbounded'};},
    value=>{value.engine='unknown-engine';},
    value=>{value.representation.segments[0].original_end=1;},
  ];
  for(const corrupt of corruptions){payload=structuredClone(good);corrupt(payload);await api.loadDeobfuscation(api.selectedSource(),{retry:true});assert.equal(ctx.state.deobfuscationRequests.get(key).status,'error');assert.equal(ctx.state.deobfuscationCache.get(key),good);}
  // A stale control must not affect a fresh owner with different assumption mode.
  const stale=control('retry');ctx.state.deobfuscationAssumeIntrinsics=true;const before=ctx.state.deobfuscationRequests.size;await stale.listeners.click[0]();assert.equal(ctx.state.deobfuscationRequests.size,before);
  api.releaseSourcePreview(source);ctx.state.selectedArtifactId=null;api.renderDeobfuscationReport(null);assert.equal(report.deobfuscationRender,null);assert.equal(report.querySelectorAll('pre').length,0);
  sourceOwnershipReceipt.push({test:'deob_changed_spans_unicode_paging_inert_reports_focus_retry_and_admission',status:'passed',changes:7,tables:5,corruptions:corruptions.length});
}
{
  const original='const result=1+2;',artifact=await ownedArtifact('deob-cancel',original);artifact.content=original;
  const gate=ownedDeferred();let calls=0;
  const {api,state}=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},fetch:async()=>{calls++;await gate.promise;return Response.json(ownedDerivedPayload(artifact,original,[['1+2','(3)']]));}});
  const source=api.selectedSource(),key=api.deobfuscationKey(source),pending=api.loadDeobfuscation(source),request=state.deobfuscationRequests.get(key);
  api.cancelDeobfuscation(source,request);assert.equal(request.status,'cancelled');await api.loadDeobfuscation(source);assert.equal(calls,1);
  const newer=api.loadDeobfuscation(source,{retry:true}),newRequest=state.deobfuscationRequests.get(key);api.cancelDeobfuscation(source,request);assert.equal(newRequest.status,'loading');api.cancelDeobfuscation(source,newRequest);
  gate.resolve();await Promise.all([pending,newer]);assert.equal(state.deobfuscationCache.size,0);assert.equal(request.status,'cancelled');
  const second=ownedDeferred();const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(original));let hashing=false;
  const hashCtx=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},crypto:{subtle:{digest(){hashing=true;return second.promise;}}},fetch:async()=>Response.json(ownedDerivedPayload(artifact,original,[['1+2','(3)']]))});
  const hashPending=hashCtx.api.loadDeobfuscation(hashCtx.api.selectedSource());for(let i=0;i<20&&!hashing;i++)await new Promise(resolve=>setTimeout(resolve,1));assert(hashing);
  hashCtx.api.cancelDeobfuscation(hashCtx.api.selectedSource());second.resolve(hash);await hashPending;assert.equal(hashCtx.state.deobfuscationCache.size,0);
  sourceOwnershipReceipt.push({test:'deob_explicit_cancel_late_body_and_digest_no_implicit_retry',status:'passed'});
}
{
  const original='const result="'+('x'.repeat(2047))+'😀'+('y'.repeat(64))+'";',artifact=await ownedArtifact('101',original);artifact.content=original;
  const before=original.slice(13,-1),payload=ownedDerivedPayload(artifact,original,[[before,'("short")']]);
  const {document,elements}=sourceReviewDOM();const navigated=[];
  const context=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},document,elements,formatByteSize:String,
    sourceFactsPanel:{original:()=>undefined,cancel(){},model:{status:'ready',error:''},navigate:async range=>navigated.push(range)},fetch:async()=>Response.json(payload)});
  await context.api.loadDeobfuscation(context.api.selectedSource());context.api.renderDeobfuscationReport(context.api.selectedSource());
  const report=elements.deobfuscationReport,pre=report.querySelectorAll('pre')[0];assert(pre.textContent.length<=2048);assert(!/[\uD800-\uDBFF]$/.test(pre.textContent));assert.match(report.textContent,/Snippet shows/);
  const good=context.api.selectedSource().deobfuscation;await context.api.revealDeobfuscationChange(context.api.selectedSource(),good.inspectorView);
  assert.equal(navigated.length,1);assert.equal(navigated[0].start,payload.representation.segments[1].original_start);assert.equal(navigated[0].end,payload.representation.segments[1].original_end);
  sourceOwnershipReceipt.push({test:'deob_bounded_snippet_and_verified_original_range_handoff',status:'passed'});
}

{
  for (const action of ['option','replacement','selection','eviction']) {
    const original='const result=1+2;',artifact=await ownedArtifact('102',original);artifact.content=original;
    const payload=ownedDerivedPayload(artifact,original,[['1+2','(3)']]),gate=ownedDeferred();let navigations=0;
    const {document,elements}=sourceReviewDOM();
    const ctx=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},document,elements,formatByteSize:String,fetch:async()=>Response.json(payload)});
    await ctx.api.loadDeobfuscation(ctx.api.selectedSource());const source=ctx.api.selectedSource(),good=source.deobfuscation,view=good.inspectorView,key=ctx.api.deobfuscationKey(source);
    const facts=sourceFactsUI.createSourceFactsController({getSource:ctx.api.selectedSource,protocol:'http:',onChange(){},onNavigate(){navigations++;},cryptoApi:crypto,
      fetcher:async()=>{await gate.promise;return new Response(original,{headers:{'X-Artifact-Total-Bytes':String(Buffer.byteLength(original)),'X-Artifact-Offset':'0','X-Artifact-Truncated':'false'}});}});
    ctx.sandbox.sourceFactsPanel=facts;
    const pending=ctx.api.revealDeobfuscationChange({...source,deobfuscationAssumption:false},view);assert(view.revealing);
    if(action==='option')ctx.state.deobfuscationAssumeIntrinsics=true;
    if(action==='replacement')ctx.state.deobfuscationCache.set(key,{...good,inspectorView:{change:0,pages:{},open:{},notice:''}});
    if(action==='selection')ctx.api.updateDeobfuscationView(source,view,'changes',1);
    if(action==='eviction')ctx.api.releaseSourcePreview(source);
    gate.resolve();await pending;assert.equal(navigations,0,action);assert.equal(view.revealing,false,action);assert.notEqual(facts.model.status,'loading-source',action);
  }
  sourceOwnershipReceipt.push({test:'deob_reveal_guard_before_real_facts_navigation_option_report_selection_eviction',status:'passed'});
}
{
  const original='const result=1+2;',artifact=await ownedArtifact('103',original);artifact.content=original;
  const payload=ownedDerivedPayload(artifact,original,[['1+2','(3)']]),oldGate=ownedDeferred(),factsGate=ownedDeferred();let factsSignal;
  const dom=sourceReviewDOM();
  const ctx=ownedContext({...dom,formatByteSize:String,state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},fetch:async()=>Response.json(payload)});
  await ctx.api.loadDeobfuscation(ctx.api.selectedSource());const source=ctx.api.selectedSource(),view=source.deobfuscation.inspectorView;
  const facts=sourceFactsUI.createSourceFactsController({getSource:ctx.api.selectedSource,protocol:'http:',onChange(){},onNavigate(){throw Error('Retired reveal navigated');},cryptoApi:crypto,
    fetcher:async(url,options)=>{if(url.startsWith('/api/source-facts')){factsSignal=options.signal;await factsGate.promise;return Response.json({});}await oldGate.promise;return new Response(original);}});
  ctx.sandbox.sourceFactsPanel=facts;const old=ctx.api.revealDeobfuscationChange(source,view);facts.cancel();const unrelated=facts.load();assert(factsSignal&&!factsSignal.aborted);
  ctx.api.retireDeobfuscationReveal(view);assert.equal(factsSignal.aborted,false,'Retiring an old reveal must not cancel newer unrelated Facts work');
  facts.cancel();oldGate.resolve();factsGate.resolve();await Promise.all([old,unrelated]);
  sourceOwnershipReceipt.push({test:'deob_owned_reveal_cancellation_preserves_unrelated_facts',status:'passed'});
}

{
  for(const original of ['const value=1+2;','const 雪="😀";\nconst value=1+2;','\n'.repeat(20000)+'const value=1+2;']) {
    const script={script_id:'deob-live',target_id:'owned-page',hash:'opaque-token',language:'JavaScript',length:original.length,source_type:'script',kind:'javascript',start_line:4,start_column:2};
    const payload=ownedDerivedPayload(script,original,[['1+2','(3)']]);payload.analysis.source.sha256=await ownershipHash(original);
    const {document,elements}=sourceReviewDOM();elements.sourceSidebar=document.createElement('aside');elements.sourcePosition.textContent='Existing source position';
    const line=original.split('\n').length-1,row=document.createElement('span');row.className='source-line';row.dataset.line=String(5+line);elements.sourceCode.append(row);
    const ctx=ownedContext({state:{debuggerSession:{target:{id:'owned-page'},scripts:[script]},selectedScriptId:script.script_id,sourceDeobfuscated:true,sourceSidebarOpen:true},document,elements,formatByteSize:String,
      getComputedStyle:()=>({position:'absolute'}),renderSourceSidebar(){elements.sourceSidebar.hidden=!ctx.state.sourceSidebarOpen;},
      sourceFactsPanel:{original:()=>undefined,cancel(){},navigate(){throw Error('Live text must not use captured Facts');}},
      fetch:async url=>url.startsWith('/api/debugger/source')?Response.json({protocol_version:1,script_id:script.script_id,source:original,truncated:false}):Response.json(payload)});
    runInNewContext(sourceProductionFunction('revealOriginalLine'),ctx.sandbox);
    await ctx.api.loadScriptContent(script);await ctx.api.loadDeobfuscation(ctx.api.selectedSource());const good=ctx.api.selectedSource().deobfuscation;
    await ctx.api.revealDeobfuscationChange(ctx.api.selectedSource(),good.inspectorView);
    if(line>=20000){assert.match(good.inspectorView.notice,/20,000/);assert.equal(ctx.state.sourceDeobfuscated,true);assert.equal(elements.sourcePosition.textContent,'Existing source position');}
    else {assert.equal(document.activeElement,row);assert.equal(elements.sourceSidebar.hidden,true);assert.match(elements.sourcePosition.textContent,new RegExp(`Line ${5+line}, Column ${13+(line===0?2:0)}`));}
    ctx.state.debuggerSession.scripts=[{...script,target_id:'replacement-page'}];const before=document.activeElement;await ctx.api.revealDeobfuscationChange(script,good.inspectorView);assert.equal(document.activeElement,before);
  }
  const legacyOriginal='const x=1+2;',artifact=await ownedArtifact('deob-legacy',legacyOriginal);artifact.content=legacyOriginal;
  const legacy=ownedDerivedPayload(artifact,legacyOriginal,[['1+2','(3)']]);legacy.engine='python-lexical';legacy.representation.offset_unit='unicode-code-point';
  const {document,elements}=sourceReviewDOM();const legacyContext=ownedContext({state:{artifacts:[artifact],selectedArtifactId:artifact.artifact_id},document,elements,formatByteSize:String,fetch:async()=>Response.json(legacy)});
  await legacyContext.api.loadDeobfuscation(legacyContext.api.selectedSource());legacyContext.api.renderDeobfuscationReport(legacyContext.api.selectedSource());
  assert.match(elements.deobfuscationReport.textContent,/Legacy code-point map/);assert.equal(elements.deobfuscationReport.querySelectorAll('pre').length,0);
  assert.equal(legacyContext.api.selectedSource().deobfuscation.sourceInspection.byteRanges,false);
  const nativeArtifact=await ownedArtifact('104',legacyOriginal);nativeArtifact.content=legacyOriginal;const nativePayload=ownedDerivedPayload(nativeArtifact,legacyOriginal,[['1+2','(3)']]);
  const nativeDOM=sourceReviewDOM(),native=ownedContext({state:{artifacts:[nativeArtifact],selectedArtifactId:'104'},...nativeDOM,location:{protocol:'reb:'},formatByteSize:String,fetch:async()=>Response.json(nativePayload)});
  await native.api.loadDeobfuscation(native.api.selectedSource());native.api.renderDeobfuscationReport(native.api.selectedSource());
  assert.match(nativeDOM.elements.deobfuscationReport.textContent,/Unavailable in stored-evidence native mode/);assert.equal(nativeDOM.elements.deobfuscationReport.querySelectorAll('[data-deob-control]').find(node=>node.dataset.deobControl==='reveal').disabled,true);
  const empty=ownedPayload(nativeArtifact,legacyOriginal);empty.analysis.representation={transformations:[]};
  const emptyDOM=sourceReviewDOM(),emptyCtx=ownedContext({state:{artifacts:[nativeArtifact],selectedArtifactId:'104'},...emptyDOM,formatByteSize:String,fetch:async()=>Response.json(empty)});
  await emptyCtx.api.loadDeobfuscation(emptyCtx.api.selectedSource());emptyCtx.api.renderDeobfuscationReport(emptyCtx.api.selectedSource());assert.match(emptyDOM.elements.deobfuscationReport.textContent,/0 reported rewrites/);

  sourceOwnershipReceipt.push({test:'deob_owned_live_range_target_refusal_and_qualified_legacy_map',status:'passed'});
}

{
  const text='const a = 1;', script={script_id:'mapped',target_id:'page-1',hash:'opaque-mapped-version',language:'JavaScript',length:text.length,source_type:'script',kind:'javascript',start_line:0,start_column:0,content:text};
  for(const mode of ['pretty','derived']) {
    const {document,elements}=sourceReviewDOM();let navigation;
    const {api,state}=ownedContext({state:{debuggerSession:{target:{id:'page-1'},state:'running',scripts:[script]},selectedScriptId:script.script_id,sourceFormatted:mode==='pretty',sourceDeobfuscated:mode==='derived'},document,elements,
      appendSourceSyntax:(node,tokens)=>{node.textContent=tokens.map(value=>value.text).join('');},applySourceSearch(){},memoryOriginTraceActive:()=>false,
      revealOriginalLine:(source,line,column)=>{navigation={source,line,column};}});
    const view={content:text,lineMap:[{originalLine:0,originalColumn:4}],...(mode==='pretty'?{formatted:{}}:{derived:{}})};
    api.renderSourceContent(script,view);const gutter=elements.sourceCode.children[0].querySelector('.source-gutter');
    for(let refresh=0;refresh<3;refresh++){api.renderSourceContent(script,view);api.updateSourceDecorations();assert.equal(gutter.disabled,false);assert.equal(gutter.getAttribute('aria-label'),'Show original source at line 1');}
    gutter.listeners.click[0]({stopPropagation(){}});assert.equal(navigation.line,0);assert.equal(navigation.column,4);
    // The original-runtime branch still updates genuine breakpoint controls.
    state.sourceFormatted=false;state.sourceDeobfuscated=false;api.renderSourceContent(script,{content:text,lineMap:null});
    state.debuggerSession.breakpoints=[{script_id:'mapped',line:0,locations:[{script_id:'mapped',line:0}]}];api.updateSourceDecorations();
    assert.equal(elements.sourceCode.children[0].querySelector('.source-gutter').getAttribute('aria-label'),'Remove breakpoint on line 1');
  }
  sourceOwnershipReceipt.push({test:'review_mapped_live_gutters_survive_real_decoration_refresh',status:'passed',representations:['pretty','derived']});
}
{
  const text='a();\nb();\nc();',script={script_id:'field',target_id:'page-1',hash:'opaque-field-version',language:'JavaScript',length:text.length,start_line:0,start_column:0,url:'https://fixture.invalid/field.js'};
  const elements=Object.fromEntries(['hooksScript','hooksEntryMode','hooksLine','hooksColumn','hooksLabel','sourcePosition'].map(key=>[key,{value:''}]));
  const fieldProvenanceSelection={error:null};let screens=0;
  const {state,api}=ownedContext({state:{debuggerSession:{target:{id:'page-1'},state:'running',scripts:[script]}},elements,fieldProvenanceSelection,
    showScreen(){screens++;},renderFieldProvenance(){},fetch:async()=>Response.json({protocol_version:1,script_id:'field',source:text,truncated:false})});
  const site={script_id:'field',target_id:'page-1',source_hash:script.hash,line:2,column:3};
  api.revealProvenanceSite(site);assert.equal(elements.sourcePosition.textContent,'Line 3, Column 4');assert.equal(api.sourceCursorFor(api.selectedSource()).line,2);
  assert(api.prefillHookFromSource(api.selectedSource()));assert.equal(elements.hooksLine.value,'3');assert.equal(elements.hooksColumn.value,'4');assert.equal(screens,1);
  state.debuggerSession.scripts.push({...script,target_id:'other-page'});state.selectedScriptId=null;state.sourceCursor=null;
  api.revealProvenanceSite(site);assert.match(fieldProvenanceSelection.error,/ambiguous/);assert.equal(state.selectedScriptId,null);assert.equal(state.sourceCursor,null);assert.equal(screens,1);
  assert.equal((appSource.match(/state\.sourceCursor = \{/g)??[]).length,1,'Cursor values must flow through the single receiving adapter');
  assert(!/state\.sourceCursor\s*=/.test(ownershipProvenance));
  sourceOwnershipReceipt.push({test:'review_field_trace_cursor_receiver_and_ambiguous_selection',status:'passed',hookLine:3,hookColumn:4});
}
{
  const {document,elements}=sourceReviewDOM();const first=await ownedArtifact('retry-1'),second=await ownedArtifact('retry-2','second');
  first.loadError='Synthetic preview error';second.content='second';
  const {api,state,sandbox}=ownedContext({state:{artifacts:[first,second],selectedArtifactId:first.artifact_id},document,elements,
    textElement:(tag,kind,text)=>{const node=document.createElement(tag);node.className=kind;node.textContent=text;return node;},
    appendSourceSyntax:(node,tokens)=>{node.textContent=tokens.map(value=>value.text).join('');},applySourceSearch(){}});
  const key=api.deobfuscationKey({...first,source_type:'artifact'}),analysis=ownedPayload(first,'const a = 1;');state.deobfuscationCache.set(key,analysis);
  api.renderSourceContent(api.selectedSource());const retry=elements.sourceCodeEmpty.children[1];assert(retry.listeners.click);
  api.releaseSourcePreview({...first,source_type:'artifact'});state.selectedArtifactId=second.artifact_id;api.renderSourceContent(api.selectedSource());
  assert.equal(elements.sourceCodeEmpty.hidden,true);assert.equal(elements.sourceCodeEmpty.children.length,0);assert.equal(state.deobfuscationCache.size,0);
  // Even an externally retained old handler receives descriptor-only data.
  state.selectedArtifactId=first.artifact_id;let received;
  sandbox.sourceIsCurrent=source=>{received=source;return false;};retry.listeners.click[0]();
  assert(received);for(const key of ['content','deobfuscation','controller'])assert.equal(Object.hasOwn(received,key),false);
  sourceOwnershipReceipt.push({test:'review_hidden_retry_dom_and_bound_reference_release',status:'passed',hiddenRetryNodes:0});
}
{
  const original='// a\u0000b\r\nconst snow = "雪😀";',normalized=original.replaceAll('\u0000',' ');
  for(const opaque of [await ownershipHash(normalized),'provider-specific-opaque-version']) {
    const script={script_id:'opaque',target_id:'worker-opaque',target_type:'worker',hash:opaque,language:'JavaScript',length:original.length,source_type:'script',kind:'javascript',start_line:0,start_column:0};
    let text=original,analyzerCalls=0,truncated=false;const gate=ownedDeferred();let held=false;
    const {api,state}=ownedContext({state:{debuggerSession:{target:{id:'page'},scripts:[script]},selectedScriptId:'opaque'},fetch:async url=>{
      if(url.startsWith('/api/debugger/source'))return Response.json({protocol_version:1,script_id:'opaque',source:original,truncated});
      analyzerCalls++;const result=ownedPayload(script,text);result.analysis.source.sha256=await ownershipHash(text);return held?gate.promise:Response.json(result);
    }});
    await api.loadDeobfuscation(api.selectedSource());assert.equal(analyzerCalls,0,'Unloaded live text cannot be analyzed');
    await api.loadScriptContent(script);assert.equal(state.liveScriptContent.get('opaque').content,original);
    await api.loadDeobfuscation(api.selectedSource(),{retry:true});assert.equal(api.selectedSource().deobfuscation.original_source,original);
    const key=api.deobfuscationKey(api.selectedSource()),good=state.deobfuscationCache.get(key);
    text=normalized;await api.loadDeobfuscation(api.selectedSource(),{retry:true});assert.equal(state.deobfuscationRequests.get(key).status,'error');assert.equal(state.deobfuscationCache.get(key),good);
    // A new full preview owner under the same opaque catalog token cannot take
    // an old pending analyzer result, even when its bytes are identical.
    text=original;held=true;const pending=api.loadDeobfuscation(api.selectedSource(),{retry:true});await Promise.resolve();
    const old=state.liveScriptContent.get('opaque');state.liveScriptContent.set('opaque',{...old});
    const result=ownedPayload(script,original);result.analysis.source.sha256=await ownershipHash(original);gate.resolve(Response.json(result));await pending;
    assert.equal(state.deobfuscationCache.get(key),good);assert.equal(state.deobfuscationRequests.get(key).status,'error');
    state.liveScriptContent.set('opaque',{...old,content:normalized,sourceTextLength:normalized.length});assert.equal(api.selectedSource().deobfuscation,null,'A different owned text cannot display an old derived result');
    state.liveScriptContent.delete('opaque');truncated=true;held=false;await api.loadScriptContent(script);const before=analyzerCalls;
    await api.loadDeobfuscation(api.selectedSource(),{retry:true});assert.equal(analyzerCalls,before,'A truncated preview cannot authenticate analyzer text');
  }
  sourceOwnershipReceipt.push({test:'review_opaque_cdp_token_exact_full_live_text_and_late_owner',status:'passed',nulNormalizationUsedAsProof:false,providerFormats:2});
}

if (process.env.REB_SOURCE_OWNERSHIP_BACKEND_URL) {
  const endpoint=new URL(process.env.REB_SOURCE_OWNERSHIP_BACKEND_URL);
  assert(endpoint.protocol==='http:' && ['127.0.0.1','localhost','[::1]'].includes(endpoint.hostname),'Sources fixture backend must be loopback');
  const catalog=await (await fetch(new URL('/api/artifacts?limit=500',endpoint))).json();
  const {state,api}=ownedContext({state:{artifacts:catalog.artifacts},fetch:(url,options)=>fetch(new URL(url,endpoint),options)});
  const javascript=state.artifacts.filter(source=>source.kind==='javascript');assert(javascript.length);
  for(const artifact of javascript) {
    state.selectedArtifactId=artifact.artifact_id;await api.loadArtifactContent(artifact);assert.equal(artifact.loadError,null);
    const original=artifact.content;
    for(const intrinsics of [false,true]) {
      state.deobfuscationAssumeIntrinsics=intrinsics;await api.loadDeobfuscation(api.selectedSource());
      const request=state.deobfuscationRequests.get(api.deobfuscationKey(api.selectedSource()));assert.equal(request.status,'ready',request.error);
      assert.equal(api.sourceDisplayView(api.selectedSource()).content,original);assert.equal(artifact.content,original);
    }
    const response=await fetch(new URL(`/api/artifacts/${artifact.artifact_id}/content?limit=2097152`,endpoint));
    assert.equal(await ownershipHash(new Uint8Array(await response.arrayBuffer())),artifact.sha256);
  }
  sourceOwnershipReceipt.push({test:'real_rust_worker_http_to_sources_admission',status:'passed',artifacts:javascript.length,intrinsicModes:2});
}
console.log('PASS Sources pending refresh owners, analyzer identity/hash/maps, worker targets, cursor scope, explicit retry, close/eviction byte bounds, bounded hex, stable editor and keyboard tab handlers (not rendered QA)');
if (process.env.REB_SOURCE_OWNERSHIP_RECEIPT) await writeFile(process.env.REB_SOURCE_OWNERSHIP_RECEIPT, JSON.stringify({scope:'Production-function and DOM fixtures; not rendered acceptance',results:sourceOwnershipReceipt},null,2));

// The decoded-field handoff must never silently rebind a chain to edited input
// or another request, or turn a binary/preview result into a source-text match.
const fieldHandoff = runInNewContext(
  (await readFile(join(root, "apps/research-ui/field_provenance.js"), "utf8")) +
    `;function decoderCurrentInputKey() {return currentKey;}
    function liveSources() {return sourceCatalog;}
    function liveScriptIdentity(source) {return source.target_id + ':' + source.script_id + ':' + source.hash;}
    function loadScriptContent() {return loadGate;}
    ({decodedFieldCandidate, fieldSourceMatches, clearDecoderFieldOrigin, provenanceDecoderBytes, searchFieldSources,
      setup(selection, steps, selected, key = 'original') {
        fieldProvenanceSelection = selection;
        decoderFieldOrigin = {selection, key: 'original'};
        state.decoderSteps = steps; state.decoderSelectedStepId = selected;
        state.decoderPending = false; currentKey = key;
      }, changeField() {fieldProvenanceSelection = {};}, pending() {state.decoderPending = true;},
      setSearch(selection, sources, loaded, gate) {
        fieldProvenanceSelection = selection; sourceCatalog = sources; loadGate = gate;
        state.liveScriptContent = new Map(loaded.map(([source, record]) => [source.script_id,
          {...record, identity: liveScriptIdentity(source)}]));
      }, setCatalog(sources) {sourceCatalog = sources;}})`,
  {
    TextDecoder,
    TextEncoder,
    URL,
    document: { querySelector: () => ({ hidden: true, addEventListener() {} }) },
    state: {},
    currentKey: "original",
    sourceCatalog: [],
    loadGate: null,
    decoderBase64ToBytes: (value) => new Uint8Array(Buffer.from(value, "base64")),
  },
);
const candidateStep = (id, value) => ({
  id, operation: "base64-decode", input_bytes: 32,
  output_bytes: Buffer.byteLength(value), output_base64: Buffer.from(value).toString("base64"),
});
const field = { value: "original", selector: "/payload" };
const steps = [candidateStep(1, "intermediate"), candidateStep(2, "\ufeff雪\r\n<script>inert</script>")];
fieldHandoff.setup(field, steps, 2);
const candidate = fieldHandoff.decodedFieldCandidate();
assert.equal(candidate.value, "\ufeff雪\r\n<script>inert</script>");
assert.equal(candidate.steps.length, 2);
assert.equal(field.value, "original");
fieldHandoff.setup(field, steps, 1);
assert.equal(fieldHandoff.decodedFieldCandidate().steps.length, 1);
fieldHandoff.setup(field, steps, null);
assert.match(fieldHandoff.decodedFieldCandidate().error, /completed transformation/);
fieldHandoff.setup(field, steps, 2, "edited");
assert.match(fieldHandoff.decodedFieldCandidate().error, /Input changed/);
fieldHandoff.setup(field, steps, 2);
fieldHandoff.changeField();
assert.match(fieldHandoff.decodedFieldCandidate().error, /field changed/);
fieldHandoff.setup(field, steps, 2);
fieldHandoff.pending();
assert.match(fieldHandoff.decodedFieldCandidate().error, /Wait/);
fieldHandoff.setup(field, [candidateStep(1, "x".repeat(4096))], 1);
assert.equal(fieldHandoff.decodedFieldCandidate().value.length, 4096);
for (const value of ["", "雪".repeat(1366)]) {
  fieldHandoff.setup(field, [candidateStep(1, value)], 1);
  assert.match(fieldHandoff.decodedFieldCandidate().error, /4 KiB/);
}
fieldHandoff.setup(field, [{ ...candidateStep(1, "x"), output_base64: "/w==" }], 1);
assert.match(fieldHandoff.decodedFieldCandidate().error, /Binary/);
fieldHandoff.clearDecoderFieldOrigin();
assert.match(fieldHandoff.decodedFieldCandidate().error, /Start from/);
const matches = fieldHandoff.fieldSourceMatches("雪\nfixture-origin", "fixture-origin", {
  script_id: "fixture", target_id: "target", hash: "hash", url: "http://127.0.0.1/source.js?redact=yes",
});
assert.equal(matches[0].line, 1);
assert.equal(matches[0].column, 0);
assert.equal(matches[0].source, "http://127.0.0.1/source.js");
assert.equal(fieldHandoff.provenanceDecoderBytes("\ud800"), null);
assert.equal(fieldHandoff.provenanceDecoderBytes("\udc00"), null);
assert.equal(new TextDecoder("utf-8", {ignoreBOM: true}).decode(
  fieldHandoff.provenanceDecoderBytes("\ufeff雪\r\n😀")), "\ufeff雪\r\n😀");
const source = {script_id: "script", target_id: "target", hash: "hash", kind: "javascript",
  length: 128, url: "http://127.0.0.1/source.js"};
const searchSelection = (value, derived) => ({value, derivedSearch: derived ? {value: derived} : null,
  request: {tabId: "target"}, candidates: [], gaps: []});
let selection = searchSelection("encoded-original", "decoded-result");
fieldHandoff.setSearch(selection, [source], [[source, {content: "decoded-result", sourceTextLength: 14}]]);
await fieldHandoff.searchFieldSources();
assert.equal(selection.candidates.length, 1);
assert.equal(selection.candidates[0].source_hash, "hash");
selection = searchSelection("viewer-only-notice");
fieldHandoff.setSearch(selection, [source], [[source, {content: "original\nviewer-only-notice",
  sourceTextLength: 8, contentTruncated: true}]]);
await fieldHandoff.searchFieldSources();
assert.equal(selection.candidates.length, 0);
assert(selection.gaps.includes("Partial source."));
selection = searchSelection("decoded-result");
fieldHandoff.setSearch(selection, [source], [[{...source, target_id: "other"}, {content: "decoded-result"}]]);
await fieldHandoff.searchFieldSources();
assert.equal(selection.candidates.length, 0);
assert(selection.gaps.includes("Sources changed. Retry."));
let release;
let gate = new Promise(resolve => {release = resolve;});
selection = searchSelection("encoded-original", "decoded-result");
fieldHandoff.setSearch(selection, [source], [[source, {content: "decoded-result", sourceTextLength: 14}]], gate);
let searching = fieldHandoff.searchFieldSources();
fieldHandoff.changeField(); release(); await searching;
assert.equal(selection.candidates.length, 0);
assert.equal(selection.searching, false);
gate = new Promise(resolve => {release = resolve;});
selection = searchSelection("decoded-result");
fieldHandoff.setSearch(selection, [source], [[source, {content: "decoded-result", sourceTextLength: 14}]], gate);
searching = fieldHandoff.searchFieldSources();
fieldHandoff.setCatalog([{...source, hash: "new-hash"}]); release(); await searching;
assert.equal(selection.candidates.length, 0);
assert(selection.gaps.includes("Sources changed. Retry."));
console.log("PASS decoded field identity, chain prefix, UTF-8, source identity, cancellation, and bounds");
// Chrome's port file is the readiness contract used by ChromeDriver/Telemetry;
// stderr is diagnostic only (Linux launchers may proxy it through helpers).
function trafficDevtoolsAddress(text) {
  if (typeof text !== "string" || text.length > 4096) return null;
  const match = /^([1-9][0-9]{0,4})\r?\n(\/devtools\/browser\/[a-zA-Z0-9-]{1,128})\r?\n?$/.exec(text);
  if (!match || Number(match[1]) > 65535) return null;
  return `ws://127.0.0.1:${match[1]}${match[2]}`;
}

function trafficBrowserProcess(executable, args) {
  const grouped = process.platform !== "win32";
  const started = performance.now();
  const diagnostics = {executable, args, pid: null, phase: "spawn", elapsed_ms: 0,
    exit_code: null, signal: null, spawn_error: null, port_file: "not checked", stdout: "", stderr: "", cleanup: null};
  const browser = spawn(executable, args, {detached: grouped, stdio: ["ignore", "pipe", "pipe"]});
  diagnostics.pid = browser.pid ?? null;
  browser.stdout.on("data", data => {diagnostics.stdout = (diagnostics.stdout + data).slice(-16384);});
  browser.stderr.on("data", data => {diagnostics.stderr = (diagnostics.stderr + data).slice(-16384);});
  browser.on("error", error => {diagnostics.spawn_error = `${error.code ?? "error"}: ${error.message}`.slice(0, 2048);});
  browser.on("exit", (code, signal) => {diagnostics.exit_code = code; diagnostics.signal = signal;});
  const elapsed = () => {diagnostics.elapsed_ms = Math.round(performance.now() - started);};
  const failed = () => diagnostics.spawn_error || browser.exitCode !== null || browser.signalCode !== null;
  const failure = reason => {elapsed(); return new Error(`${reason}; ${JSON.stringify(diagnostics)}`);};
  async function ready(profile, timeoutMs = 30000) {
    diagnostics.phase = "DevToolsActivePort";
    const deadline = performance.now() + timeoutMs;
    while (performance.now() < deadline) {
      if (failed()) throw failure("Chromium exited or failed before DevTools readiness");
      let handle;
      try {
        handle = await open(join(profile, "DevToolsActivePort"), "r");
        const buffer = Buffer.alloc(4097);
        const {bytesRead} = await handle.read(buffer, 0, buffer.length, 0);
        const address = bytesRead <= 4096 ? trafficDevtoolsAddress(buffer.toString("utf8", 0, bytesRead)) : null;
        diagnostics.port_file = address ? "valid" : `incomplete or malformed (${bytesRead} bytes read)`;
        if (address && !failed()) {elapsed(); return address;}
      } catch (error) {
        diagnostics.port_file = String(error.code ?? error.message).slice(0, 256);
        if (error.code !== "ENOENT") throw failure("Cannot read Chromium readiness file");
      } finally {await handle?.close();}
      await new Promise(resolve => setTimeout(resolve, Math.max(1, Math.min(50, deadline - performance.now()))));
    }
    throw failure(`Chromium DevTools readiness timed out after ${timeoutMs} ms`);
  }
  async function stop(graceMs = 2000) {
    const cleanup = {signals: [], exited: false, error: null};
    diagnostics.cleanup = cleanup;
    if (!browser.pid) {cleanup.exited = true; elapsed(); return;}
    // This group is created solely for our own browser and launcher helpers.
    // It cannot include the caller or another user's browser.
    const alive = () => {
      if (!grouped) return browser.exitCode === null && browser.signalCode === null;
      try {process.kill(-browser.pid, 0); return true;} catch (error) {if (error.code === "ESRCH") return false; throw error;}
    };
    const signal = name => {
      try {if (grouped) process.kill(-browser.pid, name); else browser.kill(name); cleanup.signals.push(name);}
      catch (error) {if (error.code !== "ESRCH") throw error;}
    };
    try {
      for (const name of ["SIGTERM", "SIGKILL"]) {
        if (!alive()) break;
        signal(name);
        const deadline = performance.now() + graceMs;
        while (alive() && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 25));
      }
      cleanup.exited = !alive();
      if (!cleanup.exited) throw new Error("Owned browser process group did not exit after bounded cleanup");
    } catch (error) {cleanup.error = String(error.message).slice(0, 2048); throw error;}
    finally {elapsed(); browser.stdout.destroy(); browser.stderr.destroy();}
  }
  return {browser, diagnostics, ready, stop};
}

async function trafficBrowserSocket(address, timeoutMs = 10000, Socket = WebSocket) {
  const socket = new Socket(address);
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {cleanup(); reject(new Error(`Chromium CDP socket timed out after ${timeoutMs} ms`));}, timeoutMs);
      const opened = () => {cleanup(); resolve();};
      const failed = event => {cleanup(); reject(new Error(`Chromium CDP socket ${event.type} before opening`));};
      function cleanup() {clearTimeout(timer); socket.removeEventListener("open", opened); socket.removeEventListener("error", failed); socket.removeEventListener("close", failed);}
      socket.addEventListener("open", opened, {once: true});
      socket.addEventListener("error", failed, {once: true});
      socket.addEventListener("close", failed, {once: true});
    });
    return socket;
  } catch (error) {socket.close(); throw error;}
}

// Real child-process fixtures cover the silent-launch path without launching a
// browser or claiming rendered QA. They run in the existing focused gate.
for (const invalid of ["", "0\n/devtools/browser/abc", "65536\n/devtools/browser/abc", "9222\nhttps://foreign.invalid/", "9222\n/devtools/page/abc", "9222\n/devtools/browser/abc?remote=x", "x".repeat(4097)]) assert.equal(trafficDevtoolsAddress(invalid), null);
assert.equal(trafficDevtoolsAddress("9222\n/devtools/browser/abc-def\n"), "ws://127.0.0.1:9222/devtools/browser/abc-def");
const startupFixture = await mkdtemp(join(tmpdir(), "reb-browser-startup-fixture-"));
try {
  const launchFixture = code => trafficBrowserProcess(process.execPath, ["-e", code, startupFixture]);
  let fixture = launchFixture(`const fs=require('node:fs');const p=require('node:path').join(process.argv[1],'DevToolsActivePort');fs.writeFileSync(p,'9222\\n');setTimeout(()=>fs.writeFileSync(p,'9222\\n/devtools/browser/silent-fixture'),50);setInterval(()=>{},1000);`);
  try {
    assert.equal(await fixture.ready(startupFixture, 3000), "ws://127.0.0.1:9222/devtools/browser/silent-fixture");
    assert.equal(fixture.diagnostics.stderr, "");
    assert.equal(fixture.diagnostics.port_file, "valid");
  } finally {await fixture.stop();}
  assert.equal(fixture.diagnostics.cleanup.exited, true);
  await rm(join(startupFixture, "DevToolsActivePort"));
  fixture = launchFixture("process.stderr.write('synthetic startup denial\\n');process.exitCode=23;");
  try {await assert.rejects(fixture.ready(startupFixture, 3000), /Chromium exited or failed/);}
  finally {await fixture.stop();}
  assert.equal(fixture.diagnostics.exit_code, 23);
  assert.match(fixture.diagnostics.stderr, /synthetic startup denial/);
  fixture = trafficBrowserProcess(join(startupFixture, "missing-browser"), []);
  try {await assert.rejects(fixture.ready(startupFixture, 3000), /ENOENT/);}
  finally {await fixture.stop();}
  fixture = launchFixture("process.on('SIGTERM',()=>{});process.stdout.write('ready');setInterval(()=>{},1000);");
  try {
    // Wait for the fixture's signal handler before testing escalation.
    const deadline = performance.now() + 3000;
    while (!fixture.diagnostics.stdout && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(fixture.diagnostics.stdout, "ready");
    await assert.rejects(fixture.ready(startupFixture, 100), /timed out/);
  } finally {await fixture.stop(100);}
  assert.deepEqual(fixture.diagnostics.cleanup.signals, ["SIGTERM", "SIGKILL"]);
  assert.equal(fixture.diagnostics.cleanup.exited, true);
  await writeFile(join(startupFixture, "DevToolsActivePort"), "9222\nhttps://foreign.invalid/");
  fixture = launchFixture("process.stdout.write('x'.repeat(20000));process.stderr.write('y'.repeat(20000));setInterval(()=>{},1000);");
  try {await assert.rejects(fixture.ready(startupFixture, 200), /incomplete or malformed/);}
  finally {await fixture.stop();}
  assert(fixture.diagnostics.stdout.length <= 16384 && fixture.diagnostics.stderr.length <= 16384);
} finally {await rm(startupFixture, {recursive: true, force: true});}
class TrafficSocketFixture extends EventTarget {
  static event = null;
  static latest;
  constructor() {super(); TrafficSocketFixture.latest = this; if (TrafficSocketFixture.event) queueMicrotask(() => this.dispatchEvent(new Event(TrafficSocketFixture.event)));}
  close() {this.closed = true;}
}
for (const event of ["open", "error", "close", null]) {
  TrafficSocketFixture.event = event;
  if (event === "open") assert(await trafficBrowserSocket("ws://127.0.0.1", 30, TrafficSocketFixture));
  else {await assert.rejects(trafficBrowserSocket("ws://127.0.0.1", 30, TrafficSocketFixture), /Chromium CDP socket/); assert.equal(TrafficSocketFixture.latest.closed, true);}
}
console.log("PASS Chromium silent port-file startup, partial/malformed ports, launch errors, early exit, timeouts, bounded diagnostics/cleanup and socket handshake fixtures (not browser QA)");

// Real, synthetic UI QA using the runner's installed Chromium and Node's CDP
// WebSocket. No package install, network capture, sandbox override, or backend
// exposure is needed. Do not substitute these screenshots for native macOS QA.
// Synthetic immutable artifacts exercise the real Sources UI without page
// instrumentation, captured third-party content, or executing analyzed code.
async function sourceFactsBrowserFixture() {
  const text = '\ufeffconst 雪 = "😀";\nfunction shadow(雪) { return 雪; }\n雪;';
  const bytes = Buffer.from(text);
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)), byte=>byte.toString(16).padStart(2,'0')).join('');
  const artifact = id => ({protocol_version:1,artifact_id:id,session_id:'11',navigation_id:'13',frame_id:'17',parent_artifact_id:'0',creator_event_id:'19',execution_context_id:'23',capture_origin:'dynamic_javascript',kind:'javascript',url:`https://fixture.invalid/facts-${id}.js`,mime_type:'text/javascript',byte_size:bytes.length,sha256:hash,sensitive:false});
  const artifacts = [artifact('7'),artifact('8')];
  const snow = Buffer.byteLength('\ufeffconst ');
  const documents = new Map(artifacts.map(source=>[source.artifact_id,bytes]));
  const debuggerState=JSON.parse(await readFile(join(root,'apps/origin-trace-backend/assets/debugger-empty.json'),'utf8'));
  const liveDocuments=new Map();
  const fixture = {mode:'partial',pending:[],requests:[],artifacts,bytes,snow,documents,debuggerState,liveDocuments,
    previewMode:'ready',previewPending:[],deobMode:'ready',deobPending:[],analysisRequests:[],previewRequests:[],
    liveMode:'ready',livePending:[],liveRequests:[],rejectedWrites:[]};
  fixture.addLiveSource = (id,text) => {
    const lines=text.split('\n');
    const source={script_id:id,url:`https://fixture.invalid/${id}.js`,hash:`opaque-${id}-v1`,source_map_url:'',language:'JavaScript',
      start_line:0,start_column:0,end_line:lines.length-1,end_column:lines.at(-1).length,execution_context_id:31,
      length:text.length,has_source_url:false,is_module:false};
    liveDocuments.set(id,{source,text});
    debuggerState.state='running';debuggerState.generation++;
    debuggerState.target??={id:'qa-source-page-one',type:'page',title:'Synthetic Sources owner',url:'https://fixture.invalid/sources'};
    debuggerState.targets=[debuggerState.target];debuggerState.live_tab_count=1;
    debuggerState.scripts=[...liveDocuments.values()].map(value=>value.source);
    return source;
  };
  fixture.addSource = async (id,text) => {
    const content=Buffer.from(text),source={...artifact(id),byte_size:content.length,sha256:await ownershipHash(content)};
    artifacts.push(source);documents.set(id,content);return source;
  };
  const report = source => ({schema:'reb-javascript-source-facts-v1',profile:'lexical-effects-v1',offset_unit:'utf-8-byte',source_bytes:bytes.length,source,ok:fixture.mode!=='unavailable',
    scopes:fixture.mode==='unavailable'?[]:[{id:0,parent_id:null,range:{start:0,end:bytes.length},kind:'program'}],
    regions:fixture.mode==='unavailable'?[]:[{id:0,parent_id:null,callable_id:null,range:{start:0,end:bytes.length},kind:'program',entry_order:0}],
    bindings:fixture.mode==='unavailable'?[]:[{id:0,scope_id:0,name:'雪',range:{start:snow,end:snow+3},kind:'const'}],callables:[],
    operations:fixture.mode==='unavailable'?[]:Array.from({length:205},(_,id)=>({id,region_id:0,order:id,range:{start:snow,end:snow+3},kind:'read',detail:{target:{kind:'binding',binding_ids:[0],resolution:'lexical-only',name:'雪'}}})),
    coverage:{status:fixture.mode==='unavailable'?'unavailable':fixture.mode==='complete'?'complete':'partial',truncated:fixture.mode==='truncated',diagnostics:fixture.mode==='unavailable'?['Synthetic parse rejection']:[],frontiers:['unavailable','complete'].includes(fixture.mode)?[]:[{range:{start:snow,end:snow+3},reason:'abrupt-completion'}]},
    limits:{max_source_bytes:4194304,max_ast_nodes:32768,max_facts:16384,max_frontiers:256,max_binding_candidates:64,preflight_depth:128,preflight_nodes:500000}});
  fixture.handle = async (request,response) => {
    const url = new URL(request.url,'http://127.0.0.1');
    const json = (status,value) => {if(!response.destroyed){response.writeHead(status,{'Content-Type':'application/json'});response.end(JSON.stringify(value));}};
    if(url.pathname==='/api/debugger/actions'){
      fixture.rejectedWrites.push({method:request.method??'POST',path:url.pathname});
      json(405,{error:'The Sources fixture never executes debugger mutations'});return true;
    }
    if(url.pathname==='/api/debugger'){json(200,debuggerState);return true;}
    if(url.pathname==='/api/debugger/source'){
      const live=liveDocuments.get(url.searchParams.get('script_id'));
      if(!live){json(404,{error:'Synthetic live source unavailable'});return true;}
      // Capture the old reply before a fixture target changes. It must never
      // become the new owner's text when the held body is delivered later.
      const reply=JSON.stringify({protocol_version:1,script_id:live.source.script_id,source:live.text,truncated:false});
      fixture.liveRequests.push(live.source.script_id);
      response.writeHead(200,{'Content-Type':'application/json'});
      if(fixture.liveMode==='pending-body'){response.flushHeaders?.();await new Promise(resolve=>fixture.livePending.push(resolve));}
      if(!response.destroyed)response.end(reply);return true;
    }
    if(url.pathname==='/api/events'){json(200,{count:0,events:[],capture_mode:'demo',broker_connected:false,capture_controls_available:false});return true;}
    if(url.pathname==='/api/artifacts'){json(200,{count:artifacts.length,artifacts});return true;}
    if(url.pathname==='/api/source-facts'){
      fixture.requests.push(url.search);
      const source=artifacts.find(value=>value.artifact_id===url.searchParams.get('artifact_id') && value.session_id===url.searchParams.get('session_id'));
      if(!source){json(404,{error:'Synthetic exact source not found'});return true;}
      if(fixture.mode==='pending') await new Promise(resolve=>fixture.pending.push(resolve));
      if(fixture.mode==='error'){json(503,{error:'Synthetic worker unavailable',code:'dependency_unavailable',details:{}});return true;}
      const value=report(source);
      if(fixture.mode==='malformed') value.source={...source,sha256:'b'.repeat(64)};
      json(200,value);return true;
    }
    if(url.pathname==='/api/deobfuscation'){
      fixture.analysisRequests.push(url.search);
      const live=liveDocuments.get(url.searchParams.get('script_id'));
      const source=live?{...live.source,source_type:'script'}:artifacts.find(value=>value.artifact_id===url.searchParams.get('artifact_id'));
      if(!source){json(404,{error:'Synthetic source unavailable'});return true;}
      const text=live?live.text:documents.get(source.artifact_id).toString('utf8');
      if(fixture.deobMode==='error'){json(503,{error:'Authored analyzer retry failure'});return true;}
      const payload=fixture.changedSource&&source.artifact_id===fixture.changedSource?ownedDerivedPayload(source,text,Array.from({length:7},(_,i)=>[`1+${i}`,`(${i+1})`])):ownedPayload(source,text);
      if(fixture.changedSource&&source.artifact_id===fixture.changedSource){
        payload.analysis.omissions=['Unsupported runtime behavior remains unresolved.'];
        payload.analysis.string_tables=Array.from({length:5},(_,i)=>({kind:`table-${i+1}`,offset:0,entry_count:8,encodings:['literal'],decoded_preview:'<script>inert fixture</script>'}));
      }
      payload.analysis.source.sha256=await ownershipHash(text);
      payload.analysis.source.lines=text.split('\n').length;
      payload.analysis.assumptions=url.searchParams.get('assume_intrinsics')==='1'?['standard-intrinsics']:[];
      if(fixture.deobMode==='wrong-id')payload.artifact_id='999';
      if(fixture.deobMode==='wrong-hash')payload.analysis.source.sha256='b'.repeat(64);
      if(fixture.deobMode==='pending')await new Promise(resolve=>fixture.deobPending.push(resolve));
      json(200,payload);return true;
    }
    if(/^\/api\/artifacts\/[0-9]+\/content$/.test(url.pathname)){
      const id=url.pathname.split('/')[3], content=documents.get(id);
      if(!content){json(404,{error:'Synthetic artifact unavailable'});return true;}
      fixture.previewRequests.push(id);
      const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||2097152);
      const chunk=Buffer.from(content.subarray(offset,offset+limit)),mode=fixture.previewMode;
      if(mode==='wrong-bytes' && chunk.length)chunk[0]^=1;
      response.writeHead(200,{'Content-Type':'application/octet-stream','X-Artifact-Total-Bytes':String(content.length),'X-Artifact-Offset':String(offset),'X-Artifact-Truncated':String(offset+chunk.length<content.length)});
      if(mode==='pending-body'){response.flushHeaders?.();await new Promise(resolve=>fixture.previewPending.push(resolve));}
      if(!response.destroyed)response.end(chunk);return true;
    }
    return false;
  };
  fixture.releasePreview = () => {for(const resolve of fixture.previewPending.splice(0)) resolve();};
  fixture.releaseLive = () => {for(const resolve of fixture.livePending.splice(0)) resolve();};
  fixture.release = () => {for(const resolve of [...fixture.pending.splice(0),...fixture.previewPending.splice(0),...fixture.deobPending.splice(0),...fixture.livePending.splice(0)]) resolve();};
  return fixture;
}

// Keep fixture routing admissible to the normal refresh path before launching
// Chrome; a blanket offline events response would prevent artifact discovery.
const sourcesFixtureControl = await sourceFactsBrowserFixture();
const sourcesFixtureModels = runInNewContext((await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8'))+';({isBrokerResponse,isArtifactResponse,isDebuggerResponse})',{TextEncoder});
async function sourcesFixtureResponse(url) {
  const response={destroyed:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(body){this.body=body;}};
  assert(await sourcesFixtureControl.handle({url},response));return response;
}
const sourcesEventsControl=await sourcesFixtureResponse('/api/events?limit=5000');
assert.equal(sourcesEventsControl.status,200);assert(sourcesFixtureModels.isBrokerResponse(JSON.parse(sourcesEventsControl.body)));
const sourcesArtifactsControl=await sourcesFixtureResponse('/api/artifacts?limit=500');
assert.equal(sourcesArtifactsControl.status,200);assert(sourcesFixtureModels.isArtifactResponse(JSON.parse(sourcesArtifactsControl.body)));
const sourcesFactsControl=await sourcesFixtureResponse('/api/source-facts?session_id=11&artifact_id=7');
assert.equal(JSON.parse(sourcesFactsControl.body).source.artifact_id,'7');
assert.equal((await sourcesFixtureResponse('/api/source-facts?session_id=12&artifact_id=7')).status,404);
const sourcesBytesControl=await sourcesFixtureResponse('/api/artifacts/7/content?offset=0&limit=2097152');
assert.equal(sourcesBytesControl.headers['X-Artifact-Truncated'],'false');assert.deepEqual(sourcesBytesControl.body,sourcesFixtureControl.bytes);
const emptyDebuggerControl=JSON.parse((await sourcesFixtureResponse('/api/debugger')).body);
assert(sourcesFixtureModels.isDebuggerResponse(emptyDebuggerControl));
const liveControl=sourcesFixtureControl.addLiveSource('qa-control','const inert = "雪";');
assert(sourcesFixtureModels.isDebuggerResponse(JSON.parse((await sourcesFixtureResponse('/api/debugger')).body)));
assert.equal(JSON.parse((await sourcesFixtureResponse('/api/debugger/source?script_id=qa-control')).body).source,'const inert = "雪";');
const liveAnalysisControl=JSON.parse((await sourcesFixtureResponse('/api/deobfuscation?script_id=qa-control&mode=derived')).body);
assert.equal(liveAnalysisControl.script_id,liveControl.script_id);assert.equal(liveAnalysisControl.artifact_id,null);
assert.equal(liveAnalysisControl.analysis.source.sha256,await ownershipHash(liveAnalysisControl.original_source));
// Held replies capture their old text, even when the fixture's current text is
// replaced before release. This checks the adversarial route itself.
sourcesFixtureControl.liveMode='pending-body';const heldLiveControl=sourcesFixtureResponse('/api/debugger/source?script_id=qa-control');
await new Promise(resolve=>setImmediate(resolve));assert.equal(sourcesFixtureControl.livePending.length,1);
sourcesFixtureControl.liveDocuments.get('qa-control').text='const newer = 1;';sourcesFixtureControl.releaseLive();
assert.equal(JSON.parse((await heldLiveControl).body).source,'const inert = "雪";');
sourcesFixtureControl.liveMode='ready';
console.log('PASS Sources browser fixture event/artifact/debugger admission, exact source text, inert analysis replies and held-body ownership routes (not rendered QA)');

// Test-only observation of the actual loader promises. Each wrapper calls its
// loader exactly once with the original receiver/arguments and returns the same
// promise. Receipts contain identities/status only, never source text or payloads.
function sourceOwnershipOperationObserver(loaders, identify) {
  const entries=new Map(),failures=[];let sequence=0,failureCount=0,pendingCount=0;
  const settle=(entry,status,error)=>{
    entry.status=status;entry.settled_at=Date.now();pendingCount--;
    if(status!=='fulfilled'){
      entry.error_name=String(error?.name??'Error').slice(0,64);entry.error_message=String(error?.message??error).slice(0,256);
      failureCount++;failures.push({...entry});if(failures.length>64)failures.shift();
    }
  };
  const observe=(promise,entry)=>{promise.then(()=>settle(entry,'fulfilled'),error=>settle(entry,'rejected',error));};
  const wrappers=Object.fromEntries(Object.entries(loaders).map(([kind,loader])=>[kind,function(...args){
    const entry={id:++sequence,kind,identity:identify(args[0]),status:'pending',started_at:Date.now(),settled_at:null};
    entries.set(entry.id,entry);pendingCount++;
    // This observer is installed only for the three held-operation cases.
    // Overflow fails receipt lookup rather than changing production execution.
    while(entries.size>64)entries.delete(entries.keys().next().value);
    try {const promise=Reflect.apply(loader,this,args);observe(promise,entry);return promise;}
    catch(error){settle(entry,'threw',error);throw error;}
  }]));
  return {wrappers,read:id=>entries.has(id)?{...entries.get(id)}:null,failures:()=>({count:failureCount,pending:pendingCount,entries:failures.map(entry=>({...entry}))}),
    pending:(kind,identity)=>[...entries.values()].filter(entry=>entry.kind===kind&&entry.identity===identity&&entry.status==='pending').map(entry=>({...entry}))};
}

async function waitForSourceOwnershipSettlement(read,expected,timeoutMs=5000) {
  const deadline=Date.now()+timeoutMs;
  do {
    const entry=await read(expected.id);
    assert(entry&&entry.id===expected.id&&entry.kind===expected.kind&&entry.identity===expected.identity,'Held source operation lost its exact receipt');
    if(entry.status!=='pending'){
      assert(['fulfilled','rejected','threw'].includes(entry.status)&&Number.isFinite(entry.settled_at),'Invalid source terminal receipt');
      return entry;
    }
    const remaining=deadline-Date.now();
    if(remaining<=0)break;
    await new Promise(resolve=>setTimeout(resolve,Math.min(25,remaining)));
  } while(Date.now()<=deadline);
  assert.fail(`Held ${expected.kind} source operation ${expected.id} did not settle within ${timeoutMs} ms`);
}

// A completion later than the old 50 ms sleep must be observed before accepting
// no-stale-commit assertions. Stalled work must fail closed, not pass on timeout.
const settlementReceiver={receiver:'unchanged'};
let releaseObserved,rejectObserved,observedCalls=0,lateObservedCommit=false;
const delayedObserved=new Promise(resolve=>{releaseObserved=resolve;});
const rejectedObserved=new Promise((resolve,reject)=>{rejectObserved=reject;});
const settlementObserver=sourceOwnershipOperationObserver({
  live:function(source,extra){assert.equal(this,settlementReceiver);assert.equal(source.identity,'exact-owner');assert.equal(extra,'unchanged');observedCalls++;return delayedObserved;},
  analysis:()=>rejectedObserved,stalled:()=>new Promise(()=>{}),
},source=>source.identity);
assert.equal(settlementObserver.wrappers.live.call(settlementReceiver,{identity:'exact-owner'},'unchanged'),delayedObserved);
assert.equal(observedCalls,1);
const observedPending=settlementObserver.pending('live','exact-owner');assert.equal(observedPending.length,1);
setTimeout(()=>{lateObservedCommit=true;releaseObserved();},180);
const observedTerminal=await waitForSourceOwnershipSettlement(settlementObserver.read,observedPending[0]);
assert.equal(observedTerminal.status,'fulfilled');assert(lateObservedCommit,'Settlement accepted before the obsolete completion');
assert.throws(()=>assert.equal(lateObservedCommit,false),'A late stale commit must fail the post-settlement acceptance');
assert.equal(settlementObserver.wrappers.analysis({identity:'exact-owner'}),rejectedObserved);
const rejectedPending=settlementObserver.pending('analysis','exact-owner')[0];rejectObserved(new Error('Synthetic cancellation'));
assert.equal((await waitForSourceOwnershipSettlement(settlementObserver.read,rejectedPending)).status,'rejected');
assert.equal(settlementObserver.failures().count,1);assert.equal(settlementObserver.failures().entries[0].error_message,'Synthetic cancellation');
settlementObserver.wrappers.stalled({identity:'exact-owner'});
await assert.rejects(waitForSourceOwnershipSettlement(settlementObserver.read,settlementObserver.pending('stalled','exact-owner')[0],60),/did not settle/);
await assert.rejects(waitForSourceOwnershipSettlement(settlementObserver.read,{...observedPending[0],identity:'other-owner'}),/exact receipt/);
console.log('PASS Sources held-operation terminal receipts: same promise/arguments/receiver, delayed stale-commit refusal, rejection, exact identity and bounded nonsettlement (not rendered QA)');

async function checkSourceFactsInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture,recordSourceCheck=()=>{}}) {
  const ownershipReceipts=[];
  const receipt=(label,detail)=>{const entry={label,...detail};ownershipReceipts.push(entry);recordSourceCheck(entry);};
  const press = value => {
    const code = {Enter:13,Escape:27,Home:36,End:35,ArrowLeft:37,ArrowRight:39,ArrowDown:40,Delete:46}[value];
    return key(value,value,{windowsVirtualKeyCode:code,
      ...(value==='Enter'?{text:'\r',unmodifiedText:'\r'}:{})});
  };
  const until = async (expression,message) => {
    const started=Date.now();
    while(Date.now()-started<5000){if(await evaluate(expression)) return;await new Promise(resolve=>setTimeout(resolve,25));}
    assert.fail(message);
  };
  const pendingRequest = async () => {
    const started=Date.now();
    while(Date.now()-started<5000){if(fixture.pending.length) return;await new Promise(resolve=>setTimeout(resolve,25));}
    assert.fail('Synthetic source-facts request did not reach the server');
  };
  const sourceClick = async selector => {
    // Scroll only the intended Sources details pane, then use the same strict
    // hit-tested pointer helper. Do not hide clipping by scrolling the workspace.
    const delta=await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});if(!n)throw new Error('Missing source control');const p=n.closest('#source-sidebar .debug-panes');if(!p)return 0;const r=n.getBoundingClientRect(),b=p.getBoundingClientRect();return r.top<b.top?r.top-b.top:r.bottom>b.bottom?r.bottom-b.bottom:0;})()`);
    if(delta) await wheel('#source-sidebar .debug-panes',delta);
    await click(selector);
  };
  await until("state.artifacts.length===2",'Synthetic captured sources did not load');
  await click('[data-screen="sources"]');
  await click('[data-artifact-id="7"]');
  await evaluate("state.sourceHooksOpen=true; document.querySelector('#screen-sources').dataset.hooksOpen='true'; renderSourceSidebar()");
  await click('#source-facts-toggle');
  assert.equal(await evaluate("state.sourceHooksOpen"),false,'Facts must dismiss the mutually exclusive Hooks pane');
  await until("document.querySelectorAll('#source-facts-report .source-fact').length===100",'Facts did not load visibly');
  assert.match(await evaluate("document.querySelector('#source-facts-report').textContent"),/Session 11 · artifact 7/);
  assert.match(await evaluate("document.querySelector('.source-facts-coverage').textContent"),/Partial coverage.*1 unknown frontiers/);
  assert(!await evaluate("document.querySelector('.source-facts-status').textContent.includes('No facts loaded')"));
  assert(await evaluate("getComputedStyle(document.querySelector('#source-facts-details')).display!=='none'"),'Stored HTTP artifacts must expose facts without a live debugger');
  await sourceClick('[data-facts-action="next"]');
  assert.match(await evaluate("document.querySelector('#source-facts-report').textContent"),/Showing 101–200 of 205/);
  await sourceClick('[data-facts-action="next"]');
  assert.equal(await evaluate("document.querySelectorAll('#source-facts-report .source-fact').length"),5);
  await sourceClick('[data-facts-action="previous"]');
  await sourceClick('[data-facts-action="previous"]');
  await sourceClick('#source-facts-report select');
  await press('Home');await press('ArrowDown');await press('Enter');
  await until("document.querySelector('#source-facts-report select').value==='bindings'",'Keyboard category selection failed');
  assert.equal(await evaluate("document.querySelectorAll('#source-facts-report .source-fact').length"),1);
  await sourceClick('.source-fact > button');
  await until("document.querySelector('#source-position').textContent.includes('Original UTF-8 bytes')",'Original-byte link did not navigate');
  assert.match(await evaluate("document.querySelector('#source-position').textContent"),/Line 1, Column 8/);
  assert.equal(await evaluate("state.sourceFormatted || state.sourceDeobfuscated"),false);
  assert(await evaluate("document.querySelector('#source-code .source-text').textContent.startsWith('\\ufeffconst 雪')"),'Original BOM must remain in byte-mapped view');
  await screenshot('source-facts-wide-original');
  fixture.mode='complete';await sourceClick('[data-facts-action="retry-facts"]');
  await until("document.querySelector('.source-facts-coverage').textContent.includes('Complete within lexical-effects-v1 only')",'Complete coverage must remain profile-relative');
  fixture.mode='truncated';await sourceClick('[data-facts-action="retry-facts"]');
  await until("document.querySelector('.source-facts-coverage').textContent.includes('TRUNCATED')",'Truncated coverage was hidden');
  await sourceClick('#source-facts-report select');await press('End');await press('Enter');
  await until("document.querySelector('#source-facts-report select').value==='frontiers'",'Unknown-frontier category did not open');
  assert.match(await evaluate("document.querySelector('.source-fact').textContent"),/abrupt-completion/);
  fixture.mode='error';await sourceClick('[data-facts-action="retry-facts"]');
  await until("document.querySelector('.source-facts-status').textContent.includes('Synthetic worker unavailable')",'Worker failure was hidden');
  fixture.mode='malformed';await sourceClick('[data-facts-action="retry-facts"]');
  await until("document.querySelector('.source-facts-status').textContent.includes('did not match')",'Changed source identity was accepted');
  assert.match(await evaluate("document.querySelector('#source-facts-report').textContent"),/last successful facts remain visible/);
  fixture.mode='unavailable';await sourceClick('[data-facts-action="retry-facts"]');
  await until("document.querySelector('.source-facts-coverage').textContent.includes('Analysis unavailable')",'Unavailable analysis was hidden');
  assert.equal(await evaluate("document.querySelectorAll('#source-facts-report .source-fact').length"),0);
  fixture.mode='pending';await sourceClick('[data-facts-action="retry-facts"]');await pendingRequest();
  await until("document.querySelector('[data-facts-action=cancel]')!==null",'Pending request has no Cancel');
  await sourceClick('[data-facts-action="cancel"]');fixture.mode='partial';fixture.release();
  assert(!await evaluate("document.querySelector('.source-facts-status').textContent.includes('Analyzing')"));
  await sourceClick('[data-facts-action="retry-facts"]');
  await until("document.querySelector('.source-facts-coverage').textContent.includes('Partial coverage')",'Explicit retry failed');
  fixture.mode='pending';await sourceClick('[data-facts-action="retry-facts"]');await pendingRequest();
  await click('[data-artifact-id="8"]');fixture.mode='partial';fixture.release();
  assert.equal(await evaluate("document.querySelectorAll('#source-facts-report .source-fact').length"),0,'Old artifact result survived selection');
  assert.match(await evaluate("document.querySelector('#source-facts-report').textContent"),/Session 11 · artifact 8/);
  await sourceClick('[data-facts-action="analyze-captured-source"]');
  await until("document.querySelectorAll('#source-facts-report .source-fact').length>0",'Second artifact did not load');
  assert(fixture.requests.every(query=>new URLSearchParams(query).get('session_id')==='11'));
  await sourceClick('[data-facts-action="close"]');
  assert.equal(await evaluate("document.querySelector('#source-facts-details').open"),false);
  assert.equal(await evaluate("document.activeElement.id"),'source-facts-toggle');
  await press('Enter');await until("document.querySelector('#source-facts-details').open",'Keyboard reopen failed');
  await press('Escape');assert.equal(await evaluate("document.querySelector('#source-facts-details').open"),false);
  await viewport(760,560);await click('#source-facts-toggle');
  await sourceClick('#source-facts-report select');await press('Home');await press('ArrowDown');await press('Enter');
  await until("document.querySelector('#source-facts-report select').value==='bindings'",'Narrow category failed');
  await screenshot('source-facts-narrow-details');
  await sourceClick('.source-fact > button');
  await until("document.querySelector('#source-sidebar').hidden",'Narrow overlay obscures original source after navigation');
  assert(await evaluate("document.activeElement.classList.contains('source-line')"),'Original range should own keyboard focus');
  assert(await evaluate("document.documentElement.scrollWidth<=innerWidth"),'Sources has horizontal page overflow');
  await screenshot('source-facts-narrow-original');
  await click('#source-facts-toggle');assert.equal(await evaluate("document.querySelector('#source-sidebar').hidden"),false,'Facts must reopen its hidden sidebar');
  await sourceClick('[data-facts-action="close"]');
  await viewport(1440,900);await click('#source-facts-toggle');
  fixture.mode='pending';await sourceClick('[data-facts-action="retry-facts"]');await pendingRequest();
  await click('[data-screen="traffic"]');fixture.mode='partial';fixture.release();
  assert(!await evaluate("document.querySelector('.source-facts-status').textContent.includes('Analyzing')"),'Leaving Sources must cancel response ownership');
  await click('[data-screen="sources"]');
  await click('[data-artifact-id="8"]');
  assert.equal(await evaluate("state.selectedArtifactId"),'8');
  // This remains the existing Sources browser mode, with the same hit-tested
  // pointer, keyboard, scroll and screenshot driver. No analyzed code runs.
  if(await evaluate("document.querySelector('#source-facts-details').open"))await sourceClick('[data-facts-action="close"]');
  assert.equal(fixture.analysisRequests.length,0,'Selection and Facts must not start Deob');
  const longSource=Array.from({length:600},(_,index)=>`const row${index} = ${index};`).join('\n');
  await fixture.addSource('9',longSource);await evaluate('refreshArtifacts()');
  fixture.previewMode='pending-body';await click('[data-artifact-id="9"]');
  const waiting=Date.now()+5000;while(!fixture.previewPending.length && Date.now()<waiting)await new Promise(resolve=>setTimeout(resolve,25));
  assert(fixture.previewPending.length,'Preview did not reach delayed body fixture');
  await fixture.addSource('10','const retry = 10;');await evaluate('refreshArtifacts()');
  assert(await evaluate("selectedSource().loading && document.querySelector('#source-code-empty').textContent.includes('Loading')"));
  fixture.previewMode='ready';fixture.releasePreview();
  await until("selectedSource()?.content?.includes('row599') && !selectedSource().loading",'Catalog refresh stranded the selected preview');
  await wheel('#source-code-wrap',900);
  await click('#source-search');for(const letter of 'row')await key(letter,`Key${letter.toUpperCase()}`,{text:letter,unmodifiedText:letter});
  await press('Enter');await press('Enter');
  const reading=await evaluate("({top:elements.sourceCodeWrap.scrollTop,index:state.sourceSearchIndex,focus:document.activeElement.id})");
  assert(reading.index>0);await evaluate('renderSources()');
  assert.deepEqual(await evaluate("({top:elements.sourceCodeWrap.scrollTop,index:state.sourceSearchIndex,focus:document.activeElement.id})"),reading,'Refresh moved the current reading/find position');
  fixture.deobMode='wrong-id';await click('#source-deob');
  await until("document.querySelector('#source-view-kind').textContent.includes('analysis failed')",'Mismatched analyzer identity was not visibly refused');
  assert(await evaluate("document.querySelector('#source-code').textContent.includes('row599')"),'Bad analyzer response changed original preview');
  if(await evaluate("document.querySelector('#source-sidebar').hidden"))await click('#source-sidebar-toggle');
  fixture.deobMode='ready';await sourceClick('#deobfuscation-report button');
  await until("document.querySelector('#source-view-kind').textContent.includes('Derived')",'Explicit analysis retry did not recover');
  await click('#source-deob');assert(await evaluate("document.querySelector('#source-view-kind').textContent.includes('Original evidence preview')"));
  await screenshot('source-ownership-wide-recovered');
  if(!await evaluate("document.querySelector('#source-sidebar').hidden"))await click('#source-sidebar-toggle');
  await click('#source-editor-tabs [aria-selected="true"]');await press('ArrowLeft');assert.equal(await evaluate('state.selectedArtifactId'),'8');
  await press('ArrowRight');assert.equal(await evaluate('state.selectedArtifactId'),'9');await press('Delete');
  assert.equal(await evaluate("state.openArtifactIds.includes('9')"),false);
  assert.equal(await evaluate("state.artifacts.find(value=>value.artifact_id==='9').content===undefined"),true,'Closing a source retained its preview');
  assert.equal(fixture.documents.get('9').toString('utf8'),longSource,'Closing a preview changed original fixture bytes');
  fixture.previewMode='wrong-bytes';await click('[data-artifact-id="10"]');
  await until("document.querySelector('#source-code-empty').textContent.includes('SHA-256')",'Wrong preview bytes were accepted');
  await viewport(760,560);await screenshot('source-ownership-narrow-error');
  fixture.previewMode='ready';await click('#source-code-empty button');
  await until("document.querySelector('#source-code').textContent.includes('const retry = 10;')",'Visible source retry did not recover');
  await viewport(360,740);await screenshot('source-ownership-small-recovered');
  assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),'Sources narrow recovery overflows the page');
  await viewport(1440,900);
  const waitFixture = async (pending,label) => {
    const deadline=Date.now()+5000;while(!pending.length&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,25));
    assert(pending.length,label);
  };
  // Real browser interaction over validated synthetic debugger replies. The
  // fixture's JavaScript is rendered as text, never loaded into a target page.
  await click('#source-search');await key('a','KeyA',{modifiers:2,windowsVirtualKeyCode:65});
  const selectedQuery=await evaluate('({focused:document.activeElement===elements.sourceSearch,value:elements.sourceSearch.value,start:elements.sourceSearch.selectionStart,end:elements.sourceSearch.selectionEnd})');
  assert.deepEqual(selectedQuery,{focused:true,value:'row',start:0,end:3},'Ctrl+A must select the complete prior source query before clearing it');
  await key('Backspace','Backspace',{windowsVirtualKeyCode:8});
  assert.equal(await evaluate('elements.sourceSearch.value'),'');
  const liveText="const owner = 'one';\n"+Array.from({length:180},(_,index)=>`const liveRow${index}={value:${index}};`).join('\n');
  fixture.addLiveSource('qa-live-source',liveText);await evaluate('refreshDebugger()');
  await until("state.debuggerSession?.scripts.some(source=>source.script_id==='qa-live-source')",'Validated live fixture did not reach Page');
  await click('[data-source-collection="page"]');await click('#source-tree [data-script-id="qa-live-source"]');
  await until(`selectedSource()?.content===sourceOwnedLiveText(selectedSource()) && selectedSource()?.content?.includes("owner = 'one'")`,'Complete owned live text did not load');
  const analysisBeforeLive=fixture.analysisRequests.length;
  for(const [size,index] of [[[1440,900],0],[[760,560],1]]) {
    await viewport(...size);
    // Home/End and return focus are exercised on the real mixed file-tab strip.
    await click('#source-editor-tabs [aria-selected="true"]');await press('End');await press('Home');
    assert.equal(await evaluate('state.selectedScriptId'),'qa-live-source');
    assert(await evaluate("document.activeElement.matches('#source-editor-tabs [aria-selected=true]')"),'Keyboard tab switch lost selected-tab focus');
    for(const [mode,button] of [['pretty','#source-pretty'],['derived','#source-deob']]) {
      await click(button);await until(mode==='pretty'?'state.sourceFormatted':"Boolean(sourceDerivedView(selectedSource())) && state.sourceDeobfuscated",`${mode}: representation did not become ready`);
      await click('#source-code-wrap');await wheel('#source-code-wrap',500);
      const before=await evaluate("({top:elements.sourceCodeWrap.scrollTop,left:elements.sourceCodeWrap.scrollLeft,focus:document.activeElement.id})");
      assert(before.top>0,`${mode}: live editor did not scroll`);assert.equal(before.focus,'source-code-wrap');
      const artifactId=String(40+index*2+(mode==='derived'?1:0));await fixture.addSource(artifactId,`const arrival${artifactId} = 1;`);
      await evaluate('refreshArtifacts()');await until(`state.artifacts.some(source=>source.artifact_id==='${artifactId}')`,'Background catalog did not refresh');
      const after=await evaluate("({top:elements.sourceCodeWrap.scrollTop,left:elements.sourceCodeWrap.scrollLeft,focus:document.activeElement.id})");
      receipt(`live-${size[0]}-${mode}-reading`,{viewport:size,before,after});
      assert.deepEqual(after,before,`${mode}: background refresh moved editor reading/focus`);
      const mapped=await evaluate(`(()=>{const box=elements.sourceCodeWrap.getBoundingClientRect();const button=[...elements.sourceCode.querySelectorAll('.source-gutter')].find(node=>{const r=node.getBoundingClientRect();return !node.disabled && r.top>=box.top+2 && r.bottom<=box.bottom-2;});if(!button)return null;return {line:button.parentElement.dataset.line,label:button.getAttribute('aria-label')};})()`);
      receipt(`live-${size[0]}-${mode}-gutter`,{viewport:size,mapped});
      assert(mapped && /^Show original source at line [0-9]+$/.test(mapped.label),`${mode}: refreshed live gutter lost original-map action`);
      const originalLine=Number(mapped.label.match(/[0-9]+$/)[0])-1;
      await screenshot(`source-ownership-${size[0]}-${mode}-mapped`);
      await click(`#source-code .source-line[data-line="${mapped.line}"] .source-gutter`);
      assert.equal(await evaluate('state.sourceFormatted || state.sourceDeobfuscated'),false);
      assert.equal(await evaluate('sourceCursorFor(selectedSource())?.line'),originalLine,`${mode}: mapped gutter navigated to the wrong original location`);
      assert(await evaluate("document.activeElement.classList.contains('source-line')"),`${mode}: original-map return lost row focus`);
      assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),'Live Sources mapping overflowed the viewport');
    }
  }
  assert(fixture.analysisRequests.length>analysisBeforeLive,'Explicit live Deob never reached the inert analyzer route');
  assert.equal(fixture.rejectedWrites.length,0,'Mapped gutter interaction attempted a debugger mutation');
  // Observe the complete real client operations, including body reads, hashing
  // and final ownership checks. This does not invoke loaders or alter UI state.
  await evaluate(`(()=>{const original={live:loadScriptContent,analysis:loadDeobfuscation};const observer=(${sourceOwnershipOperationObserver.toString()})(original,sourceIdentity);globalThis.__sourceOwnershipQA={...observer,restore(){loadScriptContent=original.live;loadDeobfuscation=original.analysis;delete globalThis.__sourceOwnershipQA;}};loadScriptContent=observer.wrappers.live;loadDeobfuscation=observer.wrappers.analysis;})()`);
  const heldOperation=async kind=>{
    const entries=await evaluate(`globalThis.__sourceOwnershipQA.pending(${JSON.stringify(kind)},sourceIdentity(selectedSource()))`);
    assert.equal(entries.length,1,`Expected exactly one held ${kind} operation for the selected identity`);return entries[0];
  };
  const releaseAndSettle=async(operation,release)=>{
    const before=await evaluate(`globalThis.__sourceOwnershipQA.read(${operation.id})`);
    assert(before&&before.id===operation.id&&before.kind===operation.kind&&before.identity===operation.identity,'Held operation changed before release');
    const releaseRequestedAt=Date.now();release();
    const terminal=await waitForSourceOwnershipSettlement(id=>evaluate(`globalThis.__sourceOwnershipQA.read(${id})`),operation);
    return {operation:terminal,terminal_before_release:before.status!=='pending',release_requested_at:releaseRequestedAt};
  };
  try {
  // Closing an in-flight live tab must cancel it. Release the server hold,
  // establish client termination, then assert no stale preview commit. A client
  // which already aborted is recorded as terminal before release, not delivery.
  fixture.addLiveSource('qa-pending-source','const pendingOwner = 1;');await evaluate('refreshDebugger()');
  await until("state.debuggerSession.scripts.some(source=>source.script_id==='qa-pending-source')",'Pending live fixture was not discovered');
  fixture.liveMode='pending-body';await click('#source-tree [data-script-id="qa-pending-source"]');
  await waitFixture(fixture.livePending,'Live body did not enter held state');
  const closedLiveOperation=await heldOperation('live');
  await click('#source-editor-tabs [aria-selected="true"]');await press('Delete');
  assert.equal(await evaluate("state.liveScriptContent.has('qa-pending-source') || state.openScriptIds.includes('qa-pending-source')"),false);
  fixture.liveMode='ready';const closedLiveSettlement=await releaseAndSettle(closedLiveOperation,fixture.releaseLive);
  const closedLiveRetained=await evaluate("state.liveScriptContent.has('qa-pending-source')");
  receipt('closed-live-late-body',{...closedLiveSettlement,retained:closedLiveRetained});
  assert.equal(closedLiveRetained,false,'Closed late live body repopulated the cache');
  // Reuse the same script ID and opaque token on a replacement target. The
  // held old text must never replace the fresh target's complete owned text.
  await click('#source-editor-tabs [aria-selected="true"]');await press('Delete');
  fixture.liveMode='pending-body';await click('[data-source-collection="page"]');
  await waitFixture(fixture.livePending,'Old target body did not enter held state');
  const replacedLiveOperation=await heldOperation('live');
  fixture.liveMode='ready';fixture.debuggerState.target={...fixture.debuggerState.target,id:'qa-source-page-two',title:'Replacement synthetic source owner'};
  fixture.debuggerState.targets=[fixture.debuggerState.target];fixture.debuggerState.generation++;
  fixture.liveDocuments.get('qa-live-source').text=liveText.replace("owner = 'one'","owner = 'two'");
  await evaluate('refreshDebugger()');
  await until(`selectedSource()?.target_id==='qa-source-page-two' && selectedSource()?.content?.includes("owner = 'two'") && !selectedSource().loading`,'Replacement target did not obtain its own complete text');
  const replacedLiveSettlement=await releaseAndSettle(replacedLiveOperation,fixture.releaseLive);
  const replacementOwned=await evaluate(`selectedSource().content.includes("owner = 'two'") && !selectedSource().content.includes("owner = 'one'")`);
  receipt('replacement-target-late-body',{...replacedLiveSettlement,newOwnerPreserved:replacementOwned});
  assert(replacementOwned,'Retired target body replaced the new source');
  // An explicit Deob on that new owner is held, then its tab is closed. Both
  // the pending request and every analysis variant for that owner must retire.
  fixture.deobMode='pending';await click('#source-deob');await waitFixture(fixture.deobPending,'Analyzer response did not enter held state');
  const closedAnalysisOperation=await heldOperation('analysis');
  const closedIdentity=await evaluate('sourceIdentity(selectedSource())');
  await click('#source-editor-tabs [aria-selected="true"]');await press('Delete');
  fixture.deobMode='ready';const closedAnalysisSettlement=await releaseAndSettle(closedAnalysisOperation,fixture.release);
  const analysisReleased=await evaluate(`![...state.deobfuscationRequests.keys(),...state.deobfuscationCache.keys()].some(key=>key.startsWith(${JSON.stringify(closedIdentity+'|')}))`);
  receipt('closed-live-late-analysis',{...closedAnalysisSettlement,released:analysisReleased,debuggerWrites:fixture.rejectedWrites.length});
  assert(analysisReleased,'Closed live analyzer owner retained a late result');
  assert.equal(fixture.rejectedWrites.length,0,'Sources QA issued an unexpected debugger action');
  await screenshot('source-ownership-narrow-closed-owner');await viewport(1440,900);
  } finally {
    // Attaching a rejection observer handles its promise, so explicitly fail QA
    // for every rejected/thrown loader, including calls outside the held case.
    const failures=await evaluate('(()=>{const observer=globalThis.__sourceOwnershipQA;if(!observer)return null;const failures=observer.failures();observer.restore();return failures;})()');
    assert(failures&&failures.count===0&&failures.pending===0,`Observed Sources loader errors or unfinished work: ${JSON.stringify(failures)}`);
  }
  // Real controls for the exact-span inspector over inert authored replies.
  const changedText='\ufeffconst 雪="😀";'+Array.from({length:7},(_,i)=>`const v${i}=1+${i};`).join('\n');
  fixture.changedSource='11';await fixture.addSource('11',changedText);await evaluate('refreshArtifacts()');
  await click('[data-source-collection="captured"]');await click('[data-artifact-id="11"]');
  await until("selectedSource()?.content?.includes('const v6')",'Changed-span fixture did not load');
  if(!await evaluate('state.sourceDeobfuscated'))await click('#source-deob');
  await until("selectedSource()?.deobfuscation?.sourceInspection?.changes.length===7",'Validated changed spans did not arrive');
  if(await evaluate("document.querySelector('#source-sidebar').hidden"))await click('#source-sidebar-toggle');
  if(!await evaluate("document.querySelector('#deobfuscation-details').open"))await sourceClick('#deobfuscation-details > summary');
  await sourceClick('[data-deob-control="change-next"]');await press('Enter');
  assert.match(await evaluate("elements.deobfuscationReport.textContent"),/Change 3 of 7/);
  assert.equal(await evaluate('document.activeElement.dataset.deobControl'),'change-next');
  await sourceClick('[data-deob-control="disclosure-tables"]');await sourceClick('[data-deob-control="tables-next"]');
  assert(await evaluate("elements.deobfuscationReport.textContent.includes('table-5')"),'Generic omissions hid recovered tables');
  await sourceClick('[data-deob-control="disclosure-transformations"]');await sourceClick('[data-deob-control="transformations-next"]');
  assert(await evaluate("elements.deobfuscationReport.textContent.includes('fixture-family-6')"),'Transformation summaries were silently truncated');
  await sourceClick('[data-deob-control="change-previous"]');await screenshot('deobfuscation-inspector-wide');
  fixture.deobMode='error';await sourceClick('[data-deob-control="reanalyze"]');
  await until("elements.deobfuscationReport.textContent.includes('Authored analyzer retry failure')",'Retry error did not remain visible');
  assert.equal(await evaluate("elements.deobfuscationReport.querySelectorAll('pre').length"),2,'Retry failure hid the previous snippets');
  await evaluate(`(()=>{const original={analysis:loadDeobfuscation};const observer=(${sourceOwnershipOperationObserver.toString()})(original,sourceIdentity);globalThis.__sourceOwnershipQA={...observer,restore(){loadDeobfuscation=original.analysis;delete globalThis.__sourceOwnershipQA;}};loadDeobfuscation=observer.wrappers.analysis;})()`);
  try {
    fixture.deobMode='pending';await sourceClick('[data-deob-control="retry"]');
    const deobDeadline=Date.now()+5000;while(!fixture.deobPending.length&&Date.now()<deobDeadline)await new Promise(resolve=>setTimeout(resolve,25));assert(fixture.deobPending.length);
    const cancelledOperation=await heldOperation('analysis');
    await sourceClick('[data-deob-control="cancel"]');fixture.deobMode='ready';
    const cancelledSettlement=await releaseAndSettle(cancelledOperation,fixture.release);
    assert.equal(await evaluate("state.deobfuscationRequests.get(deobfuscationKey(selectedSource()))?.status"),'cancelled');
    receipt('deobfuscation-cancelled-late-reply',{...cancelledSettlement,reportRetained:await evaluate("elements.deobfuscationReport.querySelectorAll('pre').length===2")});
  } finally {
    const failures=await evaluate('(()=>{const observer=globalThis.__sourceOwnershipQA;const failures=observer.failures();observer.restore();return failures;})()');
    assert.equal(failures.count,0);assert.equal(failures.pending,0);
  }
  await viewport(360,740);await screenshot('deobfuscation-inspector-narrow-cancelled');
  assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'),'Inspector overflows the narrow viewport');
  await sourceClick('[data-deob-control="reveal"]');
  await until("!state.sourceDeobfuscated&&!state.sourceFormatted&&document.activeElement.classList.contains('source-line')",'Original range did not navigate with keyboard focus');
  assert.match(await evaluate('elements.sourcePosition.textContent'),/Original UTF-8 bytes/);
  assert.equal(fixture.documents.get('11').toString('utf8'),changedText,'Inspector modified original fixture bytes');
  assert.equal(fixture.rejectedWrites.length,0,'Inspector executed a debugger mutation');
  await screenshot('deobfuscation-inspector-narrow-original');await viewport(1440,900);
  receipt('deobfuscation-inspector-controls',{changedSpans:7,recoveredTables:5,viewports:[1440,360],retryPreservesReport:true,cancelRetiresRequest:true,originalBytesPreserved:true});
  return {status:'passed',ownership_receipts:ownershipReceipts,path:'browser development Sources UI',source:'synthetic captured artifacts and validated debugger replies; no analyzed JavaScript executed',viewports:[[1440,900],[760,560],[360,740]],checks:['exact changed-span snippets, keyboard navigation, paging, retry preservation, cancel terminal receipt and original reveal at wide/360px widths','live pretty/derived mapped gutters survive background refresh and navigate by real click','editor scroll and keyboard focus retained at wide/narrow widths','mixed-tab Home/End and selected focus','close pending live body and analyzer responses','same script ID/opaque token on replacement target rejects old body','no debugger mutation from mapped links','pending preview body plus catalog refresh','no automatic Deob on source entry','mismatched analyzer and preview hash refusal','explicit analysis and preview retry','unchanged editor scroll and Find occurrence','keyboard file tabs and Delete cleanup','real hit-tested Facts controls','offline HTTP artifact availability','100-row paging','keyboard categories and disclosure','UTF-8/BOM original-byte navigation','profile-complete/partial/truncated/unknown/unavailable/error states','identity rejection and prior-report retention','Cancel and explicit retry','stale selection','Close/Escape/reopen focus','narrow overlay dismissal','workspace return']};
}

// Contract-valid synthetic investigation records, shared by the production-model
// checks and the existing real Chromium driver. No fixture code is executed.
const observationSourceBytes = Buffer.from('// Synthetic capture fixture.\nfunction collect() { return "metadata"; }\n');
const observationSourceHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', observationSourceBytes)), byte => byte.toString(16).padStart(2, '0')).join('');
function observationEvent(sequence, category, type, text, extra = {}) {
  const payload = Buffer.from(text);
  return {protocol_version:3,session_id:'7',sequence_number:String(sequence),monotonic_time_ns:String(1320000000n + BigInt(sequence) * 100000n),
    navigation_id:'101',frame_id:'301',artifact_id:'0',parent_event_id:'0',request_id:'0',process_id:42,thread_id:44,
    browser_context_id_high:'0',browser_context_id_low:'0',tab_id:3,initiator_request_id:0,initiator_process_id:0,
    encoded_data_length:'0',decoded_body_length:'0',status_code:0,error_code:0,resource_type:13,flags:0,
    category,type,payload_encoding:'hex',payload_size:payload.length,payload:payload.toString('hex'),payload_truncated:false,...extra};
}
function observationFixtureContext() {
  const events = [
    observationEvent(100,'navigator','property_read','Navigator.hardwareConcurrency'),
    observationEvent(101,'canvas','api_call','CanvasRenderingContext2D.fillText',{parent_event_id:'99',artifact_id:'9'}),
    observationEvent(102,'canvas','api_call','HTMLCanvasElement.toDataURL',{parent_event_id:'101',artifact_id:'9'}),
    observationEvent(103,'network','request_initiated','POST telemetry.fixture.invalid',{parent_event_id:'102',request_id:'9'}),
    observationEvent(104,'webgl','api_call','WebGLRenderingContext.getParameter',{artifact_id:'12'}),
    observationEvent(105,'permissions','api_call','Permissions.query'),
    observationEvent(106,'network','request_completed','telemetry.fixture.invalid',{parent_event_id:'103',request_id:'9',status_code:204}),
    observationEvent(106,'runtime','gap','2'),
    observationEvent(1,'webrtc','api_call','RTCPeerConnection.getStats',{process_id:77,navigation_id:'202',frame_id:'404'})
  ];
  const artifacts = [{protocol_version:1,session_id:'7',artifact_id:'9',navigation_id:'101',frame_id:'301',parent_artifact_id:'0',creator_event_id:'95',execution_context_id:'23',capture_origin:'network_response',kind:'javascript',url:'https://fixture.invalid/assets/collector.js',mime_type:'text/javascript',byte_size:observationSourceBytes.length,sha256:observationSourceHash,sensitive:false}];
  return {events,artifacts,request:{id:'evidence-investigation-request',origin:'live',method:'POST',path:'telemetry.fixture.invalid',hostOnly:true,events:events.filter(event=>event.category==='network')},eventsLimited:false};
}
const observationCode = (await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8')) + '\n' + packageSource;
const observationUI = runInNewContext(observationCode + ';({evidenceObservationModel,evidenceRequestKey,evidenceArtifactReference,isBrokerResponse,isArtifactResponse})', {TextDecoder, Uint8Array});
const observationContext = observationFixtureContext();
assert(observationUI.isBrokerResponse({count:observationContext.events.length,events:observationContext.events,capture_mode:'demo'}));
assert(observationUI.isArtifactResponse({count:observationContext.artifacts.length,artifacts:observationContext.artifacts}));
const observationModel = observationUI.evidenceObservationModel(observationContext);
assert.deepEqual(Array.from(observationModel.rows.filter(row=>row.group==='parent'),row=>row.key),['7:42:101','7:42:102']);
assert.deepEqual(Array.from(observationModel.rows.filter(row=>row.group==='request'),row=>row.key),['7:42:103','7:42:106']);
assert.equal(observationModel.rows.find(row=>row.key==='7:42:100').group,'context');
assert.equal(observationModel.rows.find(row=>row.key==='7:77:1').group,'unlinked');
assert.equal(observationModel.missingParents,1); assert.equal(observationModel.queueMarkers,1);
assert.equal(observationModel.rows.find(row=>row.key==='7:42:102').outcome,'Outcome not recorded');
assert.equal(observationModel.rows.find(row=>row.key==='7:42:104').artifact.status,'missing');
assert.equal(observationModel.linkedArtifacts,1);
const cachedObservationContext=observationFixtureContext();cachedObservationContext.artifacts[0].content='large cached source'.repeat(200000);cachedObservationContext.artifacts[0].deobfuscation={original_source:cachedObservationContext.artifacts[0].content};cachedObservationContext.events[0].unexpected_payload=cachedObservationContext.artifacts[0].content;
const cachedObservationModel=observationUI.evidenceObservationModel(cachedObservationContext);
assert(JSON.stringify(cachedObservationModel).length<16000,'Evidence render state must never retain or stringify cached source/analysis text or unknown event fields');
assert(!Object.hasOwn(cachedObservationModel.rows.find(row=>row.artifact.artifact)?.artifact.artifact,'content'));
const longURLContext=observationFixtureContext();longURLContext.artifacts[0].url='x'.repeat(1000000);
assert.equal(observationUI.evidenceObservationModel(longURLContext).rows.find(row=>row.artifact.artifact).artifact.artifact.url.length,2048);
const observationUnknown=structuredClone(observationContext);observationUnknown.events[0].frame_id='0';
assert.equal(observationUI.evidenceObservationModel(observationUnknown).rows[0].group,'unlinked');
const observationForeign=structuredClone(observationContext);observationForeign.events[0].session_id='8';
assert.equal(observationUI.evidenceObservationModel(observationForeign).rows[0].group,'unlinked');
const observationCollision=structuredClone(observationContext);observationCollision.events.push({...observationCollision.events[2]});
assert.equal(observationUI.evidenceObservationModel(observationCollision).rows.find(row=>row.key==='7:42:102').group,'unlinked');
observationCollision.artifacts.push({...observationCollision.artifacts[0],session_id:'8'});
assert.equal(observationUI.evidenceObservationModel(observationCollision).rows.find(row=>row.key==='7:42:101').artifact.status,'ambiguous');
const observationCDP={...observationContext,request:{...observationContext.request,protocolRequestId:'cdp-7',operation:'cdp_complete',tabId:'target',firstTimestamp:1320000000n}};
assert.equal(observationUI.evidenceObservationModel(observationCDP).correlatedRequest,true);
assert.notEqual(observationUI.evidenceRequestKey(observationCDP.request),observationUI.evidenceRequestKey({...observationCDP.request,firstTimestamp:1320000001n}));
const observationReused={...observationContext.request,events:observationContext.request.events.map(event=>({...event,session_id:'8'}))};
assert.notEqual(observationUI.evidenceRequestKey(observationContext.request),observationUI.evidenceRequestKey(observationReused));
const observationLarge={...observationContext,request:null,events:Array.from({length:6000},(_,index)=>observationEvent(index+1,'runtime','api_call','Date.now'))};
const largeObservationModel=observationUI.evidenceObservationModel(observationLarge);
assert.equal(largeObservationModel.rows.length,5000);assert.equal(largeObservationModel.limited,true);assert.equal(largeObservationModel.rows[0].key,'7:42:1001');
const observationCycle=structuredClone(observationContext);observationCycle.events[1].parent_event_id='102';
assert.equal(observationUI.evidenceObservationModel(observationCycle).parentCycle,true);
const observationBinary=structuredClone(observationContext);observationBinary.events[0].payload='ff';observationBinary.events[0].payload_size=1;
assert.equal(observationUI.evidenceObservationModel(observationBinary).rows[0].payload.encoding,'hex');
console.log('PASS Evidence observation model: contract-valid records, scoped parents, nonzero context, CDP qualification, unknown outcomes, exact artifact identity, ambiguity, eviction and bounds');

function observationPanelFixture(narrow = false) {
  const document={activeElement:null};
  class ObservationNode extends TrafficFixtureNode {
    matches(selector) {
      const match=selector.match(/^(?:(\w+))?\[([\w-]+)(?:="([^"]*)")?\]$/);
      if(match){const [,tag,name,value]=match; const actual=name.startsWith('data-')?this.dataset[name.slice(5).replace(/-([a-z])/g,(_,letter)=>letter.toUpperCase())]:this.getAttribute(name);return (!tag||this.tagName.toLowerCase()===tag)&&actual!==null&&actual!==undefined&&(value===undefined||actual===value);}
      return super.matches(selector);
    }
    focus(){document.activeElement=this;}
    scrollIntoView(){}
    replaceChildren(...nodes){if(this.contains(document.activeElement))document.activeElement=null;super.replaceChildren(...nodes);}
    emit(type,fields={}){for(const callback of this.listeners.get(type)??[])callback({target:this,currentTarget:this,preventDefault(){},...fields});}
  }
  document.createElement=tag=>new ObservationNode(tag);
  const ids=['evidence-investigation','evidence-rows','evidence-inspector','evidence-search','evidence-scope','evidence-workspace-notice','evidence-package-toggle','evidence-package-mode','evidence-return','evidence-trace','evidence-window-count','evidence-previous','evidence-next','evidence-context-kind','evidence-context-title','evidence-context-note','evidence-count','evidence-coverage-summary','evidence-gap-details','evidence-coverage-details','evidence-coverage-popover'];
  const nodes=Object.fromEntries(ids.map(id=>[id,new ObservationNode()]));
  document.querySelector=selector=>nodes[selector.slice(1)]??null;
  const layout=new ObservationNode();layout.className='evidence-investigation-layout';
  const tabs=['observations','detail'].map(value=>{const tab=new ObservationNode('button');tab.dataset.evidencePane=value;return tab;});
  nodes['evidence-coverage-details'].append(new ObservationNode('summary'),nodes['evidence-coverage-popover']);
  nodes['evidence-investigation'].append(nodes['evidence-coverage-details'],layout,...tabs);layout.append(nodes['evidence-rows'],nodes['evidence-inspector']);
  let context=observationFixtureContext(),packageVisible=false,packageCancels=0,sourceCalls=0;
  const create=runInNewContext(observationCode+';createEvidenceWorkspace',{document,TextDecoder,Uint8Array,window:{matchMedia:()=>({matches:narrow})}});
  const panel=create({getContext:()=>context,packagePanel:{sync(){},setVisible(value){packageVisible=value;if(!value)packageCancels++;}},onTrace(){},onRequest(){},onSource(){sourceCalls++;return true;},canOpenSource:()=>true});
  panel.setVisible(true);
  return {panel,nodes,tabs,document,get context(){return context;},set context(value){context=value;},get packageVisible(){return packageVisible;},get packageCancels(){return packageCancels;},get sourceCalls(){return sourceCalls;}};
}
const observations=observationPanelFixture();
const observationRows=()=>observations.nodes['evidence-rows'].querySelectorAll('[data-evidence-key]');
assert.equal(observationRows().length,7);
assert.equal(observations.nodes['evidence-coverage-summary'].textContent,'1 missing parent · coverage unknown');
assert.match(observations.nodes['evidence-gap-details'].textContent,/1 missing or ambiguous parent references/);
observationRows().find(row=>row.dataset.evidenceKey==='7:42:102').click();
const stableObservationInspector=observations.nodes['evidence-inspector'].children[0];
const provenanceSummary=observations.nodes['evidence-inspector'].querySelector('summary');
observations.nodes['evidence-inspector'].querySelector('details').open=true;provenanceSummary.focus();observations.nodes['evidence-inspector'].scrollTop=127;observations.panel.sync();
assert.equal(observations.nodes['evidence-inspector'].children[0],stableObservationInspector,'Unchanged refresh must preserve the inspector DOM');
assert.equal(observations.document.activeElement,provenanceSummary);assert.equal(observations.nodes['evidence-inspector'].scrollTop,127);
assert.match(observations.nodes['evidence-inspector'].textContent,/Outcome not recorded/);
assert.doesNotMatch(observationRows()[0].textContent,/session 7|process 42/,'First-view rows must not be dominated by identifiers');
observations.nodes['evidence-package-toggle'].click();assert.equal(observations.packageVisible,true);
observations.nodes['evidence-return'].click();assert.equal(observations.packageVisible,false);assert.equal(observations.panel.snapshot().selectedKey,'7:42:102');
assert.equal(observations.document.activeElement,observations.nodes['evidence-package-toggle']);
// A stale source button must not reinterpret the selected event's reference.
const staleSourceButton=observations.nodes['evidence-inspector'].querySelector('[data-evidence-action="source"]');
observations.context={...observations.context,artifacts:[]};staleSourceButton.click();assert.equal(observations.sourceCalls,0);
assert.match(observations.nodes['evidence-inspector'].textContent,/absent from the retained catalog/);
observations.context=observationFixtureContext();observations.panel.sync();
const retainedRow=observationRows().find(row=>row.dataset.evidenceKey==='7:42:102');retainedRow.focus();observations.nodes['evidence-rows'].scrollTop=89;
observations.context.events.push(observationEvent(108,'runtime','api_call','Date.now'));observations.panel.sync();
assert.equal(observations.document.activeElement.dataset.evidenceKey,'7:42:102');assert.equal(observations.nodes['evidence-rows'].scrollTop,89);
observations.context={...observations.context,events:observations.context.events.filter(event=>event.sequence_number!=='102')};observations.panel.sync();
assert.equal(observations.panel.snapshot().selectedKey,null);assert.match(observations.nodes['evidence-workspace-notice'].textContent,/left the retained window/);
observations.panel.sync();assert.equal(observations.panel.snapshot().selectedKey,null,'Eviction must not silently choose a neighboring record');
observations.context=observationCDP;observations.panel.sync();assert.match(observations.nodes['evidence-context-note'].textContent,/No exact producer request key/);
assert.match(observations.nodes['evidence-context-note'].textContent,/Matched by method, host and time/);
observationRows().find(row=>row.dataset.evidenceKey==='7:42:102').click();assert.match(observations.nodes['evidence-inspector'].textContent,/association does not become exact/);
observations.context=observationLarge;observations.panel.sync();assert.equal(observationRows().length,50);observations.nodes['evidence-next'].click();assert.match(observations.nodes['evidence-window-count'].textContent,/51–100 of 5000/);
observationRows()[0].emit('keydown',{key:'End'});assert.match(observations.nodes['evidence-window-count'].textContent,/4951–5000 of 5000/);
assert.equal(observations.document.activeElement.dataset.evidenceKey,'7:42:6000');
observations.nodes['evidence-search'].value='not-present';observations.nodes['evidence-search'].emit('input');assert.match(observations.nodes['evidence-rows'].textContent,/No retained observations match/);
observations.context={events:[],artifacts:[],request:null,error:'disconnected'};observations.panel.sync();assert.match(observations.nodes['evidence-workspace-notice'].textContent,/refresh is unavailable/);
observations.context={events:[],artifacts:[],request:null};observations.panel.sync();assert.doesNotMatch(observations.nodes['evidence-workspace-notice'].textContent,/refresh/);
console.log('PASS Evidence production reconciliation: stable inspector/focus/scroll, secondary package mode, stale exact-source refusal, eviction, CDP disclosure, 5,000-record paging, keyboard and failed refresh');

// Arrival order is not retained-identity membership and neither proves loss.
for (const [ids, holes, jumps, late] of [[[1,3,2],'0',1,1],[[1,4,3],'1',1,1],[[3,2,1],'0',0,2],[[1,5],'3',1,0]]) {
  const value=observationUI.evidenceObservationModel({events:ids.map(id=>observationEvent(id,'runtime','api_call','Date.now')),artifacts:[]});
  assert.equal(value.sequence.holes,holes);assert.equal(value.sequence.arrivalDiscontinuities,jumps);assert.equal(value.sequence.outOfOrderArrivals,late);
}
const scopedHoleEvents=[observationEvent(1,'runtime','api_call','Date.now'),observationEvent(3,'runtime','api_call','Date.now'),observationEvent(2,'runtime','api_call','Date.now',{session_id:'8'}),observationEvent(3,'runtime','gap','5')];
const scopedHoles=observationUI.evidenceObservationModel({events:scopedHoleEvents,artifacts:[]});
assert.equal(scopedHoles.sequence.holes,'1');assert.equal(scopedHoles.queueMarkers,1);
for (const narrow of [false,true]) {
  const panel=observationPanelFixture(narrow), nodes=panel.nodes;
  nodes['evidence-search'].value='toDataURL';nodes['evidence-search'].emit('input');
  const scopeBefore=nodes['evidence-scope'].value;
  nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:102"]').click();
  nodes['evidence-inspector'].querySelector('[data-evidence-action="parent"]').click();
  assert.equal(panel.panel.snapshot().selectedKey,'7:42:101');assert.equal(nodes['evidence-search'].value,'toDataURL');assert.equal(nodes['evidence-scope'].value,scopeBefore);
  assert.match(nodes['evidence-workspace-notice'].textContent,/selected parent is outside the current filter/);
  assert.equal(panel.document.activeElement,nodes['evidence-inspector'],'A parent outside the filter focuses its visible inspector; DOM fixture is not rendered proof');
  if(narrow)assert.equal(panel.panel.snapshot().pane,'detail');
  nodes['evidence-search'].value='';nodes['evidence-search'].emit('input');assert.equal(nodes['evidence-workspace-notice'].hidden,true,'Outside-filter notice must clear once the selected parent is included again');
}
const evictionNotice=observationPanelFixture();
evictionNotice.nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:102"]').click();
evictionNotice.context.events=evictionNotice.context.events.filter(event=>event.sequence_number!=='102');evictionNotice.context.error='disconnected';evictionNotice.panel.sync();
assert.match(evictionNotice.nodes['evidence-workspace-notice'].textContent,/left the retained window/);
evictionNotice.nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:101"]').click();
assert.doesNotMatch(evictionNotice.nodes['evidence-workspace-notice'].textContent,/left the retained window/);
assert.match(evictionNotice.nodes['evidence-workspace-notice'].textContent,/refresh is unavailable/);
evictionNotice.context.error=null;evictionNotice.panel.sync();assert.equal(evictionNotice.nodes['evidence-workspace-notice'].hidden,true);
const duplicateSource=observationPanelFixture();
duplicateSource.nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:102"]').click();
const duplicateSourceAction=duplicateSource.nodes['evidence-inspector'].querySelector('[data-evidence-action="source"]');
const exactSnapshot=duplicateSource.panel.snapshot();duplicateSource.context.events.push({...duplicateSource.context.events.find(event=>event.sequence_number==='102')});
duplicateSourceAction.click();assert.equal(duplicateSource.sourceCalls,0);assert.equal(duplicateSource.panel.canRestore(exactSnapshot),false);
const coveragePanel=observationPanelFixture();coveragePanel.nodes['evidence-coverage-details'].open=true;
coveragePanel.nodes['evidence-coverage-details'].emit('keydown',{key:'Escape',stopPropagation(){}});
assert.equal(coveragePanel.nodes['evidence-coverage-details'].open,false);assert.equal(coveragePanel.document.activeElement,coveragePanel.nodes['evidence-coverage-details'].querySelector('summary'));
console.log('PASS Evidence review regressions: arrival versus retained holes, scope separation, parent draft preservation, narrow visible-pane focus target, independent selection/error notices and stale duplicate source refusal');



// Exercise the actual shared boundary against the real Evidence controller.
// The lightweight DOM checks identity/ownership; CI owns visibility/geometry.
for (const scenario of ['return','evicted','duplicate','changed-session','interrupted']) {
  const fixture=observationPanelFixture(true), {nodes,document:owner}=fixture;
  const request=fixture.context.request;
  const other={...request,id:'other',events:request.events.map(event=>({...event,session_id:'8'}))};
  const state={requests:[request,other],events:fixture.context.events,artifacts:fixture.context.artifacts,selectedRequestId:request.id,decoderSteps:[],inspectorTab:'evidence'};
  for(const [id,node] of Object.entries(nodes))node.id=id;
  nodes['evidence-rows'].querySelector('[data-evidence-key="7:42:102"]').click();
  const source=nodes['evidence-inspector'].querySelector('[data-evidence-action="source"]');source.focus();
  nodes['evidence-rows'].scrollTop=55;nodes['evidence-inspector'].scrollTop=81;
  const panes=[nodes['evidence-rows'],nodes['evidence-inspector'],nodes['evidence-package-mode']];
  const evidenceRoot={id:'screen-evidence',scrollTop:0,scrollLeft:0,contains:()=>true,matches:s=>s==='#screen-evidence',querySelectorAll:()=>panes,
    querySelector:selector=>selector==='#evidence-open-source'?nodes['evidence-inspector'].querySelector('[data-evidence-action="source"]'):nodes[selector.slice(1)]};
  let screen='evidence',notice='',selections=0;const raf=[];
  const back={focus(){owner.activeElement=back;}};
  const document={get activeElement(){return owner.activeElement;},querySelector:selector=>selector==='.screen:not([hidden])'?{id:`screen-${screen}`}:selector==='#screen-evidence'?evidenceRoot:selector==='#investigation-notice'?{textContent:notice}:selector==='#investigation-back'?back:null};
  const sandbox={state,document,CSS:{escape:s=>s},evidenceWorkspace:fixture.panel,sourceFactsPanel:{},selectedSource:()=>null,integerText:(e,k)=>String(e[k]),requestAnimationFrame:fn=>raf.push(fn),
    selectRequest:id=>{state.selectedRequestId=id;fixture.context={...fixture.context,request:state.requests.find(item=>item.id===id)};fixture.panel.sync();selections++;},
    showScreen:name=>{screen=name;fixture.panel.setVisible(name==='evidence');},noticeWriter:value=>{notice=value;}};
  const code=await readFile(join(root,'apps/research-ui/investigation_navigation.js'),'utf8');
  const nav=runInNewContext(appSection('      function requestTraceRoot(','      function requestSignalProfileSelection(')+code+';investigationNotice=noticeWriter;({snapshot:investigationSnapshot,restore:restoreInvestigation,retire:retireInvestigationReturn})',sandbox);
  const saved=nav.snapshot();assert.equal(saved.evidence.selectedKey,'7:42:102');assert.equal(saved.focus,'#evidence-open-source');
  assert(!JSON.stringify(saved).includes('payload'),'History cannot retain record payloads');
  screen='sources';state.selectedRequestId='other';fixture.context={...fixture.context,request:other};fixture.panel.sync();fixture.panel.setVisible(false);
  nodes['evidence-search'].value='newer filter';nodes['evidence-scope'].value='all';
  if(scenario==='evicted')fixture.context.events=fixture.context.events.filter(event=>event.sequence_number!=='102');
  if(scenario==='duplicate')fixture.context.events=[...fixture.context.events,{...fixture.context.events.find(event=>event.sequence_number==='102')}];
  if(scenario==='changed-session')state.requests=[{...request,events:other.events},other];
  const restored=nav.restore(saved);
  if(['evicted','duplicate','changed-session'].includes(scenario)) {assert.equal(restored,false);assert.equal(screen,'sources');assert.equal(selections,0,'Failed preflight must not mutate current request');continue;}
  assert.equal(restored,true);assert.equal(state.selectedRequestId,request.id);assert.equal(fixture.panel.snapshot().pane,'detail');
  if(scenario==='interrupted'){nav.retire();nodes['evidence-inspector'].scrollTop=777;owner.activeElement=nodes['evidence-search'];}
  await Promise.resolve();for(const callback of raf.splice(0))callback();
  assert.equal(nodes['evidence-search'].value,'newer filter');assert.equal(nodes['evidence-scope'].value,'all');
  if(scenario==='interrupted'){assert.equal(nodes['evidence-inspector'].scrollTop,777);assert.equal(owner.activeElement,nodes['evidence-search']);}
  else {assert.equal(nodes['evidence-rows'].scrollTop,55);assert.equal(nodes['evidence-inspector'].scrollTop,81);assert.equal(owner.activeElement.id,'evidence-open-source');assert.match(nodes['evidence-workspace-notice'].textContent,/outside the current filter/);}
}
console.log('PASS shared Evidence return with original request preflight, selected-key/pane ownership, independent scroll, exact focus, preserved current filters, evicted/duplicate/session refusal and interrupted focus (not rendered QA)');

// The rendered fixture tests presentation and user actions. The separate real
// native-writer/HTTP probe establishes authoritative export and validation.
function evidenceBrowserFixture() {
  const fixture={mode:'valid',requests:[],pending:[],lastValidation:null,observationActive:false,derivedRequests:0};
  fixture.observation=observationFixtureContext();
  const bytes=packageGoldenBytes;
  fixture.events=packageGolden.records.events.map(row=>({...row,...row.key}));
  fixture.artifacts=packageGolden.records.artifacts.map(row=>({...row,...row.key}));
  fixture.handle=async(request,response)=>{
    const path=new URL(request.url,'http://127.0.0.1').pathname;
    if(path==='/api/deobfuscation') fixture.derivedRequests++;
    if(fixture.observationActive){
      const send=value=>{response.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});response.end(JSON.stringify(value));};
      if(fixture.observationFrozen&&['/api/events','/api/artifacts'].includes(path)){response.writeHead(304);response.end();return true;}
      if(path==='/api/events'){send({count:fixture.observation.events.length,events:fixture.observation.events,capture_mode:'live',broker_connected:true,capture_controls_available:false});return true;}
      if(path==='/api/artifacts'){send({count:fixture.observation.artifacts.length,artifacts:fixture.observation.artifacts});return true;}
      if(path==='/api/artifacts/9/content'){
        const parameters=new URL(request.url,'http://127.0.0.1').searchParams,offset=Number(parameters.get('offset')||0),limit=Number(parameters.get('limit')||2097152);
        const bytes=observationSourceBytes.subarray(offset,offset+limit);
        response.writeHead(200,{'Content-Type':'application/octet-stream','X-Artifact-Total-Bytes':String(observationSourceBytes.length),'X-Artifact-Offset':String(offset),'X-Artifact-Truncated':String(offset+bytes.length<observationSourceBytes.length)});response.end(bytes);return true;
      }
    }
    if(!['/api/evidence/packages/export','/api/evidence/packages/validate'].includes(path)) return false;
    let body=Buffer.alloc(0);
    for await(const chunk of request) {
      if(body.length+chunk.length>4194304){response.writeHead(413);response.end();return true;}
      body=Buffer.concat([body,chunk]);
    }
    fixture.requests.push({path,bytes:body.length});
    if(path.endsWith('/validate'))fixture.lastValidation=body;
    const mode=fixture.mode;
    if(mode==='pending_export'&&path.endsWith('/export')||mode==='pending_validate'&&path.endsWith('/validate')) await new Promise(resolve=>fixture.pending.push(resolve));
    if(response.destroyed)return true;
    const send=(status,value)=>{response.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});response.end(value);};
    if(mode==='writer_busy'){send(409,'{"error":"Synthetic held writer lease"}');return true;}
    if(mode==='unavailable'){send(503,'{"error":"Synthetic unavailable guarded store"}');return true;}
    if(path.endsWith('/export')){send(200,bytes);return true;}
    const invalid=mode==='invalid'||body.includes(Buffer.from('"protocol_version": 1, "protocol_version": 1'));
    const value=mode==='unsupported'?{...packageInvalid,status:'unsupported'}:invalid?packageInvalid:packageValid;
    send(200,JSON.stringify(value));return true;
  };
  fixture.release=()=>{for(const resolve of fixture.pending.splice(0))resolve();};
  return fixture;
}
// Exercise raw request admission and fixture status transitions before launching
// Chrome so a broken synthetic service cannot silently masquerade as UI success.
const evidenceFixtureControl=evidenceBrowserFixture();
async function evidenceFixtureResponse(path,body,mode='valid') {
  evidenceFixtureControl.mode=mode;
  const response={destroyed:false,writeHead(status,headers){this.status=status;this.headers=headers;},end(value){this.body=value;}};
  assert(await evidenceFixtureControl.handle({url:path,async *[Symbol.asyncIterator](){yield body;}},response));return response;
}
assert.deepEqual((await evidenceFixtureResponse('/api/evidence/packages/export',Buffer.from('{}'))).body,packageGoldenBytes);
assert.equal(JSON.parse((await evidenceFixtureResponse('/api/evidence/packages/validate',packageGoldenBytes)).body).status,'valid');
for(const [mode,status] of [['writer_busy',409],['unavailable',503]])assert.equal((await evidenceFixtureResponse('/api/evidence/packages/export',Buffer.from('{}'),mode)).status,status);
for(const status of ['invalid','unsupported'])assert.equal(JSON.parse((await evidenceFixtureResponse('/api/evidence/packages/validate',packageGoldenBytes,status)).body).status,status);
console.log('PASS Evidence browser fixture raw bytes, valid/invalid/unsupported and guarded-export errors (not rendered QA)');

async function checkEvidenceObservationInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture}) {
  const readingPanes=[];
  const until=async(expression,message)=>{const end=Date.now()+5000;while(Date.now()<end){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,25));}assert.fail(message);};
  const press=(value,code=value)=>key(value,code,{windowsVirtualKeyCode:({Enter:13,Escape:27,Home:36,End:35,ArrowDown:40,ArrowUp:38,Tab:9})[value],...(value==='Enter'?{text:'\r',unmodifiedText:'\r'}:{})});
  const observationReveal=async selector=>{
    for(let attempt=0;attempt<4;attempt++){
      const target=await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});if(!n)throw new Error('Missing observation control');const p=n.closest('#evidence-rows, #evidence-inspector');if(!p)return null;const r=n.getBoundingClientRect(),b=p.getBoundingClientRect();return {pane:'#'+p.id,delta:r.top<b.top+5?r.top-b.top-5:r.bottom>b.bottom-5?r.bottom-b.bottom+5:0};})()`);
      if(!target||Math.abs(target.delta)<=1)break;
      await wheel(target.pane,target.delta);
    }
  };
  const observationClick=async selector=>{await observationReveal(selector);await click(selector);};
  const geometry=async label=>{
    const result=await evaluate(`(()=>{const names=['#evidence-investigation','.evidence-investigation-layout','#evidence-rows','#evidence-inspector'];return {width:innerWidth,height:innerHeight,page:document.documentElement.scrollWidth,panes:names.map(name=>{const n=document.querySelector(name),r=n.getBoundingClientRect();return {name,visible:r.width>0&&r.height>0,left:r.left,right:r.right,top:r.top,bottom:r.bottom,client:n.clientHeight,scroll:n.scrollHeight,width:n.clientWidth,scrollWidth:n.scrollWidth};})};})()`);
    assert(result.page<=result.width+1,`${label}: no page-wide horizontal overflow`);
    for(const pane of result.panes.filter(value=>value.visible)){assert(pane.left>=-1&&pane.right<=result.width+1&&pane.bottom<=result.height+1,`${label}: ${pane.name} stays in viewport`);assert(pane.scrollWidth<=pane.width+1,`${label}: ${pane.name} does not clip content horizontally`);}
    const active=result.panes.find(value=>value.name==='#evidence-rows'&&value.visible)??result.panes.find(value=>value.name==='#evidence-inspector'&&value.visible);assert(active?.client>=120,`${label}: selected pane retains reading space (${active?.client ?? 0}px; minimum 120px)`);
    readingPanes.push({label,width:result.width,height:result.height,readingHeight:active.client});
  };
  fixture.observationActive=true;
  await evaluate('state.eventEtag=null;state.artifactEtag=null;refresh()');
  await until("state.events.some(event=>event.sequence_number==='102')&&state.artifacts.some(artifact=>artifact.artifact_id==='9')",'Investigation fixture did not load through normal broker/artifact routes');
  fixture.observationFrozen=true;
  await click('[data-request-id]');await click('#request-evidence-toggle');await click('#request-package-entry [data-screen="evidence"]');
  assert.equal(await evaluate("document.querySelector('#evidence-package-mode').hidden"),true,'Evidence must land on observations, not package controls');
  await observationClick('[data-evidence-key="7:42:102"]');
  assert.match(await evaluate("document.querySelector('#evidence-inspector').textContent"),/Outcome not recorded/);
  assert.match(await evaluate("document.querySelector('#evidence-rows').textContent"),/Recorded parent links.*Same captured context/);
  assert.equal(await evaluate("document.querySelectorAll('[data-package-candidates] input:checked').length"),0,'Observation selection must never select export identities');
  await geometry('wide investigation');await screenshot('evidence-investigation-wide');
  const inspectorBefore=await evaluate("document.querySelector('#evidence-inspector').scrollTop");await wheel('#evidence-rows',90);
  assert.equal(await evaluate("document.querySelector('#evidence-inspector').scrollTop"),inspectorBefore,'Observation scrolling must not move the record inspector');
  await observationClick('[data-evidence-key="7:42:102"]');await press('ArrowDown');
  assert.equal(await evaluate('evidenceWorkspace.snapshot().selectedKey'),'7:42:100','Keyboard movement follows the displayed group order');
  await press('ArrowUp');assert.equal(await evaluate('evidenceWorkspace.snapshot().selectedKey'),'7:42:102');
  await evaluate("window.observationFocus=document.activeElement;window.observationInspector=document.querySelector('#evidence-inspector').firstElementChild;evidenceWorkspace.sync()");
  assert.equal(await evaluate('document.activeElement===observationFocus'),true);assert.equal(await evaluate("document.querySelector('#evidence-inspector').firstElementChild===observationInspector"),true);
  await click('#evidence-package-toggle');await click('#evidence-return');
  assert.equal(await evaluate('evidenceWorkspace.snapshot().selectedKey'),'7:42:102');
  const sourceSupported=await evaluate("!document.querySelector('[data-evidence-action=source]').disabled");
  if(process.env.REB_UI_REQUIRE_EVIDENCE_NAVIGATION==='1')assert(sourceSupported,'Final composed acceptance requires the approved working source adapter');
  const sourceRoundTrips=[];
  const sourceRoundTrip=async label=>{
    if(!sourceSupported)return;
    // Seed other already-authored drafts without submitting, decoding or running.
    await evaluate("document.querySelector('#decoder-input').value='retain decoder input';document.querySelector('#native-console-source').value='/* retain console draft */'");
    await observationReveal('[data-evidence-action="source"]');
    await evaluate("window.evidenceReturnView={list:document.querySelector('#evidence-rows').scrollTop,detail:document.querySelector('#evidence-inspector').scrollTop,search:document.querySelector('#evidence-search').value,scope:document.querySelector('#evidence-scope').value,pane:evidenceWorkspace.snapshot().pane,decoder:document.querySelector('#decoder-input').value,console:document.querySelector('#native-console-source').value}");
    await click('[data-evidence-action="source"]');
    await until("!document.querySelector('#screen-sources').hidden&&selectedSource()?.artifact_id==='9'",'Exact captured source did not open');
    assert.equal(await evaluate('state.sourceDeobfuscated||state.sourceFormatted'),false);
    await click('#investigation-back');
    await until("!document.querySelector('#screen-evidence').hidden&&document.activeElement.id==='evidence-open-source'",'Shared Back did not restore the exact Evidence source trigger');
    assert.equal(await evaluate('evidenceWorkspace.snapshot().selectedKey'),'7:42:102');
    const restored=await evaluate("(()=>{const n=document.activeElement,r=n.getBoundingClientRect();return {list:document.querySelector('#evidence-rows').scrollTop===evidenceReturnView.list,detail:document.querySelector('#evidence-inspector').scrollTop===evidenceReturnView.detail,search:document.querySelector('#evidence-search').value===evidenceReturnView.search,scope:document.querySelector('#evidence-scope').value===evidenceReturnView.scope,pane:evidenceWorkspace.snapshot().pane===evidenceReturnView.pane,decoder:document.querySelector('#decoder-input').value===evidenceReturnView.decoder,console:document.querySelector('#native-console-source').value===evidenceReturnView.console,visible:r.width>0&&r.height>0&&r.top>=0&&r.bottom<=innerHeight};})()");
    assert(Object.values(restored).every(Boolean),`${label}: Source → Back must preserve both pane scrolls, visible exact focus, scope/search and other drafts: ${JSON.stringify(restored)}`);
    assert.equal(fixture.derivedRequests,0,'Evidence source navigation must not start derived analysis');
    sourceRoundTrips.push(label);await screenshot(`evidence-investigation-source-back-${label}`);
  };
  if(sourceSupported)await sourceRoundTrip('wide');
  else assert.match(await evaluate("document.querySelector('#evidence-inspector').textContent"),/Safe source navigation is unavailable/);
  await observationClick('[data-evidence-key="7:42:104"]');assert.match(await evaluate("document.querySelector('#evidence-inspector').textContent"),/absent from the retained catalog/);
  await screenshot('evidence-investigation-missing-source');
  await observationClick('[data-evidence-key="7:42:102"]');
  for(const [width,height] of [[760,560],[360,740]]){
    await viewport(width,height);assert.equal(await evaluate("getComputedStyle(document.querySelector('#evidence-package-toggle')).display==='none'"),false,'Package entry must remain available on narrow layouts');
    await click('[data-evidence-pane="observations"][role="tab"]');await geometry(`${width} observations`);await screenshot(`evidence-investigation-${width}-observations`);
    await observationClick('[data-evidence-key="7:42:102"]');await geometry(`${width} selected record`);await screenshot(`evidence-investigation-${width}-record`);
    assert.equal(await evaluate("document.activeElement.id"),'evidence-inspector','Narrow record selection must focus the revealed pane');
    const before=await evaluate("document.querySelector('#evidence-inspector').scrollTop");await wheel('#evidence-inspector',150);assert(await evaluate(`document.querySelector('#evidence-inspector').scrollTop>${before}`),'Narrow inspector scroll is independent');
    await click('[data-evidence-pane="observations"][role="tab"]');
    await click('#evidence-search');
    for(const character of 'toDataURL')await key(character,`Key${character.toUpperCase()}`,{text:character,unmodifiedText:character});
    await observationClick('[data-evidence-key="7:42:102"]');
    const scopeDraft=await evaluate("document.querySelector('#evidence-scope').value");
    await observationClick('[data-evidence-action="parent"]');
    assert.equal(await evaluate('evidenceWorkspace.snapshot().selectedKey'),'7:42:101');
    assert.equal(await evaluate("document.querySelector('#evidence-search').value"),'toDataURL');assert.equal(await evaluate("document.querySelector('#evidence-scope').value"),scopeDraft);
    assert.match(await evaluate("document.querySelector('#evidence-workspace-notice').textContent"),/selected parent is outside the current filter/);
    assert.equal(await evaluate("(()=>{const n=document.activeElement,r=n.getBoundingClientRect();return n.id==='evidence-inspector'&&r.width>0&&r.height>0&&r.top>=0&&r.bottom<=innerHeight;})()"),true,'Narrow parent traversal must leave focus in a visible inspector');
    await geometry(`${width} filtered parent`);await screenshot(`evidence-investigation-${width}-parent`);
    await click('[data-evidence-pane="observations"][role="tab"]');await observationClick('[data-evidence-key="7:42:102"]');
    await sourceRoundTrip(String(width));
    await click('[data-evidence-pane="observations"][role="tab"]');
    await evaluate("document.querySelector('#evidence-search').value='';document.querySelector('#evidence-search').dispatchEvent(new Event('input',{bubbles:true}))");
    await evaluate("window.evidenceShortRequest=state.requests[0];state.requests[0]={...state.requests[0],protocolRequestId:'long-url-cdp',operation:'cdp_complete',tabId:'long-url-target',hostOnly:false,path:('https://fixture.invalid/'+('segment/'.repeat(300))).slice(0,2048)};renderEvidence()");
    await geometry(`${width} long correlated request`);
    // A compact layout must preserve the actual qualifiers and every control,
    // rather than buying reading space by hiding warnings or reducing coverage.
    const essentials=await evaluate(`['#evidence-context-note','#evidence-workspace-notice','#evidence-coverage-summary','#evidence-search','#evidence-scope','#evidence-package-toggle','#evidence-previous','#evidence-next'].map(selector=>{const n=document.querySelector(selector),r=n.getBoundingClientRect(),style=getComputedStyle(n);return {selector,visible:r.width>0&&r.height>0&&r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight&&style.visibility!=='hidden',unclipped:n.scrollHeight<=n.clientHeight+1};})`);
    assert(essentials.every(value=>value.visible&&value.unclipped),`${width}: context qualifications, notices and controls must remain visible and unclipped: ${JSON.stringify(essentials)}`);
    assert.match(await evaluate("document.querySelector('#evidence-context-note').textContent"),/No exact producer request key/);
    assert.match(await evaluate("document.querySelector('#evidence-context-note').textContent"),/Matched by method, host and time/);
    assert.match(await evaluate("document.querySelector('#evidence-coverage-summary').textContent"),/1 missing parent · coverage unknown/);
    assert.match(await evaluate("document.querySelector('#evidence-workspace-notice').textContent"),/Request context changed/);

    const paneHeight=await evaluate("document.querySelector('.evidence-investigation-layout').clientHeight");
    await click('#evidence-coverage-details > summary');
    assert.equal(await evaluate("document.querySelector('.evidence-investigation-layout').clientHeight"),paneHeight,'Expanded coverage must not consume reading-pane height');
    const coverage=await evaluate("(()=>{const n=document.querySelector('#evidence-coverage-popover'),r=n.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,height:r.height,scroll:n.scrollHeight,client:n.clientHeight};})()");
    assert(coverage.left>=0&&coverage.right<=width&&coverage.top>=0&&coverage.bottom<=height&&coverage.height<=height*.4+1,`${width}: coverage must be bounded and inside the viewport`);
    await geometry(`${width} long request with coverage`);await screenshot(`evidence-investigation-${width}-long-coverage`);
    await click('#evidence-coverage-popover');
    if(coverage.scroll>coverage.client+1){await wheel('#evidence-coverage-popover',150);assert(await evaluate("document.querySelector('#evidence-coverage-popover').scrollTop>0"));}
    await press('Escape');assert.equal(await evaluate("document.querySelector('#evidence-coverage-details').open"),false);
    assert.equal(await evaluate("document.activeElement===document.querySelector('#evidence-coverage-details > summary')"),true);
    await evaluate("state.requests[0]=evidenceShortRequest;renderEvidence()");
    await observationClick('[data-evidence-key="7:42:102"]');
  }
  await viewport(1440,900);
  await evaluate("state.requests[0]={...state.requests[0],protocolRequestId:'synthetic-cdp',operation:'cdp_complete',tabId:'synthetic-target'};renderEvidence()");
  await observationClick('[data-evidence-key="7:42:102"]');assert.match(await evaluate("document.querySelector('#evidence-context-note').textContent"),/No exact producer request key/);await screenshot('evidence-investigation-correlated-request');
  await evaluate("state.events=state.events.filter(event=>event.sequence_number!=='102');renderEvidence()");
  assert.equal(await evaluate('evidenceWorkspace.snapshot().selectedKey'),null);assert.match(await evaluate("document.querySelector('#evidence-workspace-notice').textContent"),/left the retained window/);
  await screenshot('evidence-investigation-evicted');
  fixture.observationActive=false;
  await evaluate("state.requests=[];state.events=[];state.artifacts=[];resetRequestSelection();renderEvidence()");await screenshot('evidence-investigation-empty');
  await click('#screen-evidence .back-button');
  return {sourcePivot:sourceSupported?'passed with approved shared adapter':'unavailable until approved navigation composition',sourceRoundTrips,readingPanes,checks:['normal contract-valid broker/artifact routes','investigation-first landing','separate native parent/context/unlinked relationships','CDP association qualification','marker outcomes unknown','exact linked artifact and missing-source state','observation selection does not export','stable keyboard/focus/scroll','secondary package mode and return','narrow pane switch and scrolling','filtered parent traversal preserves drafts and visible focus','long correlated URL and bounded keyboard coverage at 760/360','composed Source Back preserves both pane scrolls and other tool drafts','eviction without substitution','empty retained window']};
}

async function checkEvidenceInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture,setFile,verifyDownload}) {
  const observations=await checkEvidenceObservationInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture});
  const packageGeometry=[];
  const status=()=>evaluate('evidencePackagePanel.controller.model.status');
  const until=async(expression,message)=>{const deadline=Date.now()+5000;while(Date.now()<deadline){if(await evaluate(expression))return;await new Promise(resolve=>setTimeout(resolve,25));}assert.fail(message);};
  const ready=()=>until("evidencePackagePanel.controller.model.status==='ready'",'Validated metadata did not become ready');
  const press=(value,code=value)=>key(value,code,{windowsVirtualKeyCode:({Enter:13,Escape:27,Home:36,End:35,ArrowDown:40,Tab:9,' ':32})[value],...(value==='Enter'?{text:'\r',unmodifiedText:'\r'}:value===' '?{text:' ',unmodifiedText:' '}:{})});
  const reveal=async selector=>{
    for(let attempt=0;attempt<4;attempt++){
      const delta=await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});if(!n)throw new Error('Missing Evidence control');const p=n.closest('.evidence-content');if(!p)return 0;const r=n.getBoundingClientRect(),b=p.getBoundingClientRect();return r.top<b.top+8?r.top-b.top-8:r.bottom>b.bottom-8?r.bottom-b.bottom+8:0;})()`);
      if(Math.abs(delta)<=1)return;
      await wheel('.evidence-content',delta,true);
    }
  };
  const packageClick=async selector=>{await reveal(selector);await click(selector);};
  const scope=async value=>{await packageClick('[data-package-scope]');await press(value==='artifacts'?'End':'Home');if(value==='retained')await press('ArrowDown');await press('Enter');await until(`document.querySelector('[data-package-scope]').value===${JSON.stringify(value)}`,'Keyboard retained-view selection failed');};
  const pending=async()=>{const deadline=Date.now()+5000;while(Date.now()<deadline){if(fixture.pending.length)return;await new Promise(resolve=>setTimeout(resolve,25));}assert.fail('Evidence request never reached the delayed server');};
  const geometry=async label=>{
    const value=await evaluate(`(()=>{const p=document.querySelector('.evidence-content'),r=p.getBoundingClientRect(),n=document.querySelector('#evidence-package-panel');return {width:innerWidth,height:innerHeight,left:r.left,right:r.right,top:r.top,bottom:r.bottom,client:p.clientHeight,scroll:p.scrollHeight,scrollTop:p.scrollTop,panelWidth:n.clientWidth,panelScroll:n.scrollWidth,pageWidth:document.documentElement.scrollWidth};})()`);
    assert(value.right<=value.width+1&&value.bottom<=value.height+1&&value.left>=0&&value.client>=120,`${label}: Evidence viewport must remain usable`);
    assert(value.pageWidth<=value.width+1&&value.panelScroll<=value.panelWidth+1,`${label}: package text/controls must not cause horizontal overflow`);return value;
  };
  await evaluate(`window.evidenceFixtureEvents=${JSON.stringify(fixture.events)};state.events=evidenceFixtureEvents;state.artifacts=${JSON.stringify(fixture.artifacts)};state.sessionMode='demo';state.requests=[{id:'package-request',path:'https://fixture.invalid/package',method:'GET',status:200,time:1,type:'xhr',origin:'demo',tabId:'qa-tab',operation:'synthetic_qa',events:evidenceFixtureEvents,exchange:{request:{state:'empty',headers:[]},response:{state:'empty',headers:[]}}}];renderRequests();`);
  await click('[data-request-id="package-request"]');
  // Inspector tabs survive Back and request selection. This entry is explicit;
  // the observation subtest above separately exercises the Evidence toggle.
  await click('#inspector-tab-evidence');
  assert.equal(await evaluate("state.inspectorTab"),'evidence');
  assert.equal(await evaluate("document.querySelector('#request-package-entry').hidden"),false);
  await click('#request-package-entry [data-screen="evidence"]');
  assert.equal(await evaluate("document.querySelector('#screen-evidence').hidden"),false);
  assert.equal(await evaluate("document.querySelector('#advanced-navigation').open"),false,'Evidence entry must dismiss the navigation popup');
  await click('#evidence-package-toggle');
  assert.equal(await evaluate("document.querySelectorAll('[data-package-candidates] input').length"),4);
  for(let index=1;index<=4;index++)await packageClick(`[data-package-candidates] label:nth-child(${index}) input`);
  await scope('artifacts');for(let index=1;index<=2;index++)await packageClick(`[data-package-candidates] label:nth-child(${index}) input`);
  assert.match(await evaluate("document.querySelector('[data-package-selection]').textContent"),/4 \/ 1,024.*2 \/ 64/);
  await packageClick('[data-package-export]');await ready();
  assert.deepEqual(new Uint8Array(fixture.lastValidation),packageGoldenBytes,'Rendered export must send exact original response bytes to validation');
  assert.match(await evaluate("document.querySelector('[data-package-report]').textContent"),/Authenticity.*not established/);
  assert.match(await evaluate("document.querySelector('[data-package-report]').textContent"),/Unknown historical facts/);
  await reveal('[data-package-report] h3');await geometry('1440x900 coverage');await screenshot('evidence-wide-coverage');
  await verifyDownload(()=>packageClick('[data-package-download]'));
  assert.match(await evaluate("document.querySelector('[data-package-notice]').textContent"),/Download requested.*Check your browser downloads/);
  fixture.mode='writer_busy';await packageClick('[data-package-export]');await until("evidencePackagePanel.controller.model.status==='error'",'Held writer failure was not shown');
  assert.match(await evaluate("document.querySelector('[data-package-notice]').textContent"),/No writer was stopped/);await reveal('[data-package-notice]');await screenshot('evidence-writer-refused');
  fixture.mode='unavailable';await packageClick('[data-package-export]');await until("evidencePackagePanel.controller.model.status==='error'",'Unavailable guarded store was not shown');
  assert.match(await evaluate("document.querySelector('[data-package-notice]').textContent"),/legacy stores are unsupported/);
  fixture.mode='valid';await packageClick('[data-package-export]');await ready();
  await packageClick('[data-package-upload] > summary');await setFile('golden');
  fixture.mode='unsupported';await packageClick('[data-package-validate]');await until("evidencePackagePanel.controller.model.status==='unsupported'",'Unsupported version/profile state was hidden');
  await reveal('[data-package-notice]');await screenshot('evidence-unsupported');
  fixture.mode='valid';await setFile('duplicate');await packageClick('[data-package-validate]');await until("evidencePackagePanel.controller.model.status==='invalid'",'Duplicate input was not shown invalid');
  assert(fixture.lastValidation.includes(Buffer.from('"protocol_version": 1, "protocol_version": 1')),'File input bytes were normalized before validation');
  assert.equal(await evaluate("document.querySelector('[data-package-download]').disabled"),true);
  await setFile('golden');await packageClick('[data-package-validate]');await ready();
  fixture.mode='pending_validate';await packageClick('[data-package-validate]');await pending();
  assert.equal(await evaluate("document.activeElement.hasAttribute('data-package-cancel')"),true,'Loading operation must focus its available Cancel action');
  await press('Escape');fixture.mode='valid';fixture.release();assert.equal(await status(),'cancelled');
  assert.equal(await evaluate("document.activeElement.hasAttribute('data-package-validate')"),true);
  await packageClick('[data-package-validate]');await ready();
  fixture.mode='pending_export';await packageClick('[data-package-export]');await pending();await packageClick('[data-package-cancel]');fixture.mode='valid';fixture.release();
  assert.equal(await status(),'cancelled');await packageClick('[data-package-export]');await ready();
  fixture.mode='pending_export';await packageClick('[data-package-export]');await pending();await packageClick('[data-package-candidates] label:first-child input');fixture.mode='valid';fixture.release();
  assert.equal(await status(),'idle');assert.equal(await evaluate('evidencePackagePanel.controller.model.bytes'),null);
  await packageClick('[data-package-candidates] label:first-child input');
  fixture.mode='pending_validate';await packageClick('[data-package-validate]');await pending();await click('#screen-evidence .back-button');fixture.mode='valid';fixture.release();
  assert.equal(await evaluate("document.querySelector('#screen-traffic').hidden"),false);
  await click('#request-package-entry [data-screen="evidence"]');assert.equal(await status(),'cancelled');
  fixture.mode='pending_export';await packageClick('[data-package-export]');await pending();await evaluate('state.requests=[];resetRequestSelection()');fixture.mode='valid';fixture.release();assert.equal(await status(),'idle');
  assert.match(await evaluate("document.querySelector('[data-package-selection]').textContent"),/0 \/ 1,024.*0 \/ 64/);
  await packageClick('[data-package-clear]');
  await evaluate("state.events=Array.from({length:55},(_,i)=>({...evidenceFixtureEvents[0],sequence_number:String(i+100)}));evidencePackagePanel.sync()");await scope('retained');
  assert.equal(await evaluate("document.querySelectorAll('[data-package-candidates] input').length"),50);
  await packageClick('[data-package-candidates] label:first-child input');
  await evaluate("window.packageFocusedKey=document.activeElement.dataset.packageKey;state.events.push({...evidenceFixtureEvents[0],sequence_number:'999'});evidencePackagePanel.sync()");
  assert.equal(await evaluate('document.activeElement.dataset.packageKey===packageFocusedKey'),true,'Refresh detached the focused identity');
  const beforeScroll=await evaluate("document.querySelector('.evidence-content').scrollTop");await wheel('[data-package-candidates]',100);
  assert(await evaluate("document.querySelector('[data-package-candidates]').scrollTop>0"));
  assert.equal(await evaluate("document.querySelector('.evidence-content').scrollTop"),beforeScroll,'Candidate scrolling moved the outer panel');
  await packageClick('[data-package-next]');assert.equal(await evaluate("document.querySelectorAll('[data-package-candidates] input').length"),6);
  await packageClick('[data-package-candidates] label:first-child input');await press(' ' ,'Space');
  assert.equal(await evaluate("document.querySelector('[data-package-candidates] input').checked"),false,'Space must toggle the focused exact identity');
  await press('Tab');await press(' ','Space');assert.equal(await evaluate("document.querySelectorAll('[data-package-candidates] input')[1].checked"),true);
  await packageClick('[data-package-selected] summary');assert.match(await evaluate("document.querySelector('[data-package-selected]').textContent"),/event 100.*event 151/);
  await reveal('[data-package-selected]');await screenshot('evidence-selected-pages');
  for(const [width,height] of [[760,560],[360,740]]){
    await viewport(width,height);await reveal('[data-package-window]');await geometry(`${width}x${height}`);
    if(width<=600){
      const contextState=()=>evaluate("(()=>{const details=document.querySelector('#investigation-navigation details');return {open:details.open,notice:document.querySelector('#investigation-notice').textContent,selection:document.querySelector('[data-package-selection]').textContent,candidates:[...document.querySelectorAll('[data-package-candidates] input')].map(n=>[n.dataset.packageKey,n.checked]),candidateScroll:document.querySelector('[data-package-candidates]').scrollTop};})()");
      const beforeContext=await contextState();
      assert(beforeContext.open,'Stale return context remains disclosed during phone package inspection');
      assert.match(beforeContext.notice,/Return unavailable:.*Nothing was fetched or recaptured/);
      await click('#investigation-navigation details > summary');
      assert.equal((await contextState()).open,false);
      await click('#investigation-navigation details > summary');
      assert.deepEqual(await contextState(),beforeContext,'Link context toggles must preserve the exact package selection, candidate scroll and complete warning');
      await reveal('[data-package-window]');
    }
    const navigationGeometry=await evaluate(`(()=>{const box=selector=>{const n=document.querySelector(selector),r=n.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,height:r.height};};return {bar:box('#investigation-navigation'),controls:box('.investigation-controls'),details:box('#investigation-navigation details'),back:box('#investigation-back'),forward:box('#investigation-forward'),notice:box('#investigation-notice'),clear:box('#investigation-clear'),overflow:getComputedStyle(document.querySelector('#investigation-navigation')).overflowY};})()`);
    if(width<=600){
      assert(navigationGeometry.details.left<=navigationGeometry.controls.left+1&&navigationGeometry.details.right>=navigationGeometry.controls.right-1&&navigationGeometry.details.top>=Math.max(navigationGeometry.back.bottom,navigationGeometry.forward.bottom), 'Open phone Link context occupies a full-width row below Back/Forward');
      for(const item of [navigationGeometry.notice,navigationGeometry.clear])assert(item.left>=navigationGeometry.bar.left&&item.right<=navigationGeometry.bar.right&&item.top>=navigationGeometry.bar.top&&item.bottom<=navigationGeometry.bar.bottom,'The complete stale warning and history control remain visible in their navigation scroller');
      assert(navigationGeometry.bar.height<=height*.35+1&&navigationGeometry.overflow==='auto','Navigation retains its own bounded scrolling owner');
    }
    const windowGeometry=await evaluate(`(()=>{const box=selector=>{const r=document.querySelector(selector).getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,height:r.height};};return {outer:box('.evidence-content'),pager:box('[data-package-pager]'),list:box('[data-package-candidates]')};})()`);
    packageGeometry.push({width,height,...windowGeometry,navigation:navigationGeometry});
    console.log('Evidence package geometry',JSON.stringify(packageGeometry.at(-1)));
    assert(windowGeometry.pager.top>=windowGeometry.outer.top&&windowGeometry.pager.bottom<=windowGeometry.outer.bottom&&windowGeometry.pager.height>=24,`${width}x${height}: candidate paging must stay visible with the list`);
    assert(windowGeometry.pager.bottom<=windowGeometry.list.top&&windowGeometry.list.bottom<=windowGeometry.outer.bottom&&windowGeometry.list.top>=windowGeometry.outer.top,`${width}x${height}: pager and candidate list must fit together without overlap`);
    assert(windowGeometry.list.height>=100,`${width}x${height}: candidate list must retain a usable height`);
    await packageClick('[data-package-previous]');await packageClick('[data-package-next]');
    await reveal('[data-package-candidates]');await screenshot(`evidence-${width}-selection`);
    const before=await geometry('before narrow scroll');await wheel('.evidence-content',150,true);const after=await geometry('after narrow scroll');
    assert(after.scrollTop!==before.scrollTop,'Narrow Evidence content must scroll independently');
    await reveal('[data-package-validate]');await packageClick('[data-package-validate]');await ready();await reveal('[data-package-report] h3');await screenshot(`evidence-${width}-coverage`);
  }
  await click('#screen-evidence .back-button');await click('#advanced-navigation > summary');await click('.nav-button[data-screen="backtrace"]');await click('#screen-backtrace .package-navigation');
  assert.equal(await evaluate("document.querySelector('#screen-evidence').hidden"),false,'Narrow Backtraces must expose the package entry');
  assert.equal(await evaluate("document.querySelector('#advanced-navigation').open"),false,'Backtraces entry must dismiss the navigation popup');
  await geometry('narrow Backtraces return');await screenshot('evidence-narrow-reopened');
  return {status:'passed',path:'browser development Evidence UI',observations,packageGeometry,source:'synthetic closed metadata fixture; authoritative native-writer HTTP checks are separate',viewports:[[1440,900],[760,560],[360,740]],checks:['Requests and narrow Backtraces pointer entry','exact scoped selection','explicit guarded export and retry','explicit browser download exact bytes; no automatic save','real file input exact-byte validation','invalid and unsupported states','writer refusal and unavailable store','Cancel and Escape focus','stale selection and Back/reopen','50-row paging','keyed refresh focus','Space/Tab keyboard selection','independent candidate/panel scrolling','narrow geometry and screenshots']};
}

async function checkTrafficBrowser() {
  const executable = process.env.REB_UI_CHROMIUM;
  assert(executable, "Set REB_UI_CHROMIUM to the installed Chrome/Chromium executable. Sandbox flags are not overridden.");
  const directory = await mkdtemp(join(tmpdir(), investigationBrowser ? "reb-investigation-ui-" : collectionBrowser ? "reb-collection-ui-" : consoleBrowser ? "reb-console-ui-" : evidenceBrowser ? "reb-evidence-ui-" : sourceFactsBrowser ? "reb-source-facts-ui-" : "reb-requests-ui-"));
  const output = process.env.REB_UI_SCREENSHOTS || join(root, "build", investigationBrowser ? "investigation-ui-qa" : collectionBrowser ? "collection-ui-qa" : consoleBrowser ? "console-ui-qa" : evidenceBrowser ? "evidence-ui-qa" : sourceFactsBrowser ? "source-facts-ui-qa" : "requests-ui-qa");
  await mkdir(output, {recursive: true});
  let trafficApiMode = "offline";
  const collectionFixture = collectionBrowser ? collectionBrowserFixture() : null;
  const factsFixture = investigationBrowser ? investigationFixture(await sourceFactsBrowserFixture()) : sourceFactsBrowser ? await sourceFactsBrowserFixture() : null;
  const consoleFixture = consoleBrowser ? createConsoleFixture() : null;
  const evidenceFixture = evidenceBrowser ? evidenceBrowserFixture() : null;
  if(evidenceFixture){
    await writeFile(join(directory,'golden.json'),packageGoldenBytes);
    await writeFile(join(directory,'duplicate.json'),new TextDecoder().decode(packageGoldenBytes).replace('"protocol_version": 1','"protocol_version": 1, "protocol_version": 1'));
  }
  const server = createServer(async (request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    if (collectionFixture && await collectionFixture.handle(request, response)) return;
    if (factsFixture && await factsFixture.handle(request, response)) return;
    if (consoleFixture && await consoleFixture.handle(request, response)) return;
    if (evidenceFixture && await evidenceFixture.handle(request, response)) return;
    if (path === "/api/events" && trafficApiMode === "malformed") {response.writeHead(200, {"Content-Type": "application/json"}); response.end('{"malformed":true}'); return;}
    if (path.startsWith("/api/")) {response.writeHead(503, {"Content-Type": "application/json"}); response.end('{"error":"Synthetic offline QA fixture"}'); return;}
    const name = path === "/" ? "index.html" : path.slice(1);
    if (!/^[a-z_]+\.(?:html|js|css)$/.test(name)) {response.writeHead(404); response.end(); return;}
    try {
      response.writeHead(200, {"Content-Type": name.endsWith(".js") ? "text/javascript" : name.endsWith(".css") ? "text/css" : "text/html"});
      response.end(await readFile(join(root, "apps/research-ui", name)));
    } catch {response.writeHead(404); response.end();}
  });
  const args = ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${directory}`,
    "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "about:blank"];
  let lifecycle, socket, validation, failure, captureFailure;
  let diagnostics = {executable, args, phase: "fixture server"};
  const commands = new Map();
  await rm(join(output, "validation.json"), {force: true});
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {cleanup(); reject(new Error("Loopback fixture server timed out"));}, 5000);
      const failed = error => {cleanup(); reject(error);};
      function cleanup() {clearTimeout(timer); server.off("error", failed);}
      server.once("error", failed);
      server.listen(0, "127.0.0.1", () => {cleanup(); resolve();});
    });
    lifecycle = trafficBrowserProcess(executable, args);
    diagnostics = lifecycle.diagnostics;
    const address = await lifecycle.ready(directory);
    diagnostics.phase = "CDP socket";
    socket = await trafficBrowserSocket(address);
    let commandId = 0;
    const runtimeErrors = [];
    const browserDialogs = [];
    socket.addEventListener("message", event => {
      const message = JSON.parse(event.data);
      if (message.method === "Page.javascriptDialogOpening") browserDialogs.push(message.params);
      if (message.method === "Runtime.exceptionThrown") runtimeErrors.push(message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text);
      const pending = commands.get(message.id);
      if (!pending) return;
      commands.delete(message.id); clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(JSON.stringify(message.error))); else pending.resolve(message.result);
    });
    const rejectCommands = reason => {
      for (const pending of commands.values()) {clearTimeout(pending.timer); pending.reject(new Error(reason));}
      commands.clear();
    };
    socket.addEventListener("close", () => rejectCommands("Chromium CDP socket closed"));
    socket.addEventListener("error", () => rejectCommands("Chromium CDP socket error"));
    let session;
    const command = (method, params = {}, attach = true) => new Promise((resolve, reject) => {
      const id = ++commandId;
      diagnostics.last_command = method;
      const timer = setTimeout(() => {commands.delete(id); reject(new Error(`CDP timed out: ${method}`));}, 10000);
      commands.set(id, {resolve, reject, timer});
      socket.send(JSON.stringify({id, method, params, ...(attach && session ? {sessionId: session} : {})}));
    });
    diagnostics.version = await command("Browser.getVersion", {}, false);
    diagnostics.phase = "page setup";
    const target = await command("Target.createTarget", {url: "about:blank"}, false);
    session = (await command("Target.attachToTarget", {targetId: target.targetId, flatten: true}, false)).sessionId;
    await command("Page.enable"); await command("Runtime.enable");
    const evaluate = async expression => {
      const result = await command("Runtime.evaluate", {expression, awaitPromise: true, returnByValue: true});
      if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
      return result.result.value;
    };
    const viewport = async (width, height) => {
      await command("Emulation.setDeviceMetricsOverride", {width, height, deviceScaleFactor: 1, mobile: false});
      await evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))");
    };
    const wheel = async (selector, deltaY, edge = false) => {
      const mode = edge === 'scrollbar' ? 'scrollbar' : edge ? 'edge' : 'center';
      const point = await evaluate(`(() => {
        const node = document.querySelector(${JSON.stringify(selector)}), r = node.getBoundingClientRect();
        const mode = ${JSON.stringify(mode)}, gutter = r.width-node.clientWidth-2*node.clientLeft;
        // An outer scroll owner's native scrollbar avoids nested list and form
        // controls. Evidence retains its original visible-padding edge mode.
        const x = mode==='scrollbar' && gutter>=6 ? r.x+node.clientLeft+node.clientWidth+gutter/2
          : mode!=='center' ? r.x+node.clientLeft+node.clientWidth-4 : r.x+r.width/2;
        const y = r.y+r.height/2, hit = document.elementFromPoint(x,y);
        if (r.width <= 0 || r.height <= 0 || x < 0 || x >= innerWidth || y < 0 || y >= innerHeight || !hit || !node.contains(hit)) throw new Error('Scroll target is clipped or offscreen: '+${JSON.stringify(selector)});
        const nested=[];
        for(let child=hit;child&&child!==node;child=child.parentElement) {
          if (['auto','scroll','overlay'].includes(getComputedStyle(child).overflowY) && child.scrollHeight>child.clientHeight+1) nested.push({id:child.id,tag:child.tagName,scrollTop:child.scrollTop,clientHeight:child.clientHeight,scrollHeight:child.scrollHeight});
        }
        if(mode!=='center' && nested.length) throw new Error('Outer wheel target is owned by a nested scroller: '+${JSON.stringify(selector)}+' '+JSON.stringify(nested));
        return {x,y,mode,gutter,scrollTop:node.scrollTop,clientHeight:node.clientHeight,scrollHeight:node.scrollHeight,hit:{id:hit.id,tag:hit.tagName},nested};
      })()`);
      const receipt={selector,deltaY,point};
      diagnostics.wheel_events=[...(diagnostics.wheel_events??[]).slice(-63),receipt];
      // Move the actual pointer after viewport/scroll-owner changes before
      // dispatching a genuine wheel event; never assign a DOM scroll offset.
      await command("Input.dispatchMouseEvent", {type:"mouseMoved",x:point.x,y:point.y});
      await command("Input.dispatchMouseEvent", {type: "mouseWheel", x:point.x, y:point.y, deltaX: 0, deltaY});
      receipt.result=await evaluate(`new Promise(resolve => {
        const node=document.querySelector(${JSON.stringify(selector)}), start=performance.now(), trace=[];
        let previous=${point.scrollTop}, moved=false, stable=0;
        function frame(){const current=node.scrollTop; moved ||= current!==${point.scrollTop};
          stable=current===previous?stable+1:0; previous=current;
          if(trace.length<128)trace.push({elapsed:Math.round(performance.now()-start),scrollTop:current,clientHeight:node.clientHeight,scrollHeight:node.scrollHeight});
          if(moved&&stable>=3 || performance.now()-start>1500) resolve({scrollTop:current,clientHeight:node.clientHeight,scrollHeight:node.scrollHeight,trace}); else requestAnimationFrame(frame);}
        requestAnimationFrame(frame);
      })`);
      return receipt;
    };
    const click = async selector => {
      // Reveal a request only by scrolling its bounded ledger. Never scroll a
      // workspace/ancestor to make an offscreen inspector control appear usable.
      const delta = await evaluate(`(() => {
        const node = document.querySelector(${JSON.stringify(selector)});
        if (!node) throw new Error('Missing control: '+${JSON.stringify(selector)});
        if (!node.matches('.request-row')) return 0;
        const r = node.getBoundingClientRect(), box = elements.requestRows.getBoundingClientRect();
        return r.top < box.top ? r.top-box.top : r.bottom > box.bottom ? r.bottom-box.bottom : 0;
      })()`);
      if (delta) await wheel('#request-rows', delta);
      const rect = await evaluate(`(() => {
        const node = document.querySelector(${JSON.stringify(selector)}), r = node.getBoundingClientRect();
        const x = r.x+r.width/2, y = r.y+r.height/2, hit = document.elementFromPoint(x,y);
        if (r.width <= 0 || r.height <= 0 || r.left < 0 || r.right > innerWidth || r.top < 0 || r.bottom > innerHeight || !hit || !node.contains(hit)) throw new Error('Control is clipped or offscreen: '+${JSON.stringify(selector)});
        return {x,y,left:r.left,right:r.right,top:r.top,bottom:r.bottom,
          hit:{id:hit.id,tag:hit.tagName},connectionOpen:document.querySelector('#native-console-connection')?.open};
      })()`);
      const receipt={selector,before:rect};
      if(consoleBrowser)diagnostics.pointer_events=[...(diagnostics.pointer_events??[]).slice(-63),receipt];
      await command("Input.dispatchMouseEvent", {type: "mousePressed", x:rect.x,y:rect.y, button: "left", clickCount: 1});
      await command("Input.dispatchMouseEvent", {type: "mouseReleased", x:rect.x,y:rect.y, button: "left", clickCount: 1});
      if(consoleBrowser)receipt.after=await evaluate(`(()=>{
        const node=document.querySelector(${JSON.stringify(selector)}),r=node?.getBoundingClientRect(),hit=document.elementFromPoint(${rect.x},${rect.y});
        return {left:r?.left,right:r?.right,top:r?.top,bottom:r?.bottom,ownsPoint:!!node?.contains(hit),hit:{id:hit?.id,tag:hit?.tagName},connectionOpen:document.querySelector('#native-console-connection')?.open};
      })()`);
    };
    const key = async (value, code = value, native = {}) => {
      await command("Input.dispatchKeyEvent", {type: "keyDown", key: value, code, ...native});
      await command("Input.dispatchKeyEvent", {type: "keyUp", key: value, code, windowsVirtualKeyCode:native.windowsVirtualKeyCode});
    };
    const dialog = async accept => {
      const start = Date.now();
      while (!browserDialogs.length && Date.now() - start < 5000) await new Promise(resolve => setTimeout(resolve, 25));
      assert(browserDialogs.length, "The explicit replacement confirmation did not open");
      const prompt = browserDialogs.shift();
      assert.equal(prompt.type, "confirm");
      assert.match(prompt.message, /Replace the current Decoder input and chain/);
      await command("Page.handleJavaScriptDialog", {accept});
    };
    const typeText = text => command("Input.insertText", {text});
    const columnsAligned = async () => {
      const measured = await evaluate(`(() => {
        const measure = node => {
          if (!node) return null;
          const r = node.getBoundingClientRect(), style = getComputedStyle(node);
          return {visible: node.getClientRects().length > 0, left:r.left, right:r.right, top:r.top,
            width:r.width, height:r.height, clientWidth:node.clientWidth, scrollWidth:node.scrollWidth,
            display:style.display, paddingLeft:style.paddingLeft, paddingRight:style.paddingRight,
            borderLeft:style.borderLeftWidth, borderRight:style.borderRightWidth,
            columns:style.gridTemplateColumns, gutter:style.scrollbarGutter, overflowY:style.overflowY};
        };
        const screen = document.querySelector('#screen-traffic');
        const header = document.querySelector('.request-head');
        const row = document.querySelector('.request-row');
        return {viewport:{width:innerWidth,height:innerHeight}, screenHidden:screen.hidden,
          screen:measure(screen), header:measure(header), ledger:measure(document.querySelector('.request-rows')),
          row:measure(row), heads:[...header.children].map(measure), cells:[...row.children].map(measure)};
      })()`);
      diagnostics.request_geometry = [...(diagnostics.request_geometry ?? []).slice(-3), measured];
      return !measured.screenHidden && measured.screen.visible && measured.header.visible && measured.row.visible &&
        measured.header.width > 0 && measured.row.width > 0 && measured.heads.some(head => head.visible) &&
        measured.heads.every((head, index) => {
          const cell = measured.cells[index];
          if (!head.visible) return cell && !cell.visible;
          return cell?.visible && Math.abs(head.left-cell.left) <= 1 && Math.abs(head.right-cell.right) <= 1;
        });
    };
    const narrowPanes = async label => {
      const geometry = await evaluate(`(() => {
        const box = selector => {
          const node = document.querySelector(selector), r = node.getBoundingClientRect();
          let left=Math.max(0,r.left), right=Math.min(innerWidth,r.right), top=Math.max(0,r.top), bottom=Math.min(innerHeight,r.bottom);
          for(let parent=node.parentElement;parent;parent=parent.parentElement){
            const p=parent.getBoundingClientRect(), style=getComputedStyle(parent);
            if(style.overflowX!=='visible'){left=Math.max(left,p.left);right=Math.min(right,p.right);}
            if(style.overflowY!=='visible'){top=Math.max(top,p.top);bottom=Math.min(bottom,p.bottom);}
          }
          return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height,
            visibleWidth:Math.max(0,right-left),visibleHeight:Math.max(0,bottom-top),
            clientHeight:node.clientHeight,scrollHeight:node.scrollHeight,scrollTop:node.scrollTop};
        };
        return {viewport:{width:innerWidth,height:innerHeight},grid:box('.traffic-grid'),ledger:box('#request-rows'),
          inspector:box('.detail-pane'),tabs:box('.inspector-tabs'),preview:box('.exchange-html-preview')};
      })()`);
      diagnostics.narrow_panes = [...(diagnostics.narrow_panes ?? []).slice(-5), {label,...geometry}];
      assert(geometry.ledger.visibleWidth >= 200 && geometry.ledger.visibleHeight >= 56, `${label}: at least two request rows must remain visible`);
      assert(geometry.tabs.visibleHeight >= 28, `${label}: inspector tabs must be visible`);
      assert(geometry.preview.visibleWidth >= 200 && geometry.preview.visibleHeight >= 80, `${label}: rendered preview must be usable alongside the ledger`);
      assert(geometry.ledger.bottom <= geometry.inspector.top + 1, `${label}: stacked panes must not overlap`);
      assert(geometry.inspector.bottom <= geometry.grid.bottom + 1 && geometry.inspector.bottom <= geometry.viewport.height, `${label}: inspector must fit the workspace`);
      assert(geometry.grid.scrollHeight <= geometry.grid.clientHeight + 1 && geometry.grid.scrollTop === 0, `${label}: workspace must not scroll to reach the inspector`);
      return geometry;
    };
    const independentlyScrollPanes = async label => {
      const before = await narrowPanes(label);
      const down = before.ledger.scrollTop < before.ledger.scrollHeight-before.ledger.clientHeight-120;
      await wheel('#request-rows', down ? 112 : -112);
      const after = await narrowPanes(label+' after ledger scroll');
      assert.notEqual(after.ledger.scrollTop, before.ledger.scrollTop, `${label}: wheel must scroll the ledger`);
      assert.equal(after.inspector.top, before.inspector.top, `${label}: ledger scroll must not move the inspector`);
      await click('#inspector-tab-response');
      assert.equal(await evaluate("state.inspectorTab"), "response");
      const bodyBefore = await evaluate("({ledger:elements.requestRows.scrollTop,body:document.querySelector('#exchange-inspector .exchange-content').scrollTop})");
      await wheel('#exchange-inspector .exchange-content', 112);
      const bodyAfter = await evaluate("({ledger:elements.requestRows.scrollTop,body:document.querySelector('#exchange-inspector .exchange-content').scrollTop,grid:document.querySelector('.traffic-grid').scrollTop})");
      assert(bodyAfter.body > bodyBefore.body, `${label}: inspector body must scroll independently`);
      assert.equal(bodyAfter.ledger, bodyBefore.ledger, `${label}: body scroll must not move the ledger`);
      assert.equal(bodyAfter.grid, 0);
      await click('#inspector-tab-preview');
      assert.equal(await evaluate("state.inspectorTab"), "preview");
      await narrowPanes(label+' restored preview');
    };
    const screenshot = async name => {
      await evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))");
      const result = await command("Page.captureScreenshot", {format: "png"});
      await writeFile(join(output, `${name}.png`), Buffer.from(result.data, "base64"));
    };
    captureFailure = async () => {
      const result = await command("Page.captureScreenshot", {format: "png"});
      await writeFile(join(output, investigationBrowser ? "investigation-failure.png" : collectionBrowser ? "collection-failure.png" : consoleBrowser ? "console-failure.png" : evidenceBrowser ? "evidence-failure.png" : sourceFactsBrowser ? "source-facts-failure.png" : "requests-failure.png"), Buffer.from(result.data, "base64"));
    };
    await viewport(1440, 900);
    await command("Page.navigate", {url: `http://127.0.0.1:${server.address().port}/`});
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (await evaluate("typeof renderRequests === 'function' && typeof state !== 'undefined'")) break;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert(await evaluate("typeof renderRequests === 'function'"), "Application did not initialize");
    diagnostics.phase = "interactive validation";
    if (investigationBrowser) {
      validation = await checkInvestigationInteractions({evaluate,viewport,click,key,wheel,screenshot,dialog,typeText,fixture:factsFixture});
      assert.deepEqual(runtimeErrors, [], "Application raised uncaught errors during investigation QA");
    } else if (collectionBrowser) {
      validation = await checkCollectionInteractions({evaluate,viewport,click,key,wheel,type:text=>command("Input.insertText",{text}),screenshot,fixture:collectionFixture});
      assert.deepEqual(runtimeErrors, [], "Application raised uncaught errors during Collection QA");
    } else if (consoleBrowser) {
      validation = await checkConsoleInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture:consoleFixture,type:text=>command("Input.insertText",{text}),recordGeometry:value=>{diagnostics.console_upper_panes=[...(diagnostics.console_upper_panes??[]).slice(-31),value];}});
      assert.deepEqual(runtimeErrors, [], "Application raised uncaught errors during Console QA");
    } else if (evidenceBrowser) {
      const setFile=async name=>{
        const doc=await command('DOM.getDocument');
        const input=await command('DOM.querySelector',{nodeId:doc.root.nodeId,selector:'[data-package-file]'});
        await command('DOM.setFileInputFiles',{nodeId:input.nodeId,files:[join(directory,name+'.json')]});
      };
      const downloadDirectory=join(directory,'downloads');await mkdir(downloadDirectory);
      await command('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:downloadDirectory},false);
      const verifyDownload=async trigger=>{
        assert.deepEqual(await readdir(downloadDirectory),[],'Validation must not automatically save a file');
        await trigger();
        const deadline=Date.now()+5000;let saved;
        while(Date.now()<deadline){try{saved=await readFile(join(downloadDirectory,'selected.reb-evidence.json'));if((await readdir(downloadDirectory)).every(name=>!name.endsWith('.crdownload')))break;}catch{}await new Promise(resolve=>setTimeout(resolve,25));}
        assert(saved,'Explicit Download did not produce a completed file');
        assert.deepEqual(new Uint8Array(saved),packageGoldenBytes,'Browser download must preserve exact validated bytes');
        assert.deepEqual(await readdir(downloadDirectory),['selected.reb-evidence.json']);
      };
      validation=await checkEvidenceInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture:evidenceFixture,setFile,verifyDownload});
      assert.deepEqual(runtimeErrors,[],"Application raised uncaught errors during Evidence QA");
    } else if (sourceFactsBrowser) {
      validation = await checkSourceFactsInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture:factsFixture,recordSourceCheck:entry=>{(diagnostics.source_ownership_checks??=[]).push(entry);}});
      assert.deepEqual(runtimeErrors, [], "Application raised uncaught errors during Sources QA");
    } else {
    await evaluate(`window.fixtureRequests = Array.from({length:520}, (_,i) => ({id:'qa-'+i,path:'https://fixture.invalid/api/item-'+i+'?view=compact',method:i%3?'GET':'POST',status:i%11===0?'pending':200,time:i%11===0?'pending':i/2,type:'xhr',origin:'demo',tabId:'qa-tab',hostOnly:false,operation:'synthetic_qa',events:[],exchange:{request:{state:'available',mime:'application/json',text:'{"id":"qa","value":"first"}',headers:[['content-type','application/json']]},response:{state:i%11===0?'loading':'available',mime:'application/json',text:i%11===0?'':'{"result":"first"}',headers:[['content-type','application/json'],['x-fixture','one']]}}})); state.requests=fixtureRequests; state.sessionMode='demo'; renderRequests(); document.querySelector('#network-notice').textContent='Synthetic browser QA fixture · no live capture';`);
    assert.equal(await evaluate("document.querySelectorAll('.request-row').length"), 500);
    assert(await columnsAligned(), "Request headers and row columns must align with the scrollbar gutter");
    assert(await evaluate("[document.querySelector('.request-row').children[1],document.querySelector('.request-row .request-type')].every(node=>node.clientWidth>0&&node.scrollWidth<=node.clientWidth)"), "Pending and type labels must fit their compact cells");
    await click('[data-request-id="qa-22"]');
    assert.equal(await evaluate("state.selectedRequestId"), "qa-22");
    await click('#inspector-tab-response');
    assert.equal(await evaluate("elements.selectedStatus.textContent"), "pending");
    assert.match(await evaluate("document.querySelector('#exchange-inspector').textContent"), /Loading response/);
    await evaluate(`window.selectedNode=document.querySelector('[data-request-id="qa-22"]'); selectedNode.focus(); window.previousTop=elements.requestRows.scrollTop; fixtureRequests[22]={...fixtureRequests[22],status:200,time:14,exchange:{...fixtureRequests[22].exchange,response:{state:'available',mime:'application/json',text:'{"result":"first"}',headers:[['x-fixture','one']]}}}; state.requests=[...fixtureRequests, {...fixtureRequests[0],id:'qa-arrival'}]; renderRequests(); renderInspector();`);
    assert(await evaluate("document.querySelector('[data-request-id=\"qa-22\"]') === selectedNode && document.activeElement === selectedNode && elements.requestRows.scrollTop === previousTop"));
    assert.equal(await evaluate("elements.selectedStatus.textContent"), "200");
    await evaluate("state.requests[22].exchange.response.text='{\"result\":\"other\"}'; renderInspector()");
    assert.match(await evaluate("document.querySelector('#exchange-inspector').textContent"), /other/);
    await click('#exchange-inspector .exchange-options summary');
    await click('#exchange-inspector .exchange-options-menu .exchange-button');
    await key('Escape');
    assert(await evaluate("document.querySelector('#exchange-inspector .exchange-controls').hidden && state.trafficDetailOpen"));
    await click('#inspector-tab-headers');
    await evaluate("state.requests[22].exchange.response.headers=[['x-fixture','two']]; renderInspector()");
    assert.match(await evaluate("document.querySelector('#exchange-inspector').textContent"), /two/);
    await screenshot("requests-wide-headers");
    trafficApiMode = "malformed";
    await evaluate("(async()=>{while(state.refreshing) await new Promise(resolve=>setTimeout(resolve,20)); await refresh();})()");
    assert.equal(await evaluate("state.eventFailureKind"), "malformed");
    assert.equal(await evaluate("state.selectedRequestId"), "qa-22");
    trafficApiMode = "offline";
    await evaluate("(async()=>{while(state.refreshing) await new Promise(resolve=>setTimeout(resolve,20)); await refresh();})()");
    assert.equal(await evaluate("state.selectedRequestId"), "qa-22");
    await evaluate("Object.assign(state.requests[22], {status:'failed', failed:true, time:27}); state.requests[22].exchange.response={state:'error',reason:'Synthetic network failure',headers:[]}; renderRequests(); renderInspector()");
    assert.equal(await evaluate("document.querySelector('[data-request-id=\"qa-22\"]').children[1].textContent"), "Failed");
    assert(await evaluate("(()=>{const cell=document.querySelector('[data-request-id=\"qa-22\"]').children[1];return cell.clientWidth>0&&cell.scrollWidth<=cell.clientWidth;})()"), "Failed label must fit its compact status cell");
    await click('#inspector-tab-response');
    assert.match(await evaluate("document.querySelector('#exchange-inspector').textContent"), /Synthetic network failure/);
    assert.equal(await evaluate("elements.selectedStatus.textContent"), "failed");
    await screenshot("requests-failed-response");
    await click('[data-request-sort="name"]');
    await evaluate("elements.requestFilter.value='no-match'; elements.requestFilter.dispatchEvent(new Event('input',{bubbles:true}))");
    assert.equal(await evaluate("state.selectedRequestId"), "qa-22");
    assert.match(await evaluate("elements.requestRows.textContent"), /No requests match/);
    await evaluate("elements.requestFilter.value=''; elements.requestFilter.dispatchEvent(new Event('input',{bubbles:true}))");
    await click('#request-order');
    await click('[data-request-id="qa-22"]');
    await key('ArrowDown');
    assert.equal(await evaluate("state.selectedRequestId"), "qa-23");
    await key('Escape');
    assert.equal(await evaluate("state.trafficDetailOpen"), false);
    await evaluate("renderRequests(); renderInspector()");
    assert.equal(await evaluate("document.querySelector('.detail-pane').hidden"), true);
    await click('[data-request-id="qa-22"]');
    await evaluate("state.requests=state.requests.filter(request=>request.id!=='qa-22'); renderRequests(); renderInspector()");
    assert.equal(await evaluate("state.selectedRequestId"), null);
    assert.match(await evaluate("document.querySelector('#exchange-inspector').textContent"), /left the retained capture window/);
    await click('#request-detail-close');
    await click('#request-window-next');
    assert((await evaluate("state.trafficWindowStart")) > 0);
    assert((await evaluate("document.querySelectorAll('.request-row').length")) <= 500);
    await click('#request-window-prev');
    await click('[data-request-id="qa-23"]');
    await click('#inspector-tab-preview');
    await evaluate("state.requests.find(r=>r.id==='qa-23').exchange.response={state:'available',mime:'application/json',text:'{malformed',headers:[]}; renderInspector()");
    assert.match(await evaluate("document.querySelector('#exchange-inspector').textContent"), /Invalid JSON/);
    await evaluate("state.requests.find(r=>r.id==='qa-23').exchange.response={state:'available',mime:'text/html',text:'<h1>Safe preview</h1>\\n'+Array.from({length:80},(_,i)=>'<p>Retained preview line '+i+'</p>').join('\\n')+'<script>window.parent.compromised=true</script><img src=\"https://forbidden.invalid/image\">',headers:[]}; renderInspector()");
    assert.equal(await evaluate("document.querySelector('.exchange-html-preview').getAttribute('sandbox')"), "");
    assert.equal(await evaluate("window.compromised === true"), false);
    await viewport(600, 800);
    await independentlyScrollPanes("600x800");
    await screenshot("requests-narrow-preview");
    await viewport(360, 740);
    await independentlyScrollPanes("360x740");
    assert(await columnsAligned(), "Narrow request columns must remain aligned");
    assert(await evaluate("document.documentElement.scrollWidth <= innerWidth"), "Page has horizontal overflow at 360 px");
    await click('#inspector-tab-payload');
    assert.equal(await evaluate("state.inspectorTab"), "payload");
    await key('ArrowRight');
    assert.equal(await evaluate("state.inspectorTab"), "preview");
    await narrowPanes("360x740 keyboard preview");
    await screenshot("requests-phone-preview");
    await command("Emulation.setEmulatedMedia", {features: [{name: "prefers-reduced-motion", value: "reduce"}]});
    await evaluate("document.querySelector('.request-row').classList.add('is-new')");
    assert.equal(await evaluate("getComputedStyle(document.querySelector('.request-row')).animationName"), "none");
    await evaluate("showScreen('vm')"); await click('#screen-vm [data-screen="traffic"]');
    assert.equal(await evaluate("document.querySelector('#screen-traffic').hidden"), false);
    await evaluate("state.requests=[{...fixtureRequests[0],id:'new-capture',tabId:'new-tab'}]; renderRequests(); renderInspector()");
    assert.equal(await evaluate("state.selectedRequestId"), null);
    assert.equal(await evaluate("document.querySelectorAll('.request-row').length"), 1);
    await evaluate("state.requests=[]; renderRequests(); renderInspector()");
    assert.match(await evaluate("elements.requestRows.textContent"), /No developer evidence/);
    await screenshot("requests-empty");
    assert.deepEqual(runtimeErrors, [], "Application raised uncaught errors during rendered QA");
    validation = {status: "passed", path: "browser development UI", source: "synthetic fixture", viewports: [[1440,900],[600,800],[360,740]], checks: ["500-row bound and paging", "synchronized selected summary", "visible bounded narrow split", "independent ledger and body scrolling", "hit-tested pointer controls", "pending to response to failed", "equal-length updates", "stable focus and scroll", "sort/filter selection", "dismissal and Escape", "eviction", "arrow-key rows and tabs", "malformed JSON", "sandboxed HTML", "reduced motion", "Back to traffic", "new capture", "empty/malformed/offline"]};
    }
    diagnostics.phase = "validated";
  } catch (error) {
    failure = error;
    diagnostics.failure = String(error.stack ?? error).slice(0, 65536);
    if (captureFailure && socket?.readyState === 1) {
      try {await captureFailure();}
      catch (screenshotError) {diagnostics.failure_screenshot_error = String(screenshotError.message).slice(0, 2048);}
    }
  } finally {
    socket?.close();
    for (const pending of commands.values()) {clearTimeout(pending.timer); pending.reject(new Error("Browser QA cleanup"));}
    commands.clear();
    try {await lifecycle?.stop();}
    catch (error) {failure ??= error; diagnostics.cleanup_error = String(error.message).slice(0, 2048);}
    factsFixture?.release(); consoleFixture?.release();
    collectionFixture?.release();
    if (consoleFixture) {
      diagnostics.fixture_errors = consoleFixture.errors;
      try {await writeFile(join(output, 'console-fixture-receipts.json'), JSON.stringify({schema:'reb-console-ui-qa-v1',receipts:consoleFixture.receipts,errors:consoleFixture.errors}, null, 2));}
      catch (error) {failure ??= error; diagnostics.fixture_receipt_error = String(error.message).slice(0, 2048);}
    }
    evidenceFixture?.release();
    server.closeAllConnections();
    if (server.listening) await new Promise(resolve => server.close(resolve));
    // Keep a profile only when its owned process could not be stopped.
    if (!lifecycle || lifecycle.diagnostics.cleanup?.exited) {
      try {await rm(directory, {recursive: true, force: true, maxRetries: 3, retryDelay: 100});}
      catch (error) {failure ??= error; diagnostics.profile_cleanup_error = String(error.message).slice(0, 2048);}
    }
    await writeFile(join(output, "browser-startup.json"), JSON.stringify(diagnostics, null, 2));
  }
  if (failure) throw failure;
  await writeFile(join(output, "validation.json"), JSON.stringify(validation, null, 2));
  console.log(`PASS real Chromium ${collectionBrowser ? 'Collection' : consoleBrowser ? 'Console' : evidenceBrowser ? 'Evidence metadata' : sourceFactsBrowser ? 'Sources facts' : 'Requests'} interactions; screenshots: ${output}`);
}
if (investigationBrowser || trafficBrowser || sourceFactsBrowser || evidenceBrowser || consoleBrowser || collectionBrowser) {await checkTrafficBrowser(); process.exit(0);}

if (fieldsOnly) process.exit(0);
const temporary = await mkdtemp(join(tmpdir(), "origin-trace-debugger-"));
const resources = [];
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const fixture = createServer((req, res) => {
  if (process.env.ORIGIN_TRACE_FIXTURE_LOG)
    console.log("FIXTURE", req.method, req.url);
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }
  if (req.url === "/slow") {
    setTimeout(() => {
      if (!res.destroyed) {
        res.writeHead(200);
        res.end("slow");
      }
    }, 5000);
    return;
  }
  if (req.url === "/diff") {
    res.setHeader("Content-Type", "text/plain");
    res.end("fixture response\n<script>inert</script>\r\nlast");
    return;
  }
  if (req.url === "/worker.js") {
    res.setHeader("Content-Type", "text/javascript");
    res.end(
      'function workerPayload(input){\nconst out=input+"-worker";\nreturn out;\n}\nself.onmessage=e=>fetch("/echo",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({payload:workerPayload(e.data)})});',
    );
    return;
  }
  if (req.url === "/page") {
    res.setHeader("Content-Type", "text/html");
    res.end(`<!doctype html><title>Origin Trace disposable fixture</title><link rel="icon" href="data:,"><button id="click">Click</button><script>globalThis.fixtureObject={originTraceMarker:"fixture",count:1};
function makePayload(input){
const out=input+"-observed";
return out;
}
globalThis.worker=new Worker("/worker.js");
document.querySelector("button").onclick=()=>{fixtureObject.count++;fetch("/echo",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({payload:makePayload("fixture")})});worker.postMessage("fixture");};</script>`);
    return;
  }
  res.setHeader("Content-Type", "text/plain");
  res.end("fixture response");
});
await new Promise((r) => fixture.listen(0, "127.0.0.1", r));
const fixtureUrl = `http://127.0.0.1:${fixture.address().port}`;
let passed = 0;
try {
  for (const name of ["rust"]) {
    const directory = join(temporary, name);
    await mkdir(directory);
    const profile = join(directory, "browser");
    await mkdir(profile);
    const browser = spawn(
      process.env.ORIGIN_TRACE_TEST_BROWSER ||
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
      [
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-sync",
        "--remote-debugging-port=0",
        `--user-data-dir=${profile}`,
        fixtureUrl + "/page",
      ],
      { stdio: "ignore" },
    );
    resources.push(browser);
    let portReady = false;
    for (let i = 0; i < 300; i++) {
      try {
        await readFile(join(profile, "DevToolsActivePort"));
        portReady = true;
        break;
      } catch {}
      if (browser.exitCode !== null) throw Error(`${name} browser exited`);
      await wait(50);
    }
    assert(portReady);
    const endpoint = join(directory, "endpoint");
    const prefix = [];
    const binary =
      process.env.ORIGIN_TRACE_BACKEND ||
      join(root, "apps/origin-trace-backend/target/debug/origin-trace-backend");
    const bundled = !!process.env.ORIGIN_TRACE_BACKEND;
    const backend = spawn(
      binary,
      [
        ...prefix,
        "--port",
        "0",
        "--store",
        join(directory, "events.jsonl"),
        "--trace-store",
        join(directory, "trace.jsonl"),
        "--signal-store",
        join(directory, "signals.jsonl"),
        "--artifacts",
        join(directory, "artifacts"),
        "--api-collection",
        join(directory, "collection.json"),
        "--local-analyst",
        join(directory, "analyst.json"),
        "--devtools-active-port",
        join(profile, "DevToolsActivePort"),
        ...(bundled
          ? []
          : [
              "--debugger-transport",
              join(root, "build/reb-debugger-transport"),
            ]),
        "--endpoint-file",
        endpoint,
        ...(bundled
          ? []
          : [
              "--ui-directory",
              join(root, "apps/research-ui"),
              "--deobfuscator",
              join(
                root,
                "apps/deobfuscator-worker/target/debug/reb-deobfuscator-worker",
              ),
            ]),
      ],
      {
        cwd: root,
        env: process.env.ORIGIN_TRACE_TEST_EMPTY_PATH
          ? { ...process.env, PATH: "/nonexistent" }
          : process.env,
      },
    );
    resources.push(backend);
    let diagnostics = "";
    backend.stdout.resume();
    backend.stderr.on("data", (x) => {
      diagnostics += x;
      appendFile(join(directory, "stderr.log"), x);
    });
    backend.on("exit", (code) => {
      if (code) console.log(`${name} EXIT ${code}: ${diagnostics}`);
    });
    let url;
    for (let i = 0; i < 200; i++) {
      try {
        url = (await readFile(endpoint, "utf8")).trim();
        break;
      } catch {}
      if (backend.exitCode !== null)
        throw Error(`${name} startup ${diagnostics}`);
      await wait(50);
    }
    assert(url);
    const get = async () => {
      const r = await fetch(url + "/api/debugger");
      assert.equal(r.status, 200);
      const body = await r.json();
      if (!ui.isDebuggerResponse(body)) {
        const invalid = [
          "request_interception",
          "action_scope",
          "object_experiment",
          "runtime_hooks",
          "automation_recipes",
          "repeater",
        ].filter((key, i) => !Object.values(ui)[i + 1](body[key]));
        throw Error(
          "UI rejected debugger state " + JSON.stringify({ invalid, body }),
        );
      }
      return body;
    };
    const action = async (action, values = {}) => {
      const r = await fetch(url + "/api/debugger/actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, ...values }),
      });
      const v = await r.json();
      for (const [key, validate] of Object.entries({
        experiment: ui.isRequestInterception,
        action_scope: ui.isActionScope,
        object_experiment: ui.isObjectExperiment,
        runtime_hooks: ui.isRuntimeHooks,
        automation_recipes: ui.isAutomationRecipes,
        repeater: ui.isRepeater,
      })) {
        if (v[key])
          assert(
            validate(v[key]),
            `UI rejected ${action} ${key}: ${JSON.stringify(v[key])}`,
          );
      }
      if (r.status !== 200)
        throw Error(`${name} ${action}: HTTP ${r.status} ${JSON.stringify(v)}`);
      return v;
    };
    const click = async () => {
      const state = await get();
      const devtools = Number(
        (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split(
          "\n",
        )[0],
      );
      const targets = await (
        await fetch(`http://127.0.0.1:${devtools}/json/list`)
      ).json();
      const target = targets.find(
        (t) => t.id === state.request_interception.target_id,
      );
      assert(target);
      const socket = new WebSocket(target.webSocketDebuggerUrl);
      await new Promise((resolve, reject) => {
        socket.addEventListener("open", () => {
          socket.send(
            JSON.stringify({
              id: 1,
              method: "Runtime.evaluate",
              params: {
                expression: 'document.querySelector("button").click()',
                returnByValue: true,
              },
            }),
          );
        });
        socket.addEventListener("message", (e) => {
          const v = JSON.parse(e.data);
          if (v.id === 1) {
            socket.close();
            v.error ? reject(Error(JSON.stringify(v.error))) : resolve();
          }
        });
        socket.addEventListener("error", reject);
      });
    };
    const until = async (predicate) => {
      for (let i = 0; i < 300; i++) {
        const s = await get();
        if (predicate(s)) return s;
        await wait(50);
      }
      throw Error(
        `${name} state timeout ${JSON.stringify(((s) => ({ state: s.state, error: s.error, target: s.target, targets: s.targets, workers: s.runtime_hooks.workers, hooks: s.runtime_hooks, console: s.console, interception: s.request_interception, automation: s.automation_recipes, scope: s.action_scope }))(await get()))}`,
      );
    };
    await until((s) => s.state === "running");
    await action("create_request_interception_experiment");
    let s = await until(
      (s) =>
        s.state === "running" &&
        s.target?.id === s.request_interception.target_id &&
        s.action_scope.state === "ready",
    );
    assert(s.request_interception.isolated);
    const primary = s.target.id;
    assert(s.action_scope.targets.every((t) => t.connected && t.matched));
    console.log(`PASS ${name} isolated context`);
    passed++;
    await action("configure_request_interception", {
      mode: "fulfill",
      url_pattern: "*",
      response_code: 201,
      response_body: "synthetic fixture",
    });
    let result = await action("run_request_interception", {
      url: fixtureUrl + "/echo",
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "fixture request",
    });
    assert.equal(result.experiment.result.status, 201);
    assert.equal(result.experiment.result.body, "synthetic fixture");
    console.log(`PASS ${name} fulfill`);
    passed++;
    const newPage = await action("create_experiment_page", {
      url: "about:blank",
    });
    const second = newPage.target_id;
    await until(
      (s) =>
        s.action_scope.targets.length === 2 &&
        s.action_scope.targets.every((t) => t.connected),
    );
    await action("set_action_scope", { mode: "target", target_id: second });
    result = await action("run_request_interception", {
      url: fixtureUrl + "/echo",
      method: "GET",
      target_id: second,
    });
    assert.equal(result.experiment.result.status, 201);
    await action("close_experiment_page", { target_id: second });
    await action("set_action_scope", { mode: "global" });
    console.log(`PASS ${name} scope and page lifecycle`);
    passed++;
    await action("configure_request_interception", {
      mode: "continue",
      url_pattern: "*",
    });
    await action("configure_repeater_variables", {
      variables: { base: fixtureUrl },
    });
    await action("run_repeater_request", {
      url: "{{base}}/echo",
      method: "GET",
      timeout_ms: 1000,
    });
    s = await until(
      (s) => s.repeater.history.length === 1 && !s.repeater.active_execution,
    );
    assert.equal(s.repeater.history[0].response.status, 200);
    assert.equal(s.repeater.history[0].response.body, "fixture response");
    await action("run_repeater_request", {
      url: "{{base}}/echo",
      method: "GET",
      timeout_ms: 1000,
    });
    s = await until(
      (s) => s.repeater.history.length === 2 && !s.repeater.active_execution,
    );
    await action("compare_repeater_history", {
      baseline_id: s.repeater.history[0].id,
      current_id: s.repeater.history[1].id,
    });
    s = await get();
    assert.equal(s.repeater.comparison.body_changed, false);
    assert.equal(s.repeater.comparison.body_diff.partial, false);
    assert.equal(s.repeater.comparison.body_diff.lines.length, 0);
    console.log(`PASS ${name} repeater variables/history/comparison`);
    passed++;
    await action("run_repeater_request", {
      url: "{{base}}/slow",
      method: "GET",
      timeout_ms: 100,
    });
    s = await until(
      (s) => s.repeater.history.length === 3 && !s.repeater.active_execution,
    );
    assert(s.repeater.history[2].response.timed_out);
    console.log(`PASS ${name} repeater timeout`);
    passed++;
    await action("run_repeater_request", {
      url: "{{base}}/slow",
      method: "GET",
      timeout_ms: 10000,
    });
    await action("cancel_repeater_request");
    s = await until(
      (s) => s.repeater.history.length === 4 && !s.repeater.active_execution,
    );
    assert(s.repeater.history[3].response.cancelled);
    console.log(`PASS ${name} repeater cancellation`);
    passed++;
    await action("navigate_object_experiment", { url: fixtureUrl + "/page" });
    await until((s) => s.request_interception.pending_requests === 0);
    result = await action("search_object_experiment", {
      property_query: "originTraceMarker",
    });
    assert(result.object_experiment.results.length > 0);
    const object = result.object_experiment.results.find((v) =>
      v.preview.some((p) => p.name === "originTraceMarker"),
    );
    assert(object);
    const searchId = result.object_experiment.search_id;
    result = await action("mutate_object_experiment", {
      operation: "set",
      search_id: searchId,
      result_id: object.id,
      property: "count",
      value: 42,
      confirmed: true,
    });
    assert.equal(result.object_experiment.last_mutation.ok, true);
    assert.equal(result.object_experiment.last_mutation.outcome, "updated");
    result = await action("mutate_object_experiment", {
      operation: "delete",
      search_id: searchId,
      result_id: object.id,
      property: "count",
      confirmed: true,
    });
    assert.equal(result.object_experiment.last_mutation.outcome, "deleted");
    console.log(`PASS ${name} Object Lab search/set/delete/audit`);
    passed++;
    result = await action("search_live_objects", {
      property_query: "originTraceMarker",
    });
    assert(result.search.results.length > 0);
    console.log(`PASS ${name} passive live object search`);
    passed++;
    await until(
      (s) =>
        s.runtime_hooks.workers.length === 1 &&
        s.scripts.some((s) => s.target_type === "worker"),
    );
    let state = await get();
    let script = state.scripts.find((s) => s.url === fixtureUrl + "/page");
    assert(script);
    let source = await (
      await fetch(
        url +
          "/api/debugger/source?script_id=" +
          encodeURIComponent(script.script_id),
      )
    ).json();
    const lines = source.source.split("\n");
    const line =
      script.start_line +
      lines.findIndex((l) => l.includes('const out=input+"-observed"'));
    assert(line >= 0);
    let breakpoint = await action("set_breakpoint", {
      url: "",
      script_id: script.script_id,
      line,
      column: 0,
      kind: "line",
      expression: "",
    });
    const bp = breakpoint.breakpoint?.id || (await get()).breakpoints.at(-1).id;
    const clicking = click();
    state = await until((s) => s.state === "paused");
    assert(state.paused.call_frames.length > 0);
    await action("add_watch", { expression: "input" });
    await action("evaluate_watches", {
      call_frame_id: state.paused.call_frames[0].id,
    });
    state = await get();
    assert.equal(state.watches[0].result.value, "fixture");
    await action("step_over");
    await until((s) => s.state === "paused");
    await action("resume");
    await clicking;
    await action("remove_breakpoint", { breakpoint_id: bp });
    await until((s) => s.state === "running");
    console.log(`PASS ${name} breakpoint/watch/step/resume`);
    passed++;
    result = await action("search_heap_snapshot", {
      query: "originTraceMarker",
      scope: "all",
      case_sensitive: true,
    });
    assert(result.snapshot.results.length > 0);
    await action("capture_heap_diff_baseline");
    result = await action("compare_heap_diff");
    assert(result.diff);
    await action("clear_heap_diff_baseline");
    console.log(`PASS ${name} heap search/baseline/diff`);
    passed++;
    await action("start_memory_origin_trace", {
      query: "fixture",
      scope: "all",
      case_sensitive: true,
      before_steps: 0,
      after_steps: 1,
    });
    const memoryClick = click();
    state = await until((s) =>
      ["found", "not_found", "error", "aborted"].includes(
        s.memory_origin_trace.state,
      ),
    );
    assert.notEqual(
      state.memory_origin_trace.state,
      "error",
      JSON.stringify(state.memory_origin_trace),
    );
    assert(state.memory_origin_trace.steps.length > 0);
    await memoryClick;
    await action("clear_memory_origin_trace");
    console.log(`PASS ${name} memory origin trace`);
    passed++;

    await action("configure_runtime_field_test", {
      enabled: true,
      url: fixtureUrl + "/echo",
      method: "POST",
      kind: "json",
      pointer: "/payload",
      confirmed: true,
    });
    await action("add_runtime_hook", {
      label: "Payload return",
      script_id: script.script_id,
      line,
      column: 0,
      entry_enabled: true,
      return_enabled: true,
      return_mode: "none",
    });
    await action("arm_runtime_hooks", { confirmed: true });
    await click();
    state = await until(
      (s) =>
        s.runtime_hooks.hits.some((h) => h.category === "return") &&
        s.runtime_hooks.field_test.observations.some(
          (o) => o.status === "available",
        ),
    );
    assert(state.runtime_hooks.hits.some((h) => h.category === "entry"));
    await action("disarm_runtime_hooks");
    const baseline = state.runtime_hooks.field_test.observations.find(
      (o) => o.target_type === "page" && o.status === "available",
    );
    assert(baseline);
    await action("remove_runtime_hook", {
      hook_id: state.runtime_hooks.definitions[0].id,
    });
    await action("add_runtime_hook", {
      label: "Payload replacement",
      script_id: script.script_id,
      line,
      column: 0,
      entry_enabled: false,
      return_enabled: true,
      return_mode: "json",
      return_value: "changed",
    });
    await action("arm_runtime_hooks", { confirmed: true });
    await click();
    state = await until(
      (s) =>
        s.runtime_hooks.hits.some((h) => h.operation === "return_overridden") &&
        s.runtime_hooks.field_test.observations.some(
          (o) =>
            o.target_type === "page" &&
            o.status === "available" &&
            o.sha256 !== baseline.sha256,
        ),
    );
    await action("disarm_runtime_hooks");
    const variant = state.runtime_hooks.field_test.observations.find(
      (o) =>
        o.target_type === "page" &&
        o.status === "available" &&
        o.sha256 !== baseline.sha256,
    );
    result = await action("compare_runtime_field_test", {
      baseline_id: baseline.id,
      variant_id: variant.id,
    });
    assert(result.runtime_hooks.field_test.comparison.changed);
    assert.equal(
      result.runtime_hooks.field_test.comparison.interpretation,
      "intervention-associated",
    );
    console.log(
      `PASS ${name} hook entry/return/replacement and request-field comparison`,
    );
    passed++;
    await action("remove_runtime_hook", {
      hook_id: state.runtime_hooks.definitions[0].id,
    });
    state = await get();
    const workerScript = state.scripts.find(
      (s) => s.target_type === "worker" && s.url === fixtureUrl + "/worker.js",
    );
    assert(workerScript);
    source = await (
      await fetch(
        url +
          "/api/debugger/source?script_id=" +
          encodeURIComponent(workerScript.script_id),
      )
    ).json();
    assert(source.source.includes("workerPayload"));
    await action("add_runtime_hook", {
      label: "Worker return",
      script_id: workerScript.script_id,
      line: 1,
      column: 0,
      entry_enabled: true,
      return_enabled: true,
      return_mode: "none",
    });
    await action("arm_runtime_hooks", { confirmed: true });
    await click();
    state = await until((s) =>
      s.runtime_hooks.hits.some(
        (h) => h.target_type === "worker" && h.category === "return",
      ),
    );
    await action("disarm_runtime_hooks");
    await action("clear_runtime_hook_hits");
    await action("configure_runtime_field_test", { enabled: false });
    console.log(`PASS ${name} isolated worker source/hooks`);
    passed++;
    let recipe = await action("add_automation_recipe", {
      label: "Fixture recipe",
      source:
        'console.log("fixture automation");return Number(Utils.getVar("answer"));',
      trigger: "manual",
    });
    result = await action("run_automation_recipe", {
      recipe_id: recipe.recipe.id,
      variables: { answer: "42" },
      confirmed: true,
    });
    assert.equal(result.run.result_text, "42", JSON.stringify(result.run));
    assert.equal(result.run.operation, "completed");
    assert(result.run.logs.some((l) => l.text.includes("fixture automation")));
    console.log(`PASS ${name} manual automation with variables/logs`);
    passed++;
    const after = await action("add_automation_recipe", {
      label: "After load fixture",
      source: "return document.title;",
      trigger: "after-load",
    });
    await action("arm_automation_recipes", { confirmed: true });
    await action("navigate_object_experiment", { url: fixtureUrl + "/page" });
    s = await until((s) =>
      s.automation_recipes.runs.some((r) => r.category === "after-load"),
    );
    assert.equal(
      s.automation_recipes.runs.find((r) => r.category === "after-load")
        .result_text,
      '"Origin Trace disposable fixture"',
    );
    await action("disarm_automation_recipes");
    await action("remove_automation_recipe", { recipe_id: after.recipe.id });
    const before = await action("add_automation_recipe", {
      label: "Before load fixture",
      source: "globalThis.originTraceBeforeLoad=42;return 42;",
      trigger: "before-load",
    });
    await action("arm_automation_recipes", { confirmed: true });
    await action("navigate_object_experiment", { url: fixtureUrl + "/page" });
    s = await until((s) =>
      s.automation_recipes.runs.some((r) => r.category === "before-load"),
    );
    assert.equal(
      s.automation_recipes.runs.find((r) => r.category === "before-load")
        .operation,
      "completed",
    );
    await action("disarm_automation_recipes");
    console.log(`PASS ${name} before/after-load automation triggers`);
    passed++;

    const analyst = async (body) => {
      const response = await fetch(url + "/api/local-analyst/actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const result = await response.json();
      assert.equal(response.status, 200, JSON.stringify(result));
      return result;
    };
    await analyst({
      action: "replace_local_analyst_workspace",
      expected_generation: 0,
      folders: [{ id: 1, name: "Analyst Workspace", parent_id: null }],
      files: [
        {
          id: 1,
          folder_id: 1,
          name: "Fixture analyst",
          kind: "analyst-script",
          language: "javascript",
          content: "return WB.Node.Evidence.events().length;",
        },
      ],
    });
    let analystGeneration = 1;
    const analystRequest = (run_id, source) => ({
      action: "run_local_analyst_script",
      protocol_version: 1,
      run_id,
      script_id: 1,
      library_generation: analystGeneration,
      source,
      variables: {},
      evidence: {
        events: [],
        artifacts: [],
        trace_edges: [],
        signal_profiles: [],
        vm_analysis: null,
        selected_artifact: null,
        summary: {},
      },
      confirmed: true,
      confirmed_sensitive: false,
    });
    result = await analyst(
      analystRequest(1, "return WB.Node.Evidence.events().length;"),
    );
    assert.equal(result.outcome, "completed");
    assert.equal(result.result_text, "0");
    await analyst({
      action: "replace_local_analyst_workspace",
      expected_generation: 1,
      folders: [{ id: 1, name: "Analyst Workspace", parent_id: null }],
      files: [
        {
          id: 1,
          folder_id: 1,
          name: "Fixture analyst",
          kind: "analyst-script",
          language: "javascript",
          content: "while(true){}",
        },
      ],
    });
    analystGeneration = 2;
    result = await analyst(analystRequest(2, "while(true){}"));
    assert.equal(result.outcome, "timed_out");
    assert.equal(result.code, "timeout");
    assert.deepEqual(result.details, {phase: "worker"});
    const pendingAnalyst = analyst(analystRequest(3, "while(true){}"));
    for (let i = 0; i < 100; i++) {
      const state = await (
        await fetch(url + "/api/local-analyst/runner")
      ).json();
      if (state.active_run_id === 3) break;
      await wait(10);
    }
    await analyst({ action: "cancel_local_analyst_script", run_id: 3 });
    result = await pendingAnalyst;
    assert.equal(result.outcome, "cancelled");
    assert.equal(result.code, "cancelled");
    assert.deepEqual(result.details, {phase: "worker"});
    console.log(`PASS ${name} analyst success/timeout/cancellation`);
    passed++;
    await action("run_repeater_request", { url: fixtureUrl + "/diff", method: "GET", timeout_ms: 1000 });
    s = await until(s => !s.repeater.active_execution && s.repeater.history.at(-1)?.response.url === fixtureUrl + "/diff");
    const diff = s.repeater.comparison.body_diff;
    assert.equal(s.repeater.comparison.body_changed, true);
    assert.equal(diff.partial, false);
    assert.equal(diff.added, 3);
    assert.equal(diff.removed, 1);
    assert.equal(diff.lines[2].text, "<script>inert</script>");
    assert.equal(diff.lines[2].ending, "crlf");
    assert.equal(diff.lines[3].ending, "none");
    const malformed = structuredClone(s.repeater);
    malformed.comparison.body_diff.lines[2].current_line = 0;
    assert.equal(ui.isRepeater(malformed), false);
    malformed.comparison.body_diff.lines[2].current_line = 2;
    malformed.comparison.body_diff.lines[2].text = "x".repeat(4097);
    assert.equal(ui.isRepeater(malformed), false);
    console.log(`PASS ${name} Rust response diff and UI contract rejection`);
    passed++;
    await action("clear_automation_runs");
    await action("clear_repeater_history");
    s = await get();
    assert.equal(s.repeater.history.length, 0);
    await action("dispose_request_interception_experiment");
    s = await get();
    assert.equal(s.request_interception.state, "disposed");
    assert.equal(s.request_interception.target_id, null);
    assert.equal(s.repeater.variables.length, 0);
    assert.equal(s.runtime_hooks.hits.length, 0);
    assert.equal(s.runtime_hooks.definitions.length, 0);
    assert.equal(s.automation_recipes.runs.length, 0);
    assert.equal(s.action_scope.targets.length, 0);
    const port = Number(
      (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split(
        "\n",
      )[0],
    );
    const targets = await (
      await fetch(`http://127.0.0.1:${port}/json/list`)
    ).json();
    assert(!targets.some((t) => t.id === primary || t.id === second));
    console.log(`PASS ${name} verified context disposal`);
    passed++;
    backend.kill("SIGTERM");
    browser.kill("SIGTERM");
    await wait(500);
  }
  console.log(JSON.stringify({ temporary, passed }));
} finally {
  for (const child of resources) {
    if (child.exitCode === null) child.kill("SIGTERM");
  }
  fixture.closeAllConnections();
  await new Promise((r) => fixture.close(r));
}
