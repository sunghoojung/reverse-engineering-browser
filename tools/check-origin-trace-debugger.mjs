import { spawn } from "node:child_process";
import { runInNewContext } from "node:vm";
import {
  readFile,
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
const trafficBrowser = process.argv[2] === "--traffic-ui-browser";
const sourceFactsBrowser = process.argv[2] === "--source-facts-ui-browser";
const fieldsOnly = process.argv[2] === "--field-provenance-only";
const root = process.argv[fieldsOnly || trafficBrowser || sourceFactsBrowser ? 3 : 2] || new URL("..", import.meta.url).pathname;
// Facts are UI projections over the already validated Rust contract. These
// fixtures exercise identity and stale/cancelled request ownership, not JS execution.
const sourceFactsUI = runInNewContext(
  (await readFile(join(root, 'apps/research-ui/source_facts.js'), 'utf8')) +
  ';({sourceFactsIdentity,sourceFactsUnavailable,isSourceFactsReport,sourceFactsPosition,sourceFactsReadBytes,createSourceFactsController})',
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

// Every inspector render must refresh the strip from the same current request;
// lifecycle callers must not be able to leave a stale pending/status badge.
const summaryState = {selectedRequestId: "current", requests: [uiRequest("current")], inspectorTab: "headers",
  trafficDetailOpen: true, trafficSelectionNotice: null};
const summaryElements = {};
for (const name of ["selectedMethod", "selectedStatus", "selectedUrl", "requestCopyUrl", "requestCollectionPivot", "requestInspector", "requestSearchScope", "requestFilter"]) summaryElements[name] = new TrafficFixtureNode();
summaryElements.requestSearchScope.value = "url";
const summaryNodes = new Map(["#exchange-inspector", ".traffic-grid", ".detail-pane", "#request-evidence-toggle"].map(key => [key, new TrafficFixtureNode()]));
let renderedSummaryRequest;
const summaryInspector = runInNewContext(
  appSection("      function updateSelectionSummary(", "      function selectRequest(") +
  appSection("      function renderInspector()", "      function renderEvidence()") + ";renderInspector", {
    state: summaryState, elements: summaryElements,
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
      return sourceHeadersStalled ? abortable(new Promise(() => {})) : {ok: true, json: () => abortable(reply)};
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
  const fixture = {mode:'partial',pending:[],requests:[],artifacts,bytes,snow};
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
    if(/^\/api\/artifacts\/[78]\/content$/.test(url.pathname)){
      const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||2097152);
      const chunk=bytes.subarray(offset,offset+limit);
      response.writeHead(200,{'Content-Type':'application/octet-stream','X-Artifact-Total-Bytes':String(bytes.length),'X-Artifact-Offset':String(offset),'X-Artifact-Truncated':String(offset+chunk.length<bytes.length)});response.end(chunk);return true;
    }
    return false;
  };
  fixture.release = () => {for(const resolve of fixture.pending.splice(0)) resolve();};
  return fixture;
}

// Keep fixture routing admissible to the normal refresh path before launching
// Chrome; a blanket offline events response would prevent artifact discovery.
const sourcesFixtureControl = await sourceFactsBrowserFixture();
const sourcesFixtureModels = runInNewContext((await readFile(join(root,'apps/research-ui/evidence_models.js'),'utf8'))+';({isBrokerResponse,isArtifactResponse})');
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
console.log('PASS Sources browser fixture event admission, exact artifact identity, response and byte headers (not rendered QA)');

async function checkSourceFactsInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture}) {
  const press = value => {
    const code = {Enter:13,Escape:27,Home:36,End:35,ArrowDown:40}[value];
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
  return {status:'passed',path:'browser development Sources UI',source:'synthetic immutable-artifact fixture; no analyzed JavaScript executed',viewports:[[1440,900],[760,560]],checks:['real hit-tested Facts controls','offline HTTP artifact availability','100-row paging','keyboard categories and disclosure','UTF-8/BOM original-byte navigation','profile-complete/partial/truncated/unknown/unavailable/error states','identity rejection and prior-report retention','Cancel and explicit retry','stale selection','Close/Escape/reopen focus','narrow overlay dismissal','workspace return']};
}

async function checkTrafficBrowser() {
  const executable = process.env.REB_UI_CHROMIUM;
  assert(executable, "Set REB_UI_CHROMIUM to the installed Chrome/Chromium executable. Sandbox flags are not overridden.");
  const directory = await mkdtemp(join(tmpdir(), sourceFactsBrowser ? "reb-source-facts-ui-" : "reb-requests-ui-"));
  const output = process.env.REB_UI_SCREENSHOTS || join(root, "build", sourceFactsBrowser ? "source-facts-ui-qa" : "requests-ui-qa");
  await mkdir(output, {recursive: true});
  let trafficApiMode = "offline";
  const factsFixture = sourceFactsBrowser ? await sourceFactsBrowserFixture() : null;
  const server = createServer(async (request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    if (factsFixture && await factsFixture.handle(request, response)) return;
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
    socket.addEventListener("message", event => {
      const message = JSON.parse(event.data);
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
    const wheel = async (selector, deltaY) => {
      const point = await evaluate(`(() => {
        const node = document.querySelector(${JSON.stringify(selector)}), r = node.getBoundingClientRect();
        const x = r.x+r.width/2, y = r.y+r.height/2, hit = document.elementFromPoint(x,y);
        if (r.width <= 0 || r.height <= 0 || x < 0 || x >= innerWidth || y < 0 || y >= innerHeight || !hit || !node.contains(hit)) throw new Error('Scroll target is clipped or offscreen: '+${JSON.stringify(selector)});
        return {x,y,scrollTop:node.scrollTop};
      })()`);
      await command("Input.dispatchMouseEvent", {type: "mouseWheel", x:point.x, y:point.y, deltaX: 0, deltaY});
      await evaluate(`new Promise(resolve => {
        const node=document.querySelector(${JSON.stringify(selector)}), start=performance.now();
        let previous=${point.scrollTop}, moved=false, stable=0;
        function frame(){const current=node.scrollTop; moved ||= current!==${point.scrollTop};
          stable=current===previous?stable+1:0; previous=current;
          if(moved&&stable>=3 || performance.now()-start>1500) resolve(); else requestAnimationFrame(frame);}
        requestAnimationFrame(frame);
      })`);
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
        return {x,y};
      })()`);
      await command("Input.dispatchMouseEvent", {type: "mousePressed", ...rect, button: "left", clickCount: 1});
      await command("Input.dispatchMouseEvent", {type: "mouseReleased", ...rect, button: "left", clickCount: 1});
    };
    const key = async (value, code = value, native = {}) => {
      await command("Input.dispatchKeyEvent", {type: "keyDown", key: value, code, ...native});
      await command("Input.dispatchKeyEvent", {type: "keyUp", key: value, code, windowsVirtualKeyCode:native.windowsVirtualKeyCode});
    };
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
      await writeFile(join(output, sourceFactsBrowser ? "source-facts-failure.png" : "requests-failure.png"), Buffer.from(result.data, "base64"));
    };
    await viewport(1440, 900);
    await command("Page.navigate", {url: `http://127.0.0.1:${server.address().port}/`});
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (await evaluate("typeof renderRequests === 'function' && typeof state !== 'undefined'")) break;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert(await evaluate("typeof renderRequests === 'function'"), "Application did not initialize");
    diagnostics.phase = "interactive validation";
    if (sourceFactsBrowser) {
      validation = await checkSourceFactsInteractions({evaluate,viewport,click,key,wheel,screenshot,fixture:factsFixture});
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
    factsFixture?.release();
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
  console.log(`PASS real Chromium ${sourceFactsBrowser ? 'Sources facts' : 'Requests'} interactions; screenshots: ${output}`);
}
if (trafficBrowser || sourceFactsBrowser) {await checkTrafficBrowser(); process.exit(0);}

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
