import { spawn } from "node:child_process";
import { runInNewContext } from "node:vm";
import {
  readFile,
  mkdtemp,
  mkdir,
  writeFile,
  appendFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import assert from "node:assert/strict";
const fieldsOnly = process.argv[2] === "--field-provenance-only";
const root = process.argv[fieldsOnly ? 3 : 2] || new URL("..", import.meta.url).pathname;
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
