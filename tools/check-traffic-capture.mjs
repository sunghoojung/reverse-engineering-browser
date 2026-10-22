import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';

const source = await readFile(new URL('../apps/research-ui/traffic_view.js', import.meta.url), 'utf8');
const plain = value => JSON.parse(JSON.stringify(value));
const body = (text = '', base64 = '') => ({state:'available', mime:'application/json', text, base64, truncated:false, reason:''});
const rawUrl = 'https://synthetic-user:synthetic-pass@example.test/path?token=synthetic-query#synthetic-fragment';
const request = () => ({id:'same-id', tabId:'same-tab', captureOwner:['synthetic-instance',1], captureDropped:7,
  captureLimits:{requests:1000, body_bytes:131072, headers:128, header_bytes:65536},
  captureRecord:{id:'same-id', target_title:'Synthetic title', url:rawUrl, document_url:rawUrl,
    started_monotonic_ms:1, wall_time_ms:2, url_truncated:false, document_url_truncated:false,
    initiator:{sites:[{source:rawUrl, function:'synthetic_function'}], gaps:[]},
    request:{headers:[['Authorization','Bearer synthetic-auth'],['Cookie','synthetic-cookie'],
      ['Proxy-Authorization','synthetic-proxy'],['X-Custom-Token','synthetic-custom']], headers_truncated:false, body:body()},
    response:{headers:[['Set-Cookie','synthetic-response-cookie']], headers_truncated:true, body:body()}}});
let selected = request(), clipboard = [], resolveCopy;
const status = {textContent:''}, summary = {focus() {this.focused = true;}};
const buttons = ['raw','redacted_copy'].flatMap(mode => ['download','clipboard'].map(destination => ({
  dataset:{trafficExport:mode, trafficDestination:destination}, disabled:false,
  addEventListener(name, handler) {this[name] = handler;}
})));
const host = {open:false, events:{}, querySelector(selector) {return selector === 'summary' ? summary : status;},
  querySelectorAll() {return buttons;}, addEventListener(name, handler) {this.events[name] = handler;}};
let native = false, downloads = 0, objectUrls = 0, revoked = 0;
const document = {documentElement:{classList:{contains:() => native}}, body:{append() {}},
  createElement() {return {click() {downloads++;}, remove() {}};}};
class TestURL extends URL {
  static createObjectURL() {objectUrls++; return 'blob:synthetic';}
  static revokeObjectURL() {revoked++;}
}
const api = runInNewContext(source + ';({trafficCaptureDocument, installTrafficCaptureExport})', {
  URL:TestURL, Blob, TextEncoder, TextDecoder, document,
  navigator:{clipboard:{writeText(text) {clipboard.push(text); return new Promise(resolve => {resolveCopy = resolve;});}}},
  setTimeout(callback) {callback();}
});
for (const text of ['{"password":"synthetic-json","n":9007199254740993,"dup":1,"dup":2}',
  'token=synthetic-form&token=second+value', '\ufeff雪\r\n<script>synthetic-plain</script>']) {
  selected.captureRecord.request.body = body(text);
  selected.captureRecord.response.body = body('', Buffer.from([0,255,1,2,3]).toString('base64'));
  const original = JSON.stringify(selected);
  const raw = api.trafficCaptureDocument(selected);
  assert.equal(raw.mode, 'raw'); assert.equal(raw.format, 'reb-traffic-capture-v1');
  assert.deepEqual(plain(raw.record), selected.captureRecord);
  assert.deepEqual(Buffer.from(raw.record.request.body.text), Buffer.from(text));
  assert.equal(raw.record.response.body.base64, 'AP8BAgM=');
  const redacted = api.trafficCaptureDocument(selected, 'redacted_copy');
  assert.equal(redacted.record.url, 'https://example.test/path');
  assert.equal(redacted.record.document_url, 'https://example.test/path');
  assert.equal(redacted.record.initiator.sites[0].source, 'https://example.test/path');
  assert.equal(redacted.record.response.headers_truncated, true);
  assert.equal(redacted.record.request.body.state, 'redacted');
  assert.equal(redacted.record.request.body.text, ''); assert.equal(redacted.record.response.body.base64, '');
  for (const side of ['request','response']) assert(redacted.record[side].headers.every(([,value]) => value === '<redacted>'));
  assert.match(redacted.warning, /Paths, header names and other metadata may contain secrets/);
  assert.equal(JSON.stringify(selected), original, 'Redacted export must not alter original values or bytes');
  redacted.record.request.headers.push(['synthetic-new','synthetic']);
  assert.equal(JSON.stringify(selected), original, 'Export copy must not alias retained data');
}
assert.throws(() => api.trafficCaptureDocument(selected,'automatic'), /Unknown/);
assert.throws(() => api.trafficCaptureDocument(null), /Select/);
for (const state of ['missing','loading','error','empty']) {
  selected.captureRecord.request.body = {...body(),state,truncated:true,reason:'Synthetic capture limitation'};
  const exported = api.trafficCaptureDocument(selected,'redacted_copy');
  assert.equal(exported.record.request.body.state,state);
  assert.equal(exported.record.request.body.truncated,true);
  assert.equal(api.trafficCaptureDocument(selected).record.request.body.reason,'Synthetic capture limitation');
}
const ui = api.installTrafficCaptureExport(host,() => selected);
const copyRaw = buttons.find(button => button.dataset.trafficExport === 'raw' && button.dataset.trafficDestination === 'clipboard');
const saveRaw = buttons.find(button => button.dataset.trafficExport === 'raw' && button.dataset.trafficDestination === 'download');
let pending = copyRaw.click();
assert.equal(buttons.every(button => button.disabled),true);
await copyRaw.click(); assert.equal(clipboard.length,1, 'Repeated click while pending must not copy twice');
resolveCopy(); await pending; assert.match(status.textContent,/unmasked/);
assert.deepEqual(JSON.parse(clipboard[0]).record,selected.captureRecord);
for (const replace of [
  old => ({...old,captureOwner:['synthetic-instance',2]}),
  old => ({...old,captureOwner:['new-instance',1]}),
  old => ({...old,id:'new-id'}),
  () => null,
]) {
  selected = request(); ui.sync(); pending = copyRaw.click();
  selected = replace(selected); ui.sync(); resolveCopy(); await pending;
  assert.equal(status.textContent,'', 'Late clipboard completion must not label a different owner');
}
selected=request();ui.sync();pending=copyRaw.click();const old=selected;selected=null;ui.sync();selected=old;ui.sync();resolveCopy();await pending;
assert.equal(status.textContent,'', 'Eviction followed by identical ID restoration must retire the previous copy');
await saveRaw.click();assert.equal(downloads,1);assert.equal(objectUrls,1);assert.equal(revoked,1);
host.open=true;let prevented=false,stopped=false;
host.events.keydown({key:'Escape',preventDefault(){prevented=true;},stopPropagation(){stopped=true;}});
assert.equal(host.open,false);assert(prevented && stopped && summary.focused);
native=true;api.installTrafficCaptureExport(host,() => selected);
assert(buttons.filter(button => button.dataset.trafficDestination === 'download').every(button => button.disabled));
assert.match(saveRaw.title,/Native file download is unavailable/);
console.log('PASS raw-default retained CDP export, synthetic credentials/URLs/JSON/form/plain/binary preservation, nonmutating explicit redaction, original-byte equality, bounds disclosure, duplicate-click and stale-copy ownership, native download restriction and Escape (DOM model; not native runtime)');

// HTTP capture ownership is independent of the selected Sources debugger page.
{
  const models = await readFile(new URL('../apps/research-ui/evidence_models.js', import.meta.url), 'utf8');
  const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
  const start = app.indexOf('      function networkContentCaptureEnabled()');
  const end = app.indexOf('      function textElement(', start);
  assert(start >= 0 && end > start);
  const status = {scope:'http-page-targets',state:'ready',attached_targets:2,eligible_targets:2,
    target_limit:8,target_overflow:0,failed_targets:0,gaps:0,last_error:null,message:'Synthetic coverage'};
  const state = {sessionMode:'live',broker:'connected',events:[],requests:[],
    debuggerSession:{state:'waiting',network:{capture_enabled:true,capture_status:status,dropped:0}}};
  let notice;
  const checks = runInNewContext(models + '\n' + app.slice(start,end) +
    ';({isDebuggerNetworkCaptureStatus,isDebuggerNetwork,networkContentCaptureActive,renderNetworkNotice})',
    {state, TextEncoder, countSequenceGaps:()=>0n, countReportedQueueDrops:()=>0n,
      elements:{networkNotice:{hidden:false}},setNetworkNotice:(kind,text)=>{notice={kind,text};}});
  assert.equal(checks.isDebuggerNetworkCaptureStatus(status),true);
  for (const limit of [1, 8, 32, 128]) {
    const expanded = {...status,scope:'http-browser-targets',transport_mode:'browser-sessions',startup_mode:'passive',target_limit:limit,
      attached_targets:limit,eligible_targets:limit,failed_targets:0,
      attached_target_ids:Array.from({length:limit},(_,index)=>'owner-'+index)};
    assert.equal(checks.isDebuggerNetworkCaptureStatus(expanded),true,`Configured ${limit}-target scope is valid`);
  }

  for (const invalid of [{startup_mode:'hold'},{transport_mode:'browser-sessions'},{discovery_stale:'true'},{catalog_incomplete:'true'},{unattached_targets:[{id:'page',title:'x'.repeat(129)}]},{unattached_targets_omitted:513},{attached_targets:129},{attached_target_ids:Array(129).fill('page')},{attached_target_ids:['x'.repeat(4097)]},{attached_target_ids:[1]},{eligible_targets:513},{target_limit:129},{target_limit:0},
    {target_overflow:512},{failed_targets:-1},{gaps:NaN},{scope:'all-tabs'},
    {state:'complete'},{last_error:'x'.repeat(513)},{message:'x'.repeat(1025)}]) {
    assert.equal(checks.isDebuggerNetworkCaptureStatus({...status,...invalid}),false);
  }
  const network={...state.debuggerSession.network,target_id:null,requests:[],
    limits:{requests:1000,body_bytes:131072,headers:128,header_bytes:65536}};
  assert.equal(checks.isDebuggerNetwork(network),true);
  assert.equal(checks.isDebuggerNetwork({...network,capture_status:undefined}),true,'Older snapshots remain compatible');
  assert.equal(checks.isDebuggerNetwork({...network,capture_status:{...status,attached_targets:129}}),false);
  assert.equal(checks.networkContentCaptureActive(),true,'Healthy HTTP owners do not depend on Sources attachment');
  checks.renderNetworkNotice();
  assert.equal(notice.kind,'active'); assert.match(notice.text,/2 of 2 eligible page targets attached/);
  assert.match(notice.text,/Requests before attachment, including short-lived targets, are unavailable/);
  assert.match(notice.text,/worker and out-of-process iframe targets are not attached/);
  assert.match(notice.text,/Requests observed only by native probes are not included in this CDP list/);
  state.debuggerSession.target={id:'ninth-page'};status.attached_target_ids=['first-page','second-page'];
  checks.renderNetworkNotice();assert.equal(notice.kind,'gap');
  assert.match(notice.text,/selected debugger page is not attached for HTTP capture/);
  status.attached_target_ids.push('ninth-page');checks.renderNetworkNotice();assert.equal(notice.kind,'active');
  assert(!notice.text.includes('selected debugger page is not attached'));
  delete status.attached_target_ids;
  status.unattached_targets=Array.from({length:5},(_,i)=>({id:'page-'+i,title:'Missing page '+i}));
  status.unattached_targets_omitted=2;checks.renderNetworkNotice();
  assert.match(notice.text,/Not attached: Missing page 0 \[page-0\]/);
  assert.match(notice.text,/4 more targets not listed here/);
  assert(!notice.text.includes('Missing page 3'),'Coverage labels stay bounded');
  delete status.unattached_targets;delete status.unattached_targets_omitted;
  assert.match(notice.text,/WebSockets remain scoped to the selected debugger target/);
  Object.assign(status,{state:'partial',attached_targets:7,eligible_targets:10,target_overflow:2,failed_targets:1,gaps:3,last_error:'DO NOT ECHO RAW ERROR'});
  checks.renderNetworkNotice();
  assert.equal(notice.kind,'gap'); assert.match(notice.text,/2 page targets exceed the capture limit/);
  assert.match(notice.text,/1 target attachments failed; retry is pending/);
  assert.match(notice.text,/3 HTTP capture owner losses or retirements/);
  assert(!notice.text.includes(status.last_error),'Raw errors are not echoed into coverage notices');
  status.discovery_stale=true;checks.renderNetworkNotice();
  assert.match(notice.text,/Target discovery is unavailable; counts are last known and new tabs may not attach/);
  assert.equal(checks.networkContentCaptureActive(),true,'Existing healthy owners remain active during discovery failure');
  delete status.discovery_stale;
  Object.assign(status,{state:'waiting',attached_targets:0});
  assert.equal(checks.networkContentCaptureActive(),false);
  checks.renderNetworkNotice();assert.equal(notice.kind,'disconnected');
  state.debuggerRefreshFailed=true;Object.assign(status,{state:'ready',attached_targets:2});
  assert.equal(checks.networkContentCaptureActive(),false,'Failed poll cannot claim healthy capture');
  checks.renderNetworkNotice();assert.match(notice.text,/live debugger is disconnected/);
  state.debuggerRefreshFailed=false;
  Object.assign(status,{scope:'http-browser-targets',state:'ready',target_limit:32,
    attached_targets:12,eligible_targets:12,target_overflow:0,failed_targets:0,gaps:0});
  checks.renderNetworkNotice();
  assert.equal(notice.kind,'active');assert.match(notice.text,/12 of 12 eligible browser targets attached \(limit 32\)/);
  assert.match(notice.text,/Mode: passive browser target discovery/);
  status.catalog_incomplete=true;checks.renderNetworkNotice();assert.match(notice.text,/counts cover only known targets/);assert.equal(notice.kind,'gap');delete status.catalog_incomplete;
  assert.match(notice.text,/without requesting startup pauses/);
  assert.match(notice.text,/Attaching worker targets can affect their lifecycle and timeout behavior/);
  assert.match(notice.text,/first-request capture is not guaranteed/);
  assert(!notice.text.includes('worker and out-of-process iframe targets are not attached'));
  Object.assign(status,{state:'partial',target_limit:128,attached_targets:128,eligible_targets:130,target_overflow:2});
  checks.renderNetworkNotice();assert.equal(notice.kind,'gap');
  assert.match(notice.text,/2 browser targets exceed the capture limit/);
  Object.assign(status,{scope:'http-page-targets',state:'ready',attached_targets:32,eligible_targets:32,target_limit:32,target_overflow:0});
  checks.renderNetworkNotice();assert.match(notice.text,/Mode: page-target polling fallback/);
  assert.match(notice.text,/worker and out-of-process iframe targets are not attached/);
  assert(!notice.text.includes('Mode: passive browser target discovery'));
  delete state.debuggerSession.network.capture_status;
  state.debuggerSession.state='running';assert.equal(checks.networkContentCaptureActive(),true);
  state.debuggerSession.network.capture_enabled=false;assert.equal(checks.networkContentCaptureActive(),false);
  console.log('PASS bounded HTTP coverage validation, independent owners, overflow/failure/gap notices, pre-attachment and WebSocket scope, old snapshots and disconnect handling (model; not rendered QA)');
}

// The same scope buttons represent workers/OOPIFs in browser-session mode.
{
  const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
  const first = app.indexOf('      function renderRequestScopes()');
  const last = app.indexOf('      function renderRequests()', first);
  class ScopeNode {
    constructor() { this.children=[];this.dataset={}; }
    append(...nodes) { this.children.push(...nodes);for(const node of nodes)node.parent=this; }
    insertBefore(node,before) { this.children=this.children.filter(value=>value!==node);const index=this.children.indexOf(before);this.children.splice(index<0?this.children.length:index,0,node);node.parent=this; }
    remove() { this.parent.children=this.parent.children.filter(value=>value!==this); }
    get lastElementChild() { return this.children.at(-1); }
    setAttribute() {} addEventListener() {} contains() { return false; }
  }
  const state={requests:[{tabId:'worker-a',path:'fixture.test'}],requestTabId:'all',requestDomain:'all',
    debuggerSession:{network:{capture_status:{scope:'http-browser-targets'}}}};
  const elements={requestTabScopes:new ScopeNode(),requestDomain:new ScopeNode()};
  const render=runInNewContext(app.slice(first,last)+';renderRequestScopes',{
    state,elements,document:{activeElement:null,createElement:()=>new ScopeNode()},
    requestTabGroups:()=>[{id:'worker-a',requests:state.requests}],requestDomain:request=>request.path});
  render();
  assert.equal(elements.requestTabScopes.children[0].children[0].textContent,'All targets');
  assert.equal(elements.requestTabScopes.children[1].children[0].textContent,'fixture.test');
  assert.match(elements.requestTabScopes.children[1].title,/target id worker-a/);
  for (const missing of [undefined, 'unknown']) {
    state.requests=[{tabId:'worker-a',path:missing}];
    render();
    assert.equal(elements.requestTabScopes.children[1].children[0].textContent,'Target 1', String(missing));
  }
  state.debuggerSession.network.capture_status.scope='http-page-targets';render();
  assert.equal(elements.requestTabScopes.children[0].children[0].textContent,'All tabs');
  assert.equal(elements.requestTabScopes.children[1].children[0].textContent,'Tab 1');
  assert.match(elements.requestTabScopes.children[1].title,/tab id worker-a/);
  console.log('PASS Traffic target-scope labels use a known domain, else Target/Tab fallbacks (production function; not rendered QA)');
}
