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
let selected = request();
const api = runInNewContext(source + ';({trafficCaptureDocument})', {URL, TextEncoder, TextDecoder});
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
assert.throws(() => api.trafficCaptureDocument(null), /saved capture record is required/);
for (const state of ['missing','loading','error','empty']) {
  selected.captureRecord.request.body = {...body(),state,truncated:true,reason:'Synthetic capture limitation'};
  const exported = api.trafficCaptureDocument(selected,'redacted_copy');
  assert.equal(exported.record.request.body.state,state);
  assert.equal(exported.record.request.body.truncated,true);
  assert.equal(api.trafficCaptureDocument(selected).record.request.body.reason,'Synthetic capture limitation');
}
console.log('PASS saved reb-traffic-capture-v1 export copy: synthetic credentials/URLs/JSON/form/plain/binary preservation, nonmutating explicit redaction, original-byte equality and limitation disclosure (offline exporter library; no live UI)');

// Native failed-request notices.
{
  const models = await readFile(new URL('../apps/research-ui/evidence_models.js', import.meta.url), 'utf8');
  const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
  const start=app.indexOf('      function renderNetworkNotice()');
  const end=app.indexOf('      function textElement(',start);
  assert(start>=0 && end>start);
  const state={sessionMode:'live',broker:'connected',events:[{category:'network',type:'request_completed',error_code:0,session_id:'1',process_id:1,sequence_number:'1'}],requests:[]};
  let notice;
  const networkNotice={hidden:false,textContent:'',dataset:{}};
  const assertQuiet=()=>{assert.equal(networkNotice.hidden,true);assert.equal(networkNotice.textContent,'');};
  const standingProse=/CDP capture|debugger is disconnected/;
  const helperStart=source.indexOf('function trafficRequestFailed(');
  const helperEnd=source.indexOf('function renderTrafficRows(',helperStart);
  const checks=runInNewContext(source.slice(helperStart,helperEnd)+'\n'+models+'\n'+app.slice(start,end)+';({renderNetworkNotice,trafficRequestFailed,trafficFailedRequestCount,trafficFailedRequestNotice})',{
    state,TextEncoder,shownSequenceGaps:()=>0n,shownQueueDrops:()=>0n,eventCountScopeLabel:()=>"authored fixture",elements:{networkNotice},
    setNetworkNotice(kind,text){notice={kind,text};networkNotice.hidden=false;networkNotice.textContent=text;networkNotice.dataset.kind=kind;}
  });
  // Native rows from requestsFromEvents: request_failed sets failed and the Failed status label.
  const loadingFailed={id:'row-failed-1',path:'https://example.com/logo.png',method:'GET',status:'failed',failed:true,operation:'request_failed'};
  const nativeFailed={id:'row-failed-2',path:'https://example.com/asset',method:'GET',status:'failed',failed:true,operation:'request_failed'};
  const ok={id:'ok',path:'https://example.com/ok',method:'GET',status:200,failed:false,operation:'request_completed'};
  const httpError={id:'missing',path:'https://example.com/missing',method:'GET',status:404,failed:false,operation:'request_completed'};
  const interrupted={id:'interrupted',path:'https://example.com/redirect',method:'GET',status:'incomplete',failed:false,interrupted:true,operation:'request_failed'};
  assert.equal(checks.trafficRequestFailed(loadingFailed),true);
  assert.equal(checks.trafficRequestFailed(nativeFailed),true);
  assert.equal(checks.trafficRequestFailed(interrupted),false,'An observation handoff is not a failed request');
  assert.equal(checks.trafficRequestFailed(ok),false);
  assert.equal(checks.trafficRequestFailed(httpError),false,'An HTTP error status is not the Failed row');
  assert.equal(checks.trafficRequestFailed({error_code:0,status:200,failed:false,path:'https://example.com/quiet'}),false);
  assert.equal(checks.trafficRequestFailed({type:'gap',dropped_connections:4}),false);
  assert.equal(checks.trafficFailedRequestNotice([ok,httpError]),'');
  assert.equal(checks.trafficFailedRequestNotice([ok,loadingFailed]),'Failed requests: 1.');
  assert.equal(checks.trafficFailedRequestCount([loadingFailed,nativeFailed,ok,httpError]),2);
  const eventsBefore=JSON.stringify(state.events);
  state.requests=[ok,loadingFailed];
  checks.renderNetworkNotice();
  assert.equal(notice.kind,'empty','A failed HTTP row does not become a capture gap');
  assert.match(notice.text,/Failed requests: 1\./);
  assert.doesNotMatch(notice.text,/queue reports|Dropped:/);
  assert.doesNotMatch(notice.text, standingProse);
  assert.equal(JSON.stringify(state.events),eventsBefore);
  assert.equal(state.events[0].error_code,0);
  state.requests=[ok,loadingFailed,nativeFailed];
  checks.renderNetworkNotice();
  assert.equal(notice.kind,'empty');
  assert.match(notice.text,/Failed requests: 2\./);
  state.requests=[ok,httpError];
  checks.renderNetworkNotice();
  assertQuiet();
  console.log('PASS native failed-row notices without changing queue or error counters');
}

// Native scope buttons label tabs by a known domain, else a positional fallback.
{
  const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
  const first = app.indexOf('      function renderRequestScopes()');
  const last = app.indexOf('      function renderRequests(', first);
  class ScopeNode {
    constructor() { this.children=[];this.dataset={}; }
    append(...nodes) { this.children.push(...nodes);for(const node of nodes)node.parent=this; }
    insertBefore(node,before) { this.children=this.children.filter(value=>value!==node);const index=this.children.indexOf(before);this.children.splice(index<0?this.children.length:index,0,node);node.parent=this; }
    remove() { this.parent.children=this.parent.children.filter(value=>value!==this); }
    get lastElementChild() { return this.children.at(-1); }
    setAttribute() {} addEventListener() {} contains() { return false; }
  }
  const state={requests:[{tabId:'worker-a',path:'fixture.test'}],requestTabId:'all',requestDomain:'all'};
  const elements={requestTabScopes:new ScopeNode(),requestDomain:new ScopeNode()};
  const render=runInNewContext(app.slice(first,last)+';renderRequestScopes',{
    state,elements,document:{activeElement:null,createElement:()=>new ScopeNode()},
    requestTabGroups:()=>[{id:'worker-a',requests:state.requests}],requestDomain:request=>request.path});
  render();
  assert.equal(elements.requestTabScopes.children[0].children[0].textContent,'All tabs');
  assert.equal(elements.requestTabScopes.children[1].children[0].textContent,'fixture.test');
  assert.match(elements.requestTabScopes.children[1].title,/tab id worker-a/);
  for (const missing of [undefined, 'unknown']) {
    state.requests=[{tabId:'worker-a',path:missing}];
    render();
    assert.equal(elements.requestTabScopes.children[1].children[0].textContent,'Tab 1', String(missing));
  }
  console.log('PASS Traffic tab-scope labels use a known domain, else a Tab fallback (production function; not rendered QA)');
}
