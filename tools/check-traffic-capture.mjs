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
