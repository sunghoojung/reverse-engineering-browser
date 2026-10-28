// Synthetic saved-Traffic fixtures (reb-network-request-v1 records) for the offline
// exporter checks. No product source, captures, or profiles are modified.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

export const rawUrl = 'https://synthetic-user:synthetic-pass@example.test/path?token=synthetic-query#synthetic-fragment';
export const jsonText = '{"password":"synthetic-json","n":9007199254740993,"dup":1,"dup":2}';
export const formText = 'token=synthetic-form&token=second+value';
export const plainText = '\ufeff雪\r\n<script>synthetic-plain</script>';
export const limits = {requests:1000, body_bytes:131072, headers:128, header_bytes:65536};
const omission = 'Body content omitted from this explicitly redacted copy.';
const variants = new Set(['baseline','epoch','instance','target','truncated','states','clear','off']);
const body = (text = '', base64 = '', state = 'available') => ({state,mime:'application/json',text,base64,truncated:false,reason:''});
const copy = value => JSON.parse(JSON.stringify(value));
export function records(variant = 'baseline') {
  assert(variants.has(variant), `Unknown fixture variant: ${variant}`);
  if (['clear','off'].includes(variant)) return [];
  const record = (name, text) => ({
    id:`synthetic-${name}`,protocol_request_id:`synthetic-${name}`,target_id:'synthetic-target',target_title:'Synthetic title',
    url:rawUrl,document_url:rawUrl,url_truncated:false,document_url_truncated:false,method:'POST',method_truncated:false,
    resource_type:'Fetch',started_monotonic_ms:100,wall_time_ms:1700000000000,state:'complete',status:200,status_text:'OK',
    protocol:'HTTP/1.1',mime_type:'application/octet-stream',duration_ms:1,encoded_data_length:5,
    from_disk_cache:false,from_service_worker:false,error_text:'Synthetic diagnostic text',
    initiator:{sites:[{script_id:'synthetic-script',target_id:'synthetic-target',source:rawUrl,source_truncated:false,
      function:'synthetic_function',line:0,column:0}],gaps:[]},
    request:{headers:[['Authorization','Bearer synthetic-auth'],['Cookie','synthetic-cookie'],
      ['Proxy-Authorization','synthetic-proxy'],['X-Custom-Token','synthetic-custom']],headers_truncated:false,body:body(text)},
    response:{headers:[['Set-Cookie','synthetic-response-cookie']],headers_truncated:false,body:body('','AP8BAgM=')},
  });
  const values = [record('json',jsonText),record('form',formText),record('plain',plainText)];
  if (['epoch','instance','target'].includes(variant)) {
    values[0].request.body.text = `{"owner":"synthetic-${variant}"}`;
    if (variant === 'target') for (const item of values) {
      item.target_id='synthetic-target-2';item.initiator.sites[0].target_id=item.target_id;
    }
  }
  if (variant === 'states') return ['missing','loading','error','empty'].map(state => {
    const item = record(state,'');item.request.body=body('','',state);item.request.body.reason=`Synthetic ${state} limitation`;
    item.response.body=copy(item.request.body);return item;
  });
  if (variant === 'truncated') {
    const item = record('truncated','x'.repeat(limits.body_bytes));
    const prefix = 'https://synthetic-user:synthetic-pass@example.test/';
    item.url=prefix+'x'.repeat(65536-prefix.length);item.document_url=item.url;
    item.url_truncated=item.document_url_truncated=item.method_truncated=true;item.method='M'.repeat(32);
    item.request.headers=[['X-Synthetic-Long','雪'.repeat(2730)]];
    item.request.headers_truncated=item.response.headers_truncated=true;
    item.request.body.truncated=true;item.request.body.reason='Synthetic retained 128 KiB prefix';
    item.initiator.sites[0].source='https://example.test/'+'x'.repeat(8192-'https://example.test/'.length);
    item.initiator.sites[0].source_truncated=true;
    return [item];
  }
  return values;
}
export function network(variant = 'baseline') {
  return {capture_enabled:variant!=='off',instance_id:variant==='instance'?'synthetic-instance-2':'synthetic-instance-1',
    capture_epoch:variant==='epoch'?2:1,target_id:variant==='target'?'synthetic-target-2':'synthetic-target',
    requests:records(variant),dropped:variant==='clear'?8:7,limits:copy(limits)};
}
function redactExpected(item) {
  // Independent fixture oracle, deliberately no call into the production exporter.
  const expected = copy(item);
  const source = item.initiator.sites[0].source;
  expected.url = item.url === rawUrl ? 'https://example.test/path' : item.url.replace('synthetic-user:synthetic-pass@','');
  expected.document_url=expected.url;expected.target_title='<redacted>';expected.error_text='<redacted>';
  expected.initiator.sites[0].source=source===rawUrl?'https://example.test/path':source;
  for (const side of [expected.request,expected.response]) {
    side.headers=side.headers.map(([name])=>[name,'<redacted>']);
    if(side.body.state==='available')side.body.state='redacted';
    side.body.text='';side.body.base64='';side.body.reason=omission;
  }
  return expected;
}
export function verify(value, mode, id, variant = 'baseline') {
  assert(['raw','redacted_copy'].includes(mode),'Mode must be raw or redacted_copy');
  const expected = records(variant).find(item=>item.id===id);
  assert(expected,`No ${id} in variant ${variant}`);
  assert.equal(value.format,'reb-traffic-capture-v1');assert.equal(value.mode,mode);
  assert.equal(value.representation,'Retained CDP strings/base64, not original HTTP wire bytes.');
  assert.equal(value.coverage.dropped,network(variant).dropped);assert.deepEqual(value.coverage.limits,limits);
  assert.match(value.coverage.scope,/selected record.*ephemeral.*not a durable session archive/);
  assert.match(value.coverage.headers,/Primary CDP.*extra-info.*not guaranteed/);
  assert.match(value.coverage.storage,/Reconnect.*target change.*process exit.*retention eviction/);
  assert.deepEqual(value.record,mode==='raw'?expected:redactExpected(expected));
  assert.match(value.warning,mode==='raw'?/Raw local capture may contain credentials/:/Paths, header names and other metadata may contain secrets/);
  return {status:'passed',mode,id,variant,request_text_utf8_bytes:Buffer.byteLength(value.record.request.body.text),
    response_base64_bytes:Buffer.from(value.record.response.body.base64,'base64').length};
}
// Saved-capture wrappers in the shape the offline exporters consume. Live
// native Traffic rows never carry captureRecord; only saved documents do.
export function savedRequests(snapshot) {
  return snapshot.capture_enabled ? snapshot.requests.map(record => ({id:record.id, tabId:record.target_id,
    method:record.method, path:record.url, origin:'live', captureRecord:copy(record),
    captureOwner:[snapshot.instance_id, snapshot.capture_epoch], captureDropped:snapshot.dropped, captureLimits:copy(snapshot.limits)})) : [];
}
export async function selfTest(root) {
  const traffic = await readFile(join(root,'apps/research-ui/traffic_view.js'),'utf8');
  const api = runInNewContext(traffic+'\n;({trafficCaptureDocument})',{TextEncoder,TextDecoder,Uint8Array,URL});
  let documents = 0;
  for (const variant of variants) {
    const snapshot = network(variant);
    for (const request of savedRequests(snapshot)) {
      const before = JSON.stringify(snapshot);
      for (const mode of ['raw','redacted_copy']) {
        const value = copy(api.trafficCaptureDocument(request,mode));verify(value,mode,request.id,variant);documents++;
        const corrupted = copy(value);corrupted.record.url = 'https://wrong.example.test/';
        assert.throws(() => verify(corrupted,mode,request.id,variant));
      }
      assert.equal(JSON.stringify(snapshot),before,'Exports must not mutate the original');
    }
  }
  const bounds = records('truncated')[0];assert.equal(Buffer.byteLength(bounds.url),65536);
  assert.equal(Buffer.byteLength(bounds.request.headers[0][1]),8190);assert.equal(Buffer.byteLength(bounds.request.body.text),131072);
  assert.equal(Buffer.byteLength(bounds.initiator.sites[0].source),8192);
  assert.deepEqual([...Buffer.from('AP8BAgM=','base64')],[0,255,1,2,3]);
  console.log(JSON.stringify({status:'passed',layer:'saved-capture fixture contract and independent export oracle; offline library only',variants:variants.size,documents}));
}
