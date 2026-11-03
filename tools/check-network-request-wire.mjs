// The C++ core verdict on every valid and malformed request_body and
// request_target record (tests/network_request_test.cpp --golden) must match
// the Python evidence validator and the shipped Traffic decoders. Then the
// shipped row model joins children to their exact lifecycle parents.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const exe = process.env.REB_NETWORK_REQUEST_TEST ?? new URL('build/tests/network-request-test', root).pathname;
assert(fs.existsSync(exe), `missing ${exe}; build it with make build/tests/network-request-test`);
const source = fs.readFileSync(new URL('apps/research-ui/evidence_models.js', root), 'utf8');
const model = new Function(`${source}
return {decodeRequestBodyRecord, decodeRequestTargetRecord, requestsFromEvents, isBrokerEvent, isBrokerResponse};`)();

const cases = JSON.parse(execFileSync(exe, ['--golden'], {encoding: 'utf8'}));
assert(cases.length > 40 && cases.some(item => item.valid) && cases.some(item => !item.valid));
const python = `import importlib.util,json,sys
s=importlib.util.spec_from_file_location('validator',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for event in json.load(sys.stdin):
  try: m.validate_event(event,1);print('true')
  except ValueError: print('false')`;
const verdicts = execFileSync('python3', ['-c', python, new URL('tools/validate-evidence-store.py', root).pathname],
  {input: JSON.stringify(cases.map(item => item.event)), encoding: 'utf8'}).trim().split('\n').map(value => value === 'true');
cases.forEach((item, index) => {
  const decode = item.event.type === 'request_target' ? model.decodeRequestTargetRecord : model.decodeRequestBodyRecord;
  assert.equal(decode(item.event) !== null, item.valid, `UI decoder: ${item.name}`);
  assert.equal(verdicts[index], item.valid, `Python validator: ${item.name}`);
  // The generic envelope stays acceptable so a malformed child cannot fail a poll.
  if (item.event.category === 'network' && item.event.flags === 0) assert(model.isBrokerEvent(item.event), item.name);
});

const golden = name => structuredClone(cases.find(item => item.name === name).event);
const hex = text => Buffer.from(text).toString('hex');
// Byte 8 of a target payload is its scheme code; 2 is https.
const https = event => Object.assign(event, {payload: `${event.payload.slice(0, 16)}02${event.payload.slice(18)}`});
const start = Object.assign(golden('captured body'), {
  type: 'request_started', sequence_number: '11', parent_event_id: '0', artifact_id: '0', resource_type: 13,
  payload: hex('POST api.hcaptcha.test'), payload_size: 22
});
const body = golden('captured body');
const target = https(Object.assign(golden('short target'), {sequence_number: '13', parent_event_id: '11'}));
let [row] = model.requestsFromEvents([start, target, body], 'live');
assert.equal(row.path, 'https://api.hcaptcha.test/ab');
assert.equal(row.hostOnly, false);
assert.equal(row.targetKind, 'url');
assert.equal(row.method, 'POST');
assert.equal(row.body.state, 'captured');
assert.equal(row.body.artifactId, '901');
assert.equal(row.body.contentType, 'application/json');
assert.equal(row.body.bodyLength, '816');
assert.equal(row.urlTruncated, false);
assert.equal(row.target, '/ab');
assert.equal(row.host, 'api.hcaptcha.test');
assert(model.isBrokerResponse({count: 3, events: [start, target, body], network_events: [start, target, body]}),
  'the backend network window may carry request children');

// A long target keeps its original length and is marked truncated.
const long = Object.assign(golden('truncated target'), {sequence_number: '13', parent_event_id: '11'});
[row] = model.requestsFromEvents([start, long, body], 'live');
assert(row.urlTruncated && row.targetLength > 116 && row.path.startsWith('https://api.hcaptcha.test/checksiteconfig?'));

// Metadata-only sessions stay host-only; a body summary is still shown.
const metadata = golden('metadata-only JSON body');
[row] = model.requestsFromEvents([start, metadata], 'live');
assert.equal(row.hostOnly, true);
assert.equal(row.path, 'api.hcaptcha.test');
assert.equal(row.body.state, 'metadata_only');
assert.equal(row.body.contentCapture, false);
assert.match(row.body.sha256, /^(ab){32}$/);

// Malformed and missing children are distinct, explicit states.
[row] = model.requestsFromEvents([start, golden('captured without content flag'), target], 'live');
assert.deepEqual(row.body, {malformed: true});
[row] = model.requestsFromEvents([start, Object.assign(golden('NUL inside prefix'), {sequence_number: '13', parent_event_id: '11'})], 'live');
assert.equal(row.targetMalformed, true);
assert.equal(row.hostOnly, true);
[row] = model.requestsFromEvents([start], 'live');
assert.equal(row.body, null);

// A scheme the record does not name is shown as host plus path, not a guessed URL.
[row] = model.requestsFromEvents([start, Object.assign(golden('short target'), {sequence_number: '13', parent_event_id: '11'})], 'live');
assert.equal(row.path, 'api.hcaptcha.test/ab');
assert.equal(row.targetKind, 'path');

// Children join only their exact parent, never another record of the request.
const stray = Object.assign(golden('short target'), {sequence_number: '14', parent_event_id: '5'});
[row] = model.requestsFromEvents([start, stray, body], 'live');
assert.equal(row.hostOnly, true);

// After a redirect the row shows the redirect's own target.
const redirect = Object.assign(structuredClone(start), {type: 'request_redirected', sequence_number: '20', status_code: 307,
  resource_type: 0, payload: hex('GET accounts.hcaptcha.test'), payload_size: 26});
const redirectTarget = https(Object.assign(golden('short target'), {sequence_number: '21', parent_event_id: '20'}));
[row] = model.requestsFromEvents([start, target, body, redirect, redirectTarget], 'live');
assert.equal(row.path, 'https://accounts.hcaptcha.test/ab');
assert.equal(row.body.state, 'captured', 'the body stays the start record child');

console.log(`PASS network request wire: ${cases.length} C++ golden records agree with Python and the UI decoders; ` +
  'rows join exact target/body children, truncated, metadata-only, malformed, missing and redirect cases');
