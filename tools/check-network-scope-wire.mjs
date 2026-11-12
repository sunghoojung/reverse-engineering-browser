// The C++ core verdict on scheme classes and capture_exclusion records
// (tests/network_scope_test.cpp --golden) must match the Python evidence
// validator and the shipped readers. Then the shipped Traffic model finishes
// renderer-answered rows and the reversible browser-internal view counts them.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import {createRequire} from 'node:module';

const root = new URL('../', import.meta.url);
const exe = process.env.REB_NETWORK_SCOPE_TEST ?? new URL('build/tests/network-scope-test', root).pathname;
assert(fs.existsSync(exe), `missing ${exe}; build it with make build/tests/network-scope-test`);
const source = fs.readFileSync(new URL('apps/research-ui/evidence_models.js', root), 'utf8');
const model = new Function(`${source}\nreturn {requestsFromEvents, isBrokerEvent};`)();
const scope = createRequire(import.meta.url)('../apps/research-ui/network_scope.js');

const cases = JSON.parse(execFileSync(exe, ['--golden'], {encoding: 'utf8'}));
assert(cases.length > 25 && cases.some(item => item.valid) && cases.some(item => !item.valid));
const python = `import importlib.util,json,sys
s=importlib.util.spec_from_file_location('validator',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for event in json.load(sys.stdin):
  try: m.validate_event(event,1);print('true')
  except ValueError: print('false')`;
const verdicts = execFileSync('python3', ['-c', python, new URL('tools/validate-evidence-store.py', root).pathname],
  {input: JSON.stringify(cases.map(item => item.event)), encoding: 'utf8'}).trim().split('\n').map(value => value === 'true');
cases.forEach((item, index) => {
  assert.equal(verdicts[index], item.valid, `Python validator: ${item.name}`);
  if (item.event.type === 'capture_exclusion') {
    assert.equal(scope.decodeCaptureExclusion(item.event) !== null, item.valid, `UI decoder: ${item.name}`);
    if (item.event.flags === 0 && item.event.scheme_class === undefined) assert(model.isBrokerEvent(item.event), item.name);
  } else {
    assert.equal(model.isBrokerEvent(item.event), item.valid, `UI envelope: ${item.name}`);
  }
});

const golden = name => structuredClone(cases.find(item => item.name === name).event);
const hex = text => Buffer.from(text).toString('hex');
const renderer = (fields, payload) => Object.assign(golden('scheme on request_initiated'), {
  process_id: 31, frame_id: '77', request_id: '5', payload: hex(payload), payload_size: payload.length}, fields);
const target = (sequence, parent, text, scheme = 0) => {
  const bytes = Buffer.alloc(128);
  bytes.writeUInt16LE(1, 0); bytes.writeUInt16LE(128, 2); bytes.writeUInt32LE(text.length, 4); bytes[8] = scheme;
  bytes.write(text.slice(0, 116), 12, 'latin1');
  return renderer({type: 'request_target', sequence_number: String(sequence), parent_event_id: String(parent),
    scheme_class: undefined, payload: bytes.toString('hex'), payload_size: 128}, '');
};
const strip = event => {for (const key of Object.keys(event)) if (event[key] === undefined) delete event[key]; return event;};

// data: in a metadata session: the scheme stands in for the host, and the
// renderer's own completion finishes the row.
const dataStart = renderer({scheme_class: 5, sequence_number: '10'}, 'GET ');
const dataDone = renderer({type: 'request_completed', scheme_class: 5, sequence_number: '11', status_code: 200,
  decoded_body_length: '2', monotonic_time_ns: '2001'}, 'completed');
let [row] = model.requestsFromEvents([dataStart, dataDone], 'live');
assert.equal(row.path, 'data:');
assert(row.hostOnly && row.schemeOnly && row.method === 'GET' && row.status === 200 && row.time !== 'pending');
assert.equal(row.schemeClass, 5);
assert(model.isBrokerEvent(dataStart) && model.isBrokerEvent(dataDone));

// With request content the renderer's target child gives the path.
[row] = model.requestsFromEvents([dataStart, strip(target(12, 10, 'text/plain,hi')), dataDone], 'live');
assert.equal(row.path, 'data:text/plain,hi');
assert(!row.hostOnly && row.targetKind === 'url' && row.host === 'data:' && row.target === 'text/plain,hi');

// A service-worker answer: the browser proxy never saw this page request.
const swStart = renderer({sequence_number: '20', request_id: '6'}, 'GET example.test');
const swTarget = strip(Object.assign(target(21, 20, '/sw?q=1', 2), {request_id: '6'}));
const swDone = renderer({type: 'request_completed', sequence_number: '22', request_id: '6', status_code: 200, flags: 4,
  monotonic_time_ns: '2002'}, 'completed');
[row] = model.requestsFromEvents([swStart, swTarget, swDone], 'live');
assert.equal(row.path, 'https://example.test/sw?q=1');
assert(!row.hostOnly && row.status === 200 && row.browserObserved === false);
assert(!scope.isBrowserInternalRequest(row));

// A service worker that ended a request without a response: the renderer's
// failure with from_service_worker finishes the row, never Pending.
const swFailStart = renderer({sequence_number: '23', request_id: '16'}, 'GET example.test');
const swFailTarget = strip(Object.assign(target(24, 23, '/api?id=7', 2), {request_id: '16'}));
const swFailed = renderer({type: 'request_failed', sequence_number: '25', request_id: '16', error_code: -2, flags: 4,
  monotonic_time_ns: '2003'}, 'failed');
[row] = model.requestsFromEvents([swFailStart, swFailTarget, swFailed], 'live');
assert.equal(row.path, 'https://example.test/api?id=7');
assert(row.failed && row.status === 'failed' && row.time !== 'pending' && row.fromServiceWorker && row.errorCode === -2);
assert(model.isBrokerEvent(swFailed));

// Memory-cache reuses are complete rows of their own, with their target child.
const reuse = (name, fields) => Object.assign(golden(name), {process_id: 31, frame_id: '77'}, fields);
const cached = reuse('memory-cache image', {sequence_number: '50', request_id: '60'});
[row] = model.requestsFromEvents([cached], 'live');
assert(row.memoryCache && !row.staticData && row.hostOnly && row.path === 'cdn.example.test' && row.method === 'GET');
assert(row.status === 200 && row.time === '0.000 ms' && row.type === 'img' && row.resourceSize === 5120 &&
  row.transferSize === 0 && row.loaderObserved === false && row.initiator === 'renderer');
[row] = model.requestsFromEvents([cached, strip(Object.assign(target(51, 50, '/logo.png?v=2', 2), {request_id: '60'}))], 'live');
assert.equal(row.path, 'https://cdn.example.test/logo.png?v=2');
const decoded = reuse('memory-cache static data', {sequence_number: '52', request_id: '61'});
[row] = model.requestsFromEvents([decoded], 'live');
assert(row.memoryCache && row.staticData && row.schemeOnly && row.path === 'data:');
[row] = model.requestsFromEvents([decoded, strip(Object.assign(target(53, 52, 'image/png;base64,AAAA'), {request_id: '61'}))], 'live');
assert(row.path === 'data:image/png;base64,AAAA' && row.targetKind === 'url' && row.host === 'data:');
assert(!scope.isBrowserInternalRequest(row));

// Opted-in internal records name their scheme and are browser-internal.
const internal = renderer({scheme_class: 16, sequence_number: '30', request_id: '7'}, 'GET newtab');
[row] = model.requestsFromEvents([internal], 'live');
assert.equal(row.path, 'chrome://newtab');
assert(scope.isBrowserInternalRequest(row));
[row] = model.requestsFromEvents([internal, strip(Object.assign(target(31, 30, '/strings.js'), {request_id: '7'}))], 'live');
assert.equal(row.path, 'chrome://newtab/strings.js');

// Evidence from before scheme classes: a renderer-only bare label.
const legacy = renderer({scheme_class: undefined, sequence_number: '40', request_id: '8'}, 'GET resources');
const web = renderer({scheme_class: undefined, sequence_number: '41', request_id: '9'}, 'GET example.test');
const intranet = Object.assign(renderer({scheme_class: undefined, type: 'request_started', process_id: 2, sequence_number: '5',
  request_id: '44', browser_context_id_high: '3', browser_context_id_low: '4'}, 'GET router'));
const rows = model.requestsFromEvents([strip(legacy), strip(web), strip(intranet)], 'live');
assert.deepEqual(rows.map(scope.isBrowserInternalRequest), [true, false, false]);

// The view filter is reversible and always reports how many rows it covers.
let view = scope.browserInternalView(rows, scope.isBrowserInternalRequest, true);
assert.deepEqual([view.visible.length, view.hidden, view.internal], [2, 1, 1]);
view = scope.browserInternalView(rows, scope.isBrowserInternalRequest, false);
assert.deepEqual([view.visible.length, view.hidden, view.internal], [3, 0, 1]);
assert.equal(rows.length, 3, 'the filter never changes the rows it was given');
assert(scope.isBrowserInternalSourceUrl('chrome://newtab/strings.js'));
assert(!scope.isBrowserInternalSourceUrl('https://example.test/chrome://x') && !scope.isBrowserInternalSourceUrl('chrome-extension://id/a.js'));

// Cumulative counts: the newest per producer and class, summed.
const exclusion = (producer, cls, count, sequence) => {
  const event = golden(`exclusion class ${cls}`);
  const bytes = Buffer.from(event.payload, 'hex');
  bytes.writeBigUInt64LE(BigInt(count), 8);
  return Object.assign(event, {initiator_process_id: producer, payload: bytes.toString('hex'), sequence_number: String(sequence)});
};
const webui = golden('webui renderers');
const totals = scope.captureExclusionTotals([exclusion(1, 16, 3, 1), exclusion(1, 16, 5, 2), exclusion(2, 16, 2, 3),
  exclusion(2, 19, 1, 4), webui, golden('webui renderer with a producer')]);
assert.equal(totals.requests, 8n);
assert.equal(totals.renderers, 2n);
assert.deepEqual([...totals.byScheme], [['chrome', 7n], ['devtools', 1n]]);
assert.equal(scope.captureExclusionNotice(totals), '8 browser-internal requests not recorded · 2 WebUI renderers not admitted');
assert.equal(scope.captureExclusionNotice(scope.captureExclusionTotals([])), '');
// Requests a WebUI renderer sends through the proxy are browser-internal requests too.
const proxied = scope.captureExclusionTotals([webui, golden('webui requests at the proxy'), golden('webui requests with a producer')]);
assert.deepEqual([proxied.requests, proxied.renderers, [...proxied.byScheme]], [3n, 2n, [['webui', 3n]]]);
assert.equal(scope.captureExclusionNotice(proxied), '3 browser-internal requests not recorded · 2 WebUI renderers not admitted');
// Memory-cache reuses past a renderer's budget are their own count, never browser-internal.
const reuses = scope.captureExclusionTotals([golden('memory-cache reuses of a renderer'),
  golden('memory-cache reuses with no renderer')]);
assert.deepEqual([reuses.memoryCache, reuses.requests], [4097n, 0n]);
assert.equal(scope.captureExclusionNotice(reuses), '4097 memory-cache reuses not recorded');

console.log(`PASS network scope wire: ${cases.length} C++ golden records agree with Python and the UI readers; ` +
  'data:, service-worker, service-worker failure, memory-cache and opted-in internal rows finish with their own records; ' +
  'the browser-internal view and memory-cache exclusions are counted');
