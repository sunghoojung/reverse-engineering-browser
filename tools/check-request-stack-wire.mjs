// The C++ core verdict on every request_initiator_stack and script_identity
// record (tests/request_stack_test.cpp --golden) must match the Python
// evidence validator and the shipped Initiator decoder. Then the shipped
// Initiator panel renders a resolved stack, as text, from get_request_stack.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {runInNewContext} from 'node:vm';

const root = new URL('../', import.meta.url);
const exe = process.env.REB_REQUEST_STACK_TEST ?? new URL('build/tests/request-stack-test', root).pathname;
assert(fs.existsSync(exe), `missing ${exe}; build it with make build/tests/request-stack-test`);
const cases = JSON.parse(execFileSync(exe, ['--golden'], {encoding: 'utf8'}));
assert(cases.length > 30 && cases.some(item => item.valid) && cases.some(item => !item.valid));
const python = `import importlib.util,json,sys
s=importlib.util.spec_from_file_location('validator',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for event in json.load(sys.stdin):
  try: m.validate_event(event,1);print('true')
  except ValueError: print('false')`;
const verdicts = execFileSync('python3', ['-c', python, new URL('tools/validate-evidence-store.py', root).pathname],
  {input: JSON.stringify(cases.map(item => item.event)), encoding: 'utf8'}).trim().split('\n').map(value => value === 'true');

const {parseHTML} = createRequire(new URL('ui-startup-deps/', import.meta.url))('linkedom');
const {window, document} = parseHTML('<!doctype html><html><body><div id="tree"></div></body></html>');
const context = {document, window, URL, URLSearchParams, DataView, Uint8Array, BigInt, Number, String, Object, Error,
  location: {protocol: 'http:'}};
runInNewContext(`${fs.readFileSync(new URL('apps/research-ui/request_stack.js', root), 'utf8')}
globalThis.api = {decodeRequestStackRecord, createRequestStackPanel};`, context);
const {decodeRequestStackRecord, createRequestStackPanel} = context.api;

cases.forEach((item, index) => {
  assert.equal(verdicts[index], item.valid, `Python validator: ${item.name}`);
  if (item.event.type === 'request_initiator_stack') {
    assert.equal(decodeRequestStackRecord(item.event) !== null, item.valid, `Initiator decoder: ${item.name}`);
  }
});
console.log(`PASS request stack wire: ${cases.length} C++, Python and Initiator verdicts agree`);

const stackEvent = structuredClone(cases.find(item => item.name === 'stack record').event);
const initiated = {...stackEvent, type: 'request_initiated', sequence_number: stackEvent.parent_event_id,
  parent_event_id: '0', payload: '', payload_size: 0};
const request = {events: [initiated], details: [stackEvent]};
const frames = [
  {index: 0, kind: 'javascript', async: false, script_id: 7, position: 40, eval: false,
    resolution: {status: 'resolved', artifact_id: '31', url: 'https://app.example.test/page?x=1', line: 13, column: 10,
      artifact_line: 3, artifact_column: 10, function_name: '<img src=x onerror=alert(1)>'}},
  {index: 1, kind: 'wasm', async: false, script_id: 30, function_index: 3, module_offset: 673,
    resolution: {status: 'resolved', artifact_id: '32', url: 'https://app.example.test/m.wasm', function_name: 'encrypt'}},
  {index: 2, kind: 'javascript', async: false, script_id: 40, position: 5,
    resolution: {status: 'unresolved', reason: 'source_not_retained'}},
  {index: 3, kind: 'await', async: true, script_id: 7, position: 60, eval: false,
    resolution: {status: 'resolved', artifact_id: '31', url: 'https://app.example.test/page', line: 20, column: 3,
      artifact_line: 10, artifact_column: 3, function_name: null}}
];
let pending = null;
let opened = null;
let refreshed = 0;
const panel = createRequestStackPanel({
  load: parameters => {
    assert.equal(parameters.request_id, stackEvent.request_id);
    pending = Promise.resolve({status: 'recorded', request: {sequence_number: stackEvent.sequence_number},
      frames_retained: true, frames, omitted: 3976, omitted_after_index: 2,
      async_callers_not_shown: ['timers', 'event listeners', 'promise.then callbacks', 'message handlers']});
    return pending;
  },
  refresh: () => { refreshed += 1; },
  open: frame => { opened = frame; }
});
const tree = document.getElementById('tree');
const chain = document.createElement('div');
chain.textContent = 'Renderer request 3';
panel.render(tree, request, [chain]);
assert.match(tree.textContent, /Request call stack.*Resolving frames.*Request initiator chain.*Renderer request 3/s);
await pending;
await new Promise(resolve => setTimeout(resolve, 0));
assert.equal(refreshed, 1);
panel.render(tree, request, [chain]);
const lines = [...tree.querySelectorAll('li')].map(item => item.textContent);
assert.deepEqual(lines, [
  '<img src=x onerror=alert(1)> @ page:13:10',
  'encrypt @ m.wasm:0x2a1',
  '(script 40) @ offset 5 · source not retained',
  '3,976 frames omitted',
  'await',
  '(anonymous) @ page:20:3'
]);
assert.equal(tree.querySelectorAll('img').length, 0, 'captured names are text, never markup');
assert.match(tree.textContent, /Async callers not shown: timers, event listeners, promise.then callbacks, message handlers/);
tree.querySelector('.request-stack-open').dispatchEvent(new window.Event('click'));
assert.equal(opened.resolution.artifact_line, 3);

const parser = structuredClone(stackEvent);
parser.payload = `0100800002080000${'00'.repeat(120)}`;
panel.render(tree, {events: [initiated], details: [parser]}, [chain]);
assert.match(tree.textContent, /Request call stack\s*Parser/);
panel.render(tree, {events: [initiated], details: []}, [chain]);
assert.match(tree.textContent, /No request call stack record/);
console.log('PASS Initiator panel: frames as text, Wasm, unresolved reason, omitted marker, await separator, Parser and no record');
