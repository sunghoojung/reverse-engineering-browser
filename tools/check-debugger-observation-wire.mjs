// The C++ core verdict on every debugger observation record
// (tests/debugger_observation_test.cpp --golden) must match the Python
// evidence validator, and the shipped UI poll validator must accept every
// record the backend windows can carry, or one match fails each later poll.
// See protocol/native-debugger-observation-v1.md.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const exe = process.env.REB_DEBUGGER_OBSERVATION_TEST ??
  new URL('build/tests/debugger-observation-test', root).pathname;
assert(fs.existsSync(exe), `missing ${exe}; build it with make build/tests/debugger-observation-test`);
const cases = JSON.parse(execFileSync(exe, ['--golden'], {encoding: 'utf8'}));
assert(cases.length > 10 && cases.some(item => item.valid) && cases.some(item => !item.valid));

const python = `import importlib.util,json,sys
s=importlib.util.spec_from_file_location('validator',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for event in json.load(sys.stdin):
  try: m.validate_event(event,1);print('true')
  except ValueError: print('false')`;
const verdicts = execFileSync('python3',
  ['-c', python, new URL('tools/validate-evidence-store.py', root).pathname],
  {input: JSON.stringify(cases.map(item => item.event)), encoding: 'utf8'})
  .trim().split('\n').map(value => value === 'true');

cases.forEach((item, index) => {
  assert.equal(verdicts[index], item.valid, `Python validator disagrees on: ${item.name}`);
});

const source = fs.readFileSync(new URL('apps/research-ui/evidence_models.js', root), 'utf8');
const model = new Function(`${source}
return {isBrokerEvent, isBrokerResponse, requestsFromEvents};`)();
const types = new Set();
for (const {name, valid, event} of cases) {
  if (!valid) continue;
  types.add(event.type);
  assert(model.isBrokerEvent(event), `UI poll validator refused: ${name}`);
  assert(model.isBrokerResponse({count: 1, events: [event]}), `UI poll response refused: ${name}`);
  if (event.category === 'network') {
    assert(model.isBrokerResponse({count: 1, events: [event], network_events: [event]}), `UI network window refused: ${name}`);
    assert.deepEqual(model.requestsFromEvents([event], 'live'), [], `A watch match is not a request row: ${name}`);
  }
}
assert.deepEqual([...types].sort(), ['csp_violation', 'debugger_attached', 'debugger_breakpoint',
  'debugger_paused', 'debugger_resumed', 'dom_mutation', 'exception_observation', 'listener_dispatch',
  'request_watch_match', 'timer_observation']);
console.log(`PASS debugger observation wire: ${cases.length} C++ and Python verdicts agree; the UI poll accepts all ${types.size} record types`);
