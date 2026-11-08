// The C++ core verdict on every debugger observation record
// (tests/debugger_observation_test.cpp --golden) must match the Python
// evidence validator. See protocol/native-debugger-observation-v1.md.
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
console.log(`PASS debugger observation wire: ${cases.length} C++ and Python verdicts agree`);
