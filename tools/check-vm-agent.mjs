#!/usr/bin/env node
// Authored loopback responses only; this does not claim native helper execution.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp, writeFile, readFile, rm, symlink, mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import vm from '../apps/research-ui/vm_semantics.js';
import {capabilities} from './vm-agent.mjs';

const copy = value => JSON.parse(JSON.stringify(value));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const snapshot = () => ({pc: '0', pc_evidence: 'observed', partial: false, halted: false,
  registers: [{bits: '18446744073709551615', evidence: 'observed'}, {bits: '0', evidence: 'unknown'}], stack: [], memory: []});
const session = () => ({backend_instance_id: 'instance', session_id: 'session', run_id: 'run', run_generation: '9007199254740993',
  provider: 'live-owned-native-fixture', target_kind: 'owned_fixture', fixture: 'register', program_id: 'owned-register-v1',
  fixture_revision: 1, program_sha256: 'a'.repeat(64), program_manifest_scope: 'declared-two-program-manifest-sha256',
  build_id: 'b'.repeat(64), build_id_scope: 'configured-helper-file-sha256', pc_units: 'instruction-index',
  value_semantics: 'unsigned-64-bit-bits', tick_units: 'monotonic-nanoseconds', state: 'paused',
  control_revision: '9007199254740994', snapshot_revision: '1', executed_count: '0', retained_count: '0',
  execution_state_known: true, termination_reason: null, initial_snapshot: snapshot(), current_snapshot: snapshot(), records: [],
  recorder: {session_id: '1', document_id: '2', invocation_id: '3', generation: '1',
    stats: {attempted: '0', recorded: '0', full: '0', malformed: '0', wrong_document: '0', stale_generation: '0', exhausted: '0', expired: '0', partial: '0'}},
  last_command: null, diagnostics: {stderr_bytes: '0', stderr_truncated: false}, disposal_failed: false});
const view = () => ({schema: 'reb-owned-vm-debug-session-v1', available: true, unavailable_reason: null, backend_instance_id: 'instance', session: session()});
const offlineState = pc => ({pc, halted: false, registers: [null, 7], stack: [], memory: []});
const trace = {format: 'reb-vm-trace-v1', identity: {trace_id: 'owned-agent', investigation_id: 'i', finding_id: 'f', artifact_id: 'a',
  artifact_sha256: 'c'.repeat(64), scope_id: 'owned-synthetic', backend: 'fixture'}, architecture: 'register',
  coverage: {complete: false, dropped_steps: 2, limitations: ['Authored synthetic observations only']},
  steps: [{sequence: 7, opcode: '01', operands: [1, 7], instruction_size: 1, before: offlineState(0), after: offlineState(1), evidence_refs: ['authored:7']}]};
const cli = resolve('tools/vm-agent.mjs'), directory = await mkdtemp(join(tmpdir(), 'reb-vm-agent-check-'));
const calls = [], sockets = new Set(); let handler;
const server = createServer(async (request, response) => {
  let body = ''; for await (const chunk of request) body += chunk;
  const call = {method: request.method, path: request.url, headers: request.headers, body}; calls.push(call);
  response.setHeader('Content-Type', 'application/json'); handler(call, response);
});
server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const run = (...args) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [cli, ...args], {env: {...process.env, HTTP_PROXY: 'http://192.0.2.1:1', HTTPS_PROXY: 'http://192.0.2.1:1', ALL_PROXY: 'http://192.0.2.1:1'}, stdio: ['ignore', 'pipe', 'pipe']});
  let stdout = '', stderr = ''; const timer = setTimeout(() => { child.kill(); reject(Error('CLI did not finish within the test deadline')); }, 15000);
  child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
  child.on('error', reject); child.on('close', code => { clearTimeout(timer); resolve({code, stdout, stderr}); });
});
let serial = 0;
const input = async (label, value) => { const path = join(directory, `${serial++}-${label}`); await writeFile(path, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)); return path; };
const good = async (...args) => { const result = await run(...args); assert.equal(result.code, 0, result.stderr); assert.equal(result.stderr, ''); return JSON.parse(result.stdout); };
const bad = async (args, code = 2, reason) => { const result = await run(...args); assert.equal(result.code, code, result.stderr); assert.equal(result.stdout, ''); const failure = JSON.parse(result.stderr); assert.equal(failure.format, 'reb-vm-agent-error-v1'); assert.equal(failure.retry_allowed, false); if (reason) assert.equal(failure.code, reason); return failure; };
const reply = value => { handler = (_, response) => response.end(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)); };
const stateFile = await input('state.json', view()), traceFile = await input('trace.json', trace);
const statusArgs = ['status', '--base-url', base], traceArgs = ['trace', '--base-url', base, '--state', stateFile];
const actionArgs = (action = 'step', file = stateFile, id = 'authored-command') => ['action', action, '--base-url', base, '--state', file, '--command-id', id];
function actionReply(action, ack = 'completed') {
  const result = view(); result.command_id = 'authored-command'; result.ack = ack;
  result.session.control_revision = '9007199254740995';
  if (action === 'step') { result.session.executed_count = '1'; result.session.snapshot_revision = '2'; }
  if (action === 'run') result.session.state = 'running';
  if (action === 'stop') result.session.state = 'stopped';
  if (action === 'close') result.session = null;
  if (action === 'reset') { result.session.run_id = 'new-run'; result.session.run_generation = '9007199254740994'; result.session.build_id = 'd'.repeat(64); }
  return result;
}
try {
  assert.match((await run('--help')).stdout, /select-step never executes code/);
  assert.deepEqual(await good('capabilities'), capabilities()); assert.equal(calls.length, 0);
  assert.equal(capabilities().owned.creation.available, false);
  for (const args of [[], ['create'], ['action', 'create'], ['action', 'execute'], ['capabilities', '--base-url', base], ['inspect', '--input', traceFile, '--input', traceFile], ['status'], ['status', '--base-url', base, '--timeout-ms', '0'], ['status', '--base-url', base, '--timeout-ms', '10001'], ['status', '--base-url', base, '--timeout-ms', '1e2']]) await bad(args);
  for (const url of ['http://localhost:80', 'https://127.0.0.1:80', 'http://127.0.0.2:80', 'http://2130706433:80', 'http://127.1:80', 'http://0x7f000001:80', 'http://[::ffff:127.0.0.1]:80', 'http://127.0.0.1', 'http://127.0.0.1:00080', 'http://127.0.0.1:65536', 'http://127.0.0.1:0', base + '/other', base + '?x=1', base + '#x', base.replace('http://', 'http://user@'), ' ' + base, base + '\n']) await bad(['status', '--base-url', url], 2, 'endpoint_refused');
  assert.equal(calls.length, 0, 'Invalid commands/endpoints must not connect');

  const inspected = await good('inspect', '--input', traceFile); assert.deepEqual(inspected.result, vm.inspect(trace)); assert.equal(inspected.source_sha256, hash(await readFile(traceFile))); assert.notEqual(inspected.source_sha256, trace.identity.artifact_sha256);
  const selected = await good('select-step', '--input', traceFile, '--sequence', '7'); assert.deepEqual(selected.result.step, trace.steps[0]); assert.deepEqual(selected.result.coverage, trace.coverage); assert.equal(selected.result.executes_code, false); assert.equal(selected.result.reads, 'unknown');
  const hypotheses = {format: 'reb-vm-hypothesis-v1', trace_id: trace.identity.trace_id, mappings: []}, hypothesesFile = await input('hypotheses.json', hypotheses);
  const validated = await good('validate', '--input', traceFile, '--hypotheses', hypothesesFile); assert.deepEqual(validated.result, vm.validate(trace, hypotheses)); assert.equal(validated.hypotheses_sha256, hash(await readFile(hypothesesFile)));
  const spaced = await input('spaced.json', JSON.stringify(trace, null, 2));
  const compared = await good('compare', '--input', traceFile, '--sequence', '7', '--right', spaced, '--right-sequence', '7'); assert.deepEqual(compared.result, vm.compareSteps(trace, 7, trace, 7)); assert.notEqual(compared.source_sha256, compared.right_source_sha256); assert.equal(compared.result.equivalence_proven, false);
  for (const sequence of ['6', '0', '07', '-1', '-0', '+7', '7.0', '7e0', '9007199254740992']) await bad(['select-step', '--input', traceFile, '--sequence', sequence]);
  for (const data of ['{}', '{"format":1,"format":2}', '\ufeff' + JSON.stringify(trace), Buffer.concat([Buffer.from(JSON.stringify(trace)), Buffer.from([0xff])]), ' '.repeat(1048577)]) {
    const file = await input('bad.json', data); await bad(['inspect', '--input', file], 2, 'input_refused'); await bad(actionArgs('step', file), 2, 'input_refused');
  }
  const link = join(directory, 'link'); await symlink(traceFile, link);
  const dir = join(directory, 'directory'); await mkdir(dir);
  const fifo = join(directory, 'fifo'); assert.equal(spawnSync('mkfifo', [fifo]).status, 0);
  for (const file of [link, dir, fifo, '/dev/null', join(directory, 'missing')]) await bad(['inspect', '--input', file], 2, 'input_refused');
  assert.equal(calls.length, 0, 'Offline commands and invalid state must remain offline');

  reply(view()); assert.deepEqual(await good(...statusArgs), view()); assert.deepEqual(calls.at(-1), {method: 'GET', path: '/api/vm-debugger', headers: {accept: 'application/json', origin: base, host: base.slice(7), connection: 'close'}, body: ''});
  assert.deepEqual(await good(...traceArgs), view()); const query = new URL(calls.at(-1).path, base); assert.equal(query.pathname, '/api/vm-debugger/trace'); assert.deepEqual(Object.fromEntries(query.searchParams), {backend_instance_id: 'instance', session_id: 'session', run_id: 'run', run_generation: '9007199254740993'});
  const unavailable = {...view(), available: false, unavailable_reason: 'Authored unavailable fixture', session: null}; reply(unavailable); assert.deepEqual(await good(...statusArgs), unavailable);
  for (const mutate of [v => v.session.run_id = 'different', v => v.session.program_sha256 = 'e'.repeat(64), v => v.session.build_id = 'e'.repeat(64), v => v.session.control_revision = '1', v => v.session.snapshot_revision = '0']) { const wrong = view(); mutate(wrong); reply(wrong); await bad(traceArgs, 2, 'scope_mismatch'); }
  handler = (_, response) => { response.statusCode = 409; response.end(JSON.stringify({error: 'Authored stale scope', code: 'stale_generation', details: {}})); };
  const count = calls.length; await bad(traceArgs, 2, 'server_refusal'); assert.equal(calls.length, count + 1, 'Stale selection must not request latest state');
  for (const action of ['run', 'pause', 'step', 'stop', 'reset', 'close']) {
    const returned = actionReply(action); reply(returned); assert.deepEqual(await good(...actionArgs(action)), returned);
    const sent = JSON.parse(calls.at(-1).body); assert.equal(calls.at(-1).method, 'POST'); assert.equal(calls.at(-1).path, '/api/vm-debugger/actions');
    assert.deepEqual(sent, {action, command_id: 'authored-command', backend_instance_id: 'instance', session_id: 'session', run_id: 'run', run_generation: '9007199254740993',
      ...(['run', 'step'].includes(action) ? {expected_control_revision: '9007199254740994'} : {}), ...(action === 'step' ? {expected_executed_count: '0'} : {})});
    assert.equal(calls.at(-1).headers['content-length'], String(Buffer.byteLength(calls.at(-1).body)));
  }
  // Real backend finish_exchange may confirm an instruction/initial handshake
  // at the expiry boundary. Preserve that terminal evidence, not false uncertainty.
  for (const action of ['step', 'reset', 'pause']) {
    const expired = actionReply(action); expired.session.state = 'expired'; expired.session.termination_reason = 'expired';
    reply(expired); assert.deepEqual(await good(...actionArgs(action)), expired);
    if (action !== 'pause') {
      const wrongCount = copy(expired); wrongCount.session.executed_count = action === 'step' ? '2' : '1';
      reply(wrongCount); await bad(actionArgs(action), 3, 'command_outcome_unknown');
      const wrongScope = copy(expired); wrongScope.session.session_id = 'another-session';
      reply(wrongScope); await bad(actionArgs(action), 3, 'command_outcome_unknown');
    }
  }
  const runExpired = actionReply('run'); runExpired.session.state = 'expired'; reply(runExpired);
  await bad(actionArgs('run'), 3, 'command_outcome_unknown');
  for (const mutate of [v => v.available = false, v => v.session.state = 'running', v => v.session.execution_state_known = false,
    v => v.session.disposal_failed = true, v => v.session.last_command = {command_id: 'previous', action: 'step', ack: 'pending'}]) {
    const value = view(); mutate(value); const file = await input('unconfirmed.json', value), count = calls.length; await bad(actionArgs('step', file), 2, 'state_refused'); assert.equal(calls.length, count);
  }
  const prior = view(); prior.session.last_command = {command_id: 'authored-command', action: 'step', ack: 'completed'};
  await bad(actionArgs('step', await input('already-used.json', prior)), 2, 'command_refused');
  for (const id of ['!', 'x'.repeat(65), 'with space']) await bad(actionArgs('step', stateFile, id), 2, 'command_refused');
  await bad(actionArgs('step', traceFile), 2, 'input_refused');

  for (const [ack, code, reason] of [['pending', 4, 'command_pending'], ['outcome_unknown', 3, 'command_outcome_unknown'], ['rejected', 2, 'command_rejected']]) {
    const value = actionReply('step', ack); reply(value); const count = calls.length, failure = await bad(actionArgs(), code, reason); assert.deepEqual(failure.response, value); assert.equal(failure.command.run_generation, '9007199254740993'); assert.equal(calls.length, count + 1);
  }
  for (const mutate of [v => v.command_id = 'other', v => v.backend_instance_id = 'other', v => v.session.run_id = 'other', v => v.session.build_id = 'e'.repeat(64), v => v.session.control_revision = '1', v => v.session.executed_count = '2', v => v.session.execution_state_known = false]) {
    const value = actionReply('step'); mutate(value); reply(value); const count = calls.length; await bad(actionArgs(), 3, 'command_outcome_unknown'); assert.equal(calls.length, count + 1);
  }
  const unchangedReset = actionReply('reset'); unchangedReset.session.run_generation = '9007199254740993'; reply(unchangedReset); await bad(actionArgs('reset'), 3, 'command_outcome_unknown');
  for (const [serverCode, code] of [['stale_generation', 2], ['state_conflict', 2], ['command_outcome_unknown', 3], ['unspecified', 3]]) {
    handler = (_, response) => { response.statusCode = 409; response.end(JSON.stringify({error: 'Authored rejection', code: serverCode, details: {}})); };
    const count = calls.length; await bad(actionArgs(), code); assert.equal(calls.length, count + 1);
  }
  const malformed = ['{}', '{"schema":1,"schema":2}', JSON.stringify(view()).replace('"run_generation":"9007199254740993"', '"run_generation":9007199254740993'), JSON.stringify({...view(), extra: true}), JSON.stringify(view()).replace('"fixture_revision":1', '"fixture_revision":1.0'), Buffer.from([0xff]), '\ufeff' + JSON.stringify(view()), JSON.stringify({...view(), session: {...session(), program_sha256: 'bad'}})];
  for (const value of malformed) { reply(value); await bad(statusArgs, 2, 'invalid_response'); await bad(actionArgs(), 3, 'command_outcome_unknown'); }
  for (const setup of [
    (_, response) => { response.statusCode = 302; response.setHeader('Location', base + '/must-not-follow'); response.end('{}'); },
    (_, response) => { response.setHeader('Content-Type', 'text/plain'); response.end('{}'); },
    (_, response) => { response.setHeader('Content-Type', ['application/json', 'application/json']); response.end('{}'); },
    (_, response) => { response.setHeader('Content-Encoding', 'gzip'); response.end('{}'); },
    (_, response) => { response.setHeader('Content-Length', '1048577'); response.end('{}'); },
    (_, response) => { response.write(' '.repeat(1048576)); response.end(' '); },
    (_, response) => { response.setHeader('Content-Length', '1000'); response.write('{}'); response.destroy(); },
    (_, response) => { response.socket.destroy(); },
  ]) {
    handler = setup; const count = calls.length; await bad(actionArgs(), 3, 'command_outcome_unknown'); assert.equal(calls.length, count + 1, 'Invalid action response must never retry or redirect');
  }
  handler = (_, response) => { response.write('{'); }; const beforeTimeout = calls.length;
  await bad([...actionArgs(), '--timeout-ms', '50'], 3, 'command_outcome_unknown'); assert.equal(calls.length, beforeTimeout + 1);
  await bad([...statusArgs, '--timeout-ms', '50'], 2, 'timeout');
  const bytes = JSON.stringify(view()); reply(bytes + ' '.repeat(1048576 - Buffer.byteLength(bytes))); assert.deepEqual(await good(...statusArgs), view());
  assert.equal(calls.some(call => call.path.includes('must-not-follow')), false);
  assert((await readFile(stateFile, 'utf8')) === JSON.stringify(view()), 'Saved state must remain unchanged');
} finally {
  for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); await rm(directory, {recursive: true, force: true});
}
console.log('PASS VM agent facade: offline capabilities/analysis, exact provenance/u64 scope, explicit controls, authored loopback transport, bounded strict responses, pending/rejected/unknown outcomes and no retries. No native execution or rendered acceptance claimed.');
