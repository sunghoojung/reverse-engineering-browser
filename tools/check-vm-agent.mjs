#!/usr/bin/env node
// Authored loopback responses only; this does not claim native helper execution.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp, writeFile, readFile, rm, symlink, mkdir, stat} from 'node:fs/promises';
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
  const path = await good('observed-path', '--input', traceFile); assert.deepEqual(path.result, vm.observedPath(trace));assert.equal(path.source_sha256, inspected.source_sha256);
  const occurrenceArgs=(location='registers:1',page='0',size='16',file=traceFile)=>['occurrences','--input',file,'--location',location,'--page',page,'--page-size',size];
  for(const location of ['pc','halted','registers:0','registers:1','stack:0','memory:65535']) {
    const occurrences=await good(...occurrenceArgs(location));assert.deepEqual(occurrences.result,vm.occurrences(trace,location));
    assert.equal(occurrences.source_sha256,inspected.source_sha256);assert.equal(occurrences.result.reads,'unknown');
  }
  const pagedTrace={...trace,steps:[trace.steps[0],{...copy(trace.steps[0]),sequence:9}]},pagedFile=await input('paged.json',pagedTrace);
  const secondPage=await good(...occurrenceArgs('registers:1','1','1',pagedFile));assert.deepEqual(secondPage.result,vm.occurrences(pagedTrace,'registers:1',1,1));assert.equal(secondPage.result.items[0].sequence,9);
  assert.deepEqual((await good(...occurrenceArgs('registers:1','2','1',pagedFile))).result.items,[]);
  for(const location of ['registers:64','stack:128','memory:65536','registers:01','memory:-0','registers:1\n','__proto__'])await bad(occurrenceArgs(location));
  for(const value of ['-1','-0','+1','01','1.0','1e0','9007199254740992']){await bad(occurrenceArgs('pc',value));await bad(occurrenceArgs('pc','0',value));}
  for(const size of ['0','65'])await bad(occurrenceArgs('pc','0',size));
  await bad(occurrenceArgs('pc','9007199254740991','64'));
  for(const args of [['observed-path','--input',traceFile,'--base-url',base],occurrenceArgs().slice(0,-2),[...occurrenceArgs(),'--output','unused.json']])await bad(args,2,'usage');
  assert(capabilities().offline.commands.includes('observed-path'));assert(capabilities().offline.commands.includes('occurrences'));assert.equal(capabilities().writes_files,false);
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

  const definition = {format: 'reb-vm-definition-v1', definition_id: 'agent-static', architecture: 'stack',
    opcode_bytes: 1, operand_endianness: 'little', register_count: 0, opcodes: [
      {code: '01', mnemonic: 'PUSH', operands: [{name: 'value', width: 2, signed: true, kind: 'immediate'}],
        semantics: {operation: 'stack_const', args: ['value']}, flow: {kind: 'next'}},
      {code: 'ff', mnemonic: 'HALT', operands: [], semantics: {operation: 'halt', args: []}, flow: {kind: 'halt'}},
    ]};
  const bytecode = {format: 'reb-vm-bytecode-v1', image_id: 'agent-bytes', definition_id: 'agent-static',
    entry_offsets: [0], bytes_hex: '01feffff'};
  const definitionFile = await input('definition.json', definition), bytecodeFile = await input('bytecode.json', bytecode);
  const staticArgs = command => [command, '--definition', definitionFile, '--input', bytecodeFile];
  const definitionResult = await good('validate-definition', '--definition', definitionFile);
  assert.equal(definitionResult.format, 'reb-vm-agent-static-analysis-v1');
  assert.deepEqual(definitionResult.result, {valid: true, definition});
  assert.equal(definitionResult.definition_source_sha256, hash(await readFile(definitionFile)));
  assert.equal(definitionResult.source_sha256, null); assert.equal(definitionResult.executes_imported_code, false);
  const decoded = await good(...staticArgs('decode-bytecode'));
  assert.deepEqual(decoded.result.instructions.map(value => [value.offset, value.size, value.opcode, value.operands.map(item => item.value)]),
    [[0, 3, '01', [-2]], [3, 1, 'ff', []]]);
  assert.equal(decoded.source_sha256, hash(await readFile(bytecodeFile)));
  assert.equal(decoded.result.runtime_state, 'unknown'); assert.equal(decoded.result.equivalence_proven, false);
  assert.equal(Object.hasOwn(decoded.result, 'cfg'), false);
  assert(decoded.result.instructions.every(value => !Object.hasOwn(value, 'pseudocode')));
  const analyzed = await good(...staticArgs('analyze-static'));
  assert.equal(analyzed.result.format, 'reb-vm-static-analysis-v1');
  assert.equal(analyzed.result.provenance.definition_source_sha256, definitionResult.definition_source_sha256);
  assert.equal(analyzed.result.provenance.image_source_sha256, decoded.source_sha256);
  assert.equal(analyzed.result.provenance.image_bytes_sha256, hash(Buffer.from('01feffff', 'hex')));
  assert.equal(analyzed.result.cfg.complete, false); assert.equal(analyzed.executes_imported_code, false);
  const instruction = await good(...staticArgs('select-instruction'), '--pc', '3');
  assert.equal(instruction.result.instruction.id, 'insn:3'); assert.equal(instruction.result.instruction.offset, 3);
  assert.deepEqual(instruction.result.pseudocode.map(value => [value.instruction_id, value.offset]), [['insn:3', 3]]);
  assert.equal(instruction.result.runtime_state, 'unknown'); assert.equal(instruction.result.equivalence_proven, false);
  assert.deepEqual(instruction.result.outgoing_edges, []);
  assert.deepEqual(instruction.result.incoming_edges, [{from_offset: 0, to_offset: 3, kind: 'fallthrough', status: 'resolved', evidence: 'declared_static'}]);
  const prettyDefinition = await input('definition-pretty.json', JSON.stringify(definition, null, 2));
  const prettyImage = await input('bytecode-pretty.json', JSON.stringify(bytecode, null, 2));
  const pretty = await good('analyze-static', '--definition', prettyDefinition, '--input', prettyImage);
  assert.notEqual(pretty.definition_source_sha256, analyzed.definition_source_sha256);
  assert.notEqual(pretty.source_sha256, analyzed.source_sha256);
  assert.equal(pretty.result.provenance.definition_canonical_sha256, analyzed.result.provenance.definition_canonical_sha256);
  assert.equal(pretty.result.provenance.image_bytes_sha256, analyzed.result.provenance.image_bytes_sha256);
  const unknownFile = await input('unknown-bytecode.json', {...bytecode, bytes_hex: '01feff02ff'});
  const unknown = await good('analyze-static', '--definition', definitionFile, '--input', unknownFile);
  assert.equal(unknown.result.coverage.stop_reason, 'unknown_opcode');
  assert.equal(unknown.result.coverage.decoded_bytes, 3); assert.equal(unknown.result.coverage.undecoded_bytes, 2);
  await bad(['select-instruction', '--definition', definitionFile, '--input', unknownFile, '--pc', '4'], 2, 'selection_refused');
  for (const pc of ['1', '2', '4', '03', '-0', '-1', '+3', '3.0', '3e0', '9007199254740992']) {
    await bad([...staticArgs('select-instruction'), '--pc', pc], 2, 'selection_refused');
  }
  const wrongDefinition = await input('wrong-definition.json', {...bytecode, definition_id: 'other'});
  await bad(['analyze-static', '--definition', definitionFile, '--input', wrongDefinition], 2, 'analysis_refused');
  for (const args of [
    ['validate-definition', '--definition', definitionFile, '--input', bytecodeFile],
    [...staticArgs('analyze-static'), '--base-url', base], [...staticArgs('decode-bytecode'), '--timeout-ms', '1'],
    [...staticArgs('select-instruction')], ['analyze-static', '--input', bytecodeFile],
    ['execute-bytecode', '--definition', definitionFile, '--input', bytecodeFile],
  ]) await bad(args, 2, 'usage');
  for (const data of ['{}', '{"format":1,"format":2}', '\ufeff' + JSON.stringify(definition), Buffer.from([0xff]), ' '.repeat(1048577)]) {
    const malformed = await input('malformed-static.json', data);
    await bad(['validate-definition', '--definition', malformed], 2, 'input_refused');
    await bad(['analyze-static', '--definition', definitionFile, '--input', malformed], 2, 'input_refused');
  }
  for (const file of [link, dir, fifo, '/dev/null', join(directory, 'missing')]) {
    await bad(['validate-definition', '--definition', file], 2, 'input_refused');
    await bad(['analyze-static', '--definition', definitionFile, '--input', file], 2, 'input_refused');
  }
  const blockedNetwork = await input('network-blocker.cjs', `
    const deny = () => { throw Error('Offline command attempted network access'); };
    for (const name of ['node:http', 'node:https']) {
      const api = require(name); api.request = deny; api.get = deny;
    }
    require('node:net').Socket.prototype.connect = deny;
    require('node:tls').connect = deny;
    require('node:dns').lookup = deny;
    globalThis.fetch = deny;
    require('node:module').syncBuiltinESMExports();
  `);
  for (const args of [['capabilities'], ['observed-path','--input',traceFile], occurrenceArgs(), ['create-opcode-ledger','--definition',definitionFile], ['validate-definition', '--definition', definitionFile],
    staticArgs('decode-bytecode'), staticArgs('analyze-static'), [...staticArgs('select-instruction'), '--pc', '0']]) {
    const offline = spawnSync(process.execPath, ['--require', blockedNetwork, cli, ...args], {encoding: 'utf8', timeout: 10000});
    assert.equal(offline.status, 0, offline.stderr); assert.equal(offline.stderr, '');
    assert.equal(typeof JSON.parse(offline.stdout), 'object');
  }
  const occurrenceOutput=join(directory,'occurrences.json');
  const semantics=(...args)=>spawnSync(process.execPath,['--require',blockedNetwork,'tools/vm-semantics.mjs',...args],{encoding:'utf8',timeout:10000});
  const occurrenceFile=semantics('occurrences',pagedFile,'registers:1','1','1',occurrenceOutput);assert.equal(occurrenceFile.status,0,occurrenceFile.stderr);
  const occurrenceReport=JSON.parse(await readFile(occurrenceOutput,'utf8'));assert.deepEqual(occurrenceReport.result,secondPage.result);assert.equal(occurrenceReport.source_sha256,hash(await readFile(pagedFile)));assert.equal(occurrenceReport.hypotheses_sha256,null);
  assert.equal((await stat(occurrenceOutput)).mode&0o777,0o600);
  const preserved=await readFile(occurrenceOutput,'utf8');assert.equal(semantics('occurrences',pagedFile,'pc','0','1',occurrenceOutput).status,1);assert.equal(await readFile(occurrenceOutput,'utf8'),preserved);
  const outputLink=join(directory,'occurrences-link.json');await symlink(occurrenceOutput,outputLink);assert.equal(semantics('occurrences',pagedFile,'pc','0','1',outputLink).status,1);assert.equal(await readFile(occurrenceOutput,'utf8'),preserved);
  const refusedOutput=join(directory,'refused-occurrences.json');
  for(const args of [['occurrences',pagedFile,'pc','01','16',refusedOutput],['occurrences',pagedFile,'memory:65536','0','16',refusedOutput],['occurrences',pagedFile,'pc','0','65',refusedOutput],['occurrences',link,'pc','0','1',refusedOutput]])assert.equal(semantics(...args).status,1);
  await assert.rejects(stat(refusedOutput),{code:'ENOENT'});
  const denseDefinition = {...definition, opcodes: [{code: '00', mnemonic: 'UNSPECIFIED',
    operands: Array.from({length: 8}, (_, index) => ({name: `arg${index}`, width: 1, signed: false, kind: 'immediate'})),
    semantics: {operation: 'unknown', args: []}, flow: {kind: 'next'}}]};
  const denseDefinitionFile = await input('dense-definition.json', denseDefinition);
  const denseImageFile = await input('dense-bytecode.json', {...bytecode, bytes_hex: '00'.repeat(9 * 4096)});
  await bad(['analyze-static', '--definition', denseDefinitionFile, '--input', denseImageFile], 2, 'output_limit');
  const definitionBytes = JSON.stringify(definition);
  const paddedDefinition = await input('max-file-definition.json', definitionBytes + ' '.repeat(1048576 - Buffer.byteLength(definitionBytes)));
  const exactLimit = await good('validate-definition', '--definition', paddedDefinition);
  assert.equal(exactLimit.definition_source_sha256, hash(await readFile(paddedDefinition)));
  const registry = capabilities().imported_static;
  assert.deepEqual(registry.commands, ['validate-definition', 'decode-bytecode', 'analyze-static', 'select-instruction']);
  assert.equal(registry.live_capture_adapter.available, false); assert.equal(registry.executes_plugins, false);
  assert.equal(registry.network_requests, 0); assert.equal(registry.runtime_state, 'unknown');
  assert.equal(capabilities().owned.creation.available, false);
  assert.equal(await readFile(definitionFile, 'utf8'), JSON.stringify(definition));
  assert.equal(await readFile(bytecodeFile, 'utf8'), JSON.stringify(bytecode));
  assert.equal(calls.length, 0, 'All static import commands must remain offline and preserve source files');

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
console.log('PASS VM agent facade: offline capabilities/observations/declarative static analysis, exact provenance/u64 scope, explicit controls, authored loopback transport, bounded strict responses, pending/rejected/unknown outcomes and no retries. No native execution or rendered acceptance claimed.');
