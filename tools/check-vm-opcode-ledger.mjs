#!/usr/bin/env node
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp, writeFile, readFile, symlink, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {inspectLedger} from './vm-opcode-ledger.mjs';

const definition = JSON.stringify({format: 'reb-vm-definition-v1', definition_id: 'synthetic', architecture: 'stack', opcode_bytes: 1,
  operand_endianness: 'little', register_count: 0, opcodes: ['00', '01', 'ff'].map(code => ({code, mnemonic: 'UNKNOWN', operands: [], semantics: {operation: 'unknown', args: []}, flow: {kind: 'unknown'}}))});
const sha = text => createHash('sha256').update(text).digest('hex');
const ref = {artifact_id: 'synthetic-handler', event_id: 'event-7'};
const entry = {opcode: '00', status: 'observed', meaning: '<script>inert evidence</script>', handler_location: {artifact_id: 'synthetic-handler', byte_offset: 12},
  operand_format: null, source_refs: [ref], test_status: 'passed', test_refs: [ref], unresolved_questions: ['Does overflow wrap?']};
const ledger = {format: 'reb-vm-opcode-ledger-v1', definition_id: 'synthetic', definition_source_sha256: sha(definition), entries: [entry,
  {...entry, opcode: '01', status: 'inferred', test_status: 'not_run', test_refs: []}]};
const inspect = v => inspectLedger(JSON.stringify(v), definition);
const result = inspect(ledger);
assert.deepEqual(result.coverage.counts, {observed: 1, inferred: 1, unmodeled: 1, missing_entries: 1});
assert.equal(result.coverage.opcodes[0].declared_operation, 'unknown');
assert.equal(result.coverage.opcodes[2].meaning, null);
assert.equal(result.tests_executed, false);
assert.equal(result.references_verified, false);
assert.deepEqual(inspect(result.ledger).ledger, ledger);
const bad = mutate => { const v = structuredClone(ledger); mutate(v); assert.throws(() => inspect(v)); };
bad(v => v.entries.push(v.entries[0]));
bad(v => v.entries[0].opcode = 'ab');
bad(v => v.definition_source_sha256 = '0'.repeat(64));
bad(v => v.entries[0].handler_location.byte_offset = true);
bad(v => v.entries[0].handler_location.byte_offset = -1);
bad(v => v.entries[0].handler_location.byte_offset = 2 ** 53);
bad(v => v.entries[0].status = 'proven');
bad(v => v.entries[0].status = 'unmodeled');
bad(v => v.entries[0].meaning = null);
bad(v => v.entries[0].meaning = 'x'.repeat(1025));
bad(v => v.entries[0].meaning = '\ud800');
bad(v => v.entries[0].meaning = '\u001b[31m');
bad(v => v.entries[0].meaning = '\u202eunsafe');
bad(v => v.entries[0].source_refs = []);
bad(v => v.entries[0].source_refs[0].artifact_id = 'bad/id');
bad(v => v.entries[0].source_refs[0].event_id = true);
bad(v => v.entries[0].source_refs[0].extra = 'ignored?');
bad(v => v.definition_id = 'wrong');
bad(v => v.entries = Array(257).fill(entry));
bad(v => v.entries[0].source_refs.push(ref));
bad(v => v.entries[0].source_refs = Array(17).fill(ref));
bad(v => v.entries[0].test_refs = []);
bad(v => v.entries[0].test_status = 'not_run');
bad(v => v.entries[0].unresolved_questions = Array(17).fill('why'));
bad(v => v.entries[0].extra = 'ignored?');
const unknown = structuredClone(ledger); Object.assign(unknown.entries[0], {status: 'unmodeled', meaning: null, source_refs: [], test_status: 'not_run', test_refs: []});
assert.equal(inspect(unknown).coverage.counts.unmodeled, 2);
const failed = structuredClone(ledger); failed.entries[0].test_status = 'failed';
assert.equal(inspect(failed).coverage.opcodes[0].status, 'observed');
assert.equal(inspect(failed).coverage.opcodes[0].test_status, 'failed');
const boundary = structuredClone(ledger); boundary.entries[0].meaning = '🙂'.repeat(1024);
boundary.entries[0].handler_location.byte_offset = Number.MAX_SAFE_INTEGER;
boundary.entries[0].source_refs = Array.from({length: 16}, (_, i) => ({artifact_id: `synthetic-${i}`, event_id: null}));
assert.equal(inspect(boundary).ledger.entries[0].source_refs.length, 16);
assert.throws(() => inspectLedger(JSON.stringify(ledger).replace('"byte_offset":12', '"byte_offset":1.2e1'), definition));
assert.throws(() => inspectLedger(JSON.stringify(ledger).replace('"byte_offset":12', '"byte_offset":12,"byte_offset":12'), definition));
assert.throws(() => inspectLedger(' '.repeat(1048577), definition));
assert.throws(() => inspectLedger(JSON.stringify(ledger), definition + ' '));
const empty = {...ledger, entries: []};
assert.deepEqual(inspect(empty).coverage.counts, {observed: 0, inferred: 0, unmodeled: 3, missing_entries: 3});
const dir = await mkdtemp(join(tmpdir(), 'reb-ledger-'));
try {
  const def = join(dir, 'definition.json'), input = join(dir, 'ledger.json');
  await writeFile(def, definition); await writeFile(input, JSON.stringify(ledger));
  // Reject any accidental network call through either Node HTTP or global fetch.
  const guard = join(dir, 'no-network.cjs');
  await writeFile(guard, "for (const p of ['node:http','node:https','node:net','node:tls']) { const m = require(p); for (const k of ['request','get','connect','createConnection']) if (m[k]) m[k] = () => { throw Error('network forbidden'); }; } global.fetch = () => { throw Error('network forbidden'); }; require('node:module').syncBuiltinESMExports();");
  const run = args => spawnSync(process.execPath, ['--require', guard, 'tools/vm-agent.mjs', ...args], {encoding: 'utf8'});
  const args = ['opcode-ledger', '--definition', def, '--input', input];
  const out = run(args); assert.equal(out.status, 0, out.stderr);
  assert.deepEqual(JSON.parse(out.stdout), result);
  const exported = JSON.parse(out.stdout).ledger; await writeFile(join(dir, 'export.json'), JSON.stringify(exported));
  assert.equal(run([...args.slice(0, -1), join(dir, 'export.json')]).status, 0);
  assert.equal(run([...args, '--base-url', 'http://127.0.0.1:1']).status, 2);
  await symlink(input, join(dir, 'link')); assert.equal(run([...args.slice(0, -1), join(dir, 'link')]).status, 2);
  await writeFile(join(dir, 'big'), ' '.repeat(1048577)); assert.equal(run([...args.slice(0, -1), join(dir, 'big')]).status, 2);
  assert.equal(await readFile(input, 'utf8'), JSON.stringify(ledger));
  assert.equal(JSON.parse(run(['capabilities']).stdout).opcode_evidence.references_verified, false);
} finally { await rm(dir, {recursive: true, force: true}); }
console.log('VM opcode ledger model/CLI: passed; synthetic supplied evidence only, no execution or network.');
