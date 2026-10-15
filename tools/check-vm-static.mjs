#!/usr/bin/env node
// Independent hand-specified bytecode cases. No native guest or imported program runs.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import staticVm from '../apps/research-ui/vm_static.js';

const clone = value => JSON.parse(JSON.stringify(value));
const hash = text => createHash('sha256').update(text).digest('hex');
const operand = (name, kind, width = 1, signed = false) => ({name, kind, width, signed});
const opcode = (code, mnemonic, operands, operation, args, kind = 'next', target) => ({code, mnemonic, operands,
  semantics: {operation, args}, flow: {kind, ...(target ? {target} : {})}});
// PC is a byte offset. These fixtures are authored independently of the analyzer
// and of the repository-owned live fixture's instruction-index VM.
const stack = {format: 'reb-vm-definition-v1', definition_id: 'golden-stack', architecture: 'stack',
  opcode_bytes: 1, operand_endianness: 'little', register_count: 0, opcodes: [
    opcode('10', 'PUSH', [operand('value', 'immediate', 2, true)], 'stack_const', ['value']),
    opcode('20', 'ADD', [], 'stack_add', []),
    opcode('30', 'JZ', [operand('delta', 'offset', 1, true)], 'stack_branch_zero', [], 'branch', {operand: 'delta', base: 'next'}),
    opcode('40', 'JUMP', [operand('target', 'address', 2)], 'jump', [], 'jump', {operand: 'target', base: 'absolute'}),
    opcode('ff', 'HALT', [], 'halt', [], 'halt'),
  ]};
const register = {format: 'reb-vm-definition-v1', definition_id: 'golden-register', architecture: 'register',
  opcode_bytes: 2, operand_endianness: 'big', register_count: 4, opcodes: [
    opcode('aa01', 'MOVI', [operand('dst', 'register'), operand('value', 'immediate', 4, true)], 'register_const', ['dst', 'value']),
    opcode('aa02', 'ADD', [operand('dst', 'register'), operand('left', 'register'), operand('right', 'register')], 'register_add', ['dst', 'left', 'right']),
    opcode('aa03', 'JZ', [operand('test', 'register'), operand('target', 'address', 2)], 'branch_zero', ['test'], 'branch', {operand: 'target', base: 'absolute'}),
    opcode('aa04', 'CALL', [operand('delta', 'offset', 2, true)], 'call', [], 'call', {operand: 'delta', base: 'next'}),
    opcode('aa05', 'RET', [], 'return', [], 'return'),
    opcode('aaff', 'HALT', [], 'halt', [], 'halt'),
  ]};
const image = (definition, bytes_hex, entry_offsets = [0]) => ({format: 'reb-vm-bytecode-v1',
  image_id: `golden-${definition.architecture}-bytes`, definition_id: definition.definition_id, entry_offsets, bytes_hex});
// Stack: PUSH -2 at 0, PUSH 3 at 3, ADD at 6, JZ +3 at 7,
// JUMP 0 at 9, HALT at 12. Both conditional edges are static possibilities.
const stackImage = image(stack, '10feff100300203003400000ff');
// Register: MOVI r0,-2147483648 at 0, MOVI r1,2147483647 at 7,
// ADD r2,r0,r1 at 14, JZ r2,30 at 19, CALL +2 at 24,
// HALT at 28, RET at 30. Calls never imply a concrete returned state.
const registerImage = image(register, 'aa010080000000aa01017fffffffaa02020001aa0302001eaa040002aaffaa05');

assert.deepEqual(staticVm.parseDefinition(JSON.stringify(stack)), stack);
assert.deepEqual(staticVm.parseDefinition(register), register);
assert.deepEqual(staticVm.parseImage(JSON.stringify(stackImage)), stackImage);
for (const data of ['{}', '[]', 'null', '{"format":1,"format":2}', '\ufeff' + JSON.stringify(stack), JSON.stringify(stack) + '{}']) {
  assert.throws(() => staticVm.parseDefinition(data));
}
for (const token of ['-0', '1.0', '1e0', '9007199254740992', '1e400']) {
  assert.throws(() => staticVm.parseDefinition(JSON.stringify(stack).replace('"opcode_bytes":1', `"opcode_bytes":${token}`)));
}
for (const mutate of [
  v => v.extra = true, v => v.format = 'reb-vm-definition-v2', v => v.definition_id = '',
  v => v.architecture = 'hybrid', v => v.opcode_bytes = 3, v => v.operand_endianness = 'native',
  v => v.register_count = 65, v => v.opcodes.push(clone(v.opcodes[0])),
  v => v.opcodes[0].code = '0', v => v.opcodes[0].code = 'FF', v => v.opcodes[0].extra = true,
  v => v.opcodes[0].operands[0].width = 3, v => v.opcodes[0].operands[0].signed = 'true',
  v => v.opcodes[0].operands[0].kind = 'pointer',
  v => v.opcodes[0].operands.push(clone(v.opcodes[0].operands[0])),
  v => v.opcodes[0].semantics.operation = 'eval', v => v.opcodes[0].semantics.args = ['missing'],
  v => v.opcodes[0].flow = {kind: 'jump', target: {operand: 'value', base: 'absolute'}},
  v => v.opcodes[2].flow.target.operand = 'missing', v => v.opcodes[2].flow.target.base = 'current',
  v => delete v.opcodes[2].flow.target, v => v.opcodes[4].flow.target = {operand: 'missing', base: 'absolute'},
]) { const invalid = clone(stack); mutate(invalid); assert.throws(() => staticVm.parseDefinition(invalid)); }
for (const mutate of [
  v => v.extra = true, v => v.format = 'reb-vm-bytecode-v2', v => v.image_id = '',
  v => v.bytes_hex = '0', v => v.bytes_hex = 'FF', v => v.bytes_hex = 'zz',
  v => v.bytes_hex = '00'.repeat(65537), v => v.entry_offsets = [-1],
  v => v.entry_offsets = [0, 0], v => v.entry_offsets = [9007199254740992],
]) { const invalid = clone(stackImage); mutate(invalid); assert.throws(() => staticVm.parseImage(invalid)); }

// Golden assertions follow the documented public report, never a second call
// to the analyzer or expectations derived from its decode/CFG implementation.
const stackReport = await staticVm.analyze(stack, stackImage);
const registerReport = await staticVm.analyze(register, registerImage);
const decoded = report => report.instructions.map(value => [value.offset, value.size, value.opcode,
  value.operands.map(item => [item.name, item.offset, item.bytes_hex, item.value])]);
assert.deepEqual(decoded(stackReport), [
  [0, 3, '10', [['value', 1, 'feff', -2]]],
  [3, 3, '10', [['value', 4, '0300', 3]]],
  [6, 1, '20', []], [7, 2, '30', [['delta', 8, '03', 3]]],
  [9, 3, '40', [['target', 10, '0000', 0]]], [12, 1, 'ff', []],
]);
assert.deepEqual(decoded(registerReport), [
  [0, 7, 'aa01', [['dst', 2, '00', 0], ['value', 3, '80000000', -2147483648]]],
  [7, 7, 'aa01', [['dst', 9, '01', 1], ['value', 10, '7fffffff', 2147483647]]],
  [14, 5, 'aa02', [['dst', 16, '02', 2], ['left', 17, '00', 0], ['right', 18, '01', 1]]],
  [19, 5, 'aa03', [['test', 21, '02', 2], ['target', 22, '001e', 30]]],
  [24, 4, 'aa04', [['delta', 26, '0002', 2]]], [28, 2, 'aaff', []], [30, 2, 'aa05', []],
]);
const edges = report => report.cfg.edges.map(value => [value.from_offset, value.to_offset, value.kind, value.status]);
assert.deepEqual(edges(stackReport), [[0, 3, 'fallthrough', 'resolved'], [3, 6, 'fallthrough', 'resolved'],
  [6, 7, 'fallthrough', 'resolved'], [7, 12, 'branch_taken', 'resolved'], [7, 9, 'branch_not_taken', 'resolved'], [9, 0, 'jump', 'resolved']]);
assert.deepEqual(edges(registerReport), [[0, 7, 'fallthrough', 'resolved'], [7, 14, 'fallthrough', 'resolved'],
  [14, 19, 'fallthrough', 'resolved'], [19, 30, 'branch_taken', 'resolved'], [19, 24, 'branch_not_taken', 'resolved'],
  [24, 30, 'call', 'resolved'], [24, 28, 'call_continuation', 'resolved'], [30, null, 'return', 'unknown']]);
const pseudocode = report => report.pseudocode.map(value => [value.offset, value.text, value.status]);
assert.deepEqual(pseudocode(stackReport), [[0, 'push(-2);', 'declared'], [3, 'push(3);', 'declared'],
  [6, 'right = pop(); left = pop(); push(add(left, right));', 'declared'],
  [7, 'if (pop() == 0) goto 0x000c; else goto 0x0009;', 'declared'], [9, 'goto 0x0000;', 'declared'], [12, 'halt;', 'declared']]);
assert.deepEqual(pseudocode(registerReport), [[0, 'r0 = -2147483648;', 'declared'], [7, 'r1 = 2147483647;', 'declared'],
  [14, 'r2 = add(r0, r1);', 'declared'], [19, 'if (r2 == 0) goto 0x001e; else goto 0x0018;', 'declared'],
  [24, 'call 0x001e; assumed continuation 0x001c;', 'declared'], [28, 'halt;', 'declared'], [30, 'return unknown_target;', 'declared']]);
assert.deepEqual(stackReport.coverage, {decoded_bytes: 13, total_bytes: 13, instruction_count: 6, stop_reason: 'end', undecoded_bytes: 0});
assert.deepEqual(registerReport.coverage, {decoded_bytes: 32, total_bytes: 32, instruction_count: 7, stop_reason: 'end', undecoded_bytes: 0});
for (const report of [stackReport, registerReport]) {
  assert.equal(report.format, 'reb-vm-static-analysis-v1'); assert.equal(report.cfg.complete, false);
  assert.equal(report.equivalence_proven, false); assert.equal(report.provenance.definition_source_sha256, null);
  assert.equal(report.provenance.image_source_sha256, null); assert.deepEqual(report.diagnostics, []);
  assert(report.cfg.nodes.every(value => value.reachable)); assert(report.cfg.edges.every(value => value.evidence === 'declared_static'));
  assert.deepEqual(report.cfg.entries, [{offset: 0, status: 'resolved'}]);
  for (const line of report.pseudocode) {
    assert.equal(line.instruction_id, `insn:${line.offset}`);
    assert.deepEqual(report.instructions.find(value => value.offset === line.offset).pseudocode, [line]);
  }
  assert(report.warnings.some(value => /overflow/.test(value)), 'Runtime overflow semantics must remain unspecified');
}

const definitionText = JSON.stringify(stack, null, 2), imageText = JSON.stringify(stackImage, null, 2);
const sourceReport = await staticVm.analyze(definitionText, imageText);
assert.equal(sourceReport.provenance.definition_source_sha256, hash(definitionText));
assert.equal(sourceReport.provenance.image_source_sha256, hash(imageText));
assert.equal(sourceReport.provenance.image_bytes_sha256, hash(Buffer.from('10feff100300203003400000ff', 'hex')));
assert.equal(sourceReport.provenance.definition_canonical_sha256, stackReport.provenance.definition_canonical_sha256);
assert.notEqual(sourceReport.provenance.definition_source_sha256, sourceReport.provenance.definition_canonical_sha256);
const reorderedDefinition = Object.fromEntries(Object.entries(stack).reverse());
assert.equal((await staticVm.analyze(reorderedDefinition, stackImage)).provenance.definition_canonical_sha256, stackReport.provenance.definition_canonical_sha256);
assert.equal(JSON.stringify(stack, null, 2), definitionText, 'Analysis may not change a source definition');
assert.equal(JSON.stringify(stackImage, null, 2), imageText, 'Analysis may not change source bytecode');

const unknown = await staticVm.analyze(stack, image(stack, '10feffeeff', [0, 3, 4]));
assert.deepEqual(unknown.coverage, {decoded_bytes: 3, total_bytes: 5, instruction_count: 1, stop_reason: 'unknown_opcode', undecoded_bytes: 2});
assert.deepEqual(edges(unknown), [[0, 3, 'fallthrough', 'undecoded']]);
assert.deepEqual(unknown.cfg.entries, [{offset: 0, status: 'resolved'}, {offset: 3, status: 'undecoded'}, {offset: 4, status: 'undecoded'}]);
assert.equal(unknown.instructions.length, 1, 'No scanning past an unknown opcode to manufacture later HALT');
for (const [definition, bytes] of [[stack, '1001'], [register, 'aa'], [register, 'aa0100800000']]) {
  const report = await staticVm.analyze(definition, image(definition, bytes));
  assert.equal(report.coverage.stop_reason, 'truncated_instruction'); assert.equal(report.coverage.decoded_bytes, 0);
  assert.equal(report.instructions.length, 0); assert.deepEqual(report.cfg.entries, [{offset: 0, status: 'undecoded'}]);
}
const invalidRegister = await staticVm.analyze(register, image(register, 'aa010480000000aaff'));
assert.deepEqual(invalidRegister.coverage, {decoded_bytes: 0, total_bytes: 9, instruction_count: 0, stop_reason: 'invalid_operand', undecoded_bytes: 9});
assert.equal(invalidRegister.instructions.length, 0);

const midInstruction = await staticVm.analyze(stack, image(stack, '400100ff', [0, 1, 3, 4]));
assert.deepEqual(edges(midInstruction), [[0, 1, 'jump', 'mid_instruction']]);
assert.deepEqual(midInstruction.cfg.nodes.map(value => [value.offset, value.reachable]), [[0, true], [3, true]]);
assert.deepEqual(midInstruction.cfg.entries, [{offset: 0, status: 'resolved'}, {offset: 1, status: 'mid_instruction'},
  {offset: 3, status: 'resolved'}, {offset: 4, status: 'out_of_range'}]);
assert.deepEqual(pseudocode(midInstruction), [[0, 'goto unresolved(0x0001, mid_instruction);', 'declared'], [3, 'halt;', 'declared']]);
const unreachable = await staticVm.analyze(stack, image(stack, 'ff100100'));
assert.deepEqual(unreachable.cfg.nodes.map(value => [value.offset, value.reachable]), [[0, true], [1, false]]);
assert.deepEqual(edges(unreachable), [[1, 4, 'fallthrough', 'out_of_range']]);
// A signed relative back edge is computed from next byte, without wraparound.
const back = await staticVm.analyze(stack, image(stack, '30feff'));
assert.deepEqual(edges(back), [[0, 0, 'branch_taken', 'resolved'], [0, 2, 'branch_not_taken', 'resolved']]);
const negative = await staticVm.analyze(stack, image(stack, '3080ff'));
assert.deepEqual(edges(negative), [[0, -126, 'branch_taken', 'out_of_range'], [0, 2, 'branch_not_taken', 'resolved']]);

const wide = {...clone(stack), opcodes: [
  opcode('41', 'ABS', [operand('target', 'address', 4)], 'jump', [], 'jump', {operand: 'target', base: 'absolute'}),
  opcode('42', 'REL', [operand('delta', 'offset', 4, true)], 'jump', [], 'jump', {operand: 'delta', base: 'next'}),
]};
const wideAbsolute = await staticVm.analyze(wide, image(wide, '41ffffffff'));
assert.equal(wideAbsolute.instructions[0].operands[0].value, 4294967295);
assert.deepEqual(edges(wideAbsolute), [[0, 4294967295, 'jump', 'out_of_range']]);
const wideRelative = await staticVm.analyze(wide, image(wide, '42ffffff7f'));
assert.equal(wideRelative.instructions[0].operands[0].value, 2147483647);
assert.deepEqual(edges(wideRelative), [[0, 2147483652, 'jump', 'out_of_range']]);
const wideNegative = await staticVm.analyze(wide, image(wide, '4200000080'));
assert.equal(wideNegative.instructions[0].operands[0].value, -2147483648);
assert.deepEqual(edges(wideNegative), [[0, -2147483643, 'jump', 'out_of_range']]);

const unfamiliar = {...clone(stack), opcodes: [opcode('01', 'UNFAMILIAR', [], 'unknown', [], 'unknown'), stack.opcodes.at(-1)]};
const unknownSemantics = await staticVm.analyze(unfamiliar, image(unfamiliar, '01ff'));
assert.deepEqual(pseudocode(unknownSemantics), [[0, 'unknown_semantics(UNFAMILIAR);', 'unknown'], [1, 'halt;', 'declared']]);
assert.deepEqual(edges(unknownSemantics), [[0, null, 'unknown', 'unknown']]);
assert.deepEqual(unknownSemantics.cfg.nodes.map(value => [value.offset, value.reachable]), [[0, true], [1, false]]);
const budget = await staticVm.analyze(stack, stackImage, {max_instructions: 2});
assert.deepEqual(budget.coverage, {decoded_bytes: 6, total_bytes: 13, instruction_count: 2, stop_reason: 'instruction_budget', undecoded_bytes: 7});
assert.deepEqual(edges(budget), [[0, 3, 'fallthrough', 'resolved'], [3, 6, 'fallthrough', 'undecoded']]);
const maximal = await staticVm.analyze(stack, image(stack, 'ff'.repeat(65536)));
assert.deepEqual(maximal.coverage, {decoded_bytes: 4096, total_bytes: 65536, instruction_count: 4096, stop_reason: 'instruction_budget', undecoded_bytes: 61440});
const empty = await staticVm.analyze(stack, image(stack, ''));
assert.deepEqual(empty.coverage, {decoded_bytes: 0, total_bytes: 0, instruction_count: 0, stop_reason: 'end', undecoded_bytes: 0});
assert.deepEqual(empty.cfg.entries, [{offset: 0, status: 'out_of_range'}]);
await assert.rejects(staticVm.analyze(stack, {...stackImage, definition_id: 'other'}));
for (const options of [{max_instructions: 0}, {max_instructions: 4097}, {max_instructions: -0}, {max_instructions: 1.5}, {extra: true}, []]) {
  await assert.rejects(staticVm.analyze(stack, stackImage, options));
}
let invoked = false;
const accessor = {...stack}; Object.defineProperty(accessor, 'definition_id', {enumerable: true, get() { invoked = true; return 'golden-stack'; }});
assert.throws(() => staticVm.parseDefinition(accessor)); assert.equal(invoked, false);
const executable = {...stack, toJSON() { invoked = true; return stack; }};
assert.throws(() => staticVm.parseDefinition(executable)); assert.equal(invoked, false);
const cycle = {...stack}; cycle.extra = cycle; assert.throws(() => staticVm.parseDefinition(cycle));
const sparse = {...stack, opcodes: Array(1)}; assert.throws(() => staticVm.parseDefinition(sparse));
console.log('PASS independent VM static golden cases: stack/register decode, endian signed operands, exact hashes, declared CFG/pseudocode links, inert data, malformed/unknown/truncated inputs, mid-instruction/overflow targets and bounded incomplete coverage. No imported execution or native/rendered acceptance claimed.');
