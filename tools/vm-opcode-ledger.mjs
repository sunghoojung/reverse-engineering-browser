// Evidence bookkeeping only. No execution, source discovery or semantic promotion.
import {createHash} from 'node:crypto';
import captured from '../apps/research-ui/captured_client.js';
import staticVm from '../apps/research-ui/vm_static.js';

export const ledgerLimits = Object.freeze({input_bytes: 1048576, entries: 256, references: 16, questions: 16, text: 1024});
const fail = () => { throw new TypeError('Invalid bounded reb-vm-opcode-ledger-v1 or mismatched definition.'); };
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const id = v => typeof v === 'string' && /^[A-Za-z0-9_.:-]{1,128}$(?![\s\S])/.test(v);
const text = v => typeof v === 'string' && v.length > 0 && [...v].length <= ledgerLimits.text && !/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(v) && !/[\ud800-\udfff]/u.test(v);
const hash = value => createHash('sha256').update(value).digest('hex');

export function inspectLedger(input, definitionText) {
  if (typeof input !== 'string' || Buffer.byteLength(input) > ledgerLimits.input_bytes) fail();
  const tokens = new Map(), ledger = captured.capturedClientJSON(input, tokens);
  for (const token of tokens.values()) if (!/^(0|[1-9][0-9]*)$/.test(token) || !Number.isSafeInteger(Number(token))) fail();
  const definition = staticVm.parseDefinition(definitionText);
  if (!exact(ledger, ['format', 'definition_id', 'definition_source_sha256', 'entries']) || ledger.format !== 'reb-vm-opcode-ledger-v1' ||
      ledger.definition_id !== definition.definition_id || ledger.definition_source_sha256 !== hash(definitionText) ||
      !Array.isArray(ledger.entries) || ledger.entries.length > ledgerLimits.entries) fail();
  const definitions = new Map(definition.opcodes.map(op => [op.code, op])), entries = new Map();
  for (const entry of ledger.entries) {
    if (!exact(entry, ['opcode', 'status', 'meaning', 'handler_location', 'operand_format', 'source_refs', 'test_status', 'test_refs', 'unresolved_questions']) ||
        !definitions.has(entry.opcode) || entries.has(entry.opcode) || !['observed', 'inferred', 'unmodeled'].includes(entry.status) ||
        !(entry.meaning === null || text(entry.meaning)) || (entry.status === 'unmodeled' ? entry.meaning !== null : entry.meaning === null) ||
        !(entry.operand_format === null || text(entry.operand_format)) || !['not_run', 'passed', 'failed', 'inconclusive'].includes(entry.test_status)) fail();
    const handler = entry.handler_location;
    if (handler !== null && (!exact(handler, ['artifact_id', 'byte_offset']) || !id(handler.artifact_id) || !Number.isSafeInteger(handler.byte_offset) || handler.byte_offset < 0)) fail();
    for (const refs of [entry.source_refs, entry.test_refs]) {
      if (!Array.isArray(refs) || refs.length > ledgerLimits.references) fail();
      const seen = new Set();
      for (const ref of refs) {
        if (!exact(ref, ['artifact_id', 'event_id']) || !id(ref.artifact_id) || !(ref.event_id === null || id(ref.event_id))) fail();
        const key = JSON.stringify([ref.artifact_id, ref.event_id]);
        if (seen.has(key)) fail();
        seen.add(key);
      }
    }
    if (entry.status !== 'unmodeled' && !entry.source_refs.length ||
        (entry.test_status === 'not_run' ? entry.test_refs.length !== 0 : !entry.test_refs.length) ||
        !Array.isArray(entry.unresolved_questions) || entry.unresolved_questions.length > ledgerLimits.questions || !entry.unresolved_questions.every(text)) fail();
    entries.set(entry.opcode, entry);
  }
  const counts = {observed: 0, inferred: 0, unmodeled: 0, missing_entries: 0};
  const coverage = definition.opcodes.map(op => {
    const entry = entries.get(op.code), status = entry?.status ?? 'unmodeled';
    counts[status]++;
    if (!entry) counts.missing_entries++;
    return {opcode: op.code, status, entry_present: !!entry, declared_operation: op.semantics.operation,
      meaning: entry?.meaning ?? null, test_status: entry?.test_status ?? 'not_run',
      definition_operands: op.operands, operand_endianness: definition.operand_endianness};
  });
  return {format: 'reb-vm-opcode-ledger-analysis-v1', source_sha256: hash(input), definition_source_sha256: hash(definitionText),
    executes_imported_code: false, references_verified: false, tests_executed: false,
    semantics: 'Researcher assertions only; references and test results are supplied, not verified. Coverage counts declared opcodes, not runtime execution or semantic correctness.',
    ledger, coverage: {denominator: 'declared-opcodes', total: definition.opcodes.length, counts, opcodes: coverage}};
}
