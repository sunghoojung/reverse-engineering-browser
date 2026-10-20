#!/usr/bin/env node
// Agent-facing adapter only: fixed owned-fixture routes and inert declarative inputs.
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {request} from 'node:http';
import {pathToFileURL} from 'node:url';
import vm from '../apps/research-ui/vm_semantics.js';
import owned from '../apps/research-ui/vm_debugger.js';
import staticVm from '../apps/research-ui/vm_static.js';
import contextualVm from '../apps/research-ui/vm_contextual.js';
import contextualEvidence from '../apps/research-ui/vm_contextual_evidence.js';
import opcodeLedger from '../apps/research-ui/vm_opcode_ledger.js';
import {inspectLedger, ledgerLimits} from './vm-opcode-ledger.mjs';

const INPUT_LIMIT = 1048576, OUTPUT_LIMIT = 4194304, DEFAULT_TIMEOUT = 9000;
const scopeKeys = ['backend_instance_id', 'session_id', 'run_id', 'run_generation'];
const actions = ['run', 'pause', 'step', 'stop', 'reset', 'close'];
const immutableKeys = ['provider', 'target_kind', 'fixture', 'program_id', 'fixture_revision', 'program_sha256',
  'program_manifest_scope', 'build_id', 'build_id_scope', 'pc_units', 'value_semantics', 'tick_units'];
const errorCodes = ['unspecified', 'invalid_request', 'state_conflict', 'protocol_error', 'stale_generation',
  'target_unavailable', 'dependency_unavailable', 'resource_limit', 'timeout', 'cancelled', 'command_outcome_unknown', 'application_failed'];
const usage = `Usage: node tools/vm-agent.mjs COMMAND [OPTIONS]
  capabilities                              Offline JSON discovery; no connection
  inspect --input TRACE.json                Inspect supplied observations only
  observed-path --input TRACE.json          Retained occurrence edges, not a static CFG
  occurrences --input TRACE.json --location registers:0 --page N --page-size N
  select-step --input TRACE.json --sequence N
  validate --input TRACE.json --hypotheses HYPOTHESES.json
  compare --input LEFT.json --sequence N --right RIGHT.json --right-sequence N
  validate-definition --definition VM.json  Validate inert declarative VM layout
  decode-bytecode --definition VM.json --input BYTECODE.json
  analyze-static --definition VM.json --input BYTECODE.json
  select-instruction --definition VM.json --input BYTECODE.json --pc N
  analyze-contextual --definition BUILD.json --input IMAGE.json
  link-contextual --definition BUILD.json --input IMAGE.json --evidence EVENTS.json
  opcode-ledger --definition VM.json --input LEDGER.json
  create-opcode-ledger --definition VM.json  Empty hash-bound ledger JSON to stdout
  status --base-url URL                      Read cached owned-fixture state
  trace --base-url URL --state STATE.json    Read the exact saved native run
  action ACTION --base-url URL --state STATE.json --command-id ID

ACTION: run | pause | step | stop | reset | close. Actions are explicit writes.
URL: http://127.0.0.1:PORT or http://[::1]:PORT, optional trailing slash.
Online commands accept --timeout-ms 1..10000 (default ${DEFAULT_TIMEOUT}).
STATE is a reviewed raw reb-owned-vm-debug-session-v1 view from status/reb-api.
Imported traces are inert: select-step never executes code.
Occurrence locations use pc, halted, registers:N, stack:N or memory:N; pages start at 0,
page size is 1..64. Ledger creation asserts no meanings or verified evidence.
Static commands interpret declarative metadata only, never execute imported bytecode. No arbitrary code,
URL targets, port scanning, redirects, proxies, storage writes or automatic retries.
Native fixture creation is unavailable here; use the existing owned-fixture UI or reb-api after
reviewing reb-api describe vm_debugger_action --action create.
JSON goes to stdout; JSON errors go to stderr. Exit: 0 confirmed result,
2 invalid/refused/read failure, 3 command outcome unknown, 4 command pending.
A completed Run acknowledges scheduling, not a halted program. --help is offline.
`;

class Refusal extends Error {
  constructor(code, message, details = {}) { super(message); this.code = code; this.details = details; }
}
const fail = (code, message, details) => { throw new Refusal(code, message, details); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const scope = value => Object.fromEntries(scopeKeys.map(key => [key, value[key]]));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const decode = bytes => new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes);

export function capabilities() {
  return {format: 'reb-vm-agent-capabilities-v1', discovery: 'offline-static-not-server-attestation',
    offline: {format: 'reb-vm-trace-v1', commands: ['inspect', 'observed-path', 'occurrences', 'select-step', 'validate', 'compare'], executes_imported_code: false,
      occurrence_locations: ['pc', 'halted', 'registers:N', 'stack:N', 'memory:N'], occurrence_page_size: {minimum: 1, maximum: 64},
      semantics: 'existing bounded supplied-observation model; hypotheses are not proof', network_requests: 0},
    imported_static: {definition_format: 'reb-vm-definition-v1', bytecode_format: 'reb-vm-bytecode-v1',
      commands: ['validate-definition', 'decode-bytecode', 'analyze-static', 'select-instruction'],
      executes_imported_code: false, executes_plugins: false, network_requests: 0,
      semantics: 'researcher-supplied declarative layout and meanings; static edges and pseudocode are not observed execution',
      runtime_state: 'unknown', live_capture_adapter: {available: false},
      architectures: ['stack', 'register'], opcode_bytes: [1, 2], operand_width_bytes: [1, 2, 4],
      operand_endianness: ['little', 'big'], pc_units: 'byte-offset',
      limits: {bytecode_bytes: 65536, instructions: 4096, opcode_definitions: 256, operands_per_instruction: 8},
      extension_boundary: 'reviewed declarative definitions using supported model operations; no executable plugin loader'},
    contextual: {commands: ['analyze-contextual', 'link-contextual'], definition_format: 'reb-vm-contextual-definition-v1',
      image_format: 'reb-vm-contextual-image-v1', evidence_format: 'reb-vm-contextual-evidence-v1',
      executes_imported_code: false, network_requests: 0, vendor_compatibility: 'unverified',
      semantics: 'hash-bound supplied declarations; explicit supplied jump evidence is separate from declared edges'},
    opcode_evidence: {format: 'reb-vm-opcode-ledger-v1', commands: ['opcode-ledger', 'create-opcode-ledger'], network_requests: 0,
      executes_imported_code: false, tests_executed: false, references_verified: false, limits: ledgerLimits},
    owned: {schema: 'reb-owned-vm-debug-session-v1', read_commands: ['status', 'trace'], actions,
      target: 'existing repository-owned cooperative native register/stack fixtures only', exact_scope: scopeKeys,
      action_requires: ['explicit action', 'reviewed saved state', 'user-supplied command ID', 'selected loopback base URL'],
      creation: {available: false, existing_workflow: 'Owned VM UI or reb-api describe vm_debugger_action --action create'},
      action_effects: {run: 'schedule native instructions', step: 'execute at most one native instruction',
        pause: 'request cooperative pause', stop: 'dispose helper', reset: 'dispose helper and create fresh paused run', close: 'dispose helper and clear session'},
      provenance: 'preserves supplied program-manifest and configured-helper hashes; not remote attestation'},
    transport: {hosts: ['127.0.0.1', '::1'], protocol: 'http', explicit_port: true, redirects: false, proxies: false,
      auto_retry: false, timeout_ms: DEFAULT_TIMEOUT, maximum_timeout_ms: 10000, response_bytes: INPUT_LIMIT, request_bytes: 2048},
    options: {inspect: ['--input'], 'observed-path': ['--input'], occurrences: ['--input', '--location', '--page', '--page-size'],
      'select-step': ['--input', '--sequence'], validate: ['--input', '--hypotheses'],
      compare: ['--input', '--sequence', '--right', '--right-sequence'],
      'validate-definition': ['--definition'], 'decode-bytecode': ['--definition', '--input'],
      'analyze-static': ['--definition', '--input'], 'select-instruction': ['--definition', '--input', '--pc'],
      'analyze-contextual': ['--definition', '--input'], 'link-contextual': ['--definition', '--input', '--evidence'],
      'opcode-ledger': ['--definition', '--input'], 'create-opcode-ledger': ['--definition'], status: ['--base-url'],
      trace: ['--base-url', '--state'], action: ['--base-url', '--state', '--command-id'], online_optional: ['--timeout-ms']},
    limits: {input_file_bytes: INPUT_LIMIT, output_bytes: OUTPUT_LIMIT}, writes_files: false,
    exit_codes: {'0': 'confirmed result; Run means scheduling acknowledged', '2': 'invalid/refused/read failure',
      '3': 'command outcome unknown; reconcile with status without replay', '4': 'command pending; reconcile with status without replay'}};
}

function options(argv) {
  const args = [...argv], command = args.shift(), action = command === 'action' ? args.shift() : null;
  const required = {capabilities: [], inspect: ['input'], 'observed-path': ['input'], occurrences: ['input', 'location', 'page', 'page-size'],
    'select-step': ['input', 'sequence'], validate: ['input', 'hypotheses'],
    compare: ['input', 'sequence', 'right', 'right-sequence'],
    'validate-definition': ['definition'], 'decode-bytecode': ['definition', 'input'],
    'analyze-static': ['definition', 'input'], 'select-instruction': ['definition', 'input', 'pc'],
    'analyze-contextual': ['definition', 'input'], 'link-contextual': ['definition', 'input', 'evidence'],
    'opcode-ledger': ['definition', 'input'], 'create-opcode-ledger': ['definition'], status: ['base-url'], trace: ['base-url', 'state'],
    action: ['base-url', 'state', 'command-id']};
  if (!Object.hasOwn(required, command) || command === 'action' && !actions.includes(action)) fail('usage', 'Use --help for explicit supported commands. Native fixture creation is not supported by this facade.');
  const online = ['status', 'trace', 'action'].includes(command), result = {};
  const allowed = [...required[command], ...(online ? ['timeout-ms'] : [])];
  while (args.length) {
    const key = args.shift(), value = args.shift();
    if (!key?.startsWith('--') || !allowed.includes(key.slice(2)) || Object.hasOwn(result, key.slice(2)) || typeof value !== 'string' || !value || value.startsWith('--')) fail('usage', 'Unknown, repeated or missing option. Use --help.');
    result[key.slice(2)] = value;
  }
  if (!required[command].every(key => Object.hasOwn(result, key))) fail('usage', 'Required option missing. Use --help.');
  if (online) {
    if (!/^http:\/\/(?:127\.0\.0\.1|\[::1\]):[1-9][0-9]{0,4}\/?$/.test(result['base-url'])) fail('endpoint_refused', 'Select an explicit numeric HTTP loopback root and port.');
    const port = Number(result['base-url'].match(/:([0-9]+)\/?$/)[1]);
    if (port > 65535) fail('endpoint_refused', 'Loopback port is out of range.');
    result.base = result['base-url'].replace(/\/$/, '');
    if (result['timeout-ms'] !== undefined && !/^[1-9][0-9]{0,4}$/.test(result['timeout-ms'])) fail('usage', 'Timeout must be an exact integer from 1 through 10000 ms.');
    result.timeout = Number(result['timeout-ms'] ?? DEFAULT_TIMEOUT);
    if (result.timeout > 10000) fail('usage', 'Timeout must be from 1 through 10000 ms.');
  }
  return {command, action, ...result};
}

async function readBounded(path, parser) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const info = await file.stat();
    if (!info.isFile() || info.size > INPUT_LIMIT) fail('input_refused', 'Expected a regular, non-symlink file up to 1 MiB.');
    const bytes = Buffer.alloc(INPUT_LIMIT + 1); let length = 0;
    while (length < bytes.length) { const result = await file.read(bytes, length, bytes.length - length, null); if (!result.bytesRead) break; length += result.bytesRead; }
    if (length > INPUT_LIMIT) fail('input_refused', 'Input file exceeds 1 MiB.');
    const data = bytes.subarray(0, length);
    return {value: parser(decode(data)), sha256: sha256(data)};
  } catch (error) {
    if (error instanceof Refusal) throw error;
    fail('input_refused', 'Input cannot be read as bounded strict UTF-8 JSON satisfying the selected VM contract.');
  } finally { await file?.close(); }
}

function sequence(value, label = 'sequence ID') {
  if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value))) fail('selection_refused', `Select an exact canonical nonnegative safe-integer ${label}.`);
  return Number(value);
}

function validateError(value) {
  if (!exact(value, ['error', 'code', 'details']) || typeof value.error !== 'string' || value.error.length > 512 ||
      !errorCodes.includes(value.code) || !object(value.details)) return false;
  const enums = {phase: ['request_body', 'worker', 'command_exchange'], cause: ['timeout', 'disconnected', 'transport_failure', 'invalid_reply'],
    selection_reason: ['stale_capture', 'request_not_retained', 'ambiguous_request']};
  return Object.entries(value.details).every(([key, data]) => Object.hasOwn(enums, key) ? enums[key].includes(data) :
    ['expected_generation', 'current_generation'].includes(key) && Number.isSafeInteger(data) && data >= 0);
}

function exchange(base, path, timeout, body) {
  // node:http has no ambient proxy/redirect handling. Numeric hosts avoid DNS.
  return new Promise((resolve, reject) => {
    let finished = false, req, timer;
    const finish = (error, value) => {
      if (finished) return; finished = true; clearTimeout(timer);
      if (error) { req?.destroy(); reject(error); } else resolve(value);
    };
    const rejectReply = message => finish(new Refusal('invalid_response', message));
    timer = setTimeout(() => finish(new Refusal('timeout', 'The bounded request deadline expired.')), timeout);
    req = request(new URL(path, base), {method: body ? 'POST' : 'GET', agent: false, maxHeaderSize: 16384,
      headers: {Accept: 'application/json', Origin: base, Host: base.slice('http://'.length), ...(body ? {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)} : {})}}, res => {
      const count = name => res.rawHeaders.filter((_, index) => index % 2 === 0 && res.rawHeaders[index].toLowerCase() === name).length;
      if (count('content-type') !== 1 || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(res.headers['content-type'] || '') ||
          count('content-encoding') > 1 || !['', 'identity'].includes(res.headers['content-encoding'] || '') ||
          Number(res.headers['content-length'] || 0) > INPUT_LIMIT || res.statusCode >= 300 && res.statusCode < 400) {
        rejectReply('Response headers, encoding, size or redirect violate the fixed JSON transport.'); res.destroy(); return;
      }
      const chunks = []; let size = 0;
      res.on('data', bytes => {
        size += bytes.length;
        if (size > INPUT_LIMIT) { rejectReply('Response exceeds 1 MiB.'); res.destroy(); } else chunks.push(bytes);
      });
      res.on('error', () => finish(new Refusal('transport_error', 'Response transport failed.')));
      res.on('aborted', () => finish(new Refusal('transport_error', 'Response ended before completion.')));
      res.on('end', () => {
        if (finished) return;
        try { finish(null, {status: res.statusCode, value: owned.ownedVmParseJSON(decode(Buffer.concat(chunks, size)))}); }
        catch { rejectReply('Response is not bounded strict UTF-8 JSON with unique keys and exact integers.'); }
      });
    });
    req.on('error', () => finish(new Refusal('transport_error', 'Loopback request failed.')));
    req.end(body);
  });
}

function stateParser(text) { return owned.ownedVmValidateView(owned.ownedVmParseJSON(text)); }
function sameProvenance(before, after, includeBuild = true) {
  return immutableKeys.filter(key => includeBuild && before.build_id !== null || key !== 'build_id').every(key => before[key] === after[key]);
}
function validateRead(value, selected) {
  owned.ownedVmValidateView(value);
  if (Object.hasOwn(value, 'ack')) fail('invalid_response', 'A read returned an unexpected action acknowledgment.');
  if (selected && (!owned.ownedVmSameRun(selected, value.session) || !sameProvenance(selected, value.session))) fail('scope_mismatch', 'Response does not belong to the exact saved run and provenance.');
  if (selected && ['control_revision', 'snapshot_revision', 'executed_count'].some(key => BigInt(value.session[key]) < BigInt(selected[key]))) fail('scope_mismatch', 'Response regressed behind the saved confirmed state.');
  return value;
}
function validateAction(value, saved, action, commandId) {
  owned.ownedVmValidateView(value);
  if (value.command_id !== commandId || value.backend_instance_id !== saved.backend_instance_id) fail('scope_mismatch', 'Control reply has a different command or backend identity.');
  const before = saved.session, after = value.session;
  if (action === 'close' && value.ack === 'completed') {
    if (after !== null) fail('scope_mismatch', 'Close did not acknowledge disposal.');
  } else if (action === 'reset' && ['completed', 'pending'].includes(value.ack)) {
    if (!after || before.session_id !== after.session_id || before.run_id === after.run_id || BigInt(after.run_generation) <= BigInt(before.run_generation) ||
        !sameProvenance(before, after, false)) fail('scope_mismatch', 'Reset did not identify a fresh run of the same owned fixture.');
    if (value.ack === 'completed' && (!['paused', 'expired'].includes(after.state) || after.executed_count !== '0' || !after.execution_state_known || after.initial_snapshot === null)) fail('invalid_response', 'Reset did not confirm a fresh initial snapshot, paused or expired during setup.');
  } else if (!(action === 'close' && value.ack === 'outcome_unknown' && after === null)) {
    if (!owned.ownedVmSameRun(before, after) || !sameProvenance(before, after)) fail('scope_mismatch', 'Control reply belongs to a different run or provenance.');
    if (['control_revision', 'snapshot_revision', 'executed_count'].some(key => BigInt(after[key]) < BigInt(before[key]))) fail('scope_mismatch', 'Control reply regressed behind the saved confirmed state.');
  }
  if (value.ack === 'completed' && action === 'step' && (!after.execution_state_known || BigInt(after.executed_count) !== BigInt(before.executed_count) + 1n || !['paused', 'halted', 'expired'].includes(after.state))) fail('invalid_response', 'Step did not confirm exactly one completed native instruction.');
  if (value.ack === 'completed' && action === 'run' && (!after.execution_state_known || after.state !== 'running')) fail('invalid_response', 'Run did not confirm native scheduling.');
  if (value.ack === 'completed' && action === 'pause' && ['starting', 'running', 'pausing', 'stepping', 'stopping'].includes(after.state)) fail('invalid_response', 'Pause did not confirm a stable instruction boundary.');
  if (value.ack === 'completed' && action === 'stop' && (after.state !== 'stopped' || after.disposal_failed)) fail('invalid_response', 'Stop did not confirm helper disposal.');
  return value;
}

export async function execute(argv) {
  const opts = options(argv), {command, action} = opts;
  if (command === 'capabilities') return capabilities();
  if (['analyze-contextual', 'link-contextual'].includes(command)) {
    const definition = await readBounded(opts.definition, text => { contextualVm.parseDefinition(text); return text; });
    const source = await readBounded(opts.input, text => { contextualVm.parseImage(text); return text; });
    const evidence = command === 'link-contextual' ? await readBounded(opts.evidence, text => { contextualEvidence.parseEvidence(text); return text; }) : null;
    try {
      const result = evidence ? await contextualEvidence.link(definition.value, source.value, evidence.value) : await contextualVm.analyze(definition.value, source.value);
      return {format: 'reb-vm-agent-contextual-analysis-v1', command, executes_imported_code: false,
        definition_source_sha256: definition.sha256, source_sha256: source.sha256, evidence_source_sha256: evidence?.sha256 ?? null, result};
    } catch { fail('analysis_refused', 'Contextual build, image hash, evidence identity or bounded analysis failed.'); }
  }
  if (['opcode-ledger', 'create-opcode-ledger'].includes(command)) {
    const definition = await readBounded(opts.definition, text => { staticVm.parseDefinition(text); return text; });
    if (command === 'create-opcode-ledger') return opcodeLedger.createLedger(definition.value);
    return (await readBounded(opts.input, text => inspectLedger(text, definition.value))).value;
  }
  if (['inspect', 'observed-path', 'occurrences', 'select-step', 'validate', 'compare'].includes(command)) {
    const source = await readBounded(opts.input, text => vm.trace(vm.parse(text)));
    const report = {format: 'reb-vm-agent-analysis-v1', command, source_sha256: source.sha256, hypotheses_sha256: null, result: null};
    try {
      if (command === 'inspect') report.result = vm.inspect(source.value);
      if (command === 'observed-path') report.result = vm.observedPath(source.value);
      if (command === 'occurrences') report.result = vm.occurrences(source.value, opts.location, sequence(opts.page, 'page'), sequence(opts['page-size'], 'page size'));
      if (command === 'select-step') {
        const selected = vm.step(source.value, sequence(opts.sequence));
        report.result = {format: selected.format, identity: selected.identity, coverage: source.value.coverage,
          step: selected.step, changes: selected.changes, reads: 'unknown', executes_code: false};
      }
      if (command === 'validate') {
        const hypotheses = await readBounded(opts.hypotheses, vm.parse);
        report.hypotheses_sha256 = hypotheses.sha256; report.result = vm.validate(source.value, hypotheses.value);
      }
      if (command === 'compare') {
        const right = await readBounded(opts.right, text => vm.trace(vm.parse(text)));
        report.right_source_sha256 = right.sha256;
        report.result = vm.compareSteps(source.value, sequence(opts.sequence), right.value, sequence(opts['right-sequence']));
      }
    } catch (error) {
      if (error instanceof Refusal) throw error;
      fail('analysis_refused', 'Supplied evidence, hypotheses or exact step selection failed the existing offline model.');
    }
    return report;
  }
  if (['validate-definition', 'decode-bytecode', 'analyze-static', 'select-instruction'].includes(command)) {
    const definition = await readBounded(opts.definition, text => ({text, parsed: staticVm.parseDefinition(text)}));
    const report = {format: 'reb-vm-agent-static-analysis-v1', command, definition_source_sha256: definition.sha256,
      source_sha256: null, executes_imported_code: false, result: null};
    if (command === 'validate-definition') {
      report.result = {valid: true, definition: definition.value.parsed};
      return report;
    }
    const source = await readBounded(opts.input, text => ({text, parsed: staticVm.parseImage(text)}));
    report.source_sha256 = source.sha256;
    try {
      // Pass original strict UTF-8 text so the shared model preserves exact
      // source hashes separately from its explicitly canonical definition hash.
      const analysis = await staticVm.analyze(definition.value.text, source.value.text);
      if (command === 'analyze-static') report.result = analysis;
      if (command === 'decode-bytecode') report.result = {
        definition_id: analysis.definition.definition_id, image_id: analysis.image.image_id,
        provenance: analysis.provenance,
        instructions: analysis.instructions.map(({pseudocode: _pseudocode, ...instruction}) => instruction),
        coverage: analysis.coverage, diagnostics: analysis.diagnostics, warnings: analysis.warnings,
        runtime_state: 'unknown', equivalence_proven: false,
      };
      if (command === 'select-instruction') {
        if (!/^(0|[1-9][0-9]*)$/.test(opts.pc) || !Number.isSafeInteger(Number(opts.pc))) fail('selection_refused', 'Select an exact canonical nonnegative byte-offset PC.');
        const pc = Number(opts.pc), instruction = analysis.instructions.find(value => value.offset === pc);
        if (!instruction) fail('selection_refused', 'No decoded instruction starts at the exact selected byte offset.');
        report.result = {definition_id: analysis.definition.definition_id, image_id: analysis.image.image_id,
          provenance: analysis.provenance, coverage: analysis.coverage, diagnostics: analysis.diagnostics, warnings: analysis.warnings,
          instruction, cfg_node: analysis.cfg.nodes.find(value => value.offset === pc),
          incoming_edges: analysis.cfg.edges.filter(value => value.to_offset === pc),
          outgoing_edges: analysis.cfg.edges.filter(value => value.from_offset === pc),
          pseudocode: analysis.pseudocode.filter(value => value.instruction_id === instruction.id),
          runtime_state: 'unknown', equivalence_proven: false};
      }
    } catch (error) {
      if (error instanceof Refusal) throw error;
      fail('analysis_refused', 'Declarative definition, bytecode identity or static analysis failed the bounded model.');
    }
    return report;
  }
  let saved;
  if (command !== 'status') {
    saved = (await readBounded(opts.state, stateParser)).value;
    if (!saved.session) fail('scope_refused', 'Saved state has no exact owned run.');
  }
  if (command !== 'action') {
    const path = command === 'status' ? '/api/vm-debugger' : '/api/vm-debugger/trace?' + new URLSearchParams(scope(saved.session));
    const reply = await exchange(opts.base, path, opts.timeout);
    if (reply.status !== 200) {
      if (!validateError(reply.value)) fail('invalid_response', 'Error response does not satisfy the bounded API error contract.');
      fail('server_refusal', 'Backend rejected the read; no fallback selection was made.', {http_status: reply.status, server: reply.value});
    }
    try { return validateRead(reply.value, saved?.session); }
    catch (error) { if (error instanceof Refusal) throw error; fail('invalid_response', 'Read response does not satisfy the owned-VM view contract.'); }
  }
  const commandId = opts['command-id'];
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(commandId)) fail('command_refused', 'Supply an explicit command ID of 1..64 ASCII letters, digits, underscores or hyphens.');
  if (saved.session.last_command?.command_id === commandId || saved.command_id === commandId) fail('command_refused', 'Command ID already appears in the saved state. Reconcile before deciding on a new action.');
  if (['run', 'step'].includes(action) && (!saved.available || saved.session.state !== 'paused' || !saved.session.execution_state_known || saved.session.disposal_failed ||
      ['pending', 'outcome_unknown'].includes(saved.ack) || ['pending', 'outcome_unknown'].includes(saved.session.last_command?.ack))) fail('state_refused', 'Run/Step requires confirmed paused state; reconcile uncertainty with status first.');
  const body = owned.ownedVmBuildAction(saved, action, commandId), commandScope = {...scope(saved.session), action, command_id: commandId};
  try {
    const reply = await exchange(opts.base, '/api/vm-debugger/actions', opts.timeout, JSON.stringify(body));
    if (reply.status !== 200) {
      if (!validateError(reply.value)) fail('invalid_response', 'Error response does not satisfy the bounded API error contract.');
      // A generic error is not proof of rollback. Only explicit precondition
      // refusals have a rejected classification, and none authorize replay.
      const rejected = ['invalid_request', 'state_conflict', 'stale_generation', 'dependency_unavailable'].includes(reply.value.code);
      fail(rejected ? 'command_rejected' : 'command_outcome_unknown', 'Backend did not confirm completion. Reconcile with status; never replay automatically.',
        {outcome: rejected ? 'rejected' : 'unknown', http_status: reply.status, server: reply.value});
    }
    const value = validateAction(reply.value, saved, action, commandId);
    if (value.ack !== 'completed') fail(value.ack === 'pending' ? 'command_pending' : value.ack === 'rejected' ? 'command_rejected' : 'command_outcome_unknown',
      'Control was not confirmed complete. Reconcile with status; never replay automatically.', {outcome: value.ack === 'outcome_unknown' ? 'unknown' : value.ack, response: value});
    return value;
  } catch (error) {
    const details = error instanceof Refusal ? error.details : {};
    throw new Refusal(details.outcome ? error.code : 'command_outcome_unknown',
      details.outcome ? error.message : 'Control outcome is unknown after dispatch. Reconcile with status; never replay automatically.',
      {...details, outcome: details.outcome || 'unknown', cause: error instanceof Refusal ? error.code : 'invalid_response', command: commandScope, retry_allowed: false});
  }
}

export async function main(argv) {
  if (argv.length === 1 && argv[0] === '--help') { process.stdout.write(usage); return; }
  try {
    const result = await execute(argv), output = JSON.stringify(result, null, 2) + '\n';
    if (Buffer.byteLength(output) > OUTPUT_LIMIT) fail('output_limit', 'Report exceeds 4 MiB; no partial report was emitted.');
    process.stdout.write(output);
  } catch (error) {
    const known = error instanceof Refusal;
    const result = {format: 'reb-vm-agent-error-v1', code: known ? error.code : 'invalid_input',
      message: known ? error.message : 'Input or response failed validation.', retry_allowed: false, ...(known ? error.details : {})};
    process.stderr.write(JSON.stringify(result) + '\n');
    process.exitCode = result.outcome === 'unknown' ? 3 : result.outcome === 'pending' ? 4 : 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main(process.argv.slice(2));
