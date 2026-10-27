#!/usr/bin/env node
// Full shipped page with authored loopback responses; never native capture.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext, Script} from 'node:vm';
import ledgerModel from '../apps/research-ui/vm_opcode_ledger.js';
import staticModel from '../apps/research-ui/vm_static.js';
import staticView from '../apps/research-ui/vm_static_view.js';
import contextualEvidence from '../apps/research-ui/vm_contextual_evidence.js';

// Rendered VM composition is covered by `make rendered-ui-check` in the packaged
// app; this check takes no flags, so a stale or misspelled one fails loudly.
if (process.argv.length > 2) throw new Error(`Unexpected arguments: ${process.argv.slice(2).join(' ')}`);
import debuggerModel from '../apps/research-ui/vm_debugger.js';
import {recordCompatibilityDemo} from './generate-vm-compatibility-demo.mjs';
import {contextualFixture} from './check-vm-contextual-ui.mjs';

// Decode source literals without evaluating their contents. Compile the cooked
// browser expression: node --check alone cannot catch a second-level quote loss.
function readExpressionLiteral(source, start) {
  const quote = source[start]; let value = '', dynamic = false;
  for (let index = start + 1; index < source.length; index++) {
    const character = source[index];
    if (character === quote) return {value, dynamic, end: index + 1};
    if (quote === '`' && character === '$' && source[index + 1] === '{') dynamic = true;
    if (character !== '\\') { value += character; continue; }
    const escaped = source[++index];
    if (escaped === '\n') continue;
    if (escaped === '\r') { if (source[index + 1] === '\n') index++; continue; }
    if (escaped === 'x' || escaped === 'u') {
      const braced = escaped === 'u' && source[index + 1] === '{';
      const end = braced ? source.indexOf('}', index + 2) : index + (escaped === 'x' ? 2 : 4) + 1;
      const hex = source.slice(index + (braced ? 2 : 1), end);
      assert(/^[0-9a-f]+$/i.test(hex) && (braced || hex.length === (escaped === 'x' ? 2 : 4)), 'Invalid source literal escape');
      value += String.fromCodePoint(parseInt(hex, 16)); index = braced ? end : end - 1; continue;
    }
    assert(escaped !== undefined && !/[1-9]/.test(escaped) && !(escaped === '0' && /[0-9]/.test(source[index + 1] || '')), 'Unsupported source literal escape');
    value += ({n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', 0: '\0'})[escaped] ?? escaped;
  }
  throw Error('Unterminated source literal');
}
function compileLiteralEvaluations(source) {
  const calls = /\bevaluate\s*\(\s*(?=["'`])/g; let count = 0, call;
  while ((call = calls.exec(source))) {
    const literal = readExpressionLiteral(source, calls.lastIndex);
    if (!literal.dynamic && /^\s*[),]/.test(source.slice(literal.end))) {
      new Script(literal.value, {filename: 'full-shell-browser-expression-at-line-' + (source.slice(0, call.index).split('\n').length)});
      count++;
    }
    calls.lastIndex = literal.end;
  }
  return count;
}
const root = fileURLToPath(new URL('..', import.meta.url));
const output = process.env.REB_VM_FULL_SHELL_OUTPUT || join(root, 'build/vm-workspace-ui-qa/full-shell');
const html = await readFile(join(root, 'apps/research-ui/index.html'), 'utf8');
const model = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const fixture = JSON.parse(await readFile(join(root, 'tests/research_ui/fixtures/vm-opcode-workspace-v2.json'), 'utf8'));
const workspace = fixture.workspaces[0];
// Source-backed diagnostic copy, not runtime evidence. The Rust producer test
// separately validates the actual emitted no-samples workspace.
const opcodeSource = await readFile(join(root, 'apps/origin-trace-backend/src/vm_opcode.rs'), 'utf8');
const samplerDetail = opcodeSource.match(/"reason":"sampler-unavailable", "detail":\s*("[^"\n]+")/);
assert(samplerDetail, 'The no-samples producer diagnostic must be available to the UI regression');
const samplerOmission = {reason: 'sampler-unavailable', detail: JSON.parse(samplerDetail[1])};
assert(samplerOmission.detail.startsWith('No native dispatch samples were retained. Rebuild with native guest capture, enable an exact matching adapter, and inspect capture omissions.'), 'Observed missing samples must lead immediately into the native rebuild/adapter requirements, before secondary caveats');
assert(samplerOmission.detail.endsWith('Static dispatch, Canvas calls and snapshots alone do not prove a guest PC.'), 'Native adapter availability must not turn static evidence or snapshots alone into guest-PC proof');
assert(!samplerOmission.detail.includes('sampling is not implemented'), 'The no-samples state must not deny the implemented native adapter capture path');
assert(!samplerOmission.detail.includes('no guest dispatch emitter'), 'Missing samples must not deny caller-fed writer capability');
const analysis = {
  contract_version: 1, document_kind: 'vm-analysis', document_digest: fixture.analysis_digest,
  profile_digest: fixture.profile_digest, profile: {profile_id: 'anti-bot-vm-detection-v1'},
  input_coverage: {complete: false, omissions: ['Authored UI fixture, not a live capture.']},
  results: [{artifact_id: workspace.interpreter_artifact_id, artifact_sha256: workspace.source_artifact_sha256,
    finding_id: workspace.finding_id, runtime: 'javascript', status: 'partial', tier: 'candidate',
    vm_score: 20, anti_bot_score: 0, evidence_families: ['authored-dispatch'], related_request_ids: [],
    observations: [{rule_id: 'authored-fixture', family: 'authored-dispatch', weight: 20,
      coordinate: {byte_offset: 0, byte_size: 1}, detail: 'Authored retained-workspace fixture. No browser capture or guest execution.'}],
    coverage: {complete: false, residual_unknowns: ['Guest semantics remain unconfirmed.']}}],
  mixed_findings: [], opcode_workspace: fixture
};
assert(runInNewContext(`${model}\nisVmAnalysisDocument(analysis) && isVmOpcodeWorkspaceDocument(fixture)`, {analysis, fixture, TextEncoder}));
const noSamplerFixture = structuredClone(fixture), noSamplerWorkspace = noSamplerFixture.workspaces[0];
noSamplerWorkspace.runtime = 'webassembly'; noSamplerWorkspace.model = 'unknown';
noSamplerWorkspace.evidence_class = 'handler-table-candidate';
delete noSamplerWorkspace.machine_state;
noSamplerWorkspace.samples = []; noSamplerWorkspace.sample_count = noSamplerFixture.summary.sample_count = 0;
for (const handler of noSamplerWorkspace.handlers) {
  handler.sample_count = 0;
  if (handler.state === 'observed') handler.state = 'inferred';
}
noSamplerWorkspace.coverage.complete = false;
noSamplerWorkspace.coverage.omissions.push(samplerOmission);
noSamplerFixture.document_digest = 'b'.repeat(64);
assert(runInNewContext(`${model}\nisVmOpcodeWorkspaceDocument(noSamplerFixture)`, {noSamplerFixture, TextEncoder}));
const assets = new Set(['index.html', ...[...html.matchAll(/(?:src|href)="([^"/]+\.(?:js|css))"/g)].map(match => match[1])]);
const compareInputs = {};
for (const [key, name] of [['pack','pack.json'],['left','build-a.workspace.json'],['right','build-b.workspace.json']]) {
  compareInputs[key] = JSON.parse(await readFile(join(root, 'tools/fixtures/vm-analysis-packs', name), 'utf8'));
}
const compareRequest = {...compareInputs, left_artifact: '1', right_artifact: '1'};
const compareReport = {contract_version: 1, document_kind: 'vm-instruction-set-comparison', document_digest: 'a'.repeat(64),
  behavioral_equivalence_proven: false, rows: [
    {status: 'moved', match_basis: 'unique-exact-effect-shape', left: {opcode: 1}, right: {opcode: 4}},
    {status: 'unknown', match_basis: 'unmatched', left: {opcode: 2}, right: null}
  ], limitations: ['Authored presentation fixture; not actual backend analysis.']};
const executionTrace = recordCompatibilityDemo();
const staticInputs = staticView.vmStaticOwnedExample();
const staticReport = await staticModel.analyze(JSON.stringify(staticInputs.definition), JSON.stringify(staticInputs.image));
const contextualInputs = await contextualFixture();
const contextualReport = await contextualEvidence.link(...['definition','image','evidence'].map(kind => JSON.stringify(contextualInputs[kind])));
// Independent checked-in goldens are presentation inputs, not a completed
// command or a claim that this browser test ran the native helper.
const golden = JSON.parse(await readFile(join(root, 'tools/fixtures/owned-vm-golden-transitions-v1.json'), 'utf8')).register;
const liveRecords = golden.transitions.slice(0, 5).map((record, index) => ({...record, tick: String(index + 1)}));
const idleLiveView = {schema: 'reb-owned-vm-debug-session-v1', available: true, unavailable_reason: null,
  backend_instance_id: 'authored-shell-no-native-execution', session: null};
const populatedLiveView = {...idleLiveView, session: {
  backend_instance_id: idleLiveView.backend_instance_id, session_id: 'authored-golden-presentation',
  run_id: 'authored-golden-no-command', run_generation: '1', provider: 'live-owned-native-fixture',
  target_kind: 'owned_fixture', fixture: 'register', program_id: 'owned-register-v1', fixture_revision: 1,
  program_sha256: 'a'.repeat(64), program_manifest_scope: 'declared-two-program-manifest-sha256',
  build_id: null, build_id_scope: 'configured-helper-file-sha256', pc_units: 'instruction-index',
  value_semantics: 'unsigned-64-bit-bits', tick_units: 'monotonic-nanoseconds', state: 'paused',
  control_revision: '1', snapshot_revision: '1', executed_count: String(liveRecords.length), retained_count: String(liveRecords.length),
  execution_state_known: true, termination_reason: null, initial_snapshot: golden.initial, current_snapshot: liveRecords.at(-1).after,
  records: liveRecords, recorder: {session_id: '1', document_id: '2', invocation_id: '3', generation: '1',
    stats: Object.fromEntries(['attempted','recorded','full','malformed','wrong_document','stale_generation','exhausted','expired','partial']
      .map(key => [key, ['attempted','recorded'].includes(key) ? String(liveRecords.length) : '0']))},
  last_command: null, diagnostics: {stderr_bytes: '0', stderr_truncated: false}, disposal_failed: false
}};
assert.equal(staticReport.coverage.instruction_count, 16);
assert.equal(contextualReport.analysis.instructions.length, 3);
assert.equal(contextualReport.observed_edges.length, 1);
assert.equal(debuggerModel.ownedVmValidateView(populatedLiveView).session.records.length, 5);
let liveView = idleLiveView;
const requests = [];
const server = createServer(async (request, response) => {
  const path = request.url.split('?')[0];
  const json = value => { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(value)); };
  if (path.startsWith('/api/')) {
    requests.push({method: request.method, path});
    if (request.method === 'POST' && path === '/api/analysis/vm/packs/compare') {
      let body = ''; let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 1048576) { response.statusCode = 413; json({error: 'Fixture request bound exceeded'}); return; }
        body += chunk.toString('utf8');
      }
      try { assert.deepEqual(JSON.parse(body), compareRequest); }
      catch { response.statusCode = 422; json({error: 'Only the exact authored comparison inputs are accepted'}); return; }
      return json(compareReport);
    }
    if (request.method !== 'GET') { response.statusCode = 405; json({error: 'Read-only authored fixture'}); return; }
    if (path === '/api/events') return json({count: 0, events: [], capture_mode: 'demo', broker_connected: false, capture_stopped: true});
    if (path === '/api/artifacts') return json({count: 0, artifacts: []});
    if (path === '/api/vm-debugger') return json(liveView);
    if (path === '/api/analysis/vm') return json(analysis);
    if (path === '/api/analysis/vm/opcodes') return json(fixture);
    response.statusCode = 503; json({error: 'Unavailable in authored full-shell fixture'}); return;
  }
  const name = path === '/' ? 'index.html' : path.slice(1);
  if (!/^[a-z][a-z0-9_]*\.(?:html|js|css)$/.test(name) || !assets.has(name)) { response.writeHead(404).end(); return; }
  try {
    response.setHeader('content-type', name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html');
    response.end(await readFile(join(root, 'apps/research-ui', name)));
  } catch { response.writeHead(500).end(); }
});
{
  const brokenSelector = 'document.querySelectorAll("[data-vm-paged-rows="retained samples"] > details").length';
  assert.throws(() => compileLiteralEvaluations('evaluate(' + JSON.stringify(brokenSelector) + ')'), SyntaxError);
  assert.equal(compileLiteralEvaluations('evaluate("1 + 2"); evaluate(\'3 + 4\'); evaluate(`5 + 6`); evaluate(`${neverRun()}`);'), 3);
  assert.equal(readExpressionLiteral("'line\\n\\x41\\u0042\\u{43}'", 0).value, 'line\nABC');
  liveView = populatedLiveView;
  for (const [method, url, status] of [['GET', '/api/unavailable', 503], ['POST', '/api/analysis/vm', 405], ['GET', '/api/analysis/vm', 200], ['GET', '/api/vm-debugger', 200], ['POST', '/api/vm-debugger/actions', 405]]) {
    const response = {statusCode: 200, headersSent: false, headers: {},
      setHeader(name, value) { assert.equal(this.headersSent, false, 'Headers must precede body'); this.headers[name] = value; },
      writeHead(code) { this.statusCode = code; this.headersSent = true; },
      end(body) { this.headersSent = true; this.body = body; }};
    server.emit('request', {url, method}, response);
    assert.equal(response.statusCode, status);
    assert.equal(response.headers['content-type'], 'application/json');
    assert.doesNotThrow(() => JSON.parse(response.body));
    if (url === '/api/vm-debugger') assert.deepEqual(JSON.parse(response.body), populatedLiveView);
  }
  server.close();
  console.log("PASS full-shell literal-parser checks, authored HTTP contracts, populated native inputs and read-only refusal (not rendered)");
}
