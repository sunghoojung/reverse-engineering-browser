import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';

// Execute production capability and chain functions with authored inputs. DOM
// rendering is stubbed: this is not a rendered or macOS acceptance receipt.
export async function checkMagicDecoderUI(run) {
  const source = async name => readFile(new URL('../' + name, import.meta.url), 'utf8');
  const app = await source('apps/research-ui/app.js');
  function section(start, end) {
    const first = app.indexOf(start), last = app.indexOf(end, first);
    assert(first >= 0 && last > first, `Production function section: ${start}`);
    return app.slice(first, last);
  }
  const rust = (await source('apps/origin-trace-backend/src/decoder.rs'))
    .match(/const OPERATIONS: \[&str; (\d+)\] = \[([\s\S]*?)\];/);
  assert(rust);
  const strings = text => [...text.matchAll(/"([^"]+)"/g)].map(match => match[1]);
  const operations = strings(rust[2]);
  assert.equal(operations.length, Number(rust[1]));
  assert.equal(new Set(operations).size, operations.length);
  const swift = (await source('apps/research-ui/macos/DecoderService.swift'))
    .match(/private static let operations = \[([\s\S]*?)\]/);
  assert(swift);
  assert.deepEqual(strings(swift[1]), operations, 'Swift and Rust capability order');
  const cpp = (await source('src/analysis/decoder.cpp'))
    .match(/DecoderOperation>, (\d+)> kOperations = \{\{([\s\S]*?)\}\};/);
  assert(cpp);
  assert.equal(Number(cpp[1]), operations.length);
  assert.deepEqual(strings(cpp[2]), operations, 'C++ and Rust capability order');
  const schema = JSON.parse(await source('protocol/openapi.json'));
  const transform = schema.components.schemas.DecoderAction.oneOf
    .find(action => action.properties.action.const === 'transform');
  assert.deepEqual(transform.properties.operation.enum, operations, 'OpenAPI operations');
  const html = await source('apps/research-ui/index.html');
  const menu = html.match(/<select id="decoder-operation"[^>]*>([\s\S]*?)<\/select>/);
  assert(menu);
  const menuOperations = [...menu[1].matchAll(/<option value="([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual([...menuOperations].sort(), [...operations, 'html-encode', 'html-decode'].sort());
  const identityGroup = menu[1].match(/<optgroup label="Identify and hash">([\s\S]*?)<\/optgroup>/);
  assert(identityGroup);
  assert.deepEqual([...identityGroup[1].matchAll(/value="([^"]+)"/g)].map(match => match[1]),
    ['magic-inspect', 'sha256', 'sha384', 'sha512']);

  const state = {decoderPending: false, decoderSteps: [], decoderSelectedStepId: null,
    decoderInputSnapshot: null, decoderNextOperationId: 1, decoderEngine: {available: true}};
  const toolsElements = {input: {value: 'deadbeef'}, inputEncoding: {value: 'text'},
    operation: {value: 'magic-inspect'}};
  const calls = [];
  const ui = runInNewContext(
    section('      const decoderNativeOperations =', '      function isJwtInspection') +
    section('      function decoderBytesToBase64', '      async function refreshDecoderEngine') +
    section('      async function appendDecoderTransform()', '      function decoderHexDump') +
    ';({isDecoderEngine, appendDecoderTransform})', {
      state, toolsElements, TextEncoder, TextDecoder, atob, btoa,
      isPlainObject: value => value !== null && typeof value === 'object' && !Array.isArray(value),
      isSafeIntegerInRange: (value, minimum, maximum) => Number.isSafeInteger(value) && value >= minimum && value <= maximum,
      renderTools() {}, formatByteSize: value => `${value} bytes`,
      fetch: async (url, options) => {
        assert.equal(url, '/api/decoder/actions'); assert.equal(options.method, 'POST');
        const request = JSON.parse(options.body), input = Buffer.from(request.input_base64, 'base64');
        calls.push(request);
        const result = run(request.operation, input);
        if (result.status !== 0) return {ok: false, json: async () => ({error: 'Authored malformed input rejected'})};
        const bytes = Buffer.from(result.stdout);
        return {ok: true, json: async () => ({protocol_version: 1, ok: true,
          operation_id: request.operation_id, operation: request.operation,
          input_bytes: input.length, output_bytes: bytes.length, output_base64: bytes.toString('base64'),
          utf8_text: bytes.toString('utf8'), hex_preview: bytes.subarray(0, 256).toString('hex'),
          preview_truncated: bytes.length > 256, duration_us: 1})};
      },
    });
  const engine = {protocol_version: 1, available: true, busy: false, limits: {
    input_bytes: 1048576, output_bytes: 1048576, pipeline_steps: 16, retained_bytes: 4194304,
    jwt_bytes: 65536, secret_bytes: 4096, json_depth: 64, json_tokens: 100000,
    timeout_ms: 2000, operations, jwt_algorithms: ['HS256', 'HS384', 'HS512', 'none'],
  }};
  assert(ui.isDecoderEngine(engine));
  for (const changed of [operations.slice(0, -1), [...operations, 'invented'],
    [...operations.slice(0, -1), operations[0]]]) {
    assert.equal(ui.isDecoderEngine({...engine, limits: {...engine.limits, operations: changed}}), false);
  }
  assert.equal(calls.length, 0, 'Selecting Magic never automatically runs a transform');
  await ui.appendDecoderTransform();
  assert.equal(calls.length, 1); assert.equal(state.decoderSteps.length, 1);
  const snapshot = {...state.decoderInputSnapshot}, magicStep = state.decoderSteps[0];
  assert.equal(snapshot.base64, Buffer.from('deadbeef').toString('base64'));
  const report = JSON.parse(magicStep.utf8_text);
  assert.equal(report.automatic_transforms, 0); assert.equal(report.meaning_verified, false);
  assert.equal(toolsElements.input.value, 'deadbeef');
  // Failure after a report retains the source, successful step and selection.
  toolsElements.operation.value = 'base64-decode';
  await ui.appendDecoderTransform();
  assert.equal(state.decoderStatus, 'error'); assert.equal(state.decoderSteps.length, 1);
  assert.equal(state.decoderSteps[0], magicStep); assert.equal(state.decoderSelectedStepId, magicStep.id);
  assert.deepEqual({...state.decoderInputSnapshot}, snapshot);
  // An explicit SHA step on the selected report hashes the report, not a guess.
  toolsElements.operation.value = 'sha256';
  await ui.appendDecoderTransform();
  assert.equal(state.decoderSteps.length, 2);
  assert.equal(state.decoderSteps[1].utf8_text,
    createHash('sha256').update(Buffer.from(magicStep.output_base64, 'base64')).digest('hex'));
  assert.equal(state.decoderSteps[0], magicStep);
  // Explicitly selecting the root branches from the original exact bytes.
  state.decoderSelectedStepId = null; toolsElements.operation.value = 'sha512';
  await ui.appendDecoderTransform();
  assert.equal(state.decoderSteps.length, 1);
  assert.equal(state.decoderSteps[0].utf8_text, createHash('sha512').update('deadbeef').digest('hex'));
  assert.deepEqual({...state.decoderInputSnapshot}, snapshot);
  const completed = state.decoderSteps[0], requestCount = calls.length;
  toolsElements.input.value = 'changed input';
  await ui.appendDecoderTransform();
  assert.equal(calls.length, requestCount); assert.equal(state.decoderSteps[0], completed);
  assert.match(state.decoderMessage, /Input changed/);
  toolsElements.input.value = 'deadbeef'; state.decoderEngine.available = false;
  await ui.appendDecoderTransform();
  assert.equal(calls.length, requestCount); assert.equal(state.decoderSteps[0], completed);
  assert.match(state.decoderMessage, /unavailable/);
  console.log('PASS exact C++/Rust/Swift/UI/OpenAPI operation parity and production chain: explicit-only Magic, preserved root/history, failed-step retention, report-byte hashing, explicit branching and unavailable/changed-input refusal (not rendered QA)');
}
