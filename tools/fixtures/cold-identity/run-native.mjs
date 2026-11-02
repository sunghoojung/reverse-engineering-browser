// Offline failing-closed stub, not an engine launcher or a native adapter.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createContext, Script } from 'node:vm';

const root = new URL('./', import.meta.url);
const repository = new URL('../../../', root);
const program = readFileSync(new URL('owned-program.js', root));
const exercise = readFileSync(new URL('native-exercise.js', root), 'utf8');
const manifestText = readFileSync(new URL('pairs.json', root), 'utf8');
const manifest = JSON.parse(manifestText);
const sha256 = value => createHash('sha256').update(value).digest('hex');
// Keep BS's portable entrypoint and original input bytes unchanged. Check the
// same exact inputs here before the separate native acceptance entrypoint.
assert.equal(manifest.schema, 'reb.owned-cold-identity-input.v1');
assert.equal(manifest.provenance, 'owned-synthetic');
assert.equal(program.length, manifest.programBytes);
assert.equal(sha256(program), manifest.programSha256);
assert.deepEqual(manifest.pairs.map(pair => pair.name), ['deferred', 'wasm-start']);
for (const pair of manifest.pairs) {
  assert.match(pair.wasmHex, /^(?:[0-9a-f]{2})+$/);
  const bytes = Buffer.from(pair.wasmHex, 'hex');
  assert.equal(bytes.length, pair.wasmBytes);
  assert.equal(sha256(bytes), pair.wasmSha256);
}
for (const [name, expected] of Object.entries(manifest.pins)) {
  assert.equal(readFileSync(new URL('browser/config/' + name, repository), 'utf8').trim(),
    expected, 'fixture engine pin drift: ' + name);
}
const source = new TextDecoder('utf-8', { fatal: true }).decode(program);
const original = new Script(source, { filename: fileURLToPath(new URL('owned-program.js', root)) });
const nativeTest = new Script(exercise, { filename: fileURLToPath(new URL('native-exercise.js', root)) });
let result;
for (const mode of ['missing-host', 'accessor-host', 'incomplete-host']) {
  const output = [];
  let exitStatus = null;
  let getterCalls = 0;
  const globals = {
    read(path) {
      assert.equal(path, 'tools/fixtures/cold-identity/pairs.json');
      return manifestText;
    },
    print(value) { output.push(value); },
    quit(code) { exitStatus = code; }
  };
  if (mode === 'accessor-host') {
    Object.defineProperty(globals, '__rebColdIdentityNativeTest', {
      get() { ++getterCalls; throw new Error('must not invoke native host getter'); }
    });
  } else if (mode === 'incomplete-host') {
    globals.__rebColdIdentityNativeTest = Object.freeze({});
  }
  const context = createContext(globals, { codeGeneration: { strings: false, wasm: true } });
  original.runInContext(context, { timeout: 1000 });
  nativeTest.runInContext(context, { timeout: 1000 });
  assert.equal(exitStatus, 78, 'missing native support must not pass');
  assert.equal(getterCalls, 0);
  assert.equal(output.length, 1);
  const observed = JSON.parse(output[0]);
  assert.equal(observed.status, mode === 'missing-host'
    ? 'BLOCKED_NATIVE_COLD_ID_API_UNAVAILABLE' : 'BLOCKED_NATIVE_COLD_ID_TEST_HOST_UNSUPPORTED');
  assert.equal(observed.coldInstanceConstructed, true);
  assert.equal(observed.fixtureMutations, 0, 'native unavailability must leave instance cold');
  assert.deepEqual(observed.nativeTestHostAssertionsCompleted, []);
  for (const flag of ['nativeInstanceIdTested', 'pinnedEngineVerified', 'nativeOriginalSitesTested',
    'browserLifecycleTested', 'originalBoundaryTransportAvailable', 'liveJoinTested', 'parity',
    'rawRenderingParity', 'productionProof']) assert.equal(observed[flag], false);
  assert.equal(observed.nativeCoverage, null);
  assert.equal(observed.deterministicJoins, 0);
  if (mode === 'missing-host') result = observed;
}
console.log(JSON.stringify({ ...result,
  engine: { host: 'node-vm-no-native-test-host', node: process.versions.node, v8: process.versions.v8 },
  exactOwnedInputsChecked: true,
  offlineRefusalChecks: ['missing-host', 'accessor-host', 'incomplete-host']
}, null, 2));
// Deliberately unavailable, even though the offline refusal assertions passed.
process.exitCode = 78;
