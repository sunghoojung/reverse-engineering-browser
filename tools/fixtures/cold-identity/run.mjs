// Offline only. Compile the exact owned original source in an isolated realm.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createContext, Script } from 'node:vm';

const root = new URL('./', import.meta.url);
const repository = new URL('../../../', root);
const program = readFileSync(new URL('owned-program.js', root));
const exercise = readFileSync(new URL('exercise.js', root), 'utf8');
const manifestText = readFileSync(new URL('pairs.json', root), 'utf8');
const manifest = JSON.parse(manifestText);
const sha256 = value => createHash('sha256').update(value).digest('hex');
function verifyProgram(value) {
  assert.equal(value.length, manifest.programBytes, 'owned program byte length');
  assert.equal(sha256(value), manifest.programSha256, 'owned program SHA-256');
}
function verifyWasm(pair, value) {
  assert.equal(value.length, pair.wasmBytes, 'owned Wasm byte length');
  assert.equal(sha256(value), pair.wasmSha256, 'owned Wasm SHA-256');
}
assert.equal(manifest.schema, 'reb.owned-cold-identity-input.v1');
assert.equal(manifest.provenance, 'owned-synthetic');
assert.deepEqual(manifest.pairs.map(pair => pair.name), ['deferred', 'wasm-start']);
verifyProgram(program);
const changedProgram = Buffer.from(program);
changedProgram[0] ^= 1;
assert.throws(() => verifyProgram(changedProgram), /owned program SHA-256/);
for (const pair of manifest.pairs) {
  assert.match(pair.wasmHex, /^(?:[0-9a-f]{2})+$/);
  const value = Buffer.from(pair.wasmHex, 'hex');
  verifyWasm(pair, value);
  const changed = Buffer.from(value);
  changed[changed.length - 1] ^= 1;
  assert.throws(() => verifyWasm(pair, changed), /owned Wasm SHA-256/);
}
for (const [name, expected] of Object.entries(manifest.pins)) {
  assert.equal(readFileSync(new URL('browser/config/' + name, repository), 'utf8').trim(),
    expected, 'fixture engine pin drift: ' + name);
}

const output = [];
const context = createContext({
  read(path) {
    assert.equal(path, 'tools/fixtures/cold-identity/pairs.json');
    return manifestText;
  },
  print(value) { output.push(value); }
}, { codeGeneration: { strings: false, wasm: true } });
const source = new TextDecoder('utf-8', { fatal: true }).decode(program);
new Script(source, { filename: fileURLToPath(new URL('owned-program.js', root)) })
  .runInContext(context, { timeout: 1000 });
new Script(exercise, { filename: fileURLToPath(new URL('exercise.js', root)) })
  .runInContext(context, { timeout: 1000 });
assert.equal(output.length, 1);
const result = JSON.parse(output[0]);
assert.equal(result.casesPassed.length, 13);
console.log(JSON.stringify({ ...result,
  engine: { host: 'node-vm', node: process.versions.node, v8: process.versions.v8 },
  exactOwnedInputsChecked: true,
  alteredProgramAndWasmRefused: true,
  programSha256: manifest.programSha256,
  pairs: manifest.pairs.map(({ name, wasmSha256 }) => ({ name, wasmSha256 }))
}, null, 2));
