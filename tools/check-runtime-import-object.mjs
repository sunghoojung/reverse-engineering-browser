// Authored Wasm plus real V8 descriptor semantics, not a browser/Brave acceptance claim.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import inspector from 'node:inspector';
import vm from 'node:vm';

const source = await readFile(new URL('../apps/runtime-hook-demo/imports.js', import.meta.url), 'utf8');
const controls = new Map(['#inspect', '#run', '#result'].map(id => [id, {textContent: '', addEventListener(type, callback) {this[type] = callback;}}]));
const context = vm.createContext({document: {querySelector: selector => controls.get(selector)}});
const session = new inspector.Session();
session.connect();
// In-process inspector callbacks must finish synchronously while paused.
function post(method, params = {}) {
  let reply, error, returned = false;
  session.post(method, params, (failure, result) => {error = failure; reply = result; returned = true;});
  assert(returned, 'The in-process inspector command must complete synchronously');
  if (error) throw error;
  return reply;
}
let observed = null, failure = null;
const scripts = new Map();
session.on('Debugger.scriptParsed', ({params}) => scripts.set(params.scriptId, params));
session.on('Debugger.paused', ({params}) => {
  try {
    assert.equal(params.callFrames[0].functionName, 'createOwnedModule');
    const local = params.callFrames[0].scopeChain.find(scope => scope.type === 'local');
    const get = id => post('Runtime.getProperties', {objectId: id, ownProperties: true, accessorPropertiesOnly: false, generatePreview: false});
    const binding = get(local.object.objectId).result.find(property => property.name === 'imports');
    assert.equal(binding.value.type, 'object');
    const namespaces = get(binding.value.objectId).result;
    assert.equal(namespaces.find(property => property.name === 'accessorNamespace').get.type, 'function');
    assert.equal(namespaces.find(property => property.name === 'proxyNamespace').value.subtype, 'proxy');
    // No property query on either of those objects and no getter evaluation.
    const env = namespaces.find(property => property.name === 'env');
    const clock = get(env.value.objectId).result.find(property => property.name === 'clock');
    assert.equal(clock.value.type, 'function');
    const metadata = get(clock.value.objectId);
    assert.equal(metadata.result.find(property => property.name === 'name').value.value, 'ownedClock');
    const location = metadata.internalProperties.find(property => property.name === '[[FunctionLocation]]').value.value;
    assert.equal(scripts.get(location.scriptId).url, 'owned-imports-fixture.js');
    assert(source.split('\n')[location.lineNumber].includes('ownedClock'));
    observed = {module: env.name, name: clock.name, location};
    post('Debugger.resume');
  } catch (error) { failure = error; }
});
try {
  post('Debugger.enable');
  vm.runInContext(source, context, {filename: 'owned-imports-fixture.js'});
  const imports = JSON.parse(vm.runInContext('JSON.stringify(WebAssembly.Module.imports(new WebAssembly.Module(ownedModuleBytes)))', context));
  assert.deepEqual(imports, [{module: 'env', name: 'clock', kind: 'function'}]);
  controls.get('#inspect').click();
  if (failure) throw failure;
  assert(observed, 'The explicit owned pause must expose the import binding');
  assert.equal(observed.module, 'env'); assert.equal(observed.name, 'clock');
  controls.get('#run').click();
  assert.equal(vm.runInContext('calls', context), 1);
  assert.equal(vm.runInContext('unexpectedInspection', context), 0);
  assert.match(controls.get('#result').textContent, /env.clock returned 1; unexpected getters\/proxy traps: 0/);
} finally { session.disconnect(); }
console.log('PASS owned Wasm import fixture: actual V8 own descriptors/function location, static env.clock identity, benign Wasm call and zero getter/proxy traps (not browser acceptance)');
