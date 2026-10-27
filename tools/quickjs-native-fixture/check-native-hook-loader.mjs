// Prerequisite only: ordinary loading/program behavior in a bare JS context.
// This cannot establish native capture, even when its host-call assertions pass.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createContext, runInContext} from 'node:vm';
import path from 'node:path';
const directory = path.resolve(process.argv[2]);
const calls = [];
const context = createContext({
  rebPublicQuickJSWasm: await readFile(path.join(directory, 'quickjs.wasm')),
  rebNativeHostProbe: value => calls.push(value),
});
runInContext(await readFile(path.join(directory, 'quickjs-native-hook.js'), 'utf8'), context, {timeout: 10000});
const deadline = Date.now() + 10000;
while (!context.rebPublicQuickJSDone && !context.rebPublicQuickJSError && Date.now() < deadline) {
  await new Promise(resolve => setTimeout(resolve, 10));
}
assert.equal(context.rebPublicQuickJSError, '');
assert.equal(context.rebPublicQuickJSDone, true);
assert.deepEqual(calls, [100, 201, 102, 203, 100, 201, 102, 203]);
console.log(JSON.stringify({target: 'public-quickjs-0.32.0', loader_validated: true, native_capture_validated: false, calls}));
