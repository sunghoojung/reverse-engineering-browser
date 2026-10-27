// Ordinary loader/program only. All guest-state observation is in the C++ test.
import {newQuickJSWASMModuleFromVariant} from 'quickjs-emscripten-core';
import {QuickJSFFI} from '@jitl/quickjs-wasmfile-debug-sync/ffi';
import loadModule from '@jitl/quickjs-wasmfile-debug-sync/emscripten-module';
import sourceMap from './node_modules/@jitl/quickjs-wasmfile-debug-sync/dist/emscripten-module.wasm.map' with {type: 'json'};

globalThis.window = {};
globalThis.console ??= {log() {}, error() {}, warn() {}};
// Browser glue requests its official source map. There is no network in cctest.
globalThis.fetch = async url => {
  if (url !== 'emscripten-module.wasm.map') throw new Error(`Unexpected resource: ${url}`);
  return {json: async () => sourceMap};
};
globalThis.rebPublicQuickJSDone = false;
globalThis.rebPublicQuickJSError = '';
(async () => {
  const variant = {
    type: 'sync',
    importFFI: async () => QuickJSFFI,
    importModuleLoader: async () => options => loadModule({
      ...options,
      locateFile: name => name,
      instantiateWasm(imports, receiveInstance) {
        const module = new WebAssembly.Module(globalThis.rebPublicQuickJSWasm);
        const instance = new WebAssembly.Instance(module, imports);
        receiveInstance(instance, module);
        return instance.exports;
      },
    }),
  };
  const QuickJS = await newQuickJSWASMModuleFromVariant(variant);
  const vm = QuickJS.newContext();
  const host = vm.newFunction('hostProbe', value => {
    // This enters C++ while the actual qts_host_call_function import is live.
    globalThis.rebNativeHostProbe(vm.getNumber(value));
  });
  vm.setProp(vm.global, 'hostProbe', host);
  host.dispose();
  const result = vm.evalCode("function visit(n){for(let i=0;i<n;i++){if((i&1)===0)hostProbe(100+i);else hostProbe(200+i);}} visit(4);visit(4);'complete';", 'reb-public-quickjs-acceptance.js');
  try {
    if (result.error) {
      const message = JSON.stringify(vm.dump(result.error));
      result.error.dispose();
      throw new Error(message);
    }
    const value = vm.dump(result.value);
    result.value.dispose();
    if (value !== 'complete') throw new Error('Unexpected guest result');
  } finally {
    vm.dispose();
  }
  globalThis.rebPublicQuickJSDone = true;
})().catch(error => { globalThis.rebPublicQuickJSError = String(error.stack || error); });
