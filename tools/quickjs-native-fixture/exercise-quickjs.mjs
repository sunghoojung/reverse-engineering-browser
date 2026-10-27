// Normal interpreter execution only; no debugger, memory inspection or sampling.
import {newQuickJSWASMModuleFromVariant} from 'quickjs-emscripten-core';
import variant from '@jitl/quickjs-wasmfile-debug-sync';
const QuickJS=await newQuickJSWASMModuleFromVariant(variant),vm=QuickJS.newContext(),calls=[];
const host=vm.newFunction('hostProbe',value=>{calls.push(vm.getNumber(value));});
vm.setProp(vm.global,'hostProbe',host);host.dispose();
const result=vm.evalCode("function visit(n){for(let i=0;i<n;i++){if((i&1)===0)hostProbe(100+i);else hostProbe(200+i);}} visit(4);visit(4);'complete';",'reb-public-quickjs-acceptance.js');
if(result.error){const error=vm.dump(result.error);result.error.dispose();vm.dispose();throw new Error(JSON.stringify(error));}
const value=vm.dump(result.value);result.value.dispose();vm.dispose();
if(value!=='complete'||JSON.stringify(calls)!==JSON.stringify([100,201,102,203,100,201,102,203]))throw new Error('Target mismatch');
console.log(JSON.stringify({value,calls,target:'QuickJS 0.32.0 debug-sync',native_capture_validated:false}));
