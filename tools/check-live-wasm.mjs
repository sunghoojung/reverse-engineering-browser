// Real local V8 inspector + production target-side helper. No browser/site access.
import assert from 'node:assert/strict';
import {Session} from 'node:inspector';
import {readFile} from 'node:fs/promises';
const session=new Session();session.connect();
const call=(method,params={})=>new Promise((resolve,reject)=>session.post(method,params,(e,r)=>e?reject(e):resolve(r)));
const bounded=await readFile(new URL('../apps/origin-trace-backend/assets/live-wasm-list.js',import.meta.url),'utf8');
const slice=await readFile(new URL('../apps/origin-trace-backend/assets/live-wasm-slice.js',import.meta.url),'utf8');
try {
 globalThis.rebOwnedWasm={module:new WebAssembly.Module(new Uint8Array([0,97,115,109,1,0,0,0,5,3,1,0,1,7,10,1,6,109,101,109,111,114,121,2,0]))};
 rebOwnedWasm.instance=new WebAssembly.Instance(rebOwnedWasm.module);rebOwnedWasm.memory=rebOwnedWasm.instance.exports.memory;
 new Uint8Array(rebOwnedWasm.memory.buffer).set([17,33,65,129]);
 globalThis.rebOwnedMemories=Array.from({length:40},()=>new WebAssembly.Memory({initial:1}));
 const handles={};
 for(const [kind,constructor] of [['instance','Instance'],['module','Module'],['memory','Memory']]){
  const proto=await call('Runtime.evaluate',{expression:`WebAssembly.${constructor}.prototype`,objectGroup:'reb-owned-wasm'});
  const found=await call('Runtime.queryObjects',{prototypeObjectId:proto.result.objectId,objectGroup:'reb-owned-wasm'});
  const limited=await call('Runtime.callFunctionOn',{objectId:found.objects.objectId,functionDeclaration:bounded,objectGroup:'reb-owned-wasm'});
  const props=await call('Runtime.getProperties',{objectId:limited.result.objectId,ownProperties:true});assert(props.result.some(p=>p.value?.className===constructor));
  assert(props.result.length<=33);if(kind==='memory')assert.equal(props.result.filter(p=>p.name!=='length').length,32);
  for(const objectId of [proto.result.objectId,found.objects.objectId,limited.result.objectId])await call('Runtime.releaseObject',{objectId});
  const retained=props.result.find(p=>p.value?.className===constructor).value.objectId;
  assert((await call('Runtime.getProperties',{objectId:retained,ownProperties:true})).result);
  handles[kind]=(await call('Runtime.evaluate',{expression:`rebOwnedWasm.${kind}`,objectGroup:'reb-owned-wasm'})).result.objectId;
 }
 const read=async(kind,exportName,offset,length)=>(await call('Runtime.callFunctionOn',{objectId:handles[kind],functionDeclaration:slice,arguments:[kind,exportName,offset,length].map(value=>({value})),returnByValue:true}));
 for(const kind of ['instance','memory']){const r=await read(kind,kind==='instance'?'memory':null,0,4);assert.deepEqual(r.result.value.bytes,[17,33,65,129]);assert.equal(r.result.value.byte_length,65536);}
 for(const args of [['memory',null,-1,1],['memory',null,0,4097],['memory',null,65535,2],['instance','missing',0,1],['module',null,0,1]])assert((await read(...args)).exceptionDetails);
 rebOwnedWasm.memory.grow(1);assert.equal((await read('memory',null,65536,1)).result.value.byte_length,131072);
 await call('Runtime.releaseObjectGroup',{objectGroup:'reb-owned-wasm'});await assert.rejects(read('memory',null,0,1));
 console.log('PASS live Wasm: actual V8 prototype queries and bounded memory/export reads; missing export, bounds, growth, stale handles');
} finally {delete globalThis.rebOwnedWasm;delete globalThis.rebOwnedMemories;session.disconnect();}
