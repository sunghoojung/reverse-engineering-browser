// Execute only the repository-owned retention ledger, never captured source.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('./fixtures/dispatch-retention/',import.meta.url));
const ledger=JSON.parse(fs.readFileSync(path.join(root,'ledger.json'),'utf8'));
function literalPart(part) {
  let state = part.seed;
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  return Array.from({length: part.count}, () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return alphabet[state >>> 26];
  }).join('');
}
function generatedSource(row) {
  const source = Buffer.from(ledger.sources[row.source_ref]);
  const chunks = [];
  let cursor = 0;
  for (const [offset, length, text] of row.edits ?? []) {
    chunks.push(source.subarray(cursor, offset), Buffer.from(text));
    cursor = offset + length;
  }
  return Buffer.concat([...chunks, source.subarray(cursor), Buffer.from(row.mutation === undefined ? '' : `\n/* unique ${row.mutation} */`)]);
}
for(const row of [...ledger.cases, ...(ledger.review_cases ?? [])]){
  const bytes = row.source_ref ? generatedSource(row) : row.hex ? Buffer.from(row.hex, 'hex') : row.parts ? Buffer.from(row.parts.map(part => part.seed !== undefined ? literalPart(part) : part.template
    ? Array.from({length: part.count}, (_, offset) => part.template.replaceAll('%i%', String(part.start + offset))
      .replaceAll('%mod%', String((part.start + offset) % part.modulus))).join('')
    : part.text.repeat(part.repeat)).join('')) : row.source !== undefined ? Buffer.from(row.source)
    : fs.readFileSync(path.join(root,row.file));
  if(row.sha256) assert.equal(createHash('sha256').update(bytes).digest('hex'), row.sha256, row.file);
  const runtime = ledger.runtime_observations[row.runtime_ref];
  const call = ledger.runtime_calls[runtime.call_ref];
  const source=bytes.toString('utf8');
  const context=vm.createContext({});
  let result;
  try{
    if(runtime.wasm){
      result={value:String(WebAssembly.validate(bytes))};
    }else if(/^(?:import|export)\b/m.test(source)||row.file.endsWith('/module_table.js')){
      const module=new vm.SourceTextModule(`${source}\nglobalThis.result=${call};`,{context});
      await module.link(()=>new vm.SourceTextModule('export const ops={};',{context}));
      await module.evaluate({timeout:1000});
      result={value:JSON.stringify(await context.result)??'undefined'};
    }else{
      result={value:JSON.stringify(await vm.runInContext(`${source}\n${call}`,context,{timeout:row.file.includes('/fuzz/')?100:1000}))??'undefined'};
    }
  }catch(error){result={error:error.name,message:error.message};}
  if(runtime.error){
    assert.equal(result.error,runtime.error,row.file);
    if(runtime.error==='Error')assert.equal(result.message,runtime.message,row.file);
  }else assert.equal(result.value,runtime.value,`${row.file}: ${JSON.stringify(result)}`);
}
console.log(`PASS ${ledger.cases.length + (ledger.review_cases?.length ?? 0)} owned dispatch retention runtime judgments`);
