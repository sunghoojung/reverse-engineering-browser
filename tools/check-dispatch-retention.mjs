// Execute only the repository-owned retention ledger, never captured source.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('./fixtures/dispatch-retention/',import.meta.url));
const ledger=JSON.parse(fs.readFileSync(path.join(root,'ledger.json'),'utf8'));
const reviews=ledger.review_case_files.flatMap(file=>JSON.parse(fs.readFileSync(path.join(root,file),'utf8')));
assert.equal(reviews.length,ledger.review_case_count,'Every judged review case must be loaded');
for(const row of [...ledger.cases, ...reviews]){
  const bytes = row.hex ? Buffer.from(row.hex, 'hex') : row.parts ? Buffer.from(row.parts.map(part => part.template
    ? Array.from({length: part.count}, (_, offset) => part.template.replaceAll('%i%', String(part.start + offset))
      .replaceAll('%mod%', String((part.start + offset) % part.modulus))).join('')
    : part.text.repeat(part.repeat)).join('')) : row.source !== undefined ? Buffer.from(row.source)
    : fs.readFileSync(path.join(root,row.file));
  if(row.sha256) assert.equal(createHash('sha256').update(bytes).digest('hex'), row.sha256, row.file);
  const source=bytes.toString('utf8');
  const context=vm.createContext({});
  let result;
  try{
    if(row.runtime.wasm){
      result={value:String(WebAssembly.validate(bytes))};
    }else if(/^(?:import|export)\b/m.test(source)||row.file.endsWith('/module_table.js')){
      const module=new vm.SourceTextModule(`${source}\nglobalThis.result=${row.runtime.call};`,{context});
      await module.link(()=>new vm.SourceTextModule('export const ops={};',{context}));
      await module.evaluate({timeout:1000});
      result={value:JSON.stringify(await context.result)??'undefined'};
    }else{
      result={value:JSON.stringify(await vm.runInContext(`${source}\n${row.runtime.call}`,context,{timeout:row.review_input?.startsWith('fuzz/')?100:1000}))??'undefined'};
    }
  }catch(error){result={error:error.name,message:error.message};}
  if(row.runtime.error){
    assert.equal(result.error,row.runtime.error,row.file);
    if(row.runtime.error==='Error')assert.equal(result.message,row.runtime.message,row.file);
  }else assert.equal(result.value,row.runtime.value,`${row.file}: ${JSON.stringify(result)}`);
}
console.log(`PASS ${ledger.cases.length + reviews.length} owned dispatch retention runtime judgments`);
