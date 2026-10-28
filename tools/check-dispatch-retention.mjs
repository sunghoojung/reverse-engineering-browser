// Execute only the repository-owned retention ledger, never captured source.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('./fixtures/dispatch-retention/',import.meta.url));
const ledger=JSON.parse(fs.readFileSync(path.join(root,'ledger.json'),'utf8'));
for(const row of ledger.cases){
  const source=fs.readFileSync(path.join(root,row.file),'utf8');
  const context=vm.createContext({});
  let result;
  try{
    if(/^(?:import|export)\b/m.test(source)||row.file.endsWith('/module_table.js')){
      const module=new vm.SourceTextModule(`${source}\nglobalThis.result=${row.runtime.call};`,{context});
      await module.link(()=>new vm.SourceTextModule('export const ops={};',{context}));
      await module.evaluate({timeout:1000});
      result={value:JSON.stringify(await context.result)??'undefined'};
    }else{
      result={value:JSON.stringify(await vm.runInContext(`${source}\n${row.runtime.call}`,context,{timeout:1000}))??'undefined'};
    }
  }catch(error){result={error:error.name,message:error.message};}
  if(row.runtime.error){
    assert.equal(result.error,row.runtime.error,row.file);
    if(row.runtime.error==='Error')assert.equal(result.message,row.runtime.message,row.file);
  }else assert.equal(result.value,row.runtime.value,`${row.file}: ${JSON.stringify(result)}`);
}
console.log(`PASS ${ledger.cases.length} owned dispatch retention runtime judgments`);
