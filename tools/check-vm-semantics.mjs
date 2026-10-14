#!/usr/bin/env node
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {mkdtemp,writeFile,readFile,rm,stat,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import vm from '../apps/research-ui/vm_semantics.js';
import client from '../apps/research-ui/captured_client.js';
import {runInNewContext} from 'node:vm';
const copy=x=>JSON.parse(JSON.stringify(x));
const initial=()=>({pc:0,halted:false,registers:[0,0,0],stack:[],memory:[]});
// Independently authored tiny interpreters. No call to vm.predict when generating evidence.
function fixture(architecture) {
 const program=architecture==='stack'?[[1,7],[1,8],[2],[9]]:[[3,0,7],[3,1,8],[4,2,0,1],[5,42,2],[6,0,42],[3,1,0],[7,1,8],[3,0,99],[8,10],[3,0,99],[9]];
 const steps=[],state=initial();let sequence=0;
 while(!state.halted){assert(sequence<32);const before=copy(state),instruction=program[state.pc],op=instruction[0],a=instruction.slice(1);state.pc++;
  switch(op){case 1:state.stack.push(a[0]);break;case 2:{const right=state.stack.pop(),left=state.stack.pop();state.stack.push((left+right)|0);break;}case 3:state.registers[a[0]]=a[1];break;case 4:state.registers[a[0]]=(state.registers[a[1]]+state.registers[a[2]])|0;break;case 5:state.memory=[[a[0],state.registers[a[1]]]];break;case 6:state.registers[a[0]]=state.memory.find(c=>c[0]===a[1])[1];break;case 7:if(state.registers[a[0]]===0)state.pc=a[1];break;case 8:state.pc=a[0];break;case 9:state.pc=before.pc;state.halted=true;break;default:throw Error('Fixture opcode');}
  steps.push({sequence:sequence++,opcode:op.toString(16).padStart(2,'0'),operands:a,instruction_size:1,before,after:copy(state),evidence_refs:['toy:step:'+sequence]});
 }
 return {format:'reb-vm-trace-v1',identity:{trace_id:'toy:'+architecture,investigation_id:'1',finding_id:'2',artifact_id:'3',artifact_sha256:'a'.repeat(64),scope_id:'owned-toy',backend:'fixture'},architecture,coverage:{complete:true,dropped_steps:0,limitations:['Owned interpreter fixture, not a captured website']},steps};
}
const mappings=[['01','stack_const'],['02','stack_add'],['03','register_const'],['04','register_add'],['05','store'],['06','load'],['07','branch_zero'],['08','jump'],['09','halt']];
for(const arch of ['stack','register']){
 const trace=fixture(arch),mapping=mappings.filter(([opcode])=>trace.steps.some(s=>s.opcode===opcode)).map(([opcode,operation])=>({opcode,operation}));
 const hypotheses={format:'reb-vm-hypothesis-v1',trace_id:trace.identity.trace_id,mappings:mapping};
 const report=vm.validate(trace,hypotheses);assert(report.results.every(x=>x.status==='matched'));assert.equal(report.equivalence_proven,false);
 const inspection=vm.inspect(trace);for(const m of mapping)assert(inspection.opcodes.find(x=>x.opcode===m.opcode).candidates.includes(m.operation));
 assert.equal(inspection.reads,'unknown; snapshots establish differences only');assert(inspection.steps.some(x=>x.changes.length));
 const wrong=copy(hypotheses);wrong.mappings[0].operation='halt';assert(vm.validate(trace,wrong).results.some(x=>x.status==='unsupported'||x.status==='contradicted'));
 const unknown=copy(trace);unknown.steps=[unknown.steps.at(-1)];unknown.steps[0].opcode='ff';assert.equal(vm.validate(unknown,{...hypotheses,mappings:[]}).results[0].status,'unknown');
 const reordered=copy(trace);reordered.steps[0].before=Object.fromEntries(Object.entries(reordered.steps[0].before).reverse());assert(vm.validate(reordered,hypotheses).results.every(x=>x.status==='matched'));
 for(const mutate of [v=>v.steps[0].before.registers.push(1.5),v=>v.steps[0].opcode='<script>',v=>v.steps[0].before.memory=[[1,2],[1,3]],v=>v.steps[1].sequence=0,v=>v.steps[1].before.pc=123,v=>v.coverage.dropped_steps=1,v=>v.identity.artifact_sha256='bad',v=>v.steps[0].extra=true,v=>v.steps[0].before.halted=true]){const bad=copy(trace);mutate(bad);assert.throws(()=>vm.trace(bad));}
 const gap=copy(trace);gap.steps=gap.steps.filter((_,i)=>i!==1);assert.throws(()=>vm.trace(gap));gap.coverage.complete=false;gap.coverage.dropped_steps=1;assert(vm.trace(gap));
 assert.throws(()=>vm.validate(trace,{...hypotheses,trace_id:'wrong'}));assert.throws(()=>vm.validate(trace,{...hypotheses,mappings:[mapping[0],mapping[0]]}));
}
const reg=fixture('register'),missing=copy(reg.steps.find(s=>s.opcode==='06'));missing.before.memory=[];assert.throws(()=>vm.predict(missing,'load','register'));
const over=copy(fixture('stack').steps.find(s=>s.opcode==='02'));over.before.stack=[2147483647,1];assert.equal(vm.predict(over,'stack_add','stack').stack[0],-2147483648);over.before.stack=[null,1];assert.throws(()=>vm.predict(over,'stack_add','stack'));
const dir=await mkdtemp(join(tmpdir(),'reb-vm-fixture-'));const run=(...args)=>spawnSync(process.execPath,['tools/vm-semantics.mjs',...args],{encoding:'utf8',timeout:10000});
try{const input=join(dir,'trace.json'),output=join(dir,'report.json');await writeFile(input,JSON.stringify(reg));let result=run('inspect',input,output);assert.equal(result.status,0,result.stderr);const saved=await readFile(output,'utf8');assert.match(saved,/source_sha256/);assert.equal((await stat(output)).mode&0o777,0o600);assert.notEqual(run('inspect',input,output).status,0);assert.equal(await readFile(output,'utf8'),saved);const link=join(dir,'symlink');await symlink(input,link);assert.notEqual(run('inspect',link,join(dir,'new')).status,0);assert.equal(run('step',input,'0',join(dir,'step')).status,0);assert.notEqual(run('step',input,'999',join(dir,'missing')).status,0);await writeFile(input,'{"format":1,"format":2}');assert.notEqual(run('inspect',input,join(dir,'duplicate')).status,0);}finally{await rm(dir,{recursive:true,force:true});}
console.log('PASS owned stack/register interpreter traces, all nine semantic operations, state continuity/gaps/unknowns, wrong hypotheses, overflow, exact provenance, bounded offline CLI and private no-overwrite output');

const document={activeElement:null,querySelector:()=>null};
class Element {
 constructor(tag){this.tagName=tag;this.children=[];this.attributes={};this.events={};this.style={};this.value='';this.files=[];this.text='';}
 set textContent(v){this.text=String(v);this.children=[];}get textContent(){return this.text+this.children.map(x=>x.textContent).join('');}
 contains(element){return this===element||this.children.some(child=>child.contains?.(element));}
 append(...items){this.children.push(...items);}replaceChildren(...items){this.children=items;}
 setAttribute(k,v){this.attributes[k]=v;}addEventListener(k,v){this.events[k]=v;}focus(){document.activeElement=this;}
}
document.createElement=tag=>new Element(tag);
const source=await readFile(new URL('../apps/research-ui/vm_semantics.js',import.meta.url),'utf8');
const api=runInNewContext(source+';({mountVmSemantics})',{document,TextEncoder,TextDecoder,crypto:webcrypto,capturedClientJSON:client.capturedClientJSON});
const ui=api.mountVmSemantics(new Element('details'));
const file=value=>{const bytes=Buffer.from(JSON.stringify(value));return {size:bytes.length,arrayBuffer:async()=>bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.length)};};
assert(ui.selector.disabled);ui.input.files=[file(reg)];await ui.input.events.change();assert.equal(ui.selector.disabled,false);assert(ui.map.textContent.includes('toy:register'));assert(ui.details.textContent.includes('observed_changes'));
ui.selector.value='1';ui.selector.events.change();assert(ui.details.textContent.includes('"sequence": 1'));
ui.input.files=[file({bad:'<img onerror=alert(1)>'})];await ui.input.events.change();assert(ui.notice.textContent.includes('Previous valid trace'));assert(ui.map.textContent.includes('toy:register'));
let release;ui.input.files=[{size:10,arrayBuffer:()=>new Promise(resolve=>{release=resolve;})}];const pending=ui.input.events.change();ui.clear.events.click();release(Buffer.from('{}'));await pending;assert(ui.selector.disabled);assert.equal(ui.map.textContent,'');assert.equal(document.activeElement,ui.input);
console.log('PASS VM controller: local import, exact step selection, invalid import preserves prior trace, clear cancels late completion and restores focus (not rendered acceptance)');

const backend=await readFile(new URL('../apps/origin-trace-backend/src/app.rs',import.meta.url),'utf8');
const assets=backend.match(/const UI_ASSETS: \[&str; (\d+)\] = \[([\s\S]*?)\];/);assert(assets);assert.equal(Number(assets[1]),[...assets[2].matchAll(/"[^"]+"/g)].length);assert(assets[2].includes('"vm_semantics.js"'));

const counterexample=fixture('register');counterexample.steps=[counterexample.steps[0]];counterexample.steps[0].after.registers[0]=8;
assert.equal(vm.validate(counterexample,{format:'reb-vm-hypothesis-v1',trace_id:counterexample.identity.trace_id,mappings:[{opcode:'03',operation:'register_const'}]}).results[0].status,'contradicted');
const tooLarge=fixture('register');tooLarge.coverage.limitations=['x'.repeat(1048577)];assert.throws(()=>vm.trace(tooLarge));

for(const mutate of [v=>v.identity.artifact_sha256=['a'.repeat(64)],v=>v.steps[0].opcode=10]){const invalid=fixture('register');mutate(invalid);assert.throws(()=>vm.trace(invalid));}
const boundary=copy(fixture('register').steps.at(-1));boundary.before.pc=65535;boundary.after.pc=65535;assert.equal(vm.predict(boundary,'halt','register').pc,65535);
boundary.operands=[0];assert.equal(vm.predict(boundary,'jump','register').pc,0);boundary.operands=[1,0];assert.equal(vm.predict(boundary,'branch_zero','register').pc,0);
boundary.before.registers[1]=1;assert.throws(()=>vm.predict(boundary,'branch_zero','register'));

for(const token of ['9007199254740991.1','1e400','1e-400','-0','1.0','1e2','9007199254740992'])assert.throws(()=>vm.parse('{"value":'+token+'}'));
for(const n of [Infinity,-Infinity,NaN,-0,9007199254740992]){const bad=fixture('register');bad.steps[0].before.registers[0]=n;assert.throws(()=>vm.trace(bad));}
assert.deepEqual(vm.parse('{"positive":2147483647,"negative":-2147483648,"zero":0}'),{positive:2147483647,negative:-2147483648,zero:0});

const dense=fixture('register');dense.steps=Array.from({length:256},(_,i)=>({sequence:i,opcode:'03',operands:[0,0],instruction_size:1,before:{pc:i,halted:false,registers:[0],stack:[],memory:Array.from({length:200},(_,j)=>[j,0])},after:{pc:i+1,halted:false,registers:[0],stack:[],memory:Array.from({length:200},(_,j)=>[j,0])},evidence_refs:['dense:'+i]}));
const denseJSON=JSON.stringify(dense);assert(Buffer.byteLength(denseJSON)<1048576);assert.equal(vm.trace(vm.parse(denseJSON)).steps.length,256);

// Linked workspace controller checks do not replace rendered acceptance.
const descendants=e=>[e,...e.children.flatMap(descendants)];
ui.input.files=[file(reg)];await ui.input.events.change();
assert(ui.stateView.textContent.includes('Before: 0'));assert(ui.stateView.textContent.includes('After: 7'));
const support=descendants(ui.map).find(e=>e.textContent==='Support step 1');support.events.click();assert.equal(ui.selector.value,'1');
const location=descendants(ui.stateView).find(e=>e.tagName==='button'&&e.textContent==='registers:1');location.events.click();assert(ui.occurrences.textContent.includes('Observed snapshots for registers:1'));
assert(ui.occurrences.textContent.includes('not establish reads or writes'));
ui.comparisonInput.files=[file(reg)];await ui.comparisonInput.events.change();ui.comparisonSelector.value='1';ui.compare.events.click();assert(ui.comparisonView.textContent.includes('Manual pair: primary step 1'));
assert(ui.comparisonView.textContent.includes('observed_equal'));
ui.comparisonInput.files=[file({bad:true})];await ui.comparisonInput.events.change();assert(ui.notice.textContent.includes('Both previous valid traces'));assert.equal(ui.selector.value,'1');assert.equal(ui.comparisonSelector.value,'1');
ui.selector.value='0';ui.selector.events.change();assert(!ui.comparisonView.textContent.includes('Manual pair:'));
ui.hypothesis.files=[file({format:'reb-vm-hypothesis-v1',trace_id:reg.identity.trace_id,mappings:[{opcode:'03',operation:'jump'}]})];await ui.hypothesis.events.change();assert(ui.validationView.textContent.includes('unsupported: step 0'));
const wrong=copy(reg);wrong.steps=[wrong.steps[0]];wrong.steps[0].after.registers[0]=8;
ui.input.files=[file(wrong)];await ui.input.events.change();ui.hypothesis.files=[file({format:'reb-vm-hypothesis-v1',trace_id:reg.identity.trace_id,mappings:[{opcode:'03',operation:'register_const'}]})];await ui.hypothesis.events.change();
const contradiction=descendants(ui.validationView).find(e=>e.textContent==='contradicted: step 0');contradiction.events.click();assert(ui.stateView.textContent.includes('registers:0: expected 7; observed 8'));
let finishFirst,finishSecond;
ui.comparisonInput.files=[{size:20,arrayBuffer:()=>new Promise(resolve=>{finishFirst=resolve;})}];const firstImport=ui.comparisonInput.events.change();
ui.comparisonInput.files=[{size:20,arrayBuffer:()=>new Promise(resolve=>{finishSecond=resolve;})}];const secondImport=ui.comparisonInput.events.change();
const newer=copy(reg);newer.identity.trace_id='newer';finishSecond(await file(newer).arrayBuffer());await secondImport;finishFirst(await file(reg).arrayBuffer());await firstImport;
ui.compare.events.click();assert(ui.comparisonView.textContent.includes('newer'));
ui.clearComparison.events.click();assert.equal(document.activeElement,ui.comparisonInput);assert(ui.comparisonSelector.disabled);assert(!ui.selector.disabled);
let finishHypothesis;ui.hypothesis.files=[{size:20,arrayBuffer:()=>new Promise(resolve=>{finishHypothesis=resolve;})}];const lateHypothesis=ui.hypothesis.events.change();ui.clear.events.click();finishHypothesis(await file({}).arrayBuffer());await lateHypothesis;assert.equal(ui.validation.textContent,'');assert.equal(document.activeElement,ui.input);
console.log('PASS linked VM controller: support-step/cell navigation, explicit manual pair, invalid comparison retention, exact counterexample mismatch, newer import ownership, clear focus and late hypothesis cancellation');
const sparse=copy(reg);sparse.coverage.complete=false;sparse.coverage.dropped_steps=3;sparse.steps=[sparse.steps[0],sparse.steps[1]];sparse.steps[1].sequence=4;
sparse.steps[0].before.registers=[null,0];sparse.steps[0].after.registers=[null,0];sparse.steps[0].before.stack=[0];sparse.steps[0].after.stack=[];sparse.steps[0].before.memory=[[0,0],[9,null]];sparse.steps[0].after.memory=[[9,null],[20,0]];
ui.input.files=[file(sparse)];await ui.input.events.change();assert(ui.stateView.textContent.includes('Gap after selected step: next retained sequence 4'));assert(ui.stateView.textContent.includes('Before: absent (not recorded)'));assert(ui.stateView.textContent.includes('After: absent (not recorded)'));ui.changesOnly.checked=false;ui.changesOnly.events.change();assert(ui.stateView.textContent.includes('unknown (null)'));ui.next.events.click();assert.equal(ui.selector.value,'4');assert(ui.stateView.textContent.includes('Gap before selected step: previous retained sequence 0'));ui.previous.events.click();assert.equal(ui.selector.value,'0');
ui.hypothesis.files=[file({format:'reb-vm-hypothesis-v1',trace_id:sparse.identity.trace_id,mappings:[]})];await ui.hypothesis.events.change();const audit=JSON.parse(ui.validation.textContent);assert.match(audit.exact_trace_input_file_sha256,/^[a-f0-9]{64}$/);assert.match(audit.exact_hypothesis_input_file_sha256,/^[a-f0-9]{64}$/);
let finishHash;const delayedCrypto={subtle:{digest:()=>new Promise(resolve=>{finishHash=resolve;})}};
const delayedAPI=runInNewContext(source+';({mountVmSemantics})',{document,TextEncoder,TextDecoder,crypto:delayedCrypto,capturedClientJSON:client.capturedClientJSON});const delayedUI=delayedAPI.mountVmSemantics(new Element('details'));delayedUI.input.files=[file(reg)];const digestPending=delayedUI.input.events.change();while(!finishHash)await Promise.resolve();delayedUI.clear.events.click();finishHash(new Uint8Array(32).buffer);await digestPending;assert(delayedUI.selector.disabled);assert.equal(delayedUI.details.textContent,'');
console.log('PASS VM UI provenance hashes, visible retained gaps, sparse memory additions/removals, stack pop, null/absent/zero labels and late digest cancellation');

const maximalTrace=(offset=0)=>({format:'reb-vm-trace-v1',identity:{...reg.identity,trace_id:'maximal:'+offset},architecture:'register',coverage:{complete:true,dropped_steps:0,limitations:[]},steps:[{sequence:0,opcode:'03',operands:[63,7],instruction_size:1,before:{pc:0,halted:false,registers:Array(64).fill(0),stack:Array(128).fill(0),memory:Array.from({length:256},(_,i)=>[offset+i,0])},after:{pc:1,halted:false,registers:[...Array(63).fill(0),8],stack:Array(128).fill(0),memory:Array.from({length:256},(_,i)=>[offset+256+i,0])},evidence_refs:['maximal:0']}]});
const findButton=(root,label)=>descendants(root).find(e=>e.tagName==='button'&&e.textContent===label);
const pageLocations=(root,attribute)=>descendants(root).filter(e=>e.attributes[attribute]).map(e=>e.attributes[attribute]);
ui.input.files=[file(maximalTrace())];await ui.input.events.change();ui.changesOnly.checked=false;ui.changesOnly.events.change();
let stateLocations=[];
while(true){const rows=pageLocations(ui.stateView,'data-vm-location');assert(rows.length<=64);stateLocations.push(...rows);const next=findButton(ui.stateView,'Next state locations page');if(next.disabled)break;next.events.click();assert(['Next state locations page','Previous state locations page'].includes(document.activeElement.textContent));assert.equal(ui.selector.value,'0');}
assert.equal(stateLocations.length,706);assert.equal(new Set(stateLocations).size,706);assert(ui.stateView.textContent.includes('705–706 of 706; page 12 of 12'));
findButton(ui.stateView,'memory:511').events.click();findButton(ui.map,'Support step 0').events.click();assert(pageLocations(ui.stateView,'data-vm-location').includes('memory:511'));assert(ui.occurrences.textContent.includes('Observed snapshots for memory:511'));findButton(ui.occurrences,'Step 0').events.click();assert(pageLocations(ui.stateView,'data-vm-location').includes('memory:511'));
ui.hypothesis.files=[file({format:'reb-vm-hypothesis-v1',trace_id:'maximal:0',mappings:[{opcode:'03',operation:'register_const'}]})];await ui.hypothesis.events.change();findButton(ui.validationView,'contradicted: step 0').events.click();assert.equal(document.activeElement.textContent,'registers:63');assert(pageLocations(ui.stateView,'data-vm-location').includes('registers:63'));assert(ui.stateView.textContent.includes('page 2 of 12'));
let mismatchCount=0;while(true){const rows=descendants(ui.stateView).filter(e=>e.className==='vm-mismatch');assert(rows.length<=64);mismatchCount+=rows.length;const next=findButton(ui.stateView,'Next hypothesis mismatches page');if(next.disabled)break;next.events.click();assert(['Next hypothesis mismatches page','Previous hypothesis mismatches page'].includes(document.activeElement.textContent));assert.equal(ui.selector.value,'0');}assert.equal(mismatchCount,513);assert.equal(JSON.parse(ui.validation.textContent).result.results[0].observed.memory.length,256);
ui.comparisonInput.files=[file(maximalTrace(512))];await ui.comparisonInput.events.change();ui.compare.events.click();let comparedLocations=[];
while(true){const rows=pageLocations(ui.comparisonView,'data-vm-comparison-location');assert(rows.length<=64);comparedLocations.push(...rows);const next=findButton(ui.comparisonView,'Next comparison locations page');if(next.disabled)break;next.events.click();assert(['Next comparison locations page','Previous comparison locations page'].includes(document.activeElement.textContent));assert.equal(ui.selector.value,'0');assert.equal(ui.comparisonSelector.value,'0');}
assert.equal(comparedLocations.length,1218);assert.equal(new Set(comparedLocations).size,1218);assert(ui.comparisonView.textContent.includes('1217–1218 of 1218; page 20 of 20'));
const fullComparison=descendants(ui.comparisonView).find(e=>e.tagName==='pre');assert.equal(JSON.parse(fullComparison.textContent).report.cells.length,1218);
findButton(ui.comparisonView,'Previous comparison locations page').events.click();assert.equal(document.activeElement.textContent,'Previous comparison locations page');
ui.input.files=[file(reg)];await ui.input.events.change();assert(ui.stateView.textContent.includes('page 1 of 1'));assert(!ui.comparisonView.textContent.includes('Manual pair:'));
ui.input.files=[file(dense)];await ui.input.events.change();ui.hypothesis.files=[file({format:'reb-vm-hypothesis-v1',trace_id:dense.identity.trace_id,mappings:[]})];await ui.hypothesis.events.change();assert.equal(descendants(ui.validationView).filter(e=>e.attributes['data-vm-step']).length,64);findButton(ui.validationView,'Next validation steps page').events.click();assert.equal(document.activeElement.textContent,'Next validation steps page');assert.equal(descendants(ui.validationView).filter(e=>e.attributes['data-vm-step'])[0].attributes['data-vm-step'],'64');
findButton(ui.map,'Next support steps page').events.click();assert.equal(document.activeElement.textContent,'Next support steps page');assert(findButton(ui.map,'Support step 64'));
console.log('PASS bounded visible VM pages: all706/1218 locations reachable exactly once,64-row DOM cap, focus-preserving boundaries, off-page support/counterexample targets, full raw audits and64-link validation/support pages');

// Listing presentation consumes the same exact trace/report; it is not a decoder.
ui.input.files=[file(dense)];await ui.input.events.change();
const listingRows=()=>descendants(ui.listingBody).filter(e=>e.attributes['data-vm-sequence']!==undefined);
const rowBySequence=sequence=>listingRows().find(e=>e.attributes['data-vm-sequence']===String(sequence));
const press=(sequence,key,extra={})=>{let prevented=false;rowBySequence(sequence).events.keydown({key,preventDefault(){prevented=true;},...extra});return prevented;};
assert.equal(listingRows().length,64);assert.equal(listingRows().filter(row=>row.tabIndex===0).length,1);
assert.equal(rowBySequence(0).attributes['aria-selected'],'true');assert(rowBySequence(0).textContent.includes('Ambiguous:'));
findButton(ui.listingPager,'Next retained steps page').events.click();assert.equal(ui.selector.value,'0');assert(ui.listingStatus.textContent.includes('off this page'));
assert.equal(listingRows()[0].attributes['data-vm-sequence'],'64');ui.focusSelectedRow();assert.equal(document.activeElement,rowBySequence(0));
assert(press(0,'PageDown'));assert.equal(ui.selector.value,'64');assert.equal(rowBySequence(64).attributes['aria-selected'],'true');
assert(press(64,'ArrowUp'));assert.equal(ui.selector.value,'63');assert(press(63,'ArrowDown'));assert.equal(ui.selector.value,'64');
assert(press(64,'End'));assert.equal(ui.selector.value,'255');assert(press(255,'ArrowDown'));assert.equal(ui.selector.value,'255');
assert(press(255,'Home'));assert.equal(ui.selector.value,'0');assert(press(0,'ArrowUp'));assert.equal(ui.selector.value,'0');
assert(press(0,'PageDown'));assert(press(64,'PageUp'));assert.equal(ui.selector.value,'0');
assert(!press(0,'ArrowDown',{isComposing:true}));assert(!press(0,'ArrowDown',{altKey:true}));assert.equal(ui.selector.value,'0');
assert(press(0,'Enter'));assert.equal(document.activeElement.textContent.includes('Step 0'),true);ui.focusSelectedRow();
ui.filter.value='no retained row';ui.filter.events.input();assert.equal(listingRows().length,0);assert.equal(ui.selector.value,'0');assert(ui.listingBody.textContent.includes('selected step remains unchanged'));
ui.focusSelectedRow();assert.equal(ui.filter.value,'');assert(rowBySequence(0));
ui.go(200);assert(rowBySequence(200));assert.equal(ui.selector.value,'200');ui.go(9999);assert.equal(ui.selector.value,'200');assert(ui.notice.textContent.includes('selection unchanged'));
let listed=[];ui.go(0);for(let page=0;page<4;page++){listed.push(...listingRows().map(row=>Number(row.attributes['data-vm-sequence'])));if(page<3)findButton(ui.listingPager,'Next retained steps page').events.click();}
assert.deepEqual(listed,Array.from({length:256},(_,i)=>i));assert.equal(ui.selector.value,'0');
for(let pass=0;pass<100;pass++){const next=findButton(ui.listingPager,'Next retained steps page'),previous=findButton(ui.listingPager,'Previous retained steps page');(next.disabled?previous:next).events.click();assert.equal(listingRows().length,64);assert.equal(ui.selector.value,'0');}
const runtimeOnly=copy(sparse);runtimeOnly.steps=runtimeOnly.steps.slice(0,2);runtimeOnly.steps[0].before.pc=7;runtimeOnly.steps[0].after.pc=7;runtimeOnly.steps[0].instruction_size=5;runtimeOnly.steps[0].opcode='0011223344556677';runtimeOnly.steps[1].before.pc=7;runtimeOnly.steps[1].after.pc=7;runtimeOnly.steps[1].sequence=Number.MAX_SAFE_INTEGER;
ui.input.files=[file(runtimeOnly)];await ui.input.events.change();assert.equal(listingRows().length,2);assert(ui.listingBody.textContent.includes('Gap before '+Number.MAX_SAFE_INTEGER));assert(rowBySequence(0).textContent.includes('0011223344556677'));assert(rowBySequence(0).textContent.includes('Unknown'));
assert.equal(JSON.parse(ui.details.textContent).report.step.instruction_size,5);assert.equal(JSON.parse(ui.details.textContent).report.identity.trace_id,runtimeOnly.identity.trace_id);assert.deepEqual(JSON.parse(ui.details.textContent).report.coverage,runtimeOnly.coverage);
ui.filter.value='0011223344556677';ui.filter.events.input();assert.equal(listingRows().length,1);assert.equal(ui.selector.value,'0');
ui.go(Number.MAX_SAFE_INTEGER);assert.equal(ui.selector.value,String(Number.MAX_SAFE_INTEGER));assert.equal(ui.filter.value,'');assert(rowBySequence(Number.MAX_SAFE_INTEGER));
ui.go(0);ui.changesOnly.checked=false;ui.changesOnly.events.change();
ui.stateButtons.registers.events.click();assert(pageLocations(ui.stateView,'data-vm-location').every(location=>location.startsWith('registers:')));assert.equal(ui.selector.value,'0');
findButton(ui.stateView,'registers:0').events.click();assert.equal(findButton(ui.stateView,'registers:0').attributes['aria-pressed'],'true');assert(ui.occurrences.textContent.includes('registers:0'));
ui.stateButtons.stack.events.click();assert(pageLocations(ui.stateView,'data-vm-location').every(location=>location.startsWith('stack:')));assert(ui.stateView.textContent.includes('registers:0 is absent or hidden'));
ui.stateButtons.memory.events.click();assert(pageLocations(ui.stateView,'data-vm-location').every(location=>location.startsWith('memory:')));assert(ui.stateView.textContent.includes('unknown (null)'));assert(ui.stateView.textContent.includes('absent (not recorded)'));
ui.stateButtons.instruction.events.click();assert(pageLocations(ui.stateView,'data-vm-location').includes('registers:0'));assert.equal(ui.selector.value,'0');
ui.changeLayout(1440);ui.changeLayout(900);ui.changeLayout(360);assert.equal(ui.selector.value,'0');assert.equal(findButton(ui.stateView,'registers:0').attributes['aria-pressed'],'true');
ui.openContext('comparison');ui.closeContext();assert.equal(ui.selector.value,'0');
console.log('PASS retained listing:256 exact rows/64-row pages, repeated PCs and large safe IDs, explicit inferred/ambiguous/unknown meanings, gaps versus filters, no-match preservation, all row keys/IME isolation, tab namespaces, selected location, complete raw report and100 bounded pager actions (not rendered QA)');
// Regressions for off-page Enter and durable occurrence-close focus at phone width.
ui.input.files=[file(dense)];await ui.input.events.change();ui.changeLayout(360);ui.setPanel('listing');
findButton(ui.listingPager,'Next retained steps page').events.click();assert.equal(ui.selector.value,'0');assert(press(64,'Enter'));assert.equal(ui.selector.value,'64');assert(document.activeElement.textContent.includes('Step 64'));
ui.changesOnly.checked=false;ui.changesOnly.events.change();findButton(ui.stateView,'registers:0').events.click();assert.equal(document.activeElement,ui.contextButtons.occurrences);ui.closeContext();assert.equal(document.activeElement,findButton(ui.stateView,'registers:0'));
findButton(ui.stateView,'registers:0').events.click();findButton(ui.occurrences,'Step 0').events.click();assert.equal(ui.selector.value,'0');assert(document.activeElement.textContent.includes('Step 0'));assert.equal(findButton(ui.stateView,'registers:0').attributes['aria-pressed'],'true');
findButton(ui.map,'Support step 1').events.click();assert.equal(ui.selector.value,'1');assert(document.activeElement.textContent.includes('Step 1'));
console.log('PASS phone focus regression:off-page Enter selects focused sequence, cell→occurrences→Close restores current selected cell, support/occurrence links expose exact state');
for(const width of [900,1440]){ui.changeLayout(360);ui.setPanel('listing');ui.panelButtons.listing.focus();ui.changeLayout(width);assert.equal(document.activeElement,ui.filter);ui.changeLayout(360);ui.setPanel('state');ui.panelButtons.state.focus();ui.changeLayout(width);assert.equal(document.activeElement,ui.stateButtons.instruction);ui.changeLayout(360);ui.panelButtons.evidence.events.click();ui.panelButtons.evidence.focus();ui.changeLayout(width);assert.equal(document.activeElement,ui.contextButtons.occurrences);}

// The local mode switch changes visibility only; neither owner is reconstructed.
const shellRoot=new Element('section'),findingsRoot=new Element('div'),findingsButton=new Element('button'),executionButton=new Element('button'),findingNode=new Element('article');
findingsRoot.append(findingNode);findingsRoot.scrollTop=150;shellRoot.hidden=true;
const shellNodes=new Map([['#vm-semantics-workflow',shellRoot],['#vm-findings-workspace',findingsRoot],['#vm-show-findings',findingsButton],['#vm-show-execution',executionButton]]);
document.querySelector=selector=>shellNodes.get(selector)??null;
const shell=runInNewContext(source+';vmExecutionWorkspace',{document,TextEncoder,TextDecoder,crypto:webcrypto,capturedClientJSON:client.capturedClientJSON});
shell.execution.input.files=[file(dense)];await shell.execution.input.events.change();shell.execution.go(173);
shell.execution.changeLayout(360);shell.execution.setPanel('listing');shell.execution.panelButtons.evidence.events.click();assert.equal(document.activeElement,shell.execution.contextButtons.occurrences);shell.execution.closeContext();assert.equal(document.activeElement,shell.execution.panelButtons.listing);assert.equal(shellRoot.attributes['data-panel'],'listing');
shell.execution.changeLayout(900);findButton(shellRoot,'Trace navigation').focus();shell.execution.changeLayout(1440);assert.equal(document.activeElement,shell.execution.navigator);shell.execution.changeLayout(900);findButton(shellRoot,'Trace navigation').events.click();findButton(shellRoot,'Close navigation').focus();shell.execution.changeLayout(1440);assert.equal(document.activeElement,shell.execution.navigator);
shell.execution.changeLayout(360);shell.execution.setPanel('listing');shell.execution.panelButtons.evidence.events.click();shell.execution.changeLayout(1440);shell.execution.closeContext();assert.equal(document.activeElement,shell.execution.filter);
const hiddenLauncher=new Element('button');hiddenLauncher.getClientRects=()=>[];hiddenLauncher.focus();shell.execution.openContext('audit');shell.execution.changeLayout(360);shell.execution.closeContext();assert.equal(document.activeElement,shell.execution.panelButtons.listing);
const listingIdentity=shell.execution.listingBody.children,findingsIdentity=findingsRoot.children;
executionButton.events.click();assert.equal(shellRoot.hidden,false);assert.equal(findingsRoot.hidden,true);findingsButton.events.click();assert.equal(shellRoot.hidden,true);assert.equal(findingsRoot.hidden,false);assert.equal(findingsRoot.children,findingsIdentity);assert.equal(findingsRoot.children[0],findingNode);assert.equal(findingsRoot.scrollTop,150);assert.equal(shell.execution.selector.value,'173');executionButton.events.click();assert.equal(shell.execution.listingBody.children,listingIdentity);
shell.showWorkspace('findings');assert.equal(shellRoot.hidden,true);assert.equal(findingsButton.attributes['aria-pressed'],'true');
document.querySelector=()=>null;
console.log('PASS VM-local Findings/Execution round trip preserves both DOM owners, selected sequence and finding scroll; finding entry restores Findings (DOM model, not rendered/source-link acceptance)');
