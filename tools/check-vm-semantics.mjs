#!/usr/bin/env node
import assert from 'node:assert/strict';
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
 append(...items){this.children.push(...items);}replaceChildren(...items){this.children=items;}
 setAttribute(k,v){this.attributes[k]=v;}addEventListener(k,v){this.events[k]=v;}focus(){document.activeElement=this;}
}
document.createElement=tag=>new Element(tag);
const source=await readFile(new URL('../apps/research-ui/vm_semantics.js',import.meta.url),'utf8');
const api=runInNewContext(source+';({mountVmSemantics})',{document,TextEncoder,TextDecoder,capturedClientJSON:client.capturedClientJSON});
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
