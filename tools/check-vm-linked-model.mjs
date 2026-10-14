#!/usr/bin/env node
import assert from 'node:assert/strict';
import vm from '../apps/research-ui/vm_semantics.js';

const copy=value=>JSON.parse(JSON.stringify(value));
const states=[
  {pc:0,halted:false,registers:[0,null,9],stack:[null,0],memory:[[0,0],[42,null],[100,7]]},
  {pc:1,halted:false,registers:[0,null],stack:[null],memory:[[0,0],[42,null],[101,0]]},
  {pc:2,halted:false,registers:[null,0,9],stack:[null,0],memory:[[0,null],[42,0],[101,0]]},
  {pc:3,halted:false,registers:[null,0,9],stack:[],memory:[[42,0]]},
  {pc:3,halted:true,registers:[null,0,9],stack:[],memory:[[42,0]]},
];
// Authored snapshots, independent of the model's prediction/effect routines.
const fixture=()=>({format:'reb-vm-trace-v1',identity:{trace_id:'linked:fixture',investigation_id:'owned:investigation',
  finding_id:'owned:finding',artifact_id:'owned:artifact',artifact_sha256:'b'.repeat(64),scope_id:'owned:scope',backend:'fixture'},
  architecture:'register',coverage:{complete:true,dropped_steps:0,limitations:['Authored bounded fixture only']},
  steps:states.slice(0,-1).map((before,sequence)=>({sequence,opcode:sequence===3?'09':'ff',operands:[],instruction_size:1,
    before:copy(before),after:copy(states[sequence+1]),evidence_refs:['owned:step:'+sequence]}))});
const trace=fixture(),original=copy(trace),first=vm.step(trace,0),cell=(report,location)=>report.cells.find(item=>item.location===location);
assert.equal(first.format,'reb-vm-step-v1');
assert.deepEqual(first.identity,trace.identity);assert.deepEqual(first.coverage,trace.coverage);assert.deepEqual(first.step,trace.steps[0]);
assert.deepEqual(first.evidence_refs,['owned:step:0']);assert.equal(first.previous_sequence,null);assert.equal(first.next_sequence,1);
assert.equal(first.equivalence_proven,false);assert.equal(first.reads,'unknown');assert(first.warnings.length);
assert.deepEqual(first.cells.map(item=>item.location),['pc','halted','registers:0','registers:1','registers:2','stack:0','stack:1','memory:0','memory:42','memory:100','memory:101']);
assert.deepEqual(cell(first,'registers:0'),{location:'registers:0',before:{present:true,value:0},after:{present:true,value:0},changed:false,status:'observed_equal'});
assert.deepEqual(cell(first,'registers:1'),{location:'registers:1',before:{present:true,value:null},after:{present:true,value:null},changed:false,status:'unknown'});
assert.deepEqual(cell(first,'memory:101'),{location:'memory:101',before:{present:false,value:null},after:{present:true,value:0},changed:true,status:'different'});
assert.deepEqual(cell(first,'registers:2').after,{present:false,value:null});
assert.deepEqual(cell(first,'memory:100').after,{present:false,value:null});
assert.equal(cell(first,'pc').status,'different');assert.equal(cell(first,'halted').status,'observed_equal');
assert.deepEqual(first.changes,vm.effects(trace.steps[0]));
assert.equal(vm.step(trace,3).next_sequence,null);assert.equal(vm.step(trace,3).previous_sequence,2);
assert.equal(cell(vm.step(trace,1),'registers:0').status,'unknown');
assert.equal(cell(vm.step(trace,1),'registers:0').changed,true);
for(const sequence of ['0',-0,-1,1.1,NaN,Infinity,Number.MAX_SAFE_INTEGER+1,null,undefined,4])assert.throws(()=>vm.step(trace,sequence));
const sparse=fixture();sparse.steps.forEach((item,index)=>item.sequence=index*10+7);sparse.coverage.complete=false;sparse.coverage.dropped_steps=9;
assert.equal(vm.step(sparse,17).previous_sequence,7);assert.equal(vm.step(sparse,17).next_sequence,27);
assert(vm.step(sparse,17).warnings.some(message=>message.includes('gaps')));assert.throws(()=>vm.step(sparse,1),/not retained/);
const maximum=fixture();maximum.steps=[maximum.steps[0]];maximum.steps[0].sequence=Number.MAX_SAFE_INTEGER;
assert.equal(vm.step(maximum,Number.MAX_SAFE_INTEGER).step.sequence,Number.MAX_SAFE_INTEGER);

const same=vm.compareSteps(trace,0,trace,0);
assert.equal(same.format,'reb-vm-step-comparison-v1');assert.equal(same.equivalence_proven,false);
assert.equal(same.left.step.sequence,0);assert.equal(same.right.step.sequence,0);assert.equal(cell(same,'registers:0').status,'observed_equal');
assert.equal(cell(same,'registers:1').status,'unknown');assert.equal(cell(same,'memory:101').before_status,'unknown');
assert.equal(cell(same,'memory:101').after_status,'observed_equal');assert.equal(cell(same,'memory:101').status,'unknown');
assert.equal(cell(same,'registers:2').after_status,'unknown');assert.equal(cell(same,'registers:2').status,'unknown');
assert(same.warnings.some(message=>message.includes('no instruction, location or trace alignment')));
const other=fixture();other.identity.trace_id='linked:other';other.identity.scope_id='owned:another';other.architecture='stack';
const comparison=vm.compareSteps(trace,0,other,1);
assert.equal(comparison.left.identity.trace_id,'linked:fixture');assert.equal(comparison.right.identity.trace_id,'linked:other');
assert.equal(comparison.left.step.sequence,0);assert.equal(comparison.right.step.sequence,1);
assert.equal(cell(comparison,'pc').status,'different');assert.equal(cell(comparison,'registers:0').after_status,'unknown');
assert.equal(cell(comparison,'memory:100').before_status,'different');assert.equal(cell(comparison,'memory:100').after_status,'unknown');
assert(comparison.warnings.some(message=>message.includes('different architectures')));
assert(comparison.warnings.some(message=>message.includes('scope_id')));
assert(comparison.warnings.some(message=>message.includes('capture-adapter-defined units')));
assert(comparison.warnings.some(message=>message.includes('exact input-file hashes do not establish trace alignment')));
const differentArtifact=fixture();differentArtifact.identity.artifact_id='different:artifact';differentArtifact.identity.artifact_sha256='c'.repeat(64);differentArtifact.identity.investigation_id='different:investigation';
assert(vm.compareSteps(trace,0,differentArtifact,0).warnings.some(message=>['artifact_id','artifact_sha256','investigation_id'].every(field=>message.includes(field))));
assert.throws(()=>vm.compareSteps(trace,0,other,'1'));assert.throws(()=>vm.compareSteps(trace,99,other,1));
assert.throws(()=>vm.compareSteps(trace,0,{...other,architecture:'unsupported'},1));

const page=vm.occurrences(trace,'memory:42',0,2);
assert.equal(page.format,'reb-vm-location-occurrences-v1');assert.equal(page.total,4);assert.equal(page.page,0);assert.equal(page.page_size,2);assert.equal(page.next_page,1);
assert.deepEqual(page.items.map(item=>item.sequence),[0,1]);assert.deepEqual(page.evidence_refs,['owned:step:0','owned:step:1']);
assert.equal(page.items[0].changed,false);assert.equal(page.items[0].status,'unknown');
assert.equal(page.items[1].changed,true);assert.equal(page.items[1].status,'unknown');
assert.equal(page.equivalence_proven,false);assert.deepEqual(page.coverage,trace.coverage);assert(page.warnings.some(message=>message.includes('not proven accesses')));
const last=vm.occurrences(trace,'memory:42',1,2);assert.deepEqual(last.items.map(item=>item.sequence),[2,3]);assert.equal(last.next_page,null);
assert.deepEqual(vm.occurrences(trace,'memory:42',2,2).items,[]);assert.equal(vm.occurrences(trace,'memory:65535').total,0);
assert.deepEqual(vm.occurrences(trace,'registers:2').items.map(item=>item.sequence),[0,1,2,3]);
assert.deepEqual(vm.occurrences(trace,'stack:1').items.map(item=>item.sequence),[0,1,2]);
assert.equal(vm.occurrences(trace,'pc').total,4);assert.equal(vm.occurrences(trace,'halted').items.at(-1).after.value,true);
for(const location of ['register:0','registers:00','registers:-1','registers:64','stack:128','memory:65536','memory:1e2','memory:1.0','memory:9007199254740993','pc:0','halted:0','0','memory:0 ',null,{}])assert.throws(()=>vm.occurrences(trace,location));
for(const [page,pageSize] of [[-1,16],[-0,16],['0',16],[0,0],[0,65],[0,1.1],[0,'16'],[NaN,16],[Infinity,16],[Number.MAX_SAFE_INTEGER,64]])assert.throws(()=>vm.occurrences(trace,'pc',page,pageSize));
assert.equal(vm.occurrences(trace,'memory:42',Number.MAX_SAFE_INTEGER,1).items.length,0);
assert.deepEqual(trace,original,'All linked reports must preserve supplied evidence');
first.step.before.registers[0]=99;first.identity.trace_id='mutated';assert.deepEqual(trace,original,'Reports must not share mutable input references');

// Largest supported page traversal retains exact IDs and never clamps missing IDs.
const dense=fixture();dense.steps=Array.from({length:256},(_,sequence)=>({sequence,opcode:'ff',operands:[],instruction_size:1,
  before:{pc:sequence,halted:false,registers:[null],stack:[],memory:[[0,0]]},
  after:{pc:sequence+1,halted:false,registers:[null],stack:[],memory:[[0,0]]},evidence_refs:['dense:'+sequence]}));
let ids=[];for(let page=0;page<16;page++){const report=vm.occurrences(dense,'registers:0',page,16);assert(report.items.length<=16);ids.push(...report.items.map(item=>item.sequence));assert(report.items.every(item=>item.status==='unknown'));}
assert.deepEqual(ids,Array.from({length:256},(_,index)=>index));assert.equal(vm.occurrences(dense,'pc',3,64).next_page,null);
assert.equal(vm.step(dense,255).previous_sequence,254);assert.equal(vm.step(dense,255).next_sequence,null);
const malformed=fixture();malformed.steps[0].before.registers[0]=1.5;
for(const operation of [()=>vm.step(malformed,0),()=>vm.occurrences(malformed,'pc'),()=>vm.compareSteps(trace,0,malformed,0)])assert.throws(operation);

// Four disjoint full memory snapshots exercise every permitted location without truncation.
const full=(base)=>{const result=fixture();result.steps=[result.steps[0]];
  for(const [boundary,offset] of [['before',0],['after',256]]){const snapshot=result.steps[0][boundary];snapshot.registers=Array(64).fill(0);snapshot.stack=Array(128).fill(null);snapshot.memory=Array.from({length:256},(_,index)=>[base+offset+index,index]);}
  return result;
};
assert.equal(vm.step(full(0),0).cells.length,706);
const largest=vm.compareSteps(full(0),0,full(512),0);assert.equal(largest.cells.length,1218);assert.equal(new Set(largest.cells.map(item=>item.location)).size,1218);
assert.equal(cell(largest,'memory:1023').right_after.value,255);assert.equal(cell(largest,'memory:1023').left_after.present,false);
assert(Buffer.byteLength(JSON.stringify(largest,null,2))<4194304);
console.log('PASS exact VM step selection, complete location states, unknown/absent/zero distinctions, manual comparison, exact namespaces, evidence identity, bounded occurrence pagination and immutable inputs');
