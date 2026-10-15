#!/usr/bin/env node
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,stat,symlink,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import vm from '../apps/research-ui/vm_semantics.js';

// Independently authored snapshots: repeated PCs are occurrences, not basic blocks.
const state=(pc,halted=false)=>({pc,halted,registers:[null,0],stack:[],memory:[[7,null]]});
const step=(sequence,from,to,halted=false)=>({sequence,opcode:'ff',operands:[],instruction_size:2,
 before:state(from),after:state(to,halted),evidence_refs:['owned:'+sequence]});
const input={format:'reb-vm-trace-v1',identity:{trace_id:'owned-path',investigation_id:'owned-investigation',finding_id:'owned-finding',artifact_id:'owned-artifact',artifact_sha256:'a'.repeat(64),scope_id:'owned-scope',backend:'fixture'},architecture:'register',coverage:{complete:false,dropped_steps:2,limitations:['Only supplied snapshots']},steps:[step(7,0,2),step(8,2,0),step(9,0,2),step(12,10,12),step(13,12,12,true)]};
const original=JSON.stringify(input),path=vm.observedPath(input);
assert.equal(path.format,'reb-vm-observed-path-v1');
assert.deepEqual(path.identity,input.identity);assert.deepEqual(path.coverage,input.coverage);
assert.equal(path.nodes.length,5);assert.deepEqual(path.nodes.map(n=>n.sequence),[7,8,9,12,13]);
assert.deepEqual(path.nodes.map(n=>n.pc_before),[0,2,0,10,12]);
assert.deepEqual(path.edges.map(e=>[e.from_sequence,e.to_sequence,e.observed_pc]),[[7,8,2],[8,9,0],[12,13,12]]);
assert.deepEqual(path.gaps,[{before_sequence:9,after_sequence:12,missing_steps:2,kind:'sequence_gap'}]);
assert.deepEqual(path.edges[0].evidence_refs,['owned:7','owned:8']);
for(const [index,node] of path.nodes.entries()){
 const retained=input.steps[index];
 assert.equal(node.sequence,retained.sequence);assert.equal(node.opcode,retained.opcode);
 assert.deepEqual(node.operands,retained.operands);assert.equal(node.instruction_size,retained.instruction_size);
 assert.deepEqual(node.evidence_refs,retained.evidence_refs);assert.equal(node.branch_alternatives,'unknown');
}
assert.equal(path.nodes[0].pc_movement,'matches_supplied_advance');
assert.equal(path.nodes[1].pc_movement,'differs_from_supplied_advance');
assert.equal(path.nodes[4].pc_movement,'halted_snapshot');
assert.equal(path.static_cfg_complete,false);assert.equal(path.equivalence_proven,false);
assert(path.warnings.some(w=>w.includes('not static instructions')));
assert(path.warnings.some(w=>w.includes('unrecorded branch alternatives')));
assert.equal(JSON.stringify(input),original);
path.nodes[0].evidence_refs.push('mutated-result');assert.equal(JSON.stringify(input),original,'Reports cannot mutate caller input');
const full=structuredClone(input);full.coverage={complete:true,dropped_steps:0,limitations:[]};full.steps=Array.from({length:256},(_,i)=>step(i,0,0));
const bounded=vm.observedPath(full);assert.equal(bounded.nodes.length,256);assert.equal(bounded.edges.length,255);assert.equal(bounded.gaps.length,0);assert.equal(bounded.static_cfg_complete,false);
const huge=structuredClone(full);huge.steps=huge.steps.slice(0,2);huge.steps[0].sequence=Number.MAX_SAFE_INTEGER-1;huge.steps[1].sequence=Number.MAX_SAFE_INTEGER;
assert.deepEqual(vm.observedPath(huge).edges.map(e=>e.to_sequence),[Number.MAX_SAFE_INTEGER]);
const maximumGap=structuredClone(input);maximumGap.steps=[step(0,0,1),step(Number.MAX_SAFE_INTEGER,65535,0)];
const hugePath=vm.observedPath(maximumGap);assert.equal(hugePath.gaps[0].missing_steps,Number.MAX_SAFE_INTEGER-1);assert.equal(hugePath.nodes[1].supplied_advance_pc,null);assert.equal(hugePath.edges.length,0);
const single=structuredClone(input);single.steps=[step(42,5,5)];const one=vm.observedPath(single);assert.equal(one.edges.length,0);assert.equal(one.nodes[0].halted_after,false);
for(const mutate of [v=>v.steps.push(step(14,12,12)),v=>v.steps[1].before.pc=4,v=>v.steps[1].sequence=7,v=>v.coverage.complete=true,v=>v.steps[0].sequence=-0,v=>v.steps=[]]){
 const invalid=structuredClone(input);mutate(invalid);assert.throws(()=>vm.observedPath(invalid));
}
const tooMany=structuredClone(full);tooMany.steps.push(step(256,0,0));assert.throws(()=>vm.observedPath(tooMany));
console.log('PASS observed path model: exact occurrences/evidence, repeated PCs, consecutive edges only, gaps, terminal unknown, 256-node/255-edge bound, safe IDs, immutability and parser failures');

const dir=await mkdtemp(join(tmpdir(),'reb-vm-path-cli-'));
const run=(...args)=>spawnSync(process.execPath,['tools/vm-semantics.mjs',...args],{encoding:'utf8',timeout:10000});
try{
 const traceFile=join(dir,'trace.json'),output=join(dir,'path.json');await writeFile(traceFile,original);
 assert.equal(run('path',traceFile,output).status,0);
 const bytes=await readFile(output),saved=JSON.parse(bytes);
 assert.deepEqual(Object.keys(saved).sort(),['hypotheses_sha256','result','source_sha256']);
 assert.equal(saved.source_sha256,createHash('sha256').update(original).digest('hex'));
 assert.equal(saved.hypotheses_sha256,null);assert.deepEqual(saved.result,vm.observedPath(input));
 assert.equal((await stat(output)).mode&0o777,0o600);
 assert.notEqual(run('path',traceFile,output).status,0);assert.deepEqual(await readFile(output),bytes);
 const link=join(dir,'input-link');await symlink(traceFile,link);assert.notEqual(run('path',link,join(dir,'new.json')).status,0);
 const outputLink=join(dir,'output-link');await symlink(output,outputLink);assert.notEqual(run('path',traceFile,outputLink).status,0);assert.deepEqual(await readFile(output),bytes);
 assert.match(run('--help').stdout,/path TRACE.json OUTPUT.json/);
 assert.notEqual(run('path',traceFile).status,0);assert.notEqual(run('path',traceFile,join(dir,'other.json'),'extra').status,0);
 await writeFile(traceFile,'{"format":1,"format":2}');assert.notEqual(run('path',traceFile,join(dir,'bad.json')).status,0);
}finally{await rm(dir,{recursive:true,force:true});}
console.log('PASS offline path CLI: exact input digest, same bounded model, private no-overwrite output, symlink refusal, malformed input, explicit help/arity');
