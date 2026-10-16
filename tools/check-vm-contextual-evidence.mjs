#!/usr/bin/env node
// Authored inert fixtures only. No capture hooks, guest evaluation or vendor data.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import vm from '../apps/research-ui/vm_contextual.js';
import evidenceModel from '../apps/research-ui/vm_contextual_evidence.js';
const clone = value => JSON.parse(JSON.stringify(value));
const bytes_hex = 'aa02aabb';
const definition = {format:'reb-vm-contextual-definition-v1',build_id:'owned-build',definition_id:'owned-definition',
  image_sha256:createHash('sha256').update(Buffer.from(bytes_hex,'hex')).digest('hex'),architecture:'stack',opcode_bytes:1,
  operand_endianness:'little',register_count:0,instructions:[
    {instruction_id:'BR',mnemonic:'BR',operands:[{name:'target',width:1,signed:false,kind:'address'}],operations:[{operation:'stack_branch_zero',args:[]}],flow:{kind:'branch',target:{operand:'target',base:'absolute'}}},
    {instruction_id:'HALT',mnemonic:'HALT',operands:[],operations:[{operation:'halt',args:[]}],flow:{kind:'halt'}}],
  mappings:[{pc:0,decoder_state:'first',raw_opcode:'aa',instruction_id:'BR',next_decoder_state:'second'},
    {pc:2,decoder_state:'second',raw_opcode:'aa',instruction_id:'HALT',next_decoder_state:null},
    {pc:0,decoder_state:'other',raw_opcode:'aa',instruction_id:'HALT',next_decoder_state:null}]};
const image = {format:'reb-vm-contextual-image-v1',build_id:definition.build_id,definition_id:definition.definition_id,image_id:'owned-image',bytes_hex,entry_contexts:[{offset:0,decoder_state:'first'},{offset:0,decoder_state:'other'}]};
const baseline = await vm.analyze(definition,image);
const step = (event_id,sequence,pc=0,decoder_state='first',raw_opcode='aa') => ({event_id,sequence,kind:'step',pc,decoder_state,raw_opcode,to:null});
const jump = (event_id,sequence,to={pc:2,decoder_state:'second'}) => ({...step(event_id,sequence),kind:'jump',to});
const evidence = {format:'reb-vm-contextual-evidence-v1',identity:clone(baseline.identity),capture_id:'owned-capture',run_id:'run-1',context_id:'vm-1',mapping_provenance:{kind:'supplied',reference:'authored-map-1'},events:[jump('e0',0),step('e3',3,2,'second')],gaps:[{after_sequence:0,missing_count:2}]};
const linked = await evidenceModel.link(definition,image,evidence);
assert.deepEqual(linked.analysis,baseline);
assert.equal(linked.complete,false);
assert.deepEqual(linked.links.map(x=>x.instruction_id),['context:0:first','context:2:second']);
assert.equal(linked.observed_edges.length,1);
assert.equal(linked.observed_edges[0].status,'observed');
assert.equal(linked.observed_edges[0].declared_relation,'matches_declared');
assert.equal(linked.observed_edges[0].capture_id,'owned-capture');
assert.deepEqual(linked.observed_edges[0].mapping_provenance,evidence.mapping_provenance);
assert.deepEqual(linked.diagnostics.map(x=>x.code),['sequence_gap','reported_gap']);
assert.ok(linked.analysis.cfg.edges.every(x=>x.evidence==='declared_static'));
assert.equal(linked.analysis.cfg.complete,false);
// Full report identity is rederived, never taken from a caller's analysis.
for (const key of Object.keys(evidence.identity)) {
  const altered = clone(evidence); altered.identity[key] = key.endsWith('sha256') ? '0'.repeat(64) : 'other';
  await assert.rejects(evidenceModel.link(definition,image,altered),/identity/);
}
const changedDefinition=clone(definition); changedDefinition.instructions[1].mnemonic='STOP';
await assert.rejects(evidenceModel.link(changedDefinition,image,evidence),/identity/);
await assert.rejects(evidenceModel.link(baseline,image,evidence));
// Decode policy changes do not fabricate observed reachability.
const limited=await evidenceModel.link(definition,image,evidence,{max_instructions:1});
assert.equal(limited.observed_edges[0].to_instruction_id,null);
assert.equal(limited.observed_edges[0].to_status,'instruction_budget');
const run = async events => evidenceModel.link(definition,image,{...evidence,events,gaps:[]});
let report = await run([step('s',0,0,'other')]);
assert.equal(report.links[0].instruction_id,'context:0:other');
report = await run([step('s',0,0,null)]);
assert.equal(report.links[0].status,'unknown_state');
report = await run([step('s',0,0,'null')]);
assert.equal(report.links[0].status,'not_decoded');
report = await run([step('s',0,0,'first','bb')]);
assert.equal(report.links[0].status,'opcode_mismatch');
report = await run([step('s',0,65535)]);
assert.equal(report.links[0].status,'out_of_range');
report = await run([{...jump('s',0),raw_opcode:'bb'}]);
assert.equal(report.observed_edges[0].status,'unlinked');
assert.equal(report.observed_edges[0].from_instruction_id,null);
assert.equal(report.observed_edges[0].declared_relation,'unknown');
report = await run([jump('s',0,{pc:2,decoder_state:null})]);
assert.equal(report.observed_edges[0].to_status,'unknown_state');
assert.equal(report.observed_edges[0].declared_relation,'unknown');
report = await run([jump('s',0,{pc:3,decoder_state:'second'})]);
assert.equal(report.observed_edges[0].to_status,'not_decoded');
assert.equal(report.observed_edges[0].declared_relation,'differs_from_declared');
assert.equal(report.analysis.instructions.length,baseline.instructions.length);
// Adjacent steps, even when consecutive or separated by gaps, imply no jump.
assert.deepEqual((await run([step('a',0),step('b',1,2,'second')])).observed_edges,[]);
assert.deepEqual((await run([step('a',0),step('b',99,2,'second')])).observed_edges,[]);
assert.deepEqual((await run([])).links,[]);
const dynamic=clone(definition); dynamic.instructions[0].flow={kind:'jump',target:null}; dynamic.instructions[0].operations=[{operation:'jump',args:[]}];
const dynamicAnalysis=await vm.analyze(dynamic,image);
const dynamicLinked=await evidenceModel.link(dynamic,image,{...evidence,identity:dynamicAnalysis.identity,events:[jump('d',0)],gaps:[]});
assert.equal(dynamicLinked.observed_edges[0].to_status,'not_decoded');
assert.equal(dynamicLinked.observed_edges[0].declared_relation,'unresolved_declared');
assert.equal(dynamicLinked.analysis.cfg.edges[0].to_offset,null);
// Input copies cannot mutate retained reports, and reports cannot mutate callers.
const copied=evidenceModel.parseEvidence(evidence); copied.events[0].pc=7; assert.equal(evidence.events[0].pc,0);
linked.evidence.identity.build_id='changed'; assert.equal(evidence.identity.build_id,'owned-build');
const invalid = change => { const value=clone(evidence); change(value); assert.throws(()=>evidenceModel.parseEvidence(value)); };
invalid(x=>x.events.push(clone(x.events[0])));
invalid(x=>x.events[1].sequence=0);
invalid(x=>x.events[0].pc=-0);
invalid(x=>x.events[0].sequence=Number.MAX_SAFE_INTEGER+1);
invalid(x=>x.events[0].raw_opcode='AA');
invalid(x=>x.events[0].raw_opcode='aa\n');
invalid(x=>x.events[0].to=null);
invalid(x=>x.events[1].to={pc:2,decoder_state:'second'});
invalid(x=>x.events[0].extra=1);
invalid(x=>x.capture_id='<img onerror=alert(1)>');
invalid(x=>x.mapping_provenance.reference='javascript:alert(1)');
invalid(x=>x.identity.image_bytes_sha256+='\n');
invalid(x=>x.gaps=[{after_sequence:0,missing_count:3}]);
invalid(x=>x.gaps=[{after_sequence:4,missing_count:3},{after_sequence:5,missing_count:1}]);
invalid(x=>x.gaps=[{after_sequence:Number.MAX_SAFE_INTEGER,missing_count:1}]);
invalid(x=>x.gaps=Array.from({length:257},(_,i)=>({after_sequence:10+i*2,missing_count:1})));
invalid(x=>x.events=Array.from({length:4097},(_,i)=>step('e'+i,i)));
invalid(x=>x.events[0].event_id='a'.repeat(1048577));
invalid(x=>x.extra=Array.from({length:100},()=> 'x'.repeat(20000)));
const accessor=clone(evidence); let called=false; Object.defineProperty(accessor,'events',{enumerable:true,get(){called=true;return [];}});
assert.throws(()=>evidenceModel.parseEvidence(accessor)); assert.equal(called,false);
const sparse=clone(evidence); delete sparse.events[0]; assert.throws(()=>evidenceModel.parseEvidence(sparse));
const cycle=clone(evidence); cycle.loop=cycle; assert.throws(()=>evidenceModel.parseEvidence(cycle));
const inherited=Object.create(evidence); assert.throws(()=>evidenceModel.parseEvidence(inherited));
const symbolic=clone(evidence); symbolic[Symbol('x')]=1; assert.throws(()=>evidenceModel.parseEvidence(symbolic));
const serialized=JSON.stringify(evidence);
assert.deepEqual(evidenceModel.parseEvidence(serialized),evidence);
assert.throws(()=>evidenceModel.parseEvidence(serialized.replace('"sequence":0','"sequence":0,"sequence":0')));
assert.throws(()=>evidenceModel.parseEvidence(serialized.replace('"sequence":0','"sequence":0e0')));
assert.throws(()=>evidenceModel.parseEvidence(serialized.replace('"sequence":0','"sequence":-0')));
console.log('Contextual runtime evidence: identity, context, jump separation, gaps and strict bounds passed.');
