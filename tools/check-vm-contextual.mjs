#!/usr/bin/env node
// Authored inert programs. No vendor output or guest code is evaluated.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import model from '../apps/research-ui/vm_contextual.js';
import staticModel from '../apps/research-ui/vm_static.js';
const clone = value => JSON.parse(JSON.stringify(value));
const sha = hex => createHash('sha256').update(Buffer.from(hex,'hex')).digest('hex');
const op = (operation,args = []) => ({operation,args});
const field = (name,kind,width=1,signed=false) => ({name,kind,width,signed});
const instruction = (instruction_id,operands,operations,flow={kind:'next'}) => ({instruction_id,mnemonic:instruction_id,operands,operations,flow});
const mapping = (pc,decoder_state,raw_opcode,instruction_id,next_decoder_state) => ({pc,decoder_state,raw_opcode,instruction_id,next_decoder_state});
function fixture(raw='10',build='owned-A') {
  // Independent original behavior: (2 + 3) = 5. Same raw opcode at every PC.
  const bytes_hex = raw+'02'+raw+'03'+raw+raw;
  const definition = {format:'reb-vm-contextual-definition-v1',build_id:build,definition_id:'owned-sum',image_sha256:sha(bytes_hex),
    architecture:'stack',opcode_bytes:1,operand_endianness:'little',register_count:0,instructions:[
      instruction('PUSH',[field('value','immediate')],[op('stack_const',['value'])]),
      instruction('ADD',[],[op('stack_add')]),instruction('HALT',[],[op('halt')],{kind:'halt'})],
    mappings:[mapping(0,'s0',raw,'PUSH','s1'),mapping(2,'s1',raw,'PUSH','s2'),mapping(4,'s2',raw,'ADD','s3'),mapping(5,'s3',raw,'HALT',null)]};
  const image = {format:'reb-vm-contextual-image-v1',image_id:'owned-sum-bytes',definition_id:definition.definition_id,build_id:build,bytes_hex,entry_contexts:[{offset:0,decoder_state:'s0'}]};
  return {definition,image};
}
const a = fixture(), b = fixture('20','owned-B');
const report = await model.analyze(a.definition,a.image), other = await model.analyze(b.definition,b.image);
assert.deepEqual(report.instructions.map(i => [i.offset,i.decoder_state,i.raw_opcode,i.instruction_id]),[
  [0,'s0','10','PUSH'],[2,'s1','10','PUSH'],[4,'s2','10','ADD'],[5,'s3','10','HALT']]);
assert.deepEqual(report.instructions.map(i => i.pseudocode.map(p => p.text)),[['push(2);'],['push(3);'],['right = pop(); left = pop(); push(add(left, right));'],['halt;']]);
assert.deepEqual(report.instructions.map(i=>i.operations),other.instructions.map(i=>i.operations));
assert.notEqual(report.identity.image_bytes_sha256,other.identity.image_bytes_sha256);
assert.notEqual(report.identity.definition_canonical_sha256,other.identity.definition_canonical_sha256);
assert.equal(report.coverage.decoded_bytes,6); assert.equal(report.cfg.complete,false); assert.equal(report.equivalence_proven,false);
assert.ok(report.cfg.edges.every(e=>e.status==='resolved' && e.evidence==='declared_static'));
assert.equal(report.cfg.edges[2].to_instruction_id,'context:5:s3');
// A tiny independent fixture oracle validates the authored behavior. It accepts
// only these hand-written program declarations, not imported user programs.
const stack=[];
for (const item of report.instructions) {
  if(item.instruction_id==='PUSH') stack.push(item.operands[0].value);
  if(item.instruction_id==='ADD') { const right=stack.pop(),left=stack.pop(); stack.push(left+right); }
}
assert.deepEqual(stack,[5]);

const variants=clone(a); variants.image.entry_contexts.push({offset:0,decoder_state:'alternate'});
variants.definition.mappings.push(mapping(0,'alternate','10','HALT',null));
const variantReport=await model.analyze(variants.definition,variants.image);
assert.deepEqual(variantReport.instructions.filter(i=>i.offset===0).map(i=>i.id),['context:0:s0','context:0:alternate']);
assert.equal(variantReport.instructions.find(i=>i.decoder_state==='alternate').instruction_id,'HALT');

const missing=clone(a); missing.definition.mappings[0].next_decoder_state=null;
const stopped=await model.analyze(missing.definition,missing.image);
assert.equal(stopped.instructions.length,1); assert.equal(stopped.cfg.edges[0].status,'unknown_state');
assert.deepEqual(stopped.diagnostics,[{offset:2,decoder_state:null,code:'unknown_state'}]);
assert.equal(stopped.coverage.undecoded_bytes,4);
const unknown=clone(a); unknown.definition.mappings.splice(1,1);
assert.equal((await model.analyze(unknown.definition,unknown.image)).cfg.edges[0].status,'unknown_mapping');
const literalNull=clone(a); literalNull.image.entry_contexts=[{offset:0,decoder_state:null},{offset:0,decoder_state:'null'}];
literalNull.definition.mappings=[mapping(0,'null','10','HALT',null)];
const nullReport=await model.analyze(literalNull.definition,literalNull.image);
assert.equal(nullReport.instructions[0].id,'context:0:null'); assert.equal(nullReport.cfg.entries[0].status,'unknown_state');

const dynamic=clone(a); dynamic.definition.instructions[0].operations=[op('jump')]; dynamic.definition.instructions[0].flow={kind:'jump',target:null};
const jumpReport=await model.analyze(dynamic.definition,dynamic.image);
assert.equal(jumpReport.instructions.length,1); assert.equal(jumpReport.cfg.edges[0].status,'unknown_target');
assert.equal(jumpReport.cfg.edges[0].to_offset,null); assert.equal(jumpReport.instructions[0].pseudocode[0].text,'goto unknown_target;');

// A backward branch changes decoder state. The same offset must be decoded
// again, while an identical PC/state cycle must terminate without enumeration.
const branch=clone(a); branch.image.bytes_hex='100010'; branch.definition.image_sha256=sha(branch.image.bytes_hex);
branch.definition.instructions=[instruction('BR',[field('target','address')],[op('stack_branch_zero')],{kind:'branch',target:{operand:'target',base:'absolute'}}),instruction('HALT',[],[op('halt')],{kind:'halt'})];
branch.definition.mappings=[mapping(0,'s0','10','BR','s1'),mapping(0,'s1','10','HALT',null),mapping(2,'s1','10','HALT',null)];
const branches=await model.analyze(branch.definition,branch.image);
assert.deepEqual(branches.instructions.map(i=>i.id),['context:0:s0','context:0:s1','context:2:s1']);
branch.definition.mappings[0].next_decoder_state='s0';
assert.equal((await model.analyze(branch.definition,branch.image)).instructions.length,1);

const macro=clone(a); macro.definition.architecture='register'; macro.definition.register_count=2;
macro.image.bytes_hex='1000070110'; macro.definition.image_sha256=sha(macro.image.bytes_hex);
macro.definition.instructions=[instruction('PAIR',[field('dst','register'),field('value','immediate'),field('copy','register')],[op('register_const',['dst','value']),op('register_move',['copy','dst'])]),instruction('HALT',[],[op('halt')],{kind:'halt'})];
macro.definition.mappings=[mapping(0,'s0','10','PAIR','s1'),mapping(4,'s1','10','HALT',null)];
const macros=await model.analyze(macro.definition,macro.image);
assert.deepEqual(macros.instructions[0].pseudocode.map(p=>[p.operation_index,p.text,p.instruction_id]),[[0,'r0 = 7;','context:0:s0'],[1,'r1 = r0;','context:0:s0']]);
assert.equal(macros.instructions[0].size,4);
const repeat=clone(macro); repeat.definition.instructions[0].operations[1]=op('register_const',['dst','value']);
assert.equal((await model.analyze(repeat.definition,repeat.image)).instructions[0].pseudocode[1].text,'r0 = 7;');

for(const mutate of [
 v=>v.mappings.push(clone(v.mappings[0])),v=>v.mappings[0].raw_opcode='XX',v=>v.mappings[0].instruction_id='missing',
 v=>v.mappings[0].decoder_state=null,v=>v.instructions[0].operations=[op('jump'),op('stack_add')],
 v=>v.instructions[0].operations=Array.from({length:9},()=>op('stack_add')),v=>v.instructions[0].operations=[op('eval')],
 v=>v.instructions[0].operands[0].kind='pointer',v=>v.instructions[0].operations[0].args=['missing'],
 v=>v.instructions[0].flow={kind:'jump',target:{operand:'value',base:'absolute'}},v=>v.extra=true,
]) { const value=clone(a.definition);mutate(value);assert.throws(()=>model.parseDefinition(value)); }
for(const mutate of [v=>v.build_id='wrong',v=>v.definition_id='wrong',v=>v.bytes_hex='00']) {
 const image=clone(a.image);mutate(image);await assert.rejects(model.analyze(a.definition,image));
}
for(const data of ['null','[]','{}',JSON.stringify(a.definition).replace('"opcode_bytes":1','"opcode_bytes":1e0'),'{"format":1,"format":2}']) assert.throws(()=>model.parseDefinition(data));
const getter=clone(a.definition); Object.defineProperty(getter,'image_sha256',{get(){throw Error('getter invoked');},enumerable:true});
assert.throws(()=>model.parseDefinition(getter),/accessors/);
const truncated=clone(a);truncated.image.bytes_hex='10';truncated.definition.image_sha256=sha('10');
assert.equal((await model.analyze(truncated.definition,truncated.image)).diagnostics[0].code,'truncated_instruction');
const invalid=clone(macro); invalid.image.bytes_hex='1002070110';invalid.definition.image_sha256=sha(invalid.image.bytes_hex);
assert.equal((await model.analyze(invalid.definition,invalid.image)).diagnostics[0].code,'invalid_operand');
const budget=await model.analyze(a.definition,a.image,{max_instructions:1});
assert.equal(budget.instructions.length,1);assert.equal(budget.cfg.edges[0].status,'instruction_budget');
for (const settings of [{max_instructions:0},{max_instructions:4097},{expression:'eval'}]) await assert.rejects(model.analyze(a.definition,a.image,settings));
const serialized=await model.analyze(JSON.stringify(a.definition),JSON.stringify(a.image));
assert.ok(serialized.provenance.definition_source_sha256);assert.ok(serialized.provenance.image_source_sha256);
assert.equal(serialized.identity.definition_canonical_sha256,report.identity.definition_canonical_sha256);
// Undecoded declarations are not labeled decoys; unknown bytes are not decoded.
const unused=clone(a);unused.definition.instructions.push(instruction('UNUSED',[],[op('nop')]));
assert.equal((await model.analyze(unused.definition,unused.image)).instructions.length,4);
assert.throws(()=>staticModel.parseDefinition(a.definition)); // no accidental v1 reinterpretation
assert.deepEqual(model.parseImage(a.image),a.image);
const original=JSON.stringify(a); await model.analyze(a.definition,a.image);assert.equal(JSON.stringify(a),original);
// Two-byte opcodes are literal even under big-endian signed operands.
const wide=clone(a);wide.definition.opcode_bytes=2;wide.definition.operand_endianness='big';
wide.image.bytes_hex='abcdfffeabcd';wide.definition.image_sha256=sha(wide.image.bytes_hex);
wide.definition.instructions=[instruction('PUSH',[field('value','immediate',2,true)],[op('stack_const',['value'])]),instruction('HALT',[],[op('halt')],{kind:'halt'})];
wide.definition.mappings=[mapping(0,'s0','abcd','PUSH','s1'),mapping(4,'s1','abcd','HALT',null)];
const wideReport=await model.analyze(wide.definition,wide.image);
assert.equal(wideReport.instructions[0].operands[0].value,-2);assert.equal(wideReport.instructions[0].size,4);
const out=clone(branch);out.image.bytes_hex='10ff';out.definition.image_sha256=sha(out.image.bytes_hex);
assert.equal((await model.analyze(out.definition,out.image)).cfg.edges[0].status,'out_of_range');
const states=clone(a.definition);states.mappings=Array.from({length:257},(_,i)=>mapping(i,'state'+i,'10','HALT',null));
assert.throws(()=>model.parseDefinition(states),/state budget/);
const sparse=clone(a.definition);delete sparse.mappings[0];assert.throws(()=>model.parseDefinition(sparse),/dense/);
const empty=clone(a);empty.image.bytes_hex='';empty.definition.image_sha256=sha('');
assert.equal((await model.analyze(empty.definition,empty.image)).cfg.entries[0].status,'out_of_range');
assert.equal(variantReport.coverage.decoded_bytes,6); // overlapping contexts counted once
// Aggregate object input must reject before serializing or UTF-8 allocating a
// complete document. Shared 1 MiB strings keep this adversarial fixture cheap.
const repeated='x'.repeat(model.limits.input_bytes);
const oversizedInputs=[
  {values:Array(4096).fill(repeated)},
  {first:'x'.repeat(600000),second:'y'.repeat(600000)},
  {escaped:'\n'.repeat(600000)},
  {controls:'\u0000'.repeat(200000)},
  {unicode:'😀'.repeat(300000)},
  {['漢'.repeat(400000)]:0},
];
// Exact UTF-8 boundary includes keys, JSON escapes, commas, brackets, colons,
// numbers, booleans, surrogate pairs and independently unpaired surrogates.
const boundary={nested:[null,true,false,0,-9007199254740991,'\u0000\b\t\n\f\r"é漢😀\ud800\udc00\ud800','\udc00'],['key\n漢']:'value',pad:''};
boundary.nested.push(String.fromCharCode(92));
const boundaryOverhead=Buffer.byteLength(JSON.stringify(boundary),'utf8');
boundary.pad='x'.repeat(model.limits.input_bytes-boundaryOverhead);
assert.equal(Buffer.byteLength(JSON.stringify(boundary),'utf8'),model.limits.input_bytes);
const aboveBoundary={...boundary,pad:boundary.pad+'x'};
const nativeStringify=JSON.stringify,NativeEncoder=globalThis.TextEncoder;
try {
  JSON.stringify=()=>{throw Error('Unexpected whole-document serialization');};
  globalThis.TextEncoder=class {constructor(){throw Error('Unexpected full UTF-8 allocation');}};
  for(const value of oversizedInputs) assert.throws(()=>model.parseDefinition(value),/exceeds 1 MiB/);
  assert.throws(()=>model.parseDefinition(boundary),/Invalid contextual definition/);
  assert.throws(()=>model.parseDefinition(aboveBoundary),/exceeds 1 MiB/);
} finally {JSON.stringify=nativeStringify;globalThis.TextEncoder=NativeEncoder;}
assert.deepEqual(model.parseDefinition(a.definition),a.definition);
assert.deepEqual(model.parseImage(a.image),a.image);
console.log('Contextual VM checks passed: build identity, PC/state mappings, macros, branches, unknowns and bounds.');
