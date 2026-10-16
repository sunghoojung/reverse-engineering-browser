import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source = readFileSync(new URL('../apps/research-ui/evidence_models.js', import.meta.url), 'utf8');
const api = new Function(source + '\nreturn {isVmOpcodeEffect,isVmOpcodeEffects,isVmByteCoverage,isVmInstructionTraversal};')();
const effectRow = (operation, instruction_size, operand_layout, kind) => ({effect_id:operation, evidence_class:'inferred',
  operation, instruction_size, operand_layout, reads:[], writes:[], flow:{kind,target_operand:null,target_offset:null},
  atomic_group:null,superoperator:null});
const handlers = [{opcode:1, effects:[effectRow('constant',2,[{name:'value',kind:'immediate',byte_offset:1,byte_size:1}],'next')]},
  {opcode:8,effects:[effectRow('halt',1,[],'halt')]}];
const effect=handlers[0].effects[0];
assert(api.isVmOpcodeEffect(effect));
for(const patch of [{operation:'eval'},{expression:'globalThis.x=1'},{module:'import("x")'}, {operand_layout:[{name:'import("x")',kind:'immediate',byte_offset:1,byte_size:1}]}]) assert.equal(api.isVmOpcodeEffect({...effect,...patch}),false);
assert.equal(api.isVmOpcodeEffects([effect,effect]),false);
const snapshot={artifact_id:'1',byte_count:3,preview_hex:'010708',truncated:false};
const range=(byte_offset,byte_size,opcode,kind)=>({artifact_id:'1',byte_offset,byte_size,opcode,kind,evidence_class:'inferred'});
const coverage={complete:true,handler_count:handlers.length,retained_snapshot_bytes:3,characterized_bytes:3,uncharacterized_bytes:0,
 attributions:[range(0,1,1,'opcode'),range(1,1,1,'operand'),range(2,1,8,'opcode')],omissions:[]};
assert(api.isVmByteCoverage(coverage,[snapshot],handlers,[]));
assert.equal(api.isVmByteCoverage({...coverage,attributions:[null]},[snapshot],handlers,[]),false);
assert.equal(api.isVmByteCoverage({...coverage,handler_count:0},[snapshot],[],[]),false);
assert.equal(api.isVmByteCoverage({...coverage,attributions:[range(0,3,1,'opcode')]},[snapshot],handlers,[]),false);
assert.equal(api.isVmByteCoverage(coverage,[snapshot],handlers,['unknown']),false);
assert.equal(api.isVmByteCoverage(coverage,[{...snapshot,truncated:true}],handlers,[]),false);
const traversal={entry_offsets:[{artifact_id:'1',byte_offset:0}],instructions:[{artifact_id:'1',byte_offset:0,byte_size:2,opcode:1,effect_id:effect.effect_id},{artifact_id:'1',byte_offset:2,byte_size:1,opcode:8,effect_id:handlers[1].effects[0].effect_id}],edges:[{artifact_id:'1',from_offset:0,to_offset:2,kind:'fallthrough'}],frontier:[],complete:true};
assert(api.isVmInstructionTraversal(traversal,[snapshot],handlers));
assert.equal(api.isVmInstructionTraversal({...traversal,edges:[]},[snapshot],handlers),false);
for(const key of ['entry_offsets','instructions','edges','frontier']) assert.equal(api.isVmInstructionTraversal({...traversal,[key]:[null]},[snapshot],handlers),false);
assert.equal(api.isVmInstructionTraversal({...traversal,entry_offsets:[{artifact_id:'1',byte_offset:2}]},[snapshot],handlers),false);
assert.equal(api.isVmInstructionTraversal({...traversal,instructions:[...traversal.instructions,traversal.instructions[0]]},[snapshot],handlers),false);
assert.equal(api.isVmByteCoverage({...coverage,attributions:[range(1,2,1,'operand')]},[snapshot],handlers,[]),false);
console.log('PASS workspace contract helper valid cases and adversarial nulls, executable payloads, unknown opcode, false-complete/graph, overlaps and byte boundaries');
const overlapCoverage={...coverage,attributions:[range(0,1,1,'opcode'),range(1,1,1,'operand'),range(1,1,1,'opcode'),range(2,1,1,'operand')]};
assert.equal(api.isVmByteCoverage(overlapCoverage,[{...snapshot,preview_hex:'010100'}],handlers,[]),false);
assert.equal(api.isVmByteCoverage({...coverage,attributions:[range(1,1,1,'operand')],characterized_bytes:1,uncharacterized_bytes:2,complete:false},[snapshot],handlers,[]),false);
console.log('PASS overlapping instruction attribution and orphan operand refusal');

assert.equal(api.isVmInstructionTraversal(traversal,[{...snapshot,truncated:true}],handlers),false);
assert.equal(api.isVmInstructionTraversal(traversal,[{...snapshot,byte_count:4}],handlers),false);
assert.equal(api.isVmInstructionTraversal(traversal,[snapshot,{...snapshot,artifact_id:'2'}],handlers),false);
console.log('PASS complete traversal refuses truncated tails and missing snapshot entries');
