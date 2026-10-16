import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../apps/research-ui/evidence_models.js',import.meta.url),'utf8');
const {isVmOwnedExperimentRecord:valid}=new Function(source+'\nreturn {isVmOwnedExperimentRecord};')();
const effect={operation:'add_modulo_2_64',value:'12',next_pc:'3',branch_taken:null};
const request={command_id:'owned-test',fixture:'register',workspace_digest:'a'.repeat(64),source_artifact_sha256:'32f42d2408c8b2b77539c49ad458f3923d819fedc323e6529bbff7e83b14a52e',interpreter_artifact_id:'107',finding_id:'f-1',opcode:2,effect_id:'native-register-add_modulo_2_64-v1',inputs:{left:'7',right:'5'},expected:effect};
const row={request,effect_digest:'b'.repeat(64),fixture_revision:1,status:'confirmed',independent:effect,reason:'agreement-for-listed-inputs-only',observed:{backend_instance_id:'backend',session_id:'session',run_id:'run',run_generation:'1',invocation_id:'1',record_sequence:'3',build_id:'c'.repeat(64),program_sha256:'2e9f20bb3380e518db160b5da89e9a1530b03e31fb2bf094591b7ee5e0e1e778',opcode:2,handler_index:2,pc_before:'2',instruction_pointer_units:'instruction-index',inputs:request.inputs,effect}};
assert(valid(row));
for(const mutate of [r=>r.request.expected.value='13',r=>r.observed.effect.next_pc='4',r=>r.observed.pc_before='0',r=>r.observed.handler_index=7,r=>r.observed.instruction_pointer_units='byte-offset',r=>r.request.inputs.left='8',r=>r.observed=null,r=>r.independent=null,r=>r.expression='eval("x")',r=>r.request.inputs.right='18446744073709551616']) {const bad=JSON.parse(JSON.stringify(row));mutate(bad);assert.equal(valid(bad),false);}
assert.equal(valid(null),false);
const wrong=JSON.parse(JSON.stringify(row));wrong.status='mismatch';wrong.reason='expected-or-observed-effect-differs';wrong.request.expected.value='13';assert(valid(wrong));
const unsupported=JSON.parse(JSON.stringify(row));unsupported.status='unsupported';unsupported.reason='fixed-owned-inputs-only';unsupported.request.inputs.left='8';unsupported.independent=null;unsupported.observed=null;assert(valid(unsupported));
console.log('PASS owned opcode experiment records: input-specific confirmation, mismatch, unsupported, forged confirmation refusal');
