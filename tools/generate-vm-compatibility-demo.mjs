#!/usr/bin/env node
/* Owned, bounded compatibility fixture. No upstream runtime or captured code. */
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import vm from '../apps/research-ui/vm_semantics.js';
import {saveArchive} from './captured-request-export.mjs';
export const upstreamCommit='7182b81613e8278aafe4ef1da13dd3988eae2f77';
export const program=Object.freeze([0x0601,0x0711,0x0d31,0x0035,0x1003,0x102b,0x2a11,0x0a31,0x0366,0xff21,0x0087,0x0018,0x003d,0x0244,0x001d]);
export function recordCompatibilityDemo(){
 const code=Buffer.alloc(program.length*2);program.forEach((word,i)=>code.writeUInt16LE(word,i*2));
 const memory=new Map(program.map((word,address)=>[address,word]));memory.set(64,0);
 const registers=[0,0,0,0],stack=[];let pc=0,halted=false;
 const snapshot=()=>({pc,halted,registers:[...registers,stack.length],stack:[...stack],memory:[...memory].sort((a,b)=>a[0]-b[0])});
 const steps=[];
 while(!halted){
  if(steps.length>=32||!Number.isInteger(pc)||pc<0||pc>=program.length)throw Error('Owned fixture control-flow bound exceeded');
  const before=snapshot(),word=memory.get(pc++),opcode=word&15;let operands;
  // Intentionally only this fixed program's operations. No input program loader.
  if(opcode===1){const register=(word>>4)&3,constant=word>>8;registers[register]=constant;operands=[register,constant];}
  else if(word===0x0035){stack.push(pc);pc=registers[3];operands=[3];}
  else if(word===0x1003){memory.set(64,registers[0]&65535);operands=[64,0];}
  else if(word===0x102b){registers[2]=memory.get(64);operands=[2,64];}
  else if(word===0x0244){registers[0]=(registers[0]*registers[1])&65535;operands=[0,1];}
  else if(word===0x001d){if(!stack.length)throw Error('Owned fixture return underflow');pc=stack.pop();operands=[];}
  else if(word===0x0366){if(registers[2]===registers[1])pc=registers[3];operands=[2,1,3];}
  else if(word===0x0087){stack.push(registers[2]);operands=[2];}
  else if(word===0x0018){if(!stack.length)throw Error('Owned fixture pop underflow');registers[1]=stack.pop();operands=[1];}
  else if(word===0x003d){halted=true;operands=[];}
  else throw Error('Instruction outside the reviewed compatibility subset');
  const bytes=Buffer.alloc(2);bytes.writeUInt16LE(word);
  steps.push({sequence:steps.length,opcode:bytes.toString('hex'),operands,instruction_size:1,before,after:snapshot(),evidence_refs:[`owned-16bit-demo:step:${steps.length}`]});
 }
 return vm.trace({format:'reb-vm-trace-v1',identity:{trace_id:'owned-16bit-compatibility-demo',investigation_id:'owned-demo',finding_id:'unlinked',artifact_id:'owned-demo-code-words',artifact_sha256:createHash('sha256').update(code).digest('hex'),scope_id:'fixed-15-word-program',backend:'fixture'},architecture:'register',coverage:{complete:true,dropped_steps:0,limitations:[
  'Owned source-derived compatibility fixture; not execution of upstream 16bitjs or an unknown VM.',
  `ISA reference: francisrstokes/16bitjs at ${upstreamCommit}; reviewed fixed-program subset only.`,
  'PC, memory addresses and instruction_size use 16-bit word units. Supplied opcode hex is the complete instruction word in little-endian byte order.',
  'Registers are A,B,C,D,SP in that order. SP is the logical stack length; IP is represented by pc. Stack contains live entries only.',
  'Memory retains all 15 code words and data address64, initially known zero. Other addresses are omitted and therefore unknown in this projection.',
  'HLT increments PC during fetch, then sets halted. Final PC13 does not imply that the instruction at13 executed again.',
  'Declared subset semantics and independent golden checks are documented in docs/development/vm-compatibility-demo.md. No native/browser capture is claimed.'
 ]},steps});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const usage='Usage: node tools/generate-vm-compatibility-demo.mjs OUTPUT.json\n       node tools/generate-vm-compatibility-demo.mjs --help\nRecords only the fixed owned compatibility fixture; refuses existing outputs.';
 try{
  const args=process.argv.slice(2);
  if(args.length===1&&args[0]==='--help')console.log(usage);
  else {
   if(args.length!==1||args[0].startsWith('-'))throw Error(usage);
   const trace=recordCompatibilityDemo();await saveArchive(args[0],Buffer.from(JSON.stringify(trace,null,2)+'\n'));
   console.log(`Recorded ${trace.steps.length} owned compatibility-fixture transitions.`);
  }
 }catch(error){console.error(error.message);process.exitCode=1;}
}
