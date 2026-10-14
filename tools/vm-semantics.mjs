#!/usr/bin/env node
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import vm from '../apps/research-ui/vm_semantics.js';
import {saveArchive} from './captured-request-export.mjs';
async function read(path){let file;try{file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);const info=await file.stat();if(!info.isFile()||info.size>1048576)throw Error('Expected regular file up to 1 MiB');const data=Buffer.alloc(1048577);let length=0;while(length<data.length){const r=await file.read(data,length,data.length-length,null);if(!r.bytesRead)break;length+=r.bytesRead;}if(length>1048576)throw Error('File exceeds 1 MiB');const bytes=data.subarray(0,length);return {document:vm.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes)),sha256:createHash('sha256').update(bytes).digest('hex')};}finally{await file?.close();}}
try{
 const args=process.argv.slice(2);if(args.length===1&&args[0]==='--help'){console.log('node tools/vm-semantics.mjs inspect TRACE.json OUTPUT.json\nnode tools/vm-semantics.mjs step TRACE.json SEQUENCE OUTPUT.json\nnode tools/vm-semantics.mjs validate TRACE.json HYPOTHESES.json OUTPUT.json\nOffline, bounded supplied evidence only; never executes captured code.');}else{
 const [command,input,third,fourth]=args;if(!['inspect','step','validate'].includes(command)||args.length!==(command==='inspect'?3:4))throw Error('Use --help for explicit offline commands');
 const source=await read(input),trace=vm.trace(source.document);let result,hypothesisHash=null;
 if(command==='inspect')result=vm.inspect(trace);
 if(command==='step'){if(!/^(0|[1-9][0-9]*)$/.test(third))throw Error('Expected exact sequence');const step=trace.steps.find(s=>String(s.sequence)===third);if(!step)throw Error('Step not retained');result={format:'reb-vm-step-v1',identity:trace.identity,step,changes:vm.effects(step),reads:'unknown'};}
 if(command==='validate'){const hypotheses=await read(third);result=vm.validate(trace,hypotheses.document);hypothesisHash=hypotheses.sha256;}
 const output=Buffer.from(JSON.stringify({source_sha256:source.sha256,hypotheses_sha256:hypothesisHash,result},null,2)+'\n');if(output.length>4194304)throw Error('Report exceeds 4 MiB');const cleanup=await saveArchive(command==='inspect'?third:fourth,output);console.log(JSON.stringify({bytes:output.length,network_requests:0,temporary_cleanup_pending:cleanup}));
 }
}catch(error){console.error(error.message);process.exitCode=1;}
