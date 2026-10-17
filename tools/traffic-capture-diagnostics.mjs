// Fixture-only byte-preserving relay. Extra process scheduling can perturb timing.
// Whitelisted control metadata only; no URLs, headers, bodies or script sources.
import {spawn} from 'node:child_process';
import {appendFileSync,writeFileSync} from 'node:fs';
import {readdir,readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';

export async function prepareCaptureDiagnosticTransport(directory,transport) {
  const quote=s=>"'"+s.replaceAll("'","'\\''")+"'",path=join(directory,'diagnostic-transport');
  await writeFile(path,`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(fileURLToPath(import.meta.url))} --relay ${quote(directory)} ${quote(transport)} "$@"\n`,{mode:0o700});
  return path;
}
export async function readCaptureDiagnostics(directory) {
  let output=Buffer.alloc(0);
  for(const file of (await readdir(directory)).filter(name=>/^capture-lifecycle-\d+$/.test(name)).sort().slice(0,64)) {
    const bytes=await readFile(join(directory,file));output=Buffer.concat([output,bytes.subarray(0,65536-output.length)]);
    if(output.length===65536)break;
  }
  return output.toString('utf8');
}
if(process.argv[2]==='--relay') {
  const [directory,transport,...args]=process.argv.slice(3),path=join(directory,`capture-lifecycle-${process.pid}`);
  writeFileSync(path,'');let written=0,stopping=false,timer;
  const child=spawn(transport,args,{stdio:['pipe','pipe','inherit']}),pending=new Map();
  const text=value=>typeof value==='string'?value.slice(0,128):null;
  const record=value=>{const bytes=Buffer.from(JSON.stringify({time:Date.now(),connection:process.pid,...value})+'\n');if(written+bytes.length<=8192){appendFileSync(path,bytes);written+=bytes.length;}};
  const stop=()=>{if(stopping)return;stopping=true;child.stdin.destroy();child.kill('SIGTERM');timer=setTimeout(()=>child.kill('SIGKILL'),250);timer.unref();};
  process.on('SIGTERM',stop);process.on('SIGINT',stop);process.stdout.on('error',stop);child.stdin.on('error',stop);
  process.on('exit',()=>child.kill('SIGKILL'));
  const inspect=direction=>{
    let header=Buffer.alloc(0),remaining=0,parts=[],keep=false;
    return chunk=>{
      while(chunk.length) {
        if(remaining===0) {
          const size=Math.min(8-header.length,chunk.length);header=Buffer.concat([header,chunk.subarray(0,size)]);chunk=chunk.subarray(size);
          if(header.length<8)continue;
          remaining=header.readUInt32BE(4);keep=remaining>0&&remaining<=32768;parts=[];header=Buffer.alloc(0);
          if(remaining===0)continue;
        }
        const size=Math.min(remaining,chunk.length);if(keep)parts.push(chunk.subarray(0,size));chunk=chunk.subarray(size);remaining-=size;
        if(remaining||!keep)continue;
        let m;try{m=JSON.parse(Buffer.concat(parts));}catch{continue;}
        if(direction==='sent'&&Number.isSafeInteger(m.id)&&['Network.enable','Target.setAutoAttach','Runtime.runIfWaitingForDebugger'].includes(m.method)) {
          if(pending.size<256)pending.set(m.id,{method:m.method,session:text(m.sessionId)});
          record({phase:'sent',id:m.id,method:m.method,session:text(m.sessionId),wait:typeof m.params?.waitForDebuggerOnStart==='boolean'?m.params.waitForDebuggerOnStart:null});
        } else if(direction==='received'&&pending.has(m.id)) {
          record({phase:'reply',id:m.id,...pending.get(m.id),error:!!m.error});pending.delete(m.id);
        } else if(direction==='received'&&m.method==='Target.attachedToTarget') {
          record({phase:'attached',session:text(m.params?.sessionId),parent:text(m.sessionId),target:text(m.params?.targetInfo?.targetId),type:text(m.params?.targetInfo?.type),waiting:typeof m.params?.waitingForDebugger==='boolean'?m.params.waitingForDebugger:null});
        }
      }
    };
  };
  process.stdin.on('data',inspect('sent'));child.stdout.on('data',inspect('received'));
  process.stdin.pipe(child.stdin);child.stdout.pipe(process.stdout);
  process.stdin.on('end',()=>{timer=setTimeout(stop,1000);timer.unref();});
  child.on('error',error=>{console.error(error.message);process.exitCode=1;process.stdin.destroy();});
  child.on('close',(code,signal)=>{clearTimeout(timer);process.stdin.destroy();process.exitCode=code??(signal?1:0);});
}
