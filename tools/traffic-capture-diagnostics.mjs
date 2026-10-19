// Fixture-only byte-preserving relay. Extra process scheduling can perturb timing.
// Whitelisted control metadata only; no URLs, headers, bodies or script sources.
import {spawn} from 'node:child_process';
import {writeFileSync,renameSync} from 'node:fs';
import {readdir,open,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';

export async function prepareCaptureDiagnosticTransport(directory,transport) {
  const quote=s=>"'"+s.replaceAll("'","'\\''")+"'",path=join(directory,'diagnostic-transport');
  await writeFile(path,`#!/bin/sh\nexec ${quote(process.execPath)} ${quote(fileURLToPath(import.meta.url))} --relay ${quote(directory)} ${quote(transport)} "$@"\n`,{mode:0o700});
  return path;
}
const safeInteger=value=>Number.isSafeInteger(value)&&value>=0?value:null;
const alias=value=>typeof value==='string'&&/^identity-[1-9][0-9]{0,2}$/.test(value)?value:null;
function cleanEvent(value) {
  const phase=enumValue(value?.phase,['sent','reply','attached']);
  if(!phase)throw Error('invalid-diagnostic-event');
  return {phase,time:safeInteger(value.time),connection:safeInteger(value.connection),
    ...(phase==='attached'?{session:alias(value.session),parent:alias(value.parent),target:alias(value.target),
      type:enumValue(value.type,['page','iframe','worker','shared_worker','service_worker','other']),waiting:typeof value.waiting==='boolean'?value.waiting:null}
      :{id:safeInteger(value.id),method:enumValue(value.method,['Network.enable','Target.setAutoAttach','Runtime.runIfWaitingForDebugger']),
        session:alias(value.session),...(phase==='sent'?{wait:typeof value.wait==='boolean'?value.wait:null}:{error:typeof value.error==='boolean'?value.error:null})})};
}
export function createCaptureDiagnosticTail() {
  const limit=8192;
  const events=[]; let sequence=0,droppedEvents=0,skippedFrames=0,droppedCorrelations=0;
  const snapshot=()=>({sequence,firstSequence:events[0]?.sequence??null,retainedEvents:events.length,droppedEvents,skippedFrames,droppedCorrelations,
    truncated:droppedEvents>0||skippedFrames>0||droppedCorrelations>0,events:[...events]});
  const encode=()=>{
    while(Buffer.byteLength(JSON.stringify(snapshot()))>limit&&events.length){events.shift();droppedEvents++;}
    return JSON.stringify(snapshot());
  };
  return {
    record(value){events.push({...cleanEvent(value),sequence:++sequence});return encode();},
    skip(){skippedFrames++;return encode();},
    dropCorrelation(){droppedCorrelations++;return encode();},
    encode,
  };
}
export async function readCaptureDiagnostics(directory) {
  const files=(await readdir(directory)).filter(name=>/^capture-lifecycle-\d+$/.test(name)).sort((a,b)=>Number(a.split('-').at(-1))-Number(b.split('-').at(-1)));
  const result={connections:[],omittedConnections:Math.max(0,files.length-64),omittedEvents:0,unreadableConnections:0,truncated:files.length>64};
  for(const file of files.slice(-64)) {
    try {
      const handle=await open(join(directory,file),'r');
      let bytes;
      try {const buffer=Buffer.alloc(8193);const result=await handle.read(buffer,0,buffer.length,0);bytes=buffer.subarray(0,result.bytesRead);}finally{await handle.close();}
      if(bytes.length>8192)throw Error('diagnostic-limit');
      const value=JSON.parse(bytes);
      const keys=['sequence','retainedEvents','droppedEvents','skippedFrames','droppedCorrelations'];
      if(!Array.isArray(value.events)||value.events.length>512||keys.some(key=>safeInteger(value[key])===null)||typeof value.truncated!=='boolean')throw Error('invalid-diagnostic-tail');
      const safe={...Object.fromEntries(keys.map(key=>[key,value[key]])),firstSequence:safeInteger(value.firstSequence),truncated:value.truncated,
        events:value.events.map(event=>{if(safeInteger(event.sequence)===null)throw Error('invalid-diagnostic-sequence');return {...cleanEvent(event),sequence:event.sequence};})};
      result.connections.push(safe);
      result.truncated ||= safe.truncated;
    } catch {result.unreadableConnections++;result.truncated=true;}
  }
  while(Buffer.byteLength(JSON.stringify(result))>65536&&result.connections.length){
    result.omittedEvents+=result.connections.shift().events.length;result.omittedConnections++;result.truncated=true;
  }
  return JSON.stringify(result);
}
export const captureFirstFixturePaths = [
  '/initial','/initial-inline','/popup','/popup-inline','/contexts',
  '/dedicated.js','/dedicated-inline','/nested-worker.js','/nested-inline',
  '/outer-frame','/outer-inline','/inner-frame','/inner-inline','/frame-worker.js','/frame-worker-inline',
  ...Array.from({length:4},(_,i)=>`/early-tab/${i}`),
  ...Array.from({length:4},(_,i)=>`/early-inline/${i}`),
  ...Array.from({length:3},(_,i)=>`/worker-steady/${i}`),
];
const enumValue=(value,allowed)=>allowed.includes(value)?value:null;
const boundedCount=value=>Number.isSafeInteger(value)&&value>=0&&value<=10000000?value:null;
export function summarizeCaptureState(value) {
  const capture=value?.network?.capture_status;
  return {
    state:enumValue(value?.state,['running','waiting','stopped','failed','disabled']),
    hasError:!!value?.error,
    targetCount:boundedCount(value?.targets?.length),
    requestCount:boundedCount(value?.network?.requests?.length),
    captureStatus:{
      state:enumValue(capture?.state,['ready','waiting','initializing','failed','disabled','incomplete','partial']),
      startupMode:enumValue(capture?.startup_mode,['passive','capture-first']),
      scope:enumValue(capture?.scope,['http-page-targets','http-browser-targets']),
      transportMode:enumValue(capture?.transport_mode,['browser-sessions','page-fallback']),
      ...Object.fromEntries(['gaps','attached_targets','eligible_targets','failed_targets','target_overflow','cleanup_failures','cleanup_already_gone','unattached_targets_omitted','held_targets','resumed_targets','hold_timeouts','resume_failures','hold_max_ms'].map(key=>[key,boundedCount(capture?.[key])])),
      hasLastError:!!capture?.last_error,
    },
  };
}
export const captureCaseStages = Object.freeze([
  'case-start','navigation','target-creation','authored-worker-lookup','target-attachment',
  'evaluation','evaluation-exception','receipt-wait','backend-snapshot','row-body-wait',
  'request-row-presence','response-body-presence','receipt-multiplicity','target-owner',
  'distinct-targets','response-body-value','request-row-identity','popup-close',
  'capture-mode','debugger-focus','owned-process-stop','profile-removal',
]);
const safeCaseStage=value=>captureCaseStages.includes(value)?value:'unclassified';
export function createCaptureCaseStage() {
  let current='case-start';
  return {mark:value=>{current=safeCaseStage(value);},current:()=>current};
}
export async function captureFailureEvidence({readState,expectedPaths,servedCounts,stage}) {
  let snapshot=null,snapshotError=null;
  try {snapshot=summarizeCaptureState(await readState());} catch {snapshotError='fresh-snapshot-unavailable';}
  const paths=[...new Set(expectedPaths)].filter(path=>captureFirstFixturePaths.includes(path));
  return {stage:safeCaseStage(stage),snapshot,snapshotError,receipts:paths.map(path=>({path,count:boundedCount(servedCounts.get(path)??0)})),
    missingPaths:paths.filter(path=>!servedCounts.get(path))};
}
if(process.argv[2]==='--relay') {
  const [directory,transport,...args]=process.argv.slice(3),path=join(directory,`capture-lifecycle-${process.pid}`);
  const tail=createCaptureDiagnosticTail();
  const persist=value=>{writeFileSync(path+'.tmp',value);renameSync(path+'.tmp',path);};
  persist(tail.encode());let stopping=false,timer;
  const child=spawn(transport,args,{stdio:['pipe','pipe','pipe']}),pending=new Map();
  child.stderr.resume();
  const identities=new Map();
  const text=value=>{if(typeof value!=='string')return null;if(!identities.has(value)){if(identities.size>=512){persist(tail.dropCorrelation());return null;}identities.set(value,`identity-${identities.size+1}`);}return identities.get(value);};
  const record=value=>persist(tail.record({time:Date.now(),connection:process.pid,...value}));
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
          if(!keep)persist(tail.skip());
        }
        const size=Math.min(remaining,chunk.length);if(keep)parts.push(chunk.subarray(0,size));chunk=chunk.subarray(size);remaining-=size;
        if(remaining||!keep)continue;
        let m;try{m=JSON.parse(Buffer.concat(parts));}catch{persist(tail.skip());continue;}
        if(direction==='sent'&&Number.isSafeInteger(m.id)&&['Network.enable','Target.setAutoAttach','Runtime.runIfWaitingForDebugger'].includes(m.method)) {
          if(pending.size<256)pending.set(m.id,{method:m.method,session:text(m.sessionId)});else persist(tail.dropCorrelation());
          record({phase:'sent',id:m.id,method:m.method,session:text(m.sessionId),wait:typeof m.params?.waitForDebuggerOnStart==='boolean'?m.params.waitForDebuggerOnStart:null});
        } else if(direction==='received'&&pending.has(m.id)) {
          record({phase:'reply',id:m.id,...pending.get(m.id),error:!!m.error});pending.delete(m.id);
        } else if(direction==='received'&&m.method==='Target.attachedToTarget') {
          record({phase:'attached',session:text(m.params?.sessionId),parent:text(m.sessionId),target:text(m.params?.targetInfo?.targetId),type:enumValue(m.params?.targetInfo?.type,['page','iframe','worker','shared_worker','service_worker','other']),waiting:typeof m.params?.waitingForDebugger==='boolean'?m.params.waitingForDebugger:null});
        }
      }
    };
  };
  process.stdin.on('data',inspect('sent'));child.stdout.on('data',inspect('received'));
  process.stdin.pipe(child.stdin);child.stdout.pipe(process.stdout);
  process.stdin.on('end',()=>{timer=setTimeout(stop,1000);timer.unref();});
  child.on('error',()=>{console.error('Diagnostic transport failed to start');process.exitCode=1;process.stdin.destroy();});
  child.on('close',(code,signal)=>{clearTimeout(timer);process.stdin.destroy();process.exitCode=code??(signal?1:0);});
}
