import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp,writeFile,readFile,rm,readdir,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {prepareCaptureDiagnosticTransport,readCaptureDiagnostics,createCaptureDiagnosticTail,captureFailureEvidence,createCaptureCaseStage,captureCaseStages} from './traffic-capture-diagnostics.mjs';
import {stopBrowserTestProcess, waitForClose} from './browser-test-process.mjs';

function fixture(source) {
  const child = spawn(process.execPath, ['-e', source], {stdio: ['ignore', 'pipe', 'pipe']});
  const closed = new Promise(resolve => child.once('close', resolve));
  return {child, closed};
}

// A direct child can exit before an inherited stdio writer closes.
const inherited = fixture(`
  require('node:child_process').spawn(process.execPath,
    ['-e', 'setTimeout(() => {}, 150)'], {stdio: ['ignore', 1, 2]});
  process.exit(0);
`);
await once(inherited.child, 'exit');
assert.equal(await waitForClose(inherited.closed, 5), false);
await stopBrowserTestProcess(inherited);
assert.equal(await waitForClose(inherited.closed, 5), true);

// A TERM-resistant owned process must be killed and reaped within the bound.
const resistant = fixture(`
  process.on('SIGTERM', () => {});
  process.stdout.write('ready');
  setInterval(() => {}, 1000);
`);
await once(resistant.child.stdout, 'data');
await stopBrowserTestProcess(resistant, 100);
assert.equal(resistant.child.signalCode, 'SIGKILL');
assert.equal(await waitForClose(resistant.closed, 5), true);

// Missing executable also emits close; cleanup must not hang on spawn failure.
const missing = spawn('/reb-test-missing-executable', [], {stdio: 'ignore'});
missing.on('error', () => {});
await stopBrowserTestProcess({child: missing, closed: new Promise(resolve => missing.once('close', resolve))}, 100);

// Refuse profile removal when the owned process cannot be confirmed closed.
const signals = [];
await assert.rejects(stopBrowserTestProcess({
  child: {pid: 'fixture', exitCode: null, signalCode: null, kill: signal => signals.push(signal)},
  closed: new Promise(() => {}),
}, 5), /did not close; preserving its profile/);
assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
console.log('PASS browser fixture cleanup: inherited stdio close, bounded TERM/KILL reap, spawn failure and unreaped profile refusal');

// The optional diagnostic relay must preserve transport bytes and child lifetime.
const directory=await mkdtemp(join(tmpdir(),'reb-relay-check-')),relays=[];
const frame=value=>{
  const body=value===null?Buffer.alloc(0):Buffer.from(JSON.stringify(value));
  const header=Buffer.from([82,69,66,1,0,0,0,0]);header.writeUInt32BE(body.length,4);
  return Buffer.concat([header,body]);
};
try {
  const native=join(directory,'native'),launcher=await prepareCaptureDiagnosticTransport(directory,native);
  const start=()=>{const child=spawn(launcher,['--url','ws://127.0.0.1:1']);const relay={child,closed:new Promise(resolve=>child.once('close',resolve))};relays.push(relay);return relay;};
  const attached=frame({method:'Target.attachedToTarget',params:{sessionId:'secret-session',targetInfo:{targetId:'secret-target',type:'page',url:'secret-url'},waitingForDebugger:true}});
  const output=Buffer.concat([frame(null),attached,frame({id:1,error:{message:'secret-error'}}),frame({method:'Network.responseReceived',params:{private:'secret-response'.repeat(9000)}}),...Array(200).fill(attached)]);
  const command=frame({id:1,method:'Network.enable',params:{private:'secret-command'},sessionId:'secret-session'});
  await writeFile(native,`#!${process.execPath}
const fs=require('fs');let input=[];process.stdin.on('data',bytes=>input.push(bytes));process.stdin.on('end',()=>{
  fs.writeFileSync(${JSON.stringify(join(directory,'input'))},Buffer.concat(input));
  const output=Buffer.from(${JSON.stringify(output.toString('base64'))},'base64');process.stdout.write(output.subarray(0,3));setTimeout(()=>process.stdout.end(output.subarray(3)),5);
});`,{mode:0o700});
  const relay=start(),received=[];relay.child.stdout.on('data',bytes=>received.push(bytes));relay.child.stdin.end(command);
  assert(await waitForClose(relay.closed,5000),'Relay exact-byte fixture closes');
  assert.equal(relay.child.exitCode,0);assert.deepEqual(Buffer.concat(received),output);assert.deepEqual(await readFile(join(directory,'input')),command);
  const diagnostic=await readCaptureDiagnostics(directory);
  const tail=JSON.parse(diagnostic).connections[0];
  assert(tail.truncated&&tail.droppedEvents>0);
  assert.equal(tail.sequence,203);
  assert.equal(tail.events.at(-1).sequence,203);
  assert.equal(tail.events.at(-1).phase,'attached');
  assert.equal(tail.droppedEvents+tail.events.length,tail.sequence);
  assert.equal(tail.skippedFrames,1);
  assert(tail.events[0].sequence>1,'Tail retains newest events rather than freezing at 8 KiB');
  assert(!diagnostic.includes('secret'));
  for(const name of(await readdir(directory)).filter(name=>name.startsWith('capture-lifecycle-')))assert((await stat(join(directory,name))).size<=8192);
  for(const mode of ['signal','stdin-eof']) {
    await writeFile(native,`#!${process.execPath}
require('fs').writeFileSync(${JSON.stringify(join(directory,'pid'))},String(process.pid));process.on('SIGTERM',()=>{});process.stdout.write('ready');setInterval(()=>{},1000);`,{mode:0o700});
    const relay=start();await once(relay.child.stdout,'data');
    const pid=Number(await readFile(join(directory,'pid'),'utf8'));
    if(mode==='signal')relay.child.kill('SIGTERM');else relay.child.stdin.end();
    assert(await waitForClose(relay.closed,5000),`Relay ${mode} closes`);
    assert.throws(()=>process.kill(pid,0),{code:'ESRCH'},`Relay ${mode} reaps resistant native child`);
  }
} finally {
  for(const relay of relays)await stopBrowserTestProcess(relay,2000);
  await rm(directory,{recursive:true,force:true});
}
console.log('PASS capture diagnostic relay: exact bytes, fragmented frame, payload exclusion, bounded metadata, signal/EOF child cleanup');

const ring=createCaptureDiagnosticTail();
for(let i=0;i<200;i++)ring.record({phase:'sent',id:i,method:'Network.enable',session:'identity-1'});
const ringResult=JSON.parse(ring.encode());
assert(Buffer.byteLength(ring.encode())<=8192);
assert.equal(ringResult.events.at(-1).id,199);
assert.equal(ringResult.droppedEvents+ringResult.events.length,200);
assert.equal(ringResult.truncated,true);
const empty=JSON.parse(createCaptureDiagnosticTail().encode());
assert.equal(empty.truncated,false);
assert.equal(empty.sequence,0);
let reads=0;
const evidence=await captureFailureEvidence({
  readState:async()=>{reads++;return {state:'running',error:'PRIVATE raw error',targets:[{url:'https://private.invalid/'}],
    network:{requests:[{url:'https://private.invalid/'}],capture_status:{state:'partial',startup_mode:'capture-first',scope:'http-browser-targets',transport_mode:'browser-sessions',attached_targets:4,held_targets:2,resumed_targets:3,hold_timeouts:1,resume_failures:0,hold_max_ms:550,last_error:'PRIVATE',secret:'PRIVATE'}}};},
  expectedPaths:['/contexts','/dedicated-inline','https://private.invalid/','/PRIVATE'],
  servedCounts:new Map([['/contexts',1],['/PRIVATE',12]]),
});
assert.equal(reads,1,'Failure evidence always requests a fresh backend state');
assert.equal(evidence.snapshot.captureStatus.attached_targets,4);
assert.equal(evidence.snapshot.hasError,true);
assert.equal(evidence.snapshot.captureStatus.state,'partial');
assert.equal(evidence.snapshot.captureStatus.scope,'http-browser-targets');
assert.equal(evidence.snapshot.captureStatus.transportMode,'browser-sessions');
for(const [key,value] of Object.entries({held_targets:2,resumed_targets:3,hold_timeouts:1,resume_failures:0,hold_max_ms:550}))assert.equal(evidence.snapshot.captureStatus[key],value);
assert.deepEqual(evidence.missingPaths,['/dedicated-inline']);
assert.deepEqual(evidence.receipts,[{path:'/contexts',count:1},{path:'/dedicated-inline',count:0}]);
assert(!JSON.stringify(evidence).includes('PRIVATE'));
assert(!JSON.stringify(evidence).includes('https:'));
const unavailable=await captureFailureEvidence({readState:async()=>{throw Error('PRIVATE raw error');},expectedPaths:['/contexts'],servedCounts:new Map()});
assert.equal(unavailable.snapshot,null);
assert.equal(unavailable.snapshotError,'fresh-snapshot-unavailable');
assert.deepEqual(unavailable.missingPaths,['/contexts']);
assert(!JSON.stringify(unavailable).includes('PRIVATE'));
const runner=await readFile(new URL('./check-traffic-capture-first-browser.mjs',import.meta.url),'utf8');
assert(runner.includes('await captureFailureEvidence({readState:state,expectedPaths,servedCounts,stage:caseStage.current()})'));
assert(!runner.includes('Last capture snapshot:'));
assert(!runner.includes('${error.message}'));
console.log('PASS diagnostic tail: newest sequence, explicit loss, bounded bytes, fresh failure snapshot, authored receipt paths and raw-error/privacy refusal');

const tailDirectory=await mkdtemp(join(tmpdir(),'reb-tail-export-check-'));
try {
  for(let i=1;i<=70;i++)await writeFile(join(tailDirectory,`capture-lifecycle-${i}`),ring.encode());
  const combined=await readCaptureDiagnostics(tailDirectory),parsed=JSON.parse(combined);
  assert(Buffer.byteLength(combined)<=65536);
  assert(parsed.truncated&&parsed.omittedConnections>0&&parsed.omittedEvents>0);
  assert.equal(parsed.connections.at(-1).sequence,200);
  const privateTail=createCaptureDiagnosticTail();
  privateTail.record({phase:'attached',session:'PRIVATE',target:'PRIVATE',type:'PRIVATE',payload:'PRIVATE'});
  const privateValue=JSON.parse(privateTail.encode());
  privateValue.events[0].raw='PRIVATE';privateValue.raw='PRIVATE';
  await writeFile(join(tailDirectory,'capture-lifecycle-71'),JSON.stringify(privateValue));
  assert(!(await readCaptureDiagnostics(tailDirectory)).includes('PRIVATE'));
  await writeFile(join(tailDirectory,'capture-lifecycle-72'),'PRIVATE'.repeat(2000));
  const rejected=JSON.parse(await readCaptureDiagnostics(tailDirectory));
  assert(rejected.truncated&&rejected.unreadableConnections===1);
}finally{await rm(tailDirectory,{recursive:true,force:true});}
console.log('PASS lifecycle export: latest bounded connections, explicit aggregate loss, oversized refusal and allowlisted metadata');

const stage=createCaptureCaseStage();
assert.equal(stage.current(),'case-start');
for(const code of captureCaseStages){stage.mark(code);assert.equal(stage.current(),code);}
for(const raw of ['PRIVATE assertion failed','https://private.invalid/',undefined,{message:'PRIVATE'}]){
  stage.mark(raw);assert.equal(stage.current(),'unclassified');
  const safe=await captureFailureEvidence({stage:raw,readState:async()=>({}),expectedPaths:[],servedCounts:new Map()});
  assert.equal(safe.stage,'unclassified');assert(!JSON.stringify(safe).includes('PRIVATE'));assert(!JSON.stringify(safe).includes('https:'));
}
for(const code of ['authored-worker-lookup','evaluation-exception','receipt-wait','request-row-presence','response-body-presence','target-owner','response-body-value'])assert(runner.includes(`caseStage.mark('${code}')`));
console.log('PASS fixed case-stage allowlist: worker lookup, evaluation, receipts, missing row/body and owner/body assertions remain distinguishable without raw errors');
