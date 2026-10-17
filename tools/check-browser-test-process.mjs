import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp,writeFile,readFile,rm,readdir,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {prepareCaptureDiagnosticTransport,readCaptureDiagnostics} from './traffic-capture-diagnostics.mjs';
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
  const attached=frame({method:'Target.attachedToTarget',params:{sessionId:'s1',targetInfo:{targetId:'t1',type:'page',url:'secret-url'},waitingForDebugger:true}});
  const output=Buffer.concat([frame(null),attached,frame({id:1,result:{}}),frame({method:'Network.responseReceived',params:{private:'secret-response'.repeat(9000)}}),...Array(200).fill(attached)]);
  const command=frame({id:1,method:'Network.enable',params:{private:'secret-command'},sessionId:'s1'});
  await writeFile(native,`#!${process.execPath}
const fs=require('fs');let input=[];process.stdin.on('data',bytes=>input.push(bytes));process.stdin.on('end',()=>{
  fs.writeFileSync(${JSON.stringify(join(directory,'input'))},Buffer.concat(input));
  const output=Buffer.from(${JSON.stringify(output.toString('base64'))},'base64');process.stdout.write(output.subarray(0,3));setTimeout(()=>process.stdout.end(output.subarray(3)),5);
});`,{mode:0o700});
  const relay=start(),received=[];relay.child.stdout.on('data',bytes=>received.push(bytes));relay.child.stdin.end(command);
  assert(await waitForClose(relay.closed,5000),'Relay exact-byte fixture closes');
  assert.equal(relay.child.exitCode,0);assert.deepEqual(Buffer.concat(received),output);assert.deepEqual(await readFile(join(directory,'input')),command);
  const diagnostic=await readCaptureDiagnostics(directory);
  assert(diagnostic.includes('Network.enable')&&diagnostic.includes('attached')&&diagnostic.includes('reply'));
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
