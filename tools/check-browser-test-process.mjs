import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
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
  child: {pid: 12345, exitCode: null, signalCode: null, kill: signal => signals.push(signal)},
  closed: new Promise(() => {}),
}, 5), /did not close; preserving its profile/);
assert.deepEqual(signals, ['SIGTERM', 'SIGKILL']);
console.log('PASS browser fixture cleanup: inherited stdio close, bounded TERM/KILL reap, spawn failure and unreaped profile refusal');
