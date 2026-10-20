import assert from 'node:assert/strict';
import {Script} from 'node:vm';
import {createCaptureFixture} from './capture-completeness-fixture.mjs';

await assert.rejects(() => createCaptureFixture({runId: '../../escape'}), /Invalid/);
const fixture = await createCaptureFixture({runId: 'oracle-test'});
const url = (op) => fixture.origin + op.path + '?op=' + encodeURIComponent(op.operationId);
try {
  assert.equal(new URL(fixture.origin).hostname, '127.0.0.1');
  assert.equal(new URL(fixture.crossOrigin).hostname, 'localhost');
  assert.throws(() => fixture.assertComplete(), /document: incomplete/);
  await assert.rejects(
    () => fixture.waitForCompletion({timeoutMs: 0, drainMs: 0}),
    /completion timeout/,
  );
  await assert.rejects(
    () => fixture.waitForCompletion({timeoutMs: Infinity}),
    /Invalid fixture timeout/,
  );
  assert.equal((await fetch(fixture.entryUrl.replace(/\?op=.*/, '?op=wrong'))).status, 404);
  assert.equal(fixture.receipts.length, 0);
  const entry = await fetch(fixture.entryUrl).then((r) => r.text());
  assert.match(entry, /new SharedWorker/);
  assert.match(entry, /controllerchange/);
  assert.match(entry, /AbortController/);
  assert.match(entry, /window.open/);
  for (const match of entry.matchAll(/<script(?: [^>]*)?>([\s\S]*?)<\/script>/g))
    new Script(match[1]);
  for (const op of fixture.manifest.operations) {
    if (op.caseId === 'document' && op.path.endsWith('/index')) continue;
    if (op.kind === 'websocket-handshake') {
      await new Promise((resolve, reject) => {
        const socket = new WebSocket(url(op).replace('http:', 'ws:'));
        socket.onopen = () => socket.send('fixture-ping');
        socket.onmessage = (e) => {
          assert.equal(e.data, 'fixture-ping');
          socket.close();
        };
        socket.onclose = () => resolve();
        socket.onerror = reject;
      });
      continue;
    }
    for (let i = 0; i < op.expectedReceipts; i++) {
      if (op.path.endsWith('/cancel')) {
        const controller = new AbortController();
        const response = await fetch(url(op), {signal: controller.signal});
        controller.abort();
        await assert.rejects(() => response.text());
      } else if (op.path.endsWith('/reset')) {
        await assert.rejects(() => fetch(url(op)).then((r) => r.text()));
      } else {
        const response = await fetch(url(op), {redirect: 'manual', method: op.method});
        const body = await response.text();
        if (response.headers.get('content-type') === 'text/javascript') new Script(body);
        if (response.headers.get('content-type') === 'text/html')
          for (const match of body.matchAll(/<script>([\s\S]*?)<\/script>/g)) new Script(match[1]);
      }
    }
  }
  // Simulate the independent client markers only in this offline server test.
  // Browser integration must produce these markers by running the actual page.
  for (const caseId of fixture.manifest.cases) {
    const response = await fetch(`${fixture.origin}/reb-fixture/oracle-test/control/complete`, {
      method: 'POST',
      body: JSON.stringify({caseId, ok: true}),
    });
    assert.equal(response.status, 204);
  }
  assert.equal((await fixture.waitForCompletion({drainMs: 0})).caseCount, 11);
  const duplicate = await fetch(`${fixture.origin}/reb-fixture/oracle-test/control/complete`, {
    method: 'POST',
    body: JSON.stringify({caseId: 'document', ok: true}),
  });
  assert.equal(duplicate.status, 400);
  const preflightIndex = fixture.receipts.findIndex((r) => r.method === 'OPTIONS');
  const [preflightReceipt] = fixture.receipts.splice(preflightIndex, 1);
  assert.throws(() => fixture.assertComplete(), /OPTIONS: expected 1 receipts, got 0/);
  fixture.receipts.splice(preflightIndex, 0, preflightReceipt);
  const receipt = fixture.receipts.pop();
  assert.throws(() => fixture.assertComplete(), /frame mismatch/);
  fixture.receipts.push(receipt);
  const index = fixture.receipts.findIndex((r) => r.path.endsWith('/repeat'));
  const [missing] = fixture.receipts.splice(index, 1);
  assert.throws(() => fixture.assertComplete(), /expected 2 receipts, got 1/);
  fixture.receipts.splice(index, 0, missing);
  fixture.receipts.push({...missing, sequence: 999});
  assert.throws(() => fixture.assertComplete(), /expected 2 receipts, got 3/);
  fixture.receipts.pop();
  const synthetic = fixture.manifest.operations.find((op) => op.path.endsWith('/synthetic'));
  fixture.receipts.push({...synthetic, url: url(synthetic), sequence: 999});
  assert.throws(() => fixture.assertComplete(), /expected 0 receipts, got 1/);
  fixture.receipts.pop();
  fixture.completions.set('cache', {ok: false, detail: 'cache failed'});
  assert.throws(() => fixture.assertComplete(), /cache failed/);
  fixture.completions.delete('cache');
  assert.throws(() => fixture.assertComplete(), /cache: incomplete/);
  console.log('capture completeness fixture: server oracle and negative controls passed');
} finally {
  await fixture.close();
}

// Capacity failures stay visible and cannot turn into a successful empty oracle.
for (const limits of [{maxReceipts: 1}, {maxReceiptBytes: 1}]) {
  const bounded = await createCaptureFixture({runId: 'bounded-receipts', limits});
  try {
    await fetch(bounded.entryUrl)
      .then((r) => r.text())
      .catch(() => {});
    await fetch(bounded.entryUrl)
      .then((r) => r.text())
      .catch(() => {});
    assert.throws(() => bounded.assertComplete(), /receipt limit exceeded/);
    assert(bounded.receipts.length <= limits.maxReceipts || limits.maxReceiptBytes === 1);
    await assert.rejects(() => bounded.waitForCompletion({timeoutMs: 0}), /receipt limit exceeded/);
  } finally {
    await bounded.close();
  }
}
await assert.rejects(
  () => createCaptureFixture({limits: {maxReceipts: Infinity}}),
  /Invalid fixture limit/,
);
const bodyBound = await createCaptureFixture({runId: 'bounded-body', limits: {maxBodyBytes: 16}});
try {
  const response = await fetch(bodyBound.origin + '/reb-fixture/bounded-body/control/complete', {
    method: 'POST',
    body: 'x'.repeat(32),
  });
  assert.equal(response.status, 413);
  assert.throws(() => bodyBound.assertComplete(), /completion body limit exceeded/);
} finally {
  await bodyBound.close();
}
const {connect} = await import('node:net');
const socketBound = await createCaptureFixture({runId: 'bounded-sockets', limits: {maxSockets: 1}});
let first, second;
try {
  const port = Number(new URL(socketBound.origin).port);
  first = connect({port, host: '127.0.0.1'});
  await new Promise((resolve) => first.once('connect', resolve));
  second = connect({port, host: '127.0.0.1'});
  second.on('error', () => {});
  await new Promise((resolve) => second.once('close', resolve));
  assert.throws(() => socketBound.assertComplete(), /socket limit exceeded/);
} finally {
  first?.destroy();
  second?.destroy();
  await socketBound.close();
}
console.log('capture completeness fixture: receipt, body and socket bounds passed');
