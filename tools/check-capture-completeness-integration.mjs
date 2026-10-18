// Synthetic integration/negative controls, not a browser acceptance claim.
import assert from 'node:assert/strict';
import {createCaptureFixture} from './capture-completeness-fixture.mjs';
import {
  ReferenceLedger,
  compareCapture,
  completenessVerdict,
  fixtureOperation,
  compareFixtureBodies,
  captureRunVerdict,
} from './capture-completeness-reference.mjs';
import {crosscheckNetlog} from './capture-completeness-netlog.mjs';
const fixture = await createCaptureFixture({runId: 'integration'});
try {
  const version = '154.0.8037.57';
  const netlog = {
    constants: {
      logFormatVersion: 1,
      clientInfo: {version},
      logEventTypes: {URL_REQUEST_START_JOB: 1},
      logSourceType: {URL_REQUEST: 1},
      logEventPhase: {PHASE_BEGIN: 1, PHASE_END: 2, PHASE_NONE: 0},
    },
    events: [],
  };
  const ledger = new ReferenceLedger();
  ledger.session('session', 'target');
  let sequence = 0;
  for (const op of fixture.manifest.operations) {
    const url = `${fixture.origin}${op.path}?op=${encodeURIComponent(op.operationId)}`;
    for (let n = 0; n < op.expectedReceipts; n++) {
      fixture.receipts.push({...op, url, kind: op.kind, sequence: ++sequence});
      netlog.events.push({
        type: 1,
        phase: 1,
        source: {type: 1, id: sequence},
        params: {url, method: op.method},
      });
    }
    if (op.kind !== 'http') continue;
    for (let n = 0; n < (op.expectedClientCompletions ?? op.expectedReceipts); n++) {
      const requestId = String(++sequence);
      ledger.ingest({
        sessionId: 'session',
        method: 'Network.requestWillBeSent',
        params: {
          requestId,
          timestamp: sequence,
          request: {url, method: op.method},
          type: op.method === 'OPTIONS' ? 'Preflight' : 'Fetch',
        },
      });
      ledger.ingest({
        sessionId: 'session',
        method: 'Network.responseReceived',
        params: {requestId, response: {status: 200, fromServiceWorker: op.expectedReceipts === 0}},
      });
      ledger.ingest({sessionId: 'session', method: 'Network.loadingFinished', params: {requestId}});
    }
  }
  const socket = fixture.manifest.operations.find((op) => op.kind === 'websocket-handshake');
  for (const direction of ['sent', 'received'])
    fixture.receipts.push({
      operationId: socket.operationId,
      kind: 'websocket-frame',
      direction,
      payload: 'fixture-ping',
    });
  for (const caseId of fixture.manifest.cases) fixture.completions.set(caseId, {ok: true});
  const fixtureComplete = fixture.assertComplete().complete;
  ledger.finalize();
  const reference = ledger.snapshot();
  const network = {
    capture_enabled: true,
    instance_id: 'instance',
    capture_epoch: 0,
    dropped: 0,
    capture_status: {
      state: 'ready',
      startup_mode: 'passive',
      gaps: 0,
      target_overflow: 0,
      failed_targets: 0,
      unattached_targets_omitted: 0,
      unattached_targets: [],
      catalog_incomplete: false,
      discovery_stale: false,
    },
    requests: reference.hops.map((h, i) => ({
      id: String(i),
      target_id: h.targetId,
      protocol_request_id: h.requestId,
      url: h.url,
      method: h.method,
      resource_type: h.resourceType,
      status: h.status,
      state: h.state,
      from_disk_cache: h.fromDiskCache,
      from_service_worker: h.fromServiceWorker,
      timing_evidence: {request_monotonic_seconds: {state: 'available', value: h.timestamp}},
    })),
  };
  for (const row of network.requests)
    row.response = {
      body: {
        state: 'available',
        truncated: false,
        text: fixtureOperation(row, fixture.manifest)?.expectedBody ?? '',
        base64: '',
      },
    };
  const bodyMetric = compareFixtureBodies(network, fixture.manifest);
  assert.equal(bodyMetric.verdict, 'pass');
  assert(bodyMetric.expectedSamples >= 5);
  const changedBody = structuredClone(network);
  const sample = changedBody.requests.find(
    (row) => fixtureOperation(row, fixture.manifest)?.expectedBody,
  );
  sample.response.body.text = 'wrong';
  assert.equal(compareFixtureBodies(changedBody, fixture.manifest).verdict, 'fail');
  sample.response.body.truncated = true;
  assert.equal(compareFixtureBodies(changedBody, fixture.manifest).verdict, 'incomplete');
  assert.equal(compareFixtureBodies({}, fixture.manifest).verdict, 'incomplete');
  assert.equal(captureRunVerdict('pass', bodyMetric), 'pass');
  for (const bad of [undefined, {}, {verdict: 'unassessed'}, {verdict: 'incomplete'}])
    assert.equal(captureRunVerdict('pass', bad), 'incomplete');
  assert.equal(captureRunVerdict('pass', {verdict: 'fail'}), 'fail');
  const capture = {
    cleanShutdown: true,
    startedBeforeFixture: true,
    byteLength: 10000,
    limitBytes: 64 * 1024 * 1024,
    limitReached: false,
  };
  function result({
    r = reference,
    n = network,
    log = netlog,
    complete = fixtureComplete,
    captureOverride = capture,
  } = {}) {
    const comparison = compareCapture(r, n, {
      include: (h) => fixtureOperation(h, fixture.manifest) !== null,
    });
    const crosscheck = crosscheckNetlog(log, {
      manifest: fixture.manifest,
      receipts: fixture.receipts,
      referenceHops: r.hops,
      browserVersion: version,
      capture: captureOverride,
    });
    const uncovered = fixture.manifest.operations
      .filter((o) => o.kind === 'http')
      .some((op) =>
        [r.hops, n.requests ?? []].some(
          (rows) =>
            rows.filter((h) => fixtureOperation(h, fixture.manifest) === op).length !==
            (op.expectedClientCompletions ?? op.expectedReceipts),
        ),
      );
    return completenessVerdict({
      fixtureComplete: complete,
      comparison,
      uncovered,
      netlog: crosscheck,
    });
  }
  assert.equal(
    result(),
    'pass',
    'fully authored offline golden exercises actual module result shapes',
  );
  const copy = (value) => structuredClone(value);
  assert.notEqual(result({r: {...reference, hops: []}}), 'pass');
  assert.notEqual(result({r: {...reference, errors: ['drop']}}), 'pass');
  assert.notEqual(result({r: {...reference, finalized: false}}), 'pass');
  assert.notEqual(result({n: {...network, requests: []}}), 'pass');
  assert.notEqual(result({n: {...network, dropped: 1}}), 'pass');
  assert.notEqual(result({log: null}), 'pass');
  assert.notEqual(result({log: {...netlog, events: []}}), 'pass');
  assert.notEqual(result({captureOverride: {...capture, cleanShutdown: false}}), 'pass');
  assert.notEqual(result({complete: false}), 'pass');
  const bothMissing = copy(reference),
    bothMissingReb = copy(network);
  const repeatedIndex = bothMissing.hops.findIndex(
    (h) => fixtureOperation(h, fixture.manifest)?.expectedReceipts === 2,
  );
  assert(repeatedIndex >= 0);
  bothMissing.hops.splice(repeatedIndex, 1);
  bothMissingReb.requests.splice(repeatedIndex, 1);
  assert.equal(
    compareCapture(bothMissing, bothMissingReb).verdict,
    'pass',
    'two CDP clients share the missing hop',
  );
  assert.notEqual(
    result({r: bothMissing, n: bothMissingReb}),
    'pass',
    'manifest and receipts detect missing-both repeated hop',
  );
  const wrong = copy(network);
  wrong.requests[0].target_id = 'wrong';
  assert.notEqual(result({n: wrong}), 'pass');
  const malformed = copy(network);
  delete malformed.requests[0].state;
  assert.notEqual(result({n: malformed}), 'pass');
  const sharedWrong = copy(reference),
    sharedWrongReb = copy(network);
  sharedWrong.hops[0].url = sharedWrongReb.requests[0].url = sharedWrong.hops[0].url.replace(
    '/document/',
    '/wrong/',
  );
  assert.notEqual(
    result({r: sharedWrong, n: sharedWrongReb}),
    'pass',
    'shared CDP blindspot cannot satisfy owned operation denominator',
  );
  console.log(
    'Independent capture integration: actual fixture/reference/NetLog contracts and incomplete-layer negative controls passed (synthetic only).',
  );
} finally {
  await fixture.close();
}
