import assert from 'node:assert/strict';
import {
  ReferenceLedger,
  compareCapture,
  completenessVerdict,
} from './capture-completeness-reference.mjs';
const ledger = new ReferenceLedger();
ledger.session('s1', 't1');
ledger.session('s2', 't2');
function emit(method, params, sessionId = 's1') {
  ledger.ingest({method: `Network.${method}`, params, sessionId});
}
function request(requestId, url, timestamp, more = {}, session = 's1') {
  emit(
    'requestWillBeSent',
    {requestId, request: {url, method: 'GET'}, timestamp, type: 'Fetch', ...more},
    session,
  );
}
request('r', 'http://localhost/a', 1);
request('r', 'http://localhost/a', 2, {redirectResponse: {status: 302}});
emit('responseReceived', {requestId: 'r', response: {status: 200, fromDiskCache: true}});
emit('loadingFinished', {requestId: 'r'});
request('r', 'http://localhost/a', 1, {}, 's2');
emit('loadingFailed', {requestId: 'r', canceled: true}, 's2');
request('repeat', 'http://localhost/a', 3);
emit('responseReceived', {requestId: 'repeat', response: {status: 200, fromServiceWorker: true}});
emit('loadingFinished', {requestId: 'repeat'});
assert.equal(ledger.hops.length, 4);
assert.equal(ledger.hops[1].hop, 1);
assert.equal(ledger.hops[2].canceled, true);
ledger.finalize();
const reference = ledger.snapshot();
assert.deepEqual(reference.errors, []);
const rows = reference.hops.map((h, i) => ({
  id: String(i),
  target_id: h.targetId,
  protocol_request_id: h.requestId,
  timing_evidence: {request_monotonic_seconds: {state: 'available', value: h.timestamp}},
  url: h.url,
  method: h.method,
  status: h.status,
  state: h.state,
  resource_type: h.resourceType,
  from_disk_cache: h.fromDiskCache,
  from_service_worker: h.fromServiceWorker,
}));
const network = {
  requests: rows,
  capture_enabled: true,
  instance_id: 'i',
  capture_epoch: 1,
  dropped: 0,
  capture_status: {
    state: 'ready',
    startup_mode: 'passive',
    gaps: 0,
    target_overflow: 0,
    failed_targets: 0,
    unattached_targets_omitted: 0,
    catalog_incomplete: false,
    discovery_stale: false,
    unattached_targets: [],
  },
};
const run = (mutate) => {
  const n = structuredClone(network);
  mutate(n);
  return compareCapture(reference, n);
};
assert.equal(compareCapture(reference, network).verdict, 'pass');
assert.equal(run((n) => n.requests.pop()).missing, 1);
assert.equal(run((n) => n.requests.push({...n.requests[0]})).ambiguous, 1);
assert.equal(run((n) => (n.requests[0].target_id = 'wrong')).missing, 1);
assert.equal(run((n) => (n.requests[0].url = 'http://localhost/wrong')).mismatched, 1);
assert.equal(run((n) => (n.requests[0].status = 201)).mismatched, 1);
assert.equal(run((n) => (n.requests[0].from_service_worker = true)).mismatched, 1);
assert.equal(run((n) => (n.dropped = 1)).verdict, 'incomplete');
assert.equal(run((n) => (n.capture_status.target_overflow = 1)).verdict, 'incomplete');
assert.equal(run((n) => (n.requests[0].url_truncated = true)).verdict, 'incomplete');
assert.equal(
  compareCapture({...reference, hops: [...reference.hops, reference.hops[0]]}, network).ambiguous,
  1,
);
assert.equal(compareCapture({...reference, errors: ['disconnect']}, network).verdict, 'incomplete');
assert.equal(compareCapture(reference, {}).verdict, 'incomplete');
for (const limits of [{maxSessions: 0}, {maxEvents: 0}, {maxBytes: 0}, {maxHops: 0}]) {
  const l = new ReferenceLedger(limits);
  l.session('s', 't');
  l.ingest({
    sessionId: 's',
    method: 'Network.requestWillBeSent',
    params: {requestId: 'r', request: {url: 'http://localhost/a', method: 'GET'}, timestamp: 1},
  });
  assert(l.errors.size > 0);
}
const malformed = new ReferenceLedger();
malformed.session('s', 't');
malformed.ingest({
  sessionId: 's',
  method: 'Network.loadingFinished',
  params: {requestId: 'missing'},
});
assert(malformed.errors.has('orphan-network-event'));
console.log(
  'Independent capture reference: redirect loops, repeated URLs, session collisions, cancellation, cache/SW, missing/extra/wrong-owner/status and bounds controls passed.',
);

assert.equal(
  compareCapture({hops: [], errors: [], finalized: true}, network).verdict,
  'incomplete',
);
assert.equal(run((n) => delete n.capture_status.gaps).verdict, 'incomplete');
assert.equal(run((n) => delete n.requests[0].timing_evidence).verdict, 'incomplete');

const good = {
  fixtureComplete: true,
  comparison: {verdict: 'pass'},
  uncovered: false,
  netlog: {state: 'corroborated'},
};
assert.equal(completenessVerdict(good), 'pass');
for (const bad of [
  {netlog: {}},
  {netlog: {state: 'incomplete'}},
  {netlog: {verdict: 'pass'}},
  {comparison: {}},
  {fixtureComplete: false},
  {errorCode: 'truncated'},
])
  assert.equal(completenessVerdict({...good, ...bad}), 'incomplete');
assert.equal(completenessVerdict({...good, uncovered: true}), 'fail');
assert.equal(completenessVerdict({...good, netlog: {state: 'mismatch'}}), 'fail');

// Exercise the actual observer initialization rather than only the event model.
const {PassiveReference} = await import('./capture-completeness-reference.mjs');
class SocketFixture extends EventTarget {
  commands = [];
  send(raw) {
    const command = JSON.parse(raw);
    this.commands.push(command);
    queueMicrotask(() => {
      let result = {};
      if (command.method === 'Target.getTargets')
        result = {targetInfos: [{targetId: 'page', type: 'page'}]};
      if (command.method === 'Target.attachToTarget') {
        result = {sessionId: 'session'};
        this.dispatchEvent(
          new MessageEvent('message', {
            data: JSON.stringify({
              method: 'Target.attachedToTarget',
              params: {sessionId: 'session', targetInfo: {targetId: 'page', type: 'page'}},
            }),
          }),
        );
      }
      this.dispatchEvent(
        new MessageEvent('message', {data: JSON.stringify({id: command.id, result})}),
      );
    });
  }
  close() {
    this.dispatchEvent(new Event('close'));
  }
}
const socket = new SocketFixture(),
  observer = new PassiveReference(socket);
await observer.start();
assert(socket.commands.some((c) => c.method === 'Network.enable' && c.sessionId === 'session'));
assert(
  socket.commands
    .filter((c) => c.method === 'Target.setAutoAttach')
    .every((c) => c.params.waitForDebuggerOnStart === false),
);
assert(
  socket.commands.every(
    (c) =>
      ![
        'Debugger.enable',
        'Fetch.enable',
        'Network.setCacheDisabled',
        'Network.setBypassServiceWorker',
        'Runtime.runIfWaitingForDebugger',
      ].includes(c.method),
  ),
);
assert.equal(
  observer.ledger.sessions.size,
  1,
  'attach event plus reply does not duplicate session',
);
observer.ledger.finalize();
const frozen = structuredClone(observer.ledger.snapshot());
observer.ledger.ingest({
  method: 'Network.loadingFinished',
  sessionId: 'session',
  params: {requestId: 'late'},
});
assert.deepEqual(
  observer.ledger.snapshot(),
  frozen,
  'post-window events do not mutate frozen comparison',
);
observer.close();
assert(!observer.ledger.errors.has('transport-closed'), 'deliberate close is not transport loss');
const unexpected = new PassiveReference(new SocketFixture());
unexpected.socket.close();
assert(unexpected.ledger.errors.has('transport-closed'));
const invalid = new ReferenceLedger();
invalid.ingest(null);
invalid.ingest({method: 'Network.loadingFinished', params: null});
assert.equal(invalid.errors.size, 2);

assert.equal(compareCapture({...reference, epoch: 2}, network).verdict, 'incomplete');

// Reproduce discovery versus recursive-auto-attach overlap in both orderings.
class OverlapSocket extends SocketFixture {
  constructor(order, failDetach = false) {
    super();
    this.order = order;
    this.failDetach = failDetach;
  }
  send(raw) {
    const c = JSON.parse(raw);
    if (
      c.method !== 'Target.attachToTarget' &&
      !(this.failDetach && c.method === 'Target.detachFromTarget')
    )
      return super.send(raw);
    this.commands.push(c);
    const message = (value) =>
      this.dispatchEvent(new MessageEvent('message', {data: JSON.stringify(value)}));
    queueMicrotask(() => {
      if (this.failDetach && c.method === 'Target.detachFromTarget') {
        message({id: c.id, error: {code: -32000, message: 'synthetic detach rejected'}});
        return;
      }
      const attached = () =>
        message({
          method: 'Target.attachedToTarget',
          sessionId: 'parent',
          params: {sessionId: 'auto', targetInfo: {targetId: 'page', type: 'page'}},
        });
      if (this.order === 'event-first') attached();
      message({id: c.id, result: {sessionId: 'manual'}});
      if (this.order === 'reply-first') queueMicrotask(attached);
    });
  }
}
for (const order of ['event-first', 'reply-first']) {
  const socket = new OverlapSocket(order),
    reference = new PassiveReference(socket);
  await reference.start();
  await reference.ready();
  const primary = order === 'event-first' ? 'auto' : 'manual';
  const secondary = order === 'event-first' ? 'manual' : 'auto';
  assert.deepEqual(
    socket.commands.filter((c) => c.method === 'Network.enable').map((c) => c.sessionId),
    [primary],
  );
  const detached = socket.commands.filter((c) => c.method === 'Target.detachFromTarget');
  assert.equal(detached.length, 1);
  assert.equal(detached[0].params.sessionId, secondary);
  assert.equal(detached[0].sessionId, order === 'reply-first' ? 'parent' : undefined);
  assert.equal(reference.attachments.get('page'), primary);
  assert.equal(reference.duplicateSessions, 1);
  assert.deepEqual(reference.ledger.snapshot().errors, []);
  reference.close();
}
const detachFailure = new PassiveReference(new OverlapSocket('reply-first', true));
await detachFailure.start();
await detachFailure.ready();
assert(detachFailure.ledger.errors.has('duplicate-detach-failed'));
detachFailure.close();
const {CaptureIdentityTracker} = await import('./capture-completeness-reference.mjs');
const tracker = new CaptureIdentityTracker();
const startup = (state, epoch) => ({
  state,
  network: {
    instance_id: 'same',
    capture_epoch: epoch,
    capture_status: {state: state === 'running' ? 'ready' : 'waiting'},
  },
});
assert(tracker.observe(startup('connecting', 0)));
assert.equal(tracker.baseline, null);
assert(tracker.observe(startup('running', 1)));
assert.equal(tracker.readinessTransitions, 1);
assert(tracker.observe(startup('running', 1)));
assert(!tracker.observe(startup('running', 2)));
assert.equal(
  compareCapture(reference, {
    ...network,
    requests: rows.map((r, i) => (i ? r : {...r, status: 201})),
  }).mismatchReasons.status,
  1,
);

class InitializationFailureSocket extends OverlapSocket {
  send(raw) {
    const command = JSON.parse(raw);
    if (command.method !== 'Network.enable') return super.send(raw);
    this.commands.push(command);
    queueMicrotask(() =>
      this.dispatchEvent(
        new MessageEvent('message', {
          data: JSON.stringify({
            id: command.id,
            error: {code: -32000, message: 'synthetic primary failure'},
          }),
        }),
      ),
    );
  }
}
const primaryFailure = new PassiveReference(new InitializationFailureSocket('reply-first'));
await primaryFailure.start();
await primaryFailure.ready();
assert(primaryFailure.ledger.errors.has('session-initialization'));
assert(primaryFailure.ledger.errors.has('command-rejected-network-enable'));
assert.equal(
  primaryFailure.ledger.sessions.size,
  1,
  'secondary rejection does not fabricate a ready replacement',
);
primaryFailure.close();

const delayed = new PassiveReference(new OverlapSocket('reply-first'));
await delayed.start();
await delayed.ready();
delayed.socket.dispatchEvent(
  new MessageEvent('message', {
    data: JSON.stringify({method: 'Target.detachedFromTarget', params: {sessionId: 'manual'}}),
  }),
);
delayed.admit('auto', {targetId: 'page', type: 'page'}, 'parent');
assert.equal(
  delayed.attachments.has('page'),
  false,
  'late rejected reply cannot become a replacement owner',
);
assert.equal(delayed.ledger.sessions.has('auto'), false);
delayed.close();
