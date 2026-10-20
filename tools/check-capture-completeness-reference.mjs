import assert from 'node:assert/strict';
import {
  ReferenceLedger,
  compareCapture,
  completenessVerdict,
  statusValueBucketNames,
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

// Browser-owned main resources can start on a parent Network manager and
// finish on the new frame/worker manager. Keep the start identity and require
// independent protocol evidence before applying the actual terminal event.
function handoff(kind = 'iframe', {parent = 'source', targetInfo = {}, requestInfo = {}} = {}) {
  const ledger = new ReferenceLedger();
  ledger.session('source', 'page-target', {type: 'page'});
  ledger.session('unrelated', 'unrelated-target', {type: 'page'});
  const url = `http://localhost/${kind}`,
    requestId = kind === 'iframe' ? 'document-loader' : 'child-target';
  ledger.session('destination', 'child-target', {type: kind, url, ...targetInfo}, parent);
  const emit = (method, params, sessionId = 'source') =>
    ledger.ingest({method: `Network.${method}`, params, sessionId});
  const start = {
    requestId,
    loaderId: kind === 'iframe' ? requestId : '',
    frameId: kind === 'iframe' ? 'child-target' : 'page-target',
    type: kind === 'iframe' ? 'Document' : 'Script',
    request: {url, method: 'GET'},
    timestamp: 10,
    ...requestInfo,
  };
  emit('requestWillBeSent', start);
  emit('responseReceived', {requestId: start.requestId, response: {status: 200}});
  return {
    ledger,
    emit,
    start,
    finish: (params = {}) =>
      emit('loadingFinished', {requestId, timestamp: 11, ...params}, 'destination'),
  };
}
function compareLedger(ledger) {
  ledger.finalize();
  return compareCapture(ledger.snapshot(), {
    ...network,
    requests: ledger.hops.map((h, i) => ({
      id: `handoff-${i}`,
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
    })),
  });
}
for (const kind of ['iframe', 'worker', 'shared_worker']) {
  const {ledger, start, finish} = handoff(kind);
  finish();
  assert.equal(ledger.hops.length, 1, `${kind}: transfer does not invent another hop`);
  assert.equal(ledger.hops[0].state, 'complete');
  assert.equal(ledger.hops[0].sessionId, 'source');
  assert.equal(ledger.hops[0].targetId, 'page-target');
  assert.equal(ledger.hops[0].loaderId, start.loaderId);
  assert.equal(ledger.hops[0].frameId, start.frameId);
  assert.equal(ledger.hops[0].terminalSessionId, 'destination');
  assert.equal(ledger.hops[0].terminalTargetId, 'child-target');
  assert.equal(ledger.hops[0].terminalTimestamp, 11);
  assert.equal(ledger.snapshot().sessions[2].parentSessionId, 'source');
  assert.equal(compareLedger(ledger).verdict, 'pass');
}
for (const kind of ['worker', 'shared_worker']) {
  const {ledger, finish} = handoff(kind, {parent: null});
  // A discovery/manual attachment has no parent session. The documented
  // future worker target ID remains stronger than a raw-ID/URL coincidence.
  finish();
  assert.equal(ledger.hops[0].state, 'complete');
  assert.deepEqual([...ledger.errors], []);
}
const nested = handoff('iframe', {parent: 'middle'});
nested.ledger.session('middle', 'middle-target', {type: 'iframe'}, 'source');
nested.finish();
assert.equal(nested.ledger.hops[0].state, 'complete');
const targetParent = handoff('iframe', {parent: null, targetInfo: {parentId: 'page-target'}});
targetParent.finish();
assert.equal(targetParent.ledger.hops[0].state, 'complete');
const redirected = handoff('iframe');
redirected.emit('requestWillBeSent', {
  ...redirected.start,
  timestamp: 10.5,
  redirectResponse: {status: 302},
  request: {url: 'http://localhost/redirected-frame', method: 'GET'},
});
redirected.emit('responseReceived', {
  requestId: redirected.start.requestId,
  response: {status: 200},
});
redirected.finish();
assert.deepEqual(
  redirected.ledger.hops.map((h) => h.state),
  ['complete', 'complete'],
);
assert.equal(redirected.ledger.hops[0].terminalSessionId, undefined);
assert.equal(redirected.ledger.hops[1].terminalSessionId, 'destination');
assert.equal(compareLedger(redirected.ledger).verdict, 'pass');

const rejectedHandoffs = [
  ['document without lineage', 'iframe', {parent: null}],
  ['unrelated document owner', 'iframe', {parent: 'unrelated'}],
  ['wrong document loader', 'iframe', {requestInfo: {loaderId: 'ordinary-loader'}}],
  ['missing document loader', 'iframe', {requestInfo: {loaderId: undefined}}],
  ['wrong document frame', 'iframe', {requestInfo: {frameId: 'another-frame'}}],
  ['missing document frame', 'iframe', {requestInfo: {frameId: undefined}}],
  ['ordinary request in iframe', 'iframe', {requestInfo: {type: 'Fetch'}}],
  ['page is not destination iframe', 'iframe', {targetInfo: {type: 'page'}}],
  ['worker missing loader is not empty', 'worker', {requestInfo: {loaderId: undefined}}],
  ['worker nonempty loader', 'worker', {requestInfo: {loaderId: 'loader'}}],
  ['ordinary worker fetch', 'worker', {requestInfo: {type: 'Fetch'}}],
  ['wrong worker target type', 'worker', {targetInfo: {type: 'page'}}],
  ['different worker script URL', 'worker', {targetInfo: {url: 'http://localhost/other'}}],
  ['unrelated worker parent', 'worker', {parent: 'unrelated'}],
  ['contradictory worker target parent', 'worker', {targetInfo: {parentId: 'unrelated-target'}}],
  ['service worker identity unproven', 'service_worker', {}],
];
for (const [label, kind, options] of rejectedHandoffs) {
  const {ledger, finish} = handoff(kind, options);
  finish();
  assert.equal(ledger.hops[0].state, 'pending', label);
  assert(ledger.errors.has('orphan-network-event'), label);
  assert.equal(compareLedger(ledger).verdict, 'incomplete', label);
}
for (const timestamp of [undefined, null, NaN, Infinity, 9]) {
  const {ledger, finish} = handoff();
  finish({timestamp});
  assert.equal(ledger.hops[0].state, 'pending', 'invalid or stale terminal time');
  assert(ledger.errors.has('orphan-network-event'));
}
for (const event of ['responseReceived', 'requestServedFromCache', 'loadingFailed']) {
  const {ledger, emit, start} = handoff('worker');
  emit(event, {requestId: start.requestId, timestamp: 11, response: {status: 200}}, 'destination');
  assert.equal(ledger.hops[0].state, 'pending', `${event} cannot prove completion`);
  assert(ledger.errors.has('orphan-network-event'));
}
const noTerminal = handoff('worker');
assert.equal(compareLedger(noTerminal.ledger).verdict, 'incomplete');
const contradictoryLineage = handoff('worker');
contradictoryLineage.ledger.describeSession('destination', {}, 'unrelated');
contradictoryLineage.finish();
assert.equal(contradictoryLineage.ledger.hops[0].state, 'pending');
assert(contradictoryLineage.ledger.errors.has('target-lineage-conflict'));
const missingSourceType = handoff('worker');
missingSourceType.ledger.sessionInfo.get('source').type = null;
missingSourceType.finish();
assert.equal(missingSourceType.ledger.hops[0].state, 'pending');
const wrongWorkerId = handoff('worker', {requestInfo: {requestId: 'ordinary-request'}});
wrongWorkerId.finish({requestId: 'ordinary-request'});
assert.equal(wrongWorkerId.ledger.hops[0].state, 'pending');

for (const completeCollision of [false, true]) {
  const {ledger, emit, start, finish} = handoff('worker', {parent: null});
  emit('requestWillBeSent', {...start, timestamp: 10.5}, 'unrelated');
  if (completeCollision)
    emit('loadingFinished', {requestId: start.requestId, timestamp: 10.6}, 'unrelated');
  finish();
  assert.equal(ledger.hops.length, 2, 'raw-ID collisions keep both starts');
  assert.equal(ledger.hops[0].state, 'pending', 'ambiguous candidate is not adopted');
  assert(ledger.errors.has('orphan-network-event'));
}
const localCollision = handoff('worker');
localCollision.emit('requestWillBeSent', {...localCollision.start, timestamp: 10.5}, 'destination');
localCollision.finish();
assert.deepEqual(
  localCollision.ledger.hops.map((h) => h.state),
  ['pending', 'complete'],
);
assert.equal(compareLedger(localCollision.ledger).verdict, 'incomplete');
const repeatedStart = handoff('worker');
repeatedStart.emit('requestWillBeSent', {...repeatedStart.start, timestamp: 10.5});
repeatedStart.finish();
assert.equal(repeatedStart.ledger.hops.length, 1);
assert.equal(compareLedger(repeatedStart.ledger).verdict, 'incomplete');
const repeatedTerminal = handoff('worker');
repeatedTerminal.finish();
repeatedTerminal.finish();
assert(repeatedTerminal.ledger.errors.has('orphan-network-event'));
const reconnected = handoff('worker');
reconnected.ledger.epoch++;
reconnected.finish();
assert.equal(reconnected.ledger.hops[0].state, 'pending');
assert.equal(compareLedger(reconnected.ledger).verdict, 'incomplete');

// Repeated URLs with distinct documented identities stay independent.
const repeatedUrl = handoff('worker');
repeatedUrl.ledger.session('second-worker', 'second-target', {
  type: 'worker',
  url: repeatedUrl.start.request.url,
});
repeatedUrl.emit('requestWillBeSent', {
  ...repeatedUrl.start,
  requestId: 'second-target',
  timestamp: 10.1,
});
repeatedUrl.emit('responseReceived', {requestId: 'second-target', response: {status: 200}});
repeatedUrl.finish();
assert.deepEqual(
  repeatedUrl.ledger.hops.map((h) => h.state),
  ['complete', 'pending'],
);
repeatedUrl.emit('loadingFinished', {requestId: 'second-target', timestamp: 11}, 'second-worker');
assert.equal(compareLedger(repeatedUrl.ledger).verdict, 'pass');

// The observer preserves manual-session ownership while learning target
// lineage from the rejected recursive-auto-attachment, in either order.
for (const order of ['event-first', 'reply-first']) {
  const socket = new OverlapSocket(order),
    reference = new PassiveReference(socket);
  reference.ledger.session('parent', 'ancestor', {type: 'page'});
  await reference.start();
  const primary = reference.attachments.get('page'),
    info = reference.ledger.sessionInfo.get(primary);
  assert.equal(info.targetParentSessionId, 'parent');
  assert.equal(info.parentSessionId, order === 'event-first' ? 'parent' : null);
  assert.equal(info.type, 'page');
  assert.deepEqual([...reference.ledger.errors], []);
  reference.close();
}
console.log(
  'Main-resource handoff: iframe/worker lineage, terminal provenance, manual attachment, repeated URLs, raw-ID collisions, ambiguous/unrelated owners, epochs and pending negative controls passed.',
);

// Diagnostic counters expose only fixed field names, side, and multiplicity.
// Every required field is still enforced, including completed-without-status.
const fieldPairs = [
  ['state', 'state'],
  ['status', 'status'],
  ['resourceType', 'resource_type'],
  ['fromDiskCache', 'from_disk_cache'],
  ['fromServiceWorker', 'from_service_worker'],
];
for (const side of ['reference', 'reb']) {
  for (const [field, rebField] of fieldPairs) {
    for (const value of [undefined, 'PRIVATE_BAD_VALUE']) {
      const r = structuredClone(reference),
        n = structuredClone(network);
      const row = side === 'reference' ? r.hops[0] : n.requests[0];
      const key = side === 'reference' ? field : rebField;
      // Resource type permits arbitrary strings under the existing contract.
      if (field === 'resourceType' && typeof value === 'string') row[key] = null;
      else row[key] = value;
      const result = compareCapture(r, n);
      assert.equal(result.verdict, 'incomplete');
      assert(result.issues.includes('malformed-hop-state'));
      assert.equal(result.malformedFields[side][field], 1);
      assert.equal(result.malformedFields[side === 'reference' ? 'reb' : 'reference'][field], 0);
      assert(!JSON.stringify(result.malformedFields).includes('PRIVATE'));
    }
  }
}
const scopedReference = structuredClone(reference),
  scopedNetwork = structuredClone(network);
scopedReference.hops[0].status = null;
scopedNetwork.requests[1].from_disk_cache = null;
const scoped = compareCapture(scopedReference, scopedNetwork, {
  include: (row) => row === scopedReference.hops[0] || row === scopedNetwork.requests[0],
});
assert.equal(scoped.verdict, 'incomplete');
assert.equal(scoped.malformedFields.reference.status, 1);
assert.equal(scoped.malformedFields.reb.fromDiskCache, 1);
assert.equal(scoped.scopedMalformedFields.reference.status, 1);
assert.equal(scoped.scopedMalformedFields.reb.fromDiskCache, 0);
const validNoResponse = new ReferenceLedger();
validNoResponse.session('private-session', 'private-target');
validNoResponse.ingest({
  sessionId: 'private-session',
  method: 'Network.requestWillBeSent',
  params: {
    requestId: 'private-request',
    timestamp: 5,
    type: 'Fetch',
    request: {url: 'http://localhost/private-path', method: 'GET'},
  },
});
validNoResponse.ingest({
  sessionId: 'private-session',
  method: 'Network.loadingFinished',
  params: {
    requestId: 'private-request',
    timestamp: 6,
  },
});
validNoResponse.finalize();
assert.deepEqual(validNoResponse.snapshot().errors, []);
assert.equal(validNoResponse.hops[0].state, 'complete');
assert.equal(validNoResponse.hops[0].status, null);
const noResponseResult = compareCapture(validNoResponse.snapshot(), network);
assert.equal(noResponseResult.verdict, 'incomplete');
assert.equal(noResponseResult.malformedFields.reference.state, 0);
assert.equal(noResponseResult.malformedFields.reference.status, 1);
assert(!JSON.stringify(noResponseResult.malformedFields).includes('private'));
const maxRows = structuredClone(network);
maxRows.requests = Array.from({length: 10000}, () => ({...network.requests[0], status: null}));
assert.equal(compareCapture(reference, maxRows).malformedFields.reb.status, 10000);
maxRows.requests.push(maxRows.requests[0]);
assert.deepEqual(compareCapture(reference, maxRows).issues, ['invalid-reb-snapshot']);
console.log(
  'PASS bounded side-specific malformed-field counts, operation scope, required fields, and terminal-without-response incompleteness',
);

// Buckets describe values without tightening or relaxing status validation.
const statusCases = [
  [undefined, 'missing', true],
  [null, 'null', true],
  [0, 'zero', false],
  [-0, 'zero', false],
  [100, 'httpRange', false],
  [200, 'httpRange', false],
  [599, 'httpRange', false],
  [99, 'otherNumber', false],
  [600, 'otherNumber', false],
  [-1, 'otherNumber', false],
  [200.5, 'otherNumber', false],
  [1e300, 'otherNumber', false],
  [NaN, 'nonfiniteNumber', true],
  [Infinity, 'nonfiniteNumber', true],
  [-Infinity, 'nonfiniteNumber', true],
  ['PRIVATE_STATUS', 'nonnumber', true],
  [false, 'nonnumber', true],
  [{raw: 'PRIVATE_STATUS'}, 'nonnumber', true],
  [[], 'nonnumber', true],
];
for (const [status, bucket, invalid] of statusCases) {
  const r = structuredClone(reference),
    n = structuredClone(network);
  r.hops[0].status = status;
  n.requests[0].status = status;
  const result = compareCapture(r, n, {include: (h) => h === r.hops[0] || h === n.requests[0]});
  assert.equal(result.verdict, invalid ? 'incomplete' : 'pass', `${bucket}: existing verdict`);
  for (const side of ['reference', 'reb']) {
    assert.equal(result.malformedFields[side].status, invalid ? 1 : 0);
    assert.deepEqual(
      result.scopedStatusValueBuckets[side],
      Object.fromEntries(statusValueBucketNames.map((name) => [name, name === bucket ? 1 : 0])),
    );
    assert.equal(
      Object.values(result.statusValueBuckets[side]).reduce((a, b) => a + b, 0),
      4,
    );
    assert.equal(
      Object.values(result.scopedStatusValueBuckets[side]).reduce((a, b) => a + b, 0),
      1,
    );
  }
  assert(!JSON.stringify(result.statusValueBuckets).includes('PRIVATE'));
  assert.equal(result.referenceHops, 1);
  assert.equal(result.rebHops, 1);
}
for (const state of ['pending', 'failed', 'complete']) {
  const r = structuredClone(reference),
    n = structuredClone(network);
  for (const row of [r.hops[0], n.requests[0]]) Object.assign(row, {status: null, state});
  const result = compareCapture(r, n);
  assert.equal(result.verdict, state === 'failed' ? 'pass' : 'incomplete');
  for (const side of ['reference', 'reb']) {
    assert.equal(result.malformedFields[side].status, state === 'complete' ? 1 : 0);
    assert.equal(result.statusValueBuckets[side].null, 2);
  }
}
const missingStatus = structuredClone(network);
delete missingStatus.requests[0].status;
assert.equal(compareCapture(reference, missingStatus).statusValueBuckets.reb.missing, 1);
const badRow = structuredClone(network);
badRow.requests[0] = null;
const badRowResult = compareCapture(reference, badRow);
assert.equal(badRowResult.statusValueBuckets.reb.missing, 1);
assert.equal(badRowResult.scopedStatusValueBuckets.reb.missing, 0);
assert.equal(badRowResult.verdict, 'incomplete');
assert.equal(scoped.statusValueBuckets.reference.null, 2);
assert.equal(scoped.scopedStatusValueBuckets.reference.null, 1);
assert.equal(scoped.scopedStatusValueBuckets.reb.httpRange, 1);
maxRows.requests.pop();
assert.equal(compareCapture(reference, maxRows).statusValueBuckets.reb.null, 10000);
maxRows.requests.push(maxRows.requests[0]);
assert.equal(compareCapture(reference, maxRows).statusValueBuckets, undefined);
console.log(
  'PASS exclusive bounded status buckets, zero-valid predicate, null/state distinction and operation scope',
);

function extraInfoFixture(limits) {
  const ledger = new ReferenceLedger(limits);
  ledger.session('owner', 'target', {type: 'page'});
  const emit = (method, params = {}, sessionId = 'owner') =>
    ledger.ingest({
      sessionId,
      method: `Network.${method}`,
      params: {requestId: 'worker-id', ...params},
    });
  const start = (params = {}, sessionId) =>
    emit(
      'requestWillBeSent',
      {
        loaderId: '',
        type: 'Script',
        timestamp: 1,
        request: {url: 'http://localhost/worker.js', method: 'GET'},
        ...params,
      },
      sessionId,
    );
  const extra = (statusCode = 200, sessionId) =>
    emit('responseReceivedExtraInfo', {statusCode}, sessionId);
  const finish = (sessionId) => emit('loadingFinished', {timestamp: 2}, sessionId);
  return {ledger, emit, start, extra, finish};
}
function extraInfoComparison(ledger) {
  ledger.finalize();
  const reference = ledger.snapshot(),
    n = {
      ...network,
      requests: reference.hops.map((h, i) => ({
        ...rows[0],
        id: String(i),
        target_id: h.targetId,
        protocol_request_id: h.requestId,
        timing_evidence: {request_monotonic_seconds: {state: 'available', value: h.timestamp}},
        url: h.url,
        method: h.method,
        state: h.state,
        status: h.status,
        status_source: h.status_source,
        wire_status: h.wire_status,
        resource_type: h.resourceType,
        from_disk_cache: h.fromDiskCache,
        from_service_worker: h.fromServiceWorker,
      })),
    };
  return {reference, network: n, result: compareCapture(reference, n)};
}
for (const order of [
  ['extra', 'start', 'finish'],
  ['start', 'extra', 'finish'],
  ['start', 'finish', 'extra'],
]) {
  const fixture = extraInfoFixture();
  for (const step of order) fixture[step]();
  assert.equal(
    fixture.ledger.hops[0].status,
    null,
    'no speculative attribution before finalization',
  );
  const {result} = extraInfoComparison(fixture.ledger),
    hop = fixture.ledger.hops[0];
  assert.equal(result.verdict, 'pass');
  assert.equal(hop.status, 200);
  assert.equal(hop.status_source, 'response-received-extra-info');
  assert.equal(hop.wire_status, 200);
  assert.equal(fixture.ledger.hops.length, 1);
  const frozen = structuredClone(fixture.ledger.snapshot()),
    events = fixture.ledger.events;
  fixture.extra();
  fixture.ledger.finalize();
  assert.equal(fixture.ledger.events, events);
  assert.deepEqual(
    fixture.ledger.snapshot(),
    frozen,
    'closed observation window remains immutable',
  );
}
for (const extraFirst of [false, true]) {
  const f = extraInfoFixture();
  f.start();
  if (extraFirst) f.extra(304);
  f.emit('responseReceived', {response: {status: 200, fromDiskCache: true}});
  f.finish();
  if (!extraFirst) f.extra(304);
  assert.equal(extraInfoComparison(f.ledger).result.verdict, 'pass');
  assert.equal(f.ledger.hops[0].status, 200);
  assert.equal(f.ledger.hops[0].wire_status, 304);
  assert.equal(f.ledger.hops[0].status_source, 'response-received');
  assert.equal(f.ledger.hops[0].fromDiskCache, true);
}
const wireOnly = extraInfoFixture();
wireOnly.start();
wireOnly.extra(304);
wireOnly.finish();
assert.equal(extraInfoComparison(wireOnly.ledger).result.verdict, 'incomplete');
assert.equal(wireOnly.ledger.hops[0].status, null);
assert.equal(wireOnly.ledger.hops[0].wire_status, 304);
assert.equal(wireOnly.ledger.hops[0].status_source, 'unavailable');
for (const statusCode of [undefined, null, 0, 99, 600, 200.5, NaN, Infinity, '200']) {
  const f = extraInfoFixture();
  f.start();
  f.emit('responseReceivedExtraInfo', {statusCode});
  f.finish();
  assert.equal(extraInfoComparison(f.ledger).result.verdict, 'incomplete');
  assert.equal(f.ledger.hops[0].status, null);
  assert.equal(f.ledger.hops[0].wire_status, null);
}
for (const afterTerminal of [false, true]) {
  const f = extraInfoFixture();
  f.extra();
  f.start();
  if (!afterTerminal) f.extra();
  f.finish();
  if (afterTerminal) f.extra();
  assert.equal(extraInfoComparison(f.ledger).result.verdict, 'incomplete');
  assert.equal(
    f.ledger.hops[0].wire_status,
    null,
    'identical duplicate evidence remains ambiguous',
  );
}
for (const status of [undefined, null, '200', NaN]) {
  const f = extraInfoFixture();
  f.start();
  f.extra();
  f.emit('responseReceived', {response: {status}});
  f.finish();
  assert.equal(extraInfoComparison(f.ledger).result.verdict, 'incomplete');
  assert.equal(f.ledger.hops[0].status, null, 'malformed authoritative response blocks fallback');
  assert.equal(f.ledger.hops[0].status_source, 'response-received');
}
const redirectedExtra = extraInfoFixture();
redirectedExtra.start();
redirectedExtra.extra(302);
redirectedExtra.start({timestamp: 1.5, redirectResponse: {status: 302}});
redirectedExtra.extra(200);
redirectedExtra.finish();
assert.equal(extraInfoComparison(redirectedExtra.ledger).result.verdict, 'incomplete');
assert.deepEqual(
  redirectedExtra.ledger.hops.map((h) => h.wire_status),
  [null, null],
);
assert.equal(redirectedExtra.ledger.hops[0].status_source, 'redirect-response');
assert.equal(redirectedExtra.ledger.hops[1].status, null);
const nullRedirect = extraInfoFixture();
nullRedirect.start({redirectResponse: null});
nullRedirect.extra();
nullRedirect.finish();
assert.equal(extraInfoComparison(nullRedirect.ledger).result.verdict, 'incomplete');
assert.equal(
  nullRedirect.ledger.hops[0].status,
  null,
  'present null redirect marker is not absent',
);
const duplicateResponse = extraInfoFixture();
duplicateResponse.start();
duplicateResponse.extra();
duplicateResponse.emit('responseReceived', {response: {status: 200}});
duplicateResponse.emit('responseReceived', {response: {status: 201}});
duplicateResponse.finish();
assert.equal(extraInfoComparison(duplicateResponse.ledger).result.verdict, 'pass');
assert.equal(duplicateResponse.ledger.hops[0].status, 201, 'retain actual response status');
assert.equal(
  duplicateResponse.ledger.hops[0].wire_status,
  null,
  'duplicate response forbids ExtraInfo attribution',
);
for (const evictActive of [false, true]) {
  const f = extraInfoFixture();
  f.start();
  f.extra();
  f.finish();
  if (evictActive) f.ledger.active.clear();
  f.start({timestamp: 3});
  f.finish();
  assert.equal(extraInfoComparison(f.ledger).result.verdict, 'incomplete');
  assert(f.ledger.hops.every((h) => h.status === null && h.wire_status === null));
}
const unrelatedExtra = extraInfoFixture();
unrelatedExtra.ledger.session('other', 'other-target', {type: 'page'});
unrelatedExtra.start();
unrelatedExtra.extra(200, 'other');
unrelatedExtra.finish();
assert.equal(extraInfoComparison(unrelatedExtra.ledger).result.verdict, 'incomplete');
assert.equal(unrelatedExtra.ledger.hops[0].status, null, 'raw ID does not bridge session owners');
const separateOwners = extraInfoFixture();
separateOwners.ledger.session('other', 'other-target', {type: 'page'});
separateOwners.start();
separateOwners.extra(200);
separateOwners.finish();
separateOwners.start({}, 'other');
separateOwners.extra(201, 'other');
separateOwners.finish('other');
assert.equal(extraInfoComparison(separateOwners.ledger).result.verdict, 'pass');
assert.deepEqual(
  separateOwners.ledger.hops.map((h) => h.status),
  [200, 201],
);
const otherEpoch = extraInfoFixture();
otherEpoch.extra();
otherEpoch.ledger.epoch++;
otherEpoch.ledger.session('new-owner', 'new-target', {type: 'page'});
otherEpoch.start({}, 'new-owner');
otherEpoch.finish('new-owner');
assert.equal(extraInfoComparison(otherEpoch.ledger).result.verdict, 'incomplete');
assert.equal(otherEpoch.ledger.hops[0].status, null);
const cappedStatus = extraInfoFixture({maxStatusEntries: 1});
cappedStatus.emit('responseReceivedExtraInfo', {requestId: 'other-id', statusCode: 200});
cappedStatus.start();
cappedStatus.extra();
cappedStatus.finish();
assert.equal(extraInfoComparison(cappedStatus.ledger).result.verdict, 'incomplete');
assert.equal(cappedStatus.ledger.statusHistory.size, 1);
assert(cappedStatus.ledger.errors.has('status-history-limit'));
assert.equal(cappedStatus.ledger.hops[0].status, null);
const {createResponseEvidence} = await import('./capture-completeness-response-evidence.mjs');
const truncatedHistory = extraInfoFixture();
truncatedHistory.ledger.responseEvidence = createResponseEvidence({maxEvents: 0});
truncatedHistory.start();
truncatedHistory.extra();
truncatedHistory.finish();
assert.equal(extraInfoComparison(truncatedHistory.ledger).result.verdict, 'incomplete');
assert.equal(truncatedHistory.ledger.hops[0].status, null, 'omitted evidence prevents attribution');
const eventLimited = extraInfoFixture({maxEvents: 3});
eventLimited.start();
eventLimited.extra();
eventLimited.finish();
eventLimited.emit('dataReceived', {dataLength: 0});
assert.equal(extraInfoComparison(eventLimited.ledger).result.verdict, 'incomplete');
assert.equal(
  eventLimited.ledger.hops[0].status,
  null,
  'event budget loss refuses earlier fallback evidence',
);
const privateExtra = extraInfoFixture();
privateExtra.start();
privateExtra.emit('responseReceivedExtraInfo', {
  statusCode: 200,
  headers: {Authorization: 'PRIVATE'},
  blockedCookies: [{cookieLine: 'PRIVATE'}],
});
privateExtra.finish();
extraInfoComparison(privateExtra.ledger);
assert(!JSON.stringify(privateExtra.ledger.snapshot()).includes('PRIVATE'));
for (const terminal of ['pending', 'failed']) {
  const f = extraInfoFixture();
  f.start();
  f.extra(403);
  if (terminal === 'failed') f.emit('loadingFailed', {canceled: true});
  const {result} = extraInfoComparison(f.ledger);
  assert.equal(f.ledger.hops[0].state, terminal, 'status evidence never invents completion');
  assert.equal(result.verdict, terminal === 'failed' ? 'pass' : 'incomplete');
}
const provenanceFixture = extraInfoFixture();
provenanceFixture.start();
provenanceFixture.extra();
provenanceFixture.finish();
const provenance = extraInfoComparison(provenanceFixture.ledger);
for (const field of ['status_source', 'wire_status', 'both']) {
  const n = structuredClone(provenance.network);
  for (const name of field === 'both' ? ['status_source', 'wire_status'] : [field])
    delete n.requests[0][name];
  assert.equal(
    compareCapture(provenance.reference, n).verdict,
    'incomplete',
    'fallback cannot pass as legacy provenance',
  );
}
for (const [field, value, reason] of [
  ['status_source', 'response-received', 'statusSource'],
  ['status_source', 'unavailable', 'statusSource'],
  ['wire_status', 201, 'wireStatus'],
]) {
  const n = structuredClone(provenance.network);
  n.requests[0][field] = value;
  const result = compareCapture(provenance.reference, n);
  assert.notEqual(result.verdict, 'pass');
  assert.equal(result.mismatchReasons[reason], 1);
}
for (const [field, value] of [
  ['status_source', 'unknown'],
  ['status_source', 'unavailable'],
  ['wire_status', undefined],
  ['wire_status', 0],
  ['wire_status', 200.5],
  ['status', 304],
]) {
  const n = structuredClone(provenance.network);
  n.requests[0][field] = value;
  assert(compareCapture(provenance.reference, n).issues.includes('malformed-status-provenance'));
}
console.log(
  'PASS same-owner single-hop ExtraInfo status, ordering, authoritative response/304, provenance, collision, reuse, history bounds and frozen-window controls',
);
