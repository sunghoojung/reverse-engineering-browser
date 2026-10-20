import assert from 'node:assert/strict';
import {ReferenceLedger} from './capture-completeness-reference.mjs';
import {
  createResponseEvidence,
  scopedResponseEvidence,
  sanitizeResponseEvidence,
} from './capture-completeness-response-evidence.mjs';
const ledger = new ReferenceLedger();
ledger.session('source-secret', 'target-secret');
ledger.session('other-secret', 'other-target-secret');
const emit = (method, params, sessionId = 'source-secret') =>
  ledger.ingest({method, params, sessionId});
emit('Network.responseReceivedExtraInfo', {
  requestId: 'request-secret',
  statusCode: 304,
  headers: {secret: 'never-export'},
});
emit('Network.requestWillBeSent', {
  requestId: 'request-secret',
  request: {url: 'http://owned.test/a', method: 'GET'},
  timestamp: 1,
  type: 'Fetch',
});
emit('Network.responseReceived', {
  requestId: 'request-secret',
  response: {status: 200},
  hasExtraInfo: true,
});
emit(
  'Network.responseReceivedExtraInfo',
  {requestId: 'request-secret', statusCode: 201},
  'other-secret',
);
emit('Network.requestWillBeSent', {
  requestId: 'request-secret',
  request: {url: 'http://owned.test/b', method: 'GET'},
  timestamp: 2,
  type: 'Fetch',
  redirectResponse: {status: 302},
});
const snapshot = ledger.snapshot();
const scoped = scopedResponseEvidence(snapshot, () => true);
assert.equal(scoped.hops.length, 2);
assert.equal(scoped.hops[0].namespaceHopCount, 2);
assert.equal(scoped.hops[0].events[0].kind, 'extra-info');
assert.equal(scoped.hops[0].events[2].sessionRelation, 'other-session-matching-raw-id');
assert.deepEqual(
  scoped.hops[0].events,
  scoped.hops[1].events,
  'Namespace observations are not assigned to redirect hops by order',
);
assert.equal(snapshot.hops[1].status, null, 'Extra-info never supplies a missing status');
const clean = sanitizeResponseEvidence({...scoped, secret: 'bad'});
assert(!JSON.stringify(clean).includes('secret'));
assert.throws(() =>
  sanitizeResponseEvidence({
    ...scoped,
    hops: [
      {...scoped.hops[0], events: [{...scoped.hops[0].events[0], sessionRelation: 'raw-secret'}]},
    ],
  }),
);
const bounded = createResponseEvidence({maxEvents: 1});
bounded.observe(1, 's', 'Network.responseReceived', {requestId: 'r', response: {status: 0}});
bounded.observe(1, 's', 'Network.responseReceivedExtraInfo', {requestId: 'r', statusCode: 200});
assert.equal(bounded.snapshot().complete, false);
assert.equal(bounded.snapshot().omittedEvents, 1);
const later = structuredClone(snapshot);
later.hops[0].terminalSessionId = 'other-secret';
assert.equal(
  scopedResponseEvidence(later, () => true).hops[0].events[2].sessionRelation,
  'proven-terminal-session',
);
ledger.finalize();
emit('Network.responseReceivedExtraInfo', {requestId: 'request-secret', statusCode: 500});
assert.equal(
  ledger.snapshot().responseEvidence.events.length,
  3,
  'Finalized diagnostic evidence is frozen',
);
console.log(
  'PASS response event diagnostics: extra-info ordering, redirect ambiguity, unrelated sessions, bounded loss, privacy and no attribution',
);

for (const invalid of [
  {...scoped, omittedEvents: 1},
  {...scoped, omittedHops: 1},
  {...scoped, hops: [{...scoped.hops[0], omittedEvents: 1}]},
])
  assert.throws(() => sanitizeResponseEvidence(invalid), /inconsistent/);
const collidedEpoch = structuredClone(snapshot);
collidedEpoch.responseEvidence.events.push({...collidedEpoch.responseEvidence.events[0], epoch: 2});
assert.equal(scopedResponseEvidence(collidedEpoch, () => true).hops[0].events.length, 3);
