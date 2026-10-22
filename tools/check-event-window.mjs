import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';

const models = await readFile(new URL('../apps/research-ui/evidence_models.js', import.meta.url), 'utf8');
const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
const start = app.indexOf('      function networkContentCaptureEnabled()');
const end = app.indexOf('      function textElement(', start);
assert(start >= 0 && end > start, 'Traffic notice helpers must stay extractable');
const state = {
  sessionMode: 'live',
  broker: 'connected',
  eventFailureKind: null,
  eventsLimited: true,
  events: [],
  sequenceGaps: 280n,
  queueDrops: 280n,
  requests: [],
  debuggerSession: {state: 'running', network: {capture_enabled: false}}
};
let notice;
const api = runInNewContext(
  `${models}\n${app.slice(start, end)};({isBrokerResponse,captureWideTotal,countSequenceGaps,countReportedQueueDrops,requestsFromEvents,shownSequenceGaps,shownQueueDrops,eventGapLabel,fingerprintCoverageNotice,renderNetworkNotice})`,
  {
    state,
    TextEncoder,
    TextDecoder,
    elements: {networkNotice: {hidden: true, dataset: {}}},
    setNetworkNotice(kind, text) { notice = {kind, text}; }
  }
);

const canvas = sequence => ({
  protocol_version: 3,
  session_id: '1',
  sequence_number: String(sequence),
  process_id: 7,
  category: 'canvas',
  type: 'api_call',
  payload_encoding: 'hex',
  payload: '',
  payload_size: 0
});
state.events = [canvas(1), canvas(2)];
assert.equal(api.countSequenceGaps(state.events), 0n);
assert.equal(api.countReportedQueueDrops(state.events), 0n);
assert.equal(api.captureWideTotal('280'), 280n);
assert.equal(api.captureWideTotal(280), null);
assert.equal(
  api.eventGapLabel(api.shownSequenceGaps(), api.shownQueueDrops()),
  '280 missing event IDs · 280 reported queue drops (may overlap)'
);
api.renderNetworkNotice();
assert.equal(notice.kind, 'gap');
assert.match(notice.text, /Showing a 5,000-event window/);
assert.match(notice.text, /280 captured event IDs are missing/);
assert.match(notice.text, /The queue reports 280 dropped events; counts may overlap sequence gaps/);
assert.equal(
  api.fingerprintCoverageNotice(true, false, 500, 280n, 280n),
  'Fingerprint activity is visible with partial coverage: the event window is capped; 280 capture-wide event IDs are missing; 280 queue drops were reported (may overlap missing IDs).'
);

state.sequenceGaps = null;
state.queueDrops = null;
assert.equal(api.eventGapLabel(api.shownSequenceGaps(), api.shownQueueDrops()), '0 missing event IDs');
state.sequenceGaps = 280n;
state.queueDrops = 280n;

const request = (sequence, type) => ({
  protocol_version: 3,
  session_id: '9',
  sequence_number: String(sequence),
  monotonic_time_ns: String(sequence),
  navigation_id: '1',
  frame_id: '1',
  artifact_id: '0',
  parent_event_id: '0',
  request_id: String(sequence),
  process_id: 7,
  thread_id: 1,
  tab_id: 1,
  category: 'network',
  type,
  payload_encoding: 'hex',
  payload: '',
  payload_size: 0,
  browser_context_id_high: '0',
  browser_context_id_low: '0',
  encoded_data_length: '0',
  decoded_body_length: '0',
  status_code: 0,
  error_code: 0,
  resource_type: 1,
  flags: 0,
  payload_truncated: false,
  initiator_request_id: 0,
  initiator_process_id: 0
});
const gap = {
  ...request(285, 'gap'),
  category: 'webgl',
  payload_size: 3,
  payload: Buffer.from('280').toString('hex')
};
const retained = [
  request(1, 'request_initiated'),
  request(2, 'request_started'),
  request(3, 'response_started'),
  request(4, 'request_completed'),
  gap
];
assert.equal(api.countReportedQueueDrops(retained), 280n);
const rows = api.requestsFromEvents(retained, 'live');
const retainedTypes = new Set(rows.flatMap(row => row.events.map(event => event.type)));
for (const type of ['request_initiated', 'request_started', 'response_started', 'request_completed']) {
  assert(retainedTypes.has(type), type);
}
assert(!retainedTypes.has('gap'));
const response = {
  count: retained.length,
  events: retained,
  sequence_gaps: '280',
  queue_drops: '280',
  sequence_gaps_saturated: false,
  queue_drops_saturated: false
};
assert.equal(api.isBrokerResponse(response), true);
response.sequence_gaps = '0280';
assert.equal(api.isBrokerResponse(response), false);

console.log('PASS capture-wide gap totals stay visible when the rendered event window has no gap, and retained request events still form a Traffic row');
