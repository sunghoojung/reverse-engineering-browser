import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';

const models = await readFile(new URL('../apps/research-ui/evidence_models.js', import.meta.url), 'utf8');
const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
const traffic = await readFile(new URL('../apps/research-ui/traffic_view.js', import.meta.url), 'utf8');
const trafficStart = traffic.indexOf('function trafficRequestFailed(');
const trafficEnd = traffic.indexOf('function renderTrafficRows(', trafficStart);
assert(trafficStart >= 0 && trafficEnd > trafficStart);
const failedNoticeHelpers = traffic.slice(trafficStart, trafficEnd);
const start = app.indexOf('      function renderNetworkNotice()');
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
  eventCountScope: 'store',
  requests: []
};
let notice;
const api = runInNewContext(
  `${failedNoticeHelpers}\n${models}\n${app.slice(start, end)};({isBrokerResponse,acceptEventWindow,captureWideTotal,countSequenceGaps,countReportedQueueDrops,requestsFromEvents,shownSequenceGaps,shownQueueDrops,eventGapLabel,fingerprintCoverageNotice,renderNetworkNotice})`,
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
  '280 sequence-gap IDs (the stored capture) · 280 reported queue drops (may overlap)'
);
api.renderNetworkNotice();
assert.equal(notice.kind, 'gap');
assert.match(notice.text, /Showing the last 5,000 evidence events/);
assert.match(notice.text, /280 sequence-gap IDs were observed in the stored capture/);
assert.match(notice.text, /The queue reports 280 dropped events; counts may overlap sequence gaps/);
assert.equal(
  api.fingerprintCoverageNotice(true, false, 500, 280n, 280n),
  'Fingerprint activity is visible with partial coverage: the event window is capped; 280 sequence-gap IDs were observed in the stored capture; 280 queue drops were reported in the stored capture (may overlap sequence gaps).'
);

state.sequenceGaps = null;
state.queueDrops = null;
assert.equal(api.eventGapLabel(api.shownSequenceGaps(), api.shownQueueDrops()), '0 sequence-gap IDs (the stored capture)');
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

console.log('PASS scoped gap totals stay visible when the rendered event window has no gap, and retained request events still form a Traffic row');

// Run the actual admission/update helpers, not a handwritten summary projection.
const coverage = {scope: 'bounded_tail', scan_start: '100', scan_end: '200', scan_limit: 67108864,
  events_limited: false, network_events_limited: true};
const bounded = {...response, sequence_gaps: '280', event_window: coverage, network_events: retained.slice(0, 4)};
assert.equal(api.isBrokerResponse(bounded), true);
api.acceptEventWindow(bounded);
api.renderNetworkNotice();
assert.match(notice.text, /Only the newest 64 MiB/);
assert.match(notice.text, /280 sequence-gap IDs were observed in the scanned tail/);
assert.match(notice.text, /network event window is capped/);
assert.doesNotMatch(notice.text, /separate newest-network window/);
assert.match(api.eventGapLabel(api.shownSequenceGaps(), api.shownQueueDrops()), /the scanned tail/);
for (const invalid of [
  {...bounded, network_events: [gap]},
  {...bounded, event_window: {...coverage, scope: 'store'}},
  {...bounded, event_window: {...coverage, scan_end: '99'}},
  {...bounded, event_window: {...coverage, scan_end: '67108965'}},
]) assert.equal(api.isBrokerResponse(invalid), false);
api.acceptEventWindow({count: 0, events: []});
assert.equal(state.sequenceGaps, null, 'legacy/missing summaries must not preserve old totals');
assert.equal(state.queueDrops, null);
assert.equal(state.eventCountScope, 'rendered_window');
assert.equal(state.networkEventsAvailable, false);
assert.match(api.eventGapLabel(0n, 0n), /visible event window/);
console.log('PASS production scoped summary admission, independent network bounds and legacy refresh reset');

const refreshStart = app.indexOf('      async function refresh()');
const refreshEnd = app.indexOf('      function useStandalonePreview()', refreshStart);
assert(refreshStart >= 0 && refreshEnd > refreshStart);
Object.assign(state, {refreshing: false, eventEtag: null, signalKnownKeys: null, signalNewKeys: new Set(),
  lastValidAnalysisFindings: [], selectedRequestId: null});
let refreshBody = {...bounded, network_events: bounded.network_events.map(event => ({...event, request_id: '1'})), events: [{...request(999, 'api_call'), category: 'canvas'}], count: 1};
const noop = () => {};
const refresh = runInNewContext(`${models}\n${app.slice(refreshStart, refreshEnd)};refresh`, {
  state, TextEncoder, TextDecoder, TypeError,
  elements: {gaps: {textContent: ''}},
  document: {querySelector: () => ({hidden: true})},
  fetch: async () => ({ok: true, status: 200, text: async () => JSON.stringify(refreshBody), headers: {get: () => 'fixture'}}),
  fingerprintEventsFromEvents: () => [], signalEventKey: noop,
  vmFindingsFromEvents: () => ({findings: [], malformedCount: 0}),
  rebuildTrafficRequests: () => { state.requests = state.nativeRequests; },
  resetRequestSelection: noop, updateSelectionSummary: noop, renderShellStatus: noop,
  renderNetworkNotice: noop, renderRequests: noop, renderInspector: noop, renderEvidence: noop,
  renderFingerprintActivity: noop, refreshRequestSignalProfile: noop, refreshArtifacts: noop,
  refreshVmAnalysis: noop, renderVmLab: noop
});
await refresh();
assert.equal(state.eventFailureKind, null);
assert.equal(state.nativeRequests.length, 1, 'production refresh uses independently retained network events');
assert.equal(state.nativeRequests[0].operation, 'request_completed');
assert.equal(state.nativeRequests[0].rank, 5);
assert.equal(state.events[0].category, 'canvas');
// rebuildTrafficRequests() shows exactly the native rows; there is no second producer.
const liveRows = state.nativeRequests;
assert.equal(liveRows.length, 1, 'A canvas-only general window still leaves the retained network request in Traffic');
assert.equal(liveRows[0].operation, 'request_completed');
assert.equal(liveRows[0].events.some(event => event.category === 'network'), true);
for (const [type, status] of [['request_failed', 'failed'], ['response_completed', 200], ['request_redirected', 302]]) {
  refreshBody = {...bounded, count: 1, events: [{...request(999, 'api_call'), category: 'canvas'}],
    network_events: [{...request(200, type), status_code: typeof status === 'number' ? status : 0}]};
  await refresh();
  assert.equal(state.eventFailureKind, null);
  assert.equal(state.nativeRequests.length, 1);
  assert.equal(state.nativeRequests[0].status, status, `production refresh preserves ${type}`);
  assert.equal(state.nativeRequests[0].operation, type);
}
refreshBody = {count: 0, events: []};
await refresh();
assert.equal(state.sequenceGaps, null);
assert.equal(state.queueDrops, null);
assert.equal(state.nativeRequests.length, 0);
console.log('PASS actual refresh keeps Traffic outcomes through a general canvas window and resets missing summaries');

Object.assign(state, {sequenceGaps: 18446744073709551615n, queueDrops: 18446744073709551615n,
  sequenceGapsSaturated: true, queueDropsSaturated: true, eventCountScope: 'bounded_tail'});
api.renderNetworkNotice();
assert.match(notice.text, /at least 18446744073709551615 sequence-gap IDs/);
assert.match(notice.text, /reports at least 18446744073709551615 dropped events/);
const saturated = api.fingerprintCoverageNotice(false, false, 500, state.sequenceGaps, state.queueDrops, 'the scanned tail');
assert.match(saturated, /at least 18446744073709551615 sequence-gap IDs/);
assert.match(saturated, /at least 18446744073709551615 queue drops/);
console.log('PASS primary Traffic and fingerprint notices disclose saturated totals as lower bounds');

for (const invalid of ['2\n', '2\r', '2 ', ' 2', '+2', '02', '-2', '18446744073709551616']) {
  assert.equal(api.captureWideTotal(invalid), null);
  assert.equal(api.countReportedQueueDrops([{...gap, payload: Buffer.from(invalid).toString('hex')}]), 1n);
}
assert.equal(api.countSequenceGaps([request(1, 'request_started'), {...gap, sequence_number: '4', session_id: '9'}, request(5, 'request_completed')]), 2n,
  'visible fallback and backend both count a present gap marker in sequence high-water accounting');
console.log('PASS strict unsigned summaries/drop payloads and gap-marker high-water parity');

for (const sequences of [[3, 1, 2], [1, 4, 2, 3], [3, 1, 2, 2]]) {
  assert.equal(api.countSequenceGaps(sequences.map(n => request(n, 'request_started'))), 0n,
    'late ACK identities close holes and duplicates do not create loss');
}
assert.equal(api.countSequenceGaps([1, 5, 3].map(n => request(n, 'request_started'))), 2n);
console.log('PASS delayed-ACK and duplicate-aware sequence gaps');
