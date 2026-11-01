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
const elements = {networkNotice: {hidden: true, dataset: {}}};
const api = runInNewContext(
  `${failedNoticeHelpers}\n${models}\n${app.slice(start, end)};({isBrokerResponse,acceptEventWindow,captureWideTotal,countSequenceGaps,countReportedQueueDrops,requestsFromEvents,shownSequenceGaps,shownQueueDrops,shownNamedGaps,namedGapsFromEvents,namedGapsIn,namedGapNotice,eventGapLabel,fingerprintCoverageNotice,renderNetworkNotice,fingerprintSignalCategories,vmGapCategories})`,
  {
    state,
    TextEncoder,
    TextDecoder,
    elements,
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

// Live 2026-10-31 capture: two Wasm interpreters hit their 16-observation
// budgets. The browser kept exact samples and wrote two named vm gaps; nothing
// was dropped from a queue and no fingerprint or network evidence was lost.
const budgetGap = (sequence, reason, category = 'vm') => ({
  ...request(sequence, 'gap'), category, process_id: 11, payload_size: reason.length, payload: Buffer.from(reason).toString('hex')
});
const liveBudgets = [budgetGap(1, 'native_wasm_dispatch_budget_incomplete'), budgetGap(2, 'native_wasm_indirect_budget_incomplete')];
const liveResponse = {count: 2, events: liveBudgets, network_events: [], sequence_gaps: '0', queue_drops: '2',
  sequence_gaps_saturated: false, queue_drops_saturated: false, event_window: {...coverage, scope: 'store', scan_start: '0', network_events_limited: false},
  named_gaps: [{category: 'vm', reason: 'native_wasm_dispatch_budget_incomplete', count: '1'},
    {category: 'vm', reason: 'native_wasm_indirect_budget_incomplete', count: '1'}]};
assert.equal(api.isBrokerResponse(liveResponse), true);
Object.assign(state, {events: liveBudgets, requests: [], eventsLimited: false});
api.acceptEventWindow(liveResponse);
assert.equal(api.shownQueueDrops(), 0n, 'named budget markers are not queue drops');
assert.equal(api.eventGapLabel(api.shownSequenceGaps(), api.shownQueueDrops(), api.shownNamedGaps()),
  '0 sequence-gap IDs (the stored capture) · 2 sampling budgets reached (vm)');
notice = null;
elements.networkNotice.hidden = false;
api.renderNetworkNotice();
assert.equal(notice, null, 'Traffic has no network loss to report');
assert.equal(elements.networkNotice.hidden, true);
assert.equal(api.namedGapsIn(api.shownNamedGaps(), api.fingerprintSignalCategories).length, 0, 'a vm budget leaves Fingerprinting complete');
const vmNotice = api.namedGapNotice(api.namedGapsIn(api.shownNamedGaps(), api.vmGapCategories), 'the stored capture');
assert.equal(vmNotice, 'Sampling budget reached in the stored capture for Wasm br_table dispatch (native_wasm_dispatch_budget_incomplete); ' +
  'Wasm call_indirect dispatch (native_wasm_indirect_budget_incomplete). Retained observations are exact; later ones were not sampled.');
console.log('PASS named vm sampling budgets are scoped capture limits, not queue drops or Traffic/Fingerprinting loss');

// Numeric gap payloads remain queue drops beside named markers in the same total.
api.acceptEventWindow({...liveResponse, queue_drops: '7', named_gaps: [...liveResponse.named_gaps,
  {category: 'vm', reason: 'native_wasm_dispatch_transport_unavailable', count: '2'}]});
assert.equal(api.shownQueueDrops(), 3n);
assert.equal(api.eventGapLabel(0n, api.shownQueueDrops(), api.shownNamedGaps()),
  '0 sequence-gap IDs (the stored capture) · 3 reported queue drops (may overlap) · 2 sampling budgets reached (vm) · 2 reported capture losses (vm)');
api.renderNetworkNotice();
assert.equal(notice.text, 'The queue reports 3 dropped events; no sequence jump is visible in the stored capture.');
assert.match(api.namedGapNotice(api.shownNamedGaps(), 'the stored capture'),
  /^Capture reported lost vm evidence in the stored capture: native_wasm_dispatch_transport_unavailable ×2\. Sampling budget reached/);
// Saturated totals stay lower bounds after the named weight is removed.
api.acceptEventWindow({...liveResponse, queue_drops: '18446744073709551615', queue_drops_saturated: true});
api.renderNetworkNotice();
assert.match(notice.text, /reports at least 18446744073709551613 dropped events/);
console.log('PASS numeric queue drops, named losses and saturation stay separate and visible');

// A response without named_gaps still separates the named markers it can see.
api.acceptEventWindow({count: 2, events: liveBudgets, sequence_gaps: '0', queue_drops: '2'});
assert.equal(state.namedGaps, null);
assert.equal(api.countReportedQueueDrops(liveBudgets), 0n);
assert.equal(api.shownNamedGaps().length, 2);
assert.equal(api.shownQueueDrops(), 0n);
state.queueDrops = null;
assert.equal(api.countReportedQueueDrops([...liveBudgets, gap]), 280n);
assert.equal(api.namedGapsFromEvents([liveBudgets[0], liveBudgets[0], gap]).map(entry => `${entry.category}:${entry.reason}:${entry.count}`).join(),
  'vm:native_wasm_dispatch_budget_incomplete:2');
for (const payload of ['', '0', '7', 'Native_gap', 'native-gap', '1native', '_native', 'native gap', '<b>gap</b>']) {
  assert.equal(api.namedGapsFromEvents([budgetGap(1, payload)]).length, 0, payload);
}
assert.equal(api.namedGapsFromEvents([{...liveBudgets[0], payload_truncated: true}]).length, 0, 'a truncated reason is not named');
console.log('PASS legacy summaries separate visible named markers; counts and malformed text stay queue drops');

// A limit belongs to the surface that shows its category.
Object.assign(state, {events: [], namedGaps: [{category: 'network', reason: 'native_network_example_unavailable', count: 1n},
  {category: 'canvas', reason: 'native_canvas_example_unavailable', count: 1n},
  {category: 'vm', reason: 'native_js_dispatch_budget_incomplete', count: 1n}], queueDrops: 3n, queueDropsSaturated: false});
api.renderNetworkNotice();
assert.equal(notice.text, 'Capture reported lost network evidence in the stored capture: native_network_example_unavailable.');
const canvasOnly = api.namedGapsIn(api.shownNamedGaps(), api.fingerprintSignalCategories);
assert.equal(api.fingerprintCoverageNotice(false, false, 500, 0n, api.shownQueueDrops(), 'the stored capture', canvasOnly),
  'Fingerprint activity is visible with partial coverage: capture reported lost evidence in the stored capture: canvas native_canvas_example_unavailable.');
console.log('PASS named limits mark only Traffic, Fingerprinting or VM coverage for their own category');

for (const named_gaps of [
  [{category: 'vm', reason: 'native_wasm_dispatch_budget_incomplete', count: '0'}],
  [{category: 'vm', reason: 'native_wasm_dispatch_budget_incomplete', count: '01'}],
  [{category: 'vm', reason: 'Native_reason', count: '1'}],
  [{category: 'VM', reason: 'native_reason', count: '1'}],
  [{category: 'vm', reason: 'native_reason', count: '1', note: 'x'}],
  [{category: 'vm', reason: 'native_reason', count: '1'}, {category: 'vm', reason: 'native_reason', count: '1'}],
  [{category: 'vm', reason: 'native_reason', count: '3'}],
  Array.from({length: 65}, (_, index) => ({category: 'vm', reason: `native_reason_${index}`, count: '1'})),
  {category: 'vm', reason: 'native_reason', count: '1'}
]) assert.equal(api.isBrokerResponse({...liveResponse, named_gaps}), false, JSON.stringify(named_gaps).slice(0, 80));
assert.equal(api.isBrokerResponse({...liveResponse, queue_drops: '2', queue_drops_saturated: true,
  named_gaps: [{category: 'vm', reason: 'native_reason', count: '3'}]}), true, 'a saturated total is a lower bound');
console.log('PASS named gap summaries are strict, unique, bounded and covered by queue_drops');
