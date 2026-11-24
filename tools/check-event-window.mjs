// Event-window admission and the gap counts the status bar and the Traffic
// notice show, through the production models, app.js notice and the chips
// module in a LinkeDOM document (no layout or focus; make rendered-ui-check
// covers the packaged window).
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {runInNewContext} from 'node:vm';

const {parseHTML} = createRequire(new URL('ui-startup-deps/', import.meta.url))('linkedom');
const models = await readFile(new URL('../apps/research-ui/evidence_models.js', import.meta.url), 'utf8');
const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
const chipsSource = await readFile(new URL('../apps/research-ui/evidence_chips.js', import.meta.url), 'utf8');
const traffic = await readFile(new URL('../apps/research-ui/traffic_view.js', import.meta.url), 'utf8');
const trafficStart = traffic.indexOf('function trafficRequestFailed(');
const trafficEnd = traffic.indexOf('function renderTrafficRows(', trafficStart);
assert(trafficStart >= 0 && trafficEnd > trafficStart);
const failedNoticeHelpers = traffic.slice(trafficStart, trafficEnd);
const start = app.indexOf('      function setNetworkNotice(');
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
  requests: [],
  trafficFlags: {}
};
const {window} = parseHTML('<!doctype html><html><body><div id="network-notice" hidden></div><input id="filter"></body></html>');
const {document} = window;
const elements = {networkNotice: document.getElementById('network-notice'), requestFilter: document.getElementById('filter')};
let evidenceShown = 0;
const context = {state, TextEncoder, TextDecoder, elements, document, window, navigator: {}, setTimeout, clearTimeout,
  showCaptureGapsInEvidence() { evidenceShown += 1; }};
runInNewContext(chipsSource, context);
const api = runInNewContext(
  `${failedNoticeHelpers}\n${models}\n${app.slice(start, end)};({isBrokerResponse,isBrokerEvent,decodePayload,acceptEventWindow,captureWideTotal,countSequenceGaps,countReportedQueueDrops,requestsFromEvents,shownSequenceGaps,shownQueueDrops,shownNamedGaps,namedGapsFromEvents,namedGapsIn,captureGapClasses,captureGapClassChip,captureGapStatusChip,eventCountScopeLabel,eventCountScopeTitle,fingerprintCoverageNotice,renderNetworkNotice,fingerprintSignalCategories,vmGapCategories})`,
  context
);
const chips = context.RebEvidenceChips;
// Counts use the reader's locale grouping; expectations are built the same way.
const n = value => new Intl.NumberFormat().format(value);
// What the Traffic notice line shows: its lead and each chip's text.
const notice = () => {
  const line = elements.networkNotice;
  const lead = line.querySelector('.ev-notice-lead');
  return {hidden: line.hidden, kind: line.dataset.kind, lead: lead && !lead.hidden ? lead.textContent : '',
    chips: [...line.querySelectorAll('.ev-notice-chips .ev-chip')].map(chip => chip.textContent),
    names: [...line.querySelectorAll('.ev-notice-chips .ev-chip')].map(chip => chip.getAttribute('aria-label')),
    text: line.hidden ? '' : line.textContent};
};
// The status bar's chip over every class the summaries count.
const statusChip = () => api.captureGapStatusChip(api.captureGapClasses({sequenceGaps: api.shownSequenceGaps(),
  queueDrops: api.shownQueueDrops(), malformedLines: state.eventMalformedLines ?? 0, namedGaps: api.shownNamedGaps()}));

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
{
  const chip = statusChip();
  assert.equal(chip.text, '560 gaps');
  assert.equal(chip.name, '560 gaps in the stored capture');
  assert.equal(chip.tone, 'loss');
  assert.equal(chip.breakdown.scope, 'stored capture');
  assert.deepEqual(Array.from(chip.breakdown.rows, row => [row.label, row.count]), [['Sequence gaps', 280n], ['Queue drops', 280n]]);
  assert.equal(chip.breakdown.note, 'Counts can overlap: a queue drop can also leave a sequence gap.');
}
api.renderNetworkNotice();
assert.deepEqual(notice(), {hidden: false, kind: 'gap', lead: 'Incomplete capture',
  chips: ['280 sequence gaps', '280 queue drops', `newest ${n(5000)} events`],
  names: ['280 sequence gaps in the stored capture', '280 queue drops in the stored capture', `Rows come from the newest ${n(5000)} events`],
  text: notice().text});
assert.match(notice().text, /Show in Evidence$/);
elements.networkNotice.querySelector('.ev-notice-action[data-action="evidence"]').click();
assert.equal(evidenceShown, 1, 'Show in Evidence opens the coverage panel');
// Opening a chip shows its scope, meaning and nothing in place of the counts.
{
  const sequence = elements.networkNotice.querySelector('.ev-chip[data-key="sequence"]');
  assert.equal(sequence.getAttribute('aria-expanded'), 'false');
  sequence.click();
  assert.equal(sequence.getAttribute('aria-expanded'), 'true');
  const panel = document.getElementById(sequence.getAttribute('aria-controls'));
  assert.match(panel.textContent, /^Sequence gapsstored captureSequence IDs absent between the first and last record of a process/);
  sequence.click();
  assert.equal(sequence.getAttribute('aria-expanded'), 'false');
}
// Dismissing the line hides it for this session until a class it did not
// hold appears; the status bar chip keeps every count meanwhile.
elements.networkNotice.querySelector('.ev-notice-dismiss').click();
assert.equal(notice().hidden, true);
api.renderNetworkNotice();
assert.equal(notice().hidden, true, 'A dismissed line stays dismissed across polls');
assert.equal(statusChip().text, '560 gaps');
state.eventMalformedLines = 2;
api.renderNetworkNotice();
assert.deepEqual(notice().chips, ['280 sequence gaps', '280 queue drops', '2 unreadable lines', `newest ${n(5000)} events`], 'A new class brings the line back');
state.eventMalformedLines = 0;
api.renderNetworkNotice();
assert.equal(notice().hidden, false);
// Every count reads in the locale grouping, never as raw digits.
state.sequenceGaps = 75511n;
api.renderNetworkNotice();
assert.equal(notice().chips[0], `${n(75511)} sequence gaps`);
assert.equal(statusChip().text, `${n(75791)} gaps`);
if (new Intl.NumberFormat().resolvedOptions().locale.startsWith('en')) assert.equal(notice().chips[0], '75,511 sequence gaps');
state.sequenceGaps = 280n;
assert.equal(
  api.fingerprintCoverageNotice(true, false, 500, 280n, 280n),
  'Fingerprint activity is visible with partial coverage: the event window is capped; 280 sequence-gap IDs were observed in the stored capture; 280 queue drops were reported in the stored capture (may overlap sequence gaps).'
);

state.sequenceGaps = null;
state.queueDrops = null;
assert.equal(statusChip(), null, 'No gap is no chip');
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
assert.deepEqual(notice().chips, ['280 sequence gaps', '280 queue drops', `newest ${n(5000)} events`, 'newest 64 MiB']);
assert.deepEqual(notice().names.slice(0, 2), ['280 sequence gaps in the scanned tail', '280 queue drops in the scanned tail']);
{
  const limit = elements.networkNotice.querySelector('.ev-chip[data-key="window"]');
  limit.click();
  assert.match(document.getElementById(limit.getAttribute('aria-controls')).textContent, /so older lifecycle records can be missing/);
  limit.click();
  const scan = elements.networkNotice.querySelector('.ev-chip[data-key="scan"]');
  scan.click();
  assert.match(document.getElementById(scan.getAttribute('aria-controls')).textContent, /only the newest 64 MiB is scanned/);
  scan.click();
}
assert.equal(statusChip().name, '560 gaps in the scanned tail');
assert.equal(statusChip().breakdown.scope, 'newest 64 MiB');
for (const invalid of [
  {...bounded, network_events: [gap]},
  {...bounded, event_window: {...coverage, scope: 'store'}},
  {...bounded, event_window: {...coverage, scan_end: '99'}},
  {...bounded, event_window: {...coverage, scan_end: '67108965'}},
  {...bounded, event_window: {...coverage, next_before: '201'}},
  {...bounded, event_window: {...coverage, next_before: 100}},
]) assert.equal(api.isBrokerResponse(invalid), false);
// The event index counts a whole store larger than the scan limit; the windows
// still end at scan_end, and next_before reads the older events.
const indexedStore = {...bounded, event_window: {...coverage, scope: 'store', scan_start: '0',
  scan_end: '450000000', next_before: '449000000'}};
assert.equal(api.isBrokerResponse(indexedStore), true);
api.acceptEventWindow(indexedStore);
assert.equal(statusChip().name, '560 gaps in the stored capture');
assert.equal(api.isBrokerResponse({...indexedStore, event_window: {...indexedStore.event_window, next_before: null}}), true);
api.acceptEventWindow({count: 0, events: []});
assert.equal(state.sequenceGaps, null, 'legacy/missing summaries must not preserve old totals');
assert.equal(state.queueDrops, null);
assert.equal(state.eventCountScope, 'rendered_window');
assert.equal(state.networkEventsAvailable, false);
assert.equal(api.eventCountScopeLabel(), 'the visible event window');
assert.equal(api.eventCountScopeTitle(), 'visible events');
console.log('PASS production scoped summary admission, independent network bounds and legacy refresh reset');

const refreshStart = app.indexOf('      // Evidence times are relative to the store');
const refreshEnd = app.indexOf('      function useStandalonePreview()', refreshStart);
assert(refreshStart >= 0 && refreshEnd > refreshStart);
Object.assign(state, {refreshing: false, eventEtag: null, signalKnownKeys: null, signalNewKeys: new Set(),
  lastValidAnalysisFindings: [], selectedRequestId: null});
let refreshBody = {...bounded, network_events: bounded.network_events.map(event => ({...event, request_id: '1'})), events: [{...request(999, 'api_call'), category: 'canvas'}], count: 1};
const noop = () => {};
const refresh = runInNewContext(`${models}\n${app.slice(refreshStart, refreshEnd)};refresh`, {
  state, TextEncoder, TextDecoder, TypeError, AbortSignal,
  elements: {gaps: {textContent: ''}},
  document: {querySelector: () => ({hidden: true})},
  fetch: async () => ({ok: true, status: 200, text: async () => JSON.stringify(refreshBody), headers: {get: () => 'fixture'}}),
  fingerprintEventsFromEvents: () => [], signalEventKey: noop,
  vmFindingsFromEvents: () => ({findings: [], malformedCount: 0}),
  rebuildTrafficRequests: () => { state.requests = state.nativeRequests; },
  resetRequestSelection: noop, updateSelectionSummary: noop, renderShellStatus: noop,
  renderNetworkNotice: noop, renderRequests: noop, renderInspector: noop, renderEvidence: noop,
  renderFingerprintActivity: noop, refreshRequestSignalProfile: noop, refreshArtifacts: noop, refreshSelectedRequestBody: noop,
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
const most = n(18446744073709551615n);
assert.deepEqual(notice().chips.slice(0, 2), [`≥${most} sequence gaps`, `≥${most} queue drops`]);
assert.equal(statusChip().text, `≥${n(36893488147419103230n)} gaps`, 'A saturated class makes the total a lower bound');
const saturated = api.fingerprintCoverageNotice(false, false, 500, state.sequenceGaps, state.queueDrops, 'the scanned tail');
assert.match(saturated, new RegExp(`at least ${most} sequence-gap IDs`));
assert.match(saturated, new RegExp(`at least ${most} queue drops`));
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
{
  const chip = statusChip();
  assert.equal(chip.text, '2 sampling budgets (vm)', 'A single class keeps its own noun');
  assert.equal(chip.tone, 'limit', 'A sampling budget is a limit, not a loss');
  assert.deepEqual(Array.from(chip.breakdown.reasons, entry => [entry.token, entry.count]),
    [['native_wasm_dispatch_budget_incomplete', 1n], ['native_wasm_indirect_budget_incomplete', 1n]]);
}
elements.networkNotice.hidden = false;
api.renderNetworkNotice();
assert.equal(notice().hidden, true, 'Traffic has no network loss to report');
assert.equal(elements.networkNotice.children.length, 0);
assert.equal(api.namedGapsIn(api.shownNamedGaps(), api.fingerprintSignalCategories).length, 0, 'a vm budget leaves Fingerprinting complete');
// The VM notice is one chip per class; each reason chip names its raw token
// and its one-line meaning from the glossary the models define.
assert.deepEqual(Array.from(api.captureGapClasses({namedGaps: api.namedGapsIn(api.shownNamedGaps(), api.vmGapCategories)}), entry => api.captureGapClassChip(entry).text),
  ['2 sampling budgets (vm)']);
assert.deepEqual({...chips.reason('native_wasm_dispatch_budget_incomplete')}, {label: 'Wasm br_table dispatch budget', kind: 'limit',
  meaning: 'This second\'s sampling window filled: retained samples are exact, later executions keep only a compact overflow identity (past its ring, a count), and the next second samples again.'});
const overflowBytes = Buffer.alloc(32);
overflowBytes.writeUInt16LE(1, 0);
overflowBytes.writeUInt16LE(32, 2);
overflowBytes[4] = 1;
overflowBytes.writeUInt32LE(9, 8);
overflowBytes.writeUInt32LE(47, 12);
overflowBytes.writeUInt32LE(1000, 16);
overflowBytes.writeUInt32LE(2, 20);
const overflowEvent = {...request(8, 'wasm_dispatch_overflow'), category: 'vm', payload_size: 32, payload: overflowBytes.toString('hex')};
assert.equal(api.isBrokerEvent(overflowEvent), true);
assert.equal(api.decodePayload(overflowEvent),
  'Wasm br_table overflow identity: function 9, byte 47, selector 1000, arms 2, ring 0. Not a full observation.');
overflowBytes.writeUInt16LE(31, 6);
assert.equal(api.isBrokerEvent({...overflowEvent, payload: overflowBytes.toString('hex')}), true);
assert.match(api.decodePayload({...overflowEvent, payload: overflowBytes.toString('hex')}), /ring 31/);
overflowBytes.writeUInt16LE(32, 6);
assert.equal(api.isBrokerEvent({...overflowEvent, payload: overflowBytes.toString('hex')}), false);
overflowBytes.writeUInt16LE(0, 6);
assert.equal(api.isBrokerEvent({...overflowEvent, artifact_id: '1'}), false);
assert.equal(api.isBrokerEvent({...overflowEvent, parent_event_id: '4'}), false);
overflowBytes[4] = 9;
assert.equal(api.isBrokerEvent({...overflowEvent, payload: overflowBytes.toString('hex')}), false);
assert.deepEqual({...chips.reason('native_js_dispatch_budget_incomplete')}, {label: 'JavaScript dispatch budget', kind: 'limit',
  meaning: 'The sampling budget filled: retained observations are exact and later ones were not sampled.'});
const controlledBudgets = [
  budgetGap(3, 'native_wasm_dispatch_function_budget_incomplete'),
  budgetGap(4, 'native_wasm_indirect_site_budget_incomplete'),
  budgetGap(5, 'native_wasm_dispatch_filtered')
];
{
  const classes = api.captureGapClasses({namedGaps: api.namedGapsFromEvents(controlledBudgets)});
  assert.deepEqual(Array.from(classes, entry => [entry.key, api.captureGapClassChip(entry).text]),
    [['budget:vm', '2 sampling budgets (vm)'], ['policy:vm', '1 policy exclusion (vm)']]);
  const chip = api.captureGapStatusChip(classes);
  assert.equal(chip.text, '3 gaps');
  assert.equal(chip.tone, 'limit', 'Budgets and policy exclusions alone are limits');
  assert.deepEqual(Array.from(chip.breakdown.rows, row => row.label), ['Sampling budgets · vm', 'Sample policy · vm']);
  assert.equal(chip.breakdown.note, '');
}
assert.deepEqual({...chips.reason('native_wasm_dispatch_filtered')}, {label: 'Wasm br_table excluded', kind: 'policy',
  meaning: 'The sample policy excluded these executions: none was sampled or took a sample slot.'});
// A capture from an earlier build names a browser per-function cap. It is
// still a sampling budget, but no overflow identity follows it.
assert.deepEqual({...chips.reason('native_wasm_dispatch_browser_function_budget_incomplete')}, {label: 'Wasm br_table per function (browser) budget',
  kind: 'limit', meaning: 'The sampling budget filled: retained observations are exact and later ones were not sampled.'});
console.log('PASS named vm sampling budgets are scoped capture limits, not queue drops or Traffic/Fingerprinting loss');

// Numeric gap payloads remain queue drops beside named markers in the same total.
api.acceptEventWindow({...liveResponse, queue_drops: '7', named_gaps: [...liveResponse.named_gaps,
  {category: 'vm', reason: 'native_wasm_dispatch_transport_unavailable', count: '2'}]});
assert.equal(api.shownQueueDrops(), 3n);
{
  const chip = statusChip();
  assert.equal(chip.text, '7 gaps');
  assert.equal(chip.tone, 'loss');
  assert.deepEqual(Array.from(chip.breakdown.rows, row => [row.label, row.count]),
    [['Queue drops', 3n], ['Reported lost · vm', 2n], ['Sampling budgets · vm', 2n]]);
  assert.equal(chip.breakdown.note, '', 'No sequence gap, so nothing overlaps');
  assert.deepEqual(Array.from(chip.breakdown.rows[1].reasons, entry => [entry.token, entry.count]), [['native_wasm_dispatch_transport_unavailable', 2n]]);
}
api.renderNetworkNotice();
assert.deepEqual([notice().lead, notice().chips], ['Incomplete capture', ['3 queue drops']]);
// Saturated totals stay lower bounds after the named weight is removed.
api.acceptEventWindow({...liveResponse, queue_drops: '18446744073709551615', queue_drops_saturated: true});
api.renderNetworkNotice();
assert.deepEqual(notice().chips, [`≥${n(18446744073709551613n)} queue drops`]);
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
assert.deepEqual([notice().lead, notice().chips], ['Incomplete capture', ['1 lost (network)']]);
{
  const lost = elements.networkNotice.querySelector('.ev-chip[data-key="lost:network"]');
  lost.click();
  const panel = document.getElementById(lost.getAttribute('aria-controls'));
  assert.match(panel.textContent, /native_network_example_unavailable/, 'The raw reason token stays readable');
  lost.click();
}
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
// Every pair is listed, however many producers name a reason.
const manyPairs = Array.from({length: 300}, (_, index) => ({category: 'vm', reason: `native_reason_${index}`, count: '1'}));
assert.equal(api.isBrokerResponse({...liveResponse, queue_drops: '300', named_gaps: manyPairs}), true);
api.acceptEventWindow({...liveResponse, queue_drops: '300', named_gaps: manyPairs});
assert.equal(api.shownNamedGaps().length, 300);
assert.equal(api.namedGapsFromEvents(manyPairs.map((pair, index) => ({...liveBudgets[0], sequence_number: String(index + 1),
  payload: Buffer.from(pair.reason).toString('hex'), payload_size: pair.reason.length}))).length, 300);
console.log('PASS named gap summaries are strict, unique, complete and covered by queue_drops');
