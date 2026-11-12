// The backend request index (apps/origin-trace-backend/src/request_index.rs)
// must produce the rows, orders and search matches the shipped Traffic model
// produces from the same events. The Rust ignored test writes the golden.
import assert from 'node:assert/strict';
import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const path = process.env.REB_REQUEST_INDEX_GOLDEN;
assert(path && fs.existsSync(path), 'set REB_REQUEST_INDEX_GOLDEN to the golden the Rust test writes');
const golden = JSON.parse(fs.readFileSync(path, 'utf8'));
const load = (files, names) => new Function(`${files.map(file => fs.readFileSync(new URL(file, root), 'utf8')).join('\n')}\nreturn {${names}};`)();
const {requestsFromEvents} = load(['apps/research-ui/evidence_models.js'], 'requestsFromEvents');
const view = load(['apps/research-ui/request_stack.js', 'apps/research-ui/traffic_view.js', 'apps/research-ui/traffic_filter.js',
  'apps/research-ui/traffic_response.js'], `trafficSortedRequests, trafficSearchRequests,
  trafficRequestDomain, trafficIndexRequest, trafficParseFilter, trafficApplyFilter, trafficBrowserInternal, trafficSizeCell, trafficWaterfall,
  trafficInitiatorFrame, trafficStatusCell, responseBodyCase`);

const model = requestsFromEvents(golden.events, 'live');
// Tabs and the unresolved reason come from tab sets and links, as Traffic attaches them.
const {RebRequestTabs} = load(['apps/research-ui/request_tabs.js'], 'RebRequestTabs');
RebRequestTabs.attachRequestTabs(model, golden.events);
assert.equal(golden.rows.length, model.length, 'one index row per Traffic row');
assert(model.length >= 10, 'the fixture covers every row shape');
golden.rows.forEach((row, index) => {
  const expected = model[index], shown = view.trafficIndexRequest(row, 'live');
  for (const field of ['id', 'path', 'method', 'status', 'time', 'type', 'targetKind', 'hostOnly', 'failed', 'interrupted',
    'tabId', 'operation', 'targetMalformed', 'transferSize', 'resourceSize', 'fromCache', 'fromServiceWorker', 'memoryCache',
    'staticData', 'raceNetwork', 'endLost', 'mimeType', 'protocol', 'responseTimestamp', 'errorCode', 'loaderObserved', 'initiator', 'mainFrame',
    'tabReason', 'memoryCacheSource']) {
    assert.deepEqual(shown[field], expected[field], `${expected.id} ${field}`);
  }
  // Why the body is or is not retained, decided from the row's own records.
  assert.equal(row.response_body.case, view.responseBodyCase(expected), `${expected.id} body case`);
  assert.equal(view.responseBodyCase(shown), row.response_body.case, `${expected.id} index row carries its case`);
  if (expected.responseBody && !expected.responseBody.malformed) {
    assert.equal(row.response_body.artifact_id, expected.responseBody.artifactId === '0' ? null : expected.responseBody.artifactId,
      `${expected.id} body artifact`);
    assert.equal(row.response_body.record_sequence, expected.responseBody.sequenceNumber, `${expected.id} newest body record`);
  }
  // A newest record without bytes names the snapshot of the same response still retained.
  assert.equal(row.response_body.earlier_snapshot?.artifact_id ?? null, expected.responseBodyEarlier?.artifactId ?? null,
    `${expected.id} earlier snapshot`);
  for (const field of ['target', 'host', 'urlTruncated', 'targetLength']) {
    assert.deepEqual(shown[field], expected[field] ?? (field === 'urlTruncated' ? false : null), `${expected.id} ${field}`);
  }
  assert.equal(row.domain, view.trafficRequestDomain(expected), `${expected.id} domain`);
  assert.equal(row.browser_internal, view.trafficBrowserInternal(expected), `${expected.id} browser-internal`);
  const root = expected.events.find(event => event.type === 'request_started' && event.request_id !== '0') ??
    expected.events.find(event => event.type === 'request_initiated' && event.request_id !== '0') ??
    expected.events.find(event => event.request_id !== '0') ?? null;
  assert.deepEqual(row.root && [row.root.session_id, row.root.process_id, row.root.sequence_number],
    root && [root.session_id, root.process_id, root.sequence_number], `${expected.id} root event`);
});
// A service worker's end that lost its start reads as such, never Pending; a
// race network row shows what the page received.
const shownRows = golden.rows.map(row => view.trafficIndexRequest(row, 'live'));
const lost = shownRows.find(row => row.endLost);
assert(lost && lost.status === 'incomplete' && view.trafficStatusCell(lost).text === 'End lost');
const raced = shownRows.find(row => row.raceNetwork);
assert(raced && raced.status === 'failed' && raced.fromServiceWorker && view.trafficStatusCell(raced).text === 'Failed');
assert.equal(shownRows.filter(row => row.endLost || row.raceNetwork).length, 2);
// An MHTML archive reuse has no HTTP status, yet it finished: never No loader.
const archive = shownRows.find(row => row.memoryCache && row.status === 'finished');
const archiveCell = archive && view.trafficStatusCell(archive);
assert(archiveCell && archiveCell.text === 'Finished' && archiveCell.title.startsWith('No HTTP status: archive resource') &&
  archive.time !== 'pending', 'an archive reuse reads Finished with no HTTP status');
// Every body case the fixture holds, and a reuse naming the request whose
// response it reused, which the index answers with that request's body.
const cases = new Set(golden.rows.map(row => row.response_body.case));
for (const kind of ['captured', 'not_modified', 'malformed', 'redirected', 'cancelled_before_response', 'service_worker',
  'memory_cache', 'failed_before_response', 'renderer_answered', 'pending', 'end_lost', 'no_record', 'partial',
  'captured_truncated', 'aborted', 'cancelled', 'empty', 'no_response', 'not_captured_session_budget']) {
  assert(cases.has(kind), `the fixture has a ${kind} row`);
}
const named = golden.rows.find(row => row.memory_cache_source);
assert(named && named.memory_cache_source.found && named.memory_cache_source.response_body.case === 'captured' &&
  named.memory_cache_source.response_body.artifact_id === '78' && named.memory_cache_source.response_body.partial_index === 0,
'a reuse names its source row and that row\'s ended body, not its snapshot');
assert.equal(golden.rows.find(row => row.id === named.memory_cache_source.id)?.response_body.case, 'captured');
// A redirect that then fails, is cancelled or stays open reads as that, in both models.
const byId = new Map(golden.rows.map(row => [row.id, row.response_body.case]));
for (const [id, kind] of [['S1:R62:9', 'failed_before_response'], ['S1:R62:10', 'cancelled_before_response'],
  ['S1:R62:11', 'pending'], ['S1:R62:8', 'not_modified'], ['S1:R61:25', 'redirected']]) {
  assert.equal(byId.get(id), kind, `${id} after a redirect`);
}
assert(golden.rows.some(row => row.response_body.earlier_snapshot?.artifact_id === '85'), 'a refused end keeps its snapshot');
for (const [sort, orders] of Object.entries(golden.orders)) {
  for (const [direction, sign] of [['asc', 1], ['desc', -1]]) {
    assert.deepEqual(orders[direction], view.trafficSortedRequests(model, sort, sign).map(request => request.id), `${sort} ${direction}`);
  }
}
for (const [needle, ids] of Object.entries(golden.searches)) {
  assert.deepEqual(ids, [...view.trafficSearchRequests(model, needle).matches.keys()], `search ${needle}`);
}
for (const [raw, expected] of Object.entries(golden.filters)) {
  const query = new URLSearchParams(raw), filter = view.trafficParseFilter(query.get('q') ?? '');
  const flags = {failed: query.has('failed'), invert: query.has('invert'), hideInternal: query.has('hide_internal'), thirdParty: query.has('third_party')};
  const range = query.has('from_ns') || query.has('to_ns')
    ? {from: BigInt(query.get('from_ns') ?? 0), to: BigInt(query.get('to_ns') ?? '18446744073709551615')} : null;
  const result = view.trafficApplyFilter(model, view.trafficSearchRequests(model, filter.text).matches, filter, {flags, range});
  assert.deepEqual([...result.matches.keys()], expected.ids, `filter ${raw}`);
  assert.deepEqual(result.sizes, expected.sizes, `filter ${raw} sizes`);
  assert.equal(result.hiddenInternal, expected.hidden_internal, `filter ${raw} hidden`);
  assert.deepEqual([result.timeline.first?.toString() ?? null, result.timeline.last?.toString() ?? null, result.timeline.buckets],
    [expected.timeline.first_time_ns, expected.timeline.last_time_ns, expected.timeline.buckets], `filter ${raw} timeline`);
}
// Size and the waterfall come from the recorded lengths and timestamps.
const timeline = golden.filters['hide_internal=1'].timeline;
const scale = {start: BigInt(timeline.first_time_ns), end: BigInt(timeline.last_time_ns)};
let measured = 0;
golden.rows.forEach(row => {
  const shown = view.trafficIndexRequest(row, 'live'), records = golden.events.filter(event => model.find(request => request.id === row.id).events.includes(event));
  const terminal = records.filter(event => ['request_completed', 'request_failed', 'response_completed'].includes(event.type)).at(-1);
  if (terminal && BigInt(terminal.encoded_data_length) >= 0n && !shown.fromCache && !shown.fromServiceWorker) {
    assert.match(view.trafficSizeCell(shown).title, new RegExp(`Transferred: ${Number(terminal.encoded_data_length).toLocaleString('en-US')} byte`), `${row.id} transferred`);
    assert.match(view.trafficSizeCell(shown).title, new RegExp(`Resource: ${Number(terminal.decoded_body_length).toLocaleString('en-US')} byte`), `${row.id} resource`);
    measured += 1;
  }
  const times = records.map(event => BigInt(event.monotonic_time_ns)), span = Number(scale.end - scale.start);
  const first = times.reduce((a, b) => a < b ? a : b), last = times.reduce((a, b) => a > b ? a : b);
  const response = records.find(event => event.type === 'response_started');
  const bar = view.trafficWaterfall(shown, scale);
  const percent = value => Number(value - scale.start) * 100 / span;
  assert(Math.abs(bar.left - percent(first)) < 1e-9, `${row.id} waterfall start`);
  if (shown.time !== 'pending') assert(Math.abs(bar.left + bar.width - percent(last)) < 1e-9, `${row.id} waterfall end`);
  if (response) assert(Math.abs(bar.left + bar.wait - percent(BigInt(response.monotonic_time_ns))) < 1e-9, `${row.id} response start`);
});
assert(measured >= 3, 'the fixture records completion lengths');
// The index resolves a script start's innermost frame; the column names it file:line.
const scripted = view.trafficIndexRequest({...golden.rows[0], initiator: 'script', initiator_frame: {status: 'resolved', artifact_id: '21',
  url: 'https://app.test/static/a.js?v=2', line: 3, column: 7, function_name: 'load'}}, 'live');
assert.deepEqual(view.trafficInitiatorFrame(scripted), {label: 'a.js:3', title: 'https://app.test/static/a.js?v=2:3:7 in load. The Initiator tab shows the call stack.'});
assert.equal(view.trafficInitiatorFrame({...scripted, initiatorFrame: {status: 'unresolved', reason: 'source_not_retained'}}), null);
console.log(`PASS request index: ${model.length} rows, ${Object.keys(golden.orders).length} sorts, ${Object.keys(golden.searches).length} searches and ${Object.keys(golden.filters).length} filters match the shipped Traffic model; Size and waterfall follow the recorded lengths and timestamps; a resolved initiator frame reads file:line`);
