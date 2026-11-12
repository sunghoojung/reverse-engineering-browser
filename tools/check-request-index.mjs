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
const view = load(['apps/research-ui/request_stack.js', 'apps/research-ui/traffic_view.js', 'apps/research-ui/traffic_filter.js'], `trafficSortedRequests, trafficSearchRequests,
  trafficRequestDomain, trafficIndexRequest, trafficParseFilter, trafficApplyFilter, trafficBrowserInternal, trafficSizeCell, trafficWaterfall,
  trafficInitiatorFrame, trafficStatusCell`);

const model = requestsFromEvents(golden.events, 'live');
assert.equal(golden.rows.length, model.length, 'one index row per Traffic row');
assert(model.length >= 10, 'the fixture covers every row shape');
golden.rows.forEach((row, index) => {
  const expected = model[index], shown = view.trafficIndexRequest(row, 'live');
  for (const field of ['id', 'path', 'method', 'status', 'time', 'type', 'targetKind', 'hostOnly', 'failed', 'interrupted',
    'tabId', 'operation', 'targetMalformed', 'transferSize', 'resourceSize', 'fromCache', 'fromServiceWorker', 'memoryCache',
    'staticData', 'raceNetwork', 'endLost', 'mimeType', 'protocol', 'responseTimestamp', 'errorCode', 'loaderObserved', 'initiator', 'mainFrame']) {
    assert.deepEqual(shown[field], expected[field], `${expected.id} ${field}`);
  }
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
