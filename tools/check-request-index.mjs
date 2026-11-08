// The backend request index (apps/origin-trace-backend/src/request_index.rs)
// must produce the rows, orders and search matches the shipped Traffic model
// produces from the same events. The Rust ignored test writes the golden.
import assert from 'node:assert/strict';
import fs from 'node:fs';

const root = new URL('../', import.meta.url);
const path = process.env.REB_REQUEST_INDEX_GOLDEN;
assert(path && fs.existsSync(path), 'set REB_REQUEST_INDEX_GOLDEN to the golden the Rust test writes');
const golden = JSON.parse(fs.readFileSync(path, 'utf8'));
const load = (file, names) => new Function(`${fs.readFileSync(new URL(file, root), 'utf8')}\nreturn {${names}};`)();
const {requestsFromEvents} = load('apps/research-ui/evidence_models.js', 'requestsFromEvents');
const view = load('apps/research-ui/traffic_view.js', 'trafficSortedRequests, trafficSearchRequests, trafficRequestDomain, trafficIndexRequest');

const model = requestsFromEvents(golden.events, 'live');
assert.equal(golden.rows.length, model.length, 'one index row per Traffic row');
assert(model.length >= 10, 'the fixture covers every row shape');
golden.rows.forEach((row, index) => {
  const expected = model[index], shown = view.trafficIndexRequest(row, 'live');
  for (const field of ['id', 'path', 'method', 'status', 'time', 'type', 'targetKind', 'hostOnly', 'failed', 'interrupted',
    'tabId', 'operation', 'targetMalformed']) {
    assert.deepEqual(shown[field], expected[field], `${expected.id} ${field}`);
  }
  for (const field of ['target', 'host', 'urlTruncated', 'targetLength']) {
    assert.deepEqual(shown[field], expected[field] ?? (field === 'urlTruncated' ? false : null), `${expected.id} ${field}`);
  }
  assert.equal(row.domain, view.trafficRequestDomain(expected), `${expected.id} domain`);
  const root = expected.events.find(event => event.type === 'request_started' && event.request_id !== '0') ??
    expected.events.find(event => event.type === 'request_initiated' && event.request_id !== '0') ??
    expected.events.find(event => event.request_id !== '0') ?? null;
  assert.deepEqual(row.root && [row.root.session_id, row.root.process_id, row.root.sequence_number],
    root && [root.session_id, root.process_id, root.sequence_number], `${expected.id} root event`);
});
for (const [sort, orders] of Object.entries(golden.orders)) {
  for (const [direction, sign] of [['asc', 1], ['desc', -1]]) {
    assert.deepEqual(orders[direction], view.trafficSortedRequests(model, sort, sign).map(request => request.id), `${sort} ${direction}`);
  }
}
for (const [needle, ids] of Object.entries(golden.searches)) {
  assert.deepEqual(ids, [...view.trafficSearchRequests(model, needle).matches.keys()], `search ${needle}`);
}
console.log(`PASS request index: ${model.length} rows, ${Object.keys(golden.orders).length} sorts and ${Object.keys(golden.searches).length} searches match the shipped Traffic model`);
