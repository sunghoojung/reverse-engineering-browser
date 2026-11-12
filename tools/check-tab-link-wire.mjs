// The C++ core verdict on loader kinds, tab_set and request_tab_link records
// (tests/tab_link_test.cpp --golden) must match the Python evidence validator
// and the shipped readers. Then the shipped Traffic model places worker rows in
// every linked tab, names tabs by their page and reports unlinked rows.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import {createRequire} from 'node:module';

const root = new URL('../', import.meta.url);
const exe = process.env.REB_TAB_LINK_TEST ?? new URL('build/tests/tab-link-test', root).pathname;
assert(fs.existsSync(exe), `missing ${exe}; build it with make build/tests/tab-link-test`);
const source = fs.readFileSync(new URL('apps/research-ui/evidence_models.js', root), 'utf8');
const model = new Function(`${source}\nreturn {requestsFromEvents, isBrokerEvent, isBrokerResponse};`)();
const tabs = createRequire(import.meta.url)('../apps/research-ui/request_tabs.js');

const cases = JSON.parse(execFileSync(exe, ['--golden'], {encoding: 'utf8'}));
assert(cases.length > 40 && cases.some(item => item.valid) && cases.some(item => !item.valid));
const python = `import importlib.util,json,sys
s=importlib.util.spec_from_file_location('validator',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for event in json.load(sys.stdin):
  try: m.validate_event(event,1);print('true')
  except ValueError: print('false')`;
const verdicts = execFileSync('python3', ['-c', python, new URL('tools/validate-evidence-store.py', root).pathname],
  {input: JSON.stringify(cases.map(item => item.event)), encoding: 'utf8'}).trim().split('\n').map(value => value === 'true');
cases.forEach((item, index) => {
  assert.equal(verdicts[index], item.valid, `Python validator: ${item.name}`);
  if (item.event.type === 'tab_set') {
    assert.equal(tabs.decodeTabSet(item.event) !== null, item.valid, `UI tab set: ${item.name}`);
  } else if (item.event.type === 'request_tab_link') {
    assert.equal(tabs.decodeTabLink(item.event) !== null, item.valid, `UI link: ${item.name}`);
  } else if (item.event.type === 'request_extension_link') {
    assert.equal(tabs.decodeExtensionLink(item.event) !== null, item.valid, `UI extension link: ${item.name}`);
  } else {
    assert.equal(model.isBrokerEvent(item.event), item.valid, `UI envelope: ${item.name}`);
  }
  if (item.valid) assert(model.isBrokerEvent(item.event), `UI accepts ${item.name}`);
});

const golden = name => structuredClone(cases.find(item => item.name === name).event);
const hex = text => Buffer.from(text).toString('hex');
const record = (fields, payload = 'GET example.test') => Object.assign(golden('renderer loader kind 16'), {
  process_id: 31, request_id: '5', sequence_number: '31', payload: hex(payload), payload_size: payload.length}, fields);
const withTabs = (event, list, total = list.length, part = 0) => {
  const bytes = Buffer.from(event.payload, 'hex');
  bytes.fill(0, 24);
  bytes.writeUInt32LE(total, 16);
  bytes.writeUInt16LE(list.length, 20);
  bytes.writeUInt16LE(part, 6);
  list.forEach((tab, index) => bytes.writeUInt32LE(tab, 24 + 4 * index));
  return Object.assign(event, {payload: bytes.toString('hex'), tab_id: list[0]});
};
const linkTo = (event, count, kind, initiator) => {
  const bytes = Buffer.from(event.payload, 'hex');
  bytes.writeUInt32LE(count, 16);
  bytes[4] = kind;
  return Object.assign(event, {payload: bytes.toString('hex'), tab_id: count === 1 ? event.tab_id || 4 : 0}, initiator);
};

// A shared worker request: the renderer start, the browser start joined to it,
// the worker's set and the link. The row is in both tabs and counted once.
const start = record({loader_kind: 18, frame_id: '2748'});
const browser = Object.assign(golden('browser loader kind 5'), {process_id: 2, request_id: '900', sequence_number: '7',
  initiator_process_id: 31, initiator_request_id: 5, browser_context_id_high: '3', browser_context_id_low: '4'});
const set = withTabs(golden('one-part set'), [4, 9]);
const link = linkTo(golden('link to two tabs'), 2, 2, {initiator_process_id: 31, initiator_request_id: 5});
assert(tabs.decodeTabSet(set) && tabs.decodeTabLink(link));
let rows = model.requestsFromEvents([start, browser, set, link], 'live');
assert.equal(rows.length, 1);
tabs.attachRequestTabs(rows, [start, browser, set, link]);
assert.deepEqual(rows[0].tabIds, ['4', '9']);
assert.equal(rows[0].tabLinkLabel, 'Shared worker · 2 tabs');
assert(!tabs.isUnresolved(rows[0]));

// The backend's network window carries sets and links beside lifecycle records.
const window = [start, browser, set, link];
assert(model.isBrokerResponse({events: window, count: window.length, network_events: window}));

// A set missing a part keeps what arrived and is marked incomplete.
const thirty = Array.from({length: 30}, (_, index) => 100 + index);
const firstPart = withTabs(golden('first of two parts'), thirty.slice(0, 26), 30);
const serviceLink = linkTo(golden('link to two tabs'), 30, 3, {initiator_process_id: 31, initiator_request_id: 6});
const serviceStart = record({loader_kind: 19, request_id: '6', sequence_number: '32'});
rows = tabs.attachRequestTabs(model.requestsFromEvents([serviceStart], 'live'), [serviceStart, firstPart, serviceLink]);
assert.equal(rows[0].tabIds.length, 26);
assert(!rows[0].tabLink.complete && rows[0].tabLinkLabel === 'Service worker · 30 tabs');
const secondPart = withTabs(golden('second of two parts'), thirty.slice(26), 30, 1);
rows = tabs.attachRequestTabs(model.requestsFromEvents([serviceStart], 'live'), [serviceStart, firstPart, secondPart, serviceLink]);
assert(rows[0].tabIds.length === 30 && rows[0].tabLink.complete);

// No tab and no link is a capture error that stays listed.
const orphan = Object.assign(golden('browser loader kind 6'), {process_id: 2, request_id: '901', sequence_number: '8',
  browser_context_id_high: '3', browser_context_id_low: '4'});
rows = tabs.attachRequestTabs(model.requestsFromEvents([orphan], 'live'), [orphan]);
assert(rows.length === 1 && tabs.isUnresolved(rows[0]) && rows[0].tabIds.length === 0);
assert.equal(tabs.unresolvedNotice(1), '1 request without a tab (capture error)');
assert.equal(tabs.unresolvedNotice(0), '');

// A service-worker update check: the browser record and its browser-record link.
const update = Object.assign(golden('browser loader kind 6'), {process_id: 7, request_id: '900', sequence_number: '32',
  browser_context_id_high: '11', browser_context_id_low: '12'});
const updateSet = withTabs(golden('one-part set'), [4, 9]);
const updateLink = golden('browser record link to two tabs');
rows = tabs.attachRequestTabs(model.requestsFromEvents([update], 'live'), [update, updateSet, updateLink]);
assert.deepEqual(rows[0].tabIds, ['4', '9']);
assert(!tabs.isUnresolved(rows[0]) && rows[0].tabLinkLabel === 'Service worker · 2 tabs');

// A version's install-time fetch links to the tab whose register() installed it.
const installStart = record({loader_kind: 19, request_id: '18', sequence_number: '33'});
const registrant = golden('registrant link');
Object.assign(registrant, {initiator_process_id: 31, initiator_request_id: 18});
rows = tabs.attachRequestTabs(model.requestsFromEvents([installStart], 'live'),
  [installStart, withTabs(golden('one-part set'), [4, 9]), registrant]);
assert.deepEqual(rows[0].tabIds, ['4', '9']);
assert(!tabs.isUnresolved(rows[0]) && rows[0].tabLinkLabel === 'Service worker · installed from 2 tabs');
assert.equal(tabs.linkLabel({kind: 5, count: 1}), 'Service worker · installed from 1 tab');

// A worklet's record names its creating document and carries that tab like one.
const worklet = record({loader_kind: 22, request_id: '19', sequence_number: '34', frame_id: '77', tab_id: 4});
assert(model.isBrokerEvent(worklet));
rows = tabs.attachRequestTabs(model.requestsFromEvents([worklet], 'live'), [worklet]);
assert(!tabs.isUnresolved(rows[0]) && rows[0].tabIds[0] === '4');

// Extension traffic recorded by opt-in sits under its extension, never under no tab.
const extensionScript = Object.assign(golden('browser loader kind 6'), {process_id: 7, request_id: '900',
  sequence_number: '32', browser_context_id_high: '11', browser_context_id_low: '12'});
const extensionLink = golden('extension service-worker script');
rows = tabs.attachRequestTabs(model.requestsFromEvents([extensionScript], 'live'), [extensionScript, extensionLink]);
assert.equal(rows[0].extensionId, 'abcdefghijklmnopabcdefghijklmnop');
assert.deepEqual(tabs.rowTabs(rows[0]), ['extension:abcdefghijklmnopabcdefghijklmnop']);
assert(!tabs.isUnresolved(rows[0]));
assert.equal(tabs.scopeLabel('extension:abcdefghijklmnopabcdefghijklmnop'), 'Extension abcdefgh…');
assert.equal(tabs.scopeLabel('4'), null);
const workerStart = record({loader_kind: 19, request_id: '17', process_id: 4242, sequence_number: '31'});
rows = tabs.attachRequestTabs(model.requestsFromEvents([workerStart], 'live'),
  [workerStart, golden('extension service-worker request')]);
assert.equal(rows[0].extensionId, 'abcdefghijklmnopabcdefghijklmnop');

// A tab is named by its newest main-frame navigation, not its first request.
const navigation = (sequence, time, host) => Object.assign(golden('browser loader kind 1'), {process_id: 2,
  request_id: String(sequence), sequence_number: String(sequence), monotonic_time_ns: String(time), tab_id: 4,
  resource_type: 0, payload: hex(`GET ${host}`), payload_size: 4 + host.length,
  browser_context_id_high: '3', browser_context_id_low: '4'});
const page = [navigation(20, 5000, 'newtab'), navigation(21, 9000, 'example.test'), navigation(22, 7000, 'older.test')];
rows = tabs.attachRequestTabs(model.requestsFromEvents(page, 'live'), page);
const domain = row => String(row.path).split('/')[0];
assert.equal(tabs.tabPageLabel(rows, domain), 'example.test');

console.log(`PASS tab link wire: ${cases.length} C++ golden records agree with Python and the UI readers; ` +
  'worker rows appear in every linked tab once, incomplete sets say so, browser records, registrants, worklets and ' +
  'extension traffic link, ' +
  'unlinked rows are errors and tabs are named by their page');
