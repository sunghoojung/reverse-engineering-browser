import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import packs from '../apps/research-ui/vm_analysis_packs.js';
const root = new URL('../', import.meta.url);
const fixture = name => readFile(new URL(`tools/fixtures/vm-analysis-packs/${name}`, root), 'utf8');
const inputs = {pack: await fixture('pack.json'), left: await fixture('build-a.workspace.json'), right: await fixture('build-b.workspace.json')};
const body = packs.vmPackRequestText('compare', inputs, '1', '1');
assert.equal(JSON.parse(body).left_artifact, '1');
assert(body.includes(inputs.left), 'Exact source text is retained, not reserialized');
const largeId = '18446744073709551615';
assert.equal(JSON.parse(packs.vmPackRequestText('compare', inputs, largeId, '1')).left_artifact, largeId);
for (const id of ['', '01', '-1', '1.0', '18446744073709551616', '<script>']) assert.throws(() => packs.vmPackRequestText('compare', inputs, id, '1'));
for (const mode of ['execute', '', null]) assert.throws(() => packs.vmPackRequestText(mode, inputs, '1', '1'));
assert.throws(() => packs.vmPackRequestText('compare', {...inputs, pack: '{' + ' '.repeat(65536)}, '1', '1'));
assert.throws(() => packs.vmPackRequestText('apply', {...inputs, analysis: null}));
const unrounded = '{"artifact_id":18446744073709551615}';
assert(packs.vmPackRequestText('apply', {...inputs, analysis: unrounded}).includes(unrounded));
assert.throws(() => packs.vmPackRequestText('compare', {...inputs, left: '{' + ' '.repeat(8388608), right: '{' + ' '.repeat(8388608)}, '1', '1'));
const spec = JSON.parse(await readFile(new URL('protocol/openapi.json', root), 'utf8'));
for (const mode of ['apply', 'compare']) {
  const route = spec.paths[`/api/analysis/vm/packs/${mode}`].post;
  assert.equal(route.operationId, `vm_pack_${mode}`);
  assert.equal(route['x-max-body-bytes'], 16777216);
  assert.deepEqual(route['x-reb-execution'].effects, ['analysis']);
  assert.equal(route.requestBody.content['application/json'].schema.additionalProperties, false);
}
console.log('VM pack request text, bounds, exact integer preservation and agent discovery passed.');

// Exercise the mounted controller with the shipped bounded response reader.
const {runInNewContext} = await import('node:vm');
const source = await readFile(new URL('apps/research-ui/vm_analysis_packs.js', root), 'utf8');
const readerSource = await readFile(new URL('apps/research-ui/evidence_package.js', root), 'utf8');
function harness({native = false, fetcher, clipboard} = {}) {
  class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.attributes = {}; this.value = ''; this.files = []; this.text = ''; }
    set textContent(value) { this.text = String(value); this.children = []; }
    get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
    append(...items) { this.children.push(...items); }
    setAttribute(key, value) { this.attributes[key] = String(value); }
    addEventListener(key, callback) { this.events[key] = callback; }
    click() { return this.events.click?.(); }
  }
  const document = {createElement: tag => new Element(tag), documentElement: {classList: {contains: () => native}}};
  const api = runInNewContext(readerSource + '\n' + source + ';({mountVmAnalysisPacks})', {
    document, location: {protocol: 'http:'}, navigator: {clipboard}, TextEncoder, TextDecoder, Uint8Array, BigInt,
    AbortController, setTimeout, clearTimeout, fetch: fetcher, Blob, URL
  });
  const root = new Element('section'), ui = api.mountVmAnalysisPacks(root);
  const all = element => [element, ...element.children.flatMap(all)];
  const button = label => all(root).find(element => element.tagName === 'button' && element.textContent === label);
  const files = all(root).filter(element => element.type === 'file');
  const status = all(root).find(element => element.attributes.role === 'status');
  const load = async (index, text = '{}', arrayBuffer) => {
    const bytes = new TextEncoder().encode(text);
    files[index].files = [{name: 'owned.json', size: bytes.length, arrayBuffer: arrayBuffer || (async () => bytes.buffer)}];
    await files[index].events.change();
  };
  return {root, ui, button, files, status, load};
}
const report = {contract_version: 1, document_kind: 'vm-pack-application', document_digest: 'a'.repeat(64), rankings: []};
const response = (value = report, status = 200) => new Response(JSON.stringify(value), {status});
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; };
let calls = 0, next = response(), copied = null;
const ui = harness({native: true, fetcher: async () => { calls++; return next; }, clipboard: {writeText: async value => { copied = value; }}});
await ui.load(0); await ui.load(1); assert.equal(calls, 0, 'Imports never run analysis');
await ui.ui.run('apply'); assert.equal(calls, 1); assert.match(ui.status.textContent, /ready/);
await ui.button('Copy complete report JSON').click(); assert.equal(copied, JSON.stringify(report));
const held = deferred(); next = held.promise;
const pending = ui.ui.run('apply'); await Promise.resolve();
await ui.ui.run('apply'); assert.equal(calls, 2, 'Repeated run while pending is not sent');
ui.button('Cancel').click(); held.resolve(response()); await pending;
assert.match(ui.status.textContent, /Cancelled/); assert(ui.button('Copy complete report JSON').disabled);
const old = deferred(); next = old.promise; const obsolete = ui.ui.run('apply'); await Promise.resolve();
await ui.load(0, '{"version":2}'); next = response(); await ui.ui.run('apply'); old.resolve(response({...report, document_digest: 'b'.repeat(64)})); await obsolete;
assert.match(ui.root.textContent, new RegExp('a'.repeat(64))); assert(!ui.root.textContent.includes('b'.repeat(64)));
next = response({}); await ui.ui.run('apply'); assert.match(ui.status.textContent, /Malformed pack report/);
next = response({error: {unsafe: 'object'}}, 400); await ui.ui.run('apply'); assert.match(ui.status.textContent, /backend refused/); assert(!ui.status.textContent.includes('[object Object]'));
const readHeld = deferred(); const reading = ui.load(0, '{}', () => readHeld.promise);
ui.button('Clear').click(); readHeld.resolve(new TextEncoder().encode('{}').buffer); await reading;
await ui.ui.run('apply'); assert.match(ui.status.textContent, /Select a bounded pack/);
const heldRead = new ReadableStream({start(controller) { controller.enqueue(new TextEncoder().encode('{')); }});
await ui.load(0); await ui.load(1); next = new Response(heldRead);
const streaming = ui.ui.run('apply'); await new Promise(resolve => setTimeout(resolve, 5)); ui.button('Clear').click(); await streaming;
assert.match(ui.status.textContent, /cleared/); assert(ui.button('Copy complete report JSON').disabled);
const missingClipboard = harness({native: true, fetcher: async () => response()}); await missingClipboard.load(0); await missingClipboard.load(1); await missingClipboard.ui.run('apply'); await missingClipboard.button('Copy complete report JSON').click(); assert.match(missingClipboard.status.textContent, /Clipboard unavailable/);
console.log('Mounted VM pack import, cancellation, stale-response, malformed-response and native-copy checks passed.');

let bomBody;
const bomUi = harness({fetcher: async (_url, options) => { bomBody = options.body; return response(); }});
await bomUi.load(0, '\ufeff{}'); await bomUi.load(1); await bomUi.ui.run('apply');
assert(bomBody.includes('\ufeff{}'), 'File import preserves BOM for the exact strict backend parser to reject');
await ui.load(0); await ui.load(1);
next = response({...report, rankings: {length: 0}}); await ui.ui.run('apply');
assert.match(ui.status.textContent, /Malformed pack report/);

// Presentation remains structured; raw documents and comparison inputs are secondary.
const all = element => [element, ...element.children.flatMap(all)];
const elements = all(ui.root);
assert(elements.some(element => element.tagName === 'details' && element.attributes['data-pack-inputs'] === 'compare' && !element.open));
assert(elements.some(element => element.tagName === 'details' && element.children[0]?.textContent === 'Inspect raw report JSON' && !element.open));
next = response({...report, rankings: [{artifact_id: Number.MAX_SAFE_INTEGER + 1, anti_bot_score: 40, generic_anti_bot_score: 20, labels: ['<script>inert</script>']}]});
await ui.ui.run('apply');
assert(all(ui.root).some(element => element.tagName === 'table' && element.className === 'vm-tool-table'));
assert.match(ui.root.textContent, /See exact JSON/, 'Unsafe numeric IDs are never displayed as rounded identities');
assert.match(ui.root.textContent, /<script>inert<\/script>/);
assert(!all(ui.root).some(element => element.tagName === 'script'));
const comparison = {...report, document_kind: 'vm-instruction-set-comparison', behavioral_equivalence_proven: false,
  rows: Array.from({length: 130}, (_, index) => ({status: 'moved', match_basis: 'unique-exact-effect-shape', left: {opcode: index}, right: {opcode: index + 1}}))};
next = response(comparison); await ui.load(2); await ui.load(3);
for (const input of all(ui.root).filter(element => element.type === 'text')) input.value = '1';
await ui.ui.run('compare');
assert.match(ui.root.textContent, /130 rows · first 128 shown/);
assert.equal(all(ui.root).filter(element => element.tagName === 'tbody')[0].children.length, 128);
assert.match(ui.root.textContent, /130 moved/);
await ui.button('Copy complete report JSON').click(); assert.equal(JSON.parse(copied).rows.length, 130, 'Structured preview bounds do not truncate exact export');

assert(ui.button('Compare builds').className.includes('vm-tool-primary'));
assert(!ui.button('Apply ranking pack').className.includes('vm-tool-primary'));
const applyDisclosure = all(ui.root).find(element => element.attributes['data-pack-inputs'] === 'apply');
applyDisclosure.open = true; applyDisclosure.events.toggle();
assert(ui.button('Apply ranking pack').className.includes('vm-tool-primary'));
assert(!ui.button('Compare builds').className.includes('vm-tool-primary'));
for (const title of ['Cancel', 'Clear']) assert(ui.button(title).className.includes('vm-tool-tertiary'));
