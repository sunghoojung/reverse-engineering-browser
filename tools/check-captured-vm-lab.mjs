import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const source = await readFile(new URL('../apps/research-ui/captured_vm_lab.js', import.meta.url), 'utf8');
const lab = new Function(`${source}\nreturn CapturedVmLab;`)();
assert(lab, 'Captured VM Lab must load without a browser document');

const page = {
  state: 'paused', generation: 4,
  target: {id: 'demo-page', type: 'page'},
  target_document_epoch: 3,
  network: {instance_id: 'instance-1', capture_epoch: 2},
  object_experiment: {isolated: false, target_id: null, navigation_id: 0, url: ''}
};
const owner = lab.owner(page);
assert.deepEqual(JSON.parse(JSON.stringify(owner)), {instance_id: 'instance-1', connection_epoch: 2, document_epoch: 3, target_id: 'demo-page'});
const missing = lab.listRequest(page, false);
assert.equal(missing.ok, false);
assert.match(missing.message, /confirmed/);
assert.match(missing.message, /captured_owner\.instance_id/);
const listed = lab.listRequest(page, true);
assert.equal(listed.ok, true);
assert.equal(listed.request.confirmed, true);
assert.deepEqual(JSON.parse(JSON.stringify(listed.request.captured_owner)), JSON.parse(JSON.stringify(owner)));
assert.equal(listed.request.action, 'list_live_wasm_objects');

const worker = {...page, target: {id: 'worker-1', type: 'worker'}};
assert.equal(lab.listRequest(worker, true).ok, false);
assert.match(lab.listRequest(worker, true).message, /refused|page/);

const labPage = {...page, state: 'running', object_experiment: {isolated: true, target_id: 'demo-page', navigation_id: 5, url: 'http://127.0.0.1/owned'}};
const disposable = lab.listRequest(labPage, false);
assert.equal(disposable.ok, true);
assert.equal(disposable.request.captured_owner, undefined);
assert.equal(disposable.request.confirmed, undefined);

const listing = {listing_id: 7, target_id: 'demo-page', owner_scope: 'captured_document', objects: [{id: 'memory:0', kind: 'memory'}]};
assert.match(lab.readRequest(page, {confirmed: false, listing, objectId: 'memory:0', offset: 0, length: 16}).message, /confirmed/);
assert.match(lab.readRequest(page, {confirmed: true, listing, objectId: 'memory:0', offset: 0, length: 0}).message, /4096/);
assert.match(lab.readRequest(page, {confirmed: true, listing, objectId: 'memory:0', offset: 0, length: 4097}).message, /4096/);
const slice = lab.readRequest(page, {confirmed: true, listing, objectId: 'memory:0', offset: 8, length: 4096});
assert.equal(slice.ok, true);
assert.equal(slice.request.length, 4096);
assert.deepEqual(JSON.parse(JSON.stringify(slice.request.captured_owner)), JSON.parse(JSON.stringify(owner)));
const labListing = {...listing, owner_scope: 'object_experiment'};
const labSlice = lab.readRequest(labPage, {confirmed: true, listing: labListing, objectId: 'instance:0', exportName: 'memory', offset: 0, length: 4});
assert.equal(labSlice.request.export_name, 'memory');
assert.equal(labSlice.request.captured_owner, undefined);

const imports = lab.importRequest(page, {scopeType: 'local', callFrameId: 'frame-1', scopeIndex: 0, bindingName: 'imports'});
assert.equal(imports.ok, true);
assert.equal(imports.request.action, 'inspect_paused_import_object');
assert.equal(imports.request.expected_generation, 4);
assert.deepEqual(JSON.parse(JSON.stringify(imports.request.owner)), JSON.parse(JSON.stringify(owner)));
assert.equal(lab.importRequest(page, {scopeType: 'global', callFrameId: 'frame-1', scopeIndex: 0, bindingName: 'imports'}).ok, false);
assert.match(lab.importRequest({...page, state: 'running'}, {scopeType: 'local', callFrameId: 'frame-1', scopeIndex: 0, bindingName: 'imports'}).message, /Pause/);
const rendered = lab.reportText({provenance: 'selected-paused-own-properties', invocation: 'unproven', guest_position: null, modules: [{module_name: 'env', state: 'inspected', imports: [{import_name: 'clock', state: 'function', host_function_name: 'ownedClock', guest_position: null, host_location: null}]}], omissions: ['property-limit']});
assert.match(rendered, /invocation unproven/);
assert.match(rendered, /guest_position null/);
assert.match(rendered, /env/);
assert.match(rendered, /property-limit/);
assert.doesNotMatch(rendered, /guest_position \d/);

const html = await readFile(new URL('../apps/research-ui/index.html', import.meta.url), 'utf8');
assert.match(html, /id="debugger-vm-lab"/);
assert.match(html, /id="vm-captured-lab"/);
assert.match(html, /captured_vm_lab\.js/);
const packaged = await readFile(new URL('../scripts/build-research-app.sh', import.meta.url), 'utf8');
assert.match(packaged, /captured_vm_lab\.js/);
const native = await readFile(new URL('../apps/research-ui/macos/OriginTraceApp.swift', import.meta.url), 'utf8');
assert.match(native, /\/captured_vm_lab\.js/);
const app = await readFile(new URL('../apps/research-ui/app.js', import.meta.url), 'utf8');
assert.match(app, /CapturedVmLab\.mount/);
assert.match(app, /Map imports/);
console.log('PASS captured VM Lab request builders, import-map honesty, and debugger/VM mount points');
