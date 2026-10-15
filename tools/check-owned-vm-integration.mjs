import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const read = path => readFile(new URL('../' + path, import.meta.url), 'utf8');
const [html, css, mount, controller, backend, swift, packaging, make, specText, manifest] = await Promise.all([
  'apps/research-ui/index.html', 'apps/research-ui/app.css', 'apps/research-ui/vm_semantics.js',
  'apps/research-ui/vm_debugger.js', 'apps/origin-trace-backend/src/app.rs',
  'apps/research-ui/macos/OriginTraceApp.swift', 'scripts/build-research-app.sh',
  'mk/quality.mk', 'protocol/openapi.json', 'protocol/owned-vm-programs-v1.json'
].map(read));
assert(html.includes('id="nav-vm-workspace"') && html.includes('id="vm-show-owned"'));
assert(html.indexOf('src="vm_debugger.js"') < html.indexOf('src="vm_semantics.js"'));
assert(mount.includes('controls.append(owned.toolbar)'));
assert(mount.includes('controls.contains(document.activeElement)'));
assert(controller.includes("'aria-pressed', String(selection === record.sequence)"));
assert(css.includes('.owned-vm-debugger-history [aria-pressed="true"]'));
assert(!css.includes('.owned-vm-debugger-history [aria-current="true"]'));
const assets = backend.match(/const UI_ASSETS: \[&str; (\d+)\] = \[([\s\S]*?)\];/);
assert(assets); assert.equal(Number(assets[1]), [...assets[2].matchAll(/"[^"]+"/g)].length);
for (const source of [assets[2], swift, packaging]) assert(source.includes('vm_debugger.js'));
for (const source of [backend, packaging]) assert(source.includes('OriginTraceOwnedVmFixture'));
assert(swift.includes('"/api/vm-debugger/actions", "/api/vm-debugger/trace"'));
assert(make.includes('owned_vm_real_helper -- --ignored'));
assert(make.includes('owned-vm-helper-check'));
const spec = JSON.parse(specText), paths = spec.paths;
assert.equal(paths['/api/vm-debugger/actions'].post['x-max-body-bytes'], 2048);
assert.equal(paths['/api/vm-debugger/actions'].post['x-reb-execution'].kind, 'action-dependent');
for (const path of ['/api/vm-debugger', '/api/vm-debugger/trace']) assert.deepEqual(paths[path].get['x-reb-execution'].effects, []);
assert.equal(spec.components.schemas.OwnedVmDebuggerAction.oneOf.length, 7);
assert.equal(createHash('sha256').update(manifest).digest('hex'), '2e9f20bb3380e518db160b5da89e9a1530b03e31fb2bf094591b7ee5e0e1e778');
console.log('PASS owned VM integration contracts: entry, stable toolbar/focus boundary, history selection CSS, assets/helper packaging, read-only metadata and exact manifest (not rendered/native acceptance)');
