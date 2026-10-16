// Authored states for the shared VM Lab browser harness; no browser lifecycle here.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';

export async function workspaceUiCases() {
  const root = new URL('../', import.meta.url);
  const model = await readFile(new URL('apps/research-ui/evidence_models.js', root), 'utf8');
  const cases = {};
  for (const name of ['complete', 'partial']) {
    cases[name] = JSON.parse(await readFile(new URL(`tests/research_ui/fixtures/vm-byte-coverage-${name}-v2.json`, root), 'utf8'));
  }
  cases.empty = structuredClone(cases.complete);
  cases.empty.summary.snapshot_count = 0;
  const empty = cases.empty.workspaces[0];
  empty.snapshots = [];
  empty.coverage = {complete:false, handler_count:empty.handlers.length,
    retained_snapshot_bytes:0, characterized_bytes:0, uncharacterized_bytes:0,
    attributions:[], omissions:[{reason:'snapshot-bytes-unavailable'}]};
  for (const [name, fixture] of Object.entries(cases)) {
    assert(runInNewContext(model + '; isVmOpcodeWorkspaceDocument(fixture)', {fixture, TextEncoder}), `${name} must satisfy strict v2`);
  }
  cases.malformed = {...cases.complete, contract_version:1};
  assert(!runInNewContext(model + '; isVmOpcodeWorkspaceDocument(fixture)', {fixture:cases.malformed, TextEncoder}));
  return cases;
}

if (process.argv.includes('--validate-fixtures')) {
  await workspaceUiCases();
  console.log('PASS authored workspace UI cases: complete, partial, empty and malformed refresh');
}
