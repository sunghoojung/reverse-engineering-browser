#!/usr/bin/env node
// Validate real pipeline outputs against shipped UI models. No browser/DOM claim.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

const directory = process.argv[2];
assert(directory, 'Supply the artifact analysis directory from the pipeline');
const model = await readFile(new URL('../apps/research-ui/evidence_models.js', import.meta.url), 'utf8');
const analysis = JSON.parse(await readFile(join(directory, 'vm-analysis-v1.json'), 'utf8'));
const workspace = JSON.parse(await readFile(join(directory, 'vm-opcode-workspace-v2.json'), 'utf8'));
assert(runInNewContext(`${model}\nisVmAnalysisDocument(analysis) && isVmOpcodeWorkspaceDocument(workspace)`,
  {analysis, workspace, TextEncoder}));
assert(workspace.workspaces.some(item => item.snapshots.length > 0));
for (const item of workspace.workspaces) {
  assert.equal(item.samples.length, 0, 'Snapshot bytes are not guest dispatch samples');
  assert.equal(item.sample_count, 0);
  assert(item.coverage.omissions.some(omission => omission.reason === 'sampler-unavailable'));
}
console.log('PASS real retained runtime-snapshot output accepted by shipped UI models; no invented guest PC');
