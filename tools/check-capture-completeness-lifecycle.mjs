import assert from 'node:assert/strict';
import {
  browserSetupReasons,
  browserSetupStages,
  captureReadinessEnums,
  lifecycleErrorCodes,
} from './capture-completeness-lifecycle.mjs';
import {sanitizeCaptureReport} from './sanitize-capture-completeness-report.mjs';

// Archived reports may only carry these closed values; they never carry text.
for (const list of [lifecycleErrorCodes, browserSetupStages, browserSetupReasons, ...Object.values(captureReadinessEnums)]) {
  assert(Object.isFrozen(list) && list.length > 0, 'archived vocabularies are closed');
  assert.equal(new Set(list).size, list.length, 'archived vocabulary values are unique');
  for (const value of list) assert.match(value, /^[a-z][a-z0-9-]*$/, 'codes are identifiers, never captured text');
}
assert(lifecycleErrorCodes.includes('unknown'));
assert.equal(typeof sanitizeCaptureReport, 'function');
console.log('PASS archived capture lifecycle vocabularies are closed identifiers (no live CDP classifier remains)');
