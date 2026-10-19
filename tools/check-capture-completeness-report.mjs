import assert from 'node:assert/strict';
import {sanitizeCaptureReport} from './sanitize-capture-completeness-report.mjs';
import {statusValueBucketNames} from './capture-completeness-reference.mjs';
const input = {
  schema: 'reb-capture-completeness-v1',
  rebCommit: 'a'.repeat(40),
  secret: 'PRIVATE',
  results: ['startup', 'prearmed'].map((mode) => ({
    mode,
    browserVersion: '154.0.8037.57',
    verdict: 'incomplete',
    errorCode: 'browser-startup-unavailable',
    fixtureComplete: false,
    comparison: {verdict: 'incomplete', issues: ['invalid-reference'], headers: 'PRIVATE'},
    operations: [
      {
        operationId: `${mode}:case:op`,
        method: 'GET',
        expected: 1,
        receipts: 1,
        reference: 0,
        reb: 0,
        body: 'PRIVATE',
      },
    ],
    netlog: {state: 'incomplete', failures: ['netlog-unavailable']},
    rawUrl: 'https://private.invalid/',
  })),
};
const out = sanitizeCaptureReport(input);
assert(!JSON.stringify(out).includes('PRIVATE'));
assert(!JSON.stringify(out).includes('https:'));
assert.equal(out.results.length, 2);
assert.equal(out.results[0].operations[0].receipts, 1);
for (const change of [
  (r) => {
    r.rebCommit = 'https://private.invalid/';
  },
  (r) => {
    r.results[0].errorCode = 'https://private.invalid/';
  },
  (r) => {
    r.results[0].browserVersion = 'secret';
  },
  (r) => {
    r.results[0].operations[0].operationId = 'https://private.invalid/';
  },
  (r) => {
    r.results[0].operations[0].receipts = -1;
  },
  (r) => {
    r.results[0].operations[0].method = 'secret';
  },
  (r) => {
    r.results[0].comparison.issues = ['Authorization: private'];
  },
  (r) => {
    r.results[0].netlog.failures = ['private/raw'];
  },
]) {
  const copy = structuredClone(input);
  change(copy);
  assert.throws(() => sanitizeCaptureReport(copy));
}
console.log(
  'PASS capture report export: explicit allowlist strips sensitive extras and refuses invalid identities/counts/strings',
);

const lifecycleInput = structuredClone(input);
lifecycleInput.results[0].lifecycle = {
  samples: 2,
  invalidSamples: 0,
  firstEpoch: 0,
  lastEpoch: 1,
  setupEpochTransitions: 1,
  epochChanges: 0,
  omittedEpochTransitions: 0,
  maxima: {gaps: 9, dropped: 0, attached_targets: 5, cleanup_already_gone: 2, cleanup_failures: 1},
  epochTransitions: [{from: 0, to: 1, setup: true, secret: 'PRIVATE'}],
  errorObservations: [{code: 'target-or-ancestor-detached', samples: 1, raw: 'PRIVATE'}],
  secret: 'PRIVATE',
};
lifecycleInput.results[0].operations[0].differences = {state: 1, raw: 'PRIVATE'};
const safeLifecycle = sanitizeCaptureReport(lifecycleInput);
assert(!JSON.stringify(safeLifecycle).includes('PRIVATE'));
assert.equal(safeLifecycle.results[0].lifecycle.maxima.gaps, 9);
assert.equal(safeLifecycle.results[0].lifecycle.maxima.cleanup_already_gone, 2);
assert.equal(safeLifecycle.results[0].lifecycle.maxima.cleanup_failures, 1);
assert.equal(safeLifecycle.results[0].operations[0].differences.state, 1);
for (const mutate of [
  (r) => {
    r.results[0].lifecycle.errorObservations[0].code = 'private-error';
  },
  (r) => {
    r.results[0].lifecycle.epochTransitions[0].setup = 'PRIVATE';
  },
  (r) => {
    r.results[0].operations[0].differences.state = 'PRIVATE';
  },
]) {
  const invalid = structuredClone(lifecycleInput);
  mutate(invalid);
  assert.throws(() => sanitizeCaptureReport(invalid));
}

const startupInput = structuredClone(input);
startupInput.results[0].startupTimeline = {
  browserLaunchMs: 0,
  referenceStartMs: 1,
  devtoolsDiscoveredMs: 20,
  referenceReadyMs: 1500,
  rebStartMs: 1,
  rebReadyMs: 100,
  fixtureNavigationMs: null,
  secret: 'PRIVATE',
};
const safeStartup = sanitizeCaptureReport(startupInput);
assert(!JSON.stringify(safeStartup).includes('PRIVATE'));
assert.equal(safeStartup.results[0].startupTimeline.referenceReadyMs, 1500);
assert.equal(safeStartup.results[0].startupTimeline.fixtureNavigationMs, null);
for (const invalid of [-1, 120001, 1.5, 'PRIVATE', NaN, undefined]) {
  const copy = structuredClone(startupInput);
  copy.results[0].startupTimeline.rebStartMs = invalid;
  assert.throws(() => sanitizeCaptureReport(copy), /invalid-startup-timeline/);
}

const fieldNames = ['state', 'status', 'resourceType', 'fromDiskCache', 'fromServiceWorker'];
const malformedInput = structuredClone(input);
const diagnostics = {
  reference: Object.fromEntries(fieldNames.map((field) => [field, field === 'status' ? 1 : 0])),
  reb: Object.fromEntries(fieldNames.map((field) => [field, 0])),
  rawRequestId: 'PRIVATE',
  url: 'https://private.invalid/',
};
diagnostics.reference.sessionId = 'PRIVATE';
diagnostics.reb.targetId = 'PRIVATE';
malformedInput.results[0].comparison.malformedFields = structuredClone(diagnostics);
malformedInput.results[0].operations[0].malformedFields = structuredClone(diagnostics);
const safeMalformed = sanitizeCaptureReport(malformedInput);
assert.equal(safeMalformed.results[0].comparison.malformedFields.reference.status, 1);
assert.equal(safeMalformed.results[0].operations[0].malformedFields.reference.status, 1);
assert(!JSON.stringify(safeMalformed).includes('PRIVATE'));
assert(!JSON.stringify(safeMalformed).includes('https:'));
assert.deepEqual(Object.keys(safeMalformed.results[0].operations[0].malformedFields), [
  'reference',
  'reb',
]);
for (const side of ['reference', 'reb']) {
  assert.deepEqual(
    Object.keys(safeMalformed.results[0].operations[0].malformedFields[side]),
    fieldNames,
  );
  for (const field of fieldNames) {
    for (const invalid of [undefined, null, -1, 10001, 1.5, 'PRIVATE', NaN, Infinity]) {
      for (const scope of ['comparison', 'operation']) {
        const copy = structuredClone(malformedInput);
        const target =
          scope === 'comparison' ? copy.results[0].comparison : copy.results[0].operations[0];
        target.malformedFields[side][field] = invalid;
        assert.throws(() => sanitizeCaptureReport(copy), /invalid-malformed-fields/);
      }
    }
  }
  for (const invalid of [undefined, null, [], 'PRIVATE']) {
    const copy = structuredClone(malformedInput);
    copy.results[0].operations[0].malformedFields[side] = invalid;
    assert.throws(() => sanitizeCaptureReport(copy), /invalid-malformed-fields/);
  }
}

const readinessInput = structuredClone(input);
readinessInput.results[0].captureReadiness = {
  transport: 'page-fallback',
  scope: 'http-page-targets',
  state: 'ready',
  raw: 'PRIVATE',
};
assert.deepEqual(sanitizeCaptureReport(readinessInput).results[0].captureReadiness, {
  transport: 'page-fallback',
  scope: 'http-page-targets',
  state: 'ready',
});
readinessInput.results[0].captureReadiness.transport = 'PRIVATE';
assert.throws(() => sanitizeCaptureReport(readinessInput));

const statusInput = structuredClone(input),
  statusBuckets = {
    reference: Object.fromEntries(
      statusValueBucketNames.map((name) => [name, name === 'null' ? 1 : 0]),
    ),
    reb: Object.fromEntries(statusValueBucketNames.map((name) => [name, name === 'zero' ? 1 : 0])),
    rawStatus: 'PRIVATE',
    requestId: 'PRIVATE',
  };
statusBuckets.reference.rawStatus = 'PRIVATE';
statusBuckets.reb.url = 'https://private.invalid/';
statusInput.results[0].comparison.statusValueBuckets = structuredClone(statusBuckets);
statusInput.results[0].operations[0].statusValueBuckets = structuredClone(statusBuckets);
const safeStatus = sanitizeCaptureReport(statusInput);
assert(!JSON.stringify(safeStatus).includes('PRIVATE'));
assert(!JSON.stringify(safeStatus).includes('https:'));
for (const scope of ['comparison', 'operation']) {
  const target =
    scope === 'comparison' ? safeStatus.results[0].comparison : safeStatus.results[0].operations[0];
  assert.deepEqual(Object.keys(target.statusValueBuckets), ['reference', 'reb']);
  assert.equal(target.statusValueBuckets.reference.null, 1);
  assert.equal(target.statusValueBuckets.reb.zero, 1);
  for (const side of ['reference', 'reb']) {
    assert.deepEqual(Object.keys(target.statusValueBuckets[side]), statusValueBucketNames);
    const mutate = (fn) => {
      const copy = structuredClone(statusInput),
        value = scope === 'comparison' ? copy.results[0].comparison : copy.results[0].operations[0];
      fn(value);
      return copy;
    };
    for (const name of statusValueBucketNames)
      for (const invalid of [undefined, null, -1, 10001, 1.5, 'PRIVATE', NaN, Infinity])
        assert.throws(
          () =>
            sanitizeCaptureReport(
              mutate((v) => {
                v.statusValueBuckets[side][name] = invalid;
              }),
            ),
          /invalid-status-value-buckets/,
        );
    for (const invalid of [undefined, null, [], 'PRIVATE'])
      assert.throws(
        () =>
          sanitizeCaptureReport(
            mutate((v) => {
              v.statusValueBuckets[side] = invalid;
            }),
          ),
        /invalid-status-value-buckets/,
      );
    const atLimit = mutate((v) => {
      v.statusValueBuckets[side] = Object.fromEntries(
        statusValueBucketNames.map((name) => [name, name === 'zero' ? 10000 : 0]),
      );
    });
    assert.doesNotThrow(() => sanitizeCaptureReport(atLimit));
    const overTotal = mutate((v) => {
      v.statusValueBuckets[side].missing = 10000;
      v.statusValueBuckets[side].nonnumber = 1;
    });
    assert.throws(() => sanitizeCaptureReport(overTotal), /invalid-status-value-buckets/);
  }
}
console.log(
  'PASS status bucket export: fixed keys, observer/operation scope, privacy, count and total bounds',
);
