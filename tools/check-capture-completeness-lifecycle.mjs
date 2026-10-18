import assert from 'node:assert/strict';
import {
  classifyCaptureError,
  createLifecycleObserver,
  lifecycleErrorCodes,
} from './capture-completeness-lifecycle.mjs';
const state = (epoch, error = '', extra = {}) => ({
  network: {
    capture_epoch: epoch,
    dropped: 2,
    capture_status: {
      gaps: 3,
      attached_targets: 5,
      eligible_targets: 6,
      last_error: error,
      ...extra,
    },
  },
});
const observer = createLifecycleObserver();
observer.observe(state(0));
observer.observe(state(1));
observer.observe(state(1));
assert.equal(observer.snapshot().setupEpochTransitions, 1);
assert.equal(observer.snapshot().epochChanges, 0);
observer.observe(state(2, 'Capture detach failed: https://PRIVATE.invalid/token'));
observer.observe(state(2, 'SECRET arbitrary transport failure'));
observer.observe(
  state(2, 'Browser target or ancestor detached; unfinished evidence is unavailable.'),
);
const result = observer.snapshot();
assert.equal(result.epochChanges, 1);
assert.equal(result.maxima.gaps, 3);
assert.equal(result.maxima.dropped, 2);
assert.deepEqual(
  result.errorObservations.map((x) => x.code),
  ['detach-failed', 'unknown', 'target-or-ancestor-detached'],
);
assert(!/PRIVATE|SECRET|https:/.test(JSON.stringify(result)));
result.epochTransitions[0].to = 999;
result.maxima.gaps = 999;
assert.equal(observer.snapshot().epochTransitions[0].to, 1);
assert.equal(observer.snapshot().maxima.gaps, 3);
for (let i = 3; i < 1000; i++) observer.observe(state(i, `secret ${i}`));
assert.equal(observer.snapshot().epochTransitions.length, 16);
assert(observer.snapshot().omittedEpochTransitions > 0);
assert(observer.snapshot().errorObservations.length <= lifecycleErrorCodes.length);
for (const epoch of [NaN, Infinity, -1, 'SECRET', Number.MAX_SAFE_INTEGER + 1])
  observer.observe(state(epoch));
observer.observe(null);
assert.equal(observer.snapshot().invalidSamples, 6);
assert.equal(classifyCaptureError(''), null);
assert.equal(classifyCaptureError(null), null);
assert.equal(classifyCaptureError('Capture detach failed'), 'unknown');
const reconnect = createLifecycleObserver();
for (const n of [1, 0, 1]) reconnect.observe(state(n));
assert.equal(reconnect.snapshot().setupEpochTransitions, 0);
assert.equal(reconnect.snapshot().epochChanges, 2);
console.log(
  'Capture lifecycle: bounded aggregates, epoch setup/reconnect separation, error allowlist and privacy passed.',
);

const absent = createLifecycleObserver();
absent.observe({network: {capture_epoch: 0, capture_status: {}}});
assert(Object.values(absent.snapshot().maxima).every((value) => value === null));
absent.observe({network: {capture_epoch: 0, dropped: 0, capture_status: {gaps: 0}}});
assert.equal(absent.snapshot().maxima.gaps, 0);
assert.equal(absent.snapshot().maxima.dropped, 0);
assert.equal(absent.snapshot().maxima.attached_targets, null);
