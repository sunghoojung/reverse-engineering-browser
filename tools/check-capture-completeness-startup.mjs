import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createStartupTimeline, startCaptureObservers} from './capture-completeness-startup.mjs';
import {completenessVerdict} from './capture-completeness-reference.mjs';
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return {promise, resolve};
};
// Hold either initializer open without wall-clock sleeps. Its peer must start
// and become ready; prearmed navigation must still wait for both.
for (const slow of ['reference', 'reb']) {
  const gate = deferred();
  const events = [];
  let tick = 0;
  const timeline = createStartupTimeline(() => tick++);
  timeline.mark('browserLaunchMs');
  const initialize = (name) => async () => {
    events.push(`${name}-launch`);
    if (name === slow) await gate.promise;
    events.push(`${name}-ready`);
  };
  const run = startCaptureObservers({
    reference: initialize('reference'),
    reb: initialize('reb'),
    timeline,
  }).then(() => {
    events.push('navigate');
    timeline.mark('fixtureNavigationMs');
  });
  await new Promise((resolve) => setImmediate(resolve));
  const fast = slow === 'reference' ? 'reb' : 'reference';
  assert(events.includes(`${fast}-launch`));
  assert(events.includes(`${fast}-ready`));
  assert(!events.includes(`${slow}-ready`));
  assert(!events.includes('navigate'));
  assert.equal(timeline.snapshot()[`${slow}ReadyMs`], null);
  gate.resolve();
  await run;
  assert(events.indexOf(`${fast}-launch`) < events.indexOf(`${slow}-ready`));
  const times = timeline.snapshot();
  assert(times.fixtureNavigationMs >= times.referenceReadyMs);
  assert(times.fixtureNavigationMs >= times.rebReadyMs);
}
// Sync and async failures must not prevent the peer from launching, and must
// reject the readiness barrier (thus becoming an incomplete runner result).
for (const failed of ['reference', 'reb']) {
  for (const sync of [true, false]) {
    const events = [];
    const timeline = createStartupTimeline();
    const initialize = (name) => () => {
      events.push(name);
      if (name === failed) {
        if (sync) throw Error('runner-incomplete');
        return Promise.reject(Error('runner-incomplete'));
      }
    };
    await assert.rejects(
      startCaptureObservers({
        reference: initialize('reference'),
        reb: initialize('reb'),
        timeline,
      }),
      /runner-incomplete/,
    );
    assert.deepEqual(events, ['reference', 'reb']);
    assert.equal(timeline.snapshot()[`${failed}ReadyMs`], null);
    assert.equal(
      completenessVerdict({
        errorCode: 'runner-incomplete',
        fixtureComplete: true,
        comparison: {verdict: 'pass'},
        uncovered: false,
        netlog: {state: 'corroborated'},
      }),
      'incomplete',
    );
  }
}
// A failed observer must not trigger cleanup while its peer is still starting.
const cleanupGate = deferred();
let settled = false;
const failedRun = startCaptureObservers({
  reference: () => {
    throw Error('runner-incomplete');
  },
  reb: () => cleanupGate.promise,
  timeline: createStartupTimeline(),
}).catch((error) => {
  settled = true;
  assert.equal(error.message, 'runner-incomplete');
});
await new Promise((resolve) => setImmediate(resolve));
assert.equal(settled, false);
cleanupGate.resolve();
await failedRun;
assert.equal(settled, true);
const referenceOnly = createStartupTimeline();
await startCaptureObservers({reference: async () => {}, reb: null, timeline: referenceOnly});
assert.equal(referenceOnly.snapshot().rebStartMs, null);
assert.equal(referenceOnly.snapshot().rebReadyMs, null);
let tick = 0;
const bounded = createStartupTimeline(() => tick);
tick = 120001;
assert.throws(() => bounded.mark('referenceStartMs'), /startup-timeline-invalid/);
// Guard the actual runner wiring: all reference initialization and REB launch
// live inside the shared barrier, after Chrome launch, before prearmed navigate.
const runner = await readFile(
  new URL('./check-capture-completeness-browser.mjs', import.meta.url),
  'utf8',
);
const barrier = runner.indexOf('await startCaptureObservers(');
assert(runner.indexOf('browserProcess = start(browser') < barrier);
for (const operation of [
  'const lines = await until',
  'new WebSocket(',
  'await ref.start()',
  'start(binary,',
])
  assert(runner.indexOf(operation) > barrier);
assert(runner.indexOf("if (mode === 'prearmed')") > runner.indexOf('start(binary,'));
console.log(
  'PASS concurrent observer startup: delayed peers, readiness barrier, failures, bounded timing, and runner wiring (synthetic only)',
);
