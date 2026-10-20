// Monotonic offsets only: no wall clock, endpoints, paths, or captured data.
export const startupTimelineKeys = [
  'browserLaunchMs',
  'referenceStartMs',
  'devtoolsDiscoveredMs',
  'referenceReadyMs',
  'rebStartMs',
  'rebReadyMs',
  'fixtureNavigationMs',
];
export const startupTimelineLimitMs = 120000;
export function createStartupTimeline(now = () => performance.now()) {
  const origin = now();
  const values = Object.fromEntries(startupTimelineKeys.map((key) => [key, null]));
  return {
    mark(key) {
      const elapsed = Math.floor(now() - origin);
      if (
        !startupTimelineKeys.includes(key) ||
        !Number.isSafeInteger(elapsed) ||
        elapsed < 0 ||
        elapsed > startupTimelineLimitMs
      )
        throw Error('startup-timeline-invalid');
      values[key] = elapsed;
    },
    snapshot: () => ({...values}),
  };
}
export async function startCaptureObservers({reference, reb, timeline}) {
  const start = (name, initialize) =>
    Promise.resolve().then(async () => {
      timeline.mark(`${name}StartMs`);
      await initialize();
      timeline.mark(`${name}ReadyMs`);
    });
  // Queue both before awaiting either, including discovery, socket connection,
  // version checks, target initialization, and backend endpoint/readiness waits.
  // Settle both before cleanup so a rejected peer cannot spawn after teardown.
  const pending = [start('reference', reference)];
  if (reb) pending.push(start('reb', reb));
  const results = await Promise.allSettled(pending);
  const failed = results.find((result) => result.status === 'rejected');
  if (failed) throw failed.reason;
}
