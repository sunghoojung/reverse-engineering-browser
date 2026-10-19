// Test-only aggregate. Never export producer error text, instance/target/session
// IDs, URLs, or a snapshot. These codes describe observations, not root causes.
// Literal sources: apps/origin-trace-backend/src/debugger/network_browser.rs
// (admission, cleanup, initialization), network_capture.rs (retirement), and
// mod.rs (selected debugger connection advances network.capture_epoch).
const exactErrors = new Map([
  [
    'Browser target catalog capacity exceeded; counts exclude unknown targets until reconciliation.',
    'catalog-capacity',
  ],
  [
    'Capture attachment was acknowledged without a session event; retrying.',
    'attachment-event-missing',
  ],
  [
    'Capture cleanup capacity exceeded; closing this client leaves an explicit gap.',
    'cleanup-capacity',
  ],
  ['Malformed capture attachment session ID', 'attachment-session-malformed'],
  ['Malformed capture parent session ID', 'parent-session-malformed'],
  ['Capture session identity was reused for a different target', 'session-identity-reused'],
  [
    'Passive capture declined a target waiting for a debugger; startup ownership is unknown, so it was not resumed.',
    'unowned-startup-wait',
  ],
  [
    'Capture target crashed; unfinished evidence is unavailable and attachment will retry.',
    'target-crashed',
  ],
  [
    'Browser target or ancestor detached; unfinished evidence is unavailable.',
    'target-or-ancestor-detached',
  ],
  ['Capture transport changed; unfinished evidence has a gap.', 'transport-changed'],
  ['HTTP capture initialization failed; retry pending.', 'fallback-initialization'],
  ['Debugger WebSocket is closed', 'transport-closed'],
  ['Debugger WebSocket closed', 'transport-closed'],
  ['Debugger connection closed', 'transport-closed'],
  ['Debugger WebSocket sent malformed JSON', 'transport-malformed'],
  ['Debugger WebSocket sent a non-object message', 'transport-malformed'],
  [
    'Debugger event byte capacity exceeded; reconnecting preserves a visible gap',
    'transport-byte-capacity',
  ],
  [
    'Debugger event queue capacity exceeded; reconnecting preserves a visible gap',
    'transport-queue-capacity',
  ],
]);
const prefixErrors = [
  ['Target discovery unavailable: ', 'target-discovery-unavailable'],
  ['HTTP capture setup task failed: ', 'fallback-setup-task-failed'],
  ['Debugger WebSocket closed: ', 'transport-closed'],
  ['Debugger WebSocket is closed: ', 'transport-closed'],
  ['Debugger connection closed: ', 'transport-closed'],
  ['Capture detach failed: ', 'detach-failed'],
  ['Browser target capture initialization failed: ', 'owner-initialization-failed'],
  ['Browser capture setup failed: ', 'browser-setup-failed'],
  ['Browser capture unavailable; page polling fallback: ', 'browser-fallback'],
];
export const lifecycleErrorCodes = Object.freeze([
  ...new Set([...exactErrors.values(), ...prefixErrors.map(([, code]) => code)]),
  'unknown',
]);
export function classifyCaptureError(error) {
  if (typeof error !== 'string' || error.length === 0) return null;
  return (
    exactErrors.get(error) ??
    prefixErrors.find(([prefix]) => error.startsWith(prefix))?.[1] ??
    'unknown'
  );
}
export const browserSetupStages = Object.freeze([
  'endpoint',
  'transport-open',
  'discover-targets',
  'get-targets',
  'get-targets-shape',
]);
export const browserSetupReasons = Object.freeze([
  'timeout',
  'disconnected',
  'transport-failure',
  'invalid-reply',
  'protocol-error',
  'command-rejected',
  'dependency-unavailable',
  'resource-limit',
  'invalid-request',
  'state-conflict',
  'stale-generation',
  'target-unavailable',
  'cancelled',
  'outcome-unknown',
  'unspecified',
]);
const validCount = (value) => Number.isSafeInteger(value) && value >= 0;
const increment = (value) => Math.min(Number.MAX_SAFE_INTEGER, value + 1);
const fields = [
  'gaps',
  'dropped',
  'attached_targets',
  'eligible_targets',
  'failed_targets',
  'target_overflow',
  'cleanup_already_gone',
  'cleanup_failures',
];
export function createLifecycleObserver() {
  let samples = 0,
    invalidSamples = 0,
    firstEpoch = null,
    lastEpoch = null;
  let setupEpochTransitions = 0,
    epochChanges = 0,
    omittedEpochTransitions = 0;
  const epochTransitions = [],
    errorCounts = new Map(),
    setupCounts = new Map(),
    maxima = Object.fromEntries(fields.map((f) => [f, null]));
  return {
    observe(snapshot) {
      samples = increment(samples);
      const network = snapshot?.network,
        status = network?.capture_status;
      if (!network || !status || !validCount(network.capture_epoch)) {
        invalidSamples = increment(invalidSamples);
        return;
      }
      const epoch = network.capture_epoch;
      if (firstEpoch === null) firstEpoch = epoch;
      if (lastEpoch !== null && lastEpoch !== epoch) {
        // Only the initial debugger setup is expected. A later 0->1 is not.
        const setup =
          lastEpoch === 0 && epoch === 1 && setupEpochTransitions === 0 && epochChanges === 0;
        if (setup) setupEpochTransitions++;
        else epochChanges = increment(epochChanges);
        if (epochTransitions.length < 16)
          epochTransitions.push({from: lastEpoch, to: epoch, setup});
        else omittedEpochTransitions = increment(omittedEpochTransitions);
      }
      lastEpoch = epoch;
      for (const field of fields) {
        const value = field === 'dropped' ? network.dropped : status[field];
        if (validCount(value)) maxima[field] = Math.max(maxima[field] ?? 0, value);
      }
      const setup = status.browser_setup_failure;
      if (
        setup &&
        browserSetupStages.includes(setup.stage) &&
        browserSetupReasons.includes(setup.reason)
      ) {
        const key = `${setup.stage}:${setup.reason}`;
        setupCounts.set(key, increment(setupCounts.get(key) ?? 0));
      }
      const code = classifyCaptureError(status.last_error);
      if (code) errorCounts.set(code, increment(errorCounts.get(code) ?? 0));
    },
    snapshot() {
      return {
        samples,
        invalidSamples,
        firstEpoch,
        lastEpoch,
        setupEpochTransitions,
        epochChanges,
        epochTransitions: epochTransitions.map((value) => ({...value})),
        omittedEpochTransitions,
        maxima: {...maxima},
        browserSetupObservations: [...setupCounts].map(([key, samples]) => {
          const [stage, reason] = key.split(':');
          return {stage, reason, samples};
        }),
        errorObservations: [...errorCounts].map(([code, samples]) => ({
          code,
          samples,
        })),
      };
    },
  };
}

export const captureReadinessEnums = Object.freeze({
  transport: ['browser-sessions', 'page-fallback'],
  scope: ['http-browser-targets', 'http-page-targets'],
  state: ['waiting', 'ready', 'partial', 'disabled'],
});
export function captureReadiness(snapshot) {
  const status = snapshot?.network?.capture_status;
  return Object.fromEntries(
    Object.entries(captureReadinessEnums).map(([key, values]) => {
      const value = status?.[key === 'transport' ? 'transport_mode' : key];
      return [key, values.includes(value) ? value : null];
    }),
  );
}
