// Closed vocabularies of archived capture-completeness reports. The CDP
// producer whose status messages and debugger snapshots mapped onto these codes
// was removed, so nothing classifies live text any more. The report sanitizer
// keeps accepting exactly these values and rejects everything else.
export const lifecycleErrorCodes = Object.freeze([
  'catalog-capacity',
  'attachment-event-missing',
  'cleanup-capacity',
  'attachment-session-malformed',
  'parent-session-malformed',
  'session-identity-reused',
  'unowned-startup-wait',
  'target-crashed',
  'target-or-ancestor-detached',
  'transport-changed',
  'fallback-initialization',
  'transport-closed',
  'transport-malformed',
  'transport-byte-capacity',
  'transport-queue-capacity',
  'target-discovery-unavailable',
  'fallback-setup-task-failed',
  'detach-failed',
  'owner-initialization-failed',
  'browser-setup-failed',
  'browser-fallback',
  'event-queue-dropped',
  'unknown',
]);
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
export const captureReadinessEnums = Object.freeze({
  transport: Object.freeze(['browser-sessions', 'page-fallback']),
  scope: Object.freeze(['http-browser-targets', 'http-page-targets']),
  state: Object.freeze(['waiting', 'ready', 'partial', 'disabled']),
});
