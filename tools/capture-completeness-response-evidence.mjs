// Diagnostic-only event presence. Never supplies a status or changes ownership.
const maxExportHops = 8;
const maxExportEvents = 16;
const methods = new Map([
  ['Network.responseReceived', 'response'],
  ['Network.responseReceivedExtraInfo', 'extra-info'],
]);
export const responseStatusBuckets = [
  'missing',
  'null',
  'zero',
  'http-range',
  'other-number',
  'nonfinite-number',
  'nonnumber',
];
export function responseStatusBucket(value) {
  if (value === undefined) return 'missing';
  if (value === null) return 'null';
  if (typeof value !== 'number') return 'nonnumber';
  if (!Number.isFinite(value)) return 'nonfinite-number';
  if (value === 0) return 'zero';
  return Number.isInteger(value) && value >= 100 && value <= 599 ? 'http-range' : 'other-number';
}
export function createResponseEvidence({maxEvents = 4096, maxBytes = 1024 * 1024} = {}) {
  const events = [];
  let bytes = 0,
    omittedEvents = 0;
  return {
    observe(epoch, sessionId, method, params) {
      const kind = methods.get(method);
      if (!kind) return;
      if (
        ![sessionId, params?.requestId].every(
          (id) => typeof id === 'string' && id.length > 0 && id.length <= 4096,
        )
      ) {
        omittedEvents++;
        return;
      }
      const event = {
        epoch,
        sessionId,
        requestId: params.requestId,
        ordinal: events.length + omittedEvents + 1,
        kind,
        statusBucket: responseStatusBucket(
          kind === 'response' ? params.response?.status : params.statusCode,
        ),
        hasExtraInfo:
          kind === 'response' && typeof params.hasExtraInfo === 'boolean'
            ? params.hasExtraInfo
              ? 'yes'
              : 'no'
            : 'unknown',
      };
      const size = Buffer.byteLength(JSON.stringify(event));
      if (events.length >= maxEvents || bytes + size > maxBytes) {
        omittedEvents++;
        return;
      }
      bytes += size;
      events.push(event);
    },
    snapshot() {
      return {
        complete: omittedEvents === 0,
        omittedEvents,
        events: events.map((event) => ({...event})),
      };
    },
  };
}
export function scopedResponseEvidence(reference, include) {
  const evidence = reference.responseEvidence;
  if (!evidence) return {complete: false, omittedEvents: 0, omittedHops: 0, hops: []};
  const scoped = reference.hops.filter(include);
  const hops = scoped.slice(0, maxExportHops).map((hop) => {
    const matching = evidence.events.filter(
      (event) => event.epoch === hop.epoch && event.requestId === hop.requestId,
    );
    const observed = matching.slice(0, maxExportEvents).map((event) => ({
      ordinal: event.ordinal,
      kind: event.kind,
      statusBucket: event.statusBucket,
      hasExtraInfo: event.hasExtraInfo,
      sessionRelation:
        event.sessionId === hop.sessionId
          ? 'request-session'
          : event.sessionId === hop.terminalSessionId
            ? 'proven-terminal-session'
            : 'other-session-matching-raw-id',
    }));
    return {
      hopOrdinal: hop.hop,
      namespaceHopCount: reference.hops.filter(
        (other) =>
          other.epoch === hop.epoch &&
          other.sessionId === hop.sessionId &&
          other.requestId === hop.requestId,
      ).length,
      rawIdHopCount: reference.hops.filter(
        (other) => other.epoch === hop.epoch && other.requestId === hop.requestId,
      ).length,
      omittedEvents: matching.length - observed.length,
      events: observed,
    };
  });
  return {
    complete:
      evidence.complete &&
      scoped.length <= maxExportHops &&
      hops.every((hop) => hop.omittedEvents === 0),
    omittedEvents: evidence.omittedEvents,
    omittedHops: Math.max(0, scoped.length - maxExportHops),
    hops,
  };
}
export function sanitizeResponseEvidence(value) {
  const count = (v) => {
    if (!Number.isSafeInteger(v) || v < 0 || v > 1000000)
      throw Error('invalid-response-evidence-count');
    return v;
  };
  const choice = (v, values) => {
    if (!values.includes(v)) throw Error('invalid-response-evidence-enum');
    return v;
  };
  if (
    !value ||
    typeof value.complete !== 'boolean' ||
    !Array.isArray(value.hops) ||
    value.hops.length > maxExportHops
  )
    throw Error('invalid-response-evidence');
  if (
    value.complete &&
    (value.omittedEvents !== 0 ||
      value.omittedHops !== 0 ||
      value.hops.some((hop) => hop.omittedEvents !== 0))
  )
    throw Error('inconsistent-response-evidence-completeness');
  return {
    complete: value.complete,
    omittedEvents: count(value.omittedEvents),
    omittedHops: count(value.omittedHops),
    hops: value.hops.map((hop) => {
      if (!Array.isArray(hop.events) || hop.events.length > maxExportEvents)
        throw Error('invalid-response-evidence-events');
      return {
        hopOrdinal: count(hop.hopOrdinal),
        namespaceHopCount: count(hop.namespaceHopCount),
        rawIdHopCount: count(hop.rawIdHopCount),
        omittedEvents: count(hop.omittedEvents),
        events: hop.events.map((event) => ({
          ordinal: count(event.ordinal),
          kind: choice(event.kind, ['response', 'extra-info']),
          statusBucket: choice(event.statusBucket, responseStatusBuckets),
          hasExtraInfo: choice(event.hasExtraInfo, ['yes', 'no', 'unknown']),
          sessionRelation: choice(event.sessionRelation, [
            'request-session',
            'proven-terminal-session',
            'other-session-matching-raw-id',
          ]),
        })),
      };
    }),
  };
}
