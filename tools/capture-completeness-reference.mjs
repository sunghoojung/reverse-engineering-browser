import {createResponseEvidence} from './capture-completeness-response-evidence.mjs';
// Independent test oracle. Never import REB's capture/parser/ownership helpers.
// Metadata stays ephemeral; callers publish only the aggregate comparison.
const supported = new Set(['page', 'iframe', 'worker', 'shared_worker', 'service_worker']);
const key = (...parts) => JSON.stringify(parts);
export class ReferenceLedger {
  constructor({
    maxSessions = 128,
    maxEvents = 20000,
    maxBytes = 16 * 1024 * 1024,
    maxHops = 10000,
    maxStatusEntries = maxHops,
  } = {}) {
    this.limits = {maxSessions, maxEvents, maxBytes, maxHops, maxStatusEntries};
    this.sessions = new Map();
    this.sessionInfo = new Map();
    this.active = new Map();
    this.hops = [];
    this.websockets = [];
    this.responseEvidence = createResponseEvidence();
    this.statusHistory = new Map();
    this.statusHistoryComplete = true;
    this.events = 0;
    this.bytes = 0;
    this.errors = new Set();
    this.epoch = 1;
    this.finalized = false;
  }
  gap(reason) {
    if (this.errors.size < 32) this.errors.add(reason);
  }
  session(sessionId, targetId, info = {}, parentSessionId) {
    if (
      ![sessionId, targetId].every(
        (id) => typeof id === 'string' && id.length > 0 && id.length <= 1024,
      )
    ) {
      this.gap('invalid-session');
      return false;
    }
    if (this.sessions.has(sessionId)) {
      if (this.sessions.get(sessionId) !== targetId) this.gap('session-reused');
      else this.describeSession(sessionId, info, parentSessionId);
      return false;
    }
    if (this.sessions.size >= this.limits.maxSessions) {
      this.gap('session-limit');
      return false;
    }
    this.sessions.set(sessionId, targetId);
    this.sessionInfo.set(sessionId, {
      epoch: this.epoch,
      sessionId,
      targetId,
      parentSessionId: parentSessionId ?? null,
      targetParentSessionId: null,
      type: null,
      url: null,
      parentId: null,
      parentFrameId: null,
      openerId: null,
      openerFrameId: null,
      lineageConflict: false,
    });
    this.describeSession(sessionId, info, parentSessionId);
    return true;
  }
  describeSession(sessionId, info, parentSessionId) {
    const owner = this.sessionInfo.get(sessionId);
    if (!owner) return;
    const retain = (name, value) => {
      if (value === undefined || value === null || value === '') return;
      if (typeof value !== 'string' || value.length > 1024) {
        owner.lineageConflict = true;
        this.gap('invalid-target-lineage');
      } else if (owner[name] && owner[name] !== value) {
        owner.lineageConflict = true;
        this.gap('target-lineage-conflict');
      } else owner[name] = value;
    };
    for (const name of ['type', 'parentId', 'parentFrameId', 'openerId', 'openerFrameId'])
      retain(name, info[name]);
    // A secondary auto-attachment can prove target lineage without becoming
    // the admitted Network observer or rewriting that session's actual parent.
    retain('targetParentSessionId', parentSessionId);
    if (typeof info.url === 'string' && info.url) owner.url = info.url;
  }
  parentRelation(source, destination) {
    const visited = new Set();
    let current = destination,
      hasParent = false;
    while (current && !visited.has(current.targetId)) {
      visited.add(current.targetId);
      if (current.epoch !== this.epoch || current.lineageConflict) return false;
      const sessionParent = this.sessionInfo.get(current.targetParentSessionId);
      if (sessionParent && sessionParent.epoch !== this.epoch) return false;
      const parentId = current.parentId ?? sessionParent?.targetId;
      if (current.parentId && sessionParent && current.parentId !== sessionParent.targetId)
        return false;
      if (!parentId) return hasParent ? false : null;
      hasParent = true;
      if (parentId === source.targetId) return true;
      const parents = [...this.sessionInfo.values()].filter(
        (s) => s.epoch === this.epoch && s.targetId === parentId,
      );
      if (parents.length !== 1) return false;
      [current] = parents;
    }
    return false;
  }
  mainResourceCompletion(sessionId, params) {
    const destination = this.sessionInfo.get(sessionId);
    if (
      !destination ||
      destination.epoch !== this.epoch ||
      destination.lineageConflict ||
      !Number.isFinite(params.timestamp)
    )
      return null;
    // Chrome DevTools' NetworkManager.ts, maybeAdoptMainResourceRequest and
    // startNetworkRequest, document this main-resource lifecycle handoff:
    // https://github.com/ChromeDevTools/devtools-frontend/blob/main/front_end/core/sdk/NetworkManager.ts
    // Keep ordinary request IDs session-scoped. Even a completed colliding
    // start in another session makes this narrowly supported adoption unsafe.
    const candidates = [...this.active.values()].filter(
      (hop) => hop.epoch === this.epoch && hop.requestId === params.requestId,
    );
    if (candidates.length !== 1) return null;
    const [hop] = candidates,
      source = this.sessionInfo.get(hop.sessionId);
    if (
      hop.state !== 'pending' ||
      !source ||
      source.epoch !== this.epoch ||
      source.lineageConflict ||
      source.targetId === destination.targetId ||
      params.timestamp < hop.timestamp
    )
      return null;
    const relation = this.parentRelation(source, destination);
    // Chromium's RenderFrameDevToolsAgentHost uses the DevTools frame token
    // as its target ID; require that exact frame plus its observed ancestry.
    // https://github.com/chromium/chromium/blob/main/content/browser/devtools/render_frame_devtools_agent_host.cc
    const document =
      hop.resourceType === 'Document' &&
      hop.loaderId === hop.requestId &&
      hop.frameId === destination.targetId &&
      destination.type === 'iframe' &&
      ['page', 'iframe'].includes(source.type) &&
      relation === true;
    const worker =
      hop.resourceType === 'Script' &&
      hop.loaderId === '' &&
      hop.requestId === destination.targetId &&
      ['worker', 'shared_worker'].includes(destination.type) &&
      ['page', 'iframe', 'worker', 'shared_worker'].includes(source.type) &&
      relation !== false &&
      (!destination.url || destination.url === hop.url);
    if (!document && !worker) return null;
    return hop;
  }
  observeStatusHistory(sessionId, method, params) {
    if (
      ![
        'Network.requestWillBeSent',
        'Network.responseReceived',
        'Network.responseReceivedExtraInfo',
      ].includes(method)
    )
      return;
    if (
      typeof params.requestId !== 'string' ||
      !params.requestId ||
      params.requestId.length > 1024
    ) {
      this.statusHistoryComplete = false;
      this.gap('status-history-incomplete');
      return;
    }
    const id = key(this.epoch, sessionId, params.requestId);
    if (!this.statusHistory.has(id)) {
      if (this.statusHistory.size >= this.limits.maxStatusEntries) {
        this.statusHistoryComplete = false;
        this.gap('status-history-limit');
        return;
      }
      this.statusHistory.set(id, {
        starts: 0,
        responses: 0,
        extras: 0,
        redirect: false,
        status: null,
      });
    }
    const history = this.statusHistory.get(id);
    if (method === 'Network.requestWillBeSent') {
      history.starts = Math.min(history.starts + 1, 2);
      history.redirect ||= params.redirectResponse !== undefined;
    } else if (method === 'Network.responseReceived') {
      history.responses = Math.min(history.responses + 1, 2);
    } else {
      history.extras = Math.min(history.extras + 1, 2);
      // Retain only the scalar status. Never retain ExtraInfo headers/cookies.
      if (
        history.extras === 1 &&
        Number.isInteger(params.statusCode) &&
        params.statusCode >= 100 &&
        params.statusCode <= 599
      )
        history.status = params.statusCode;
    }
  }
  correlateExtraInfoStatus() {
    // Resolve once at the end of the observation window, so before-request,
    // after-terminal and duplicate events all participate in the same proof.
    // Network.pdl documents both missing responseReceived and cached 200/304:
    // https://github.com/ChromeDevTools/devtools-protocol/blob/master/pdl/domains/Network.pdl
    if (
      !this.statusHistoryComplete ||
      this.errors.size ||
      !this.responseEvidence.snapshot().complete
    )
      return;
    for (const hop of this.hops) {
      const history = this.statusHistory.get(key(hop.epoch, hop.sessionId, hop.requestId));
      if (
        hop.epoch !== this.epoch ||
        this.sessionInfo.get(hop.sessionId)?.epoch !== hop.epoch ||
        hop.hop !== 0 ||
        hop.redirect ||
        !history ||
        history.starts !== 1 ||
        history.redirect ||
        history.extras !== 1 ||
        history.responses > 1 ||
        history.status === null
      )
        continue;
      hop.wire_status = history.status;
      if (
        history.responses === 0 &&
        hop.status_source === 'unavailable' &&
        hop.status === null &&
        history.status !== 304
      ) {
        hop.status = history.status;
        hop.status_source = 'response-received-extra-info';
      }
    }
  }
  ingest(message, byteLength = Buffer.byteLength(JSON.stringify(message) ?? '')) {
    if (this.finalized) return;
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      this.gap('malformed-message');
      return;
    }
    this.events++;
    this.bytes += byteLength;
    if (this.events > this.limits.maxEvents || this.bytes > this.limits.maxBytes) {
      this.gap('event-budget');
      return;
    }
    const {method, params: p = {}, sessionId} = message;
    if (typeof method !== 'string' || !p || typeof p !== 'object' || Array.isArray(p)) {
      this.gap('malformed-event');
      return;
    }
    if (!method?.startsWith('Network.')) return;
    this.responseEvidence.observe(this.epoch, sessionId, method, p);
    const targetId = this.sessions.get(sessionId);
    if (!targetId) {
      this.gap('unknown-session');
      return;
    }
    this.observeStatusHistory(sessionId, method, p);
    const id = key(this.epoch, sessionId, p.requestId);
    if (method === 'Network.webSocketCreated') {
      if (this.websockets.length >= this.limits.maxHops) this.gap('websocket-limit');
      else
        this.websockets.push({
          sessionId,
          targetId,
          requestId: p.requestId,
          url: p.url,
          method: 'GET',
        });
      return;
    }
    if (method === 'Network.requestWillBeSent') {
      if (
        typeof p.requestId !== 'string' ||
        typeof p.request?.url !== 'string' ||
        typeof p.request?.method !== 'string' ||
        !Number.isFinite(p.timestamp)
      ) {
        this.gap('malformed-request');
        return;
      }
      const previous = this.active.get(id);
      if (previous && !p.redirectResponse) {
        this.gap('request-id-reused');
        return;
      }
      if (p.redirectResponse) {
        if (!previous) this.gap('redirect-start-missing');
        else {
          this.response(previous, p.redirectResponse, 'redirect-response');
          previous.state = 'complete';
          previous.redirect = true;
        }
      }
      if (this.hops.length >= this.limits.maxHops) {
        this.gap('hop-limit');
        return;
      }
      const hop = {
        epoch: this.epoch,
        sessionId,
        targetId,
        requestId: p.requestId,
        hop: previous ? previous.hop + 1 : 0,
        loaderId: typeof p.loaderId === 'string' ? p.loaderId : null,
        frameId: typeof p.frameId === 'string' ? p.frameId : null,
        url: p.request.url,
        method: p.request.method,
        resourceType: p.type ?? '',
        timestamp: p.timestamp,
        status: null,
        status_source: 'unavailable',
        wire_status: null,
        state: 'pending',
        fromDiskCache: false,
        fromServiceWorker: false,
        canceled: false,
      };
      this.hops.push(hop);
      this.active.set(id, hop);
      return;
    }
    if (
      ![
        'Network.responseReceived',
        'Network.requestServedFromCache',
        'Network.loadingFinished',
        'Network.loadingFailed',
      ].includes(method)
    )
      return;
    const hop =
      this.active.get(id) ??
      (method === 'Network.loadingFinished' ? this.mainResourceCompletion(sessionId, p) : null);
    if (!hop) {
      this.gap('orphan-network-event');
      return;
    }
    if (method === 'Network.responseReceived') this.response(hop, p.response);
    if (method === 'Network.requestServedFromCache') hop.servedFromCache = true;
    if (method === 'Network.loadingFinished') {
      hop.state = 'complete';
      hop.terminalSessionId = sessionId;
      hop.terminalTargetId = targetId;
      hop.terminalTimestamp = p.timestamp ?? null;
    }
    if (method === 'Network.loadingFailed') {
      hop.state = 'failed';
      hop.canceled = p.canceled === true;
    }
  }
  response(hop, response, source = 'response-received') {
    hop.status_source = source;
    if (!response || !Number.isFinite(response.status)) {
      this.gap('malformed-response');
      return;
    }
    hop.status = response.status;
    hop.fromDiskCache = response.fromDiskCache === true;
    hop.fromServiceWorker = response.fromServiceWorker === true;
  }
  finalize() {
    if (this.finalized) return;
    this.correlateExtraInfoStatus();
    this.finalized = true;
    this.finalSnapshot = structuredClone(this.snapshot());
  }
  snapshot() {
    if (this.finalSnapshot) return this.finalSnapshot;
    return {
      finalized: this.finalized,
      epoch: this.epoch,
      sessions: [...this.sessionInfo.values()],
      responseEvidence: this.responseEvidence.snapshot(),
      hops: this.hops,
      websockets: this.websockets,
      errors: [...this.errors],
      events: this.events,
      bytes: this.bytes,
    };
  }
}

// Counts only, with normalized field names shared by both observer shapes.
// These predicates preserve the comparator's existing validation contract.
export const malformedHopFieldNames = [
  'state',
  'status',
  'resourceType',
  'fromDiskCache',
  'fromServiceWorker',
];
function malformedHopFields(row, reference) {
  return {
    state: !['complete', 'failed', 'pending'].includes(row?.state),
    status: !(Number.isFinite(row?.status) || (row?.status === null && row?.state !== 'complete')),
    resourceType: typeof row?.[reference ? 'resourceType' : 'resource_type'] !== 'string',
    fromDiskCache: typeof row?.[reference ? 'fromDiskCache' : 'from_disk_cache'] !== 'boolean',
    fromServiceWorker:
      typeof row?.[reference ? 'fromServiceWorker' : 'from_service_worker'] !== 'boolean',
  };
}
function countMalformedHopFields(reference, reb) {
  return Object.fromEntries(
    [
      ['reference', reference],
      ['reb', reb],
    ].map(([side, rows]) => {
      const counts = Object.fromEntries(malformedHopFieldNames.map((name) => [name, 0]));
      for (const row of rows) {
        const invalid = malformedHopFields(row, side === 'reference');
        for (const name of malformedHopFieldNames) if (invalid[name]) counts[name]++;
      }
      return [side, counts];
    }),
  );
}
// Descriptive buckets only: finite zero and other finite numeric statuses
// retain the existing validation behavior above. Never export a raw value.
export const statusValueBucketNames = [
  'missing',
  'null',
  'zero',
  'httpRange',
  'otherNumber',
  'nonfiniteNumber',
  'nonnumber',
];
export function statusValueBucket(status) {
  if (status === undefined) return 'missing';
  if (status === null) return 'null';
  if (typeof status !== 'number') return 'nonnumber';
  if (!Number.isFinite(status)) return 'nonfiniteNumber';
  if (status === 0) return 'zero';
  if (Number.isInteger(status) && status >= 100 && status <= 599) return 'httpRange';
  return 'otherNumber';
}
function countStatusValues(reference, reb) {
  return Object.fromEntries(
    [
      ['reference', reference],
      ['reb', reb],
    ].map(([side, rows]) => {
      const counts = Object.fromEntries(statusValueBucketNames.map((name) => [name, 0]));
      for (const row of rows) counts[statusValueBucket(row?.status)]++;
      return [side, counts];
    }),
  );
}
function statusProvenance(row) {
  const present =
    !!row && (Object.hasOwn(row, 'status_source') || Object.hasOwn(row, 'wire_status'));
  const complete =
    !!row && Object.hasOwn(row, 'status_source') && Object.hasOwn(row, 'wire_status');
  const valid =
    complete &&
    [
      'unavailable',
      'response-received',
      'redirect-response',
      'response-received-extra-info',
    ].includes(row.status_source) &&
    (row.wire_status === null ||
      (Number.isInteger(row.wire_status) && row.wire_status >= 100 && row.wire_status <= 599)) &&
    (row.status_source !== 'unavailable' || row.status === null) &&
    (row.status_source !== 'response-received-extra-info' ||
      (row.status !== 304 && row.status === row.wire_status && Number.isInteger(row.status)));
  return {present, complete, valid};
}
// Match independently-owned sessions via browser target/raw request/time, not
// REB public IDs or local session IDs. Timestamp disambiguates looping redirects.
export function compareCapture(reference, network, {include = () => true} = {}) {
  const issues = [];
  const add = (code) => {
    if (issues.length < 64) issues.push(code);
  };
  if (!reference || !Array.isArray(reference.hops) || !Array.isArray(reference.errors)) {
    return {verdict: 'incomplete', issues: ['invalid-reference']};
  }
  if (
    !network ||
    !Array.isArray(network.requests) ||
    network.requests.length > 10000 ||
    reference.hops.length > 10000
  )
    return {verdict: 'incomplete', issues: ['invalid-reb-snapshot']};
  if (reference.errors.length || reference.finalized !== true) add('reference-incomplete');
  if (
    !Number.isSafeInteger(reference.epoch) ||
    reference.epoch < 1 ||
    reference.hops.some((h) => h?.epoch !== reference.epoch)
  )
    add('reference-epoch-invalid');
  if (
    network.capture_enabled !== true ||
    typeof network.instance_id !== 'string' ||
    !network.instance_id ||
    !Number.isSafeInteger(network.capture_epoch) ||
    network.capture_epoch < 0
  )
    add('reb-identity-missing');
  const coverage = network.capture_status;
  const counters = ['gaps', 'target_overflow', 'failed_targets', 'unattached_targets_omitted'];
  if (
    !coverage ||
    counters.some((k) => !Number.isInteger(coverage[k]) || coverage[k] < 0) ||
    typeof coverage.catalog_incomplete !== 'boolean' ||
    typeof coverage.discovery_stale !== 'boolean' ||
    !Array.isArray(coverage.unattached_targets)
  )
    add('reb-coverage-schema');
  if (
    !coverage ||
    coverage.state !== 'ready' ||
    coverage.startup_mode !== 'passive' ||
    coverage.catalog_incomplete ||
    coverage.discovery_stale ||
    ['gaps', 'target_overflow', 'failed_targets', 'unattached_targets_omitted'].some(
      (k) => (coverage[k] ?? 0) > 0,
    ) ||
    (coverage.document_navigation_gaps ?? 0) > 0 ||
    coverage.unattached_targets?.length ||
    network.dropped !== 0
  )
    add('reb-coverage-incomplete');
  const validUrl = (value) => {
    try {
      return typeof value === 'string' && !!new URL(value).protocol;
    } catch {
      return false;
    }
  };
  if (
    reference.hops.some((h) => !h || !validUrl(h.url)) ||
    network.requests.some((r) => !r || !validUrl(r.url))
  )
    add('malformed-url');
  const refs = reference.hops.filter((h) => h && include(h)),
    rows = network.requests.filter((r) => r && include(r));
  if (!refs.length) add('empty-reference');
  const validId = (value) => typeof value === 'string' && value.length > 0;
  const malformedFields = countMalformedHopFields(reference.hops, network.requests);
  if (Object.values(malformedFields).some((side) => Object.values(side).some((count) => count > 0)))
    add('malformed-hop-state');
  // Validation still covers every row. Scoped counts let authored operations
  // explain their own defects without attributing unrelated rows to each one.
  const scopedMalformedFields = countMalformedHopFields(refs, rows);
  if (
    [...reference.hops, ...network.requests].some((row) => {
      const provenance = statusProvenance(row);
      return provenance.present && !provenance.valid;
    })
  )
    add('malformed-status-provenance');
  if (
    reference.hops.some(
      (h) =>
        !h ||
        ![h.sessionId, h.targetId, h.requestId, h.url, h.method].every(validId) ||
        !Number.isFinite(h.timestamp) ||
        !Number.isInteger(h.hop) ||
        h.hop < 0,
    )
  )
    add('malformed-reference');
  if (
    network.requests.some(
      (r) =>
        !r ||
        ![r.id, r.target_id, r.protocol_request_id, r.url, r.method].every(validId) ||
        r.timing_evidence?.request_monotonic_seconds?.state !== 'available' ||
        !Number.isFinite(r.timing_evidence?.request_monotonic_seconds?.value),
    )
  )
    add('malformed-reb-row');
  const index = new Map();
  const identity = (target, request, timestamp) => key(target, request, timestamp);
  for (const row of rows) {
    const timestamp = row.timing_evidence?.request_monotonic_seconds?.value;
    const k = identity(row.target_id, row.protocol_request_id, timestamp);
    if (!index.has(k)) index.set(k, []);
    index.get(k).push(row);
  }
  let matched = 0,
    missing = 0,
    ambiguous = 0,
    mismatched = 0;
  const mismatchReasons = {};
  const consumed = new Set(),
    seen = new Set();
  for (const hop of refs) {
    const k = identity(hop.targetId, hop.requestId, hop.timestamp);
    if (seen.has(k)) {
      ambiguous++;
      add('duplicate-reference-observation');
      continue;
    }
    seen.add(k);
    const candidates = index.get(k) ?? [];
    if (candidates.length === 0) {
      missing++;
      continue;
    }
    if (candidates.length !== 1) {
      ambiguous++;
      continue;
    }
    const row = candidates[0];
    consumed.add(row);
    if (hop.state === 'pending' || row.state === 'pending') add('pending-request');
    if (row.url_truncated || row.method_truncated) add('truncated-identity');
    const referenceProvenance = statusProvenance(hop),
      rebProvenance = statusProvenance(row),
      fallback = [hop.status_source, row.status_source].includes('response-received-extra-info');
    if (fallback && (!referenceProvenance.complete || !rebProvenance.complete))
      add('missing-status-provenance');
    const differences = [
      ['url', row.url, hop.url],
      ['method', row.method, hop.method],
      ['status', row.status, hop.status],
      ['state', row.state, hop.state],
      ['resourceType', row.resource_type, hop.resourceType],
      ['fromDiskCache', row.from_disk_cache, hop.fromDiskCache],
      ['fromServiceWorker', row.from_service_worker, hop.fromServiceWorker],
      ...(fallback || (referenceProvenance.complete && rebProvenance.complete)
        ? [
            ['statusSource', row.status_source, hop.status_source],
            ['wireStatus', row.wire_status, hop.wire_status],
          ]
        : []),
    ].filter(([, actual, expected]) => actual !== expected);
    if (differences.length) {
      mismatched++;
      for (const [name] of differences) mismatchReasons[name] = (mismatchReasons[name] ?? 0) + 1;
    } else matched++;
  }
  const extra = rows.length - consumed.size;
  return {
    verdict: issues.length
      ? 'incomplete'
      : missing || extra || ambiguous || mismatched
        ? 'fail'
        : 'pass',
    referenceHops: refs.length,
    rebHops: rows.length,
    matched,
    missing,
    extra,
    ambiguous,
    mismatched,
    mismatchReasons,
    malformedFields,
    scopedMalformedFields,
    statusValueBuckets: countStatusValues(reference.hops, network.requests),
    scopedStatusValueBuckets: countStatusValues(refs, rows),
    issues,
    scope:
      'Observed HTTP request hops only; independent clients share Chrome CDP blind spots. Bodies, headers and WebSockets are separate coverage.',
  };
}

// All layers must be affirmative; unknown/missing layer states never imply pass.
export function completenessVerdict({errorCode, fixtureComplete, comparison, uncovered, netlog}) {
  if (
    errorCode ||
    fixtureComplete !== true ||
    !['pass', 'fail'].includes(comparison?.verdict) ||
    !['corroborated', 'mismatch'].includes(netlog?.state)
  )
    return 'incomplete';
  return comparison.verdict === 'pass' && uncovered === false && netlog.state === 'corroborated'
    ? 'pass'
    : 'fail';
}

export function fixtureOperation(row, manifest) {
  if (!row || typeof row.url !== 'string' || typeof row.method !== 'string') return null;
  try {
    const u = new URL(row.url),
      ids = u.searchParams.getAll('op');
    if (!manifest.origins.includes(u.origin) || u.username || u.password || ids.length !== 1)
      return null;
    return (
      manifest.operations.find(
        (op) => op.operationId === ids[0] && op.path === u.pathname && op.method === row.method,
      ) ?? null
    );
  } catch {
    return null;
  }
}

// Separate, authored plaintext samples. Never infer complete body/header capture
// from request presence, or publish the captured strings in a report.
export function compareFixtureBodies(network, manifest) {
  const samples = manifest.operations.filter((op) => typeof op.expectedBody === 'string');
  let expectedSamples = 0,
    checkedSamples = 0,
    missingSamples = 0,
    mismatchedSamples = 0;
  for (const op of samples) {
    const expected = op.expectedClientCompletions ?? op.expectedReceipts;
    expectedSamples += expected;
    const rows = (network?.requests ?? []).filter((row) => fixtureOperation(row, manifest) === op);
    missingSamples += Math.max(0, expected - rows.length);
    mismatchedSamples += Math.max(0, rows.length - expected);
    for (const row of rows) {
      const body = row.response?.body;
      if (body?.state !== 'available' || body.truncated !== false) {
        missingSamples++;
        continue;
      }
      checkedSamples++;
      if (body.text !== op.expectedBody || body.base64) mismatchedSamples++;
    }
  }
  return {
    verdict:
      expectedSamples === 0
        ? 'unassessed'
        : missingSamples
          ? 'incomplete'
          : mismatchedSamples
            ? 'fail'
            : 'pass',
    expectedSamples,
    checkedSamples,
    missingSamples,
    mismatchedSamples,
  };
}

export function captureRunVerdict(httpVerdict, bodyComparison) {
  if (
    !['pass', 'fail'].includes(httpVerdict) ||
    !['pass', 'fail'].includes(bodyComparison?.verdict)
  )
    return 'incomplete';
  return httpVerdict === 'pass' && bodyComparison.verdict === 'pass' ? 'pass' : 'fail';
}

// The public epoch also advances during initial selected-debugger setup. Arm
// only after that setup and browser capture are ready; later changes stay fatal.
export class CaptureIdentityTracker {
  constructor() {
    this.last = null;
    this.baseline = null;
    this.readinessTransitions = 0;
  }
  observe(snapshot) {
    const network = snapshot?.network;
    if (
      typeof network?.instance_id !== 'string' ||
      !network.instance_id ||
      !Number.isSafeInteger(network.capture_epoch) ||
      network.capture_epoch < 0
    )
      return false;
    const identity = key(network.instance_id, network.capture_epoch);
    if (this.baseline !== null) return identity === this.baseline;
    if (this.last !== null && identity !== this.last) this.readinessTransitions++;
    this.last = identity;
    if (
      snapshot.state === 'running' &&
      network.capture_epoch > 0 &&
      network.capture_status?.state === 'ready'
    )
      this.baseline = identity;
    return true;
  }
}
