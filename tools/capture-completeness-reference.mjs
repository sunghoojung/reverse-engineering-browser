// Independent test oracle. Never import REB's capture/parser/ownership helpers.
// Metadata stays ephemeral; callers publish only the aggregate comparison.
const supported = new Set(['page', 'iframe', 'worker', 'shared_worker', 'service_worker']);
const key = (...parts) => JSON.stringify(parts);
const commandCode = (method) =>
  ({
    'Network.enable': 'network-enable',
    'Target.setAutoAttach': 'auto-attach',
    'Target.attachToTarget': 'target-attach',
    'Target.detachFromTarget': 'target-detach',
    'Browser.close': 'browser-close',
  })[method] ?? 'other';
export class ReferenceLedger {
  constructor({
    maxSessions = 128,
    maxEvents = 20000,
    maxBytes = 16 * 1024 * 1024,
    maxHops = 10000,
  } = {}) {
    this.limits = {maxSessions, maxEvents, maxBytes, maxHops};
    this.sessions = new Map();
    this.active = new Map();
    this.hops = [];
    this.websockets = [];
    this.events = 0;
    this.bytes = 0;
    this.errors = new Set();
    this.epoch = 1;
    this.finalized = false;
  }
  gap(reason) {
    if (this.errors.size < 32) this.errors.add(reason);
  }
  session(sessionId, targetId) {
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
      return false;
    }
    if (this.sessions.size >= this.limits.maxSessions) {
      this.gap('session-limit');
      return false;
    }
    this.sessions.set(sessionId, targetId);
    return true;
  }
  ingest(message, byteLength = Buffer.byteLength(JSON.stringify(message) ?? '')) {
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
    const targetId = this.sessions.get(sessionId);
    if (!targetId) {
      this.gap('unknown-session');
      return;
    }
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
          this.response(previous, p.redirectResponse);
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
        url: p.request.url,
        method: p.request.method,
        resourceType: p.type ?? '',
        timestamp: p.timestamp,
        status: null,
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
    const hop = this.active.get(id);
    if (!hop) {
      this.gap('orphan-network-event');
      return;
    }
    if (method === 'Network.responseReceived') this.response(hop, p.response);
    if (method === 'Network.requestServedFromCache') hop.servedFromCache = true;
    if (method === 'Network.loadingFinished') hop.state = 'complete';
    if (method === 'Network.loadingFailed') {
      hop.state = 'failed';
      hop.canceled = p.canceled === true;
    }
  }
  response(hop, response) {
    if (!response || !Number.isFinite(response.status)) {
      this.gap('malformed-response');
      return;
    }
    hop.status = response.status;
    hop.fromDiskCache = response.fromDiskCache === true;
    hop.fromServiceWorker = response.fromServiceWorker === true;
  }
  finalize() {
    this.finalized = true;
    this.finalSnapshot = structuredClone(this.snapshot());
  }
  snapshot() {
    if (this.finalSnapshot) return this.finalSnapshot;
    return {
      finalized: this.finalized,
      epoch: this.epoch,
      hops: this.hops,
      websockets: this.websockets,
      errors: [...this.errors],
      events: this.events,
      bytes: this.bytes,
    };
  }
}

export class PassiveReference {
  constructor(socket, limits = {}) {
    this.socket = socket;
    this.ledger = new ReferenceLedger(limits);
    this.pending = new Map();
    this.attachments = new Map();
    this.initializing = new Set();
    this.sequence = 0;
    this.closed = false;
    this.rejectedSessions = new Set();
    this.duplicateSessions = 0;
    socket.addEventListener('message', (event) => {
      const bytes = Buffer.byteLength(String(event.data));
      if (bytes > 1024 * 1024) {
        this.ledger.gap('message-limit');
        return;
      }
      let m;
      try {
        m = JSON.parse(event.data);
      } catch {
        this.ledger.gap('invalid-json');
        return;
      }
      if (!m || typeof m !== 'object' || Array.isArray(m)) {
        this.ledger.gap('invalid-message');
        return;
      }
      if (m.id) {
        const waiter = this.pending.get(m.id);
        if (waiter) {
          this.pending.delete(m.id);
          clearTimeout(waiter.timer);
          if (m.error) {
            this.ledger.gap(`command-rejected-${commandCode(waiter.method)}`);
            waiter.reject(Error('CDP command rejected'));
          } else waiter.resolve(m.result);
        }
        return;
      }
      this.ledger.ingest(m, bytes);
      if (!m.params || typeof m.params !== 'object') return;
      if (m.method === 'Target.attachedToTarget')
        this.admit(m.params.sessionId, m.params.targetInfo, m.sessionId);
      if (m.method === 'Target.targetCreated' && supported.has(m.params.targetInfo?.type))
        this.attach(m.params.targetInfo).catch(() => this.ledger.gap('attach-failed'));
      if (m.method === 'Target.detachedFromTarget') {
        const sid = m.params.sessionId;
        for (const [targetId, active] of this.attachments) {
          if (active === sid) this.attachments.delete(targetId);
        }
        for (const hop of this.ledger.hops)
          if (hop.sessionId === sid && hop.state === 'pending') this.ledger.gap('detach-pending');
      }
    });
    socket.addEventListener('close', () => {
      if (!this.closed) this.ledger.gap('transport-closed');
      for (const p of this.pending.values()) {
        clearTimeout(p.timer);
        p.reject(Error('CDP closed'));
      }
      this.pending.clear();
    });
  }
  command(method, params = {}, sessionId) {
    if (this.pending.size >= 256) {
      this.ledger.gap('command-limit');
      return Promise.reject(Error('CDP command limit'));
    }
    return new Promise((resolve, reject) => {
      const id = ++this.sequence,
        timer = setTimeout(() => {
          this.pending.delete(id);
          this.ledger.gap('command-timeout');
          this.ledger.gap(`command-timeout-${commandCode(method)}`);
          reject(Error('CDP timeout'));
        }, 5000);
      this.pending.set(id, {resolve, reject, timer, method});
      try {
        this.socket.send(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}));
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error);
      }
    });
  }
  admit(sessionId, info, parentSession) {
    if (!supported.has(info?.type) || this.rejectedSessions.has(sessionId)) return;
    const primary = this.attachments.get(info.targetId);
    if (primary && primary !== sessionId) {
      if (this.rejectedSessions.size >= this.ledger.limits.maxSessions) {
        this.ledger.gap('duplicate-session-limit');
        this.socket.close();
        return;
      }
      this.rejectedSessions.add(sessionId);
      this.duplicateSessions++;
      // Discovery and recursive auto-attach can race. Never enable a second
      // Network observer for the same target; retain the original owner.
      const cleanup = this.command('Target.detachFromTarget', {sessionId}, parentSession)
        .catch(() => this.ledger.gap('duplicate-detach-failed'))
        .finally(() => this.initializing.delete(cleanup));
      this.initializing.add(cleanup);
      return;
    }
    if (!this.ledger.session(sessionId, info.targetId)) return;
    this.attachments.set(info.targetId, sessionId);
    const init = (async () => {
      await this.command('Network.enable', {}, sessionId);
      await this.command(
        'Target.setAutoAttach',
        {autoAttach: true, waitForDebuggerOnStart: false, flatten: true},
        sessionId,
      );
    })()
      .catch(() => this.ledger.gap('session-initialization'))
      .finally(() => this.initializing.delete(init));
    this.initializing.add(init);
  }
  async attach(info) {
    if (typeof info?.targetId !== 'string' || !info.targetId || info.targetId.length > 1024) {
      this.ledger.gap('invalid-target');
      return;
    }
    if (this.attachments.has(info.targetId)) return;
    if (this.attachments.size >= this.ledger.limits.maxSessions) {
      this.ledger.gap('target-limit');
      return;
    }
    this.attachments.set(info.targetId, null);
    const result = await this.command('Target.attachToTarget', {
      targetId: info.targetId,
      flatten: true,
    });
    this.admit(result.sessionId, info);
  }
  async start() {
    await this.command('Target.setDiscoverTargets', {discover: true});
    const {targetInfos} = await this.command('Target.getTargets');
    if (!Array.isArray(targetInfos) || targetInfos.length > 512) {
      this.ledger.gap('target-catalog-limit');
      return;
    }
    for (const info of targetInfos) if (supported.has(info.type)) await this.attach(info);
    await this.ready();
  }
  async ready() {
    let timer;
    try {
      await Promise.race([
        (async () => {
          while (this.initializing.size) await Promise.all([...this.initializing]);
        })(),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            this.ledger.gap('initialization-deadline');
            reject(Error('Initialization deadline'));
          }, 10000);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }
  close() {
    this.closed = true;
    this.socket.close();
  }
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
  const validState = (state, status) =>
    ['complete', 'failed', 'pending'].includes(state) &&
    (Number.isFinite(status) || (status === null && state !== 'complete'));
  if (
    reference.hops.some(
      (h) =>
        !h ||
        !validState(h.state, h.status) ||
        typeof h.resourceType !== 'string' ||
        typeof h.fromDiskCache !== 'boolean' ||
        typeof h.fromServiceWorker !== 'boolean',
    ) ||
    network.requests.some(
      (r) =>
        !r ||
        !validState(r.state, r.status) ||
        typeof r.resource_type !== 'string' ||
        typeof r.from_disk_cache !== 'boolean' ||
        typeof r.from_service_worker !== 'boolean',
    )
  )
    add('malformed-hop-state');
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
    const differences = [
      ['url', row.url, hop.url],
      ['method', row.method, hop.method],
      ['status', row.status, hop.status],
      ['state', row.state, hop.state],
      ['resourceType', row.resource_type, hop.resourceType],
      ['fromDiskCache', row.from_disk_cache, hop.fromDiskCache],
      ['fromServiceWorker', row.from_service_worker, hop.fromServiceWorker],
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
