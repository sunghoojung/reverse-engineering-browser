import {open} from 'node:fs/promises';

export const NETLOG_MAX_BYTES = 64 * 1024 * 1024;
const MAX_EVENTS = 500000,
  MAX_OPERATIONS = 256,
  MAX_ROWS = 100000;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const token = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);
const version = (value) =>
  typeof value === 'string' && /^\d{1,4}\.\d{1,4}\.\d{1,6}\.\d{1,6}$/.test(value);
export class NetlogInputError extends Error {
  constructor(code) {
    super(code);
    this.name = 'NetlogInputError';
    this.code = code;
  }
}
// Never return filesystem errors, JSON excerpts, headers, URLs, or clientInfo.
export async function readBoundedNetlog(path, maxBytes = NETLOG_MAX_BYTES) {
  if (!integer(maxBytes) || maxBytes < 1 || maxBytes > NETLOG_MAX_BYTES)
    throw new NetlogInputError('invalid-byte-bound');
  let file;
  try {
    file = await open(path, 'r');
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > maxBytes) throw new NetlogInputError('netlog-size-bound');
    const bytes = Buffer.alloc(maxBytes + 1);
    let size = 0;
    while (size < bytes.length) {
      const read = await file.read(bytes, size, bytes.length - size, null);
      if (!read.bytesRead) break;
      size += read.bytesRead;
    }
    if (size > maxBytes) throw new NetlogInputError('netlog-size-bound');
    let netlog;
    try {
      netlog = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes.subarray(0, size)));
    } catch {
      throw new NetlogInputError('netlog-truncated-or-invalid-json');
    }
    return {netlog, byteLength: size};
  } catch (error) {
    if (error instanceof NetlogInputError) throw error;
    throw new NetlogInputError('netlog-read-failed');
  } finally {
    if (file) await file.close().catch(() => {});
  }
}

// Chromium URL_REQUEST_START_JOB is repeated for redirects and intercepted jobs.
// Constants resolve enums per log; no numeric event IDs are stable assumptions.
// https://chromium.googlesource.com/chromium/src/+/main/net/log/net_log_event_type_list.h
// https://chromium.googlesource.com/chromium/src/+/main/net/log/net_log_util.cc
// FileNetLogObserver can silently drop queued events; agreement is corroboration,
// never a proof of losslessness. Raw logs must remain local to the disposable run.
export function crosscheckNetlog(netlog, options = {}) {
  const {
    manifest,
    receipts,
    referenceHops,
    browserVersion,
    capture,
    origins = manifest?.origins,
  } = options;
  const result = {
    schemaVersion: 1,
    state: 'incomplete',
    completenessClaim: false,
    browserVersion: version(browserVersion) ? browserVersion : null,
    limitations: [
      'job-starts-are-not-wire-requests',
      'netlog-queue-loss-not-independently-detectable',
      'websocket-frames-outside-url-request-check',
      'websocket-handshakes-outside-http-reference-check',
    ],
    failures: [],
    operations: [],
    ignoredEvents: 0,
  };
  const fail = (code) => {
    if (!result.failures.includes(code)) result.failures.push(code);
    return result;
  };
  if (!object(netlog) || !object(netlog.constants) || !Array.isArray(netlog.events))
    return fail('unsupported-netlog-shape');
  if (netlog.events.length > MAX_EVENTS) return fail('event-bound-exceeded');
  const c = netlog.constants;
  if (c.logFormatVersion !== 1) return fail('unsupported-netlog-format');
  if (!version(browserVersion) || c.clientInfo?.version !== browserVersion)
    return fail('browser-version-unverified');
  for (const [name, required] of [
    ['logEventTypes', ['URL_REQUEST_START_JOB']],
    ['logSourceType', ['URL_REQUEST']],
    ['logEventPhase', ['PHASE_BEGIN', 'PHASE_END', 'PHASE_NONE']],
  ]) {
    const map = c[name];
    if (
      !object(map) ||
      Object.keys(map).length > 4096 ||
      !Object.values(map).every(integer) ||
      new Set(Object.values(map)).size !== Object.keys(map).length ||
      !required.every((key) => integer(map[key]))
    )
      return fail('unsupported-netlog-constants');
  }
  if (!object(capture) || capture.cleanShutdown !== true || capture.startedBeforeFixture !== true)
    return fail('capture-window-unverified');
  if (
    capture.limitReached !== false ||
    !integer(capture.byteLength) ||
    !integer(capture.limitBytes) ||
    capture.limitBytes > NETLOG_MAX_BYTES ||
    capture.byteLength >= capture.limitBytes
  )
    return fail('capture-size-or-truncation-unverified');
  if (
    !object(manifest) ||
    !token(manifest.runId) ||
    !Array.isArray(manifest.operations) ||
    !manifest.operations.length ||
    manifest.operations.length > MAX_OPERATIONS
  )
    return fail('unsupported-fixture-manifest');
  if (!Array.isArray(origins) || !origins.length || origins.length > 4)
    return fail('owned-origins-unverified');
  const allowed = new Set();
  for (const origin of origins) {
    try {
      const u = new URL(origin);
      if (
        !['http:', 'https:'].includes(u.protocol) ||
        !['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname) ||
        u.origin !== origin
      )
        throw new Error();
      allowed.add(origin);
    } catch {
      return fail('owned-origins-unverified');
    }
  }
  const operations = new Map(),
    operationIds = new Set();
  const key = (id, method) => `${id} ${method}`;
  for (const op of manifest.operations) {
    const parts = typeof op?.operationId === 'string' ? op.operationId.split(':') : [];
    if (
      !object(op) ||
      parts.length !== 3 ||
      parts[0] !== manifest.runId ||
      parts[1] !== op.caseId ||
      !token(parts[2]) ||
      !token(op.caseId) ||
      typeof op.method !== 'string' ||
      !/^[A-Z]{1,16}$/.test(op.method) ||
      !integer(op.expectedReceipts) ||
      op.expectedReceipts > MAX_ROWS ||
      typeof op.path !== 'string' ||
      op.path !== `/reb-fixture/${manifest.runId}/${op.caseId}/${parts[2]}` ||
      operations.has(key(op.operationId, op.method))
    )
      return fail('unsupported-fixture-operation');
    operationIds.add(op.operationId);
    operations.set(key(op.operationId, op.method), {
      op,
      sources: new Set(),
      jobs: 0,
      receipts: 0,
      reference: 0,
    });
  }
  const identity = (raw, method) => {
    if (typeof raw !== 'string' || raw.length > 16384) return null;
    try {
      const u = new URL(raw);
      const origin = u.origin.replace(/^ws:/, 'http:').replace(/^wss:/, 'https:');
      if (!allowed.has(origin) || u.username || u.password) return null;
      const values = u.searchParams.getAll('op');
      if (values.length !== 1) return null;
      const parts = values[0].split(':');
      if (parts.length !== 3 || parts[0] !== manifest.runId) return null;
      const row = operations.get(key(values[0], method));
      return row && parts[1] === row.op.caseId && u.pathname === row.op.path ? row : null;
    } catch {
      return null;
    }
  };
  if (
    !Array.isArray(receipts) ||
    !Array.isArray(referenceHops) ||
    receipts.length > MAX_ROWS ||
    referenceHops.length > MAX_ROWS
  )
    return fail('unsupported-comparison-rows');
  for (const receipt of receipts) {
    if (!object(receipt)) return fail('unsupported-receipt-row');
    if (receipt.kind === 'websocket-frame') continue;
    const row = identity(receipt.url, receipt.method);
    if (!row) {
      if (operationIds.has(receipt.operationId)) return fail('receipt-identity-mismatch');
      continue;
    }
    if (receipt.operationId !== row.op.operationId || receipt.method !== row.op.method)
      return fail('receipt-identity-mismatch');
    row.receipts++;
  }
  for (const hop of referenceHops) {
    if (!object(hop)) return fail('unsupported-reference-row');
    const row = identity(hop.url, hop.method);
    if (row && hop.method === row.op.method) row.reference++;
  }
  const eventTypes = new Set(Object.values(c.logEventTypes)),
    sources = new Set(Object.values(c.logSourceType)),
    phases = new Set(Object.values(c.logEventPhase));
  for (const event of netlog.events) {
    if (
      !object(event) ||
      !eventTypes.has(event.type) ||
      !phases.has(event.phase) ||
      !object(event.source) ||
      !sources.has(event.source.type) ||
      !integer(event.source.id)
    )
      return fail('unsupported-event-shape');
    if (
      event.type !== c.logEventTypes.URL_REQUEST_START_JOB ||
      event.phase !== c.logEventPhase.PHASE_BEGIN
    ) {
      result.ignoredEvents++;
      continue;
    }
    if (
      event.source.type !== c.logSourceType.URL_REQUEST ||
      !object(event.params) ||
      typeof event.params.url !== 'string' ||
      typeof event.params.method !== 'string'
    )
      return fail('unsupported-job-start-shape');
    const row = identity(event.params.url, event.params.method);
    if (!row) {
      result.ignoredEvents++;
      continue;
    }
    if (event.params.method !== row.op.method) return fail('job-method-mismatch');
    row.jobs++;
    row.sources.add(event.source.id);
  }
  for (const {op, sources, jobs, receipts: wire, reference} of operations.values()) {
    const issues = [];
    if (wire !== op.expectedReceipts) issues.push('fixture-receipt-count-mismatch');
    if (wire > 0 && jobs === 0) issues.push('wire-operation-missing-netlog');
    if (op.kind !== 'websocket-handshake' && wire > 0 && reference === 0)
      issues.push('wire-operation-missing-reference');
    // Multiple source IDs and starts are evidence, not a request denominator.
    result.operations.push({
      operationId: op.operationId,
      caseId: op.caseId,
      method: op.method,
      wireReceipts: wire,
      referenceHops: reference,
      urlRequestSources: sources.size,
      jobStarts: jobs,
      issues,
    });
  }
  result.state = result.operations.some((row) => row.issues.length) ? 'mismatch' : 'corroborated';
  return result;
}
