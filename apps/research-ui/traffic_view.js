/* Native Traffic rows carry method, host, status, type and lifecycle timing.
 * Content capture sessions add the URL path and query, a bounded request body
 * (protocol/native-network-v2.md) shown by traffic_payload.js, and header blocks
 * shown by traffic_headers.js (v3); every session records the body's length,
 * type and digest. Response bodies have their own tabs (traffic_response.js),
 * and search never reads headers. */
// The last path segment plus the query, as DevTools names a request.
function trafficShortName(target) {
  const at = target.indexOf('?');
  const path = at < 0 ? target : target.slice(0, at), query = at < 0 ? '' : target.slice(at);
  const trimmed = path.endsWith('/') ? path.slice(0, -1) : path;
  return `${trimmed ? path.slice(trimmed.lastIndexOf('/') + 1) : ''}${query}`;
}

// The host is a sublabel only beside a captured path; a root path is named by its host.
function trafficTargetParts(request) {
  const target = String(request?.path ?? '').trim();
  if (request?.hostOnly) return {name: target || 'Unknown host', host: ''};
  const more = request?.urlTruncated ? '…' : '';
  const named = (pathAndQuery, host) => {
    const name = trafficShortName(pathAndQuery);
    return name ? {name: `${name}${more}`, host} : {name: `${host || pathAndQuery}${more}`, host: ''};
  };
  // A native target is shown exactly as captured; reparsing would re-escape it.
  if (typeof request?.target === 'string') return named(request.target, request.host ?? '');
  if (request?.targetKind === 'path') {
    const slash = target.indexOf('/');
    return slash > 0 ? named(target.slice(slash), target.slice(0, slash)) : {name: target, host: ''};
  }
  try {
    const url = new URL(target);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) throw new TypeError('Not a network URL');
    return named(`${url.pathname || '/'}${url.search}`, url.host);
  } catch {
    return {name: target || 'Unidentified request', host: ''};
  }
}

// The host a row is grouped and filtered by; the request index applies the same rule.
function trafficRequestDomain(request) {
  if (!request) return 'unknown';
  if (request.origin === 'sample') return 'checkout.acme.test';
  const target = String(request.path ?? '').trim();
  if (!target || target === 'Unidentified network event') return 'unknown';
  try {
    return new URL(target).host || 'unknown';
  } catch {
    return target.replace(/^\/\//, '').split('/')[0] || 'unknown';
  }
}

const TRAFFIC_BODY_KIND_LABELS = Object.freeze({none: 'None', bytes: 'In-memory bytes', file: 'File upload',
  data_pipe: 'Blob or data pipe', chunked_data_pipe: 'Streaming upload', mixed: 'Mixed parts',
  unknown: 'Unrecognized part'});

function trafficByteCount(value) {
  const count = BigInt(value);
  return `${count.toLocaleString('en-US')} ${count === 1n ? 'byte' : 'bytes'}`;
}

// A budget a refusal met: its size when the session context names it
// (state.sessionContentLimits, app.js), and the start panel control that sets
// it for the next session.
function trafficBudgetUsed(name, key, control) {
  const budget = typeof state === 'undefined' ? null : state?.sessionContentLimits?.[key] ?? null;
  return `this session had used its ${budget ? `${budget.toLocaleString('en-US')} MiB ` : ''}${name}. `
    + `Raise ${control} in New Live Session… for the next session.`;
}

// What happened to the bytes, in the record's own terms.
function trafficBodyCapture(body) {
  if (body === null || body === undefined) {
    return 'No body record for this request. The capture may predate request body recording, or the record left the retained window.';
  }
  if (body.malformed) return 'The body record is malformed and was not interpreted.';
  const kind = TRAFFIC_BODY_KIND_LABELS[body.kind] ?? 'Unrecognized part';
  return {
    no_body: 'No request body.',
    empty: 'Empty body (0 bytes).',
    metadata_only: 'Not retained: content capture was off for this session. Length, type and digest are recorded.',
    captured: 'Retained in full.',
    captured_truncated: `Retained prefix: ${trafficByteCount(body.capturedLength)} of ${trafficByteCount(body.bodyLength)}, truncated at the capture limit.`,
    not_captured_body_kind: `Not captured: the ${kind.toLowerCase()} parts were described, not read.`,
    not_captured_artifact_unavailable: 'Not captured: the artifact channel was unavailable.',
    not_captured_transfer_refused: 'Not captured: the bounded in-flight memory or artifact transfer queue refused it.',
    not_captured_url: 'Not captured: the URL is not HTTP(S), or in older captures longer than 8 KiB.',
    not_captured_session_budget: `Not captured: ${trafficBudgetUsed('request content budget', 'request_content_budget_mib', 'Request content budget')}`,
    not_captured_credential_form: 'Not captured: password form submission. Bytes and digest are withheld.',
    not_captured_read_incomplete: 'Not captured: a file, blob or stream part was not read whole. It changed or failed, the upload was cancelled, or capture ended first.'
  }[body.state] ?? 'Unknown capture state.';
}

function trafficBodyRows(body, artifact = null) {
  if (!body || body.malformed) return [];
  // The manifest digest covers the retained bytes when the record carries none (over its 4 MiB bound).
  const stored = body.sha256 ? null : artifact?.sha256 ?? null;
  const digest = body.sha256 ?? stored ?? (body.state === 'no_body' ? 'No body'
    : body.state === 'not_captured_credential_form' ? 'Withheld for a password form'
      : body.digestSizeLimit ? `Not computed: the body exceeds the ${body.read ? '16' : '4'} MiB digest bound`
        : body.read ? 'Not computed: the read did not finish'
          : 'Not computed: file, blob or stream parts were not read');
  return [
    ['Content type', body.contentType ?? (body.contentTypeOmitted ? 'Sent, but not a bounded media type; not recorded' : 'Not sent'),
      body.contentType ? 'value' : 'prose'],
    ['Body length', body.state === 'no_body' ? 'No body'
      : `${trafficByteCount(body.bodyLength)}${!body.lengthPartial ? '' : body.read ? ' read before the read stopped' : ' in memory; file, blob and stream parts are not counted'}`,
    body.state === 'no_body' ? 'prose' : 'value'],
    ['SHA-256', digest, body.sha256 || stored ? 'value' : 'prose'],
    ...(stored ? [['Digest source', `Artifact manifest, over the ${trafficByteCount(artifact.byte_size)} retained; the request record carries no digest.`, 'prose']] : []),
    ['Body kind', `${TRAFFIC_BODY_KIND_LABELS[body.kind] ?? 'Unrecognized part'} · ${body.elementCount} ${body.elementCount === 1 ? 'part' : 'parts'}`, 'value']
  ];
}

// The retained bytes, when there are any. Captured text is only ever assigned
// to textContent, never parsed as markup.
function trafficBodyContent(body, view) {
  if (!body || body.malformed || !['captured', 'captured_truncated'].includes(body.state)) return null;
  if (!view || view.status === 'loading') return {note: 'Loading the retained body…'};
  if (view.status === 'refused') {
    return {note: view.reason === 'sensitive_capture_disabled'
      ? 'The artifact receiver refused it: the session receiver was not started for sensitive capture.'
      : `The artifact receiver did not retain it (${view.reason || 'unknown reason'}).`};
  }
  if (view.status === 'missing') {
    return {note: view.unknown ? 'The body artifact is not in the scanned range of the artifact manifest, so whether it was retained is unknown.'
      : 'The body artifact is not in the artifact manifest: its acknowledgment is pending.'};
  }
  if (view.status === 'unavailable') return {note: 'Retained bodies are read from the local backend, which this view does not have.'};
  if (view.status === 'error') {
    return {note: `The retained body could not be read: ${view.error}.${view.retryable ? ' It is read again on the next refresh.' : ''}`};
  }
  const notes = [];
  if (body.state === 'captured_truncated') notes.push(`Prefix only: ${trafficByteCount(body.capturedLength)} of ${trafficByteCount(body.bodyLength)}.`);
  const more = view.complete === false;
  if (more) notes.push(`Showing the first ${trafficByteCount(view.loaded)} of ${trafficByteCount(view.total)} retained.`);
  if (view.moreError) notes.push(`The next range could not be read: ${view.moreError}.`);
  if (view.lossy) notes.push('Not valid UTF-8; shown with replacement characters.');
  if (!view.verified) notes.push(more ? 'The local backend checked the retained digest; this view rechecks it once every byte is shown.'
    : 'The retained digest could not be rechecked in this view.');
  return {text: view.text, note: notes.join(' '), url: view.url, more: more ? view.key : null, loadingMore: Boolean(view.loadingMore)};
}

// Request artifacts are read by ID (get_artifacts filters), not from the first 50,000
// catalog records. A read that stopped at its scan budget is unknown, not absent.
const TRAFFIC_ARTIFACT_LOOKUP_RETRY_MS = 5000;
const TRAFFIC_ARTIFACT_LOOKUP_ENTRIES = 256;
const TRAFFIC_ARTIFACT_LOOKUP_PAGES = 8;
function createTrafficArtifactLookup({fetcher = (input, init) => fetch(input, init), onChange = () => {}, valid = () => true,
  refusalText = () => ''} = {}) {
  const entries = new Map();
  const signal = () => AbortSignal.timeout(10000);
  async function read(record, after) {
    const {sessionId: session_id, artifactId: artifact_id} = record;
    let cursor = '0', complete = false;
    for (let page = 0; page < TRAFFIC_ARTIFACT_LOOKUP_PAGES && !complete; page += 1) {
      const response = await fetcher(`/api/artifacts?${new URLSearchParams({artifact_id, session_id, after: cursor, limit: '1'})}`, {cache: 'no-store', signal: signal()});
      if (!response.ok) throw new Error(`the artifact store returned ${response.status}`);
      const body = await response.json();
      if (!valid(body) || !body.query) throw new Error('the artifact store answer is malformed');
      if (body.artifacts.length) return {status: 'found', artifact: body.artifacts[0]};
      if (body.query.budget_exhausted) cursor = String(body.query.next_after);
      else complete = true;
    }
    // A receiver refusal arrives soon after its creator record, so one page from the request's first record is enough.
    const refusals = await fetcher(`/api/events?${new URLSearchParams({type: 'artifact_capture_failed', artifact_id, session_id, after, limit: '1'})}`, {cache: 'no-store', signal: signal()});
    if (!refusals.ok) throw new Error(`the event store returned ${refusals.status}`);
    const body = await refusals.json();
    if (!Array.isArray(body?.events) || !body.query) throw new Error('the event store answer is malformed');
    if (body.events.length) return {status: 'refused', reason: refusalText(body.events[0])};
    return {status: complete && !body.query.budget_exhausted ? 'absent' : 'unknown'};
  }
  return {
    // The manifest record for a record's artifact ID, read once per retry interval.
    lookup(record, after = '0') {
      const key = `${record.sessionId}:${record.artifactId}`;
      const known = entries.get(key);
      const retry = known && ['absent', 'unknown'].includes(known.status) && Date.now() >= known.retryAt;
      if (known && !retry) return known.status === 'loading' && known.previous ? known.previous : known;
      const entry = {status: 'loading', previous: known};
      entries.delete(key);
      entries.set(key, entry);
      while (entries.size > TRAFFIC_ARTIFACT_LOOKUP_ENTRIES) entries.delete(entries.keys().next().value);
      read(record, after).then(result => Object.assign(entry, result), error => Object.assign(entry, {status: 'unknown', error: String(error?.message ?? error)}))
        .finally(() => {
          entry.retryAt = Date.now() + TRAFFIC_ARTIFACT_LOOKUP_RETRY_MS;
          onChange();
        });
      return known ?? entry;
    },
    clear: () => entries.clear()
  };
}

// The Request URL row: the full target once retained bytes are loaded, else
// the captured prefix and what happened to the rest.
const TRAFFIC_TARGET_RETENTION = Object.freeze({
  not_retained_artifact_unavailable: 'the artifact channel was unavailable',
  not_retained_transfer_refused: 'the bounded in-flight memory or artifact transfer queue refused it',
  not_retained_url: 'the URL has no HTTP(S) or WebSocket origin or exceeds the URL limit'
});
function trafficRequestUrl(request, view) {
  if (request.hostOnly) return `${request.path} (${request.schemeOnly ? 'path' : 'host only; path and query'} not captured)`;
  if (!request.urlTruncated) return request.path;
  if (view?.status === 'ready' && view.complete) return `${view.url}${view.text}`;
  const prefix = `${request.path}… (truncated; the original path and query are ${request.targetLength} bytes`;
  const retention = request.fullTarget?.retention;
  if (retention === 'retained') {
    return `${prefix}; ${!view || view.status === 'loading' ? 'loading the retained full target'
      : view.status === 'refused' ? `the artifact receiver did not retain the full target (${view.reason || 'unknown reason'})`
        : view.status === 'missing' ? `the full target artifact is ${view.unknown ? 'not in the scanned range of the artifact manifest' : 'not in the artifact manifest'}`
          : view.status === 'error' ? `the full target could not be read: ${view.error}` : 'the full target is not readable here'})`;
  }
  if (retention === 'not_retained_session_budget') {
    return `${prefix}; the full target was not retained: ${trafficBudgetUsed('request content budget', 'request_content_budget_mib', 'Request content budget').replace(/\.$/, '')})`;
  }
  return TRAFFIC_TARGET_RETENTION[retention] ? `${prefix}; the full target was not retained: ${TRAFFIC_TARGET_RETENTION[retention]})` : `${prefix})`;
}

const TRAFFIC_TYPE_LABELS = Object.freeze({xhr: 'Fetch/XHR', doc: 'Document', css: 'CSS', js: 'Script',
  font: 'Font', img: 'Image', media: 'Media', socket: 'WebSocket', wasm: 'Wasm', other: 'Other'});
function trafficTypeLabel(type) {
  return Object.hasOwn(TRAFFIC_TYPE_LABELS, type) ? TRAFFIC_TYPE_LABELS[type] : 'Other';
}

// The verb's color class: requests that carry a body or change state stand
// out from the reads around them.
function trafficMethodClass(method) {
  const verb = String(method ?? '').toUpperCase();
  return verb === 'DELETE' ? 'delete' : ['POST', 'PUT', 'PATCH'].includes(verb) ? 'mutating' : 'safe';
}

// Keep table labels compact; filters and tooltips retain the full type names.
const TRAFFIC_TABLE_TYPE_LABELS = Object.freeze({xhr: 'XHR/F', doc: 'Doc', css: 'CSS', js: 'JS',
  font: 'Font', img: 'Img', media: 'Media', socket: 'WS', wasm: 'Wasm'});
function trafficTableTypeLabel(type) {
  return Object.hasOwn(TRAFFIC_TABLE_TYPE_LABELS, type) ? TRAFFIC_TABLE_TYPE_LABELS[type] : 'Other';
}

function trafficTimeLabel(time) {
  if (typeof time !== 'number' || !Number.isFinite(time)) return time === 'pending' ? '—' : String(time ?? '—');
  if (time < 1) return `${time.toFixed(2)} ms`;
  if (time < 100) return `${time.toFixed(1)} ms`;
  if (time < 1000) return `${Math.round(time)} ms`;
  return `${(time / 1000).toFixed(2)} s`;
}

// DevTools-style decimal units; tooltips keep the exact byte count.
function trafficBytesLabel(bytes) {
  if (bytes < 1000) return `${bytes} B`;
  const [value, unit] = bytes < 1e6 ? [bytes / 1e3, 'kB'] : bytes < 1e9 ? [bytes / 1e6, 'MB'] : [bytes / 1e9, 'GB'];
  return `${value < 100 ? value.toFixed(1) : Math.round(value)} ${unit}`;
}

// Transferred is the terminal record's encoded_data_length, resource its decoded_body_length.
function trafficSizeCell(request) {
  const exact = value => `${value.toLocaleString('en-US')} ${value === 1 ? 'byte' : 'bytes'}`;
  const transfer = Number.isSafeInteger(request?.transferSize) ? request.transferSize : null;
  const resource = Number.isSafeInteger(request?.resourceSize) ? request.resourceSize : null;
  const served = request?.memoryCache ? '(memory cache)' : request?.fromServiceWorker ? '(service worker)'
    : request?.fromCache ? '(disk cache)' : null;
  const notes = {'(memory cache)': request?.staticData
    ? 'Decoded in the renderer from a data: URL or an MHTML archive, so no request was made.'
    : 'Served from the memory cache: Blink reused a resource it held, so no request was made.',
  '(service worker)': 'Served by a service worker.', '(disk cache)': 'Served from the HTTP cache.'};
  const lines = [served ? notes[served] : '',
    transfer === null ? 'Transferred: no completion record.' : `Transferred: ${exact(transfer)}.`,
    resource === null ? 'Resource: not recorded.' : `Resource: ${exact(resource)}.`].filter(Boolean);
  return {transfer: served ?? (transfer === null ? '—' : trafficBytesLabel(transfer)), served: Boolean(served),
    resource: resource === null ? '' : trafficBytesLabel(resource), title: lines.join('\n')};
}

const TRAFFIC_INITIATOR_LABELS = Object.freeze({script: 'Script', parser: 'Parser', renderer: 'Renderer', worker: 'Service worker',
  browser: 'Browser', worker_script: 'Worker script', worker_loader: 'Worker loader', worker_unwalked: 'Worker, not walked'});
const TRAFFIC_INITIATOR_TITLES = Object.freeze({
  script: 'JavaScript or WebAssembly was running when the renderer started this request. The Initiator tab shows its call stack.',
  parser: 'No script was on the stack when the renderer started this request: the HTML parser, a preload, or a deferred start.',
  renderer: 'A renderer started this request. Parser and script starts are not told apart without an initiator stack.',
  worker: 'A service worker started this request.',
  worker_script: 'JavaScript or WebAssembly was running in a dedicated, shared or service worker when it started this request. The Initiator tab shows its call stack.',
  worker_loader: 'A dedicated, shared or service worker started this request with no script on its stack: its script or module loader, or a deferred start.',
  worker_unwalked: 'A dedicated, shared or service worker started this request, but the renderer\'s 32 worker stack tables were in use, so no stack was walked.',
  browser: 'The browser process started this request, such as a navigation; no renderer record names it.'});
function trafficInitiatorLabel(request) {
  return Object.hasOwn(TRAFFIC_INITIATOR_LABELS, request?.initiator ?? '') ? TRAFFIC_INITIATOR_LABELS[request.initiator] : null;
}
// A script start's resolved innermost frame (protocol/request-index-v1.md), named file:line as DevTools does.
function trafficInitiatorFrame(request) {
  const frame = request?.initiatorFrame;
  if (frame?.status !== 'resolved') return null;
  const file = typeof requestStackFile === 'function' ? requestStackFile(frame.url) : String(frame.url ?? '');
  const line = frame.line ? `:${frame.line}` : '';
  return {label: `${file}${line}`, title: `${frame.url}${line}${frame.column ? `:${frame.column}` : ''}` +
    `${frame.function_name ? ` in ${frame.function_name}` : ''}. The Initiator tab shows the call stack.`};
}

// Verified against net/base/net_error_list.h at the pinned Chromium.
const TRAFFIC_NET_ERRORS = Object.freeze({'-2': 'FAILED', '-3': 'ABORTED', '-6': 'FILE_NOT_FOUND', '-7': 'TIMED_OUT',
  '-10': 'ACCESS_DENIED', '-20': 'BLOCKED_BY_CLIENT', '-21': 'NETWORK_CHANGED', '-22': 'BLOCKED_BY_ADMINISTRATOR',
  '-27': 'BLOCKED_BY_RESPONSE', '-30': 'BLOCKED_BY_CSP', '-32': 'BLOCKED_BY_ORB', '-100': 'CONNECTION_CLOSED',
  '-101': 'CONNECTION_RESET', '-102': 'CONNECTION_REFUSED', '-103': 'CONNECTION_ABORTED', '-104': 'CONNECTION_FAILED',
  '-105': 'NAME_NOT_RESOLVED', '-106': 'INTERNET_DISCONNECTED', '-107': 'SSL_PROTOCOL_ERROR', '-109': 'ADDRESS_UNREACHABLE',
  '-118': 'CONNECTION_TIMED_OUT', '-137': 'NAME_RESOLUTION_FAILED', '-200': 'CERT_COMMON_NAME_INVALID',
  '-201': 'CERT_DATE_INVALID', '-202': 'CERT_AUTHORITY_INVALID', '-206': 'CERT_REVOKED', '-300': 'INVALID_URL',
  '-301': 'DISALLOWED_URL_SCHEME', '-302': 'UNKNOWN_URL_SCHEME', '-310': 'TOO_MANY_REDIRECTS', '-311': 'UNSAFE_REDIRECT',
  '-312': 'UNSAFE_PORT', '-320': 'INVALID_RESPONSE', '-324': 'EMPTY_RESPONSE', '-330': 'CONTENT_DECODING_FAILED',
  '-337': 'HTTP2_PROTOCOL_ERROR', '-355': 'INCOMPLETE_CHUNKED_ENCODING', '-356': 'QUIC_PROTOCOL_ERROR',
  '-400': 'CACHE_MISS', '-501': 'INSECURE_RESPONSE'});
function trafficNetError(code) {
  const key = String(code);
  return Object.hasOwn(TRAFFIC_NET_ERRORS, key) ? `net::ERR_${TRAFFIC_NET_ERRORS[key]} (${key})` : `net error ${key}`;
}

// Pending, Failed and a renderer-only row read differently; 3xx, 4xx and 5xx have their own colors.
function trafficStatusCell(request) {
  const code = Number(request.status);
  if (request.failed) {
    return {text: 'Failed', className: 'status-error', title: request.errorCode
      ? `Failed: ${trafficNetError(request.errorCode)}.` : 'Request failed. Inspect the retained response state for details.'};
  }
  if (request.interrupted) {
    return {text: String(request.status), className: 'status-neutral', title: 'Native proxy observation ended; final network outcome is unavailable.'};
  }
  if (request.endLost) {
    return {text: 'End lost', className: 'status-neutral status-unobserved',
      title: 'A service worker ended this request without a response, but the renderer had already reused the slot that held its start, so its outcome was not recorded.'};
  }
  if (request.status === 'finished') {
    return {text: 'Finished', className: 'status-neutral', title: request.staticData
      ? 'No HTTP status: archive resource. Blink decoded this MHTML archive resource itself and the load finished; an archive resource carries no HTTP status.'
      : 'No HTTP status: Blink reused a resource whose response carried none, and the load finished.'};
  }
  if (request.status === 'pending' && request.loaderObserved === false) {
    return {text: 'No loader', className: 'status-neutral status-unobserved',
      title: 'Browser loader not observed: only the renderer recorded this request, so its status, size and completion are unknown.'};
  }
  if (request.status === 'pending') {
    return {text: 'Pending', className: 'status-neutral', title: Number.isInteger(request.provisionalStatus)
      ? `Still pending. Response extra info reported HTTP ${request.provisionalStatus}; that is not a finished response.`
      : 'No terminal lifecycle event has been captured.'};
  }
  const className = !Number.isInteger(code) || code < 100 ? 'status-neutral' : code >= 500 ? 'status-error status-server'
    : code >= 400 ? 'status-error status-client' : code >= 300 ? 'status-redirect' : code >= 200 ? 'status-ok' : 'status-neutral';
  // Headers arrived; the code stands while the body is still in flight, and Time reads a dash.
  return {text: String(request.status), className,
    title: `HTTP status ${request.status}${request.time === 'pending' ? '. No terminal record yet.' : ''}`};
}

// Bar geometry in percent of the scale, from recorded timestamps only. A
// pending request runs to the end of the scale.
function trafficWaterfall(request, scale) {
  const first = request?.firstTimestamp, last = request?.lastTimestamp;
  if (!scale || typeof first !== 'bigint' || typeof last !== 'bigint' || scale.end <= scale.start) return null;
  const pending = request.time === 'pending';
  const end = pending && scale.end > last ? scale.end : last;
  const span = Number(scale.end - scale.start);
  const at = value => Math.max(0, Math.min(100, Number(value - scale.start) * 100 / span));
  const response = request.responseTimestamp;
  const split = typeof response === 'bigint' && response >= first && response <= end ? response : null;
  const left = at(first), right = at(end);
  return {left, width: right - left, wait: (split === null ? right : at(split)) - left, pending,
    outside: last < scale.start || first > scale.end, split};
}

function trafficWaterfallTitle(request, scale) {
  const geometry = trafficWaterfall(request, scale);
  if (!geometry) return 'No timestamps to place on the waterfall.';
  const ms = nanoseconds => trafficTimeLabel(Number(nanoseconds) / 1e6);
  const first = request.firstTimestamp, origin = scale.origin ?? scale.start;
  const parts = [`Started ${first >= origin ? ms(first - origin) : `-${ms(origin - first)}`} after the first request`];
  if (geometry.split !== null) parts.push(`to response start ${ms(geometry.split - first)}`, `response ${ms(request.lastTimestamp - geometry.split)}`);
  parts.push(geometry.pending ? 'still pending' : `total ${ms(request.lastTimestamp - first)}`);
  return `${parts.join(' · ')}${geometry.outside ? ' · outside the selected time range' : ''}`;
}

// One 500-row block is read at a time; only its rows near the view are mounted, with spacers for the rest.
const TRAFFIC_ROW_LIMIT = 500;
const TRAFFIC_ROW_MARGIN = 100;
const TRAFFIC_ROW_OVERSCAN = 8;
// Rows mounted when the list has no measured height, such as while hidden.
const TRAFFIC_ROW_UNMEASURED = 40;
function trafficTimeValue(request) {
  if (typeof request.time === 'number' && Number.isFinite(request.time)) return request.time;
  const milliseconds = /^(\d+(?:\.\d+)?) ms$/.exec(String(request.time));
  return milliseconds && Number.isFinite(Number(milliseconds[1])) ? Number(milliseconds[1]) : null;
}
function trafficSortedRequests(requests, key = 'capture', direction = 1) {
  if (key === 'capture') return direction < 0 ? [...requests].reverse() : requests;
  const value = request => key === 'name' ? trafficTargetParts(request).name
    : key === 'time' ? trafficTimeValue(request)
      : key === 'status' ? /^\d+$/.test(String(request.status)) ? Number(request.status) : null
        : key === 'type' ? trafficTypeLabel(request.type)
          : key === 'size' ? Number.isSafeInteger(request.transferSize) ? request.transferSize : null
            : key === 'start' ? typeof request.firstTimestamp === 'bigint' ? request.firstTimestamp : null
              : key === 'initiator' ? trafficInitiatorLabel(request)
                : key === 'protocol' ? request.protocol ?? null : request.method;
  // Precompute URL/type keys once; stable ties retain evidence order.
  return requests.map((request, index) => ({request, index, value: value(request)})).sort((a, b) => {
    if (a.value === null || b.value === null) return a.value === b.value ? a.index - b.index : a.value === null ? 1 : -1;
    const comparison = typeof a.value === 'number' ? a.value - b.value
      : typeof a.value === 'bigint' ? (a.value < b.value ? -1 : a.value > b.value ? 1 : 0)
        : String(a.value).localeCompare(String(b.value));
    return comparison * direction || a.index - b.index;
  }).map(entry => entry.request);
}

function trafficWindow(requests, start, anchor = null) {
  const found = anchor === null ? -1 : requests.findIndex(request => request.id === anchor);
  const offset = Math.max(0, Math.min(found < 0 ? start : found, Math.max(0, requests.length - TRAFFIC_ROW_LIMIT)));
  return {start: offset, rows: requests.slice(offset, offset + TRAFFIC_ROW_LIMIT)};
}

function trafficRowHeight(container) {
  const height = container.querySelector('.request-row')?.offsetHeight;
  if (height > 0) container.dataset.rowHeight = String(height);
  return Number(container.dataset.rowHeight) || 28;
}

// Follows the viewport, not the block: a position the block does not hold
// mounts as a placeholder, so a scroll past a held block is never blank.
function trafficMountedRange(container, top, height, total) {
  const first = Math.floor(Math.max(0, top || 0) / height);
  const shown = Math.ceil((container.clientHeight || 0) / height) || TRAFFIC_ROW_UNMEASURED;
  const from = Math.max(0, Math.min(total, first - TRAFFIC_ROW_OVERSCAN));
  return {from, to: Math.max(from, Math.min(total, first + shown + TRAFFIC_ROW_OVERSCAN))};
}

function trafficRowsCover(container) {
  const block = container.trafficBlock;
  if (!block) return true;
  const height = trafficRowHeight(container), total = block.options.total ?? block.requests.length;
  const first = Math.floor((container.scrollTop || 0) / height);
  const last = first + (Math.ceil((container.clientHeight || 0) / height) || TRAFFIC_ROW_UNMEASURED);
  return Math.min(first, total) >= block.from && Math.min(last, total) <= block.to;
}

function remountTrafficRows(container) {
  const block = container.trafficBlock;
  if (block && !trafficRowsCover(container)) renderTrafficRows(container, block.requests, {...block.options, newIds: new Set()});
}

// Moves the read block only when the viewport nears one of its edges.
function trafficBlockStart(container, total, start) {
  const maximum = Math.max(0, total - TRAFFIC_ROW_LIMIT);
  const height = trafficRowHeight(container);
  const first = Math.floor((container.scrollTop || 0) / height);
  const last = first + Math.ceil((container.clientHeight || 0) / height);
  start = Math.min(start, maximum);
  if ((start === 0 || first >= start + TRAFFIC_ROW_MARGIN) &&
      (start >= maximum || last <= start + TRAFFIC_ROW_LIMIT - TRAFFIC_ROW_MARGIN)) return start;
  return Math.max(0, Math.min(maximum, first - 2 * TRAFFIC_ROW_MARGIN));
}

// A request index row (protocol/request-index-v1.md) in the Traffic row shape.
function trafficIndexRequest(row, origin) {
  return {id: row.id, path: row.path, method: row.method, status: row.status, time: row.time, type: row.type, origin,
    targetKind: row.target_kind, hostOnly: row.target_kind === 'host', failed: row.failed, interrupted: row.interrupted,
    tabId: row.tab_id, tabIds: row.tab_ids, extensionId: row.extension_id ?? null, operation: row.operation,
    tabLink: row.tab_link ?? null, tabReason: row.tab_reason ?? null, initiatorFrame: row.initiator_frame ?? null, tabLinkLabel: row.tab_link ? globalThis.RebRequestTabs?.linkLabel(row.tab_link) ?? '' : '', target: row.target, host: row.host, urlTruncated: row.url_truncated,
    targetLength: row.target_length, targetMalformed: row.target_malformed,
    firstTimestamp: BigInt(row.first_time_ns), lastTimestamp: BigInt(row.last_time_ns),
    transferSize: row.transfer_size, resourceSize: row.resource_size, fromCache: row.from_cache,
    fromServiceWorker: row.from_service_worker, memoryCache: row.memory_cache === true, staticData: row.static_data === true,
    raceNetwork: row.race_network === true, endLost: row.end_lost === true,
    // Index-only facts: every row's body case, and the row a reuse names with its body.
    responseBodyIndex: row.response_body ?? null, memoryCacheSource: row.memory_cache_source?.id ?? null,
    memoryCacheSourceRow: row.memory_cache_source ?? null,
    mimeType: row.mime_type, protocol: row.protocol,
    responseTimestamp: row.response_time_ns === null ? null : BigInt(row.response_time_ns), errorCode: row.error_code,
    loaderObserved: row.loader_observed, initiator: row.initiator, mainFrame: row.main_frame, browserInternal: row.browser_internal,
    events: [], details: [], indexRow: row};
}

// Native request failures and the Failed row label are not queue drops.
// Counting them must not write error_code or change dropped_connections.
function trafficRequestFailed(request) {
  return Boolean(request && typeof request === 'object' && (request.failed === true || request.status === 'failed'));
}

function trafficFailedRequestCount(requests) {
  if (!Array.isArray(requests)) return 0;
  let count = 0;
  for (const request of requests) if (trafficRequestFailed(request)) count += 1;
  return count;
}

function trafficFailedRequestNotice(requests) {
  const count = trafficFailedRequestCount(requests);
  return count > 0 ? `Failed requests: ${count}.` : '';
}

// Selection does not change row content, order or geometry. Keep keyboard
// movement independent of retained-body search and avoid layout reads/writes.
function renderTrafficRowSelection(container, selectedId) {
  const block = container.trafficBlock;
  if (block) {
    block.options = {...block.options, selectedId};
    const at = block.requests.findIndex(request => request?.id === selectedId);
    if (at >= 0) container.dataset.selectedPosition = String(block.start + at); else delete container.dataset.selectedPosition;
  }
  const rows = [...container.querySelectorAll('.request-row')].filter(row => row.dataset.requestId);
  const selectedVisible = rows.some(row => row.dataset.requestId === selectedId);
  rows.forEach((row, index) => {
    const selected = row.dataset.requestId === selectedId;
    const ariaSelected = String(selected);
    if (row.getAttribute('aria-selected') !== ariaSelected) row.setAttribute('aria-selected', ariaSelected);
    const tabIndex = selected || !selectedVisible && index === 0 ? 0 : -1;
    if (row.tabIndex !== tabIndex) row.tabIndex = tabIndex;
  });
}

// `requests` is the block from list position `start` of `total`; a missing entry is not loaded yet.
// `scale` ({start, end, origin} in nanoseconds) places the waterfall bars.
function renderTrafficRows(container, requests, options) {
  const {start = 0, total = requests.length, selectedId, newIds, onSelect, onKey, nameOf = () => null, pending = 'Loading…', scale = null} = options;
  requests = requests.slice(0, TRAFFIC_ROW_LIMIT);
  const scaleKey = scale ? `${scale.start}:${scale.end}:${scale.origin ?? ''}` : null;
  const previousRows = new Map([...container.querySelectorAll('.request-row')].map(row => [row.dataset.requestId, row]));
  const focused = document.activeElement;
  const focusedId = container.contains(focused) && focused !== container ? focused.dataset.requestId : null;
  const scrollTop = container.scrollTop || 0;
  const height = trafficRowHeight(container);
  // Away from the top, the first row in view stays in place when rows arrive above it.
  const anchor = scrollTop > 0 ? [...previousRows.values()].find(row => row.dataset.requestId && (Number(row.dataset.position) + 1) * height > scrollTop) : null;
  const anchorAt = anchor ? requests.findIndex(request => request?.id === anchor.dataset.requestId) : -1;
  const top = anchorAt >= 0 ? (start + anchorAt) * height - (Number(anchor.dataset.position) * height - scrollTop) : scrollTop;
  const {from, to} = trafficMountedRange(container, top, height, total);
  container.trafficBlock = {requests, options, start, from, to};
  const mounted = Array.from({length: to - from}, (_, index) => requests[from - start + index] ?? null);
  const selectedAt = requests.findIndex(request => request?.id === selectedId);
  if (selectedAt >= 0) container.dataset.selectedPosition = String(start + selectedAt); else delete container.dataset.selectedPosition;
  const selectedVisible = mounted.some(request => request?.id === selectedId);
  const firstLoaded = mounted.findIndex(Boolean);
  const rows = mounted.map((request, index) => {
    const position = from + index;
    if (!request) {
      const placeholder = trafficNode('div', 'request-row request-placeholder', pending);
      placeholder.setAttribute('aria-hidden', 'true');
      placeholder.dataset.position = String(position);
      placeholder.classList.toggle('is-striped', position % 2 === 1);
      return placeholder;
    }
    let row = previousRows.get(String(request.id));
    if (!row) {
      row = trafficNode('button', 'request-row'); row.type = 'button';
      row.setAttribute('role', 'option'); row.dataset.requestId = request.id;
      row.addEventListener('click', () => onSelect(row.dataset.requestId));
      row.addEventListener('keydown', onKey);
      row.addEventListener('animationend', () => row.classList.remove('is-new'));
      row.addEventListener('animationcancel', () => row.classList.remove('is-new'));
      if (newIds.has(request.id) && (typeof matchMedia !== 'function' || !matchMedia('(prefers-reduced-motion: reduce)').matches)) row.classList.add('is-new');
    }
    const researcherName = nameOf(request);
    const time = value => typeof value === 'bigint' ? String(value) : null;
    const key = JSON.stringify([request.path, request.method, request.status, request.time,
      request.type, request.origin, request.hostOnly, request.failed, request.targetKind, request.operation, researcherName,
      request.tabLinkLabel, request.transferSize, request.resourceSize, request.fromCache, request.fromServiceWorker,
      request.memoryCache, request.staticData, request.raceNetwork, request.endLost, request.mimeType, request.protocol,
      request.initiator, trafficInitiatorFrame(request)?.title, request.errorCode, request.loaderObserved, time(request.firstTimestamp), time(request.lastTimestamp),
      time(request.responseTimestamp), scaleKey]);
    // Reuse the row itself on lifecycle changes, preserving focus and its single
    // arrival animation. Unchanged rows do not rebuild captured text children.
    if (row.dataset.renderKey !== key) {
      row.dataset.renderKey = key;
      row.dataset.origin = request.origin;
      row.dataset.targetKind = request.targetKind ?? 'unknown';
      row.dataset.pending = String(request.status === 'pending' && !request.failed);
      // Resource kind and verb select the row's colors; the cells keep their text.
      row.dataset.type = Object.hasOwn(TRAFFIC_TYPE_LABELS, request.type) ? request.type : 'other';
      row.dataset.method = trafficMethodClass(request.method);
      const target = trafficTargetParts(request);
      const cell = (column, className, text, title) => {
        const node = trafficNode('span', className, text);
        node.dataset.column = column;
        if (title) node.title = title;
        return node;
      };
      const url = `${request.path}${request.urlTruncated ? '…' : ''}`;
      const name = cell('name', 'request-name', undefined, `${url}\n${trafficOriginLabel(request)} · ${request.method} · network · ${request.operation ?? 'network'} · request ${request.id}${request.tabLinkLabel ? ` · ${request.tabLinkLabel}` : ''}${request.tabReason ? ` · no tab: ${request.tabReason}` : ''}${request.hostOnly ? ' · URL path and query not captured' : request.urlTruncated ? ` · path and query truncated from ${request.targetLength} bytes` : ''}`);
      // A researcher name leads the cell; the captured path and host stay visible.
      if (researcherName) name.append(trafficNode('span', 'researcher-name', researcherName));
      const host = trafficNode('span', 'request-host', target.host);
      if (request.tabLinkLabel) host.append(trafficNode('span', 'request-tab-link', `${target.host ? ' · ' : ''}${request.tabLinkLabel}`));
      name.append(trafficNode('span', 'request-resource', target.name), host);
      const statusCell = trafficStatusCell(request);
      const status = cell('status', statusCell.className, statusCell.text, statusCell.title);
      const type = cell('type', 'request-type', trafficTableTypeLabel(request.type),
        `${trafficTypeLabel(request.type)}${request.mimeType ? ` · ${request.mimeType}` : ''}`);
      const protocol = cell('protocol', 'request-protocol', request.protocol ?? '—',
        request.protocol ? `Negotiated protocol (ALPN): ${request.protocol}` : 'No negotiated protocol recorded.');
      const initiatorLabel = trafficInitiatorLabel(request);
      const initiatorFrame = trafficInitiatorFrame(request);
      const initiator = cell('initiator', 'request-initiator', initiatorFrame?.label ?? initiatorLabel ?? '—',
        initiatorFrame?.title ?? (initiatorLabel ? TRAFFIC_INITIATOR_TITLES[request.initiator] : 'No versioned lifecycle record says who started this request.'));
      const sizeCell = trafficSizeCell(request);
      // A served row's label fills the default column; app.css shows its resource size once the column is widened.
      const size = cell('size', `request-size${sizeCell.served ? ' is-served' : ''}`, undefined, sizeCell.title);
      size.append(trafficNode('span', 'size-transfer', sizeCell.transfer));
      if (sizeCell.resource) size.append(trafficNode('span', 'size-resource', sizeCell.resource));
      const timeLabel = trafficTimeLabel(request.time);
      const timeCell = cell('time', 'request-time', timeLabel,
        request.time === 'pending' ? 'No terminal record yet.' : `${timeLabel} from the first to the last record.`);
      const waterfall = cell('waterfall', 'request-waterfall', undefined, trafficWaterfallTitle(request, scale));
      const geometry = trafficWaterfall(request, scale);
      if (geometry && !geometry.outside) {
        const bar = trafficNode('span', `waterfall-bar${geometry.pending ? ' is-pending' : ''}`);
        bar.style.left = `${geometry.left}%`;
        bar.style.width = `${geometry.width}%`;
        // The newest rows start at the end of the scale. Pull the 2 px minimum
        // bar back inside the cell, which clips anything past its edge.
        bar.style.marginLeft = `min(0px, calc(${100 - geometry.left}% - 2px))`;
        const wait = trafficNode('span', 'waterfall-wait');
        wait.style.width = `${geometry.width > 0 ? geometry.wait * 100 / geometry.width : 100}%`;
        bar.append(wait);
        waterfall.append(bar);
      }
      row.replaceChildren(name, status, type, cell('method', 'request-method', request.method, request.method),
        protocol, initiator, size, timeCell, waterfall);
      row.setAttribute('aria-label', `${researcherName ? `${researcherName} (researcher name). ` : ''}${trafficOriginLabel(request)} ${request.hostOnly ? 'host-only metadata' : 'request'}: ${request.method} ${request.path}, ${status.textContent}, ${sizeCell.transfer}, ${timeLabel}, ${request.operation ?? 'network'}, request ${request.id}`);
    }
    row.setAttribute('aria-selected', String(request.id === selectedId));
    // Positions in the whole list, not the mounted rows.
    if (row.dataset.position !== String(position)) {
      row.dataset.position = String(position);
      row.setAttribute('aria-posinset', String(position + 1));
    }
    if (row.getAttribute('aria-setsize') !== String(total)) row.setAttribute('aria-setsize', String(total));
    row.classList.toggle('is-striped', position % 2 === 1);
    row.tabIndex = request.id === selectedId || !selectedVisible && index === firstLoaded ? 0 : -1;
    return row;
  });
  const spacers = container.trafficSpacers ??= [0, 1].map(() => {
    const spacer = trafficNode('div', 'request-spacer');
    spacer.setAttribute('aria-hidden', 'true');
    return spacer;
  });
  const below = Math.max(0, total - to);
  spacers[0].style.height = `${from * height}px`;
  spacers[1].style.height = `${below * height}px`;
  const nodes = [...(from > 0 ? [spacers[0]] : []), ...rows, ...(below > 0 ? [spacers[1]] : [])];
  // Remove first, so a row that stays is never moved. WebKit drops a click whose
  // pressed row was reparented before the release, and scrolling would move all of them.
  const kept = new Set(nodes);
  for (const child of [...container.children]) if (!kept.has(child)) child.remove();
  nodes.forEach((node, index) => {
    const current = container.children[index];
    if (current !== node) container.insertBefore(node, current ?? null);
  });
  if ((container.scrollTop || 0) !== top) container.scrollTop = top;
  if (focusedId && document.activeElement !== focused) {
    // A focused row scrolled out of the mounted rows leaves focus on the list; it returns when the row does.
    container.dataset.focusId = focusedId;
    container.focus({preventScroll: true});
  }
  const returning = container.dataset.focusId && document.activeElement === container
    ? rows.find(row => row.dataset.requestId === container.dataset.focusId) : null;
  if (returning) {
    delete container.dataset.focusId;
    returning.focus({preventScroll: true});
  }
  container.tabIndex = rows.length ? -1 : 0;
}

// Search covers the method, host or URL and status a row carries and any
// researcher name shown beside it, never retained headers or bodies.
function trafficSearchRequests(requests, needle, nameOf = () => null) {
  const matches = new Map();
  for (const request of requests) {
    if (!needle || `${request.method} ${request.path} ${request.status}`.toLowerCase().includes(needle)) {
      matches.set(request.id, {label: 'URL / method / status'});
    } else if (nameOf(request)?.toLowerCase().includes(needle)) {
      matches.set(request.id, {label: 'Researcher name'});
    }
  }
  return {matches};
}

function trafficNode(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Copies captured text and reports the outcome in a status region.
async function trafficCopyText(text, status, copied = 'Copied.') {
  try {
    await navigator.clipboard.writeText(text);
    status.textContent = copied;
  } catch {
    status.textContent = 'Copy failed.';
  }
}

function trafficOriginLabel(request) {
  return request?.origin === 'demo' ? 'Demo evidence'
    : request?.origin === 'live' ? 'Live metadata' : 'Local evidence';
}

// Make capture coverage explicit instead of rendering panes that stay empty.
// `unchecked`: no request index answer has held this row yet. The newest
// window keeps no gap records, so its Pending cannot yet rule out End lost.
function renderTrafficDetails(container, request, notice = '', targetView = null, unchecked = false) {
  const key = JSON.stringify([request?.origin, request?.id, notice]);
  if (container.dataset.selection !== key) {
    container.dataset.selection = key;
    container.replaceChildren();
    if (!request) {
      container.append(trafficNode('div', 'exchange-no-selection', notice || 'Select a request to inspect captured details.'));
      return;
    }
    const general = trafficNode('section', 'traffic-general');
    general.append(trafficNode('h2', '', 'General'));
    for (const label of ['Request URL', 'Document URL', 'Request method', 'Status', 'Source', 'Request ID', 'Browser tab', 'Capture coverage']) {
      const row = trafficNode('div', 'traffic-general-row');
      row.append(trafficNode('span', '', label), trafficNode('span', 'traffic-general-value'));
      general.append(row);
    }
    container.append(general);
  }
  if (!request) return;
  const fullTarget = request.urlTruncated && targetView?.status === 'ready' && targetView.complete;
  const values = [trafficRequestUrl(request, targetView),
    request.documentUrl ?? 'Not captured', request.method, request.failed ? 'Failed' : request.endLost ? 'End lost'
      : request.status === 'finished' ? `Finished · no HTTP status${request.staticData ? ' (archive resource)' : ''}`
      : request.status === 'pending'
      ? `${Number.isInteger(request.provisionalStatus) ? `Pending · provisional HTTP ${request.provisionalStatus}` : 'Pending'}${
        unchecked ? ' · not yet checked against the request index' : ''}`
      : request.status, trafficOriginLabel(request), request.id,
    trafficTabText(request),
    `${request.endLost ? 'A service worker ended this request without a response, but the renderer had already reused the slot that held its start, so its outcome was not recorded. ' : ''}${request.raceNetwork ? 'This request took a service worker race route, so the worker and the network both handled it: the status is what the page received, which the worker or the network may have answered (the records do not say which), and the browser records are the network attempt, whose status and timing may differ. ' : ''}${request.memoryCache ? `${request.staticData
      ? 'Blink decoded this data: URL or MHTML archive resource in the renderer and made no request, so no headers, request body or response body exist for it.'
      : 'Blink answered this load from a resource it already held (the memory cache) and made no request, so no headers, request body or response body exist for it.'}${
        request.hostOnly ? ' Its URL path and query are recorded only in content capture sessions.' : ''}`
      : `${request.hostOnly
      ? 'Native capture recorded method, host, status and lifecycle timing. URL path, query, headers and body bytes are recorded only in content capture sessions.'
      : 'Native capture recorded method, URL path and query, status and lifecycle timing; the Headers tab shows retained headers.'} The request body is on the Payload tab. Response bodies are on the Response tab.`}${request.targetMalformed ? ' The URL target record is malformed and was not interpreted.' : ''}${request.urlTruncated && !fullTarget ? ' Request URL truncated.' : ''}${request.documentUrlTruncated ? ' Document URL truncated.' : ''}${request.methodTruncated ? ' Method truncated.' : ''}`];
  // Captured values stay mono; coverage notes read as prose; Source is provenance.
  const kinds = ['value', request.documentUrl ? 'value' : 'prose', 'value', /^\d+$/.test(String(values[3])) ? 'value' : 'prose',
    'provenance', 'value', trafficTabs(request).length ? 'value' : 'prose', 'prose'];
  container.querySelector('.traffic-general').querySelectorAll('.traffic-general-value').forEach((node, index) => {
    if (node.textContent !== String(values[index])) node.textContent = String(values[index]);
    node.dataset.kind = kinds[index];
    if (kinds[index] === 'provenance') node.dataset.origin = request.origin ?? 'local';
  });
}

function trafficTabs(request) {
  return globalThis.RebRequestTabs?.rowTabs(request) ?? (request.tabId && request.tabId !== '0' ? [request.tabId] : []);
}

function trafficTabText(request) {
  const tabs = trafficTabs(request);
  if (!tabs.length) return request.origin === 'live' ? 'No tab linked. This is a capture error.' : 'Not applicable';
  const names = tabs.map(tab => tab.startsWith('extension:') ? `Extension ${tab.slice(10)}` : tab);
  return `${names.join(', ')}${request.tabLinkLabel ? ` (${request.tabLinkLabel})` : ''}`;
}

// Saved-capture record export for the offline generators. Native Traffic rows
// carry no captureRecord. Redaction transforms a copy, never capture state.
function trafficCaptureDocument(request, mode = 'raw') {
  if (!request?.captureRecord) throw new TypeError('A saved capture record is required.');
  if (!['raw', 'redacted_copy'].includes(mode)) throw new TypeError('Unknown capture export mode.');
  const record = JSON.parse(JSON.stringify(request.captureRecord));
  if (mode === 'redacted_copy') {
    const redactUrl = value => {
      if (!value) return value;
      try {
        const url = new URL(value);
        if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) return '<redacted>';
        url.username = ''; url.password = ''; url.search = ''; url.hash = '';
        return url.href;
      } catch { return '<redacted>'; }
    };
    record.url = redactUrl(record.url);
    record.document_url = redactUrl(record.document_url);
    record.target_title = '<redacted>';
    if (record.error_text) record.error_text = '<redacted>';
    for (const site of record.initiator?.sites ?? []) {
      site.source = redactUrl(site.source);
    }
    for (const side of [record.request, record.response]) {
      side.headers = side.headers.map(([name]) => [name, '<redacted>']);
      if (side.body.state === 'available') side.body.state = 'redacted';
      side.body.text = ''; side.body.base64 = '';
      side.body.reason = 'Body content omitted from this explicitly redacted copy.';
    }
  }
  return {
    format: 'reb-traffic-capture-v1', mode,
    representation: 'Retained CDP strings/base64, not original HTTP wire bytes.',
    warning: mode === 'raw'
      ? 'Raw local capture may contain credentials and personal data. Review before sharing.'
      : 'Best-effort redacted copy. Paths, header names and other metadata may contain secrets. Review before sharing.',
    coverage: {
      scope: 'One selected record from the ephemeral CDP Traffic window; not a durable session archive.',
      headers: 'Primary CDP event headers only; extra-info headers, original casing/order and duplicate wire lines are not guaranteed.',
      storage: 'Reconnect, target change, process exit or retention eviction can discard the live record.',
      dropped: request.captureDropped ?? 0,
      limits: JSON.parse(JSON.stringify(request.captureLimits ?? {}))
    },
    record
  };
}

// Why a content session's hop has a provisional request block and no
// `network` one ("Missing final blocks" in protocol/native-network-v3.md),
// decided from the row's browser records exactly as get_request_headers does.
const TRAFFIC_MISSING_REASONS = Object.freeze({
  in_progress: 'The request has not ended, so the network stack may still report what it sent.',
  download: 'Downloads load through the browser\'s own factory, which has no DevTools observer at the pinned Chromium.',
  service_worker: 'A service worker answered it, so no request reached the network.',
  from_cache: 'The HTTP cache answered it without sending a request, so there are no sent headers or cookies.',
  failed: 'It failed before the network stack reported the headers it sent.',
  redirect_not_sent: 'Nothing was sent for this redirect hop: it was an internal redirect, such as an HSTS upgrade, or one the HTTP cache answered, while a later hop reported what it sent.',
  record_dropped: 'A full queue dropped records while this request ran, so the headers it sent may have been reported and lost.',
  not_reported: 'The network stack reported no sent headers for this hop: its factory had no DevTools observer, or the block arrived after the capture stopped tracking the request.'
});
// A hop with sent cookies and no response list: the response headers bring it.
const TRAFFIC_MISSING_RECEIVED_REASONS = Object.freeze({
  in_progress: TRAFFIC_MISSING_REASONS.in_progress,
  failed: 'It failed before a response arrived.',
  record_dropped: 'A full queue dropped records while this request ran, so its response cookie list may have been reported and lost.',
  no_raw_response: 'The network stack reported what was sent for this hop but no response headers: no response arrived, or it arrived after the capture stopped tracking the request.'
});
const TRAFFIC_MISSING_LABELS = Object.freeze({download: 'download', service_worker: 'service worker',
  from_cache: 'HTTP cache', failed: 'failed', not_reported: 'not reported', record_dropped: 'possibly dropped'});

// The records a gap says a full queue dropped, as the backend weighs them
// (event_window.rs): a named reason (an identifier category of at most 32
// bytes and reason of at most 128, payload not truncated) is no loss; any
// other gap counts its decimal payload, or 1. Any category: a renderer's drop
// gap takes the category of the last record drained before it.
function trafficDroppedRecords(event) {
  if (event?.type !== 'gap') return 0;
  const hex = typeof event.payload === 'string' && /^(?:[0-9a-f]{2})*$/i.test(event.payload) ? event.payload : null;
  const text = hex === null ? null : (hex.match(/../g) ?? []).map(byte => String.fromCharCode(Number.parseInt(byte, 16))).join('');
  const identifier = (value, maximum) => typeof value === 'string' && value.length >= 1 && value.length <= maximum &&
    /^[a-z][a-z0-9_]*$/.test(value);
  if (event.payload_truncated !== true && identifier(event.category, 32) && identifier(text, 128)) return 0;
  return text !== null && /^(?:0|[1-9][0-9]*)$/.test(text) && Number(text) > 0 ? Number(text) : 1;
}

// How long after a request's last record a drop of one of its records can
// still be reported: the browser writer reports drops on its next wake.
const TRAFFIC_DROP_REPORT_SLACK_NS = 1000000000n;

// Whether a record of `request` may have been lost: a drop gap of its session
// while it ran or reported just after, or any later one while it is open.
function trafficDroppedDuring(request, events, ended) {
  const session = request?.events?.[0]?.session_id;
  const first = request?.firstTimestamp, last = request?.lastTimestamp;
  if (typeof first !== 'bigint' || typeof last !== 'bigint') return false;
  return (Array.isArray(events) ? events : []).some(event => {
    if ((session && event?.session_id !== session) || !trafficDroppedRecords(event)) return false;
    let time;
    try { time = BigInt(event.monotonic_time_ns); } catch { return false; }
    return time >= first && (!ended || time <= last + TRAFFIC_DROP_REPORT_SLACK_NS);
  });
}

// A reason inferred from an absence is unsure once records may have dropped.
function trafficQualifiedReason(reason, dropped) {
  return dropped && ['redirect_not_sent', 'not_reported', 'no_raw_response'].includes(reason) ? 'record_dropped' : reason;
}

function trafficRequestLifecycle(request) {
  const life = {ended: false, failed: false, responded: false, fromCache: false, fromServiceWorker: false, download: false};
  for (const event of request?.events ?? []) {
    // Renderer records of the row are not the browser loader's.
    if (event?.category !== 'network' || ((event.browser_context_id_high ?? '0') === '0' &&
        (event.browser_context_id_low ?? '0') === '0')) continue;
    if (event.type === 'request_started') life.download ||= event.loader_kind === 2;
    else if (event.type === 'response_started') {
      life.responded = true;
      life.fromCache ||= (event.flags & 2) !== 0;
      life.fromServiceWorker ||= (event.flags & 4) !== 0;
    } else if (['request_completed', 'response_completed'].includes(event.type)) life.ended = true;
    else if (event.type === 'request_failed') Object.assign(life, {ended: true, failed: true});
  }
  return life;
}

// `laterReported`: a later hop of the request has a network block, so its
// factory observes it and an earlier hop without one sent nothing.
function trafficMissingReason(life, last, laterReported = false) {
  if (last && !life.ended) return 'in_progress';
  if (life.download) return 'download';
  if (!last && laterReported) return 'redirect_not_sent';
  if (last && life.fromServiceWorker) return 'service_worker';
  if (last && life.fromCache) return 'from_cache';
  if (last && life.failed && !life.responded) return 'failed';
  return 'not_reported';
}

// A sent cookie list without a received one: Chromium reports both with the
// raw notifications, the received list with the response headers.
function trafficMissingReceivedReason(life, last) {
  if (last && !life.ended) return 'in_progress';
  if (last && life.failed && !life.responded) return 'failed';
  return 'no_raw_response';
}

// Each hop of a row with a provisional block and whether the network
// reported it; the last such hop is the one its response belongs to.
function trafficFinalBlocks(request, events = typeof state === 'object' ? state.events : []) {
  const hops = new Map();
  for (const block of request?.headerBlocks ?? []) {
    if (block.malformed || block.kind !== 'request') continue;
    const hop = hops.get(block.hop) ?? {provisional: false, network: false};
    if (block.source === 'browser') hop.provisional = true;
    if (block.source === 'network') hop.network = true;
    hops.set(block.hop, hop);
  }
  const provisional = [...hops].filter(([, hop]) => hop.provisional).map(([hop]) => hop);
  const last = provisional.length ? Math.max(...provisional) : null;
  const laterReported = hop => [...hops].some(([other, blocks]) => other > hop && blocks.network);
  const life = trafficRequestLifecycle(request);
  return {hops, last, laterReported, life, dropped: trafficDroppedDuring(request, events, life.ended)};
}

// What the loaded rows did not retain or could not join: header blocks and
// cookie lists in states 4 to 8, late network blocks, and requests that ended
// without a final block, each by reason. Counts only; it reads no block.
function trafficHeaderCoverage(requests, events = typeof state === 'object' ? state.events : []) {
  const notRetained = new Map(), missing = new Map();
  let unattributedBlocks = 0, unattributedLists = 0;
  const count = (map, key) => map.set(key, (map.get(key) ?? 0) + 1);
  for (const request of Array.isArray(requests) ? requests : []) {
    for (const block of request.headerBlocks ?? []) {
      if (block.malformed) continue;
      if (/^not_captured_/.test(block.state ?? '')) count(notRetained, `headers:${block.state}`);
      unattributedBlocks = Math.max(unattributedBlocks, block.unattributedBlocks ?? 0);
    }
    for (const list of request.cookieLists ?? []) {
      if (list.malformed) continue;
      if (/^not_captured_/.test(list.state ?? '')) count(notRetained, `cookies:${list.state}`);
      unattributedLists = Math.max(unattributedLists, list.unattributedLists ?? 0);
    }
    const {hops, last, life, dropped} = trafficFinalBlocks(request, events);
    if (last === null || hops.get(last).network) continue;
    const reason = trafficQualifiedReason(trafficMissingReason(life, true), dropped);
    if (reason !== 'in_progress') count(missing, reason);
  }
  return {notRetained, missing, unattributedBlocks, unattributedLists};
}

const TRAFFIC_NOT_RETAINED_LABELS = Object.freeze({not_captured_block_limit: 'size limit',
  not_captured_artifact_unavailable: 'no artifact channel', not_captured_transfer_refused: 'queue refused',
  not_captured_session_budget: 'session budget', not_captured_url: 'no HTTP(S) URL or hop'});

// "(reason)" for one reason, else "(n reason, m reason)": the footer stays short.
function trafficReasonList(reasons, labels) {
  const label = reason => labels[reason] ?? reason.replaceAll('_', ' ');
  return reasons.length === 1 ? `(${label(reasons[0][0])})`
    : `(${reasons.map(([reason, value]) => `${value} ${label(reason)}`).join(', ')})`;
}

// What was not retained or joined, and why: one line each for the footer's
// breakdown.
function trafficHeaderCoverageParts(coverage) {
  if (!coverage) return [];
  const parts = [];
  for (const [kind, noun] of [['headers', 'header block'], ['cookies', 'cookie list']]) {
    const reasons = [...coverage.notRetained].filter(([key]) => key.startsWith(`${kind}:`))
      .map(([key, total]) => [key.slice(kind.length + 1), total]);
    const total = reasons.reduce((sum, [, value]) => sum + value, 0);
    if (!total) continue;
    parts.push(`${total} ${noun}${total === 1 ? '' : 's'} not retained ${trafficReasonList(reasons, TRAFFIC_NOT_RETAINED_LABELS)}`);
  }
  // Network blocks and lists that arrived after their request ended: on no row.
  const late = coverage.unattributedBlocks + coverage.unattributedLists;
  if (late) parts.push(`${late} late header ${late === 1 ? 'record' : 'records'} on no row`);
  const missing = [...coverage.missing];
  const total = missing.reduce((sum, [, value]) => sum + value, 0);
  if (total) {
    parts.push(`${total} ${total === 1 ? 'request' : 'requests'} without final headers ${trafficReasonList(missing, TRAFFIC_MISSING_LABELS)}`);
  }
  return parts;
}

function trafficHeaderCoverageNotice(coverage) {
  return trafficHeaderCoverageParts(coverage).join(' · ');
}

// Every block and list not retained, late record and request without final
// headers: the one count the footer shows.
function trafficHeaderGapCount(coverage) {
  if (!coverage) return 0;
  const sum = values => [...values].reduce((total, value) => total + value, 0);
  return sum(coverage.notRetained.values()) + coverage.unattributedBlocks + coverage.unattributedLists +
    sum(coverage.missing.values());
}

// The footer keeps one item, "N header gaps", a button that opens its
// breakdown below it, so the footer stays the size it was however many
// reasons there are; the breakdown is text only.
function renderTrafficHeaderGaps(button, detail, coverage) {
  if (!button || !detail) return;
  const count = trafficHeaderGapCount(coverage);
  const label = `${count.toLocaleString('en-US')} header ${count === 1 ? 'gap' : 'gaps'}`;
  button.hidden = count === 0;
  if (button.textContent !== label) button.textContent = label;
  if (count === 0) setTrafficHeaderGapsOpen(button, detail, false);
  const parts = trafficHeaderCoverageParts(coverage);
  const key = JSON.stringify(parts);
  if (detail.dataset.renderKey === key) return;
  detail.dataset.renderKey = key;
  const list = trafficNode('ul', 'request-header-gaps-list');
  list.append(...parts.map(part => trafficNode('li', '', part)));
  detail.replaceChildren(list);
}

function setTrafficHeaderGapsOpen(button, detail, open) {
  button.setAttribute('aria-expanded', String(open));
  detail.hidden = !open;
}

// Reuse the explicit export-copy policy from the offline client-project command.
if (typeof module === 'object' && module?.exports && typeof require === 'function') module.exports = {trafficCaptureDocument};
