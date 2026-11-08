/* Native Traffic rows carry method, host, status, type and lifecycle timing.
 * Content capture sessions add the URL path and query and a bounded request
 * body (protocol/native-network-v2.md); every session records the body's
 * length, type and digest. Headers and response bodies are not part of native
 * capture, so this view never implies or searches them. */
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
    captured_truncated: `Retained prefix: ${trafficByteCount(body.capturedLength)} of ${trafficByteCount(body.bodyLength)}, truncated at the 256 KiB capture limit.`,
    not_captured_body_kind: `Not captured: ${kind.toLowerCase()} bodies are never read by native capture.`,
    not_captured_artifact_unavailable: 'Not captured: the artifact channel was unavailable.',
    not_captured_transfer_refused: 'Not captured: the artifact transfer queue refused it.',
    not_captured_url: 'Not captured: the URL is not HTTP(S) or is longer than 8 KiB.',
    not_captured_session_budget: 'Not captured: this session reached its request body budget (1,024 bodies or 64 MiB).',
    not_captured_credential_form: 'Not captured: password form submission. Bytes and digest are withheld.'
  }[body.state] ?? 'Unknown capture state.';
}

function trafficBodyRows(body) {
  if (!body || body.malformed) return [];
  const digest = body.sha256 ?? (body.state === 'no_body' ? 'No body'
    : body.state === 'not_captured_credential_form' ? 'Withheld for a password form'
      : body.digestSizeLimit ? 'Not computed: the body exceeds the 4 MiB digest bound'
        : 'Not computed: file, blob or stream parts are not read');
  return [
    ['Content type', body.contentType ?? (body.contentTypeOmitted ? 'Sent, but not a bounded media type; not recorded' : 'Not sent'),
      body.contentType ? 'value' : 'prose'],
    ['Body length', body.state === 'no_body' ? 'No body'
      : `${trafficByteCount(body.bodyLength)}${body.lengthPartial ? ' in memory; file, blob and stream parts are not counted' : ''}`,
    body.state === 'no_body' ? 'prose' : 'value'],
    ['SHA-256', digest, body.sha256 ? 'value' : 'prose'],
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
    return {note: 'The body artifact is not in the current catalog: its acknowledgment is pending, or it is outside the 500 newest artifacts.'};
  }
  if (view.status === 'unavailable') return {note: 'Retained bodies are read from the local backend, which this view does not have.'};
  if (view.status === 'error') {
    return {note: `The retained body could not be read: ${view.error}.${view.retryable ? ' It is read again on the next refresh.' : ''}`};
  }
  const notes = [];
  if (body.state === 'captured_truncated') notes.push(`Prefix only: ${trafficByteCount(body.capturedLength)} of ${trafficByteCount(body.bodyLength)}.`);
  if (view.lossy) notes.push('Not valid UTF-8; shown with replacement characters.');
  if (!view.verified) notes.push('The retained digest could not be rechecked in this view.');
  return {text: view.text, note: notes.join(' '), url: view.url};
}

const TRAFFIC_TYPE_LABELS = Object.freeze({xhr: 'Fetch/XHR', doc: 'Document', css: 'CSS', js: 'Script',
  font: 'Font', img: 'Image', media: 'Media', socket: 'WebSocket', wasm: 'Wasm', other: 'Other'});
function trafficTypeLabel(type) {
  return Object.hasOwn(TRAFFIC_TYPE_LABELS, type) ? TRAFFIC_TYPE_LABELS[type] : 'Other';
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
  const served = request?.fromServiceWorker ? '(service worker)' : request?.fromCache ? '(disk cache)' : null;
  const lines = [served === '(service worker)' ? 'Served by a service worker.' : served ? 'Served from the HTTP cache.' : '',
    transfer === null ? 'Transferred: no completion record.' : `Transferred: ${exact(transfer)}.`,
    resource === null ? 'Resource: not recorded.' : `Resource: ${exact(resource)}.`].filter(Boolean);
  return {transfer: served ?? (transfer === null ? '—' : trafficBytesLabel(transfer)),
    resource: resource === null ? '' : trafficBytesLabel(resource), title: lines.join('\n')};
}

const TRAFFIC_INITIATOR_LABELS = Object.freeze({renderer: 'Renderer', worker: 'Service worker', browser: 'Browser'});
const TRAFFIC_INITIATOR_TITLES = Object.freeze({
  renderer: 'A renderer started this request. Parser and script starts are not told apart without an initiator stack.',
  worker: 'A service worker started this request.',
  browser: 'The browser process started this request, such as a navigation; no renderer record names it.'});
function trafficInitiatorLabel(request) {
  return Object.hasOwn(TRAFFIC_INITIATOR_LABELS, request?.initiator ?? '') ? TRAFFIC_INITIATOR_LABELS[request.initiator] : null;
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
  return {text: String(request.status), className, title: `HTTP status ${request.status}`};
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

// One mounted block of at most 500 rows; spacers stand for the rest.
const TRAFFIC_ROW_LIMIT = 500;
const TRAFFIC_ROW_MARGIN = 100;
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

// Moves the mounted block only when the viewport nears one of its edges.
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
    tabId: row.tab_id, operation: row.operation, target: row.target, host: row.host, urlTruncated: row.url_truncated,
    targetLength: row.target_length, targetMalformed: row.target_malformed,
    firstTimestamp: BigInt(row.first_time_ns), lastTimestamp: BigInt(row.last_time_ns),
    transferSize: row.transfer_size, resourceSize: row.resource_size, fromCache: row.from_cache,
    fromServiceWorker: row.from_service_worker, mimeType: row.mime_type, protocol: row.protocol,
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

// `requests` is the block from row `start` of `total`; a missing entry is not loaded yet.
// `scale` ({start, end, origin} in nanoseconds) places the waterfall bars.
function renderTrafficRows(container, requests, {start = 0, total = requests.length, selectedId, newIds, onSelect, onKey, nameOf = () => null, pending = 'Loading…', scale = null}) {
  requests = requests.slice(0, TRAFFIC_ROW_LIMIT);
  const scaleKey = scale ? `${scale.start}:${scale.end}:${scale.origin ?? ''}` : null;
  const previousRows = new Map([...container.querySelectorAll('.request-row')].map(row => [row.dataset.requestId, row]));
  const focused = document.activeElement;
  const focusedId = container.contains(focused) ? focused.dataset.requestId : null;
  const scrollTop = container.scrollTop;
  const height = trafficRowHeight(container);
  // At the top, rows that arrive above stay in view instead of pushing it.
  const anchor = scrollTop > 0 ? [...previousRows.values()].find(row => row.dataset.requestId && row.offsetTop + row.offsetHeight > scrollTop) : null;
  const anchorOffset = anchor ? anchor.offsetTop - scrollTop : 0;
  const selectedVisible = requests.some(request => request?.id === selectedId);
  const firstLoaded = requests.findIndex(Boolean);
  const rows = requests.map((request, index) => {
    if (!request) {
      const placeholder = trafficNode('div', 'request-row request-placeholder', pending);
      placeholder.setAttribute('aria-hidden', 'true');
      placeholder.classList.toggle('is-striped', (start + index) % 2 === 1);
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
      request.transferSize, request.resourceSize, request.fromCache, request.fromServiceWorker, request.mimeType, request.protocol,
      request.initiator, request.errorCode, request.loaderObserved, time(request.firstTimestamp), time(request.lastTimestamp),
      time(request.responseTimestamp), scaleKey]);
    // Reuse the row itself on lifecycle changes, preserving focus and its single
    // arrival animation. Unchanged rows do not rebuild captured text children.
    if (row.dataset.renderKey !== key) {
      row.dataset.renderKey = key;
      row.dataset.origin = request.origin;
      row.dataset.targetKind = request.targetKind ?? 'unknown';
      row.dataset.pending = String(request.status === 'pending' && !request.failed);
      const target = trafficTargetParts(request);
      const cell = (column, className, text, title) => {
        const node = trafficNode('span', className, text);
        node.dataset.column = column;
        if (title) node.title = title;
        return node;
      };
      const url = `${request.path}${request.urlTruncated ? '…' : ''}`;
      const name = cell('name', 'request-name', undefined, `${url}\n${trafficOriginLabel(request)} · ${request.method} · network · ${request.operation ?? 'network'} · request ${request.id}${request.hostOnly ? ' · URL path and query not captured' : request.urlTruncated ? ` · path and query truncated from ${request.targetLength} bytes` : ''}`);
      // A researcher name leads the cell; the captured path and host stay visible.
      if (researcherName) name.append(trafficNode('span', 'researcher-name', researcherName));
      name.append(trafficNode('span', 'request-resource', target.name),
        trafficNode('span', 'request-host', target.host));
      const statusCell = trafficStatusCell(request);
      const status = cell('status', statusCell.className, statusCell.text, statusCell.title);
      const type = cell('type', 'request-type', trafficTableTypeLabel(request.type),
        `${trafficTypeLabel(request.type)}${request.mimeType ? ` · ${request.mimeType}` : ''}`);
      const protocol = cell('protocol', 'request-protocol', request.protocol ?? '—',
        request.protocol ? `Negotiated protocol (ALPN): ${request.protocol}` : 'No negotiated protocol recorded.');
      const initiatorLabel = trafficInitiatorLabel(request);
      const initiator = cell('initiator', 'request-initiator', initiatorLabel ?? '—',
        initiatorLabel ? TRAFFIC_INITIATOR_TITLES[request.initiator] : 'No versioned lifecycle record says who started this request.');
      const sizeCell = trafficSizeCell(request);
      const size = cell('size', 'request-size', undefined, sizeCell.title);
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
    // Stripes follow the row's place in the whole list, not in the block.
    row.classList.toggle('is-striped', (start + index) % 2 === 1);
    row.tabIndex = request.id === selectedId || !selectedVisible && index === firstLoaded ? 0 : -1;
    return row;
  });
  const spacers = container.trafficSpacers ??= [0, 1].map(() => {
    const spacer = trafficNode('div', 'request-spacer');
    spacer.setAttribute('aria-hidden', 'true');
    return spacer;
  });
  const below = Math.max(0, total - start - rows.length);
  spacers[0].style.height = `${start * height}px`;
  spacers[1].style.height = `${below * height}px`;
  const nodes = [...(start > 0 ? [spacers[0]] : []), ...rows, ...(below > 0 ? [spacers[1]] : [])];
  nodes.forEach((node, index) => {
    const current = container.children[index];
    if (current !== node) container.insertBefore(node, current ?? null);
  });
  while (container.children.length > nodes.length) container.lastElementChild.remove();
  const restored = anchor && rows.find(row => row.dataset.requestId === anchor.dataset.requestId);
  container.scrollTop = restored ? restored.offsetTop - anchorOffset : scrollTop;
  if (focusedId && document.activeElement !== focused) (rows.find(row => row.dataset.requestId === focusedId) ?? rows[0] ?? container).focus({preventScroll: true});
  container.tabIndex = rows.length ? -1 : 0;
}

// Native rows retain no headers; search covers the method, host or URL and
// status they carry and any researcher name shown beside them.
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
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function trafficOriginLabel(request) {
  return request?.origin === 'demo' ? 'Demo evidence'
    : request?.origin === 'live' ? 'Live metadata' : 'Local evidence';
}

// Native capture has no header or response body record to show. Make that
// coverage explicit instead of rendering request/response panes that stay empty.
function renderTrafficDetails(container, request, notice = '', bodyView = null) {
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
    const body = trafficNode('section', 'traffic-body');
    body.append(trafficNode('h2', '', 'Request body'));
    container.append(general, body);
  }
  if (!request) return;
  renderTrafficBody(container.querySelector('.traffic-body'), request, bodyView);
  const values = [request.hostOnly ? `${request.path} (host only; path and query not captured)`
    : request.urlTruncated ? `${request.path}… (truncated; the original path and query are ${request.targetLength} bytes)` : request.path,
    request.documentUrl ?? 'Not captured', request.method, request.failed ? 'Failed' : request.status === 'pending'
      ? (Number.isInteger(request.provisionalStatus) ? `Pending · provisional HTTP ${request.provisionalStatus}` : 'Pending')
      : request.status, trafficOriginLabel(request), request.id,
    request.tabId && request.tabId !== '0' ? request.tabId : 'Unattributed',
    `${request.hostOnly
      ? 'Native capture recorded method, host, status and lifecycle timing. URL path, query and body bytes are recorded only in content capture sessions.'
      : 'Native capture recorded method, URL path and query, status and lifecycle timing.'} Request and response headers and response bodies are not captured.${request.targetMalformed ? ' The URL target record is malformed and was not interpreted.' : ''}${request.urlTruncated ? ' Request URL truncated.' : ''}${request.documentUrlTruncated ? ' Document URL truncated.' : ''}${request.methodTruncated ? ' Method truncated.' : ''}`];
  // Captured values stay mono; coverage notes read as prose; Source is provenance.
  const kinds = ['value', request.documentUrl ? 'value' : 'prose', 'value', /^\d+$/.test(String(values[3])) ? 'value' : 'prose',
    'provenance', 'value', request.tabId && request.tabId !== '0' ? 'value' : 'prose', 'prose'];
  container.querySelector('.traffic-general').querySelectorAll('.traffic-general-value').forEach((node, index) => {
    if (node.textContent !== String(values[index])) node.textContent = String(values[index]);
    node.dataset.kind = kinds[index];
    if (kinds[index] === 'provenance') node.dataset.origin = request.origin ?? 'local';
  });
}

function renderTrafficBody(section, request, view) {
  const body = request.origin === 'live' || request.origin === 'demo' ? request.body ?? null : undefined;
  const content = body === undefined ? null : trafficBodyContent(body, view);
  const key = JSON.stringify([body, content]);
  if (section.dataset.renderKey === key) return;
  section.dataset.renderKey = key;
  const rows = body === undefined ? [['Capture', 'This row has no native body record.', 'prose']]
    : [['Capture', trafficBodyCapture(body), 'prose'], ...trafficBodyRows(body)];
  const nodes = rows.map(([label, value, kind]) => {
    const row = trafficNode('div', 'traffic-general-row');
    const valueNode = trafficNode('span', 'traffic-general-value', String(value));
    valueNode.dataset.kind = kind;
    row.append(trafficNode('span', '', label), valueNode);
    return row;
  });
  if (content?.url) {
    const row = trafficNode('div', 'traffic-general-row');
    const valueNode = trafficNode('span', 'traffic-general-value', content.url);
    valueNode.dataset.kind = 'value';
    row.append(trafficNode('span', '', 'Body artifact URL'), valueNode);
    nodes.push(row);
  }
  if (content?.note) nodes.push(trafficNode('p', 'traffic-body-note', content.note));
  if (content?.text !== undefined) {
    const text = trafficNode('pre', 'traffic-body-text', content.text);
    text.tabIndex = 0;
    text.setAttribute('aria-label', 'Retained request body text');
    nodes.push(text);
  }
  section.replaceChildren(trafficNode('h2', '', 'Request body'), ...nodes);
  section.dataset.state = body === undefined ? 'none' : body === null ? 'missing' : body.malformed ? 'malformed' : body.state;
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

// Reuse the explicit export-copy policy from the offline client-project command.
if (typeof module === 'object' && module?.exports && typeof require === 'function') module.exports = {trafficCaptureDocument};
