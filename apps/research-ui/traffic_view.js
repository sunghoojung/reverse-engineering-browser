/* Native Traffic rows carry method, host, status, type and lifecycle timing.
 * Content capture sessions add the URL path and query and a bounded request
 * body (protocol/native-network-v2.md); every session records the body's
 * length, type and digest. Response bodies have their own tabs
 * (traffic_response.js). Headers are not part of native capture, so this view
 * never implies or searches them. */
function trafficTargetParts(request) {
  const target = String(request?.path ?? '').trim();
  if (request?.hostOnly) return {name: target || 'Unknown host', host: request.schemeOnly ? 'Path not captured' : 'Host-only metadata'};
  const more = request?.urlTruncated ? '…' : '';
  // A native target is shown exactly as captured; reparsing would re-escape it.
  if (typeof request?.target === 'string') return {name: `${request.target}${more}`, host: request.host ?? ''};
  if (request?.targetKind === 'path') {
    const slash = target.indexOf('/');
    return slash > 0 ? {name: `${target.slice(slash)}${more}`, host: target.slice(0, slash)} : {name: target, host: ''};
  }
  try {
    const url = new URL(target);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) throw new TypeError('Not a network URL');
    return {name: `${url.pathname || '/'}${url.search}${more}`, host: url.host};
  } catch {
    return {name: target || 'Unidentified request', host: ''};
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
    captured_truncated: `Retained prefix: ${trafficByteCount(body.capturedLength)} of ${trafficByteCount(body.bodyLength)}, truncated at the capture limit.`,
    not_captured_body_kind: `Not captured: ${kind.toLowerCase()} bodies are never read by native capture.`,
    not_captured_artifact_unavailable: 'Not captured: the artifact channel was unavailable.',
    not_captured_transfer_refused: 'Not captured: the bounded in-flight memory or artifact transfer queue refused it.',
    not_captured_url: 'Not captured: the URL is not HTTP(S), or in older captures longer than 8 KiB.',
    not_captured_session_budget: 'Not captured: this session had used its request body budget.',
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
  const more = view.complete === false;
  if (more) notes.push(`Showing the first ${trafficByteCount(view.loaded)} of ${trafficByteCount(view.total)} retained.`);
  if (view.moreError) notes.push(`The next range could not be read: ${view.moreError}.`);
  if (view.lossy) notes.push('Not valid UTF-8; shown with replacement characters.');
  if (!view.verified) notes.push(more ? 'The local backend checked the retained digest; this view rechecks it once every byte is shown.'
    : 'The retained digest could not be rechecked in this view.');
  return {text: view.text, note: notes.join(' '), url: view.url, more: more ? view.key : null, loadingMore: Boolean(view.loadingMore)};
}

// The Request URL row: the full target once retained bytes are loaded, else
// the captured prefix and what happened to the rest.
const TRAFFIC_TARGET_RETENTION = Object.freeze({
  not_retained_artifact_unavailable: 'the artifact channel was unavailable',
  not_retained_transfer_refused: 'the bounded in-flight memory or artifact transfer queue refused it',
  not_retained_session_budget: 'this session had used its request content budget',
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
        : view.status === 'missing' ? 'the full target artifact is not in the current catalog'
          : view.status === 'error' ? `the full target could not be read: ${view.error}` : 'the full target is not readable here'})`;
  }
  return TRAFFIC_TARGET_RETENTION[retention] ? `${prefix}; the full target was not retained: ${TRAFFIC_TARGET_RETENTION[retention]})` : `${prefix})`;
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

// The broker retains 5,000 events. A separately paged ledger never mounts more
// than 500 rows; filters and sorting still inspect the whole retained window.
const TRAFFIC_ROW_LIMIT = 500;
const TRAFFIC_RETAINED_LIMIT = 5000;
function trafficTimeValue(request) {
  if (typeof request.time === 'number' && Number.isFinite(request.time)) return request.time;
  const milliseconds = /^(\d+(?:\.\d+)?) ms$/.exec(String(request.time));
  return milliseconds && Number.isFinite(Number(milliseconds[1])) ? Number(milliseconds[1]) : null;
}
function trafficSortedRequests(requests, key = 'capture', direction = 1) {
  if (key === 'capture') return requests;
  const value = request => key === 'name' ? trafficTargetParts(request).name
    : key === 'time' ? trafficTimeValue(request)
      : key === 'status' ? /^\d+$/.test(String(request.status)) ? Number(request.status) : null
        : key === 'type' ? trafficTypeLabel(request.type) : request.method;
  // Precompute URL/type keys once; stable ties retain evidence order.
  return requests.map((request, index) => ({request, index, value: value(request)})).sort((a, b) => {
    if (a.value === null || b.value === null) return a.value === b.value ? a.index - b.index : a.value === null ? 1 : -1;
    const comparison = typeof a.value === 'number' ? a.value - b.value : String(a.value).localeCompare(String(b.value));
    return comparison * direction || a.index - b.index;
  }).map(entry => entry.request);
}

function trafficWindow(requests, start, anchor = null) {
  const found = anchor === null ? -1 : requests.findIndex(request => request.id === anchor);
  const offset = Math.max(0, Math.min(found < 0 ? start : found, Math.max(0, requests.length - TRAFFIC_ROW_LIMIT)));
  return {start: offset, rows: requests.slice(offset, offset + TRAFFIC_ROW_LIMIT)};
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
  const rows = [...container.querySelectorAll('.request-row')];
  const selectedVisible = rows.some(row => row.dataset.requestId === selectedId);
  rows.forEach((row, index) => {
    const selected = row.dataset.requestId === selectedId;
    const ariaSelected = String(selected);
    if (row.getAttribute('aria-selected') !== ariaSelected) row.setAttribute('aria-selected', ariaSelected);
    const tabIndex = selected || !selectedVisible && index === 0 ? 0 : -1;
    if (row.tabIndex !== tabIndex) row.tabIndex = tabIndex;
  });
}

function renderTrafficRows(container, requests, {selectedId, newIds, onSelect, onKey, nameOf = () => null}) {
  requests = requests.slice(0, TRAFFIC_ROW_LIMIT);
  const previousRows = new Map([...container.querySelectorAll('.request-row')].map(row => [row.dataset.requestId, row]));
  const focused = document.activeElement;
  const focusedId = container.contains(focused) ? focused.dataset.requestId : null;
  const scrollTop = container.scrollTop;
  const anchor = [...previousRows.values()].find(row => row.offsetTop + row.offsetHeight > scrollTop);
  const anchorOffset = anchor ? anchor.offsetTop - scrollTop : 0;
  const selectedVisible = requests.some(request => request.id === selectedId);
  const rows = requests.map((request, index) => {
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
    const key = JSON.stringify([request.path, request.method, request.status, request.time,
      request.type, request.origin, request.hostOnly, request.failed, request.targetKind, request.operation, researcherName,
      request.tabLinkLabel]);
    // Reuse the row itself on lifecycle changes, preserving focus and its single
    // arrival animation. Unchanged rows do not rebuild captured text children.
    if (row.dataset.renderKey !== key) {
      row.dataset.renderKey = key;
      row.dataset.origin = request.origin;
      row.dataset.targetKind = request.targetKind ?? 'unknown';
      row.dataset.pending = String(request.status === 'pending' && !request.failed);
      const target = trafficTargetParts(request);
      const name = trafficNode('span', 'request-name');
      name.title = `${trafficOriginLabel(request)} · ${request.method} ${request.path}${request.urlTruncated ? '…' : ''} · network · ${request.operation ?? 'network'} · request ${request.id}${request.tabLinkLabel ? ` · ${request.tabLinkLabel}` : ''}${request.hostOnly ? ' · URL path and query not captured' : request.urlTruncated ? ` · path and query truncated from ${request.targetLength} bytes` : ''}`;
      // A researcher name leads the cell; the captured path and host stay visible.
      if (researcherName) name.append(trafficNode('span', 'researcher-name', researcherName));
      const host = trafficNode('span', 'request-host', target.host);
      if (request.tabLinkLabel) host.append(trafficNode('span', 'request-tab-link', ` · ${request.tabLinkLabel}`));
      name.append(trafficNode('span', 'request-resource', target.name), host);
      const numericStatus = Number(request.status);
      const status = trafficNode('span', request.failed || numericStatus >= 400 ? 'status-error'
        : numericStatus >= 200 ? 'status-ok' : 'status-neutral', request.failed ? 'Failed' : request.status === 'pending' ? 'Pending' : String(request.status));
      status.title = request.failed ? 'Request failed. Inspect the retained response state for details.'
        : request.interrupted ? 'Native proxy observation ended; final network outcome is unavailable.'
        : request.status === 'pending' ? (Number.isInteger(request.provisionalStatus)
          ? `Still pending. Response extra info reported HTTP ${request.provisionalStatus}; that is not a finished response.`
          : 'No terminal lifecycle event has been captured.') : `HTTP status ${request.status}`;
      const type = trafficNode('span', 'request-type', trafficTableTypeLabel(request.type));
      type.title = trafficTypeLabel(request.type);
      row.replaceChildren(name, status, type,
        trafficNode('span', 'request-method', request.method), trafficNode('span', 'request-time', trafficTimeLabel(request.time)));
      row.setAttribute('aria-label', `${researcherName ? `${researcherName} (researcher name). ` : ''}${trafficOriginLabel(request)} ${request.hostOnly ? 'host-only metadata' : 'request'}: ${request.method} ${request.path}, ${status.textContent}, ${trafficTimeLabel(request.time)}, ${request.operation ?? 'network'}, request ${request.id}`);
    }
    row.setAttribute('aria-selected', String(request.id === selectedId));
    row.tabIndex = request.id === selectedId || !selectedVisible && index === 0 ? 0 : -1;
    return row;
  });
  rows.forEach((row, index) => {
    const current = container.children[index];
    if (current !== row) container.insertBefore(row, current ?? null);
  });
  while (container.children.length > rows.length) container.lastElementChild.remove();
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

// Native capture has no header record to show. Make that coverage explicit
// instead of rendering request/response panes that stay empty.
function renderTrafficDetails(container, request, notice = '', bodyView = null, targetView = null) {
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
  const fullTarget = request.urlTruncated && targetView?.status === 'ready' && targetView.complete;
  const values = [trafficRequestUrl(request, targetView),
    request.documentUrl ?? 'Not captured', request.method, request.failed ? 'Failed' : request.status === 'pending'
      ? (Number.isInteger(request.provisionalStatus) ? `Pending · provisional HTTP ${request.provisionalStatus}` : 'Pending')
      : request.status, trafficOriginLabel(request), request.id,
    trafficTabText(request),
    `${request.hostOnly
      ? 'Native capture recorded method, host, status and lifecycle timing. URL path, query and body bytes are recorded only in content capture sessions.'
      : 'Native capture recorded method, URL path and query, status and lifecycle timing.'} Request and response headers are not captured. Response bodies are on the Response tab.${request.targetMalformed ? ' The URL target record is malformed and was not interpreted.' : ''}${request.urlTruncated && !fullTarget ? ' Request URL truncated.' : ''}${request.documentUrlTruncated ? ' Document URL truncated.' : ''}${request.methodTruncated ? ' Method truncated.' : ''}`];
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
  return `${tabs.join(', ')}${request.tabLinkLabel ? ` (${request.tabLinkLabel})` : ''}`;
}

function renderTrafficBody(section, request, view) {
  const body = request.origin === 'live' || request.origin === 'demo' ? request.body ?? null : undefined;
  const content = body === undefined ? null : trafficBodyContent(body, view);
  // Text is keyed by length: the body record and loaded range already identify it.
  const key = JSON.stringify([body, content && {...content, text: content.text?.length}]);
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
  if (content?.more) {
    const more = trafficNode('button', 'secondary-button traffic-body-more', content.loadingMore ? 'Loading…' : 'Show the next 256 KiB');
    more.type = 'button';
    more.dataset.contentKey = content.more;
    more.disabled = content.loadingMore;
    nodes.push(more);
  }
  // Keyboard focus stays on the body when its next range replaces the button.
  const refocus = Boolean(section.querySelector('.traffic-body-more')) &&
    section.querySelector('.traffic-body-more') === globalThis.document?.activeElement;
  section.replaceChildren(trafficNode('h2', '', 'Request body'), ...nodes);
  if (refocus) (section.querySelector('.traffic-body-more') ?? section.querySelector('.traffic-body-text'))?.focus?.();
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
