// Traffic Headers tab (protocol/native-network-v3.md): General, then response
// and request headers per hop, from the native header records joined to the
// selected request. Retained blocks are read after a size and SHA-256 check
// and only ever assigned as text.
const TRAFFIC_HEADER_RETRY_MS = 2000;
const trafficHeaderViews = new Map();
const trafficHeaderSections = new Map();

const trafficHeaderStateNotes = {
  empty: 'No headers.',
  not_captured_block_limit: 'Longer than the 320 KiB block limit, so only its count and size were recorded.',
  not_captured_artifact_unavailable: 'Not retained: the artifact channel was unavailable.',
  not_captured_transfer_refused: 'Not retained: the bounded artifact queue refused it.',
  not_captured_session_budget: 'Not retained: this session already retained 64 MiB of header blocks.',
  not_captured_url: 'Not retained: not an HTTP(S) URL, longer than 8 KiB, or its hop was not tracked.'
};

// `name: value` CRLF lines, split at the first colon after the first byte so
// HTTP/2 and HTTP/3 pseudo-headers keep their leading colon.
function trafficHeaderLines(text, count) {
  if (!text.endsWith('\r\n')) return null;
  const lines = [];
  for (const line of text.slice(0, -2).split('\r\n')) {
    const colon = line.indexOf(':', 1);
    if (colon < 1 || line[colon + 1] !== ' ') return null;
    lines.push({name: line.slice(0, colon), value: line.slice(colon + 2)});
  }
  return lines.length === count ? lines : null;
}

function trafficHeaderHops(request) {
  const hops = new Map();
  for (const block of request?.headerBlocks ?? []) {
    if (block.malformed) continue;
    if (!hops.has(block.hop)) hops.set(block.hop, {hop: block.hop, request: [], response: []});
    hops.get(block.hop)[block.kind].push(block);
  }
  return [...hops.values()].sort((left, right) => left.hop - right.hop);
}

function trafficHeaderView(block, rerender) {
  if (!['captured', 'captured_shared'].includes(block.state)) return null;
  if (typeof location === 'object' && location.protocol === 'file:') return {status: 'unavailable'};
  const refusal = (typeof state === 'object' ? state.events ?? [] : []).find(event =>
    event.type === 'artifact_capture_failed' && event.artifact_id === block.artifactId && event.session_id === block.sessionId);
  if (refusal) return {status: 'refused', reason: typeof decodePayload === 'function' ? decodePayload(refusal) : ''};
  const key = `${block.sessionId}:${block.artifactId}:${block.sha256}`;
  const view = trafficHeaderViews.get(key);
  if (view && !(view.retryable && Date.now() - view.failedAt >= TRAFFIC_HEADER_RETRY_MS)) return view;
  trafficHeaderViews.set(key, {status: 'loading'});
  void trafficLoadHeaderBlock(block, key, rerender);
  return view ?? {status: 'loading'};
}

async function trafficLoadHeaderBlock(block, key, rerender) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  // A transient failure is retried by a later render; an integrity failure stays.
  const mismatch = message => Object.assign(new Error(message), {integrity: true});
  let view;
  try {
    const response = await fetch(`/api/artifacts/${encodeURIComponent(block.artifactId)}/content?limit=${block.blockLength}`,
      {cache: 'no-store', signal: controller.signal});
    if (!response.ok) throw new Error(`the artifact store returned ${response.status}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length !== block.blockLength) throw mismatch('its retained size does not match the header record');
    if (globalThis.crypto?.subtle) {
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
        byte => byte.toString(16).padStart(2, '0')).join('');
      if (digest !== block.sha256) throw mismatch('its bytes do not match the recorded SHA-256');
    }
    const text = new TextDecoder('utf-8', {fatal: false, ignoreBOM: true}).decode(bytes);
    const lines = trafficHeaderLines(text, block.headerCount);
    if (!lines) throw mismatch('its lines do not match the recorded header count');
    view = {status: 'ready', text, lines};
  } catch (error) {
    view = {status: 'error', error: controller.signal.aborted ? 'timed out after 10 seconds'
      : String(error?.message ?? error).replace(/\.$/, ''), retryable: error?.integrity !== true, failedAt: Date.now()};
  } finally {
    clearTimeout(timeout);
  }
  trafficHeaderViews.delete(key);
  trafficHeaderViews.set(key, view);
  while (trafficHeaderViews.size > 32) trafficHeaderViews.delete(trafficHeaderViews.keys().next().value);
  rerender?.();
}

function trafficHeaderSection(id, title, {count = null, note = '', view = null} = {}) {
  const saved = trafficHeaderSections.get(id) ?? {open: true, raw: false};
  const details = trafficNode('details', 'traffic-headers-section');
  details.open = saved.open;
  details.dataset.section = id;
  details.addEventListener('toggle', () =>
    trafficHeaderSections.set(id, {...(trafficHeaderSections.get(id) ?? saved), open: details.open}));
  const summary = trafficNode('summary', '', title);
  if (count !== null) summary.append(trafficNode('span', 'traffic-headers-count', String(count)));
  details.append(summary);
  if (note) details.append(trafficNode('p', 'traffic-headers-note', note));
  if (view?.status !== 'ready') {
    const message = view?.status === 'loading' ? 'Loading retained headers…'
      : view?.status === 'refused' ? `The artifact receiver refused this block${view.reason ? `: ${view.reason}` : ''}.`
        : view?.status === 'unavailable' ? 'Retained headers are read from the local backend, not from a file.'
          : view?.status === 'error' ? `Could not read the retained block: ${view.error}.` : '';
    if (message) details.append(trafficNode('p', 'traffic-headers-note', message));
    return details;
  }
  const tools = trafficNode('div', 'traffic-headers-tools');
  const raw = trafficNode('button', 'secondary-button', 'Raw');
  raw.type = 'button';
  raw.setAttribute('aria-pressed', String(saved.raw));
  const copyAll = trafficNode('button', 'secondary-button', 'Copy all');
  copyAll.type = 'button';
  const status = trafficNode('span', 'traffic-headers-status');
  status.setAttribute('role', 'status');
  tools.append(raw, copyAll, status);
  copyAll.addEventListener('click', () => trafficCopyText(view.text, status));
  const body = trafficNode('div', 'traffic-headers-body');
  const show = asRaw => {
    if (asRaw) {
      const pre = trafficNode('pre', 'traffic-headers-raw', view.text);
      pre.tabIndex = 0;
      pre.setAttribute('aria-label', `${title}, raw`);
      body.replaceChildren(pre);
      return;
    }
    body.replaceChildren(...view.lines.map(line => {
      const row = trafficNode('div', 'traffic-header-row');
      const copy = trafficNode('button', 'traffic-header-copy', 'Copy');
      copy.type = 'button';
      copy.setAttribute('aria-label', `Copy ${line.name} value`);
      copy.addEventListener('click', () => trafficCopyText(line.value, status));
      row.append(trafficNode('span', 'traffic-header-name', line.name),
        trafficNode('span', 'traffic-header-value', line.value), copy);
      return row;
    }));
  };
  raw.addEventListener('click', () => {
    const next = raw.getAttribute('aria-pressed') !== 'true';
    raw.setAttribute('aria-pressed', String(next));
    trafficHeaderSections.set(id, {open: details.open, raw: next});
    show(next);
  });
  show(saved.raw);
  details.append(tools, body);
  return details;
}

function trafficHeaderBlockSection(id, title, block, rerender, extraNote = '') {
  const view = trafficHeaderView(block, rerender);
  const notes = [extraNote, trafficHeaderStateNotes[block.state] ?? '',
    block.state === 'captured_shared' ? 'Identical to an earlier block of this session, retained once.' : '']
    .filter(Boolean).join(' ');
  const section = trafficHeaderSection(id, title, {count: block.headerCount, note: notes, view});
  section.dataset.state = block.state;
  section.dataset.source = block.source;
  return {section, key: `${id}|${block.sequenceNumber}|${view?.status ?? block.state}`};
}

function trafficHeadersGeneral(request, hops, targetView) {
  const last = hops.at(-1);
  const response = last?.response.find(block => block.source === 'browser');
  const provisional = hops[0]?.request.find(block => block.source === 'browser');
  const rows = [['Request URL', trafficRequestUrl(request, targetView)],
    ['Request method', request.method],
    ['Status code', response?.statusCode ? String(response.statusCode) : String(request.status ?? 'Not captured')],
    ['Remote address', response?.remoteAddress ? `${response.remoteAddress}:${response.remotePort}` : 'Not captured'],
    ['Referrer policy', provisional?.referrerPolicy ?? 'Not captured']];
  if (hops.length > 1) rows.push(['Redirect hops', String(hops.length - 1)]);
  const unattributed = Math.max(0, ...(request.headerBlocks ?? []).map(block => block.unattributedBlocks ?? 0));
  if (unattributed) rows.push(['Unattributed blocks', `${unattributed} network header blocks arrived after their request ended`]);
  const section = trafficHeaderSection('general', 'General');
  for (const [label, value] of rows) {
    const row = trafficNode('div', 'traffic-general-row');
    row.append(trafficNode('span', '', label), trafficNode('span', 'traffic-general-value', value));
    section.append(row);
  }
  return {section, key: JSON.stringify(rows)};
}

function renderTrafficHeaders(container, request, rerender, targetView = null) {
  if (!request) {
    container.replaceChildren(trafficNode('div', 'exchange-no-selection', 'Select a request to inspect its headers.'));
    container.dataset.renderKey = '';
    return;
  }
  const hops = trafficHeaderHops(request);
  const parts = [trafficHeadersGeneral(request, hops, targetView)];
  const malformed = (request.headerBlocks ?? []).filter(block => block.malformed).length;
  let message = '';
  if (!Array.isArray(request.headerBlocks)) message = 'This row has no native header record.';
  else if (!hops.length && !malformed) message = request.hostOnly
    ? 'Headers are recorded only in content capture sessions.' : 'No header record was retained for this request.';
  if (malformed) message = `${message} ${malformed} header record${malformed === 1 ? ' is' : 's are'} malformed and not shown.`.trim();
  for (const hop of [...hops].reverse()) {
    const suffix = hops.length > 1 ? ` · hop ${hop.hop}` : '';
    const response = hop.response.find(block => block.source === 'browser');
    if (response) {
      parts.push(trafficHeaderBlockSection(`response-${hop.hop}`,
        `Response headers${suffix}${response.statusCode ? ` (${response.statusCode})` : ''}`, response, rerender));
    }
    hop.response.filter(block => block.source === 'early_hints').forEach((block, index) =>
      parts.push(trafficHeaderBlockSection(`hints-${hop.hop}-${index}`, `Early hints${suffix} (103)`, block, rerender)));
    const sent = hop.request.find(block => block.source === 'network');
    const provisional = hop.request.find(block => block.source === 'browser');
    const shown = sent ?? provisional;
    if (shown) {
      parts.push(trafficHeaderBlockSection(`request-${hop.hop}`, `Request headers${suffix}`, shown, rerender,
        sent ? '' : 'Provisional headers are shown: the network stack had not reported what it sent, such as Cookie and Host.'));
    }
  }
  const key = JSON.stringify([request.origin, request.id, message, parts.map(part => part.key)]);
  if (container.dataset.renderKey === key) return;
  container.dataset.renderKey = key;
  const nodes = parts.map(part => part.section);
  if (message) nodes.splice(1, 0, trafficNode('p', 'traffic-headers-note', message));
  container.replaceChildren(...nodes);
}

if (typeof module === 'object' && module?.exports) module.exports = {trafficHeaderLines, trafficHeaderHops, renderTrafficHeaders};
