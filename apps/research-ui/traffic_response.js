/* Response and Preview tabs (protocol/native-network-v3.md). Content capture
 * sessions retain response bodies; every session retains script and Wasm
 * responses. Captured bytes only ever become text nodes, hex, a JSON tree of
 * text nodes, or a raster image whose signature matches its bytes. HTML is
 * shown as source and never rendered. */
const TRAFFIC_RESPONSE_PAGE_BYTES = 2 * 1024 * 1024;
const TRAFFIC_RESPONSE_CACHE_BYTES = 48 * 1024 * 1024;
const TRAFFIC_RESPONSE_RETRY_MS = 2000;
const TRAFFIC_RESPONSE_FIND_LIMIT = 1000;
// Hex shows one window of this many bytes at a time, paged to the end of the body.
const TRAFFIC_RESPONSE_HEX_BYTES = 256 * 1024;
const TRAFFIC_RESPONSE_CAPTURE_BYTES = 16n * 1024n * 1024n;
// Bytes of a cut, partial or stopped body can end inside a character.
const TRAFFIC_RESPONSE_OPEN_ENDED = new Set(['captured_truncated', 'partial', 'aborted', 'cancelled']);

const TRAFFIC_RESPONSE_CODINGS = Object.freeze({gzip: 'gzip', deflate: 'deflate', br: 'br', zstd: 'zstd',
  dcb: 'dcb (shared dictionary)', dcz: 'dcz (shared dictionary)', compress: 'compress', other: 'unrecognized'});

function trafficResponseBytes(value) {
  const count = BigInt(value);
  return `${count.toLocaleString('en-US')} ${count === 1n ? 'byte' : 'bytes'}`;
}

// Why a request's response body is or is not retained (protocol/native-network-v3.md
// "Bodies the proxy never sees"). The request index's body_case is the same
// decision, held equal by tools/check-request-index.mjs; an index row that has
// no records loaded carries its answer.
function responseBodyCase(request) {
  if (!request) return 'pending';
  if (!request.events?.length && request.responseBodyIndex) return request.responseBodyIndex.case;
  // A row with neither records nor an index answer cannot be decided.
  if (request.rank === undefined && !request.responseBody && !request.responseStarted) return 'unknown';
  const record = request.responseBody;
  if (record) return record.malformed ? 'malformed' : record.state;
  if (request.responseStarted) return ['js', 'wasm'].includes(request.type) ? 'source_artifact' : 'no_record';
  if (request.memoryCache) return 'memory_cache';
  if (request.fromServiceWorker && !request.failed && !request.interrupted && request.rank >= 5) return 'service_worker';
  if (request.redirected) return 'redirected';
  if (request.failed) return request.errorCode === -3 ? 'cancelled_before_response' : 'failed_before_response';
  if (request.interrupted) return 'interrupted';
  if (request.endLost) return 'end_lost';
  if (!(request.rank >= 5)) return 'pending';
  return request.browserObserved ? 'no_response' : 'renderer_answered';
}

// Seconds from the response's start to a record, or null.
function trafficResponseAfter(record, request) {
  const [at, start] = [record?.monotonicTimeNs, request?.responseStarted?.monotonicTimeNs];
  if (typeof at !== 'string' || typeof start !== 'string') return null;
  const elapsed = BigInt(at) - BigInt(start);
  return elapsed >= 0n ? `${(Number(elapsed / 1000000n) / 1000).toFixed(1)} s` : null;
}

// Why a request with no body record has none, by its body case.
function trafficResponseUnseen(request, contentSession, kind = responseBodyCase(request)) {
  const error = request?.errorCode ? ` (net error ${request.errorCode})` : '';
  return {
    source_artifact: 'Scripts and Wasm are retained as source artifacts. This one is not in the current catalog: its acknowledgment is pending, it was refused (see artifact_capture_failed in Evidence), or the session retains more than the 100,000 sources the catalog loads.',
    no_record: contentSession
      ? 'No response body record. The body may still be arriving, or its record left the retained window.'
      : 'Response bodies are retained only in content capture sessions. Scripts and Wasm are retained in every session.',
    memory_cache: request?.staticData
      ? 'Decoded in the renderer: Blink decoded this data: URL or MHTML archive resource itself, so no request was made and no body passed the browser. A data: URL\'s content is the URL itself.'
      : 'Reused from the memory cache: Blink answered this load from a resource it already held, so no request was made and no body passed the browser.',
    service_worker: 'Served by a service worker: the worker answered in the renderer, which the browser network proxy never sees, so the bytes the page received are not retained for this request.',
    redirected: 'Every response was a redirect. Chromium discards redirect bodies.',
    failed_before_response: request?.fromServiceWorker
      ? `The service worker ended this request without a response${error}, so there was no body.`
      : `Failed before any response${error}, so there was no body.`,
    cancelled_before_response: request?.fromServiceWorker
      ? 'Cancelled while the service worker held it, before any response, so there was no body.'
      : 'Cancelled before any response: the page or browser stopped the request, so there was no body.',
    interrupted: 'Observation ended before any response: the browser proxy was destroyed or handed the request to another loader, so whether a body followed is not recorded.',
    end_lost: 'A service worker ended this request, but the renderer had reused the slot that held its start, so its outcome and any body are not recorded.',
    pending: 'No response yet.',
    renderer_answered: 'Answered in the renderer without a URL loader (data:, blob: and other local schemes), so no body passed the browser network proxy. A data: URL\'s content is the URL itself.',
    no_response: 'The request ended with no response record, so there is no body to show.'
  }[kind] ?? 'The browser network proxy recorded no response for this request.';
}

// What the record says happened to the body, or why there is no record.
function trafficResponseCapture(request, contentSession) {
  const record = request?.responseBody;
  if (record?.malformed) return 'The response body record is malformed and was not interpreted.';
  if (!record) return trafficResponseUnseen(request, contentSession);
  const kept = `${trafficResponseBytes(record.capturedLength)} of ${trafficResponseBytes(record.bodyLength)}`;
  const after = trafficResponseAfter(record, request);
  const sealed = record.state === 'partial' && BigInt(record.capturedLength) < BigInt(record.bodyLength);
  return {
    captured: record.shared ? 'Retained in full. Identical bytes were already retained, so this names that artifact.' : 'Retained in full.',
    captured_truncated: `Retained prefix: ${kept}, truncated at the 16 MiB capture limit.`,
    partial: `Still arriving: ${trafficResponseBytes(record.bodyLength)} had arrived${after ? ` ${after} after the response started` : ''}, at snapshot ${record.partialIndex}. ${sealed
      ? `The first ${trafficResponseBytes(record.capturedLength)} reached the 16 MiB capture limit and are retained as they will stay; later bytes are only counted.`
      : 'All of them are retained in this snapshot.'} The record of the ended body replaces it.`,
    aborted: record.capturedLength === '0' ? 'Aborted: the network failed before any byte was retained.'
      : `Aborted: the network failed mid-body. The ${trafficResponseBytes(record.capturedLength)} that arrived are retained.`,
    cancelled: record.capturedLength === '0' ? 'Cancelled: the page or browser stopped the request before any byte arrived.'
      : `Cancelled: the page or browser stopped reading. The ${trafficResponseBytes(record.capturedLength)} that arrived are retained.`,
    empty: 'Empty body (0 bytes).',
    not_modified: 'Not modified (304): the server sent no body.',
    redirected: 'Redirect: Chromium discards redirect bodies.',
    not_captured_type: 'Not retained: images, audio, video and fonts that page elements load are kept only with REB_CAPTURE_RESPONSE_MEDIA=1.',
    not_captured_artifact_unavailable: 'Not retained: the artifact channel was unavailable.',
    not_captured_transfer_refused: 'Not retained: the bounded in-flight memory or artifact transfer queue refused it.',
    not_captured_session_budget: 'Not retained: this session had used its response body budget. Raise REB_RESPONSE_BODY_BUDGET_MIB for a new session.'
  }[record.state] ?? 'Unknown capture state.';
}

function trafficResponseRows(record) {
  if (!record || record.malformed) return [];
  const codings = record.codings.map(coding => TRAFFIC_RESPONSE_CODINGS[coding] ?? coding).join(', ');
  const notes = [record.fromCache && 'served from the HTTP cache', record.serviceWorker && 'served by a service worker',
    record.completionUnobserved && 'the loader reported no completion, so the end is unconfirmed'].filter(Boolean);
  return [
    ['Content type', record.contentType ?? 'Not a bounded media type; not recorded', record.contentType ? 'value' : 'prose'],
    ['Content encoding', codings ? `${codings}${record.codingsOmitted ? ', more not recorded' : ''} · ${record.stillEncoded
      ? 'bytes are as transferred (client-side decoding)' : 'bytes are decoded'}` : 'None', codings ? 'value' : 'prose'],
    ['Body length', record.bodyLength === '0' && record.state !== 'empty'
      ? 'Not observed' : `${trafficResponseBytes(record.bodyLength)} decoded`, 'value'],
    ['SHA-256', record.sha256 ?? 'No retained bytes', record.sha256 ? 'value' : 'prose'],
    ...(notes.length ? [['Delivery', notes.join('; '), 'prose']] : [])
  ];
}

// The artifact that holds this request's response bytes: the record's own,
// or a script or Wasm artifact created by the final response_started record.
function trafficResponseArtifact(request, artifacts) {
  const record = request?.responseBody;
  const response = request?.responseStarted;
  if (record && !record.malformed) {
    if (record.artifactId === '0') return null;
    return artifacts.find(artifact => artifact.artifact_id === record.artifactId && artifact.kind === 'response_body' &&
      artifact.session_id === record.sessionId && (record.shared || artifact.creator_event_id === record.parentEventId)) ?? null;
  }
  if (!response) return null;
  const matches = artifacts.filter(artifact => ['javascript', 'wasm'].includes(artifact.kind) &&
    artifact.capture_origin === 'network_response' && artifact.session_id === response.sessionId &&
    artifact.creator_event_id === response.sequenceNumber);
  return matches.length === 1 ? matches[0] : null;
}

// Raster formats only, and only when the bytes carry that format's signature.
function trafficImageType(bytes, mime) {
  const at = (offset, signature) => [...signature].every((character, index) => bytes[offset + index] === character.charCodeAt(0));
  const type = String(mime ?? '').toLowerCase();
  const found = at(0, '\x89PNG\r\n\x1a\n') ? 'image/png'
    : at(0, '\xff\xd8\xff') ? 'image/jpeg'
      : at(0, 'GIF87a') || at(0, 'GIF89a') ? 'image/gif'
        : at(0, 'RIFF') && at(8, 'WEBP') ? 'image/webp'
          : at(4, 'ftypavif') || at(4, 'ftypavis') ? 'image/avif'
            : at(0, 'BM') ? 'image/bmp'
              : at(0, '\x00\x00\x01\x00') ? 'image/x-icon' : null;
  return found && (type.startsWith('image/') || type === 'application/octet-stream' || type === '') ? found : null;
}

// `open`: the bytes may end inside a character, which is left out rather than failed.
// Text that is not UTF-8 shows with replacement characters; control bytes mean binary.
function trafficResponseText(bytes, open = false) {
  try {
    const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes, {stream: open});
    return /\u0000/.test(text) ? null : {text, lossy: false};
  } catch {
    if (bytes.some(byte => (byte < 32 && ![9, 10, 12, 13].includes(byte)) || byte === 127)) return null;
    return {text: new TextDecoder('utf-8', {fatal: false, ignoreBOM: true}).decode(bytes, {stream: open}), lossy: true};
  }
}

// A body the request index (`response_body`) or the Traffic model describes, as a
// request the artifact join reads: its record and its final response.
function trafficResponseStand(id, type, body) {
  const started = body?.response_started;
  const responseStarted = started ? {sequenceNumber: started.sequence_number, sessionId: started.session_id,
    processId: started.process_id} : null;
  const responseBody = body?.artifact_id && started ? {state: body.case, shared: body.shared === true,
    artifactId: body.artifact_id, sessionId: started.session_id, parentEventId: started.sequence_number,
    bodyLength: body.body_length, capturedLength: body.captured_length, sha256: body.sha256, partialIndex: body.partial_index ?? 0} : null;
  return {id, type, responseStarted, responseBody};
}

// The row a memory-cache reuse names as the request whose response Blink
// reused (protocol/native-network-v3.md), from the index or the model's rows.
function trafficMemoryCacheSource(request, rows = []) {
  const id = request?.memoryCacheSource;
  if (!id) return null;
  const indexed = request.memoryCacheSourceRow;
  if (indexed?.id === id) {
    return {id, found: indexed.found === true, body: indexed.response_body ?? null, path: indexed.path ?? null,
      stand: indexed.found ? trafficResponseStand(id, indexed.type, indexed.response_body) : null};
  }
  const row = rows.find(candidate => candidate.id === id);
  if (!row) return {id, found: null, body: null, path: null, stand: null};
  return {id, found: true, body: {case: responseBodyCase(row)}, path: row.path,
    stand: {id, type: row.type, responseStarted: row.responseStarted, responseBody: row.responseBody}};
}

// Requests the service worker made for this request's URL while it was open:
// the bytes it answered with may be theirs, which the records do not prove.
function trafficServiceWorkerFetches(request, rows) {
  if (!request || responseBodyCase(request) !== 'service_worker') return [];
  const url = row => `${row.host ?? ''}${row.target ?? (row.hostOnly ? '' : row.path)}`;
  const wanted = url(request);
  if (!request.host || wanted === request.host) return [];
  return rows.filter(row => row.id !== request.id && row.initiator === 'worker' && url(row) === wanted &&
    row.firstTimestamp >= request.firstTimestamp && row.firstTimestamp <= request.lastTimestamp);
}

// One line for each body case, as the session summary words it.
function trafficResponseCaseMeaning(kind) {
  return {
    captured: 'retained in full', captured_truncated: 'retained up to the 16 MiB capture limit',
    partial: 'still arriving; its newest snapshot is retained', aborted: 'the network failed mid-body; what arrived is retained',
    cancelled: 'stopped mid-body; what arrived is retained', empty: 'an empty body', not_modified: 'HTTP 304, no body',
    redirected: 'a redirect, whose body Chromium discards', not_captured_type: 'media or a font, not asked for',
    not_captured_artifact_unavailable: 'the artifact channel was unavailable', not_captured_transfer_refused: 'refused by the bounded transfer',
    not_captured_session_budget: 'past the response body budget', malformed: 'a malformed record',
    source_artifact: 'retained as a source artifact', no_record: 'no body record', memory_cache: 'itself reused from the memory cache',
    service_worker: 'itself served by a service worker', failed_before_response: 'failed before any response',
    cancelled_before_response: 'cancelled before any response', interrupted: 'observation ended first', end_lost: 'its end was lost',
    pending: 'no response yet', renderer_answered: 'answered in the renderer', no_response: 'no response record'
  }[kind] ?? 'unknown';
}

// `request` and `worker` replace the format client's backend read and layout worker.
// `related(request)` answers {status, rows} of rows that may hold its bytes;
// `open(id)` selects another Traffic row.
function createTrafficResponse({getArtifacts, getEvents, contentSession, readable, onChange, request, worker, lookup = null,
  getRequests = () => [], related = null, open = null}) {
  const views = new Map();
  const options = {pretty: false, wrap: true, hex: false, query: '', current: 0, hexKey: null, hexOffset: 0};
  const previews = new Map();
  let previewArea = null;
  let generation = 0;
  const layouts = createCodeLayouts({request, layouts: worker, onChange: () => {generation += 1; onChange();}});

  async function load(artifact, key, previous) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const mismatch = message => Object.assign(new Error(message), {integrity: true});
    const loaded = previous?.bytes ?? new Uint8Array(0);
    let view;
    try {
      const limit = Math.min(artifact.byte_size - loaded.length, TRAFFIC_RESPONSE_PAGE_BYTES);
      const response = await fetch(`/api/artifacts/${encodeURIComponent(artifact.artifact_id)}/content?offset=${loaded.length}&limit=${limit}`,
        {cache: 'no-store', signal: controller.signal});
      if (!response.ok) {
        if (response.status === 500 && (await Promise.resolve(response.json?.()).catch(() => null))?.code === 'artifact_integrity') throw mismatch('its bytes do not match the retained SHA-256');
        response.body?.cancel().catch(() => {});
        throw new Error(`the artifact store returned ${response.status}`);
      }
      const chunk = await sourceFactsReadBytes(response, limit, controller.signal);
      if (chunk.length !== limit) throw mismatch('its retained byte size changed');
      const bytes = new Uint8Array(loaded.length + chunk.length);
      bytes.set(loaded);
      bytes.set(chunk, loaded.length);
      const complete = bytes.length === artifact.byte_size;
      let verified = false;
      if (complete && globalThis.crypto?.subtle) {
        const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
          byte => byte.toString(16).padStart(2, '0')).join('');
        if (digest !== artifact.sha256) throw mismatch('its bytes do not match the retained SHA-256');
        verified = true;
      }
      view = {status: 'ready', artifact, bytes, complete, verified, loaded: bytes.length, total: artifact.byte_size};
    } catch (error) {
      const message = controller.signal.aborted ? 'timed out after 10 seconds' : String(error?.message ?? error).replace(/\.$/, '');
      view = previous ? {...previous, moreError: message}
        : {status: 'error', error: message, retryable: error?.integrity !== true, failedAt: Date.now()};
    } finally {
      clearTimeout(timeout);
    }
    views.delete(key);
    views.set(key, view);
    evict(key);
    onChange();
  }

  // Bytes and parsed previews share one budget. A preview goes with its view,
  // and its source length stands in for an object graph that is larger still.
  function evict(keep) {
    const cost = (item, key) => (item.bytes?.length ?? 0) + (previews.get(key)?.sourceBytes ?? 0);
    let retained = [...views.entries()].reduce((sum, [key, item]) => sum + cost(item, key), 0);
    for (const [oldest, item] of views) {
      if (views.size <= 8 && retained <= TRAFFIC_RESPONSE_CACHE_BYTES) break;
      if (oldest === keep) continue;
      retained -= cost(item, oldest);
      views.delete(oldest);
      previews.delete(oldest);
    }
  }

  function viewOf(artifact) {
    if (!readable()) return {status: 'unavailable'};
    const key = `${artifact.session_id}:${artifact.artifact_id}:${artifact.sha256}`;
    const current = views.get(key);
    if (current?.retryable && Date.now() - current.failedAt >= TRAFFIC_RESPONSE_RETRY_MS) {
      views.set(key, {status: 'loading', previous: current});
      void load(artifact, key, null);
      return {...current, key};
    }
    if (current) return {...(current.previous ?? current), loadingMore: current.status === 'loading' && Boolean(current.previous?.bytes), key};
    views.set(key, {status: 'loading'});
    void load(artifact, key, null);
    return {status: 'loading', key};
  }

  function more(key) {
    const view = views.get(key);
    if (view?.status !== 'ready' || view.complete) return;
    views.set(key, {status: 'loading', previous: {...view, moreError: null}});
    void load(view.artifact, key, view);
    onChange();
  }

  // The receiver's refusal joins the artifact's creator record exactly.
  function refusalOf(request) {
    const record = request?.responseBody;
    if (!record || record.malformed || record.artifactId === '0') return null;
    const event = (getEvents() ?? []).find(item => item.type === 'artifact_capture_failed' && item.artifact_id === record.artifactId &&
      item.session_id === record.sessionId && (record.shared || item.parent_event_id === record.parentEventId));
    return event ? decodePayload(event) || 'unknown reason' : null;
  }

  // Past the catalog's cap, or not in it yet: read the artifact by ID.
  function artifactOf(selected, record) {
    const catalog = trafficResponseArtifact(selected, getArtifacts() ?? []);
    if (catalog || !lookup || !readable() || !record || record.malformed || record.artifactId === '0') return {artifact: catalog, found: null};
    const found = lookup(record, selected);
    return {artifact: found.status === 'found' ? trafficResponseArtifact(selected, [found.artifact]) : null, found};
  }

  function contentNote(record, artifact, view, refusal, found) {
    if (refusal) {
      return refusal === 'sensitive_capture_disabled'
        ? 'The artifact receiver refused it: the session receiver was not started for sensitive capture.'
        : `The artifact receiver did not retain it (${refusal}).`;
    }
    if (!artifact) {
      if (!record || record.malformed || record.artifactId === '0') return null;
      if (found?.status === 'loading') return 'Looking up the retained body…';
      return found?.status === 'unknown'
        ? 'The body artifact is not in the scanned range of the artifact manifest, so whether it was retained is unknown.'
        : 'The body artifact is not in the artifact manifest: its acknowledgment is pending.';
    }
    if (view.status === 'unavailable') return 'Retained bodies are read from the local backend, which this view does not have.';
    if (view.status === 'loading') return 'Loading the retained body…';
    if (view.status === 'error') return `The retained body could not be read: ${view.error}.${view.retryable ? ' It is read again on the next refresh.' : ''}`;
    const notes = [];
    if (!view.complete) notes.push(`Showing the first ${trafficResponseBytes(view.loaded)} of ${trafficResponseBytes(view.total)} retained.`);
    if (view.moreError) notes.push(`The next range could not be read: ${view.moreError}.`);
    if (!view.verified) notes.push(view.complete ? 'The retained digest could not be rechecked in this view.'
      : 'The local backend checked the retained digest; this view rechecks it once every byte is shown.');
    return notes.join(' ') || null;
  }

  function codeView(text, artifact, language, {layout = null, status = null, find = true} = {}) {
    const syntax = language === 'text' ? {kind: 'plain', mime_type: 'text/plain'}
      : {kind: artifact.kind === 'wasm' ? 'wasm' : 'response_body', mime_type: artifact.mime_type, url: artifact.url};
    const rows = codeViewRows(text);
    const found = find && options.query ? findSourceOccurrences(rows.map(row => row.text), options.query, TRAFFIC_RESPONSE_FIND_LIMIT) : {matches: []};
    const current = found.matches.length ? options.current % found.matches.length : -1;
    const marks = new Map();
    found.matches.forEach((match, index) => {
      if (!marks.has(match.line)) marks.set(match.line, []);
      marks.get(match.line).push({column: match.column, length: match.length, match: index});
    });
    const view = createCodeView({text, rows, syntax, label: 'Response body', className: 'traffic-response-code', rowClass: 'traffic-response-line',
      wrap: options.wrap, marks, current, layout: layout?.map ? layout : null, onRaw: status && (raw => {status.textContent = codeViewRawText(raw);})});
    if (current >= 0) view.reveal(found.matches[current].line);
    return {code: view.box, view, matches: found.matches.length, truncated: Boolean(found.truncated), current};
  }

  // Preview shares the Payload tree, so its reach and keys are the same.
  function jsonPreview(key, value, sourceBytes) {
    let shown = previews.get(key);
    if (!shown) {
      shown = {model: {json: {value}, keys: new WeakMap()}, expanded: new Set(['$']), selected: null,
        find: {query: '', matches: [], current: -1, truncated: false}, sourceBytes};
      previews.set(key, shown);
      while (previews.size > 8) previews.delete(previews.keys().next().value);
      evict(key);
    }
    const holder = trafficNode('div', 'traffic-response-tree');
    const draw = (focus = false, keepScroll = false) => {
      const top = keepScroll ? previewArea?.box.scrollTop ?? 0 : 0;
      previewArea?.dispose();
      previewArea = trafficPayloadTreeArea(shown.model, shown, () => draw(true, true), 'Response JSON tree');
      holder.replaceChildren(previewArea.box);
      previewArea.box.scrollTop = top;
      if (focus) previewArea.box.querySelector('[tabindex="0"]')?.focus();
    };
    draw();
    return holder;
  }

  function toolbar(container, binary, prettyable, shown, text, copyNote) {
    const bar = trafficNode('div', 'traffic-response-toolbar');
    bar.setAttribute('role', 'toolbar');
    bar.setAttribute('aria-label', 'Response body view');
    const toggle = (control, label, pressed, disabled = false) => {
      const button = trafficNode('button', 'secondary-button', label);
      button.type = 'button';
      button.dataset.control = control;
      button.setAttribute('aria-pressed', String(pressed));
      button.disabled = disabled;
      bar.append(button);
    };
    toggle('pretty', 'Pretty print', options.pretty && prettyable, !prettyable || options.hex);
    toggle('wrap', 'Wrap', options.wrap);
    toggle('hex', 'Hex', binary || options.hex, binary);
    const copy = trafficNode('button', 'secondary-button', 'Copy');
    copy.type = 'button';
    copy.dataset.control = 'copy';
    bar.append(copy);
    const find = document.createElement('input');
    find.type = 'search';
    find.className = 'traffic-response-find';
    find.placeholder = 'Find';
    find.value = options.query;
    find.dataset.control = 'find';
    find.setAttribute('aria-label', 'Find in response body');
    bar.append(find);
    const findCount = shown.matches;
    const count = trafficNode('span', 'traffic-response-count', !options.query ? '' : !findCount ? 'No matches'
      : `${shown.current + 1} of ${findCount.toLocaleString('en-US')}${shown.truncated ? '+' : ''}`);
    count.setAttribute('aria-live', 'polite');
    const status = trafficNode('span', 'traffic-response-status');
    status.setAttribute('role', 'status');
    bar.append(count, status);
    bar.addEventListener('click', event => {
      const control = event.target.closest('button')?.dataset.control;
      if (!control) return;
      if (control === 'copy') {
        void trafficCopyText(text, status, copyNote);
        return;
      }
      options[control] = !options[control];
      container.dataset.renderKey = '';
      onChange();
    });
    find.addEventListener('input', () => {
      options.query = find.value;
      options.current = 0;
      container.dataset.renderKey = '';
      onChange();
      container.querySelector('.code-view-mark.is-current')?.scrollIntoView?.({block: 'center'});
    });
    find.addEventListener('keydown', event => {
      if (event.key !== 'Enter' || !findCount) return;
      event.preventDefault();
      options.current = (shown.current + (event.shiftKey ? findCount - 1 : 1)) % findCount;
      container.dataset.renderKey = '';
      onChange();
      container.querySelector('.code-view-mark.is-current')?.scrollIntoView?.({block: 'center'});
    });
    return bar;
  }

  // Previous and next hex windows; a window past the loaded bytes reads the next range.
  function hexPager(range, view) {
    const bar = trafficNode('div', 'traffic-response-hex-pager');
    bar.setAttribute('role', 'group');
    bar.setAttribute('aria-label', 'Hex range');
    for (const [control, label, step, disabled] of [
      ['hex-previous', `Previous ${trafficResponseBytes(TRAFFIC_RESPONSE_HEX_BYTES)}`, -1, range.start === 0],
      ['hex-next', `Next ${trafficResponseBytes(TRAFFIC_RESPONSE_HEX_BYTES)}`, 1, range.end >= view.total]]) {
      const button = trafficNode('button', 'secondary-button', label);
      button.type = 'button';
      button.dataset.control = control;
      // Not `disabled`, so keyboard focus stays when a step reaches either end.
      button.setAttribute('aria-disabled', String(disabled));
      button.addEventListener('click', () => {
        if (disabled) return;
        options.hexOffset = Math.max(0, range.start + step * TRAFFIC_RESPONSE_HEX_BYTES);
        onChange();
      });
      bar.append(button);
    }
    return bar;
  }

  function responseBody(container, request, artifact, view) {
    const nodes = [];
    const bytes = view.bytes;
    const decoded = trafficResponseText(bytes, !view.complete || TRAFFIC_RESPONSE_OPEN_ENDED.has(request?.responseBody?.state));
    const text = decoded?.text ?? null;
    const binary = text === null;
    const source = {kind: 'response_body', mime_type: artifact.mime_type, url: artifact.url};
    const language = binary ? 'bytes' : sourceSyntaxLanguage(source);
    const prettyable = !binary && sourcePrettySupported(source);
    let shown;
    let value = text;
    let note = null;
    let copyNote = 'Copied.';
    let layout = null;
    const raw = trafficNode('p', 'traffic-body-note code-view-raw');
    raw.setAttribute('role', 'status');
    let hexWindow = null;
    if (binary || options.hex) {
      // One window at a time, paged by range to the end of the retained body.
      if (options.hexKey !== view.key) {
        options.hexKey = view.key;
        options.hexOffset = 0;
      }
      const last = Math.max(0, Math.floor((view.total - 1) / TRAFFIC_RESPONSE_HEX_BYTES) * TRAFFIC_RESPONSE_HEX_BYTES);
      const start = Math.min(options.hexOffset, last);
      const end = Math.min(start + TRAFFIC_RESPONSE_HEX_BYTES, view.total);
      hexWindow = {start, end, loaded: bytes.length >= end};
      value = formatWasmHex(bytes.subarray(start, Math.min(end, bytes.length)), start);
      shown = codeView(value, artifact, 'text');
      if (view.total > TRAFFIC_RESPONSE_HEX_BYTES) {
        note = `Hex shows bytes ${start.toLocaleString('en-US')} to ${(end - 1).toLocaleString('en-US')} of ${trafficResponseBytes(view.total)}.`;
        copyNote = `Copied the hex of bytes ${start.toLocaleString('en-US')} to ${(end - 1).toLocaleString('en-US')} of ${trafficResponseBytes(view.total)}.`;
      }
      // A window past the loaded ranges reads the next range itself.
      if (!hexWindow.loaded && !view.loadingMore && !view.moreError) void Promise.resolve().then(() => more(view.key));
    } else {
      if (options.pretty && prettyable && view.complete) {
        layout = layouts.layout(artifact, text, source, null);
        note = codeLayoutNote(layout);
        if (layout.status === 'ready') value = layout.text;
      } else if (options.pretty && prettyable) {
        note = 'Pretty print waits until every retained byte is shown.';
      }
      shown = codeView(value, artifact, language, {layout: layout?.status === 'ready' ? layout : null, status: raw});
    }
    if (!binary && !view.complete && !options.hex) copyNote = `Copied the ${trafficResponseBytes(bytes.length)} loaded so far; ${trafficResponseBytes(view.total - bytes.length)} more are retained.`;
    nodes.push(toolbar(container, binary, prettyable, shown, value, copyNote));
    if (decoded?.lossy && !options.hex) nodes.push(trafficNode('p', 'traffic-body-note', 'Not valid UTF-8; shown with replacement characters. Hex shows the exact bytes.'));
    if (note) nodes.push(trafficNode('p', 'traffic-body-note', note));
    if (hexWindow && view.total > TRAFFIC_RESPONSE_HEX_BYTES) nodes.push(hexPager(hexWindow, view));
    if (hexWindow && !hexWindow.loaded) {
      nodes.push(trafficNode('p', 'traffic-body-note', view.moreError
        ? `These bytes could not be read: ${view.moreError}.` : 'Reading these bytes…'));
    }
    nodes.push(shown.code);
    if (layout?.status === 'ready' && layout.map) nodes.push(raw);
    if (!view.complete && !hexWindow) {
      const button = trafficNode('button', 'secondary-button traffic-body-more', view.loadingMore ? 'Loading…' : 'Show the next 2 MiB');
      button.type = 'button';
      button.dataset.control = 'more';
      // Not `disabled`, so keyboard focus stays on it while the range loads.
      button.setAttribute('aria-disabled', String(Boolean(view.loadingMore)));
      button.addEventListener('click', () => more(view.key));
      nodes.push(button);
    }
    return nodes;
  }

  function preview(artifact, view, record) {
    if (!view.complete) {
      if (!view.moreError) return [trafficNode('p', 'traffic-body-note', 'Reading every retained byte for Preview…')];
      const retry = trafficNode('button', 'secondary-button traffic-body-more', 'Read the rest again');
      retry.type = 'button';
      retry.dataset.control = 'more';
      retry.addEventListener('click', () => more(view.key));
      return [trafficNode('p', 'traffic-body-note', 'Preview needs every retained byte, and the next range could not be read.'), retry];
    }
    const bytes = view.bytes;
    const image = trafficImageType(bytes, artifact.mime_type);
    if (image) {
      const figure = trafficNode('figure', 'traffic-response-image');
      const img = document.createElement('img');
      img.alt = 'Retained response image';
      img.decoding = 'async';
      let binary = '';
      for (let offset = 0; offset < bytes.length; offset += 32768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
      img.src = `data:${image};base64,${btoa(binary)}`;
      const caption = trafficNode('figcaption', '', `${image} · ${trafficResponseBytes(bytes.length)}`);
      img.addEventListener('load', () => {caption.textContent = `${image} · ${img.naturalWidth} × ${img.naturalHeight} · ${trafficResponseBytes(bytes.length)}`;});
      img.addEventListener('error', () => {caption.textContent = 'The browser could not decode this image. Original evidence is unchanged.';});
      figure.append(img, caption);
      return [figure];
    }
    const decoded = trafficResponseText(bytes, TRAFFIC_RESPONSE_OPEN_ENDED.has(record?.state));
    if (decoded === null) return [trafficNode('p', 'traffic-body-note', 'Binary body: no preview. The Response tab shows it as hex.')];
    const {text, lossy} = decoded;
    const lossyNote = lossy ? [trafficNode('p', 'traffic-body-note', 'Not valid UTF-8; shown with replacement characters. The Response tab shows the bytes as hex.')] : [];
    const language = sourceSyntaxLanguage({kind: 'response_body', mime_type: artifact.mime_type, url: artifact.url});
    if (language === 'json' || /^\s*[[{]/.test(text)) {
      try {
        return [...lossyNote, jsonPreview(`${artifact.session_id}:${artifact.artifact_id}:${artifact.sha256}`, JSON.parse(text), text.length)];
      } catch {
        if (language === 'json') return [trafficNode('p', 'traffic-body-note', 'Not valid JSON; the Response tab shows its text.'), trafficNode('pre', 'traffic-body-text', text)];
      }
    }
    if (language === 'markup') {
      return [...lossyNote, trafficNode('p', 'traffic-body-note', 'Markup is shown as source and never rendered.'), codeView(text, artifact, 'markup', {find: false}).code];
    }
    const pre = trafficNode('pre', 'traffic-body-text', text);
    pre.tabIndex = 0;
    return [...lossyNote, pre];
  }

  // The rows a related lookup found for a service-worker answer, read once per request.
  const relatedAnswers = new Map();
  function fetchesOf(target) {
    const local = trafficServiceWorkerFetches(target, getRequests() ?? []);
    if (!related) return {status: 'ready', rows: local};
    let entry = relatedAnswers.get(target.id);
    if (!entry) {
      entry = {status: 'loading', rows: []};
      relatedAnswers.set(target.id, entry);
      while (relatedAnswers.size > 16) relatedAnswers.delete(relatedAnswers.keys().next().value);
      Promise.resolve().then(() => related(target)).then(answer => {
        entry.status = answer?.status ?? 'ready';
        entry.rows = Array.isArray(answer?.rows) ? answer.rows : [];
      }, () => {entry.status = 'unavailable';}).finally(onChange);
    }
    const rows = [...local, ...trafficServiceWorkerFetches(target, entry.rows).filter(row => !local.some(item => item.id === row.id))];
    return {status: entry.status, rows};
  }

  // A button that selects another Traffic row, when this view can.
  function opener(id, label) {
    const button = trafficNode('button', 'secondary-button traffic-response-open', label);
    button.type = 'button';
    button.dataset.control = `open-${id}`;
    button.dataset.request = id;
    button.addEventListener('click', () => open?.(id));
    return button;
  }

  // How a reuse names its source, and whether that source's bytes are shown.
  function sourceNote(request, source) {
    if (!source) {
      return request.staticData ? null : 'The reused resource names no request of this renderer: its record predates naming one, or no request set the response\'s ID.';
    }
    if (source.found === null) return `It names request ${source.id} of this renderer, which is not among the rows loaded here.`;
    if (!source.found) {
      return `Blink names request ${source.id} of this renderer as the one that loaded it, which this session did not record: it loaded before the session started, or its records are not indexed.`;
    }
    const kind = source.body?.case;
    if (source.stand?.responseBody || kind === 'source_artifact') {
      return 'Blink names the request of this renderer that loaded the resource. That request\'s retained body is shown here: the bytes Blink held.';
    }
    return `Blink names the request of this renderer that loaded the resource. Its body was not retained: ${trafficResponseCaseMeaning(kind)}.`;
  }

  function render(container, request, tab) {
    const record = request?.responseBody ?? null;
    const kind = responseBodyCase(request);
    const source = kind === 'memory_cache' && request ? trafficMemoryCacheSource(request, getRequests() ?? []) : null;
    const fetches = kind === 'service_worker' && request ? fetchesOf(request) : null;
    // A reuse shows the bytes of the request it names; nothing else stands in for a body.
    const shownFrom = source?.stand ?? request;
    const shownRecord = source?.stand ? source.stand.responseBody : record;
    const {artifact, found} = request ? artifactOf(shownFrom, shownRecord) : {artifact: null, found: null};
    const refusal = artifact ? null : refusalOf(shownFrom) ?? (found?.status === 'refused' ? found.reason || 'unknown reason' : null);
    const view = artifact ? viewOf(artifact) : null;
    const key = JSON.stringify([request?.id, request?.origin, tab, record, kind, request?.responseStarted?.sequenceNumber, artifact?.artifact_id,
      source && [source.id, source.found, source.body?.case], fetches && [fetches.status, fetches.rows.map(row => [row.id, row.responseBodyIndex?.case])],
      refusal, found?.status, view && [view.status, view.loaded, view.error, view.moreError, view.loadingMore], options, generation]);
    if (container.dataset.renderKey === key) return;
    container.dataset.renderKey = key;
    // The same body keeps its place across a next range, wrap or pretty print.
    const scrollKey = JSON.stringify([request?.id, request?.origin, tab, artifact?.artifact_id]);
    const shownCode = container.dataset.scrollKey === scrollKey ? container.querySelector('.traffic-response-code') : null;
    const scroll = shownCode ? {top: shownCode.scrollTop, left: shownCode.scrollLeft} : null;
    container.dataset.scrollKey = scrollKey;
    previewArea?.dispose();
    previewArea = null;
    const active = container.contains(document.activeElement) ? document.activeElement.dataset?.control : null;
    const caret = active === 'find' ? document.activeElement.selectionStart : null;
    const nodes = [trafficNode('h2', '', tab === 'preview' ? 'Preview' : 'Response')];
    if (!request) {
      container.replaceChildren(trafficNode('div', 'exchange-no-selection', 'Select a request to inspect its response.'));
      return;
    }
    const own = artifact && !record && !source;
    const rows = [['Capture', own ? 'Retained as a source artifact by this response.' : trafficResponseCapture(request, contentSession()), 'prose'],
      ...trafficResponseRows(record)];
    const reused = kind === 'memory_cache' ? sourceNote(request, source) : null;
    if (reused) rows.push(['Reused from', reused, 'prose']);
    if (fetches) {
      rows.push(['Worker fetches', fetches.status === 'loading' ? 'Looking for requests the service worker made for this URL…'
        : fetches.rows.length ? `The service worker requested this URL while this request was open (${fetches.rows.length === 1 ? 'one request' : `${fetches.rows.length} requests`}). The records do not say whether it answered with those bytes.`
          : fetches.status === 'unavailable' ? 'Requests the service worker made could not be looked up.'
            : 'The service worker made no recorded request for this URL while this one was open: it built the response or took it from Cache Storage, so the bytes are retained nowhere.', 'prose']);
    }
    if (artifact) rows.push([source?.stand ? 'Artifact (reused request)' : 'Artifact', `${artifact.kind} ${artifact.artifact_id} · ${artifact.mime_type}`, 'value']);
    // Preview names why, and leaves the record's fields to Response.
    for (const [label, value, valueKind] of tab === 'preview' ? rows.filter(([name]) => ['Capture', 'Reused from', 'Worker fetches'].includes(name)) : rows) {
      const row = trafficNode('div', 'traffic-general-row');
      const valueNode = trafficNode('span', 'traffic-general-value', String(value));
      valueNode.dataset.kind = valueKind;
      row.append(trafficNode('span', '', label), valueNode);
      nodes.push(row);
    }
    const links = [];
    if (source?.found && open) links.push(opener(source.id, `Open the request it reused${source.path ? `: ${source.path}` : ''}`));
    for (const row of (fetches?.rows ?? []).slice(0, 3)) {
      const body = row.responseBodyIndex?.case ?? responseBodyCase(row);
      if (open) links.push(opener(row.id, `Open the worker's request (${trafficResponseCaseMeaning(body)})`));
    }
    if (links.length) {
      const bar = trafficNode('div', 'traffic-response-links');
      bar.append(...links);
      nodes.push(bar);
    }
    const note = contentNote(shownRecord, artifact, view ?? {}, refusal, found);
    if (note) nodes.push(trafficNode('p', 'traffic-body-note', note));
    if (view?.status === 'ready') {
      nodes.push(...(tab === 'preview' ? preview(artifact, view, shownRecord) : responseBody(container, source?.stand ?? request, artifact, view)));
    }
    container.replaceChildren(...nodes);
    container.dataset.state = record?.malformed ? 'malformed' : record?.state ?? (own ? 'source_artifact' : kind);
    const code = scroll && container.querySelector('.traffic-response-code');
    if (code) {
      code.scrollTop = scroll.top;
      code.scrollLeft = scroll.left;
    }
    if (active) {
      const control = container.querySelector(`[data-control="${active}"]`) ??
        (active === 'more' ? container.querySelector('.traffic-response-code') : null);
      control?.focus?.();
      if (caret !== null && control?.setSelectionRange) control.setSelectionRange(caret, caret);
    }
    // A parsed preview needs every retained byte, so ranges are read on without a click.
    if (tab === 'preview' && view?.status === 'ready' && !view.complete && !view.loadingMore && !view.moreError) more(view.key);
  }

  return {render, more};
}
