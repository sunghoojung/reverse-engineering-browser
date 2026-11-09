/* Response and Preview tabs (protocol/native-network-v3.md). Content capture
 * sessions retain response bodies; every session retains script and Wasm
 * responses. Captured bytes only ever become text nodes, hex, a JSON tree of
 * text nodes, or a raster image whose signature matches its bytes. HTML is
 * shown as source and never rendered. */
const TRAFFIC_RESPONSE_PAGE_BYTES = 2 * 1024 * 1024;
const TRAFFIC_RESPONSE_CACHE_BYTES = 48 * 1024 * 1024;
const TRAFFIC_RESPONSE_RETRY_MS = 2000;
const TRAFFIC_RESPONSE_FIND_LIMIT = 1000;
const TRAFFIC_RESPONSE_HEX_BYTES = 256 * 1024;
// Bytes of a cut, partial or stopped body can end inside a character.
const TRAFFIC_RESPONSE_OPEN_ENDED = new Set(['captured_truncated', 'partial', 'aborted', 'cancelled']);

const TRAFFIC_RESPONSE_CODINGS = Object.freeze({gzip: 'gzip', deflate: 'deflate', br: 'br', zstd: 'zstd',
  dcb: 'dcb (shared dictionary)', dcz: 'dcz (shared dictionary)', compress: 'compress', other: 'unrecognized'});

function trafficResponseBytes(value) {
  const count = BigInt(value);
  return `${count.toLocaleString('en-US')} ${count === 1n ? 'byte' : 'bytes'}`;
}

// What the record says happened to the body, or why there is no record.
function trafficResponseCapture(request, contentSession) {
  const record = request?.responseBody;
  if (record?.malformed) return 'The response body record is malformed and was not interpreted.';
  if (!record) {
    if (!request?.responseStarted) {
      return request?.redirectedBody
        ? 'Every response was a redirect. Chromium discards redirect bodies.'
        : 'The browser network proxy recorded no response for this request. Service-worker and memory-cache answers, and requests that failed first, never reach it.';
    }
    if (['js', 'wasm'].includes(request.type)) {
      return 'Scripts and Wasm are retained as source artifacts. This one is not in the current catalog: its acknowledgment is pending, it was refused (see artifact_capture_failed in Evidence), or the session retains more than the 100,000 sources the catalog loads.';
    }
    return contentSession
      ? 'No response body record. The body may still be arriving, or its record left the retained window.'
      : 'Response bodies are retained only in content capture sessions. Scripts and Wasm are retained in every session.';
  }
  const kept = `${trafficResponseBytes(record.capturedLength)} of ${trafficResponseBytes(record.bodyLength)}`;
  return {
    captured: record.shared ? 'Retained in full. Identical bytes were already retained, so this names that artifact.' : 'Retained in full.',
    captured_truncated: `Retained prefix: ${kept}, truncated at the 16 MiB capture limit.`,
    partial: `Partial: snapshot ${record.partialIndex} while the body was still arriving (${kept}). It is replaced when the body ends.`,
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

// `request` and `worker` replace the format client's backend read and layout worker.
function createTrafficResponse({getArtifacts, getEvents, contentSession, readable, onChange, request, worker, lookup = null}) {
  const views = new Map();
  const options = {pretty: false, wrap: true, hex: false, query: '', current: 0};
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
      if (!response.ok) {response.body?.cancel().catch(() => {}); throw new Error(`the artifact store returned ${response.status}`);}
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
    if (binary || options.hex) {
      value = formatWasmHex(bytes.subarray(0, TRAFFIC_RESPONSE_HEX_BYTES));
      shown = codeView(value, artifact, 'text');
      if (bytes.length > TRAFFIC_RESPONSE_HEX_BYTES) {
        note = `Hex shows the first ${trafficResponseBytes(TRAFFIC_RESPONSE_HEX_BYTES)}.`;
        copyNote = `Copied the hex of the first ${trafficResponseBytes(TRAFFIC_RESPONSE_HEX_BYTES)} of ${trafficResponseBytes(bytes.length)}.`;
      }
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
    nodes.push(shown.code);
    if (layout?.status === 'ready' && layout.map) nodes.push(raw);
    if (!view.complete) {
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

  function render(container, request, tab) {
    const record = request?.responseBody ?? null;
    const {artifact, found} = request ? artifactOf(request, record) : {artifact: null, found: null};
    const refusal = artifact ? null : refusalOf(request) ?? (found?.status === 'refused' ? found.reason || 'unknown reason' : null);
    const view = artifact ? viewOf(artifact) : null;
    const key = JSON.stringify([request?.id, request?.origin, tab, record, request?.responseStarted?.sequenceNumber, artifact?.artifact_id,
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
    const rows = [['Capture', artifact && !record ? 'Retained as a source artifact by this response.' : trafficResponseCapture(request, contentSession()), 'prose'],
      ...trafficResponseRows(record)];
    if (artifact) rows.push(['Artifact', `${artifact.kind} ${artifact.artifact_id} · ${artifact.mime_type}`, 'value']);
    for (const [label, value, kind] of tab === 'preview' ? rows.slice(0, 1) : rows) {
      const row = trafficNode('div', 'traffic-general-row');
      const valueNode = trafficNode('span', 'traffic-general-value', String(value));
      valueNode.dataset.kind = kind;
      row.append(trafficNode('span', '', label), valueNode);
      nodes.push(row);
    }
    const note = contentNote(record, artifact, view ?? {}, refusal, found);
    if (note) nodes.push(trafficNode('p', 'traffic-body-note', note));
    if (view?.status === 'ready') nodes.push(...(tab === 'preview' ? preview(artifact, view, record) : responseBody(container, request, artifact, view)));
    container.replaceChildren(...nodes);
    container.dataset.state = record?.malformed ? 'malformed' : record?.state ?? (artifact ? 'source_artifact' : 'none');
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
