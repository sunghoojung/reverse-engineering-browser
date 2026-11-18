/* Response and Preview tabs (protocol/native-network-v3.md). Content capture
 * sessions retain response bodies; every session retains script and Wasm
 * responses. Captured bytes only ever become text nodes, hex, a JSON tree of
 * text nodes, or a raster image whose signature matches its bytes. HTML is
 * shown as source and never rendered. */
// Recently shown bodies kept for reselection; the newest stays whatever its size.
const TRAFFIC_RESPONSE_CACHE_BYTES = 48 * 1024 * 1024;
const TRAFFIC_RESPONSE_RETRY_MS = 2000;
// Response body records before version 3 kept at most this prefix; current
// capture keeps every body whole.
const TRAFFIC_RESPONSE_CAPTURE_BYTES = 16n * 1024n * 1024n;
// Bytes of a cut, partial or stopped body can end inside a character.
const TRAFFIC_RESPONSE_OPEN_ENDED = new Set(['captured_truncated', 'partial', 'aborted', 'cancelled']);

const TRAFFIC_RESPONSE_CODINGS = Object.freeze({gzip: 'gzip', deflate: 'deflate', br: 'br', zstd: 'zstd',
  dcb: 'dcb (shared dictionary)', dcz: 'dcz (shared dictionary)', compress: 'compress', other: 'unrecognized'});

function trafficResponseBytes(value) {
  const count = BigInt(value);
  return `${count.toLocaleString('en-US')} ${count === 1n ? 'byte' : 'bytes'}`;
}

const TRAFFIC_RESPONSE_STATES = new Set(['captured', 'captured_truncated', 'partial', 'aborted', 'cancelled', 'empty',
  'not_modified', 'redirected', 'not_captured_type', 'not_captured_artifact_unavailable', 'not_captured_transfer_refused',
  'not_captured_session_budget', 'not_captured_disk_reserve']);

// The request index read the whole session, so it decides when the loaded
// records lack the final response or its body record: a live row's
// response_started can leave the retained window while later records stay.
function trafficResponseIndexWins(request) {
  const indexed = request?.responseBodyIndex;
  if (!indexed) return false;
  if (!request.events?.length) return true;
  if (!request.responseStarted) return Boolean(indexed.response_started);
  return !request.responseBody && Boolean(indexed.record_sequence);
}

// An index body answer as the record shape the model decodes. The record's
// content type, codings and other flags are not in the index; its withheld
// flag is.
function trafficIndexRecord(body) {
  if (!body || (!TRAFFIC_RESPONSE_STATES.has(body.case) && body.case !== 'malformed')) return null;
  if (body.case === 'malformed') return {malformed: true};
  const started = body.response_started;
  return {state: body.case, shared: body.shared === true, fromCache: false, serviceWorker: false, stillEncoded: false,
    codingsOmitted: false, completionUnobserved: false, snapshotsWithheld: body.snapshots_withheld === true, contentType: null, codings: [], bodyLength: body.body_length ?? '0',
    capturedLength: body.captured_length ?? '0', partialIndex: body.partial_index ?? 0, sha256: body.sha256 ?? null,
    artifactId: body.artifact_id ?? '0', sequenceNumber: body.record_sequence, parentEventId: started?.sequence_number,
    sessionId: started?.session_id, processId: started?.process_id, monotonicTimeNs: body.record_time_ns, fromIndex: true};
}

// The body record this view describes: the loaded one, or the index's.
function trafficResponseRecord(request) {
  return trafficResponseIndexWins(request) ? trafficIndexRecord(request.responseBodyIndex) : request?.responseBody ?? null;
}

// A snapshot of the same response the receiver still holds when the newest
// record names no bytes (a refusal, or a malformed record).
function trafficResponseEarlier(request) {
  if (!trafficResponseIndexWins(request) && request?.responseBodyEarlier) return request.responseBodyEarlier;
  const earlier = request?.responseBodyIndex?.earlier_snapshot;
  const started = request?.responseBodyIndex?.response_started;
  if (!earlier || !started) return null;
  return {state: 'partial', shared: false, artifactId: earlier.artifact_id, sessionId: started.session_id,
    parentEventId: started.sequence_number, bodyLength: earlier.body_length, capturedLength: earlier.captured_length,
    partialIndex: earlier.partial_index, sha256: earlier.sha256, sequenceNumber: earlier.record_sequence,
    monotonicTimeNs: earlier.record_time_ns, codings: [], fromIndex: true};
}

// Every snapshot to try, newest first: the loaded records carry each one,
// the index names only its newest.
function trafficResponseSnapshots(request) {
  if (!trafficResponseIndexWins(request) && request?.responseBodySnapshots?.length) return request.responseBodySnapshots;
  const earlier = trafficResponseEarlier(request);
  return earlier ? [earlier] : [];
}

// Why a request's response body is or is not retained (protocol/native-network-v3.md
// "Bodies the proxy never sees"). The request index's body_case is the same
// decision, held equal by tools/check-request-index.mjs, and decides when the
// loaded records lack what it read.
function responseBodyCase(request) {
  if (!request) return 'pending';
  if (trafficResponseIndexWins(request)) return request.responseBodyIndex.case;
  // A row with neither records nor an index answer cannot be decided.
  if (request.rank === undefined && !request.responseBody && !request.responseStarted) return 'unknown';
  const record = request.responseBody;
  if (record) return record.malformed ? 'malformed' : record.state;
  if (request.responseStarted) return ['js', 'wasm'].includes(request.type) ? 'source_artifact' : 'no_record';
  if (request.memoryCache) return 'memory_cache';
  if (request.fromServiceWorker && !request.failed && !request.interrupted && request.rank >= 5) return 'service_worker';
  // A failure, an ended observation or an open request after a redirect is
  // that, not a redirect whose body was discarded.
  if (request.failed) return request.errorCode === -3 ? 'cancelled_before_response' : 'failed_before_response';
  if (request.interrupted) return 'interrupted';
  if (request.endLost) return 'end_lost';
  if (!(request.rank >= 5)) return 'pending';
  if (request.redirected) return 'redirected';
  return request.browserObserved ? 'no_response' : 'renderer_answered';
}

// Seconds from the response's start to a record, or null.
function trafficResponseAfter(record, request) {
  const [at, start] = [record?.monotonicTimeNs, request?.responseStarted?.monotonicTimeNs];
  if (typeof at !== 'string' || typeof start !== 'string') return null;
  const elapsed = BigInt(at) - BigInt(start);
  if (elapsed < 0n) return null;
  return elapsed < 1000000000n ? `${elapsed / 1000000n} ms` : `${(Number(elapsed / 1000000n) / 1000).toFixed(1)} s`;
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
    redirected: 'Every response was a redirect, and the request ended without another. Chromium discards redirect bodies.',
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

// A partial record before version 3 whose kept prefix is the whole capture
// limit is sealed: those bytes are final, whether or not more had arrived when
// it was recorded. A version 3 snapshot holds every byte that had arrived. The
// index answer names no version, so it is sealed only with bytes past the limit.
function trafficResponseSealed(record) {
  if (record?.state !== 'partial' || BigInt(record.capturedLength) !== TRAFFIC_RESPONSE_CAPTURE_BYTES) return false;
  return record.version === undefined ? BigInt(record.bodyLength) > TRAFFIC_RESPONSE_CAPTURE_BYTES : record.version < 3;
}

// What the record says happened to the body, or why there is no record.
function trafficResponseCapture(request, contentSession) {
  const record = trafficResponseRecord(request);
  if (record?.malformed) return 'The response body record is malformed and was not interpreted.';
  if (!record) return trafficResponseUnseen(request, contentSession);
  const kept = `${trafficResponseBytes(record.capturedLength)} of ${trafficResponseBytes(record.bodyLength)}`;
  const after = trafficResponseAfter(record, request);
  const sealed = trafficResponseSealed(record);
  return {
    captured: record.shared ? 'Retained in full. Identical bytes were already retained, so this names that artifact.' : 'Retained in full.',
    captured_truncated: `Retained prefix: ${kept}, truncated at 16 MiB, a limit of the browser that recorded this session; current capture keeps every body whole.`,
    partial: `Still arriving: ${trafficResponseBytes(record.bodyLength)} had arrived${after ? ` ${after} after the response started` : ''}, at snapshot ${record.partialIndex}. ${sealed
      ? `The first ${trafficResponseBytes(record.capturedLength)} reached the 16 MiB limit of the browser that recorded this session and are retained as they will stay; later bytes are only counted, and the body may still be arriving.`
      : 'All of them are retained in this snapshot.'} The record of the ended body replaces it.`,
    aborted: record.capturedLength === '0' ? 'Aborted: the network failed before any byte was retained.'
      : `Aborted: the network failed mid-body. The ${trafficResponseBytes(record.capturedLength)} that arrived are retained.`,
    cancelled: record.capturedLength === '0' ? 'Cancelled: the page or browser stopped the request before any byte arrived.'
      : `Cancelled: the page or browser stopped reading. The ${trafficResponseBytes(record.capturedLength)} that arrived are retained.`,
    empty: 'Empty body (0 bytes).',
    not_modified: 'Not modified (304): the server sent no body.',
    redirected: 'Redirect: Chromium discards redirect bodies.',
    not_captured_type: 'Not retained: the browser that recorded this session skipped images, audio, video and fonts that page elements load. Current content sessions keep them.',
    not_captured_artifact_unavailable: 'Not retained: the artifact channel was unavailable.',
    not_captured_transfer_refused: 'Not retained: the bounded in-flight memory or artifact transfer queue refused it.',
    not_captured_session_budget: 'Not retained: it arrived after the response body budget was used, a limit of the browser that recorded this session. Current capture keeps every body whole.',
    not_captured_disk_reserve: 'Not retained: storing it would have left less free disk than the artifact receiver\'s reserve. Free disk space to keep later bodies.'
  }[record.state] ?? 'Unknown capture state.';
}

function trafficResponseRows(record) {
  if (!record || record.malformed) return [];
  // Version 2 bit 7 (protocol/native-network-v3.md "Partial bodies"), which the index carries too.
  const withheld = record.snapshotsWithheld ? [['Snapshots', 'A snapshot the schedule allowed was withheld: this body\'s snapshots had copied four times what it kept plus 64 MiB, or in an older session a snapshot share or budget was used, so the newest snapshot is older than the schedule would make it.', 'prose']] : [];
  // The index answer carries lengths and the digest, not the record's type or codings.
  if (record.fromIndex) {
    return [['Body length', `${trafficResponseBytes(record.bodyLength)} decoded`, 'value'],
      ['SHA-256', record.sha256 ?? 'No retained bytes', record.sha256 ? 'value' : 'prose'],
      ['Record', 'Read from the request index: the loaded records lack it, so its content type and codings are not shown.', 'prose'],
      ...withheld];
  }
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
    ...(notes.length ? [['Delivery', notes.join('; '), 'prose']] : []),
    ...withheld
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

// A model row's body as the index words it, for the reuse's source.
function trafficResponseBodySummary(row) {
  const record = trafficResponseRecord(row);
  return {case: responseBodyCase(row), body_length: record?.bodyLength ?? null, captured_length: record?.capturedLength ?? null,
    partial_index: record?.partialIndex ?? null, record_time_ns: record?.monotonicTimeNs ?? null};
}

// The host a row was requested from: the host-only path, else its host field.
function trafficResponseHost(row) {
  return String(row?.host ?? (row?.hostOnly ? row.path : '') ?? '').replace(/:\d+$/, '').toLowerCase();
}

// The row a memory-cache reuse names as the request whose response Blink
// reused (protocol/native-network-v3.md), from the index or the model's rows.
// A renderer ID names a row only in its own process and session, so the source
// must also have the reuse's host and have started before it.
function trafficMemoryCacheSource(request, rows = []) {
  const id = request?.memoryCacheSource;
  if (!id) return null;
  const indexed = request.memoryCacheSourceRow;
  if (indexed?.id === id) {
    return {id, found: indexed.found === true, reason: indexed.reason ?? null, body: indexed.response_body ?? null,
      path: indexed.path ?? null, mimeType: indexed.mime_type ?? null,
      stand: indexed.found ? trafficResponseStand(id, indexed.type, indexed.response_body) : null};
  }
  const row = rows.find(candidate => candidate.id === id);
  if (!row) return {id, found: null, reason: null, body: null, path: null, stand: null};
  const host = trafficResponseHost(request), sourceHost = trafficResponseHost(row);
  const reason = host && sourceHost && host !== sourceHost && !(host.length === 120 && sourceHost.startsWith(host)) ? 'host_differs'
    : typeof row.firstTimestamp === 'bigint' && typeof request.firstTimestamp === 'bigint' && row.firstTimestamp > request.firstTimestamp
      ? 'started_after' : null;
  if (reason) return {id, found: false, reason, body: null, path: row.path, stand: null};
  return {id, found: true, reason: null, body: trafficResponseBodySummary(row), path: row.path, mimeType: row.mimeType ?? null,
    stand: {id, type: row.type, responseStarted: row.responseStarted, responseBody: trafficResponseRecord(row)}};
}

// What was retained of a reuse's source: complete, cut at the limit, a
// snapshot, stopped, or not at all.
function trafficSourceState(source, reuse) {
  const body = source?.body;
  if (!body) return null;
  const bytes = value => value === null || value === undefined ? 'an unknown number of bytes' : trafficResponseBytes(value);
  let when = '';
  if (typeof body.record_time_ns === 'string' && typeof reuse?.firstTimestamp === 'bigint') {
    const gap = BigInt(body.record_time_ns) - reuse.firstTimestamp;
    const magnitude = gap < 0n ? -gap : gap;
    const amount = magnitude < 1000000000n ? `${magnitude / 1000000n} ms` : `${(Number(magnitude / 1000000n) / 1000).toFixed(1)} s`;
    when = `, recorded ${amount} ${gap < 0n ? 'before' : 'after'} this reuse`;
  }
  return {
    captured: `Complete: ${bytes(body.body_length)}.`,
    captured_truncated: `Truncated: the first ${bytes(body.captured_length)} of ${bytes(body.body_length)} are retained.`,
    partial: `Partial: snapshot ${body.partial_index ?? '?'} holds ${bytes(body.captured_length)} of the ${bytes(body.body_length)} that had arrived${when}. Blink reused the whole resource.`,
    aborted: `Aborted mid-body: ${bytes(body.captured_length)} of ${bytes(body.body_length)} are retained.`,
    cancelled: `Cancelled mid-body: ${bytes(body.captured_length)} of ${bytes(body.body_length)} are retained.`,
    source_artifact: 'Retained as a script or Wasm source artifact.'
  }[body.case] ?? `Not retained: ${trafficResponseCaseMeaning(body.case)}.`;
}

// A row's host, path and query, when it has a path to match: a metadata
// session records the host alone.
function trafficResponseUrl(row) {
  if (!row?.host || row.target === undefined || row.target === null) return null;
  return `${row.host}${row.target}`;
}

// Requests the service worker made for this request's URL while it was open:
// the bytes it answered with may be theirs, which the records do not prove.
function trafficServiceWorkerFetches(request, rows) {
  if (!request || responseBodyCase(request) !== 'service_worker') return [];
  const wanted = trafficResponseUrl(request);
  if (!wanted) return [];
  return rows.filter(row => row.id !== request.id && row.initiator === 'worker' && trafficResponseUrl(row) === wanted &&
    row.firstTimestamp >= request.firstTimestamp && row.firstTimestamp <= request.lastTimestamp);
}

// One line for each body case, as the session summary words it.
function trafficResponseCaseMeaning(kind) {
  return {
    captured: 'retained in full', captured_truncated: 'retained up to the 16 MiB limit of the browser that recorded it',
    partial: 'still arriving; its newest snapshot is retained', aborted: 'the network failed mid-body; what arrived is retained',
    cancelled: 'stopped mid-body; what arrived is retained', empty: 'an empty body', not_modified: 'HTTP 304, no body',
    redirected: 'redirected, then ended with no other response', not_captured_type: 'media or a font the recording browser skipped',
    not_captured_artifact_unavailable: 'the artifact channel was unavailable', not_captured_transfer_refused: 'refused by the bounded transfer',
    not_captured_session_budget: 'past the recording browser\'s response body budget',
    not_captured_disk_reserve: 'refused to keep the disk reserve free', malformed: 'a malformed record',
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
  const options = {pretty: false, wrap: true, hex: false, hexKey: null, hexOffset: 0};
  // Find stays apart from the view options: typing updates the shown body's
  // marks and count in place instead of drawing the body again. One count
  // runs at a time, over the whole document shown (source_syntax.js).
  const find = {query: '', rank: 0, entry: null, shown: null, reveal: false};
  const previews = new Map();
  let previewArea = null;
  let generation = 0;
  const layouts = createCodeLayouts({request, layouts: worker, onChange: () => {generation += 1; onChange();}});

  // A body is read whole in one request, with its progress and Cancel and no
  // deadline. A retried failure stays shown until the new read settles.
  function start(artifact, key, previous = null) {
    const entry = {status: 'loading', artifact, received: 0, total: artifact.byte_size, verifying: false, controller: new AbortController(), previous};
    views.set(key, entry);
    void load(entry, key);
    return entry;
  }

  async function load(entry, key) {
    const {artifact, controller} = entry;
    let painted = 0;
    const repaint = () => {if (views.get(key) === entry) onChange();};
    let view;
    try {
      const {bytes, verified} = await trafficReadArtifact(artifact, {signal: controller.signal,
        onBytes: received => {
          entry.received = received;
          if (Date.now() - painted < 100) return;
          painted = Date.now();
          repaint();
        },
        onVerify: () => {entry.verifying = true; repaint();}});
      view = {status: 'ready', artifact, bytes, verified, total: bytes.length};
    } catch (error) {
      view = controller.signal.aborted ? {status: 'cancelled', artifact}
        : {status: 'error', artifact, error: String(error?.message ?? error).replace(/\.$/, ''), retryable: error?.integrity !== true, failedAt: Date.now()};
    }
    // A cancelled or evicted read has been replaced already.
    if (views.get(key) !== entry) return;
    views.delete(key);
    views.set(key, view);
    evict(key);
    onChange();
  }

  function cancel(key) {
    const entry = views.get(key);
    if (entry?.status !== 'loading') return;
    entry.controller.abort();
    views.set(key, {status: 'cancelled', artifact: entry.artifact});
    onChange();
  }

  function readAgain(key) {
    const entry = views.get(key);
    if (entry?.status !== 'cancelled') return;
    start(entry.artifact, key);
    onChange();
  }

  // Bytes and parsed previews share one budget. A preview goes with its view,
  // and its source length stands in for an object graph that is larger still.
  // The newest view stays whatever its size.
  function evict(keep) {
    const cost = (item, key) => (item.bytes?.length ?? 0) + (previews.get(key)?.sourceBytes ?? 0);
    let retained = [...views.entries()].reduce((sum, [key, item]) => sum + cost(item, key), 0);
    for (const [oldest, item] of views) {
      if (views.size <= 8 && retained <= TRAFFIC_RESPONSE_CACHE_BYTES) break;
      if (oldest === keep) continue;
      retained -= cost(item, oldest);
      item.controller?.abort();
      views.delete(oldest);
      previews.delete(oldest);
    }
  }

  function viewOf(artifact) {
    if (!readable()) return {status: 'unavailable'};
    const key = `${artifact.session_id}:${artifact.artifact_id}:${artifact.sha256}`;
    const current = views.get(key);
    if (current?.retryable && Date.now() - current.failedAt >= TRAFFIC_RESPONSE_RETRY_MS) {
      start(artifact, key, current);
      return {...current, key};
    }
    if (current) return {...(current.status === 'loading' && current.previous ? current.previous : current), key};
    return {...start(artifact, key), key};
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
    if (view.status === 'loading') return trafficReadProgress(view);
    if (view.status === 'cancelled') return 'Reading the retained body was cancelled.';
    if (view.status === 'error') return `The retained body could not be read: ${view.error}.${view.retryable ? ' It is read again on the next refresh.' : ''}`;
    return view.verified ? null : 'The retained digest could not be rechecked in this view.';
  }

  function codeView(text, artifact, language, {rows = codeViewRows(text), layout = null, status = null, marks = new Map()} = {}) {
    const syntax = language === 'text' ? {kind: 'plain', mime_type: 'text/plain'}
      : {kind: artifact.kind === 'wasm' ? 'wasm' : 'response_body', mime_type: artifact.mime_type, url: artifact.url};
    return createCodeView({text, rows, syntax, label: 'Response body', className: 'traffic-response-code', rowClass: 'traffic-response-line',
      wrap: options.wrap, marks, current: -1, layout: layout?.map ? layout : null, onRaw: status && (raw => {status.textContent = codeViewRawText(raw);})});
  }

  // The count over the shown document: a new query or document stops the
  // previous one. Its marks and count repaint about every 200 ms while it runs.
  function findIn(key, document) {
    if (!find.query) {
      cancelSourceFind(find.entry?.search);
      find.entry = null;
      return null;
    }
    if (find.entry?.key === key && find.entry.query === find.query) return find.entry.search;
    cancelSourceFind(find.entry?.search);
    const entry = find.entry = {key, query: find.query, painted: 0};
    entry.search = startSourceFind(document(), find.query, {onProgress: search => {
      if (find.entry !== entry) return;
      if (search.status === 'running' && Date.now() - entry.painted < 200) return;
      entry.painted = Date.now();
      showFind();
    }});
    return entry.search;
  }

  // Count, marks and current match of the shown body. `reveal` moves to the
  // current match, now or once the count reaches one; a match in another hex
  // window opens that window.
  function showFind(reveal = false) {
    const shown = find.shown;
    if (!shown || shown.count.isConnected === false) return;
    if (reveal) find.reveal = true;
    const search = shown.search();
    const running = search?.status === 'running';
    const progress = running ? ` · finding ${Math.floor(100 * search.scanned / search.document.chunks)}%` : '';
    let current = -1, row = null;
    if (!search?.total) {
      find.rank = 0;
      shown.count.textContent = !find.query ? '' : search.error || (running ? `No matches yet${progress}` : 'No matches');
      if (!running) find.reveal = false;
    } else {
      find.rank = running ? Math.min(find.rank, search.total - 1) : find.rank % search.total;
      const match = sourceFindMatch(search, find.rank);
      shown.count.textContent = `${(find.rank + 1).toLocaleString('en-US')} of ${search.total.toLocaleString('en-US')}${running ? '+' : ''}${progress}`;
      const window = shown.hex ? shown.hex.windowOf(match.offset) : null;
      if (window !== null && window !== shown.hex.start) {
        if (find.reveal) {
          options.hexOffset = window;
          shown.container.dataset.renderKey = '';
          onChange();
          return;
        }
      } else {
        current = match.offset;
        row = codeViewRowAt(shown.rows, match.offset - shown.base);
      }
    }
    const marked = {search, current, scanned: search?.scanned ?? 0};
    if (marked.search !== shown.marked.search || marked.current !== shown.marked.current || marked.scanned !== shown.marked.scanned) {
      shown.marked = marked;
      shown.view.mark(shown.marks, current, row === null ? [] : [row]);
    }
    if (find.reveal && row !== null) {
      find.reveal = false;
      shown.view.reveal(row);
      shown.view.box.querySelector('.code-view-mark.is-current')?.scrollIntoView?.({block: 'center'});
    }
  }

  // Until the count is done, Next stops at the last match counted.
  function stepFind(direction) {
    const search = find.entry?.search;
    if (!search?.total) return;
    const moved = find.rank + direction;
    find.rank = search.status === 'running' ? Math.max(0, Math.min(search.total - 1, moved)) : (moved + search.total) % search.total;
    showFind(true);
  }

  // Preview shares the Payload tree, so its reach and keys are the same.
  function jsonPreview(key, value, sourceBytes) {
    let shown = previews.get(key);
    if (!shown) {
      shown = {model: {json: {value}, keys: new WeakMap()}, expanded: new Set(['$']), selected: null, find: trafficPayloadNoFind(), sourceBytes};
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

  function toolbar(container, binary, prettyable, text, copyNote) {
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
    const input = document.createElement('input');
    input.type = 'search';
    input.className = 'traffic-response-find';
    input.placeholder = 'Find';
    input.value = find.query;
    input.dataset.control = 'find';
    input.setAttribute('aria-label', 'Find in response body');
    bar.append(input);
    const count = trafficNode('span', 'traffic-response-count');
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
    input.addEventListener('input', () => {
      find.query = input.value;
      find.rank = 0;
      showFind(true);
    });
    input.addEventListener('keydown', event => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      stepFind(event.shiftKey ? -1 : 1);
    });
    return {bar, count};
  }

  function responseBody(container, request, artifact, view) {
    const nodes = [];
    const bytes = view.bytes;
    const decoded = trafficResponseText(bytes, TRAFFIC_RESPONSE_OPEN_ENDED.has(request?.responseBody?.state));
    const text = decoded?.text ?? null;
    const binary = text === null;
    const source = {kind: 'response_body', mime_type: artifact.mime_type, url: artifact.url};
    const language = binary ? 'bytes' : sourceSyntaxLanguage(source);
    const prettyable = !binary && sourcePrettySupported(source);
    let value = text;
    let note = null;
    let copyNote = 'Copied.';
    let layout = null;
    let hex = null;
    let document;
    const raw = trafficNode('p', 'traffic-body-note code-view-raw');
    raw.setAttribute('role', 'status');
    if (binary || options.hex) {
      // One window at a time, paged to the end of the body; Find counts every row.
      if (options.hexKey !== view.key) {
        options.hexKey = view.key;
        options.hexOffset = 0;
      }
      hex = codeViewHexWindow(bytes, options.hexOffset);
      value = hex.text;
      document = () => sourceFindHexDocument(bytes);
      if (hex.total > CODE_VIEW_HEX_BYTES) {
        const range = `bytes ${hex.start.toLocaleString('en-US')} to ${(hex.end - 1).toLocaleString('en-US')} of ${trafficResponseBytes(hex.total)}`;
        note = `Hex shows ${range}.`;
        copyNote = `Copied the hex of ${range}.`;
      }
    } else {
      if (options.pretty && prettyable) {
        layout = layouts.layout(artifact, text, source, null);
        note = codeLayoutNote(layout);
        if (layout.status === 'ready') value = layout.text;
      }
      const searched = value;
      document = () => sourceFindTextDocument(searched);
    }
    const rows = codeViewRows(value);
    const shown = find.shown = {container, rows, hex, base: hex?.base ?? 0, marked: {search: null, current: -1, scanned: 0},
      key: JSON.stringify([view.key, hex ? 'hex' : layout?.status === 'ready' ? `pretty:${layout.engine}` : 'text'])};
    shown.search = () => findIn(shown.key, document);
    shown.marks = (first, last) => codeViewFindMarks(shown.marked.search, rows, first, last, shown.base);
    shown.view = codeView(value, artifact, hex ? 'text' : language, {rows, marks: shown.marks,
      layout: layout?.status === 'ready' ? layout : null, status: hex ? null : raw});
    const tools = toolbar(container, binary, prettyable, value, copyNote);
    shown.count = tools.count;
    nodes.push(tools.bar);
    if (decoded?.lossy && !options.hex) nodes.push(trafficNode('p', 'traffic-body-note', 'Not valid UTF-8; shown with replacement characters. Hex shows the exact bytes.'));
    if (note) nodes.push(trafficNode('p', 'traffic-body-note', note));
    if (hex && hex.total > CODE_VIEW_HEX_BYTES) nodes.push(trafficHexPager(hex, start => {options.hexOffset = start; onChange();}));
    nodes.push(shown.view.box);
    if (layout?.status === 'ready' && layout.map) nodes.push(raw);
    return nodes;
  }

  function preview(artifact, view, record) {
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
      return [...lossyNote, trafficNode('p', 'traffic-body-note', 'Markup is shown as source and never rendered.'), codeView(text, artifact, 'markup').box];
    }
    const pre = trafficNode('pre', 'traffic-body-text', text);
    pre.tabIndex = 0;
    return [...lossyNote, pre];
  }

  // The rows a related lookup found for a service-worker answer, read once per request.
  const relatedAnswers = new Map();
  // `searched` says what was looked through: the loaded rows only, or the
  // index's rows of the request's time range, which `capped` says were cut.
  function fetchesOf(target) {
    if (!trafficResponseUrl(target)) return {status: 'no_path', rows: [], searched: 'none', capped: false};
    const local = trafficServiceWorkerFetches(target, getRequests() ?? []);
    if (!related) return {status: 'ready', rows: local, searched: 'loaded', capped: false};
    let entry = relatedAnswers.get(target.id);
    if (!entry) {
      entry = {status: 'loading', rows: [], capped: false};
      relatedAnswers.set(target.id, entry);
      while (relatedAnswers.size > 16) relatedAnswers.delete(relatedAnswers.keys().next().value);
      Promise.resolve().then(() => related(target)).then(answer => {
        entry.status = answer?.status ?? 'ready';
        entry.rows = Array.isArray(answer?.rows) ? answer.rows : [];
        entry.capped = answer?.capped === true;
      }, () => {entry.status = 'unavailable';}).finally(onChange);
    }
    const rows = [...local, ...trafficServiceWorkerFetches(target, entry.rows).filter(row => !local.some(item => item.id === row.id))];
    return {status: entry.status, rows, searched: entry.status === 'ready' ? 'index' : 'loaded', capped: entry.capped};
  }

  // What the worker-fetch search found, and what it could not look at.
  function fetchesNote(fetches) {
    if (fetches.status === 'no_path') {
      return 'This row has no path to match (a metadata-only session records the host alone), so requests the service worker made cannot be matched to it.';
    }
    if (fetches.status === 'loading') return 'Looking for requests the service worker made for this URL…';
    if (fetches.rows.length) {
      return `The service worker requested this URL while this request was open (${fetches.rows.length === 1 ? 'one request' : `${fetches.rows.length} requests`}). The records do not say whether it answered with those bytes.`;
    }
    const scope = fetches.searched === 'index'
      ? `the request index's rows of this request's time range${fetches.capped ? ', cut at its first 500 rows, so later ones were not searched' : ''}`
      : fetches.status === 'unavailable' ? 'the loaded rows only: the request index could not be read' : 'the loaded rows only';
    return `No request the service worker made for this URL started while this request was open, among ${scope}. A worker that fetched before this request opened, fetched another URL, read Cache Storage or built the response leaves no match here.`;
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
      return {
        host_differs: `Blink names request ${source.id} of this renderer, but that row was requested from another host, so it is not this resource's load: the renderer's process ID may have been reused within the session.`,
        started_after: `Blink names request ${source.id} of this renderer, but that row started after this reuse, so it is not this resource's load: the renderer's process ID may have been reused within the session.`
      }[source.reason] ?? `Blink names request ${source.id} of this renderer as the one that loaded it, which this session did not record: it loaded before the session started, or its records are not indexed.`;
    }
    const kind = source.body?.case;
    if (source.stand?.responseBody || kind === 'source_artifact') {
      return kind === 'captured'
        ? 'Blink names the request of this renderer that loaded the resource. That request\'s retained body is shown here, complete.'
        : 'Blink names the request of this renderer that loaded the resource. What was retained of that request\'s body is shown here; its state is below.';
    }
    return `Blink names the request of this renderer that loaded the resource. Its body was not retained: ${trafficResponseCaseMeaning(kind)}.`;
  }

  function render(container, request, tab) {
    const record = request ? trafficResponseRecord(request) : null;
    const kind = responseBodyCase(request);
    const source = kind === 'memory_cache' && request ? trafficMemoryCacheSource(request, getRequests() ?? []) : null;
    const fetches = kind === 'service_worker' && request ? fetchesOf(request) : null;
    // A reuse shows the bytes of the request it names; nothing else stands in for a body.
    const indexed = trafficResponseIndexWins(request) ? trafficResponseStand(request.id, request.type, request.responseBodyIndex) : null;
    // A newest record without bytes does not hide a snapshot the receiver
    // holds: snapshots are tried newest first until one is not refused.
    const snapshotOf = item => ({...request, responseStarted: request.responseStarted ?? indexed?.responseStarted, responseBody: item});
    const tried = [];
    for (const item of !source && record && (record.malformed || record.artifactId === '0') ? trafficResponseSnapshots(request) : []) {
      const from = snapshotOf(item);
      const lookedUp = artifactOf(from, item);
      const refused = lookedUp.artifact ? null : refusalOf(from) ?? (lookedUp.found?.status === 'refused' ? lookedUp.found.reason || 'unknown reason' : null);
      tried.push({item, refused});
      if (!refused) break;
    }
    const chosen = tried.find(entry => !entry.refused) ?? tried[0] ?? null;
    const earlier = chosen?.item ?? null;
    const shownFrom = source?.stand ?? (earlier ? snapshotOf(earlier)
      : indexed ? {...request, responseStarted: indexed.responseStarted, responseBody: record} : request);
    const shownRecord = source?.stand ? source.stand.responseBody : earlier ?? record;
    const {artifact, found} = request ? artifactOf(shownFrom, shownRecord) : {artifact: null, found: null};
    const refusal = artifact ? null : refusalOf(shownFrom) ?? (found?.status === 'refused' ? found.reason || 'unknown reason' : null);
    const view = artifact ? viewOf(artifact) : null;
    const key = JSON.stringify([request?.id, request?.origin, tab, record, kind, request?.responseStarted?.sequenceNumber, artifact?.artifact_id,
      tried.map(entry => [entry.item.artifactId, entry.refused]), source && [source.id, source.found, source.reason, source.body, source.mimeType],
      fetches && [fetches.status, fetches.capped, fetches.searched, fetches.rows.map(row => [row.id, row.responseBodyIndex?.case])],
      refusal, found?.status, view && [view.status, view.received, view.verifying, view.error], options, generation]);
    if (container.dataset.renderKey === key) return;
    container.dataset.renderKey = key;
    // The same body keeps its place across wrap, pretty print or a refresh.
    const scrollKey = JSON.stringify([request?.id, request?.origin, tab, artifact?.artifact_id]);
    const shownCode = container.dataset.scrollKey === scrollKey ? container.querySelector('.traffic-response-code') : null;
    const scroll = shownCode ? {top: shownCode.scrollTop, left: shownCode.scrollLeft} : null;
    container.dataset.scrollKey = scrollKey;
    previewArea?.dispose();
    previewArea = null;
    find.shown?.view.dispose();
    find.shown = null;
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
    if (earlier) {
      const after = trafficResponseAfter(earlier, request);
      // Refused snapshots other than the one shown: later ones when it was
      // kept, earlier ones when every snapshot was refused.
      const others = tried.filter(entry => entry.refused && entry !== chosen).map(entry => entry.item.partialIndex);
      // Said from the artifact lookup, never assumed.
      const kept = artifact ? 'The receiver retains it, and it is shown below.'
        : refusal ? (others.length ? 'The receiver did not retain it or any earlier snapshot of this response.' : 'The receiver did not retain it.')
        : found?.status === 'loading' ? 'Looking up whether the receiver retains it.' : 'Whether the receiver retains it is not known yet.';
      const skipped = !refusal && others.length
        ? ` The receiver did not retain the later snapshot${others.length > 1 ? 's' : ''} ${others.join(', ')}.` : '';
      rows.push(['Earlier snapshot', `Snapshot ${earlier.partialIndex}: ${trafficResponseBytes(earlier.capturedLength)} of the ${trafficResponseBytes(earlier.bodyLength)} that had arrived${after ? ` ${after} after the response started` : ''}. ${kept}${skipped}`, 'prose']);
    }
    const reused = kind === 'memory_cache' ? sourceNote(request, source) : null;
    if (reused) rows.push(['Reused from', reused, 'prose']);
    const sourceState = source?.found ? trafficSourceState(source, request) : null;
    if (sourceState) rows.push(['Source body', sourceState, 'prose']);
    if (source?.found && /^multipart\/x-mixed-replace\b/i.test(source.mimeType ?? '')) {
      rows.push(['Limit', 'A multipart/x-mixed-replace response: Blink holds its last part, while the retained body has every part.', 'prose']);
    }
    if (fetches) rows.push(['Worker fetches', fetchesNote(fetches), 'prose']);
    if (artifact) rows.push([source?.stand ? 'Artifact (reused request)' : earlier ? 'Artifact (earlier snapshot)' : 'Artifact', `${artifact.kind} ${artifact.artifact_id} · ${artifact.mime_type}`, 'value']);
    // Preview names why, and leaves the record's fields to Response.
    const why = ['Capture', 'Earlier snapshot', 'Reused from', 'Source body', 'Limit', 'Worker fetches'];
    for (const [label, value, valueKind] of tab === 'preview' ? rows.filter(([name]) => why.includes(name)) : rows) {
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
    const control = (name, label, act) => {
      const button = trafficNode('button', 'secondary-button traffic-body-read', label);
      button.type = 'button';
      button.dataset.control = name;
      button.addEventListener('click', act);
      nodes.push(button);
    };
    if (view?.status === 'loading' && view.controller) control('cancel', 'Cancel', () => cancel(view.key));
    if (view?.status === 'cancelled') control('read', 'Read the body', () => readAgain(view.key));
    if (view?.status === 'ready') {
      nodes.push(...(tab === 'preview' ? preview(artifact, view, shownRecord) : responseBody(container, shownFrom, artifact, view)));
    }
    container.replaceChildren(...nodes);
    container.dataset.state = record?.malformed ? 'malformed' : record?.state ?? (own ? 'source_artifact' : kind);
    const code = scroll && container.querySelector('.traffic-response-code');
    if (code) {
      code.scrollTop = scroll.top;
      code.scrollLeft = scroll.left;
    }
    if (active) {
      // Cancel and Read the body replace each other, then give way to the body.
      const control = container.querySelector(`[data-control="${active}"]`) ??
        (['cancel', 'read'].includes(active) ? container.querySelector('[data-control="cancel"], [data-control="read"], .traffic-response-code') : null);
      control?.focus?.();
      if (caret !== null && control?.setSelectionRange) control.setSelectionRange(caret, caret);
    }
    showFind();
  }

  return {render};
}
