// Presentation and request lifecycle only. The existing Rust/Oxc worker owns
// inert analysis and the HTTP adapter owns its full, closed semantic contract.
const sourceFactsFields = ['protocol_version', 'artifact_id', 'session_id', 'navigation_id',
  'frame_id', 'parent_artifact_id', 'creator_event_id', 'execution_context_id',
  'capture_origin', 'kind', 'url', 'mime_type', 'byte_size', 'sha256', 'sensitive'];
const sourceFactsTables = ['operations', 'bindings', 'callables', 'scopes', 'regions'];
const sourceFactsMaximum = 4 * 1024 * 1024;

function sourceFactsIdentity(source) {
  return source?.source_type === 'artifact'
    ? JSON.stringify(sourceFactsFields.map(field => source[field] ?? null)) : null;
}

function sourceFactsUnavailable(source, protocol) {
  if (!['http:', 'https:'].includes(protocol)) {
    return protocol === 'reb:'
      ? 'Unavailable in stored-evidence native mode. Open a live workspace or the browser development UI to inspect JavaScript facts.'
      : 'Open the local browser development UI to inspect JavaScript facts.';
  }
  if (source?.source_type !== 'artifact' || source.kind !== 'javascript') {
    return 'Select one captured JavaScript artifact. Live scripts and derived text cannot be analyzed here.';
  }
  const canonical = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;
  if (!canonical(source.session_id) || !canonical(source.artifact_id) ||
      !/^[0-9a-f]{64}$/.test(source.sha256) || !Number.isSafeInteger(source.byte_size) || source.byte_size < 0) {
    return 'The selected source has no exact retained session, artifact, hash and byte-size identity.';
  }
  return source.byte_size > sourceFactsMaximum ? 'JavaScript facts are limited to complete artifacts of at most 4 MiB.' : '';
}

function sourceFactsRange(range, size) {
  return range && Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end) &&
    range.start >= 0 && range.end >= range.start && range.end <= size;
}

function isSourceFactsReport(value, source) {
  if (!value || value.schema !== 'reb-javascript-source-facts-v1' || value.profile !== 'lexical-effects-v1' ||
      value.offset_unit !== 'utf-8-byte' || value.source_bytes !== source.byte_size ||
      sourceFactsIdentity({...value.source, source_type: 'artifact'}) !== sourceFactsIdentity(source)) return false;
  const coverage = value.coverage;
  if (!coverage || !['complete', 'partial', 'unavailable'].includes(coverage.status) ||
      value.ok !== (coverage.status !== 'unavailable') || typeof coverage.truncated !== 'boolean' ||
      !Array.isArray(coverage.diagnostics) || coverage.diagnostics.length > 64 ||
      !coverage.diagnostics.every(text => typeof text === 'string' && text.length <= 1024) ||
      !Array.isArray(coverage.frontiers) || coverage.frontiers.length > 256 ||
      !coverage.frontiers.every(row => sourceFactsRange(row?.range, value.source_bytes) && typeof row.reason === 'string' && row.reason.length <= 128) ||
      (coverage.status === 'complete' && (coverage.truncated || coverage.frontiers.length || coverage.diagnostics.length))) return false;
  const kinds = {
    operations: ['reference', 'read', 'write', 'call', 'construct', 'literal', 'operator', 'return', 'throw', 'control', 'function-value', 'template', 'array', 'object'],
    bindings: ['var', 'let', 'const', 'using', 'await using', 'function', 'function-name', 'parameter', 'import', 'class', 'class-name', 'catch', 'lexical'],
    callables: ['function', 'arrow'], scopes: ['program', 'function', 'catch', 'with', 'block'],
    regions: ['program', 'callable-body', 'eager-argument', 'conditional-then', 'conditional-else', 'short-circuit-right', 'repeated-test', 'repeated-body', 'repeated-update']
  };
  let count = 0;
  for (const table of sourceFactsTables) {
    const rows = value[table];
    if (!Array.isArray(rows) || (count += rows.length) > 16384) return false;
    const ids = new Set();
    for (const row of rows) {
      if (!row || !Number.isSafeInteger(row.id) || row.id < 0 || row.id > 4294967295 || ids.has(row.id) ||
          !sourceFactsRange(row.range, value.source_bytes) || !kinds[table].includes(row.kind)) return false;
      ids.add(row.id);
      if (table === 'bindings' && (typeof row.name !== 'string' || row.name.length > sourceFactsMaximum)) return false;
      if (table === 'callables' && !sourceFactsRange(row.body_range, value.source_bytes)) return false;
      if (table === 'operations' && (!row.detail || typeof row.detail !== 'object' || Array.isArray(row.detail))) return false;
    }
  }
  return !(coverage.status === 'unavailable' && count);
}

async function sourceFactsReadBytes(response, maximum, signal) {
  // Own bytes immediately: retaining chunk views permits unbounded metadata and
  // large backing stores even below the byte cap. Content-Length is not trusted.
  if (!response.body?.getReader) throw new Error('Bounded response streaming is unavailable.');
  const reader = response.body.getReader();
  let cancelled = false;
  const cancel = () => {
    if (cancelled) return;
    cancelled = true;
    // A producer's cancel hook may never settle. Retire the reader without
    // making request completion or its deadline wait for that hook.
    void reader.cancel().catch(() => {});
  };
  const checkAbort = () => { if (signal?.aborted) throw new Error('Source-facts response was cancelled.'); };
  signal?.addEventListener('abort', cancel, {once: true});
  try {
    checkAbort();
    const bytes = new Uint8Array(maximum);
    let size = 0, chunks = 0;
    while (true) {
      const {done, value} = await reader.read();
      checkAbort();
      if (done) return bytes.subarray(0, size);
      if (++chunks > 65536) throw new Error('The source-facts response exceeded its stream chunk limit.');
      if (!(value instanceof Uint8Array)) throw new Error('The source-facts response contained a non-byte chunk.');
      if (value.byteLength > maximum - size) throw new Error('The source-facts response exceeded its byte limit.');
      bytes.set(value, size);
      size += value.byteLength;
      // Count empty chunks too, and let timer/cancellation tasks run even when
      // a fragmented producer keeps read() promises immediately fulfilled.
      if (chunks % 256 === 0) {
        await new Promise(resolve => setTimeout(resolve, 0));
        checkAbort();
      }
    }
  } catch (error) { cancel(); throw error; }
  finally { signal?.removeEventListener('abort', cancel); reader.releaseLock(); }
}

function sourceFactsPosition(bytes, range) {
  if (!sourceFactsRange(range, bytes.length)) throw new Error('Invalid original source range.');
  // Fatal decoding rejects a range inside a multibyte scalar. Preserve a UTF-8
  // BOM, whose three bytes are part of the original worker coordinate system.
  const decode = value => new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(value);
  const prefix = decode(bytes.subarray(0, range.start));
  const text = decode(bytes.subarray(range.start, range.end));
  return {line: prefix.split('\n').length - 1, column: prefix.length - prefix.lastIndexOf('\n') - 1,
    length: text.split('\n')[0].length, multiline: text.includes('\n')};
}

function createSourceFactsController({getSource, onChange, onNavigate, protocol,
  fetcher = fetch, cryptoApi = globalThis.crypto, deadline = 10000}) {
  const model = {key: null, source: null, status: 'idle', report: null, original: null, error: '', notice: '', revision: 0};
  let generation = 0;
  let active = null;
  let activeOwner = null;
  const change = () => { model.revision += 1; onChange(model); };
  const cancel = (message = 'Request cancelled. Any bounded worker already started may finish; its result will not be applied.') => {
    if (!active) return;
    generation += 1; active.abort(); active = null; activeOwner = null;
    model.status = model.report ? 'ready' : 'idle'; model.notice = message; change();
  };
  const sync = source => {
    const key = sourceFactsIdentity(source);
    if (key === model.key && source?.source_type === model.source?.source_type && source?.kind === model.source?.kind) return;
    generation += 1; active?.abort(); active = null; activeOwner = null;
    Object.assign(model, {key, source, status: 'idle', report: null, original: null, error: '', notice: ''}); change();
  };
  const run = async (mode, range, {owner = null, isCurrent = () => true} = {}) => {
    sync(getSource());
    const source = model.source;
    const unavailable = sourceFactsUnavailable(source, protocol);
    if (unavailable) { model.error = unavailable; change(); return; }
    if (active) return;
    const key = model.key;
    const token = ++generation;
    const controller = new AbortController(); active = controller; activeOwner = owner;
    const current = () => token === generation && sourceFactsIdentity(getSource()) === key && !controller.signal.aborted && isCurrent();
    const timer = setTimeout(() => {
      if (token !== generation) return;
      if (sourceFactsIdentity(getSource()) !== key) { sync(getSource()); return; }
      // WebCrypto cannot be aborted. Retire ownership immediately so a digest
      // that finishes after the deadline cannot leave the view busy or navigate.
      generation += 1; active = null; activeOwner = null; controller.abort();
      model.status = 'error'; model.error = 'Source facts timed out. Retry explicitly; original evidence is unchanged.'; change();
    }, deadline);
    model.status = mode === 'facts' ? 'loading' : 'loading-source'; model.error = ''; model.notice = ''; change();
    try {
      if (mode === 'facts') {
        const response = await fetcher(`/api/source-facts?session_id=${encodeURIComponent(source.session_id)}&artifact_id=${encodeURIComponent(source.artifact_id)}`, {cache: 'no-store', signal: controller.signal});
        const bytes = await sourceFactsReadBytes(response, 33 * 1024 * 1024, controller.signal);
        const report = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
        if (!response.ok) throw new Error(typeof report.error === 'string' ? report.error.slice(0, 1024) : `Source facts returned HTTP ${response.status}.`);
        if (!isSourceFactsReport(report, source)) throw new Error('Source facts did not match the selected immutable artifact or bounded contract.');
        if (!current()) return;
        model.report = report;
      } else {
        if (!model.original) {
          // Reuse the existing verified 2 MiB chunk route; do not enlarge its
          // contract or navigate against the editor's possibly lossy preview.
          const bytes = new Uint8Array(source.byte_size);
          const chunkLimit = 2 * 1024 * 1024;
          for (let offset = 0; offset < Math.max(1, source.byte_size); offset += chunkLimit) {
            const response = await fetcher(`/api/artifacts/${encodeURIComponent(source.artifact_id)}/content?offset=${offset}&limit=${chunkLimit}`, {cache: 'no-store', signal: controller.signal});
            if (!response.ok) throw new Error(`Original source returned HTTP ${response.status}.`);
            const length = Math.min(chunkLimit, source.byte_size - offset);
            if (response.headers.get('X-Artifact-Total-Bytes') !== String(source.byte_size) ||
                response.headers.get('X-Artifact-Offset') !== String(offset) ||
                response.headers.get('X-Artifact-Truncated') !== String(offset + length < source.byte_size)) {
              throw new Error('Original source chunk identity is inconsistent; byte navigation is unavailable.');
            }
            const chunk = await sourceFactsReadBytes(response, chunkLimit, controller.signal);
            if (chunk.length !== length) throw new Error('Original source is incomplete; byte navigation is unavailable.');
            if (!current()) return;
            bytes.set(chunk, offset);
          }
          if (!cryptoApi?.subtle) throw new Error('SHA-256 verification is unavailable; original byte navigation is disabled.');
          const digest = await cryptoApi.subtle.digest('SHA-256', bytes);
          const hash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
          if (hash !== source.sha256) throw new Error('Original source hash changed; byte navigation is unavailable.');
          const text = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes);
          if (!current()) return;
          model.original = {bytes, text};
        }
        const position = sourceFactsPosition(model.original.bytes, range);
        if (!current()) return;
        onNavigate(source, range, position);
        model.notice = `Original UTF-8 bytes [${range.start}, ${range.end}).${position.multiline ? ' The range spans multiple lines.' : ''}`;
      }
      if (current()) model.status = 'ready';
    } catch (error) {
      if (token !== generation || sourceFactsIdentity(getSource()) !== key) return;
      model.status = 'error';
      model.error = controller.signal.aborted ? 'Source facts timed out. Retry explicitly; original evidence is unchanged.' : error.message;
    } finally {
      clearTimeout(timer);
      controller.abort();
      if (token === generation) {
        active = null; activeOwner = null;
        if (!isCurrent()) {
          model.status = model.report ? 'ready' : 'idle';
          model.error = '';
          model.notice = 'Original range request no longer matches its analysis; late results were ignored.';
        }
        change();
      }
    }
  };
  return {model, sync, cancel, load: () => run('facts'), navigate: (range, options) => run('source', range, options),
    cancelOwned(owner, message) { if (!active || activeOwner !== owner) return false; cancel(message); return true; },
    original: source => sourceFactsIdentity(source) === model.key ? model.original?.text : undefined};
}

function createSourceFactsPanel({getSource, onNavigate, openSidebar}) {
  const toggle = document.querySelector('#source-facts-toggle');
  const details = document.querySelector('#source-facts-details');
  const container = document.querySelector('#source-facts-report');
  let category = 'operations';
  let page = 0;
  let rendered = -1;
  const node = (tag, text, className = '') => { const element = document.createElement(tag); element.textContent = text; element.className = className; return element; };
  const button = (text, action) => { const element = node('button', text, 'secondary-button'); element.type = 'button'; element.dataset.factsAction = text.toLowerCase().replaceAll(' ', '-'); element.addEventListener('click', action); return element; };
  const controller = createSourceFactsController({getSource, onChange: render, onNavigate, protocol: location.protocol});
  function render(model) {
    const unavailable = sourceFactsUnavailable(getSource(), location.protocol);
    toggle.disabled = Boolean(unavailable);
    toggle.title = unavailable || 'Inspect bounded lexical and effect facts from this captured JavaScript artifact';
    toggle.setAttribute('aria-expanded', String(details.open));
    if (rendered === model.revision) return;
    rendered = model.revision;
    const content = [];
    if (unavailable) { container.replaceChildren(node('p', unavailable)); return; }
    content.push(node('p', `Session ${model.source.session_id} · artifact ${model.source.artifact_id} · ${model.source.byte_size} original bytes`, 'source-facts-identity'));
    content.push(node('p', `SHA-256 ${model.source.sha256}`, 'source-facts-identity'));
    content.push(node('p', 'Static lexical facts only. Shadowed declarations retain distinct IDs; ambiguous bindings remain candidates. Neither proves initialized values, dataflow or runtime call targets. Local order assumes region entry and normal completion.'));
    const actions = node('div', '', 'source-facts-actions');
    const busy = ['loading', 'loading-source'].includes(model.status);
    actions.append(busy ? button('Cancel', () => controller.cancel()) : button(model.report || model.status === 'error' ? 'Retry facts' : 'Analyze captured source', () => controller.load()), button('Close', () => { details.open = false; controller.cancel(); toggle.focus(); }));
    content.push(actions);
    const status = node('p', model.error || (busy ? model.status === 'loading' ? 'Analyzing immutable JavaScript…' : 'Verifying original UTF-8 bytes…' : model.notice || (model.report ? 'Analysis response loaded. Original evidence is unchanged.' : 'No facts loaded. Analysis never executes this source.')), 'source-facts-status');
    status.setAttribute('role', model.error ? 'alert' : 'status'); content.push(status);
    const report = model.report;
    if (report) {
      const coverage = report.coverage;
      content.push(node('p', `${coverage.status === 'complete' ? 'Complete within lexical-effects-v1 only' : coverage.status === 'partial' ? 'Partial coverage: unknown effects remain' : 'Analysis unavailable'} · ${coverage.truncated ? 'TRUNCATED: analysis budget reached' : 'Analysis not truncated'} · ${coverage.frontiers.length} unknown frontiers`, 'source-facts-coverage'));
      for (const message of coverage.diagnostics) content.push(node('p', message));
      if (model.error) content.push(node('p', 'The last successful facts remain visible for these exact original bytes.'));
      const select = document.createElement('select'); select.className = 'debug-select'; select.setAttribute('aria-label', 'JavaScript fact category');
      for (const name of [...sourceFactsTables, 'frontiers']) {
        const rows = name === 'frontiers' ? coverage.frontiers : report[name];
        const option = node('option', `${name === 'frontiers' ? 'Unknown frontiers' : name[0].toUpperCase() + name.slice(1)} (${rows.length})`); option.value = name; select.append(option);
      }
      select.value = category;
      select.addEventListener('change', () => { category = select.value; page = 0; rendered = -1; render(model); container.querySelector('select')?.focus(); });
      content.push(select);
      const rows = category === 'frontiers' ? coverage.frontiers : report[category];
      page = Math.min(page, Math.max(0, Math.ceil(rows.length / 100) - 1));
      const start = page * 100;
      content.push(node('p', rows.length ? `Showing ${start + 1}–${Math.min(start + 100, rows.length)} of ${rows.length}. At most 100 rows are displayed.` : 'No facts in this category. Unknown effects are listed separately.'));
      const pages = node('div', '', 'source-facts-actions');
      const move = delta => { page += delta; rendered = -1; render(model); container.querySelector('select')?.focus(); };
      const previous = button('Previous', () => move(-1)); previous.disabled = page === 0;
      const next = button('Next', () => move(1)); next.disabled = start + 100 >= rows.length;
      pages.append(previous, next); content.push(pages);
      const list = node('div', '', 'source-facts-list');
      for (const row of rows.slice(start, start + 100)) {
        const item = node('article', '', 'source-fact');
        const title = `${row.id === undefined ? 'Unknown' : `#${row.id}`} ${row.kind ?? row.reason}${row.name === undefined ? '' : ` · ${row.name.slice(0, 256)}${row.name.length > 256 ? '…' : ''}`}`;
        item.append(node('strong', title));
        const link = button(`Original bytes [${row.range.start}, ${row.range.end})`, () => controller.navigate(row.range)); link.disabled = busy; item.append(link);
        const data = document.createElement('details'); data.append(node('summary', 'Fact details'));
        const text = JSON.stringify(row, null, 2); data.append(node('pre', text.length > 4096 ? `${text.slice(0, 4096)}\n[Detail display capped at 4,096 characters]` : text));
        item.append(data); list.append(item);
      }
      content.push(list);
    }
    container.replaceChildren(...content);
  }
  toggle.addEventListener('click', () => {
    if (details.open && details.getClientRects().length) { details.open = false; controller.cancel(); return; }
    openSidebar(); details.open = true;
    if (!controller.model.report) controller.load();
    details.querySelector('summary').focus(); details.scrollIntoView({block: 'nearest'});
  });
  details.addEventListener('keydown', event => {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); details.open = false; controller.cancel(); toggle.focus(); }
  });
  details.addEventListener('toggle', () => { if (!details.open) controller.cancel(); toggle.setAttribute('aria-expanded', String(details.open)); });
  return {...controller, sync(source) { controller.sync(source); render(controller.model); }};
}
