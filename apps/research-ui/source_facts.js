// Presentation and request lifecycle only. The existing Rust/Oxc worker owns
// inert analysis. The HTTP adapter admits its whole report row by row, keeps it
// by SHA-256 and serves it here as a summary and filtered pages of rows.
const sourceFactsFields = ['protocol_version', 'artifact_id', 'session_id', 'navigation_id',
  'frame_id', 'parent_artifact_id', 'creator_event_id', 'execution_context_id',
  'capture_origin', 'kind', 'url', 'mime_type', 'byte_size', 'sha256', 'sensitive'];
const sourceFactsTables = ['operations', 'bindings', 'callables', 'scopes', 'regions', 'frontiers'];
const sourceFactsPageRows = 100;
const sourceFactsKinds = {
  operations: ['reference', 'read', 'write', 'call', 'construct', 'literal', 'operator', 'return', 'throw', 'control', 'function-value', 'template', 'array', 'object'],
  bindings: ['var', 'let', 'const', 'using', 'await using', 'function', 'function-name', 'parameter', 'import', 'class', 'class-name', 'catch', 'lexical'],
  callables: ['function', 'arrow'], scopes: ['program', 'function', 'catch', 'with', 'block'],
  regions: ['program', 'callable-body', 'eager-argument', 'conditional-then', 'conditional-else', 'short-circuit-right', 'repeated-test', 'repeated-body', 'repeated-update']
};

function sourceFactsIdentity(source) {
  return source?.source_type === 'artifact'
    ? JSON.stringify(sourceFactsFields.map(field => source[field] ?? null)) : null;
}

function sourceFactsUnavailable(source, protocol) {
  // The stored-evidence window (reb:) forwards Facts to its bundled backend.
  if (!['http:', 'https:', 'reb:'].includes(protocol)) {
    return 'Open the local browser development UI to inspect JavaScript facts.';
  }
  if (source?.source_type !== 'artifact' || source.kind !== 'javascript') {
    return 'Select one captured JavaScript artifact. Derived text cannot be analyzed here.';
  }
  const canonical = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;
  if (!canonical(source.session_id) || !canonical(source.artifact_id) ||
      !/^[0-9a-f]{64}$/.test(source.sha256) || !Number.isSafeInteger(source.byte_size) || source.byte_size < 0) {
    return 'The selected source has no exact retained session, artifact, hash and byte-size identity.';
  }
  return '';
}

function sourceFactsRange(range, size) {
  return range && Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end) &&
    range.start >= 0 && range.end >= range.start && range.end <= size;
}

const sourceFactsCount = value => Number.isSafeInteger(value) && value >= 0;

// The summary carries coverage and the size of every table, never rows.
function isSourceFactsReport(value, source) {
  if (!value || value.schema !== 'reb-javascript-source-facts-v2' || value.profile !== 'lexical-effects-v1' ||
      value.offset_unit !== 'utf-8-byte' || value.source_bytes !== source.byte_size || typeof value.cached !== 'boolean' ||
      sourceFactsIdentity({...value.source, source_type: 'artifact'}) !== sourceFactsIdentity(source)) return false;
  const {coverage, counts} = value;
  if (!coverage || !['complete', 'partial', 'unavailable'].includes(coverage.status) ||
      value.ok !== (coverage.status !== 'unavailable') ||
      !Array.isArray(coverage.diagnostics) || !coverage.diagnostics.every(text => typeof text === 'string') ||
      !sourceFactsRange(coverage.analyzed_range, value.source_bytes) ||
      !counts || !sourceFactsTables.every(table => sourceFactsCount(counts[table]))) return false;
  const whole = coverage.analyzed_range.start === 0 && coverage.analyzed_range.end === value.source_bytes;
  if (coverage.status === 'complete' && (!whole || counts.frontiers || coverage.diagnostics.length)) return false;
  return !(coverage.status === 'unavailable' && sourceFactsTables.some(table => table !== 'frontiers' && counts[table]));
}

function sourceFactsRow(table, row, size, count) {
  if (table === 'frontiers') return Boolean(row) && sourceFactsRange(row.range, size) && typeof row.reason === 'string';
  if (!row || !Number.isSafeInteger(row.id) || row.id < 0 || row.id >= count ||
      !sourceFactsRange(row.range, size) || !sourceFactsKinds[table].includes(row.kind)) return false;
  if (table === 'bindings') return typeof row.name === 'string';
  if (table === 'callables') return sourceFactsRange(row.body_range, size);
  if (table === 'operations') return Boolean(row.detail) && typeof row.detail === 'object' && !Array.isArray(row.detail);
  return true;
}

// The one page a view names. A selected binding lists the operations whose
// admitted target names it; otherwise the category is listed, and declarations
// can be narrowed by name or to one ambiguous operation's candidates.
function sourceFactsRequest(view) {
  const declarations = !view.binding && view.category === 'bindings';
  return {
    table: view.binding ? 'operations' : view.category, offset: view.offset,
    binding_id: view.binding?.id ?? null,
    kind: view.binding && view.kind !== 'all' ? view.kind : null,
    name: declarations && view.name ? view.name : null,
    candidates_of: declarations ? view.candidates?.id ?? null : null
  };
}

function sourceFactsQuery(source) {
  return `session_id=${encodeURIComponent(source.session_id)}&artifact_id=${encodeURIComponent(source.artifact_id)}`;
}

function sourceFactsRowsURL(source, request) {
  let url = `/api/source-facts/rows?${sourceFactsQuery(source)}&table=${request.table}&offset=${request.offset}&limit=${sourceFactsPageRows}`;
  for (const key of ['binding_id', 'kind', 'name', 'candidates_of']) {
    if (request[key] !== null) url += `&${key}=${encodeURIComponent(request[key])}`;
  }
  return url;
}

function isSourceFactsPage(value, source, report, request) {
  if (!value || value.schema !== 'reb-javascript-source-fact-rows-v2' ||
      sourceFactsIdentity({...value.source, source_type: 'artifact'}) !== sourceFactsIdentity(source) ||
      value.analyzed_range?.start !== report.coverage.analyzed_range.start ||
      value.analyzed_range?.end !== report.coverage.analyzed_range.end ||
      value.table !== request.table || value.offset !== request.offset || !value.filter ||
      ['binding_id', 'kind', 'name', 'candidates_of'].some(key => (value.filter[key] ?? null) !== request[key]) ||
      !sourceFactsCount(value.total) || value.total > report.counts[request.table] ||
      !Array.isArray(value.rows) || !Array.isArray(value.bindings) ||
      value.rows.length !== Math.max(0, Math.min(sourceFactsPageRows, value.total - value.offset))) return false;
  const filtered = ['binding_id', 'kind', 'name', 'candidates_of'].some(key => request[key] !== null);
  if (!filtered && value.total !== report.counts[request.table]) return false;
  const size = source.byte_size;
  const ids = new Set();
  for (const row of value.rows) {
    if (!sourceFactsRow(value.table, row, size, report.counts[value.table]) || (row.id !== undefined && ids.has(row.id))) return false;
    ids.add(row.id);
  }
  return value.bindings.every(row => sourceFactsRow('bindings', row, size, report.counts.bindings));
}

// Join only the admitted top-level lexical target, never names, arbitrary JSON
// keys or another document's IDs. The server owns the full semantic validator;
// these local guards keep interactive links fail-closed if a target is absent.
function sourceFactsReferenceTarget(operation, bindingCount) {
  if (!['reference', 'read', 'write', 'call', 'construct'].includes(operation?.kind)) return null;
  const target = operation.detail?.target;
  if (!target || !['binding', 'ambiguous'].includes(target.kind) ||
      !Array.isArray(target.binding_ids) || target.binding_ids.length < 1 ||
      new Set(target.binding_ids).size !== target.binding_ids.length ||
      !target.binding_ids.every(id => Number.isSafeInteger(id) && id >= 0 && id < bindingCount) ||
      (target.kind === 'binding' && (target.binding_ids.length !== 1 || !['lexical-only', 'declaration'].includes(target.resolution))) ||
      (target.kind === 'ambiguous' && (target.binding_ids.length < 2 || target.resolution !== 'duplicate-declarations'))) return null;
  return target;
}

function sourceFactsOperationSummary(operation, target) {
  const detail = operation.detail?.target;
  const relationship = target ? target.kind === 'binding' ? 'Exact lexical binding' : 'Ambiguous declaration candidate'
    : detail?.kind === 'unresolved' ? `Unresolved: ${String(detail.resolution ?? 'unknown').slice(0, 128)}`
    : detail?.kind === 'property' ? 'Property target; runtime object unknown' : 'No admitted lexical binding';
  return `${relationship} · region #${operation.region_id} · local order ${operation.order}${['call', 'construct'].includes(operation.kind) ? ' · runtime call target unknown' : ''}`;
}

async function sourceFactsReadBytes(response, maximum = Infinity, signal) {
  // Own bytes immediately in one buffer that grows with the response: keeping
  // chunk views would retain every producer's backing store. Content-Length is
  // not trusted. A finite maximum is a length the caller already knows exactly.
  if (!response.body?.getReader) throw new Error('Response streaming is unavailable.');
  const reader = response.body.getReader();
  let cancelled = false;
  const cancel = () => {
    if (cancelled) return;
    cancelled = true;
    // A producer's cancel hook may never settle. Retire the reader without
    // making request completion wait for that hook.
    void reader.cancel().catch(() => {});
  };
  const checkAbort = () => { if (signal?.aborted) throw new Error('The response was cancelled.'); };
  signal?.addEventListener('abort', cancel, {once: true});
  try {
    checkAbort();
    let bytes = new Uint8Array(0);
    let size = 0, chunks = 0;
    while (true) {
      const {done, value} = await reader.read();
      checkAbort();
      if (done) return bytes.length === size ? bytes : bytes.slice(0, size);
      if (!(value instanceof Uint8Array)) throw new Error('The response contained a non-byte chunk.');
      if (value.byteLength > maximum - size) throw new Error('The response exceeded its byte limit.');
      if (value.byteLength > bytes.length - size) {
        const grown = new Uint8Array(Math.min(maximum, Math.max(size + value.byteLength, bytes.length * 2, 65536)));
        grown.set(bytes.subarray(0, size));
        bytes = grown;
      }
      bytes.set(value, size);
      size += value.byteLength;
      // Count empty chunks too, and let cancellation tasks run even when a
      // fragmented producer keeps read() promises immediately fulfilled.
      if (++chunks % 256 === 0) {
        await new Promise(resolve => setTimeout(resolve, 0));
        checkAbort();
      }
    }
  } catch (error) { cancel(); throw error; }
  finally { signal?.removeEventListener('abort', cancel); reader.releaseLock(); }
}

async function sourceFactsJSON(response, signal, label) {
  const text = new TextDecoder('utf-8', {fatal: true}).decode(await sourceFactsReadBytes(response, Infinity, signal));
  let value;
  try { value = JSON.parse(text); } catch { throw new Error(`${label} returned ${response.ok ? 'malformed JSON' : `HTTP ${response.status}`}.`); }
  if (!response.ok) throw new Error(typeof value?.error === 'string' ? value.error.slice(0, 1024) : `${label} returned HTTP ${response.status}.`);
  return value;
}

function sourceFactsPosition(bytes, range) {
  if (!sourceFactsRange(range, bytes.length)) throw new Error('Invalid original source range.');
  // Fatal decoding rejects a range inside a multibyte scalar. Preserve a UTF-8
  // BOM, whose three bytes are part of the original worker coordinate system.
  const decode = value => new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(value);
  const prefix = decode(bytes.subarray(0, range.start));
  const text = decode(bytes.subarray(range.start, range.end));
  let line = 0, start = 0;
  for (let next = prefix.indexOf('\n'); next >= 0; next = prefix.indexOf('\n', start)) {line++; start = next + 1;}
  const newline = text.indexOf('\n');
  return {line, column: prefix.length - start, length: newline < 0 ? text.length : newline, multiline: newline >= 0};
}

const sourceFactsDefaultView = () => ({category: 'operations', offset: 0, binding: null, kind: 'all', name: '', candidates: null, back: null});

// Two independent request slots. `active` analyzes the whole artifact or
// verifies its original bytes; `rows` reads one page of the admitted report.
// Neither has a deadline: each runs until it settles or is cancelled, and a
// cancelled request stops the backend work it started.
function createSourceFactsController({getSource, onChange, onNavigate, protocol,
  fetcher = fetch, cryptoApi = globalThis.crypto, now = () => Date.now()}) {
  const model = {key: null, source: null, status: 'idle', report: null, view: sourceFactsDefaultView(), page: null,
    pageStatus: 'idle', pageError: '', original: null, error: '', notice: '', started: 0, pageStarted: 0, revision: 0};
  let generation = 0, active = null, activeOwner = null, analysis = null;
  let rowsGeneration = 0, rows = null;
  const change = () => { model.revision += 1; onChange(model); };
  // A retired read leaves the view on the rows it shows.
  const retireRows = () => {
    rowsGeneration += 1; rows?.abort(); rows = null;
    if (model.pageStatus === 'loading') {
      model.pageStatus = model.page ? 'ready' : 'idle'; model.pageError = '';
      if (model.page) model.view = model.page.view;
    }
  };
  const cancel = (message = 'Request cancelled. Its backend work was stopped; original evidence is unchanged.') => {
    if (!active && !rows) return;
    if (active) {
      generation += 1; active.abort(); active = null; activeOwner = null; analysis = null;
      model.status = model.report ? 'ready' : 'idle';
    }
    retireRows();
    model.notice = message; change();
  };
  const sync = source => {
    const key = sourceFactsIdentity(source);
    if (key === model.key && source?.source_type === model.source?.source_type && source?.kind === model.source?.kind) return;
    generation += 1; active?.abort(); active = null; activeOwner = null; analysis = null; retireRows();
    Object.assign(model, {key, source, status: 'idle', report: null, view: sourceFactsDefaultView(), page: null,
      pageStatus: 'idle', pageError: '', original: null, error: '', notice: ''});
    change();
  };
  const show = async (view = model.view) => {
    const report = model.report, source = model.source, key = model.key;
    if (!report || !source) return;
    retireRows();
    const token = rowsGeneration;
    const controller = new AbortController(); rows = controller;
    const request = sourceFactsRequest(view);
    const current = () => token === rowsGeneration && model.report === report && sourceFactsIdentity(getSource()) === key;
    Object.assign(model, {view, pageStatus: 'loading', pageError: '', pageStarted: now()}); change();
    try {
      const page = await sourceFactsJSON(await fetcher(sourceFactsRowsURL(source, request), {cache: 'no-store', signal: controller.signal}), controller.signal, 'Source fact rows');
      if (!isSourceFactsPage(page, source, report, request)) throw new Error('Source fact rows did not match the selected immutable artifact, its report or the requested page.');
      if (!current()) return;
      page.view = view;
      model.page = page; model.pageStatus = 'ready';
    } catch (error) {
      if (!current()) return;
      model.pageStatus = 'error'; model.pageError = error.message;
    } finally {
      if (token === rowsGeneration) { rows = null; change(); }
    }
  };
  const run = async (mode, range, {owner = null, isCurrent = () => true} = {}) => {
    sync(getSource());
    const source = model.source;
    const unavailable = sourceFactsUnavailable(source, protocol);
    if (unavailable) { model.error = unavailable; change(); return; }
    if (active) return mode === 'facts' ? analysis : undefined;
    const key = model.key;
    const token = ++generation;
    const controller = new AbortController(); active = controller; activeOwner = owner;
    const current = () => token === generation && sourceFactsIdentity(getSource()) === key && !controller.signal.aborted && isCurrent();
    Object.assign(model, {status: mode === 'facts' ? 'loading' : 'loading-source', error: '', notice: '', started: now()}); change();
    let report = null;
    try {
      if (mode === 'facts') {
        report = await sourceFactsJSON(await fetcher(`/api/source-facts?${sourceFactsQuery(source)}`, {cache: 'no-store', signal: controller.signal}), controller.signal, 'Source facts');
        if (!isSourceFactsReport(report, source)) throw new Error('Source facts did not match the selected immutable artifact or its contract.');
        if (!current()) { report = null; return; }
        // Fact IDs are report-local. Even a successful reanalysis of the same
        // bytes cannot silently inherit a declaration selection.
        retireRows();
        Object.assign(model, {report, view: sourceFactsDefaultView(), page: null, pageStatus: 'idle', pageError: ''});
      } else {
        if (!model.original) {
          // Reuse the verified 2 MiB chunk route; do not navigate against the
          // editor's possibly lossy preview.
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
            const chunk = await sourceFactsReadBytes(response, length, controller.signal);
            if (chunk.length !== length) throw new Error('Original source is incomplete; byte navigation is unavailable.');
            if (!current()) return;
            bytes.set(chunk, offset);
          }
          if (!cryptoApi?.subtle) throw new Error('SHA-256 verification is unavailable; original byte navigation is disabled.');
          const digest = await cryptoApi.subtle.digest('SHA-256', bytes);
          // WebCrypto cannot be aborted: a digest that settles after its
          // request was cancelled or replaced is discarded here.
          if (!current()) return;
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
      model.error = error.message;
    } finally {
      controller.abort();
      if (token === generation) {
        active = null; activeOwner = null; analysis = null;
        if (!isCurrent()) {
          model.status = model.report ? 'ready' : 'idle';
          model.error = '';
          model.notice = 'Original range request no longer matches its analysis; late results were ignored.';
        }
        change();
      }
    }
    if (report && model.report === report) await show(model.view);
  };
  return {model, sync, cancel, show,
    // A repeated load joins the analysis in flight.
    load() { return active ? analysis ?? undefined : (analysis = run('facts')); },
    navigate: (range, options) => run('source', range, options),
    cancelOwned(owner, message) { if (!active || activeOwner !== owner) return false; cancel(message); return true; },
    original: source => sourceFactsIdentity(source) === model.key ? model.original?.text : undefined};
}

function createSourceFactsPanel({getSource, onNavigate, openSidebar}) {
  const toggle = document.querySelector('#source-facts-toggle');
  const details = document.querySelector('#source-facts-details');
  const container = document.querySelector('#source-facts-report');
  // The panel keeps one node per section and rebuilds a section only when what
  // it shows changes, so a page arriving never detaches a focused control or
  // an input mid-composition.
  const node = (tag, text, className = '') => { const element = document.createElement(tag); element.textContent = text; element.className = className; return element; };
  const sections = {status: null, coverage: null, controls: null, rows: null};
  let shell = null, shown = {}, rendered = -1;
  let navigationOwner = {}, ticker = null;
  const controller = createSourceFactsController({getSource, onChange: render, onNavigate, protocol: location.protocol});
  const button = (text, action, key) => {
    const element = node('button', text, 'secondary-button'); element.type = 'button';
    element.dataset.factsAction = key ?? text.toLowerCase().replaceAll(' ', '-');
    element.addEventListener('click', () => { if (element.isConnected) action(); });
    return element;
  };
  // A view change retires an original-range read this panel started.
  const show = patch => {
    controller.cancelOwned(navigationOwner, 'Original range request cancelled because the Facts selection changed.');
    navigationOwner = {};
    void controller.show({...controller.model.view, ...patch});
  };
  const currentReport = report => controller.model.report === report && controller.model.key === sourceFactsIdentity(getSource());
  const navigate = (range, report, owner) => {
    if (currentReport(report) && owner === navigationOwner) {
      void controller.navigate(range, {owner, isCurrent: () => currentReport(report) && owner === navigationOwner});
    }
  };
  const seconds = started => Math.max(0, Math.floor((Date.now() - started) / 1000));
  function statusText(model) {
    if (model.error) return model.error;
    if (model.status === 'loading') return `Analyzing immutable JavaScript… ${seconds(model.started)} s. The whole artifact is analyzed; Cancel stops the worker.`;
    if (model.status === 'loading-source') return `Verifying original UTF-8 bytes… ${seconds(model.started)} s.`;
    if (model.notice) return model.notice;
    return model.report ? `Analysis ${model.report.cached ? 'reused for these exact bytes' : 'response loaded'}. Original evidence is unchanged.`
      : 'No facts loaded. Analysis never executes this source.';
  }
  function pageText(model) {
    if (model.pageStatus === 'loading') return `Loading rows… ${seconds(model.pageStarted)} s.`;
    if (model.pageStatus === 'error') return `Rows unavailable: ${model.pageError}`;
    const page = model.page;
    if (!page) return '';
    const binding = page.view.binding;
    return page.rows.length ? `Showing ${page.offset + 1}–${page.offset + page.rows.length} of ${page.total}${binding ? ' lexical operations' : ''}.`
      : binding ? 'No admitted operations match this binding and filter. This is not proof of no runtime use; inspect coverage and unknown frontiers.'
      : page.table === 'bindings' ? 'No declarations match this filter. Unknown effects are listed separately.' : 'No facts in this category. Unknown effects are listed separately.';
  }
  function renderStatus(model) {
    const busy = ['loading', 'loading-source'].includes(model.status);
    const working = busy || model.pageStatus === 'loading';
    const {status} = sections;
    status.textContent = statusText(model);
    status.setAttribute('role', model.error ? 'alert' : 'status');
    const run = container.querySelector('[data-facts-run]'), cancel = container.querySelector('[data-facts-cancel]');
    const focused = document.activeElement;
    run.textContent = model.report || model.status === 'error' ? 'Retry facts' : 'Analyze captured source';
    run.dataset.factsAction = model.report || model.status === 'error' ? 'retry-facts' : 'analyze-captured-source';
    run.hidden = busy; cancel.hidden = !working;
    const retained = container.querySelector('.source-facts-retained');
    if (retained) retained.hidden = !model.error;
    const pageStatus = container.querySelector('.source-facts-page-status');
    if (pageStatus) {
      pageStatus.textContent = pageText(model);
      pageStatus.setAttribute('role', model.pageStatus === 'error' ? 'alert' : 'status');
    }
    const list = container.querySelector('.source-facts-list');
    if (list) list.setAttribute('aria-busy', String(model.pageStatus === 'loading'));
    for (const control of container.querySelectorAll('[data-facts-original]')) control.disabled = busy;
    for (const control of container.querySelectorAll('[data-facts-view]')) control.disabled = model.status === 'loading';
    if (busy && (focused === run || focused?.dataset.factsOriginal !== undefined)) cancel.focus({preventScroll: true});
    else if (!working && focused === cancel) run.focus({preventScroll: true});
    // Elapsed time is the progress of a request with no deadline.
    if (working && !ticker) {
      ticker = setInterval(() => {
        if (sections.status?.isConnected) renderStatus(controller.model);
        else { clearInterval(ticker); ticker = null; }
      }, 1000);
    } else if (!working && ticker) { clearInterval(ticker); ticker = null; }
  }
  // Replace one section, keeping keyboard focus on the equivalent control.
  function rebuild(section, nodes) {
    const focused = section.contains(document.activeElement) ? document.activeElement : null;
    const action = focused?.dataset.factsAction, label = focused?.getAttribute('aria-label');
    const row = focused?.closest('[data-fact-id]')?.dataset.factId;
    section.replaceChildren(...nodes);
    if (!focused) return;
    const controls = [...section.querySelectorAll('button, input, select')].filter(control => !control.disabled && !control.hidden);
    const replacement = controls.find(control => action ? control.dataset.factsAction === action && control.closest('[data-fact-id]')?.dataset.factId === row
      : label && control.getAttribute('aria-label') === label) ?? controls[0] ?? sections.status;
    replacement.focus({preventScroll: true});
  }
  function renderShell(model) {
    const content = [];
    content.push(node('p', `Session ${model.source.session_id} · artifact ${model.source.artifact_id} · ${model.source.byte_size} original bytes`, 'source-facts-identity'));
    content.push(node('p', `SHA-256 ${model.source.sha256}`, 'source-facts-identity'));
    content.push(node('p', 'Static lexical facts only. Shadowed declarations retain distinct IDs; ambiguous bindings remain candidates. Neither proves initialized values, dataflow or runtime call targets. Local order assumes region entry and normal completion.'));
    const actions = node('div', '', 'source-facts-actions');
    const run = button('Analyze captured source', () => controller.load()); run.dataset.factsRun = '';
    const cancel = button('Cancel', () => controller.cancel()); cancel.dataset.factsCancel = '';
    actions.append(run, cancel, button('Close', () => { details.open = false; controller.cancel(); toggle.focus(); }));
    content.push(actions);
    sections.status = node('p', '', 'source-facts-status');
    sections.status.tabIndex = 0; sections.status.setAttribute('aria-label', 'Source facts status');
    sections.coverage = node('div', ''); sections.controls = node('div', ''); sections.rows = node('div', '');
    content.push(sections.status, sections.coverage, sections.controls, sections.rows);
    container.replaceChildren(...content);
    shown = {};
  }
  function renderCoverage(report) {
    if (!report) { rebuild(sections.coverage, []); return; }
    const {coverage, counts} = report;
    const nodes = [node('p', `${coverage.status === 'complete' ? 'Complete within lexical-effects-v1 only' : coverage.status === 'partial' ? 'Partial coverage: unknown effects remain' : 'Analysis unavailable'} · whole artifact analyzed · ${counts.frontiers} unknown frontiers`, 'source-facts-coverage')];
    for (const message of coverage.diagnostics) nodes.push(node('p', message));
    nodes.push(node('p', 'The last successful facts remain visible for these exact original bytes.', 'source-facts-retained'));
    rebuild(sections.coverage, nodes);
  }
  function renderControls(model) {
    const {report, view} = model;
    if (!report) { rebuild(sections.controls, []); return; }
    const nodes = [];
    const select = document.createElement('select'); select.className = 'debug-select'; select.setAttribute('aria-label', 'JavaScript fact category');
    select.dataset.factsView = '';
    for (const name of sourceFactsTables) {
      const option = node('option', `${name === 'frontiers' ? 'Unknown frontiers' : name[0].toUpperCase() + name.slice(1)} (${report.counts[name]})`); option.value = name; select.append(option);
    }
    select.value = view.binding ? 'bindings' : view.category;
    select.addEventListener('change', () => {
      if (select.isConnected && currentReport(report)) show({...sourceFactsDefaultView(), category: select.value});
    });
    nodes.push(select);
    const binding = view.binding;
    if (binding) {
      const heading = node('div', '', 'source-facts-binding');
      heading.append(node('strong', `Binding #${binding.id} · ${binding.name.slice(0, 256)}${binding.name.length > 256 ? '…' : ''}`));
      heading.append(node('p', `${binding.kind} · scope #${binding.scope_id} · declaration bytes [${binding.range.start}, ${binding.range.end})`));
      const back = button(view.back?.candidates ? 'Back to candidates' : view.back?.category === 'operations' ? 'Back to operations' : 'All bindings',
        () => show(view.back ?? {...sourceFactsDefaultView(), category: 'bindings'}), 'back-to-list');
      const declaration = button('Reveal declaration', () => navigate(binding.range, report, navigationOwner), 'reveal-declaration');
      declaration.dataset.factsOriginal = '';
      heading.append(back, declaration);
      heading.append(node('p', 'Lexical operations, not runtime uses or dataflow. Multiple operations can describe the same source occurrence. Candidate rows do not identify a unique declaration.'));
      const filter = document.createElement('select'); filter.className = 'debug-select'; filter.setAttribute('aria-label', 'Lexical operation kind');
      filter.dataset.factsView = '';
      for (const [value, label] of [['all', 'All operations'], ['reference', 'References'], ['read', 'Reads'], ['write', 'Writes'], ['call', 'Calls'], ['construct', 'Constructs']]) {
        const option = node('option', label); option.value = value; filter.append(option);
      }
      filter.value = view.kind;
      filter.addEventListener('change', () => { if (filter.isConnected && currentReport(report)) show({kind: filter.value, offset: 0}); });
      heading.append(filter); nodes.push(heading);
    } else if (view.category === 'bindings') {
      const label = node('label', 'Find a declaration by name', 'source-facts-search');
      const input = document.createElement('input'); input.type = 'search'; input.value = view.name;
      input.dataset.factsBindingQuery = ''; input.setAttribute('aria-label', 'Find a declaration by name');
      let composing = false;
      // The input itself keeps the text. Each settled edit asks for the first
      // matching page; a newer edit retires the older read.
      const apply = event => {
        if (!input.isConnected || !currentReport(report) || composing || event.isComposing) return;
        show({name: input.value, offset: 0});
      };
      input.addEventListener('compositionstart', () => { composing = true; });
      input.addEventListener('compositionend', event => { composing = false; apply(event); });
      input.addEventListener('input', apply);
      label.append(input); nodes.push(label);
      if (view.candidates) {
        nodes.push(node('p', `${view.candidates.count} ambiguous declaration candidates. No unique binding is proven.`));
        nodes.push(button('Show all declarations', () => show({candidates: null, name: '', offset: 0}), 'clear-candidates'));
      }
    }
    rebuild(sections.controls, nodes);
  }
  function renderRows(model) {
    const {report, page} = model;
    if (!report) { rebuild(sections.rows, []); return; }
    const nodes = [node('p', '', 'source-facts-page-status')];
    const pages = node('div', '', 'source-facts-actions');
    const move = offset => { if (currentReport(report) && model.page === page) show({...page.view, offset}); };
    const previous = button('Previous', () => move(Math.max(0, page.offset - sourceFactsPageRows)));
    const next = button('Next', () => move(page.offset + sourceFactsPageRows));
    previous.disabled = !page || page.offset === 0; next.disabled = !page || page.offset + sourceFactsPageRows >= page.total;
    previous.dataset.factsView = ''; next.dataset.factsView = '';
    pages.append(previous, next); nodes.push(pages);
    const list = node('div', '', 'source-facts-list');
    if (page) {
      const bindings = new Map(page.bindings.map(binding => [binding.id, binding]));
      const explore = binding => show({...sourceFactsDefaultView(), category: 'bindings', binding,
        back: {...page.view, binding: null, back: null}});
      for (const row of page.rows) {
        const item = node('article', '', 'source-fact');
        item.dataset.factId = String(row.id ?? 'frontier');
        const title = `${row.id === undefined ? 'Unknown' : `#${row.id}`} ${row.kind ?? row.reason}${row.name === undefined ? '' : ` · ${row.name.slice(0, 256)}${row.name.length > 256 ? '…' : ''}`}`;
        item.append(node('strong', title));
        const link = button(`Original bytes [${row.range.start}, ${row.range.end})`, () => navigate(row.range, report, navigationOwner)); link.dataset.factsOriginal = ''; item.append(link);
        if (page.table === 'bindings') {
          item.append(node('p', `Scope #${row.scope_id} · ${row.kind} declaration`));
          item.append(button('Find lexical operations', () => explore(row), 'explore-binding'));
        } else if (page.table === 'operations') {
          const target = sourceFactsReferenceTarget(row, report.counts.bindings);
          item.append(node('p', sourceFactsOperationSummary(row, target), 'source-facts-relation'));
          if (target && !page.view.binding) {
            const declaration = target.kind === 'binding' ? bindings.get(target.binding_ids[0]) : null;
            if (declaration) {
              item.append(button(`Explore binding #${declaration.id} · ${declaration.name.slice(0, 128)}`, () => explore(declaration), 'explore-binding'));
            } else if (target.kind === 'ambiguous') {
              item.append(button(`Choose declaration (${target.binding_ids.length} candidates)`, () => show({...sourceFactsDefaultView(), category: 'bindings',
                candidates: {id: row.id, count: target.binding_ids.length}}), 'choose-candidate'));
            }
          }
        }
        const data = document.createElement('details'); data.append(node('summary', 'Fact details'));
        data.append(node('pre', JSON.stringify(row, null, 2)));
        item.append(data); list.append(item);
      }
    }
    nodes.push(list);
    rebuild(sections.rows, nodes);
  }
  function render(model) {
    const unavailable = sourceFactsUnavailable(getSource(), location.protocol);
    toggle.disabled = Boolean(unavailable);
    toggle.title = unavailable || 'Inspect lexical and effect facts from this whole captured JavaScript artifact';
    toggle.setAttribute('aria-expanded', String(details.open));
    if (rendered === model.revision) return;
    rendered = model.revision;
    if (unavailable) {
      shell = null; sections.status = null;
      if (ticker) { clearInterval(ticker); ticker = null; }
      container.replaceChildren(node('p', unavailable)); return;
    }
    if (shell !== model.key || !sections.status?.isConnected) { shell = model.key; renderShell(model); }
    if (shown.report !== model.report) {
      shown.report = model.report; renderCoverage(model.report);
    }
    // Typing a name changes only the view's name; the input keeps its text.
    const controls = [model.report, model.view.category, model.view.binding, model.view.kind, model.view.candidates];
    if (!shown.controls || shown.controls.some((value, index) => value !== controls[index])) {
      shown.controls = controls; renderControls(model);
    }
    if (!('page' in shown) || shown.page !== model.page || shown.pageReport !== model.report) {
      shown.page = model.page; shown.pageReport = model.report; renderRows(model);
    }
    renderStatus(model);
  }
  toggle.addEventListener('click', () => {
    if (details.open && details.getClientRects().length) { details.open = false; controller.cancel(); return; }
    openSidebar(); details.open = true;
    if (!controller.model.report) controller.load();
    details.querySelector('summary').focus(); details.scrollIntoView({block: 'nearest'});
  });
  details.addEventListener('keydown', event => {
    if (event.key === 'Escape' && (event.isComposing || event.keyCode === 229)) { event.stopPropagation(); return; }
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); details.open = false; controller.cancel(); toggle.focus(); }
  });
  details.addEventListener('toggle', () => { if (!details.open) controller.cancel(); toggle.setAttribute('aria-expanded', String(details.open)); });
  return {...controller, sync(source) { controller.sync(source); render(controller.model); }};
}
