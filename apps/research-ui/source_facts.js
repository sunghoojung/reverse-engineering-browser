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

// Join only the admitted top-level lexical target, never names, arbitrary JSON
// keys or another document's IDs. The server owns the full semantic validator;
// these local guards keep interactive links fail-closed if a target is absent.
function sourceFactsReferenceTarget(operation, bindings) {
  if (!['reference', 'read', 'write', 'call', 'construct'].includes(operation?.kind)) return null;
  const target = operation.detail?.target;
  if (!target || !['binding', 'ambiguous'].includes(target.kind) ||
      !Array.isArray(target.binding_ids) || target.binding_ids.length < 1 || target.binding_ids.length > 64 ||
      new Set(target.binding_ids).size !== target.binding_ids.length ||
      !target.binding_ids.every(id => Number.isSafeInteger(id) && bindings.has(id)) ||
      (target.kind === 'binding' && (target.binding_ids.length !== 1 || !['lexical-only', 'declaration'].includes(target.resolution))) ||
      (target.kind === 'ambiguous' && (target.binding_ids.length < 2 || target.resolution !== 'duplicate-declarations'))) return null;
  return target;
}

// Reports are immutable admitted JSON. Cache one target reference per operation,
// never a binding × operation expansion. Replacement/eviction releases the weak
// report owner; IDs and cached admissions never cross report boundaries.
const sourceFactsReferenceCaches = new WeakMap();
function sourceFactsReferenceContext(report) {
  let context = sourceFactsReferenceCaches.get(report);
  if (!context) {
    const bindings = new Map(report.bindings.map(binding => [binding.id, binding]));
    const targets = new WeakMap();
    context = {bindings, target(operation) {
      if (!targets.has(operation)) targets.set(operation, sourceFactsReferenceTarget(operation, bindings));
      return targets.get(operation);
    }};
    sourceFactsReferenceCaches.set(report, context);
  }
  return context;
}

function sourceFactsBindingOperations(report, bindingId, kind = 'all') {
  const context = sourceFactsReferenceContext(report);
  if (!context.bindings.has(bindingId)) return [];
  // At most 16,384 admitted facts and 64 candidates per target. Do not expand a
  // binding x operation index or clone source bytes/history for this projection.
  return report.operations.filter(operation => {
    if (kind !== 'all' && operation.kind !== kind) return false;
    return context.target(operation)?.binding_ids.includes(bindingId);
  });
}

function sourceFactsOperationSummary(operation, bindings, target = sourceFactsReferenceTarget(operation, bindings)) {
  const detail = operation.detail?.target;
  const relationship = target ? target.kind === 'binding' ? 'Exact lexical binding' : 'Ambiguous declaration candidate'
    : detail?.kind === 'unresolved' ? `Unresolved: ${String(detail.resolution ?? 'unknown').slice(0, 128)}`
    : detail?.kind === 'property' ? 'Property target; runtime object unknown' : 'No admitted lexical binding';
  return `${relationship} · region #${operation.region_id} · local order ${operation.order}${['call', 'construct'].includes(operation.kind) ? ' · runtime call target unknown' : ''}`;
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
  let line = 0, start = 0;
  for (let next = prefix.indexOf('\n'); next >= 0; next = prefix.indexOf('\n', start)) {line++; start = next + 1;}
  const newline = text.indexOf('\n');
  return {line, column: prefix.length - start, length: newline < 0 ? text.length : newline, multiline: newline >= 0};
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
  let viewKey = null, viewReport = null;
  let bindingId = null, candidates = null, query = '', operationKind = 'all', bindingPage = 0;
  let navigationOwner = {}, renderOwner = {};
  let retainedView = null, retainedReport = null, retainedKey = null;
  const node = (tag, text, className = '') => { const element = document.createElement(tag); element.textContent = text; element.className = className; return element; };
  const button = (text, action, key) => { const owner = renderOwner; const element = node('button', text, 'secondary-button'); element.type = 'button'; element.dataset.factsAction = key ?? text.toLowerCase().replaceAll(' ', '-'); element.addEventListener('click', () => { if (owner === renderOwner) action(); }); return element; };
  const controller = createSourceFactsController({getSource, onChange: render, onNavigate, protocol: location.protocol});
  const redraw = (selector, selection) => {
    controller.cancelOwned(navigationOwner, 'Original range request cancelled because the Facts selection changed.');
    navigationOwner = {};
    rendered = -1; render(controller.model);
    const control = container.querySelector(selector);
    control?.focus({preventScroll: true});
    if (selection) control?.setSelectionRange(...selection);
  };
  const currentReport = report => controller.model.report === report && controller.model.key === sourceFactsIdentity(getSource());
  const navigate = (range, report, owner) => {
    if (currentReport(report) && owner === navigationOwner) {
      void controller.navigate(range, {owner, isCurrent: () => currentReport(report) && owner === navigationOwner});
    }
  };
  function renderStatus(model) {
    const busy = ['loading', 'loading-source'].includes(model.status);
    const status = container.querySelector('.source-facts-status');
    status.textContent = model.error || (busy ? model.status === 'loading' ? 'Analyzing immutable JavaScript…' : 'Verifying original UTF-8 bytes…' : model.notice || (model.report ? 'Analysis response loaded. Original evidence is unchanged.' : 'No facts loaded. Analysis never executes this source.'));
    status.setAttribute('role', model.error ? 'alert' : 'status');
    const run = container.querySelector('[data-facts-run]'), cancel = container.querySelector('[data-facts-cancel]');
    const focused = document.activeElement;
    run.textContent = model.report || model.status === 'error' ? 'Retry facts' : 'Analyze captured source';
    run.dataset.factsAction = model.report || model.status === 'error' ? 'retry-facts' : 'analyze-captured-source';
    run.hidden = busy; cancel.hidden = !busy;
    const retained = container.querySelector('.source-facts-retained');
    if (retained) retained.hidden = !model.error;
    for (const control of container.querySelectorAll('[data-facts-original]')) control.disabled = busy;
    if (busy && (focused === run || focused?.dataset.factsOriginal !== undefined)) cancel.focus({preventScroll: true});
    else if (!busy && focused === cancel) run.focus({preventScroll: true});
  }
  function render(model) {
    const focused = container.contains(document.activeElement) ? document.activeElement : null;
    const focusedRow = focused?.closest('[data-fact-id]')?.dataset.factId;
    const focusedAction = focused?.dataset.factsAction;
    const focusedLabel = focused?.getAttribute('aria-label');
    if (viewKey !== model.key) {
      viewKey = model.key; viewReport = null;
      bindingId = null; candidates = null; query = ''; operationKind = 'all'; page = 0; bindingPage = 0;
    }
    if (model.report !== viewReport) {
      // Fact IDs are report-local. Even a successful reanalysis of the same bytes
      // cannot silently inherit a declaration selection from the previous report.
      viewReport = model.report; bindingId = null; candidates = null; page = 0; bindingPage = 0;
    }
    const unavailable = sourceFactsUnavailable(getSource(), location.protocol);
    toggle.disabled = Boolean(unavailable);
    toggle.title = unavailable || 'Inspect bounded lexical and effect facts from this captured JavaScript artifact';
    toggle.setAttribute('aria-expanded', String(details.open));
    if (rendered === model.revision) return;
    rendered = model.revision;
    // Shared navigation retires reads in a capture-phase pointer/key listener.
    // Updating status must not detach the intended click/IME target mid-event.
    if (!unavailable && retainedKey === model.key && retainedReport === model.report && retainedView === navigationOwner) {
      renderStatus(model);
      return;
    }
    renderOwner = {};
    const controlOwner = renderOwner;
    const content = [];
    const renderedOwner = navigationOwner;
    if (unavailable) { retainedKey = null; retainedReport = null; retainedView = null; container.replaceChildren(node('p', unavailable)); return; }
    content.push(node('p', `Session ${model.source.session_id} · artifact ${model.source.artifact_id} · ${model.source.byte_size} original bytes`, 'source-facts-identity'));
    content.push(node('p', `SHA-256 ${model.source.sha256}`, 'source-facts-identity'));
    content.push(node('p', 'Static lexical facts only. Shadowed declarations retain distinct IDs; ambiguous bindings remain candidates. Neither proves initialized values, dataflow or runtime call targets. Local order assumes region entry and normal completion.'));
    const actions = node('div', '', 'source-facts-actions');
    const busy = ['loading', 'loading-source'].includes(model.status);
    const run = button('Analyze captured source', () => controller.load()); run.dataset.factsRun = '';
    const cancel = button('Cancel', () => controller.cancel()); cancel.dataset.factsCancel = '';
    actions.append(run, cancel, button('Close', () => { details.open = false; controller.cancel(); toggle.focus(); }));
    content.push(actions);
    const status = node('p', model.error || (busy ? model.status === 'loading' ? 'Analyzing immutable JavaScript…' : 'Verifying original UTF-8 bytes…' : model.notice || (model.report ? 'Analysis response loaded. Original evidence is unchanged.' : 'No facts loaded. Analysis never executes this source.')), 'source-facts-status');
    status.setAttribute('role', model.error ? 'alert' : 'status'); status.tabIndex = 0; status.setAttribute('aria-label', 'Source facts status'); content.push(status);
    const report = model.report;
    if (report) {
      const coverage = report.coverage;
      content.push(node('p', `${coverage.status === 'complete' ? 'Complete within lexical-effects-v1 only' : coverage.status === 'partial' ? 'Partial coverage: unknown effects remain' : 'Analysis unavailable'} · ${coverage.truncated ? 'TRUNCATED: analysis budget reached' : 'Analysis not truncated'} · ${coverage.frontiers.length} unknown frontiers`, 'source-facts-coverage'));
      for (const message of coverage.diagnostics) content.push(node('p', message));
      content.push(node('p', 'The last successful facts remain visible for these exact original bytes.', 'source-facts-retained'));
      const select = document.createElement('select'); select.className = 'debug-select'; select.setAttribute('aria-label', 'JavaScript fact category');
      for (const name of [...sourceFactsTables, 'frontiers']) {
        const rows = name === 'frontiers' ? coverage.frontiers : report[name];
        const option = node('option', `${name === 'frontiers' ? 'Unknown frontiers' : name[0].toUpperCase() + name.slice(1)} (${rows.length})`); option.value = name; select.append(option);
      }
      select.value = category;
      const ownsView = () => currentReport(report) && controlOwner === renderOwner;
      select.addEventListener('change', () => {
        if (!ownsView()) return;
        category = select.value; page = 0; bindingId = null; candidates = null;
        redraw('[aria-label="JavaScript fact category"]');
      });
      content.push(select);
      const referenceContext = sourceFactsReferenceContext(report);
      const bindings = referenceContext.bindings;
      const explore = id => {
        if (!ownsView() || !bindings.has(id)) return;
        bindingPage = page; category = 'bindings'; bindingId = id; page = 0; operationKind = 'all';
        redraw('[data-facts-action="all-bindings"]');
      };
      let rows = category === 'frontiers' ? coverage.frontiers : report[category];
      const binding = bindings.get(bindingId);
      if (category === 'bindings') {
        if (binding) {
          const heading = node('div', '', 'source-facts-binding');
          heading.append(node('strong', `Binding #${binding.id} · ${binding.name.slice(0, 256)}${binding.name.length > 256 ? '…' : ''}`));
          heading.append(node('p', `${binding.kind} · scope #${binding.scope_id} · declaration bytes [${binding.range.start}, ${binding.range.end})`));
          const back = button(candidates ? 'Back to candidates' : 'All bindings', () => {
            if (!currentReport(report)) return;
            bindingId = null; page = bindingPage;
            redraw('[data-facts-binding-query]');
          }, 'all-bindings');
          const declaration = button('Reveal declaration', () => navigate(binding.range, report, renderedOwner), 'reveal-declaration');
          declaration.disabled = busy; declaration.dataset.factsOriginal = '';
          heading.append(back, declaration);
          heading.append(node('p', 'Lexical operations, not runtime uses or dataflow. Multiple operations can describe the same source occurrence. Candidate rows do not identify a unique declaration.'));
          const filter = document.createElement('select'); filter.className = 'debug-select'; filter.setAttribute('aria-label', 'Lexical operation kind');
          for (const [value, label] of [['all', 'All operations'], ['reference', 'References'], ['read', 'Reads'], ['write', 'Writes'], ['call', 'Calls'], ['construct', 'Constructs']]) {
            const option = node('option', label); option.value = value; filter.append(option);
          }
          filter.value = operationKind;
          filter.addEventListener('change', () => { if (!ownsView()) return; operationKind = filter.value; page = 0; redraw('[aria-label="Lexical operation kind"]'); });
          heading.append(filter); content.push(heading);
          rows = sourceFactsBindingOperations(report, binding.id, operationKind);
        } else {
          const label = node('label', 'Find a declaration by name', 'source-facts-search');
          const input = document.createElement('input'); input.type = 'search'; input.maxLength = 128; input.value = query;
          input.dataset.factsBindingQuery = ''; input.setAttribute('aria-label', 'Find a declaration by name');
          let composing = false;
          const applyQuery = event => {
            if (!ownsView() || composing || event.isComposing) return;
            query = input.value.slice(0, 128); page = 0;
            redraw('[data-facts-binding-query]', [input.selectionStart, input.selectionEnd]);
          };
          input.addEventListener('compositionstart', () => { composing = true; });
          input.addEventListener('compositionend', event => { composing = false; applyQuery(event); });
          input.addEventListener('input', applyQuery);
          label.append(input); content.push(label);
          if (candidates) {
            content.push(node('p', `${candidates.length} ambiguous declaration candidates. No unique binding is proven.`));
            content.push(button('Show all declarations', () => { candidates = null; query = ''; page = 0; redraw('[data-facts-binding-query]'); }, 'clear-candidates'));
          }
          const needle = query.toLowerCase();
          rows = rows.filter(row => (!candidates || candidates.includes(row.id)) && (!needle || row.name.toLowerCase().includes(needle)));
        }
      }
      page = Math.min(page, Math.max(0, Math.ceil(rows.length / 100) - 1));
      const start = page * 100;
      content.push(node('p', rows.length ? `Showing ${start + 1}–${Math.min(start + 100, rows.length)} of ${rows.length}${binding ? ' lexical operations' : ''}. At most 100 rows are displayed.`
        : binding ? 'No admitted operations match this binding and filter. This is not proof of no runtime use; inspect coverage and unknown frontiers.'
        : category === 'bindings' ? 'No declarations match this filter. Unknown effects are listed separately.' : 'No facts in this category. Unknown effects are listed separately.'));
      const pages = node('div', '', 'source-facts-actions');
      const move = delta => { page += delta; redraw(binding ? '[aria-label="Lexical operation kind"]' : '[aria-label="JavaScript fact category"]'); };
      const previous = button('Previous', () => move(-1)); previous.disabled = page === 0;
      const next = button('Next', () => move(1)); next.disabled = start + 100 >= rows.length;
      pages.append(previous, next); content.push(pages);
      const list = node('div', '', 'source-facts-list');
      for (const row of rows.slice(start, start + 100)) {
        const item = node('article', '', 'source-fact');
        item.dataset.factId = String(row.id ?? 'frontier');
        const title = `${row.id === undefined ? 'Unknown' : `#${row.id}`} ${row.kind ?? row.reason}${row.name === undefined ? '' : ` · ${row.name.slice(0, 256)}${row.name.length > 256 ? '…' : ''}`}`;
        item.append(node('strong', title));
        const link = button(`Original bytes [${row.range.start}, ${row.range.end})`, () => navigate(row.range, report, renderedOwner)); link.disabled = busy; link.dataset.factsOriginal = ''; item.append(link);
        if (category === 'bindings' && !binding) {
          item.append(node('p', `Scope #${row.scope_id} · ${row.kind} declaration`));
          item.append(button('Find lexical operations', () => explore(row.id), 'explore-binding'));
        } else if (category === 'operations' || binding) {
          item.append(node('p', sourceFactsOperationSummary(row, bindings, referenceContext.target(row)), 'source-facts-relation'));
          const target = referenceContext.target(row);
          if (target && !binding) {
            if (target.kind === 'binding') {
              const declaration = bindings.get(target.binding_ids[0]);
              item.append(button(`Explore binding #${declaration.id} · ${declaration.name.slice(0, 128)}`, () => explore(declaration.id), 'explore-binding'));
            } else {
              item.append(button(`Choose declaration (${target.binding_ids.length} candidates)`, () => {
                if (!currentReport(report)) return;
                category = 'bindings'; bindingId = null; candidates = [...target.binding_ids]; query = ''; page = 0;
                redraw('[data-facts-binding-query]');
              }, 'choose-candidate'));
            }
          }
        }
        const data = document.createElement('details'); data.append(node('summary', 'Fact details'));
        const text = JSON.stringify(row, null, 2); data.append(node('pre', text.length > 4096 ? `${text.slice(0, 4096)}\n[Detail display capped at 4,096 characters]` : text));
        item.append(data); list.append(item);
      }
      content.push(list);
    }
    container.replaceChildren(...content);
    retainedKey = model.key; retainedReport = model.report; retainedView = navigationOwner;
    renderStatus(model);
    // Replacing rows must not drop keyboard ownership during a read/retry.
    // A verified byte reveal deliberately focuses the editor before this render,
    // so it never matches `focused` and cannot have its focus stolen here.
    if (focused) {
      const controls = [...container.querySelectorAll('button, input, select, .source-facts-status')];
      let replacement = controls.find(control => focusedAction ? control.dataset.factsAction === focusedAction &&
        control.closest('[data-fact-id]')?.dataset.factId === focusedRow : focusedLabel && control.getAttribute('aria-label') === focusedLabel);
      if (!replacement || replacement.disabled || replacement.hidden) replacement = controls.find(control => !control.hidden && ['cancel', 'retry-facts', 'analyze-captured-source'].includes(control.dataset.factsAction));
      replacement?.focus({preventScroll: true});
    }
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
