// Cold-path presentation only. The Rust package reader owns duplicate rejection,
// the closed metadata projection, canonical identity and guarded source reads.
const evidencePackageMaximum = 4 * 1024 * 1024;
const evidencePackagePageSize = 50;
const evidencePackageResolutions = {
  included: 'Included', outside_selection: 'Outside selection',
  missing_in_retained_source: 'Missing in retained source', not_inspected: 'Not inspected',
  insufficient_identity: 'Unknown identity'
};

function evidencePackageKey(kind, value) {
  const decimal = text => typeof text === 'string' && /^[1-9][0-9]{0,19}$/.test(text) && BigInt(text) <= 18446744073709551615n;
  if (!value || !decimal(value.session_id)) return null;
  if (kind === 'event') {
    if (!decimal(value.sequence_number) || !Number.isSafeInteger(value.process_id) || value.process_id < 1 || value.process_id > 4294967295) return null;
    return {session_id: value.session_id, process_id: value.process_id, sequence_number: value.sequence_number};
  }
  return kind === 'artifact' && decimal(value.artifact_id) ? {session_id: value.session_id, artifact_id: value.artifact_id} : null;
}

function evidencePackageKeyText(kind, key) {
  return key ? kind === 'event'
    ? `session ${key.session_id} / process ${key.process_id} / event ${key.sequence_number}`
    : `session ${key.session_id} / artifact ${key.artifact_id}` : 'Identity unavailable';
}

function evidencePackageSelectionKey(selection) {
  // Object-member order is not identity; the Rust exporter sorts JSON keys.
  return JSON.stringify(['events', 'artifacts'].map(kind => selection[kind].map(key =>
    JSON.stringify(kind === 'events' ? [key.session_id, key.process_id, key.sequence_number] : [key.session_id, key.artifact_id])).sort()));
}

function evidencePackageUnavailable(protocol) {
  return ['http:', 'https:'].includes(protocol) ? '' : protocol === 'reb:'
    ? 'Package export and validation are unavailable in stored-evidence native mode. Open a live workspace or the local browser development UI.'
    : 'Open the local browser development UI for package export and validation.';
}

async function evidencePackageReadBytes(response, maximum, signal) {
  if (!response.body?.getReader) throw new Error('Bounded response reading is unavailable.');
  const reader = response.body.getReader();
  let cancelled = false;
  const cancel = () => {
    if (cancelled) return;
    cancelled = true;
    // A producer's cleanup can remain pending forever. Request ownership and
    // deadlines must not wait for it; cancelling retires pending reader reads.
    void reader.cancel().catch(() => {});
  };
  const checkAbort = () => { if (signal?.aborted) throw new Error('The package response was cancelled.'); };
  signal?.addEventListener('abort', cancel, {once: true});
  try {
    checkAbort();
    // Own each chunk immediately so tiny views cannot retain huge backing stores.
    const bytes = new Uint8Array(maximum);
    let size = 0, chunks = 0;
    while (true) {
      const {done, value} = await reader.read();
      checkAbort();
      if (done) return bytes.subarray(0, size);
      if (++chunks > 65536) throw new Error('The package response exceeded its transport chunk limit.');
      if (!(value instanceof Uint8Array)) throw new Error('The package response contained a non-byte chunk.');
      if (value.byteLength > maximum - size) throw new Error('The package response exceeded its byte limit.');
      bytes.set(value, size); size += value.byteLength;
      // Include empty chunks, and yield so timeout/Cancel tasks can run even if
      // every read is immediately fulfilled by a fragmented producer.
      if (chunks % 256 === 0) { await new Promise(resolve => setTimeout(resolve, 0)); checkAbort(); }
    }
  } catch (error) { cancel(); throw error; }
  finally { signal?.removeEventListener('abort', cancel); reader.releaseLock(); }
}

function evidencePackageValidationResult(value) {
  if (!value || value.protocol_version !== 1 || !['valid', 'invalid', 'unsupported'].includes(value.status) ||
      value.origin !== 'untrusted_input' || value.authenticity !== 'not_established' ||
      value.artifact_bytes !== 'not_present_not_reverified' || !Array.isArray(value.issues) || value.issues.length > 64 ||
      typeof value.issues_truncated !== 'boolean' || !value.checks) return false;
  const checks = ['structure', 'semantic_digest', 'references', 'metadata_profile'];
  if (!checks.every(key => ['passed', 'failed', 'not_run'].includes(value.checks[key])) ||
      !value.issues.every(issue => issue && /^[a-z_]{1,64}$/.test(issue.code) && /^[a-z_]{1,64}$/.test(issue.section) &&
        (issue.index === null || (Number.isSafeInteger(issue.index) && issue.index >= 0 && issue.index <= 4095)))) return false;
  if (value.package_id !== null && !/^reb-package-v1:sha256:[0-9a-f]{64}$/.test(value.package_id)) return false;
  return value.status !== 'valid' || (value.package_id !== null && !value.issues.length &&
    !value.issues_truncated && checks.every(key => value.checks[key] === 'passed'));
}

function evidencePackageError(status) {
  return ({400: 'The package request was rejected as malformed.',
    404: 'An exact selected identity is unavailable. Refresh the retained view and review the selection.',
    408: 'The bounded package operation timed out. No package was saved; retry only when you choose.',
    409: 'Export was refused: a writer may still hold a lease, the source changed, or identities conflict. No writer was stopped. Review the stores before retrying.',
    413: 'The package or source scan exceeds a supported bound. A smaller selection cannot bypass a whole-source scan limit.',
    422: 'The retained source or artifact integrity check failed. No package was produced.',
    503: 'Package operations are unavailable or busy. Export requires guarded stores from updated writers and safe local files; legacy stores are unsupported. No guard was created.'})[status] || `The local package service returned HTTP ${status}.`;
}

function evidencePackageView(document, validation) {
  // This runs only AFTER the exact original bytes passed the authoritative
  // validator. It is not a second parser/validator or an authentication check.
  if (document?.format !== 'reb-evidence-package' || document.protocol_version !== 1 ||
      document.package_id !== validation.package_id || document.redaction_profile !== 'reb-metadata-only-v1' ||
      !document.coverage || !document.provenance || !document.records ||
      !Array.isArray(document.records.events) || document.records.events.length > 1024 ||
      !Array.isArray(document.records.artifacts) || document.records.artifacts.length > 64 ||
      !Array.isArray(document.relationships) || document.relationships.length > 4096 ||
      !Array.isArray(document.gaps) || document.gaps.length > 4096) throw new Error('The validated package response is not supported by this view.');
  return document;
}

function createEvidencePackageController({getSelection, onChange, protocol, fetcher = fetch, deadline = 15000}) {
  const model = {status: 'idle', message: '', validation: null, document: null, bytes: null, origin: null, selectionKey: null, revision: 0};
  let generation = 0;
  let active = null;
  const changed = () => { model.revision += 1; onChange(model); };
  const cancel = (message = 'Cancelled. A bounded server operation already started may finish; its result will not be applied.') => {
    if (!active) return;
    generation += 1; clearTimeout(active.timer); active.controller.abort(); active = null;
    model.status = 'cancelled'; model.message = message; changed();
  };
  const clear = () => {
    cancel(); generation += 1;
    Object.assign(model, {status: 'idle', message: '', validation: null, document: null, bytes: null, origin: null, selectionKey: null}); changed();
  };
  const run = async (kind, file = null) => {
    if (active) return;
    const unavailable = evidencePackageUnavailable(protocol);
    if (unavailable) { model.status = 'error'; model.message = unavailable; changed(); return; }
    const selection = getSelection();
    if (kind === 'export' && (!selection.events.length && !selection.artifacts.length)) return;
    if (kind === 'file' && (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > evidencePackageMaximum)) {
      clear(); model.status = 'error'; model.message = 'Choose one nonempty package file of at most 4 MiB.'; changed(); return;
    }
    const token = ++generation;
    const controller = new AbortController();
    const current = () => generation === token && active?.controller === controller;
    const selectionCurrent = () => kind !== 'export' || evidencePackageSelectionKey(getSelection()) === model.selectionKey;
    const timer = setTimeout(() => {
      if (!current()) return;
      cancel('The package operation timed out. No result was applied; retry only when you choose.');
      model.status = 'error'; changed();
    }, deadline);
    active = {controller, timer};
    Object.assign(model, {status: 'loading', message: kind === 'export' ? 'Reading the exact selection under cooperative stopped-store leases…' : 'Validating the original file bytes with the local service…',
      validation: null, document: null, bytes: null, origin: kind, selectionKey: kind === 'export' ? evidencePackageSelectionKey(selection) : null}); changed();
    const post = async (operation, bytes, maximum) => {
      const response = await fetcher(`/api/evidence/packages/${operation}`, {method: 'POST', cache: 'no-store',
        headers: {'Content-Type': 'application/json'}, body: bytes, signal: controller.signal});
      if (!current()) return null;
      if (!response.ok) throw new Error(evidencePackageError(response.status));
      const result = await evidencePackageReadBytes(response, maximum, controller.signal);
      return current() ? result : null;
    };
    try {
      let bytes;
      if (kind === 'export') {
        // Only closed composite keys cross this boundary, never event objects.
        const request = new TextEncoder().encode(JSON.stringify({protocol_version: 1, profile: 'reb-metadata-only-v1', selection}));
        bytes = await post('export', request, evidencePackageMaximum);
      } else {
        bytes = new Uint8Array(await file.arrayBuffer());
        if (bytes.byteLength !== file.size || bytes.byteLength > evidencePackageMaximum) throw new Error('The selected file changed or exceeds the byte limit.');
      }
      if (!current() || !bytes) return;
      if (!selectionCurrent()) { clear(); return; }
      // Do not JSON.parse, stringify, decode/re-encode or otherwise normalize
      // supplied bytes before validation: that would hide duplicate JSON keys.
      const validationBytes = await post('validate', bytes, 64 * 1024);
      if (!current() || !validationBytes) return;
      if (!selectionCurrent()) { clear(); return; }
      const validation = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(validationBytes));
      if (!evidencePackageValidationResult(validation)) throw new Error('The package service returned an unsupported validation response.');
      model.validation = validation;
      if (validation.status === 'valid') {
        const document = evidencePackageView(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)), validation);
        if (kind === 'export' && evidencePackageSelectionKey(document.selection) !== model.selectionKey) throw new Error('The exported package did not match the exact selected identities.');
        model.document = document; model.bytes = bytes; model.status = 'ready';
        model.message = kind === 'export' ? 'Selected metadata exported and validated locally. Nothing has been saved yet.' : 'The supplied package is internally consistent untrusted metadata.';
      } else {
        model.status = validation.status; model.message = validation.status === 'invalid' ? 'Invalid package. No evidence was imported.' : 'Unsupported package version or profile. No best-effort interpretation was attempted.';
      }
    } catch (error) {
      if (!current()) return;
      model.status = 'error'; model.message = error instanceof Error ? error.message : 'The local package service is unavailable.';
    } finally {
      if (current()) { clearTimeout(timer); active = null; changed(); }
    }
  };
  return {model, cancel, clear, export: () => run('export'), validate: file => run('file', file)};
}

function createEvidencePackagePanel({getContext, protocol = location.protocol}) {
  const host = document.querySelector('#evidence-package-panel');
  const scope = host.querySelector('[data-package-scope]');
  const candidates = host.querySelector('[data-package-candidates]');
  const selectionSummary = host.querySelector('[data-package-selection]');
  const selectionList = host.querySelector('[data-package-selected]');
  const notice = host.querySelector('[data-package-notice]');
  const report = host.querySelector('[data-package-report]');
  const file = host.querySelector('[data-package-file]');
  const exportButton = host.querySelector('[data-package-export]');
  const validateButton = host.querySelector('[data-package-validate]');
  const cancelButton = host.querySelector('[data-package-cancel]');
  const downloadButton = host.querySelector('[data-package-download]');
  const copyButton = host.querySelector('[data-package-copy]');
  const saveNote = host.querySelector('[data-package-save-note]');
  const nativeShell = document.documentElement.classList.contains('native-shell');
  let copying = false;
  const selected = {events: new Map(), artifacts: new Map()};
  let contextKey = null;
  let page = 0;
  let rows = [];
  let signature = null;
  let visible = false;
  let viewRevision = 0;
  let selectionSignature = null;
  const getSelection = () => ({events: [...selected.events.values()], artifacts: [...selected.artifacts.values()]});
  const node = (tag, text, className = '') => { const element = document.createElement(tag); element.textContent = text; element.className = className; return element; };
  const button = (text, action) => { const element = node('button', text, 'secondary-button'); element.type = 'button'; element.addEventListener('click', action); return element; };
  const paragraph = text => node('p', text, 'package-note');
  const facts = entries => {
    const list = node('dl', '', 'package-facts');
    entries.forEach(([label, value]) => list.append(node('dt', label), node('dd', String(value)))); return list;
  };
  const paged = (title, entries) => {
    const disclosure = node('details', '', 'package-disclosure');
    disclosure.append(node('summary', `${title} · ${entries.length}`));
    const list = node('ol', '', 'package-report-rows');
    const toolbar = node('div', '', 'package-toolbar');
    const label = node('span', ''); let start = 0;
    const render = () => {
      list.replaceChildren(...entries.slice(start, start + evidencePackagePageSize).map(text => node('li', text)));
      label.textContent = entries.length ? `${start + 1}–${Math.min(start + evidencePackagePageSize, entries.length)} of ${entries.length}` : 'No records';
      previous.disabled = start === 0; next.disabled = start + evidencePackagePageSize >= entries.length;
    };
    const previous = button('Previous', () => { start = Math.max(0, start - evidencePackagePageSize); render(); });
    const next = button('Next', () => { start += evidencePackagePageSize; render(); });
    previous.setAttribute('aria-label', `Previous ${title.toLowerCase()}`); next.setAttribute('aria-label', `Next ${title.toLowerCase()}`);
    toolbar.append(previous, label, next); disclosure.append(list, toolbar); render(); return disclosure;
  };
  const renderReport = model => {
    report.replaceChildren();
    const validation = model.validation;
    if (validation) {
      report.append(facts(Object.entries(validation.checks).map(([name, value]) => [name.replaceAll('_', ' '), value])));
      if (validation.issues.length) report.append(paged('Validation issues', validation.issues.map(issue => `${issue.section} · ${issue.code}${issue.index === null ? '' : ` · index ${issue.index}`}`)));
      if (validation.issues_truncated) report.append(paragraph('Additional validation issues were omitted by the service limit.'));
    }
    const value = model.document;
    if (!value) return;
    report.append(node('h3', 'Package coverage'), paragraph('Valid means internally consistent untrusted metadata. Authenticity, full recording, artifact bytes and equivalence are not established.'),
      facts([['Package ID', value.package_id], ['Profiles', `${value.serialization_profile} / ${value.redaction_profile} / ${value.semantics_profile}`], ['Source', model.origin === 'export' ? 'This explicit local guarded export' : 'Supplied file; exporter claims are untrusted'],
        ['Consistency', model.origin === 'export' ? 'Cooperative stopped-store export; supported writers only' : `Unverified claim: ${value.provenance.consistency}`],
        ['Producer and browser build', 'Unknown historical facts'], ['Capture configuration / authorization', 'Unknown / not attested'],
        ['Observer regime', 'Probe sites, execution tier, forced mode, mutation, serialization and measured overhead: unknown'],
        ['Epochs and context', 'Document, execution-context and catalog epochs: unknown. Recorded IDs are shown below when present; they do not identify the currently active page.'],
        ['API completion coverage', 'Markers only. Return, throw, WASM trap, reentry and Promise settlement were not recorded.']]));
    for (const kind of ['events', 'artifacts']) {
      const section = value.coverage[kind];
      report.append(node('h4', kind === 'events' ? 'Native events' : 'Artifacts'), facts([
        ['Selected metadata', `${section.selected_count} · ${section.selection_state.replaceAll('_', ' ')}`],
        ['Retained-source scan', `${section.source_scan.replaceAll('_', ' ')}${model.origin === 'file' ? ' (unverified exporter claim)' : ''}`],
        ['Capture coverage', section.capture_state === 'partial' ? 'Partial: scoped loss observations' : 'Unknown'],
        ['Limitations', section.limitations.map(text => text.replaceAll('_', ' ')).join(', ')]]));
    }
    report.append(paragraph('A complete retained-source scan is not a complete recording. Empty, disconnected or absent records do not establish disabled, expired, evicted or filtered capture.'),
      paragraph(`Outside this metadata profile: ${value.coverage.excluded_sections.map(text => text.replaceAll('_', ' ')).join(', ')}. Payloads, URLs, headers, cookies, bodies and hook values are never exported.`));
    const counts = Object.keys(evidencePackageResolutions).map(resolution => [evidencePackageResolutions[resolution], value.relationships.filter(row => row.resolution === resolution).length]);
    report.append(node('h4', 'Reference coverage'), facts(counts), paragraph('Included targets are selected. Outside selection means retained but omitted. Missing means absent from the scanned retained source. Not inspected and unknown identity cannot establish absence.'));
    const drops = value.gaps.filter(gap => gap.kind === 'queue_drop_marker');
    const holes = value.gaps.filter(gap => gap.kind === 'sequence_discontinuity');
    report.append(node('h4', 'Loss observations'), facts([['Native queue-drop markers', `${drops.length} records; counts may be unknown`], ['Sequence discontinuities', `${holes.length} ranges`]]),
      paragraph('Queue-drop counts and sequence holes can overlap. They are never added as a unique lost-event total. Sparse selection alone does not create sequence gaps.'));
    report.append(paged('Event metadata', value.records.events.map(event => `${evidencePackageKeyText('event', event.key)} · time ${event.monotonic_time_ns} ns (monotonic) · ${event.category}/${event.type} · ${event.operation ?? 'No recognized API operation'} · marker seen; outcome not recorded; placement unknown · navigation ${event.navigation_id}; frame ${event.frame_id}; thread ${event.thread_id}; tab ${event.tab_id ?? 'unknown'}; browser context ${event.browser_context_id_high === null ? 'unknown' : `${event.browser_context_id_high}:${event.browser_context_id_low}`}`)),
      paged('Artifact metadata', value.records.artifacts.map(artifact => `${evidencePackageKeyText('artifact', artifact.key)} · ${artifact.kind} · ${artifact.byte_size} bytes · SHA-256 ${artifact.sha256} · navigation ${artifact.navigation_id}; frame ${artifact.frame_id}; execution context ${artifact.execution_context_id ?? 'unknown'}; capture origin ${artifact.capture_origin} · content omitted; ${model.origin === 'file' ? 'export-time verification is an untrusted claim' : 'bytes verified at this export'}`)),
      paged('References', value.relationships.map(row => `${evidencePackageKeyText(row.from_kind, row.from_key)} → ${row.relation.replaceAll('_', ' ')} → ${evidencePackageKeyText(row.to_kind, row.to_key)} · ${evidencePackageResolutions[row.resolution]}`)),
      paged('Gaps', value.gaps.map(gap => gap.kind === 'queue_drop_marker'
        ? `Native queue drop · session ${gap.session_id} / process ${gap.process_id} / anchor ${gap.anchor_sequence} · count ${gap.reported_dropped_count ?? 'unknown'} · occurrences ${gap.occurrences}`
        : gap.kind === 'sequence_discontinuity' ? `Sequence gap · session ${gap.session_id} / process ${gap.process_id} · ${gap.first_missing_sequence}–${gap.last_missing_sequence}`
          : gap.kind === 'creator_identity_incomplete' ? `Unknown creator identity · ${evidencePackageKeyText('artifact', gap.artifact_key)} · creator sequence ${gap.creator_event_id}`
            : `Missing retained reference · ${evidencePackageKeyText(gap.from_kind, gap.from_key)} → ${evidencePackageKeyText(gap.to_kind, gap.to_key)}`)));
  };
  const renderStatus = model => {
    const unavailable = evidencePackageUnavailable(protocol);
    const cancelOwnedFocus = document.activeElement === cancelButton;
    notice.textContent = unavailable || model.message || 'Select identities to export, or choose a file to validate locally.';
    notice.dataset.kind = model.status; cancelButton.hidden = model.status !== 'loading';
    exportButton.disabled = Boolean(unavailable) || model.status === 'loading' || (!selected.events.size && !selected.artifacts.size);
    validateButton.disabled = Boolean(unavailable) || model.status === 'loading' || !file.files?.length;
    file.disabled = Boolean(unavailable) || model.status === 'loading';
    downloadButton.disabled = !model.bytes || nativeShell;
    saveNote.textContent = nativeShell
      ? 'Download is unavailable in the native app. Copy validated metadata explicitly, or use the local browser development UI to download the original bytes. Clipboard availability depends on this web view.'
      : 'Download saves the exact validated bytes only when you click. Copy puts JSON text on the clipboard only when you click.';
    copyButton.disabled = !model.bytes || copying; renderReport(model);
    if (cancelOwnedFocus && model.status !== 'loading') (model.origin === 'file' ? validateButton : exportButton).focus({preventScroll: true});
  };
  const controller = createEvidencePackageController({getSelection, protocol, onChange: renderStatus});
  const renderSelection = () => {
    selectionSummary.textContent = `${selected.events.size} / 1,024 events · ${selected.artifacts.size} / 64 artifacts selected`;
    exportButton.disabled = Boolean(evidencePackageUnavailable(protocol)) || controller.model.status === 'loading' || (!selected.events.size && !selected.artifacts.size);
    // Keep every selected identity inspectable even when its original row leaves
    // the retained window or another candidate page/view is visible.
    const labels = ['events', 'artifacts'].flatMap(kind => [...selected[kind].values()].map(key => evidencePackageKeyText(kind.slice(0, -1), key)));
    const nextSignature = JSON.stringify(labels);
    if (selectionSignature !== nextSignature) {
      selectionSignature = nextSignature; selectionList.replaceChildren(paged('Selected identities', labels));
    }
  };
  const renderCandidates = () => {
    page = Math.min(page, Math.max(0, Math.ceil(rows.length / evidencePackagePageSize) - 1));
    const start = page * evidencePackagePageSize;
    const focused = candidates.contains(document.activeElement) ? document.activeElement.dataset.packageKey : null;
    const scrollTop = candidates.scrollTop;
    candidates.replaceChildren(...rows.slice(start, start + evidencePackagePageSize).map(row => {
      const label = node('label', '', 'package-candidate');
      const input = document.createElement('input'); input.type = 'checkbox'; input.checked = selected[row.kind].has(row.id); input.dataset.packageKey = row.id;
      input.addEventListener('change', () => {
        const map = selected[row.kind], maximum = row.kind === 'events' ? 1024 : 64;
        if (input.checked && map.size >= maximum) { input.checked = false; notice.textContent = `Selection limit reached: ${maximum} ${row.kind}.`; return; }
        controller.clear();
        if (input.checked) map.set(row.id, row.key); else map.delete(row.id);
        renderSelection();
      });
      label.append(input, node('span', row.label)); return label;
    }));
    if (focused) {
      const input = [...candidates.querySelectorAll('input')].find(value => value.dataset.packageKey === focused);
      (input ?? candidates).focus({preventScroll: true});
    }
    candidates.scrollTop = scrollTop;
    host.querySelector('[data-package-page]').textContent = rows.length ? `${start + 1}–${Math.min(start + evidencePackagePageSize, rows.length)} of ${rows.length}` : 'No selectable identities in this view';
    host.querySelector('[data-package-previous]').disabled = page === 0;
    host.querySelector('[data-package-next]').disabled = start + evidencePackagePageSize >= rows.length;
    renderSelection();
  };
  const sync = () => {
    const context = getContext();
    if (contextKey !== context.requestId) {
      contextKey = context.requestId; selected.events.clear(); selected.artifacts.clear(); page = 0; signature = null; controller.clear();
    }
    if (!visible) return;
    const source = scope.value === 'artifacts' ? context.artifacts.slice(0, 500)
      : scope.value === 'retained' ? context.events.slice(-5000) : (context.requestEvents ?? []).slice(-5000);
    const next = new Map();
    for (const value of source) {
      const kind = scope.value === 'artifacts' ? 'artifact' : 'event';
      if (kind === 'event' && (![2, 3].includes(value.protocol_version) || value.type === 'gap')) continue;
      const key = evidencePackageKey(kind, value); if (!key) continue;
      const id = `${kind}:${JSON.stringify(key)}`;
      next.set(id, {id, key, kind: `${kind}s`, label: `${evidencePackageKeyText(kind, key)} · ${kind === 'event' ? `${value.category}/${value.type}${value.type === 'api_call' ? ' · API marker seen; outcome unrecorded' : ''}` : `${value.kind} · ${value.byte_size} bytes`}`});
    }
    const newSignature = JSON.stringify([scope.value, [...next.values()].map(row => [row.id, row.label])]);
    if (signature !== newSignature) { signature = newSignature; rows = [...next.values()]; renderCandidates(); }
    host.querySelector('[data-package-context]').textContent = `${rows.length} selectable keys in this view. ${context.requestCorrelated && scope.value === 'request' ? 'Native association with the debugger request is correlated, not exact. ' : ''}${context.eventsLimited && scope.value !== 'artifacts' ? 'Latest 5,000-event window; older records may be absent.' : 'Retained window may be incomplete.'}`;
  };
  scope.addEventListener('change', () => { page = 0; signature = null; sync(); });
  host.querySelector('[data-package-previous]').addEventListener('click', () => { page -= 1; renderCandidates(); });
  host.querySelector('[data-package-next]').addEventListener('click', () => { page += 1; renderCandidates(); });
  host.querySelector('[data-package-clear]').addEventListener('click', () => { controller.clear(); selected.events.clear(); selected.artifacts.clear(); renderCandidates(); });
  const start = operation => {
    const pending = operation();
    if (controller.model.status === 'loading') cancelButton.focus({preventScroll: true});
    return pending;
  };
  exportButton.addEventListener('click', () => start(() => controller.export()));
  validateButton.addEventListener('click', () => start(() => controller.validate(file.files?.[0])));
  file.addEventListener('change', () => { controller.clear(); renderStatus(controller.model); });
  cancelButton.addEventListener('click', () => controller.cancel());
  downloadButton.addEventListener('click', () => {
    if (!controller.model.bytes || downloadButton.disabled) return;
    const url = URL.createObjectURL(new Blob([controller.model.bytes], {type: 'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = 'selected.reb-evidence.json'; link.hidden = true;
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    notice.textContent = 'Download requested for the exact validated metadata bytes. Check your browser downloads for completion.';
  });
  copyButton.addEventListener('click', async () => {
    const bytes = controller.model.bytes; if (!bytes || copying || copyButton.disabled) return;
    const revision = controller.model.revision, view = viewRevision;
    copying = true; copyButton.disabled = true;
    try {
      await navigator.clipboard.writeText(new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes));
      if (visible && view === viewRevision && revision === controller.model.revision) notice.textContent = 'Validated metadata copied to the clipboard.';
    } catch {
      if (visible && view === viewRevision && revision === controller.model.revision) notice.textContent = 'Clipboard access was unavailable. The validated package remains visible.';
    } finally { copying = false; copyButton.disabled = !controller.model.bytes; }
  });
  host.addEventListener('keydown', event => {
    if (event.key !== 'Escape' || controller.model.status !== 'loading') return;
    event.preventDefault(); event.stopPropagation(); controller.cancel(); (controller.model.origin === 'file' ? validateButton : exportButton).focus({preventScroll: true});
  });
  renderStatus(controller.model); renderSelection();
  return {sync, controller, setVisible(value) { if (visible !== value) viewRevision += 1; visible = value; if (!value) controller.cancel(); sync(); }};
}

// Investigation is a read-only projection of the already retained broker window.
// Keep it separate from package selection: highlighting a record never exports it.
const evidenceObservationLimit = 5000;
const evidenceObservationPage = 50;
const evidenceRelationshipGroups = [
  ['request', 'Request records', 'Native lifecycle records attached to this request'],
  ['parent', 'Recorded parent links', 'Explicit parent identifiers; no value-flow claim'],
  ['context', 'Same captured context', 'Correlation only; no recorded request link'],
  ['unlinked', 'Unlinked records', 'No demonstrated relationship to the selected request']
];
function evidenceEventKey(event) {
  const key = evidencePackageKey('event', event);
  return key ? `${key.session_id}:${key.process_id}:${key.sequence_number}` : null;
}
function evidenceDebuggerRequest(request) {
  return Boolean(request?.protocolRequestId || String(request?.operation).startsWith('cdp_'));
}
function evidenceRequestKey(request) {
  if (!request) return null;
  if (evidenceDebuggerRequest(request)) return JSON.stringify(['debugger', request.id, request.tabId, request.protocolRequestId, String(request.firstTimestamp)]);
  const events = request.events ?? [];
  const root = events.find(event => event.type === 'request_started') ?? events.find(event => event.type === 'request_initiated') ?? events[0];
  return JSON.stringify(['native', request.id, evidenceEventKey(root), root?.request_id ?? null]);
}
function evidenceArtifactReference(event, artifacts, index = null) {
  if (!event.artifact_id || event.artifact_id === '0') return {status: 'none', message: 'No artifact reference was recorded.'};
  const matches = index?.byKey.get(`${event.session_id}:${event.artifact_id}`) ?? (index ? [] : artifacts.filter(value => value.session_id === event.session_id && value.artifact_id === event.artifact_id));
  if (matches.length !== 1) return {status: matches.length ? 'ambiguous' : 'missing', message: matches.length ? 'More than one descriptor has this exact artifact identity.' : 'The referenced artifact is absent from the retained catalog.'};
  const stored = matches[0];
  // Source controllers attach cached text and analyses to descriptors. None of
  // those payloads belong in this metadata projection or its render signatures.
  const artifact = {session_id: stored.session_id, artifact_id: stored.artifact_id, sha256: stored.sha256, byte_size: stored.byte_size,
    kind: artifactKinds.has(stored.kind) ? stored.kind : 'unknown', url: typeof stored.url === 'string' ? stored.url.slice(0, 2048) : '',
    urlTruncated: typeof stored.url === 'string' && stored.url.length > 2048, capture_origin: artifactCaptureOrigins.has(stored.capture_origin) ? stored.capture_origin : 'unknown'};
  const key = evidencePackageKey('artifact', artifact);
  if (!key || !/^[0-9a-f]{64}$/.test(artifact.sha256) || !Number.isSafeInteger(artifact.byte_size) || artifact.byte_size < 0) return {status: 'unknown', message: 'The artifact hash or original byte size is unknown.'};
  const identity = {type: 'captured-artifact', session: key.session_id, artifact: key.artifact_id, sha256: artifact.sha256, bytes: artifact.byte_size};
  const ambiguous = (index?.idCounts.get(event.artifact_id) ?? artifacts.filter(value => value.artifact_id === event.artifact_id).length) !== 1;
  return {status: ambiguous ? 'ambiguous' : 'ready', artifact, identity,
    message: ambiguous ? 'The artifact ID is reused across retained sessions. Sources cannot select it unambiguously.' : 'Exact session and artifact reference. This does not establish which source produced the operation.'};
}
function evidencePayload(event) {
  try {
    const bytes = bytesFromHex(event.payload);
    const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
    return /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text) ? {text: event.payload, encoding: 'hex'} : {text, encoding: 'UTF-8'};
  } catch { return {text: event.payload ?? '', encoding: 'hex'}; }
}
function evidenceObservationLabel(event, payload) {
  const labels = {request_initiated: 'Request initiated', request_started: 'Request started', request_redirected: 'Request redirected', response_started: 'Response started', response_completed: 'Response completed', request_completed: 'Request completed', request_failed: 'Request failed', artifact_captured: 'Artifact retained', artifact_capture_failed: 'Artifact capture failed', module_compiled: 'Module compiled', module_instantiated: 'Module instantiated', vm_finding: 'VM finding recorded', property_read: 'Property read', api_call: 'API operation marker'};
  return ['api_call', 'property_read'].includes(event.type) && payload.encoding === 'UTF-8' && payload.text
    ? payload.text.slice(0, 160) : labels[event.type] ?? event.type.replaceAll('_', ' ');
}
function evidenceObservationOutcome(event) {
  if (event.type === 'api_call' || event.type === 'property_read') return 'Outcome not recorded';
  if (event.type === 'request_failed') return `Failure recorded · error ${event.error_code}`;
  if (event.type === 'request_completed' || event.type === 'response_completed') return `Completion record${event.status_code > 0 ? ` · HTTP ${event.status_code}` : ''}`;
  if (event.type === 'artifact_captured') return 'Receiver acknowledgment recorded';
  if (event.type === 'artifact_capture_failed') return 'Capture failure recorded';
  return 'This observation does not establish completion';
}
function evidenceMonotonicLabel(value) {
  const ns = BigInt(value);
  return `${ns / 1000000n}.${String(ns % 1000000n / 1000n).padStart(3, '0')} ms`;
}
function evidenceSequenceObservations(events) {
  const streams = new Map();
  let arrivalDiscontinuities = 0, outOfOrderArrivals = 0, holes = 0n;
  for (const event of events) {
    const key = `${event.session_id}:${event.process_id}`, sequence = BigInt(event.sequence_number);
    const stream = streams.get(key) ?? {ids: new Set(), high: null};
    if (stream.high !== null && sequence > stream.high + 1n) arrivalDiscontinuities += 1;
    if (stream.high !== null && sequence < stream.high) outOfOrderArrivals += 1;
    stream.high = stream.high === null || sequence > stream.high ? sequence : stream.high;
    stream.ids.add(sequence); streams.set(key, stream);
  }
  // Arrival order can be out of sequence. Only sorted unique retained identities
  // establish numeric holes, and even these are not proof of capture loss.
  for (const stream of streams.values()) {
    const ids = [...stream.ids].sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
    for (let index = 1; index < ids.length; index += 1) holes += ids[index] - ids[index - 1] - 1n;
  }
  return {holes: String(holes), arrivalDiscontinuities, outOfOrderArrivals};
}

function evidenceObservationModel(context) {
  const window = (context.events ?? []).slice(-evidenceObservationLimit);
  const artifacts = (context.artifacts ?? []).slice(0, 500);
  const artifactIndex = {byKey: new Map(), idCounts: new Map()}, artifactReferences = new Map();
  for (const artifact of artifacts) {
    const key = `${artifact.session_id}:${artifact.artifact_id}`;
    const matches = artifactIndex.byKey.get(key) ?? []; matches.push(artifact); artifactIndex.byKey.set(key, matches);
    artifactIndex.idCounts.set(artifact.artifact_id, (artifactIndex.idCounts.get(artifact.artifact_id) ?? 0) + 1);
  }
  const records = new Map(), duplicates = new Set();
  let omitted = 0, queueMarkers = 0;
  for (const event of window) {
    if (!isBrokerEvent(event) || ![2, 3].includes(event.protocol_version)) { omitted += 1; continue; }
    if (event.type === 'gap') { queueMarkers += 1; continue; }
    const key = evidenceEventKey(event);
    if (!key) { omitted += 1; continue; }
    if (records.has(key)) { duplicates.add(key); continue; }
    records.set(key, Object.fromEntries(['protocol_version', 'session_id', 'sequence_number', 'monotonic_time_ns', 'navigation_id', 'frame_id', 'artifact_id', 'parent_event_id', 'request_id', 'process_id', 'thread_id', 'browser_context_id_high', 'browser_context_id_low', 'tab_id', 'status_code', 'error_code', 'category', 'type', 'payload', 'payload_truncated'].filter(field => Object.hasOwn(event, field)).map(field => [field, event[field]])));
  }
  const request = context.request;
  const correlatedRequest = evidenceDebuggerRequest(request);
  const requestKeys = new Set((['live', 'demo'].includes(request?.origin) ? request.events ?? [] : []).slice(-5000).filter(event => event.category === 'network' && networkLifecycleTypes.has(event.type)).map(evidenceEventKey).filter(Boolean));
  const retainedRequest = new Set([...requestKeys].filter(key => records.has(key) && !duplicates.has(key)));
  const parents = new Set(), missing = new Set();
  let parentLimit = false, parentCycle = false;
  // Only inspect ancestors of attached native request records. The selected
  // debugger request association remains correlated for every such ancestor.
  for (const start of retainedRequest) {
    let key = start; const seen = new Set([key]);
    for (let depth = 0; depth < 32; depth += 1) {
      const event = records.get(key);
      if (!event?.parent_event_id || event.parent_event_id === '0') break;
      const parent = `${event.session_id}:${event.process_id}:${event.parent_event_id}`;
      if (seen.has(parent)) { parentCycle = true; break; }
      if (!records.has(parent) || duplicates.has(parent)) { missing.add(parent); break; }
      seen.add(parent); parents.add(parent); key = parent;
      if (depth === 31 && records.get(key).parent_event_id !== '0') parentLimit = true;
    }
  }
  const contexts = new Set([...retainedRequest].map(key => records.get(key)).filter(event => event.navigation_id !== '0' && event.frame_id !== '0')
    .map(event => `${event.session_id}:${event.process_id}:${event.navigation_id}:${event.frame_id}`));
  const rows = [...records].map(([key, event]) => {
    const group = duplicates.has(key) ? 'unlinked' : retainedRequest.has(key) ? 'request' : parents.has(key) ? 'parent'
      : event.navigation_id !== '0' && event.frame_id !== '0' && contexts.has(`${event.session_id}:${event.process_id}:${event.navigation_id}:${event.frame_id}`) ? 'context' : 'unlinked';
    const artifactKey = `${event.session_id}:${event.artifact_id}`;
    if (!artifactReferences.has(artifactKey)) artifactReferences.set(artifactKey, evidenceArtifactReference(event, artifacts, artifactIndex));
    const payload = evidencePayload(event), artifact = artifactReferences.get(artifactKey);
    return {key, event, group, payload, artifact, duplicate: duplicates.has(key), title: evidenceObservationLabel(event, payload), outcome: evidenceObservationOutcome(event)};
  });
  const related = rows.filter(row => row.group !== 'unlinked');
  return {request: request ? {id: request.id, origin: request.origin, method: request.method, path: String(request.path ?? '').slice(0, 2048), hostOnly: request.hostOnly} : null,
    requestKey: evidenceRequestKey(request), correlatedRequest, rows, related, omitted, queueMarkers,
    missingParents: missing.size, unavailableRequest: requestKeys.size - retainedRequest.size,
    duplicates: duplicates.size, parentLimit, parentCycle, limited: Boolean(context.eventsLimited || (context.events?.length ?? 0) > 5000),
    sequence: evidenceSequenceObservations([...records.values()]),
    linkedArtifacts: new Set(related.filter(row => row.artifact.status === 'ready').map(row => JSON.stringify(row.artifact.identity))).size};
}

function createEvidenceWorkspace({getContext, packagePanel, onTrace, onRequest, onSource, canOpenSource}) {
  const find = id => document.querySelector(`#${id}`);
  const host = find('evidence-investigation'), list = find('evidence-rows'), inspector = find('evidence-inspector');
  const search = find('evidence-search'), scope = find('evidence-scope'), notice = find('evidence-workspace-notice');
  const layout = host.querySelector('.evidence-investigation-layout');
  const toggle = find('evidence-package-toggle'), packageHost = find('evidence-package-mode');
  const paneTabs = [...host.querySelectorAll('button[data-evidence-pane]')];
  let visible = false, packages = false, requestKey = undefined, selectedKey = null, page = 0, model = null;
  let listSignature = '', detailSignature = '', filtered = [], pane = 'observations';
  let selectionNotice = '', refreshNotice = '', outsideFilterNotice = false;
  const coverageDetails = find('evidence-coverage-details');
  const node = (tag, text = '', className = '') => {const result = document.createElement(tag); result.textContent = String(text); result.className = className; return result;};
  const button = (label, action, key) => {const result = node('button', label, 'secondary-button'); result.type = 'button'; if (key) result.dataset.evidenceAction = key; result.addEventListener('click', action); return result;};
  const renderNotice = () => {notice.textContent = [refreshNotice, selectionNotice].filter(Boolean).join(' '); notice.hidden = !notice.textContent;};
  const message = (text, outside = false) => {selectionNotice = text; outsideFilterNotice = outside; renderNotice();};
  const facts = entries => {const dl = node('dl', '', 'evidence-record-facts'); for (const [label, value] of entries) dl.append(node('dt', label), node('dd', value)); return dl;};
  const setPane = (value, focus = false) => {
    pane = value; layout.dataset.evidencePane = value;
    for (const tab of paneTabs) {const active = tab.dataset.evidencePane === value; tab.setAttribute('aria-selected', String(active)); tab.tabIndex = active ? 0 : -1;}
    if (focus) (value === 'detail' ? inspector : list.querySelector('[aria-current="true"]') ?? list).focus({preventScroll: true});
  };
  const relation = row => row.duplicate ? 'Ambiguous identity' : row.group === 'request' ? model.correlatedRequest ? 'Associated native record · request correlation only' : 'Native request record'
    : row.group === 'parent' ? model.correlatedRequest ? 'Recorded parent · request association correlated' : 'Recorded parent relationship'
      : row.group === 'context' ? 'Same context · correlation only' : 'No recorded request relationship';
  function renderDetail() {
    const row = model.rows.find(candidate => candidate.key === selectedKey);
    const signature = JSON.stringify([row, model.requestKey, model.correlatedRequest, canOpenSource()]);
    if (signature === detailSignature) return;
    detailSignature = signature;
    const sameRecord = inspector.dataset.evidenceKey === row?.key;
    const open = sameRecord && inspector.querySelector('details')?.open;
    const focused = inspector.contains(document.activeElement) ? document.activeElement.dataset.evidenceAction : null;
    const top = sameRecord ? inspector.scrollTop : 0;
    inspector.dataset.evidenceKey = row?.key ?? '';
    if (!row) {
      inspector.replaceChildren(node('div', 'Select a recorded observation', 'evidence-detail-empty'), node('p', 'Inspect its operation, captured payload, request relationship and exact artifact reference here.', 'evidence-detail-hint'));
      return;
    }
    const event = row.event;
    const head = node('div', '', 'evidence-detail-head');
    head.append(node('div', `${event.category.replaceAll('_', ' ')} · ${event.type.replaceAll('_', ' ')}`, 'evidence-eyebrow'), node('h2', row.title), node('p', relation(row), `evidence-relation evidence-relation-${row.group}`));
    const observation = node('section', '', 'evidence-detail-section');
    observation.append(node('h3', 'What was recorded'));
    const marker = ['api_call', 'property_read'].includes(event.type);
    observation.append(node('div', row.payload.text || 'No inline payload was recorded.', 'evidence-value'));
    observation.append(node('p', marker ? 'An operation marker was seen. Arguments, returned values, exceptions and Promise settlement are not recorded by this marker.'
      : `Bounded ${row.payload.encoding} payload${event.payload_truncated ? ' · truncated at capture' : ''}. This is retained evidence, not reconstructed content.`, 'evidence-detail-hint'));
    if (marker && event.payload_truncated) observation.append(node('p', 'The operation payload was truncated at capture.', 'evidence-detail-hint'));
    observation.append(facts([['Outcome', row.outcome], ['Recorded time', `${evidenceMonotonicLabel(event.monotonic_time_ns)} · monotonic`], ['Observer / placement', 'Unknown']]));
    const source = node('section', '', 'evidence-detail-section'); source.append(node('h3', 'Referenced artifact'));
    if (row.artifact.artifact) {
      const artifact = row.artifact.artifact, card = node('div', '', 'evidence-artifact-card');
      card.append(node('span', artifact.kind.replaceAll('_', ' '), 'evidence-eyebrow'), node('strong', artifact.url || 'Captured artifact'), node('p', `${artifact.byte_size.toLocaleString()} original bytes · ${artifact.capture_origin?.replaceAll('_', ' ') || 'capture origin unknown'}`));
      const sourceButton = button('Open captured source ↗', () => {
        const current = evidenceObservationModel(getContext()).rows.find(candidate => candidate.key === selectedKey);
        if (!current || current.key !== row.key || current.duplicate || current.artifact.status !== 'ready' || JSON.stringify(current.artifact.identity) !== JSON.stringify(row.artifact.identity)) {message('The selected event or its exact artifact is no longer unambiguous. No source was opened.'); sync(); return;}
        if (!onSource(current.artifact.identity)) message('The exact source could not be opened. No other artifact or URL was substituted.');
      }, 'source');
      sourceButton.id = 'evidence-open-source';
      const supported = ['javascript', 'wasm', 'source_map', 'response_body'].includes(artifact.kind);
      sourceButton.disabled = row.artifact.status !== 'ready' || row.duplicate || !supported || !canOpenSource();
      card.append(sourceButton); source.append(card);
      if (artifact.urlTruncated) source.append(node('p', 'Artifact URL display is limited to 2,048 characters. Navigation uses exact identity, never this text.', 'evidence-detail-hint'));
      if (!supported) source.append(node('p', 'This artifact kind has no Sources view.', 'evidence-detail-hint'));
      else if (!canOpenSource()) source.append(node('p', 'Safe source navigation is unavailable in this build. The exact reference is preserved below.', 'evidence-detail-hint'));
    }
    source.append(node('p', row.artifact.message, 'evidence-detail-hint'));
    const connection = node('section', '', 'evidence-detail-section'); connection.append(node('h3', 'Relationship to this request'));
    connection.append(node('p', row.group === 'parent' ? 'A retained record names this event as a parent. That records a link between native observations; it does not establish how a value was computed.'
      : row.group === 'request' ? model.correlatedRequest ? 'These native records were associated by method, host and time. There is no producer-provided key proving that they belong to the selected debugger request.' : 'This event is part of the selected native request’s recorded lifecycle.'
        : row.group === 'context' ? 'Session, renderer process, navigation and frame match. No parent or request link was recorded for this observation.' : 'No link to the selected request is established in this retained window.', 'evidence-detail-hint'));
    if (model.correlatedRequest && row.group === 'parent') connection.append(node('p', 'The selected debugger request is only correlated with the native records. Its association does not become exact through a native parent link.', 'evidence-detail-hint'));
    const actions = node('div', '', 'evidence-record-actions');
    if (model.request) actions.append(button('View request', onRequest, 'request'));
    const parentKey = event.parent_event_id !== '0' ? `${event.session_id}:${event.process_id}:${event.parent_event_id}` : null;
    if (parentKey) {
      const parent = model.rows.find(candidate => candidate.key === parentKey && !candidate.duplicate);
      if (parent) actions.append(button('Inspect recorded parent', () => select(parent.key, true, 'parent'), 'parent'));
      else connection.append(node('p', 'The recorded parent is absent or ambiguous in this retained window.', 'evidence-detail-hint'));
    }
    connection.append(actions);
    const provenance = node('details', '', 'evidence-provenance'); provenance.open = Boolean(open);
    const summary = node('summary', 'Provenance & exact identifiers'); summary.dataset.evidenceAction = 'provenance'; provenance.append(summary);
    provenance.append(facts([['Native event', evidencePackageKeyText('event', evidencePackageKey('event', event))], ['Protocol', event.protocol_version], ['Monotonic time', `${event.monotonic_time_ns} ns`], ['Parent event', event.parent_event_id === '0' ? 'Not recorded' : event.parent_event_id], ['Request', event.request_id === '0' ? 'Not recorded' : event.request_id], ['Navigation / frame', `${event.navigation_id} / ${event.frame_id} (zero means unknown)`], ['Thread', event.thread_id], ['Tab', event.tab_id || 'Unknown'], ['Browser context', browserContextToken(event) || 'Unknown'], ['Artifact', event.artifact_id === '0' ? 'Not recorded' : `${event.session_id} / ${event.artifact_id}`], ['Artifact SHA-256', row.artifact.artifact?.sha256 || 'Unknown'], ['Producer / historical build', 'Unknown']]));
    inspector.replaceChildren(head, observation, source, connection, provenance);
    if (focused) (inspector.querySelector(`[data-evidence-action="${focused}"]`) ?? inspector).focus({preventScroll: true});
    inspector.scrollTop = top;
  }
  function select(key, focus = false, kind = 'observation') {
    if (!model.rows.some(row => row.key === key)) return;
    selectedKey = key;
    const index = filtered.findIndex(row => row.key === key);
    if (index >= 0) page = Math.floor(index / evidenceObservationPage);
    message(index < 0 ? `The selected ${kind} is outside the current filter. Its details remain visible; your filter is unchanged.` : '', index < 0);
    listSignature = ''; renderList(); renderDetail();
    if (focus) {
      const narrowDetail = window.matchMedia('(max-width: 760px)').matches && pane === 'detail';
      const row = !narrowDetail && [...list.querySelectorAll('[data-evidence-key]')].find(candidate => candidate.dataset.evidenceKey === key);
      (row || inspector).focus({preventScroll: true});
      if (row) row.scrollIntoView({block: 'nearest'});
    }
  }
  function renderList() {
    page = Math.min(page, Math.max(0, Math.ceil(filtered.length / evidenceObservationPage) - 1));
    const start = page * evidenceObservationPage, rows = filtered.slice(start, start + evidenceObservationPage);
    const signature = JSON.stringify([rows, selectedKey, page, model.correlatedRequest]);
    if (signature !== listSignature) {
      listSignature = signature;
      const focused = list.contains(document.activeElement) ? document.activeElement.dataset.evidenceKey : null;
      const top = list.scrollTop, nodes = [];
      for (const [group, name, description] of evidenceRelationshipGroups) {
        const members = rows.filter(row => row.group === group); if (!members.length) continue;
        const section = node('section', '', 'evidence-observation-group');
        const title = group === 'request' && model.correlatedRequest ? 'Associated native records' : group === 'parent' && model.correlatedRequest ? 'Parents of associated records' : name;
        const heading = node('h3', `${title} · ${filtered.filter(row => row.group === group).length}`);
        section.append(heading, node('p', group === 'request' && model.correlatedRequest ? 'Debugger request association is correlated, not exact' : description, 'evidence-group-note'));
        for (const row of members) {
          const element = node('button', '', 'evidence-observation'); element.type = 'button'; element.dataset.evidenceKey = row.key; element.dataset.relationship = row.group;
          element.setAttribute('aria-current', String(row.key === selectedKey));
          const line = node('span', '', 'evidence-observation-meta'); line.append(node('span', row.event.category.replaceAll('_', ' ')), node('time', evidenceMonotonicLabel(row.event.monotonic_time_ns)));
          element.append(line, node('strong', row.title), node('span', row.duplicate ? 'Duplicate event identity · relationship unknown' : row.artifact.artifact?.url || (row.payload.text === row.title ? row.outcome : row.payload.text) || row.outcome, 'evidence-observation-preview'));
          element.addEventListener('click', () => {select(row.key); if (window.matchMedia('(max-width: 760px)').matches) setPane('detail', true);});
          element.addEventListener('keydown', event => {
            if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault(); const index = filtered.findIndex(candidate => candidate.key === row.key);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? filtered.length - 1 : Math.max(0, Math.min(filtered.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
            select(filtered[next].key, true);
          });
          section.append(element);
        }
        nodes.push(section);
      }
      if (!nodes.length) nodes.push(node('div', search.value ? 'No retained observations match this filter.' : model.rows.length ? 'No linked observations are retained for this request. Choose Retained window to inspect unlinked records.' : 'No native observations are retained in this window.', 'evidence-list-empty'));
      list.replaceChildren(...nodes);
      if (focused) ([...list.querySelectorAll('[data-evidence-key]')].find(candidate => candidate.dataset.evidenceKey === focused) ?? list).focus({preventScroll: true});
      list.scrollTop = top;
    }
    find('evidence-window-count').textContent = filtered.length ? `${start + 1}–${Math.min(start + evidenceObservationPage, filtered.length)} of ${filtered.length}` : '0 records';
    find('evidence-previous').disabled = page === 0; find('evidence-next').disabled = start + evidenceObservationPage >= filtered.length;
  }
  function rebuild() {
    const needle = search.value.trim().toLowerCase().slice(0, 256);
    filtered = evidenceRelationshipGroups.flatMap(([group]) => model.rows.filter(row => row.group === group && (scope.value === 'all' || !model.request || group !== 'unlinked') && (!needle || `${row.title}\n${row.payload.text}\n${row.artifact.artifact?.url ?? ''}\n${row.event.category}`.toLowerCase().includes(needle))));
    if (outsideFilterNotice && selectedKey && filtered.some(row => row.key === selectedKey)) message('');
  }
  function sync() {
    packagePanel.sync();
    if (!visible) return;
    const context = getContext(); model = evidenceObservationModel(context);
    if (requestKey !== model.requestKey) {
      const changed = requestKey !== undefined;
      requestKey = model.requestKey; selectedKey = null; page = 0; listSignature = ''; detailSignature = ''; search.value = ''; scope.value = model.request ? 'related' : 'all';
      setPane('observations'); if (changed) message(model.request ? 'Request context changed. Observation selection was reset.' : 'The selected request is no longer retained. Showing the retained window.');
    }
    if (selectedKey && !model.rows.some(row => row.key === selectedKey)) {selectedKey = null; message('The selected observation left the retained window. No neighboring record was substituted.');}
    if (!selectedKey && !detailSignature) selectedKey = model.related[0]?.key ?? model.rows[0]?.key ?? null;
    find('evidence-context-kind').textContent = model.request ? model.correlatedRequest ? 'Debugger request · correlated native context' : model.related.length ? model.request.origin === 'demo' ? 'Demo native request' : 'Selected native request' : 'Selected request · native identity unavailable' : 'Retained evidence window';
    find('evidence-context-title').textContent = model.request ? `${model.request.method} ${model.request.path}` : 'Explore recorded observations';
    find('evidence-context-title').title = find('evidence-context-title').textContent;
    find('evidence-context-note').textContent = model.request ? model.correlatedRequest ? 'Native records are matched by method, host and time. No exact producer request key connects them.' : `${model.request.hostOnly ? 'Host-only metadata · ' : ''}${model.related.length} related observations · ${model.linkedArtifacts} exact artifact references` : 'Choose a request in Traffic to separate recorded links from context-only correlations.';
    find('evidence-count').textContent = `${model.rows.length} retained observations`;
    find('evidence-coverage-summary').textContent = `${model.missingParents} missing parent references · coverage unknown`;
    find('evidence-gap-details').textContent = `${model.limited ? 'Latest 5,000-record window; earlier records may be evicted. ' : 'Retained window only; complete capture is not established. '}${model.queueMarkers} native queue-drop markers; ${model.sequence.holes} absent sequence IDs between retained stream endpoints (not proof of capture loss); ${model.sequence.arrivalDiscontinuities} forward-jump observations in arrival order; ${model.sequence.outOfOrderArrivals} later arrivals below a prior high-water ID; ${model.missingParents} missing or ambiguous parent references; ${model.unavailableRequest} attached request records outside this window; ${model.duplicates} duplicate identities; ${model.omitted} unsupported or unaddressable records omitted.${model.parentLimit ? ' Parent lookup stopped at its 32-link bound.' : ''}${model.parentCycle ? ' A repeated parent identity stopped lookup.' : ''} Queue markers, sequence holes and missing references can overlap and are not added into a loss total.`;
    find('evidence-trace').disabled = model.request?.origin !== 'live' || model.correlatedRequest || !model.related.length;
    find('evidence-trace').title = model.correlatedRequest ? 'A correlated debugger request has no exact native trace root.' : 'Inspect the selected request’s recorded predecessor chain.';
    refreshNotice = context.error ? `Evidence refresh ${context.error === 'malformed' ? 'returned malformed records' : 'is unavailable'}. Retained observations remain visible.` : '';
    renderNotice();
    rebuild(); renderList(); renderDetail();
  }
  function showPackages(value, focus = true) {
    packages = value; host.hidden = value; packageHost.hidden = !value; toggle.setAttribute('aria-expanded', String(value));
    packagePanel.setVisible(visible && value);
    if (focus) (value ? find('evidence-return') : toggle).focus({preventScroll: true});
    if (!value) sync();
  }
  coverageDetails.addEventListener('keydown', event => {
    if (event.key !== 'Escape' || !coverageDetails.open) return;
    event.preventDefault(); event.stopPropagation(); coverageDetails.open = false; coverageDetails.querySelector('summary').focus({preventScroll: true});
  });
  host.addEventListener('pointerdown', event => {if (coverageDetails.open && !coverageDetails.contains(event.target)) coverageDetails.open = false;});
  toggle.addEventListener('click', () => showPackages(!packages));
  find('evidence-return').addEventListener('click', () => showPackages(false));
  find('evidence-trace').addEventListener('click', onTrace);
  for (const tab of paneTabs) {
    tab.addEventListener('click', () => setPane(tab.dataset.evidencePane));
    tab.addEventListener('keydown', event => {if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return; event.preventDefault(); const value = event.key === 'Home' ? 'observations' : event.key === 'End' ? 'detail' : pane === 'detail' ? 'observations' : 'detail'; setPane(value); paneTabs.find(candidate => candidate.dataset.evidencePane === value).focus();});
  }
  search.maxLength = 256;
  search.addEventListener('input', () => {page = 0; rebuild(); renderList();});
  scope.addEventListener('change', () => {page = 0; rebuild(); renderList();});
  find('evidence-previous').addEventListener('click', () => {page -= 1; renderList(); list.scrollTop = 0;});
  find('evidence-next').addEventListener('click', () => {page += 1; renderList(); list.scrollTop = 0;});
  return {sync, setVisible(value) {visible = value; packagePanel.setVisible(value && packages); sync();}, showPackages,
    // Bounded view state only. Shared navigation may restore this without
    // retaining payloads, source text, reports or package bytes in history.
    snapshot: () => ({requestKey, selectedKey, page, pane, packages}),
    canRestore(value, request = getContext().request) {const current = evidenceObservationModel({...getContext(), request}); return Boolean(value && value.requestKey === current.requestKey && (!value.selectedKey || current.rows.some(row => row.key === value.selectedKey && !row.duplicate)));},
    restore(value) {
      if (!this.canRestore(value)) return false;
      // Shared return may run while hidden. Adopt the verified context before
      // ordinary visibility reconciliation, preserving the current filter draft.
      model = evidenceObservationModel(getContext()); requestKey = model.requestKey;
      selectedKey = value.selectedKey; page = Number.isSafeInteger(value.page) ? Math.max(0, Math.min(99, value.page)) : 0;
      listSignature = ''; rebuild();
      detailSignature = 'restoring'; setPane(value.pane === 'detail' ? 'detail' : 'observations'); showPackages(Boolean(value.packages), false); sync();
      const outside = Boolean(selectedKey && !filtered.some(row => row.key === selectedKey));
      message(outside ? 'The restored observation is outside the current filter. Its details remain visible.' : '', outside);
      return true;
    }};
}
