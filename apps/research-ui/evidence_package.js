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
    host.querySelector('[data-package-context]').textContent = `${rows.length} selectable keys in this view. ${context.eventsLimited && scope.value !== 'artifacts' ? 'Latest 5,000-event window; older records may be absent.' : 'Retained window may be incomplete.'}`;
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
