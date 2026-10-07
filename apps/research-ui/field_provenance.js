/* Field provenance is an evidence projection. Equal text never establishes value flow. */
let fieldProvenanceSelection = null;
let decoderFieldOrigin = null;
const provenanceUI = Object.fromEntries(['target', 'notice', 'value', 'back', 'search', 'decode', 'original', 'derived', 'derived-value', 'derived-steps', 'test', 'candidates', 'replay', 'gaps']
  .map(name => [name, document.querySelector(`#field-provenance-${name}`)]));

function provenanceButton(label, action) {
  const button = trafficNode('button', 'secondary-button', label); button.type = 'button';
  button.addEventListener('click', action); return button;
}

function provenanceRequestURL(request) {
  try {
    const url = new URL(request.path);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    url.search = ''; url.hash = ''; return url.href;
  } catch { return null; }
}

function openFieldProvenance(selection) {
  const {request, value, selector, kind} = selection;
  if (!request || request.urlTruncated || typeof value !== 'string' || !['json', 'query'].includes(kind) ||
      !selector || new TextEncoder().encode(value).length > 4096 || new TextEncoder().encode(selector).length > 256) return;
  fieldProvenanceSelection = {...selection, url: provenanceRequestURL(request), candidates: [],
    searched: false, searching: false, gaps: [], error: null, replayKey: null};
  showScreen('field-provenance'); renderFieldProvenance();
  requestAnimationFrame(() => provenanceUI.search.focus({preventScroll: true}));
}

function clearDecoderFieldOrigin() {
  decoderFieldOrigin = null;
}

function provenanceDecoderBytes(value) {
  const bytes = new TextEncoder().encode(value);
  // TextEncoder replaces unpaired UTF-16 surrogates. Such a string cannot
  // become an exact UTF-8 chain root; preserve it as captured evidence instead.
  return new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes) === value ? bytes : null;
}

function decodeProvenanceValue() {
  const selection = fieldProvenanceSelection;
  if (!selection || state.decoderPending) return;
  const bytes = provenanceDecoderBytes(selection.value);
  if (!bytes) {
    selection.error = 'This string cannot be represented as UTF-8 without changing it.';
    renderFieldProvenance(); return;
  }
  resetDecoderChain('Original request string copied. Choose each transformation explicitly.');
  toolsElements.inputEncoding.value = 'text';
  toolsElements.input.value = selection.value;
  // Textareas normalize line endings. Preserve the captured bytes as the chain
  // root, and use the displayed input key only to detect subsequent edits.
  state.decoderInputSnapshot = {key: decoderCurrentInputKey(), base64: decoderBytesToBase64(bytes), bytes: bytes.length};
  decoderFieldOrigin = {selection, key: decoderCurrentInputKey()};
  showScreen('tools'); setToolsTab('decoder');
  requestAnimationFrame(() => toolsElements.operation.focus({preventScroll: true}));
}

function decodedFieldCandidate() {
  if (!decoderFieldOrigin) return {error: 'Start from a request string in Field trace.'};
  if (decoderFieldOrigin.selection !== fieldProvenanceSelection) return {error: 'The selected request field changed. Start again from Field trace.'};
  if (decoderFieldOrigin.key !== decoderCurrentInputKey()) return {error: 'Input changed. Start again from Field trace to preserve its original bytes.'};
  if (state.decoderPending) return {error: 'Wait for the current transformation.'};
  const index = state.decoderSteps.findIndex(step => step.id === state.decoderSelectedStepId);
  if (index < 0) return {error: 'Select a completed transformation to search its result.'};
  const step = state.decoderSteps[index];
  if (step.output_bytes === 0 || step.output_bytes > 4096) return {error: 'Source search requires a nonempty result of at most 4 KiB.'};
  const bytes = decoderBase64ToBytes(step.output_base64);
  let value;
  try { value = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes); }
  catch { return {error: 'Binary results cannot be searched as source text. Choose another step.'}; }
  return {value, steps: state.decoderSteps.slice(0, index + 1).map(item => ({
    operation: item.operation, input_bytes: item.input_bytes, output_bytes: item.output_bytes
  }))};
}

function renderDecoderFieldOrigin() {
  toolsElements.fieldOrigin.hidden = !decoderFieldOrigin;
  if (!decoderFieldOrigin) return;
  const {selection} = decoderFieldOrigin;
  toolsElements.fieldOriginLabel.textContent = `Request field: ${selection.request.method} ${selection.url || 'captured request'} · ${selection.selector}`;
  const candidate = decodedFieldCandidate();
  toolsElements.findSources.disabled = Boolean(candidate.error);
  toolsElements.fieldOriginNotice.textContent = candidate.error || 'Search the complete UTF-8 result. Matches are candidates, not proof of page transformations.';
}

function searchDecodedFieldSources() {
  const candidate = decodedFieldCandidate();
  if (candidate.error) return;
  // Replace the projection so an older asynchronous search cannot attach its
  // results to a different needle. Captured value and replay selector stay intact.
  fieldProvenanceSelection = {...fieldProvenanceSelection, derivedSearch: candidate,
    candidates: [], searched: false, searching: false, gaps: [], error: null};
  decoderFieldOrigin.selection = fieldProvenanceSelection;
  showScreen('field-provenance'); renderFieldProvenance();
  requestAnimationFrame(() => provenanceUI.search.focus({preventScroll: true}));
  searchFieldSources();
}

function revealProvenanceSite(site) {
  const source = liveSources().find(source => source.script_id === site.script_id && source.target_id === site.target_id && site.source_hash && source.hash === site.source_hash);
  if (!source) {
    fieldProvenanceSelection.error = 'Source detached. Evidence retained.';
    renderFieldProvenance(); return;
  }
  if (selectScript(source.script_id, site.line) === false || !setSourceCursor(source, site.line, site.column)) {
    fieldProvenanceSelection.error = 'The exact source location is unavailable or ambiguous. Evidence retained.';
    renderFieldProvenance(); return;
  }
  showScreen('sources');
  elements.sourcePosition.textContent = `Line ${site.line + 1}, Column ${site.column + 1}`;
}

function provenanceSourceURL(address) {
  try {
    const url = new URL(address);
    if (!['http:', 'https:'].includes(url.protocol)) return '';
    url.username = ''; url.password = ''; url.search = ''; url.hash = '';
    return url.href.slice(0, 8192);
  } catch { return ''; }
}

// Literal text search is deterministic and inert, with UTF-16 positions matching CDP.
function fieldSourceMatches(content, needle, source, limit = 32) {
  if (!needle) return [];
  const matches = [];
  let offset = 0, scanned = 0, line = source.start_line ?? 0, column = source.start_column ?? 0;
  while (matches.length < limit && (offset = content.indexOf(needle, offset)) !== -1) {
    for (; scanned < offset; scanned += 1) {
      if (content[scanned] === '\n') { line += 1; column = 0; } else column += 1;
    }
    matches.push({script_id: source.script_id, target_id: source.target_id, source: provenanceSourceURL(source.url), source_hash: source.hash,
      function: 'Text match', line, column});
    offset += needle.length;
  }
  return matches;
}

async function searchFieldSources() {
  const selection = fieldProvenanceSelection;
  if (!selection || selection.searching) return;
  const needle = selection.derivedSearch?.value ?? selection.value;
  selection.searching = true; selection.error = null; renderFieldProvenance();
  const preferred = new Set((selection.request.initiator?.sites ?? []).map(site => site.script_id));
  const sources = liveSources().filter(source => source.target_id === selection.request.tabId && source.kind === 'javascript')
    .sort((a, b) => Number(preferred.has(b.script_id)) - Number(preferred.has(a.script_id)));
  const candidates = [], gaps = [];
  if (sources.length > 8) gaps.push('8-script limit.');
  if (!sources.length) gaps.push('Sources detached.');
  let bytes = 0;
  try {
    for (const source of sources.slice(0, 8)) {
      if (fieldProvenanceSelection !== selection) return;
      if (bytes + source.length > 2 * 1024 * 1024) { gaps.push('2 MiB search limit.'); break; }
      await loadScriptContent(source);
      if (fieldProvenanceSelection !== selection) return;
      const loaded = state.liveScriptContent.get(source.script_id);
      if (loaded?.identity !== liveScriptIdentity(source)) { gaps.push('Sources changed. Retry.'); continue; }
      if (loaded?.loadError) { gaps.push(loaded.loadError); continue; }
      if (typeof loaded?.content !== 'string') { gaps.push('Source unavailable. Retry.'); continue; }
      // The source viewer may append a truncation notice. That presentation
      // text must never be mistaken for captured JavaScript in a source search.
      const content = loaded.content.slice(0, loaded.sourceTextLength);
      bytes += new TextEncoder().encode(content).length;
      if (bytes > 2 * 1024 * 1024) { gaps.push('2 MiB search limit.'); break; }
      if (loaded.contentTruncated) gaps.push('Partial source.');
      const matches = fieldSourceMatches(content, needle, source, 33 - candidates.length);
      candidates.push(...matches);
      if (candidates.length > 32) { candidates.length = 32; gaps.push('32-match limit.'); break; }
    }
    // Recheck identity after asynchronous source reads. Navigation can reuse script IDs.
    const current = liveSources();
    const valid = site => current.some(source => source.script_id === site.script_id &&
      source.target_id === site.target_id && site.source_hash === source.hash);
    const refreshed = candidates.filter(valid);
    if (refreshed.length !== candidates.length) gaps.push('Sources changed. Retry.');
    selection.candidates = !refreshed.length && gaps.length ? selection.candidates.filter(valid) : refreshed;
    if (gaps.length) selection.error = 'Search incomplete. See Coverage.';
    selection.gaps = [...new Set(gaps)]; selection.searched = true; selection.scanned = Math.min(sources.length, 8);
  } catch (error) { selection.error = error.message; }
  finally { selection.searching = false; if (fieldProvenanceSelection === selection) renderFieldProvenance(); }
}

function renderFieldProvenance() {
  const selection = fieldProvenanceSelection;
  if (!selection || document.querySelector('#screen-field-provenance').hidden) return;
  const hooks = runtimeHooksState(), test = hooks?.field_test;
  provenanceUI.target.textContent = `${selection.request.method} ${selection.url || selection.request.path} · ${selection.selector}`;
  provenanceUI.value.textContent = `${selection.value.slice(0, 256)}${selection.value.length > 256 ? '…' : ''}`;
  provenanceUI.value.title = selection.value.length > 256 ? 'Value preview' : '';
  provenanceUI.derived.hidden = !selection.derivedSearch;
  provenanceUI.original.hidden = !selection.derivedSearch;
  provenanceUI.search.textContent = selection.derivedSearch ? 'Find decoded sources' : 'Find sources';
  const exactDecoderInput = provenanceDecoderBytes(selection.value) !== null;
  provenanceUI.decode.disabled = state.decoderPending || !exactDecoderInput;
  provenanceUI.decode.title = exactDecoderInput ? 'Start a decoder chain from the original request string.'
    : 'This string cannot be represented as UTF-8 without changing it.';
  if (selection.derivedSearch) {
    provenanceUI['derived-value'].textContent = selection.derivedSearch.value;
    provenanceUI['derived-steps'].textContent = selection.derivedSearch.steps.map((step, index) =>
      `${index + 1}. ${step.operation.replaceAll('-', ' ')} · ${step.input_bytes} B → ${step.output_bytes} B`).join('\n');
  }
  provenanceUI.notice.textContent = selection.error || (selection.searching ? 'Searching…' :
    selection.searched ? `${selection.candidates.length} ${selection.candidates.length === 1 ? 'match' : 'matches'}` : '');
  provenanceUI.search.disabled = selection.searching;
  provenanceUI.test.disabled = !selection.url || !['running', 'paused'].includes(state.debuggerSession?.state) || state.debuggerActionPending;
  const sites = isFieldCallSites(selection.request.initiator) ? selection.request.initiator.sites : [];
  const rows = sites.map(site => provenanceSiteRow(site, 'Observed'));
  rows.push(...selection.candidates.map(site => provenanceSiteRow(site, selection.derivedSearch ? 'Decoded candidate' : 'Correlated')));
  const sourceCatalog = liveSources().map(source => [source.script_id, source.target_id, source.hash]);
  const candidatesKey = JSON.stringify([sites, selection.candidates, selection.searched, sourceCatalog]);
  if (selection.candidatesKey !== candidatesKey) {
    selection.candidatesKey = candidatesKey;
    preserveProvenanceFocus(provenanceUI.candidates, () => provenanceUI.candidates.replaceChildren(...(rows.length ? rows :
      [trafficNode('p', 'field-provenance-empty', selection.searched ? 'No source match.' : 'No call sites captured.')])));
  }
  const matching = test?.enabled && test.url === selection.url && test.method === selection.request.method &&
    test.kind === selection.kind && test.pointer === selection.selector;
  const replayKey = JSON.stringify([matching && test, hooks?.session_id, state.debuggerError, sourceCatalog]);
  if (selection.replayKey !== replayKey) {
    selection.replayKey = replayKey;
    const disclosures = new Map([...provenanceUI.replay.querySelectorAll('[data-provenance-disclosure]')]
      .map(detail => [detail.dataset.provenanceDisclosure, detail.open]));
    const replay = [];
    if (state.debuggerError) {
      const error = trafficNode('p', 'field-provenance-empty', 'Offline. Last evidence retained.');
      error.title = state.debuggerError; replay.push(error);
    }
    if (matching) {
      const count = test.observations.length;
      replay.push(trafficNode('p', 'field-provenance-empty', `${count} ${count === 1 ? 'request' : 'requests'}${test.observation_evictions ? ` · ${test.observation_evictions} evicted` : ''}`));
      if (test.comparison) {
        const comparison = test.comparison;
        const result = trafficNode('p', 'field-provenance-comparison', `#${comparison.baseline_id} → #${comparison.variant_id} · ${comparison.changed ? 'Changed' : 'Unchanged'} · ${comparison.interpretation === 'intervention-associated' ? 'Intervention-associated' : 'Inconclusive'}`);
        result.title = comparison.interpretation === 'intervention-associated'
          ? 'A controlled return intervention is associated with this change. Other inputs may still differ.'
          : 'These observations do not establish an intervention-associated change.';
        replay.push(result);
      }
      for (const observation of [...test.observations].reverse()) {
        const row = trafficNode('details', 'field-provenance-observation');
        row.dataset.provenanceDisclosure = `observation-${observation.id}`;
        row.open = disclosures.get(row.dataset.provenanceDisclosure) ?? (disclosures.size === 0 && observation.id === test.observations.at(-1)?.id);
        const summary = trafficNode('summary', '', `#${observation.id} · ${new Date(observation.occurred_at_ms).toLocaleTimeString()} · ${observation.status === 'available' ? 'Captured' : observation.status.replaceAll('_', ' ')}`);
        summary.dataset.provenanceFocus = row.dataset.provenanceDisclosure;
        row.append(summary, trafficNode('pre', 'field-provenance-replay-value', observation.preview || 'Value unavailable.'));
        for (const site of observation.provenance?.call_sites ?? []) row.append(provenanceSiteRow(site, 'Observed', observation.id));
        for (const candidate of observation.provenance?.candidates ?? []) row.append(provenanceSiteRow(candidate, 'Correlated', `${observation.id}-${candidate.hit_id}`));
        const metadata = trafficNode('details', 'field-provenance-metadata');
        metadata.dataset.provenanceDisclosure = `metadata-${observation.id}`;
        metadata.open = disclosures.get(metadata.dataset.provenanceDisclosure) ?? false;
        const metadataSummary = trafficNode('summary', '', 'Details');
        metadataSummary.dataset.provenanceFocus = metadata.dataset.provenanceDisclosure;
        metadata.append(metadataSummary, trafficNode('pre', '', `${observation.target_type} ${observation.target_id}\nrequest ${observation.request_id}\n${observation.bytes} bytes\nSHA-256 ${observation.sha256 || 'unavailable'}`));
        for (const candidate of observation.provenance?.candidates ?? []) {
          metadata.append(trafficNode('p', '', `Hit ${candidate.hit_id} · ${candidate.phase} · ${candidate.operation} · ${candidate.matched_values.join(', ')}${hooks.hits.some(hit => hit.id === candidate.hit_id) ? '' : ' · evicted'}`));
        }
        row.append(metadata); replay.push(row);
      }
      if (!count) replay.push(trafficNode('p', 'field-provenance-empty', 'Waiting for requests.'));
    } else replay.push(trafficNode('p', 'field-provenance-empty', 'No replay yet.'));
    preserveProvenanceFocus(provenanceUI.replay, () => provenanceUI.replay.replaceChildren(...replay));
  }
  const gapLabels = {
    initiator_unavailable: 'Call sites unavailable.', malformed_call_site: 'Invalid call site omitted.',
    call_site_limit: '16-frame limit.', async_parent_unresolved: 'Async callers unavailable.',
    value_flow_unobserved: 'Value flow untracked.', transforms_unobserved: 'Transforms untracked.',
    async_worker_wasm_flow_unobserved: 'Async / worker / WASM flow untracked.',
    complete_string_unavailable: 'Complete string unavailable.', no_matching_runtime_value: 'No runtime match.',
    candidate_hit_limit: '32-hit limit.'
  };
  const gaps = ['Matches are candidates, not proof.', 'Transforms untracked.', 'Async / worker / WASM flow untracked.',
    ...selection.gaps, ...(selection.request.initiator?.gaps ?? []).map(gap => gapLabels[gap]),
    ...(matching ? test.observations.flatMap(observation => observation.provenance?.gaps ?? []).map(gap => gapLabels[gap]) : [])];
  provenanceUI.gaps.replaceChildren(...[...new Set(gaps)].filter(Boolean).map(gap => trafficNode('li', '', gap)));
}

function preserveProvenanceFocus(container, update) {
  const key = container.contains(document.activeElement) ? document.activeElement.dataset.provenanceFocus : null;
  update();
  if (key) [...container.querySelectorAll('[data-provenance-focus]')].find(element => element.dataset.provenanceFocus === key)?.focus({preventScroll: true});
}

function provenanceSiteRow(site, label, context = '') {
  let filename = site.source || 'Generated source';
  try { filename = new URL(site.source).pathname.split('/').pop() || new URL(site.source).host; } catch { /* Retain generated label. */ }
  const location = `${filename}:${site.line + 1}:${site.column + 1}`;
  const button = provenanceButton('', () => revealProvenanceSite(site));
  button.className = 'field-provenance-source';
  button.setAttribute('aria-label', `${label}: Open ${site.function || 'anonymous'} at ${location}`);
  const text = trafficNode('span', 'field-provenance-source-text');
  text.append(trafficNode('strong', '', site.function || '(anonymous)'), trafficNode('span', '', location));
  button.append(text, trafficNode('span', 'field-provenance-confidence', label), trafficNode('span', 'field-provenance-arrow', '↗'));
  button.disabled = !liveSources().some(source => source.script_id === site.script_id && source.target_id === site.target_id && site.source_hash && source.hash === site.source_hash);
  button.dataset.provenanceFocus = JSON.stringify([context, label, site.target_id, site.script_id, site.line, site.column]);
  button.title = button.disabled ? 'Source detached. Evidence retained.' :
    `${label === 'Observed' ? 'Observed call site' : label === 'Decoded candidate' ? 'Decoded source-text candidate' : 'Correlated candidate'} · ${site.source}\n${site.target_id} · script ${site.script_id} · ${site.source_hash || 'hash unavailable'}`;
  return button;
}

provenanceUI.search.addEventListener('click', searchFieldSources);
provenanceUI.decode.addEventListener('click', decodeProvenanceValue);
provenanceUI.original.addEventListener('click', () => {
  const previous = fieldProvenanceSelection;
  fieldProvenanceSelection = {...fieldProvenanceSelection, derivedSearch: null,
    candidates: [], searched: false, searching: false, gaps: [], error: null};
  // The chain remains valid for the same captured field after switching needles.
  if (decoderFieldOrigin?.selection === previous) decoderFieldOrigin.selection = fieldProvenanceSelection;
  renderFieldProvenance(); provenanceUI.search.focus({preventScroll: true});
});
provenanceUI.back.addEventListener('click', () => {
  showScreen('traffic'); requestAnimationFrame(() => elements.requestFilter.focus({preventScroll: true}));
});
provenanceUI.test.addEventListener('click', () => {
  const selection = fieldProvenanceSelection;
  if (!selection?.url) return;
  // Prefill only. Capture and mutation retain the existing explicit confirmations.
  elements.hooksFieldUrl.value = selection.url; elements.hooksFieldMethod.value = selection.request.method;
  elements.hooksFieldKind.value = selection.kind; elements.hooksFieldPointer.value = selection.selector;
  elements.hooksFieldConfirm.checked = false;
  showScreen('sources'); if (!state.sourceHooksOpen) openSourceHooks(false, false);
  renderRuntimeHooks(); focusRuntimeFieldTest();
});
