/* Field provenance is an evidence projection. Equal text never establishes value flow. */
let fieldProvenanceSelection = null;
let decoderFieldOrigin = null;
const provenanceUI = Object.fromEntries(['target', 'notice', 'value', 'back', 'decode', 'original', 'derived', 'derived-value', 'derived-steps', 'candidates', 'gaps']
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
  requestAnimationFrame(() => provenanceUI.decode.focus({preventScroll: true}));
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
  if (!investigationAllowDecoderReplace()) return;
  resetDecoderChain('Original request string copied. Choose each transformation explicitly.');
  toolsElements.inputEncoding.value = 'text';
  toolsElements.input.value = selection.value;
  // Textareas normalize line endings. Preserve the captured bytes as the chain
  // root, and use the displayed input key only to detect subsequent edits.
  state.decoderInputSnapshot = {key: decoderCurrentInputKey(), base64: decoderBytesToBase64(bytes), bytes: bytes.length};
  decoderFieldOrigin = {selection, key: decoderCurrentInputKey()};
  const requestIdentity = investigationRequestIdentity(selection.request);
  investigationDecoderOrigin = {route: requestIdentity ? {kind:'request', identity:requestIdentity, inspectorTab:'payload'} : null, key:decoderCurrentInputKey(),
    description:`Selected request string · ${selection.selector}. UTF-8 string bytes preserved; raw HTTP byte offsets are unavailable.${requestIdentity ? '' : ' Exact request identity is unavailable.'}`};
  showScreen('tools'); setToolsTab('decoder');
  const revision = investigationRevision;
  requestAnimationFrame(() => {if (revision === investigationRevision && investigationScreen() === 'tools') toolsElements.operation.focus({preventScroll: true});});
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
  toolsElements.fieldOriginNotice.textContent = candidate.error || 'View this decoded value beside the retained original. It is not proof of page transformations.';
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
  requestAnimationFrame(() => provenanceUI.decode.focus({preventScroll: true}));
}

// Retained call-site identities remain readable; no live lookup or replay is offered.
function renderFieldProvenance() {
  const selection = fieldProvenanceSelection;
  if (!selection || document.querySelector('#screen-field-provenance').hidden) return;
  provenanceUI.target.textContent = `${selection.request.method} ${selection.url || selection.request.path} · ${selection.selector}`;
  provenanceUI.value.textContent = `${selection.value.slice(0, 256)}${selection.value.length > 256 ? '…' : ''}`;
  provenanceUI.derived.hidden = !selection.derivedSearch;
  provenanceUI.original.hidden = !selection.derivedSearch;
  provenanceUI.decode.disabled = state.decoderPending || provenanceDecoderBytes(selection.value) === null;
  if (selection.derivedSearch) {
    provenanceUI['derived-value'].textContent = selection.derivedSearch.value;
    provenanceUI['derived-steps'].textContent = selection.derivedSearch.steps.map((step, index) =>
      `${index + 1}. ${step.operation} · ${step.input_bytes} B → ${step.output_bytes} B`).join('\n');
  }
  provenanceUI.notice.textContent = 'Retained identities only. Live debugger lookup and request replay have been removed.';
  const sites = isFieldCallSites(selection.request.initiator) ? selection.request.initiator.sites : [];
  provenanceUI.candidates.replaceChildren(...(sites.length ? sites.map(site =>
    trafficNode('pre', 'field-provenance-site', JSON.stringify(site, null, 2))) :
    [trafficNode('p', 'field-provenance-empty', 'No call sites captured.')]));
  provenanceUI.gaps.replaceChildren(trafficNode('li', '', 'Equal or decoded text does not establish runtime value flow.'));
}
provenanceUI.decode.addEventListener('click', decodeProvenanceValue);
provenanceUI.original.addEventListener('click', () => {
  const previous = fieldProvenanceSelection;
  fieldProvenanceSelection = {...previous, derivedSearch: null};
  if (decoderFieldOrigin?.selection === previous) decoderFieldOrigin.selection = fieldProvenanceSelection;
  renderFieldProvenance(); provenanceUI.decode.focus({preventScroll: true});
});
provenanceUI.back.addEventListener('click', () => {
  showScreen('traffic'); requestAnimationFrame(() => elements.requestFilter.focus({preventScroll: true}));
});
