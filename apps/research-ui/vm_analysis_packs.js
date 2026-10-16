/* Data-only analysis through the same local Rust library as origin-trace-vm-pack.
 * Keep imported JSON as text: parsing/re-encoding would round u64 evidence IDs. */
function vmPackRequestText(mode, inputs, leftArtifact, rightArtifact) {
  const limit = 16777216;
  if (!['apply', 'compare'].includes(mode)) throw new TypeError('Unknown pack operation.');
  const keys = mode === 'apply' ? ['pack', 'analysis'] : ['pack', 'left', 'right'];
  for (const key of keys) {
    if (typeof inputs[key] !== 'string' || !inputs[key].trim().startsWith('{') ||
        new TextEncoder().encode(inputs[key]).length > (key === 'pack' ? 65536 : limit)) {
      throw new TypeError(`Select a bounded ${key} JSON object.`);
    }
  }
  // The backend's strict parser rejects duplicate keys, nonintegers, trailing
  // values, unknown fields, stale digests and mismatched source identities.
  let body = `{"pack":${inputs.pack}`;
  if (mode === 'apply') body += `,"analysis":${inputs.analysis}}`;
  else {
    for (const value of [leftArtifact, rightArtifact]) {
      if (!/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > 18446744073709551615n) throw new TypeError('Choose exact positive u64 interpreter artifact IDs.');
    }
    body += `,"left":${inputs.left},"left_artifact":${JSON.stringify(leftArtifact)},"right":${inputs.right},"right_artifact":${JSON.stringify(rightArtifact)}}`;
  }
  if (new TextEncoder().encode(body).length > limit) throw new TypeError('Combined request exceeds 16 MiB. Use the offline CLI for separate larger inputs.');
  return body;
}

function mountVmAnalysisPacks(root) {
  const node = (tag, text = '', className = '') => {
    const element = document.createElement(tag); element.textContent = text; element.className = className; return element;
  };
  const inputs = {}, epochs = {}, pickers = {}, statuses = {};
  let generation = 0, controller = null, reportText = null, pending = false, review = null;
  root.className = 'vm-tool-shell';
  const heading = node('h2', 'Analysis packs', 'vm-tool-title');
  const help = node('p', 'Apply a ranking overlay or compare instruction sets across two builds.', 'vm-tool-subtitle');
  const limits = node('p', 'Pack: 64 KiB. Combined request: 16 MiB. Both workspace digests and exact interpreter IDs are verified. A family binding is your declaration, not proof of behavioral equivalence.');
  const status = node('p', 'Select a pack and analysis, or two opcode workspace documents.', 'vm-tool-status vm-pack-status');
  status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  const fields = node('div', '', 'vm-tool-imports vm-pack-inputs'), actions = node('div', '', 'vm-tool-toolbar');
  const imports = node('details', '', 'vm-tool-editor vm-review-imports'); imports.open = true; imports.setAttribute('data-pack-inputs', 'all'); imports.append(node('summary', 'Pack inputs'), fields);
  const applyInputs = node('details', '', 'vm-tool-editor'); applyInputs.open = true; applyInputs.setAttribute('data-pack-inputs', 'apply'); applyInputs.append(node('summary', 'Apply a ranking pack'));
  const compareInputs = node('details', '', 'vm-tool-editor'); compareInputs.setAttribute('data-pack-inputs', 'compare'); compareInputs.append(node('summary', 'Compare two builds'));
  const results = node('section', '', 'vm-tool-results');
  const empty = () => { review = null; results.textContent = ''; results.append(node('h3', 'No analysis report yet'), node('p', 'Choose a pack and the local evidence to analyze. Results will appear here without changing the original evidence.', 'vm-tool-empty')); };
  empty();
  const raw = node('details', '', 'vm-tool-editor'); raw.append(node('summary', 'Inspect raw report JSON'));
  const output = node('pre', '', 'vm-pack-output'); output.tabIndex = 0; output.setAttribute('aria-label', 'Analysis pack report preview'); raw.append(output);
  const textValue = value => typeof value === 'string' ? value.length > 2048 ? value.slice(0, 2048) + '…' : value : typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : value == null ? '—' : 'See exact JSON';
  // JSON.parse is only for presentation. Never show a rounded integer as an
  // evidence identity, and never use this presentation copy for an export.
  const displayJson = (value, space = 2) => JSON.stringify(value, (_key, item) =>
    typeof item === 'number' && !Number.isSafeInteger(item) ? 'See exact JSON: integer outside safe browser range' : item, space);
  const labelText = value => Array.isArray(value) ? value.map(label =>
    label && typeof label === 'object' ? `${textValue(label.rule_id)}: ${textValue(label.label)}` : textValue(label)).join(', ') : '—';
  function renderReport(report, mode) {
    results.textContent = '';
    const rows = mode === 'apply' ? report.rankings : report.rows, pageSize = 64;
    const searchText = rows.map(entry => (displayJson(entry, 0) || '').toLowerCase());
    let filtered = rows.map((_entry, index) => index), selected = rows.length ? 0 : null, page = 0, activeTab = 'row';
    results.append(node('h3', mode === 'apply' ? 'Ranking overlay' : 'Instruction-set comparison'));
    results.append(node('p', `${rows.length} rows · ${mode === 'apply' ? 'Original evidence and generic scores unchanged' : 'Comparison hypotheses, not proven behavioral equivalence'}`, 'vm-tool-subtitle'));
    if (mode === 'compare') {
      const counts = new Map(); for (const row of rows) { const key = ['unchanged', 'moved', 'changed', 'ambiguous', 'unknown', 'contradicted', 'left-only', 'right-only'].includes(row?.status) ? row.status : 'unknown'; counts.set(key, (counts.get(key) || 0) + 1); }
      results.append(node('p', Array.from(counts, ([key, count]) => `${count} ${key}`).join(' · '), 'vm-tool-subtitle'));
    }
    const workbench = node('div', '', 'vm-review-workbench');
    const listing = node('section', '', 'vm-review-listing'), inspector = node('section', '', 'vm-review-inspector');
    listing.setAttribute('aria-label', 'Pack report listing'); inspector.setAttribute('aria-label', 'Selected pack row inspector');
    const filterLabel = node('label', 'Filter all report rows', 'vm-review-filter'), filter = node('input');
    filter.type = 'search'; filter.placeholder = 'Artifact, opcode, label, status or evidence'; filter.setAttribute('aria-label', 'Filter pack report rows');
    filterLabel.append(filter); listing.append(filterLabel);
    const counter = node('p', '', 'vm-tool-subtitle'); counter.setAttribute('aria-live', 'polite'); listing.append(counter);
    const table = node('table', '', 'vm-tool-table'), head = node('thead'), header = node('tr'), body = node('tbody');
    table.setAttribute('role', 'grid'); table.setAttribute('aria-label', 'Pack report rows');
    for (const title of mode === 'apply' ? ['Artifact', 'Pack score', 'Generic score', 'Labels'] : ['Left opcode', 'Right opcode', 'Status', 'Match basis']) { const cell = node('th', title); cell.setAttribute('scope', 'col'); header.append(cell); }
    head.append(header); table.append(head, body); listing.append(table);
    const noRows = node('p', '', 'vm-tool-empty'); listing.append(noRows);
    const paging = node('div', '', 'vm-tool-toolbar'), pageStatus = node('span');
    const previousPage = node('button', 'Previous page', 'secondary-button'), nextPage = node('button', 'Next page', 'secondary-button');
    for (const button of [previousPage, nextPage]) button.type = 'button';
    paging.append(previousPage, pageStatus, nextPage); listing.append(paging);
    const tabs = node('div', '', 'vm-review-tabs'), rowTab = node('button', 'Selected row', 'secondary-button'), provenanceTab = node('button', 'Report provenance', 'secondary-button');
    const detail = node('div', '', 'vm-review-detail');
    for (const button of [rowTab, provenanceTab]) { button.type = 'button'; tabs.append(button); }
    inspector.append(tabs, detail); workbench.append(listing, inspector); results.append(workbench);
    const field = (title, value) => detail.append(node('h4', title), node('p', textValue(value)));
    function renderInspector() {
      rowTab.setAttribute('aria-pressed', String(activeTab === 'row')); provenanceTab.setAttribute('aria-pressed', String(activeTab === 'provenance'));
      detail.textContent = '';
      if (activeTab === 'provenance') {
        detail.append(node('h3', 'Report identity and limitations'));
        field('Report SHA-256', report.document_digest);
        for (const [key, title] of [['pack_digest', 'Pack SHA-256'], ['analysis_digest', 'Analysis SHA-256'], ['program_family', 'Declared program family'], ['family_binding', 'Family binding']]) if (report[key] != null) field(title, report[key]);
        for (const side of ['left', 'right']) if (mode === 'compare' && report[side]) {
          detail.append(node('h4', `${side === 'left' ? 'Left' : 'Right'} workspace identity`), node('pre', displayJson(report[side]), 'vm-pack-row-json'));
        }
        detail.append(node('p', mode === 'compare' ? 'Family bindings and effect matches are declarations and hypotheses. Behavioral equivalence is not proven.' : 'This ranking overlay does not change the original evidence or generic scores.'));
        for (const limitation of (Array.isArray(report.limitations) ? report.limitations.slice(0, 32) : [])) detail.append(node('p', textValue(limitation)));
        if (Array.isArray(report.limitations) && report.limitations.length > 32) detail.append(node('p', 'First 32 limitations shown. The complete report export retains every limitation.'));
        return;
      }
      if (selected == null) { detail.append(node('h3', 'No selected row'), node('p', rows.length ? 'Clear or change the filter to inspect retained report rows.' : 'The accepted report has no rows.', 'vm-tool-empty')); return; }
      const entry = rows[selected];
      detail.append(node('h3', `Report row ${selected + 1} of ${rows.length}`));
      if (mode === 'apply') {
        field('Artifact', entry?.artifact_id); field('Pack score', entry?.anti_bot_score); field('Original generic score', entry?.generic_anti_bot_score);
        field('Applied labels', labelText(entry?.labels));
      } else {
        field('Status', entry?.status); field('Match basis', entry?.match_basis);
        field('Left opcode', entry?.left?.opcode); field('Right opcode', entry?.right?.opcode);
        field('Effect shape SHA-256', entry?.effect_shape_digest);
      }
      detail.append(node('h4', 'Retained row evidence'));
      const json = displayJson(entry) || 'null', preview = node('pre', json.length > 65536 ? `${json.slice(0, 65536)}\n… Row preview limited to 65,536 characters. Complete exact values remain in the report export.` : json, 'vm-pack-row-json');
      preview.tabIndex = 0; detail.append(preview);
      detail.append(node('p', 'Presentation only. Unsafe integer identities are marked See exact JSON. The complete report export retains the original response bytes.', 'vm-tool-subtitle'));
    }
    function renderListing(focus = false) {
      body.textContent = '';
      const start = page * pageSize, visible = filtered.slice(start, start + pageSize);
      counter.textContent = `${filtered.length} of ${rows.length} rows · ${filtered.length ? `${start + 1}–${start + visible.length}` : '0'} shown`;
      noRows.textContent = filtered.length ? '' : rows.length ? 'No rows match this filter. The complete report is unchanged.' : 'No matching rows were returned. Unknowns remain in the complete report.';
      noRows.hidden = filtered.length > 0;
      for (const index of visible) {
        const entry = rows[index], row = node('tr'); row.tabIndex = index === selected ? 0 : -1;
        row.setAttribute('aria-selected', String(index === selected)); row.setAttribute('data-pack-row', String(index));
        row.className = index === selected ? 'selected' : '';
        const cells = mode === 'apply' ? [entry?.artifact_id, entry?.anti_bot_score, entry?.generic_anti_bot_score, labelText(entry?.labels)] : [entry?.left?.opcode, entry?.right?.opcode, entry?.status, entry?.match_basis];
        for (const value of cells) row.append(node('td', textValue(value)));
        row.addEventListener('click', () => select(index, true));
        row.addEventListener('keydown', event => {
          if (event.isComposing || event.altKey || event.ctrlKey || event.metaKey || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
          event.preventDefault();
          if (event.key === 'Home' || event.key === 'End') select(filtered[event.key === 'Home' ? 0 : filtered.length - 1], true);
          else move(event.key === 'ArrowDown' ? 1 : -1, true);
        });
        body.append(row); if (focus && index === selected) row.focus();
      }
      pageStatus.textContent = `Page ${filtered.length ? page + 1 : 0} of ${Math.ceil(filtered.length / pageSize)}`;
      previousPage.disabled = page === 0 || !filtered.length; nextPage.disabled = (page + 1) * pageSize >= filtered.length;
      renderInspector();
    }
    function select(index, focus = false) {
      const position = filtered.indexOf(index); if (position < 0) return;
      selected = index; page = Math.floor(position / pageSize); renderListing(focus);
    }
    function move(delta, focus = true) {
      if (!filtered.length) return;
      const position = filtered.indexOf(selected); select(filtered[Math.max(0, Math.min(filtered.length - 1, position + delta))], focus);
    }
    filter.addEventListener('input', () => {
      const query = filter.value.toLowerCase(); filtered = rows.map((_entry, index) => index).filter(index => searchText[index].includes(query));
      if (!filtered.includes(selected)) selected = filtered[0] ?? null;
      page = selected == null ? 0 : Math.floor(filtered.indexOf(selected) / pageSize); renderListing();
    });
    function changePage(delta, button, fallback) {
      if (button.disabled) return;
      const hadFocus = document.activeElement === button;
      select(filtered[(page + delta) * pageSize]);
      // Disabling the active edge control must not strand keyboard focus.
      if (hadFocus && button.disabled) fallback.focus();
    }
    previousPage.addEventListener('click', () => changePage(-1, previousPage, nextPage));
    nextPage.addEventListener('click', () => changePage(1, nextPage, previousPage));
    rowTab.addEventListener('click', () => { activeTab = 'row'; renderInspector(); });
    provenanceTab.addEventListener('click', () => { activeTab = 'provenance'; renderInspector(); });
    review = {search: () => filter.focus(), move, query: () => ({search: true, previous: filtered.indexOf(selected) > 0, next: selected != null && filtered.indexOf(selected) < filtered.length - 1})}; renderListing();
  }
  root.addEventListener('vm-workspace-query', event => { if (event.detail && review) Object.assign(event.detail, review.query()); });
  root.addEventListener('vm-workspace-search', () => review?.search());
  root.addEventListener('vm-workspace-next', () => review?.move(1));
  root.addEventListener('vm-workspace-previous', () => review?.move(-1));
  const invalidate = () => {
    generation++; controller?.abort(); controller = null; pending = false; reportText = null;
    output.textContent = ''; empty(); download.disabled = true; apply.disabled = false; compare.disabled = false;
  };
  for (const [key, title] of [['pack', 'Analysis pack'], ['analysis', 'VM analysis (apply)'], ['left', 'Left opcode workspace'], ['right', 'Right opcode workspace']]) {
    const label = node('label', title, 'vm-tool-import-card'), picker = node('input'); picker.type = 'file'; picker.setAttribute('aria-label', title); picker.accept = '.json,application/json';
    const selected = node('span', 'No file selected'); pickers[key] = picker; statuses[key] = selected; epochs[key] = 0;
    picker.addEventListener('change', async () => {
      const epoch = ++epochs[key], file = picker.files?.[0]; invalidate(); inputs[key] = null;
      if (key !== 'pack') selectAction(key === 'analysis' ? 'apply' : 'compare');
      selected.textContent = file ? 'Reading selected file…' : 'No file selected';
      status.textContent = file ? 'Reading input. Previous report cleared.' : 'Input selection cleared. Previous report cleared.';
      if (!file) return;
      try {
        if (file.size > (key === 'pack' ? 65536 : 16777216)) throw new Error('File exceeds the input limit.');
        const text = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(await file.arrayBuffer());
        if (epoch !== epochs[key]) return;
        inputs[key] = text; selected.textContent = `${file.name} · ${file.size} bytes`;
        status.textContent = 'Inputs changed. Run an explicit analysis to validate these documents.';
      } catch (error) { if (epoch === epochs[key]) { selected.textContent = `Unavailable: ${error.message}`; status.textContent = `Import refused: ${error.message}`; } }
    });
    label.append(picker, selected); (key === 'pack' ? fields : key === 'analysis' ? applyInputs : compareInputs).append(label);
  }
  const ids = {};
  for (const side of ['left', 'right']) {
    const label = node('label', `${side === 'left' ? 'Left' : 'Right'} interpreter artifact ID`, 'vm-tool-import-card'), input = node('input'); input.type = 'text'; input.setAttribute('aria-label', `${side} interpreter artifact ID`); input.inputMode = 'numeric'; input.maxLength = 20;
    input.addEventListener('input', () => { selectAction('compare'); invalidate(); status.textContent = 'Interpreter selection changed. Run comparison again.'; });
    ids[side] = input; label.append(input); compareInputs.append(label);
  }
  fields.append(applyInputs, compareInputs);
  const button = (text, callback) => { const element = node('button', text, 'secondary-button'); element.type = 'button'; element.addEventListener('click', callback); actions.append(element); return element; };
  const run = async mode => {
    if (pending) return;
    selectAction(mode);
    invalidate(); const current = generation;
    let timer;
    try {
      if (!['http:', 'https:'].includes(location.protocol)) throw new Error('This view needs the local Rust HTTP backend. Use make ui or the offline origin-trace-vm-pack CLI.');
      const body = vmPackRequestText(mode, inputs, ids.left.value, ids.right.value);
      pending = true; apply.disabled = true; compare.disabled = true; controller = new AbortController();
      const requestController = controller;
      timer = setTimeout(() => requestController.abort(), 30000);
      status.textContent = 'Validating exact source identities and running data-only analysis…';
      const response = await fetch(`/api/analysis/vm/packs/${mode}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body, signal: controller.signal, redirect: 'error'});
      const bytes = await evidencePackageReadBytes(response, 33554432, requestController.signal);
      const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
      if (current !== generation) return;
      if (!response.ok) { let message = `Local backend refused the request (${response.status}).`; try { const error = JSON.parse(text).error; if (typeof error === 'string' && error.length <= 8192) message = error; } catch {} throw new Error(message); }
      // Parse only for display metadata; downloads retain exact original text.
      const report = JSON.parse(text), expected = mode === 'apply' ? 'vm-pack-application' : 'vm-instruction-set-comparison';
      if (report.contract_version !== 1 || report.document_kind !== expected || !/^[a-f0-9]{64}$/.test(report.document_digest) ||
          !Array.isArray(mode === 'apply' ? report.rankings : report.rows) || mode === 'compare' && report.behavioral_equivalence_proven !== false) throw new Error('Malformed pack report.');
      renderReport(report, mode); imports.open = false; reportText = text; output.textContent = text.length > 65536 ? `${text.slice(0, 65536)}\n… Preview limited to 65,536 characters. Download retains the complete report.` : text;
      const count = mode === 'apply' ? report.rankings?.length : report.rows?.length;
      status.textContent = `${mode === 'apply' ? 'Ranking overlay' : 'Build comparison'} ready · ${count ?? 'unknown'} rows. Original evidence retained. Report identity and limitations are below.`;
      download.disabled = false;
    } catch (error) {
      if (current === generation) status.textContent = error.name === 'AbortError' ? 'Request cancelled or deadline exceeded. No report accepted; retry explicitly.' : `Analysis refused: ${error.message}`;
    } finally {
      clearTimeout(timer); if (current === generation) { pending = false; controller = null; apply.disabled = false; compare.disabled = false; }
    }
  };
  const apply = button('Apply ranking pack', () => run('apply'));
  const compare = button('Compare builds', () => run('compare'));
  const selectAction = mode => {
    apply.className = `secondary-button${mode === 'apply' ? ' vm-tool-primary' : ''}`;
    compare.className = `secondary-button${mode === 'compare' ? ' vm-tool-primary' : ''}`;
  };
  selectAction('apply');
  applyInputs.addEventListener('toggle', () => { if (applyInputs.open) selectAction('apply'); });
  compareInputs.addEventListener('toggle', () => { if (compareInputs.open) selectAction('compare'); });
  const cancel = button('Cancel', () => { invalidate(); status.textContent = 'Cancelled. No report accepted. Inputs retained.'; });
  const clear = button('Clear', () => { invalidate(); imports.open = true; for (const key of Object.keys(pickers)) { epochs[key]++; inputs[key] = null; pickers[key].value = ''; statuses[key].textContent = 'No file selected'; } ids.left.value = ''; ids.right.value = ''; status.textContent = 'Inputs and report cleared.'; });
  cancel.className += ' vm-tool-tertiary'; clear.className += ' vm-tool-tertiary';
  const nativeShell = document.documentElement.classList.contains('native-shell');
  const download = button(nativeShell ? 'Copy complete report JSON' : 'Download complete report', async () => {
    if (!reportText) return;
    if (nativeShell) {
      const current = generation;
      try { await navigator.clipboard.writeText(reportText); if (current === generation) status.textContent = 'Complete report JSON copied. Save it locally and review before sharing.'; }
      catch { if (current === generation) status.textContent = 'Clipboard unavailable. Use the browser development UI to download the complete report.'; }
      return;
    }
    const url = URL.createObjectURL(new Blob([reportText], {type: 'application/json'})), link = node('a'); link.href = url; link.download = 'vm-pack-report.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }); download.disabled = true;
  const boundaries = node('details', '', 'vm-tool-editor'); boundaries.append(node('summary', 'Input limits and research boundaries'), limits, node('p', 'Packs are inert declarations. No imported source or bytecode executes and no external service is contacted. Reports may contain private evidence; review before sharing.'));
  root.append(heading, help, imports, actions, status, results, raw, boundaries);
  return {clear: () => { invalidate(); }, run};
}
if (typeof module !== 'undefined') module.exports = {vmPackRequestText, mountVmAnalysisPacks};
