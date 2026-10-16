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
  let generation = 0, controller = null, reportText = null, pending = false;
  root.className = 'vm-tool-shell';
  const heading = node('h2', 'Analysis packs', 'vm-tool-title');
  const help = node('p', 'Apply a ranking overlay or compare instruction sets across two builds.', 'vm-tool-subtitle');
  const limits = node('p', 'Pack: 64 KiB. Combined request: 16 MiB. Both workspace digests and exact interpreter IDs are verified. A family binding is your declaration, not proof of behavioral equivalence.');
  const status = node('p', 'Select a pack and analysis, or two opcode workspace documents.', 'vm-tool-status vm-pack-status');
  status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  const fields = node('div', '', 'vm-tool-imports vm-pack-inputs'), actions = node('div', '', 'vm-tool-toolbar');
  const applyInputs = node('details', '', 'vm-tool-editor'); applyInputs.open = true; applyInputs.setAttribute('data-pack-inputs', 'apply'); applyInputs.append(node('summary', 'Apply a ranking pack'));
  const compareInputs = node('details', '', 'vm-tool-editor'); compareInputs.setAttribute('data-pack-inputs', 'compare'); compareInputs.append(node('summary', 'Compare two builds'));
  const results = node('section', '', 'vm-tool-results');
  const empty = () => { results.textContent = ''; results.append(node('h3', 'No analysis report yet'), node('p', 'Choose a pack and the local evidence to analyze. Results will appear here without changing the original evidence.', 'vm-tool-empty')); };
  empty();
  const raw = node('details', '', 'vm-tool-editor'); raw.append(node('summary', 'Inspect raw report JSON'));
  const output = node('pre', '', 'vm-pack-output'); output.tabIndex = 0; output.setAttribute('aria-label', 'Analysis pack report preview'); raw.append(output);
  const textValue = value => typeof value === 'string' ? value.length > 2048 ? value.slice(0, 2048) + '…' : value : typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : value == null ? '—' : 'See exact JSON';
  function renderReport(report, mode) {
    results.textContent = '';
    const rows = mode === 'apply' ? report.rankings : report.rows;
    results.append(node('h3', mode === 'apply' ? 'Ranking overlay' : 'Instruction-set comparison'));
    results.append(node('p', `${rows.length} rows${rows.length > 128 ? ' · first 128 shown; complete results in JSON export' : ''} · ${mode === 'apply' ? 'Original evidence and generic scores unchanged' : 'Comparison hypotheses, not proven behavioral equivalence'}`, 'vm-tool-subtitle'));
    if (mode === 'compare') {
      const counts = new Map(); for (const row of rows) { const key = ['unchanged', 'moved', 'changed', 'ambiguous', 'unknown', 'contradicted', 'left-only', 'right-only'].includes(row?.status) ? row.status : 'unknown'; counts.set(key, (counts.get(key) || 0) + 1); }
      results.append(node('p', Array.from(counts, ([key, count]) => `${count} ${key}`).join(' · '), 'vm-tool-subtitle'));
    }
    const table = node('table', '', 'vm-tool-table'), head = node('thead'), header = node('tr'), body = node('tbody');
    for (const title of mode === 'apply' ? ['Artifact', 'Pack score', 'Generic score', 'Labels'] : ['Left opcode', 'Right opcode', 'Status', 'Match basis']) { const cell = node('th', title); cell.setAttribute('scope', 'col'); header.append(cell); }
    head.append(header);
    for (const entry of rows.slice(0, 128)) {
      const row = node('tr');
      const cells = mode === 'apply' ? [entry?.artifact_id, entry?.anti_bot_score, entry?.generic_anti_bot_score, Array.isArray(entry?.labels) ? entry.labels.map(textValue).join(', ') : null] : [entry?.left?.opcode, entry?.right?.opcode, entry?.status, entry?.match_basis];
      for (const value of cells) row.append(node('td', textValue(value))); body.append(row);
    }
    table.append(head, body); results.append(table);
    if (!rows.length) results.append(node('p', 'No matching rows were returned. Unknowns remain in the complete report.', 'vm-tool-empty'));
    const provenance = node('details', '', 'vm-tool-editor'); provenance.append(node('summary', 'Report identity and limitations'));
    provenance.append(node('p', `SHA-256 ${report.document_digest}`));
    for (const limitation of (Array.isArray(report.limitations) ? report.limitations.slice(0, 32) : [])) provenance.append(node('p', textValue(limitation)));
    results.append(provenance);
  }
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
      renderReport(report, mode); reportText = text; output.textContent = text.length > 65536 ? `${text.slice(0, 65536)}\n… Preview limited to 65,536 characters. Download retains the complete report.` : text;
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
  const clear = button('Clear', () => { invalidate(); for (const key of Object.keys(pickers)) { epochs[key]++; inputs[key] = null; pickers[key].value = ''; statuses[key].textContent = 'No file selected'; } ids.left.value = ''; ids.right.value = ''; status.textContent = 'Inputs and report cleared.'; });
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
  root.append(heading, help, fields, actions, status, results, raw, boundaries);
  return {clear: () => { invalidate(); }, run};
}
if (typeof module !== 'undefined') module.exports = {vmPackRequestText, mountVmAnalysisPacks};
