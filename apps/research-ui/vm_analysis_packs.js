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
  const heading = node('h2', 'Analysis packs and build comparison');
  const help = node('p', 'Import local JSON. Packs are inert ranking and family declarations. No source or bytecode is executed, capture is unchanged, and no external service is contacted.');
  const limits = node('p', 'Pack: 64 KiB. Combined request: 16 MiB. Both workspace digests and exact interpreter IDs are verified. A family binding is your declaration, not proof of behavioral equivalence.');
  const status = node('p', 'Select a pack and analysis, or two opcode workspace documents.', 'vm-static-notice');
  status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  const fields = node('div', '', 'vm-static-toolbar'), actions = node('div', '', 'vm-static-toolbar');
  const output = node('pre', '', 'vm-pack-output'); output.tabIndex = 0; output.setAttribute('aria-label', 'Analysis pack report preview');
  const invalidate = () => {
    generation++; controller?.abort(); controller = null; pending = false; reportText = null;
    output.textContent = ''; download.disabled = true; apply.disabled = false; compare.disabled = false;
  };
  for (const [key, title] of [['pack', 'Analysis pack'], ['analysis', 'VM analysis (apply)'], ['left', 'Left opcode workspace'], ['right', 'Right opcode workspace']]) {
    const label = node('label', title), picker = node('input'); picker.type = 'file'; picker.setAttribute('aria-label', title); picker.accept = '.json,application/json';
    const selected = node('span', 'No file selected'); pickers[key] = picker; statuses[key] = selected; epochs[key] = 0;
    picker.addEventListener('change', async () => {
      const epoch = ++epochs[key], file = picker.files?.[0]; invalidate(); inputs[key] = null;
      selected.textContent = file ? 'Reading selected file…' : 'No file selected';
      status.textContent = file ? 'Reading input. Previous report cleared.' : 'Input selection cleared. Previous report cleared.';
      if (!file) return;
      try {
        if (file.size > (key === 'pack' ? 65536 : 16777216)) throw new Error('File exceeds the input limit.');
        const text = new TextDecoder('utf-8', {fatal: true}).decode(await file.arrayBuffer());
        if (epoch !== epochs[key]) return;
        inputs[key] = text; selected.textContent = `${file.name} · ${file.size} bytes`;
        status.textContent = 'Inputs changed. Run an explicit analysis to validate these documents.';
      } catch (error) { if (epoch === epochs[key]) { selected.textContent = `Unavailable: ${error.message}`; status.textContent = `Import refused: ${error.message}`; } }
    });
    label.append(picker, selected); fields.append(label);
  }
  const ids = {};
  for (const side of ['left', 'right']) {
    const label = node('label', `${side === 'left' ? 'Left' : 'Right'} interpreter artifact ID`), input = node('input'); input.type = 'text'; input.setAttribute('aria-label', `${side} interpreter artifact ID`); input.inputMode = 'numeric'; input.maxLength = 20;
    input.addEventListener('input', () => { invalidate(); status.textContent = 'Interpreter selection changed. Run comparison again.'; });
    ids[side] = input; label.append(input); fields.append(label);
  }
  const button = (text, callback) => { const element = node('button', text, 'secondary-button'); element.type = 'button'; element.addEventListener('click', callback); actions.append(element); return element; };
  const run = async mode => {
    if (pending) return;
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
      if (report.contract_version !== 1 || report.document_kind !== expected || !/^[a-f0-9]{64}$/.test(report.document_digest)) throw new Error('Malformed pack report.');
      reportText = text; output.textContent = text.length > 65536 ? `${text.slice(0, 65536)}\n… Preview limited to 65,536 characters. Download retains the complete report.` : text;
      const count = mode === 'apply' ? report.rankings?.length : report.rows?.length;
      status.textContent = `${mode === 'apply' ? 'Ranking overlay' : 'Build comparison'} ready · ${count ?? 'unknown'} rows · digest ${report.document_digest}. Original evidence retained; this is not proof of execution or equivalence.`;
      download.disabled = false;
    } catch (error) {
      if (current === generation) status.textContent = error.name === 'AbortError' ? 'Request cancelled or deadline exceeded. No report accepted; retry explicitly.' : `Analysis refused: ${error.message}`;
    } finally {
      clearTimeout(timer); if (current === generation) { pending = false; controller = null; apply.disabled = false; compare.disabled = false; }
    }
  };
  const apply = button('Apply ranking pack', () => run('apply'));
  const compare = button('Compare builds', () => run('compare'));
  button('Cancel', () => { invalidate(); status.textContent = 'Cancelled. No report accepted. Inputs retained.'; });
  button('Clear', () => { invalidate(); for (const key of Object.keys(pickers)) { epochs[key]++; inputs[key] = null; pickers[key].value = ''; statuses[key].textContent = 'No file selected'; } ids.left.value = ''; ids.right.value = ''; status.textContent = 'Inputs and report cleared.'; });
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
  root.append(heading, help, limits, fields, actions, status, node('p', 'Reports may contain sensitive retained evidence. Review before sharing. Downloads use your browser’s normal file permissions.'), output);
  return {clear: () => { invalidate(); }, run};
}
if (typeof module !== 'undefined') module.exports = {vmPackRequestText, mountVmAnalysisPacks};
