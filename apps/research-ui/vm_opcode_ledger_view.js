/* Local researcher assertions only. Imports, edits and exports never execute code. */
const RebVmOpcodeLedgerView = (() => {
  function mount(root, model = vmOpcodeLedger) {
    const node = (tag, text = '') => { const el = document.createElement(tag); el.textContent = text; return el; };
    const button = (text, action) => { const el = node('button', text); el.type = 'button'; el.className = 'secondary-button'; el.addEventListener('click', action); return el; };
    const editors = {}, files = {}, reads = {definition: 0, ledger: 0};
    let revision = 0, report = null, current = false;
    const pending = {definition: false, ledger: false};
    const notice = node('p', 'Choose exact definition JSON and a ledger, or create a new ledger.');
    notice.setAttribute('role', 'status'); notice.setAttribute('aria-live', 'polite');
    const coverageState = node('p');
    const results = node('section'); results.setAttribute('aria-label', 'Opcode ledger coverage');
    const controls = node('div'); controls.className = 'vm-static-toolbar';
    const invalidate = () => {
      revision++; current = false; download.disabled = true;
      coverageState.textContent = report ? 'Previous coverage is stale and does not describe the current draft.' : '';
      notice.textContent = report ? 'Draft changed. Previous coverage is stale; validate to refresh and enable export.' : 'Draft changed. Validate before export.';
    };
    async function importFile(kind, file) {
      if (!file) return;
      const serial = ++reads[kind]; invalidate(); pending[kind] = true;
      try {
        if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > model.ledgerLimits.input_bytes) throw new TypeError('File exceeds the 1 MiB bound or is empty.');
        const bytes = new Uint8Array(await file.arrayBuffer());
        if (serial !== reads[kind]) return;
        if (bytes.byteLength > model.ledgerLimits.input_bytes) throw new TypeError('File exceeds the 1 MiB bound.');
        const text = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes);
        if (text.charCodeAt(0) === 0xfeff) throw new TypeError('JSON must not begin with a UTF-8 BOM.');
        editors[kind].value = text; invalidate();
        notice.textContent = `${kind === 'definition' ? 'Definition' : 'Ledger'} loaded locally. Validate the draft to check schema and exact definition identity.`;
      } catch (error) { if (serial === reads[kind]) notice.textContent = `Import refused: ${error.message}`; }
      finally { if (serial === reads[kind]) pending[kind] = false; }
    }
    for (const [kind, title] of [['definition', 'Exact definition JSON'], ['ledger', 'Opcode ledger JSON editor']]) {
      const section = node('section'), label = node('label', title), fileLabel = node('label', `Import ${kind} JSON`);
      const editor = node('textarea'); editor.rows = kind === 'ledger' ? 14 : 5; editor.spellcheck = false;
      editor.style.width = '100%'; editor.style.boxSizing = 'border-box'; editor.style.maxWidth = '100%';
      editor.maxLength = model.ledgerLimits.input_bytes; editor.setAttribute('aria-label', title);
      editor.addEventListener('input', () => { reads[kind]++; pending[kind] = false; invalidate(); });
      const file = node('input'); file.type = 'file'; file.accept = '.json,application/json'; file.setAttribute('aria-label', `Import ${kind} JSON`);
      file.style.maxWidth = '100%'; file.addEventListener('change', () => { const selected = file.files?.[0]; file.value = ''; void importFile(kind, selected); });
      label.append(editor); fileLabel.append(file); section.append(label, fileLabel); root.append(section);
      editors[kind] = editor; files[kind] = file;
    }
    function render() {
      results.replaceChildren();
      const counts = report.coverage.counts;
      results.append(node('p', `${report.coverage.total} declared opcodes: ${counts.observed} observed, ${counts.inferred} inferred, ${counts.unmodeled} unmodeled; ${counts.missing_entries} missing entries. These are supplied labels, not runtime coverage.`));
      const identity = node('p', `Definition ${report.ledger.definition_id} · exact source SHA-256 ${report.definition_source_sha256}`); identity.style.overflowWrap = 'anywhere'; results.append(identity);
      for (const entry of report.coverage.opcodes) {
        const row = node('p', `${entry.opcode} · ${entry.status}${entry.entry_present ? '' : ' (missing entry)'} · declared operation: ${entry.declared_operation} · supplied tests: ${entry.test_status} · ${entry.meaning ?? 'No asserted meaning'}`);
        row.style.overflowWrap = 'anywhere'; results.append(row);
      }
    }
    async function validate() {
      if (pending.definition || pending.ledger) { notice.textContent = 'Wait for the selected file to finish loading.'; return; }
      const serial = ++revision; current = false; download.disabled = true;
      coverageState.textContent = report ? 'Previous coverage is stale and does not describe the current draft.' : '';
      notice.textContent = 'Validating schema and exact definition identity…';
      try {
        const next = await model.inspectLedger(editors.ledger.value, editors.definition.value);
        if (serial !== revision) return;
        report = next; current = true; render(); download.disabled = false; coverageState.textContent = 'Validated coverage for the current draft.';
        notice.textContent = 'Valid ledger. References are unverified and tests were not executed. Review private data before exporting.';
      } catch (error) { if (serial === revision) notice.textContent = `Validation refused: ${error.message}${report ? ' Previous coverage is stale.' : ''}`; }
    }
    async function create() {
      if (pending.definition || pending.ledger) { notice.textContent = 'Wait for the selected file to finish loading.'; return; }
      if (editors.ledger.value.trim()) { notice.textContent = 'Clear the ledger editor deliberately before creating a new ledger; existing work was kept.'; return; }
      const serial = ++revision; current = false; download.disabled = true;
      coverageState.textContent = report ? 'Previous coverage is stale and does not describe the current draft.' : '';
      try {
        const next = await model.createLedger(editors.definition.value);
        if (serial !== revision) return;
        editors.ledger.value = JSON.stringify(next, null, 2); invalidate();
        notice.textContent = 'Created an empty ledger bound to these exact definition bytes. Add reviewed entries, then validate. No entries or meanings are inferred.';
      } catch (error) { if (serial === revision) notice.textContent = `Creation refused: ${error.message}`; }
    }
    function exportText() { return current ? JSON.stringify(report.ledger, null, 2) + '\n' : null; }
    const download = button('Export validated ledger JSON', () => {
      const text = exportText(); if (text === null) return;
      const url = URL.createObjectURL(new Blob([text], {type: 'application/json'}));
      const link = node('a'); link.href = url; link.download = 'opcode-ledger.json'; root.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }); download.disabled = true;
    const validateButton = button('Validate ledger', () => void validate());
    const createButton = button('Create empty ledger', () => void create());
    const clear = button('Clear all ledger inputs', () => {
      reads.definition++; reads.ledger++; pending.definition = false; pending.ledger = false; editors.definition.value = ''; editors.ledger.value = ''; report = null;
      invalidate(); results.replaceChildren(); notice.textContent = 'Local inputs and coverage cleared.'; files.definition.focus();
    });
    controls.append(createButton, validateButton, download, clear);
    const help = node('details'); help.append(node('summary', 'Entry schema and research boundaries'));
    help.append(node('p', 'Edit entries in the JSON editor. Each opcode must exist in the definition. Observed/inferred require meaning and source_refs. Unmodeled requires null meaning. Passed/failed/inconclusive tests require test_refs; not_run requires none. Handler offsets are byte offsets. Nothing is fetched, verified, executed, uploaded or automatically saved.'));
    const sample = node('pre', JSON.stringify({opcode: '00', status: 'unmodeled', meaning: null, handler_location: null, operand_format: null, source_refs: [], test_status: 'not_run', test_refs: [], unresolved_questions: []}, null, 2));
    sample.style.whiteSpace = 'pre-wrap'; sample.style.overflowWrap = 'anywhere'; help.append(sample);
    root.append(controls, notice, help, coverageState, results);
    return {editors, files, notice, results, validate, create, importFile, exportText, download, clear, getReport: () => report};
  }
  return {mount};
})();
if (typeof module === 'object' && module?.exports) module.exports = RebVmOpcodeLedgerView;
