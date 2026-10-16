/* Local researcher assertions only. Imports, edits and exports never execute code. */
const RebVmOpcodeLedgerView = (() => {
  function mount(root, model = vmOpcodeLedger) {
    const node = (tag, text = '', className = '') => { const el = document.createElement(tag); el.textContent = text; el.className = className; return el; };
    root.className = 'vm-tool-shell';
    const heading = node('h2', 'Opcode evidence ledger', 'vm-tool-title');
    const subtitle = node('p', 'Track what each opcode means, what supports it, and what remains unknown.', 'vm-tool-subtitle');
    const imports = node('div', '', 'vm-tool-imports');
    const editorArea = node('div', '', 'vm-tool-imports');
    const inputSummaries = {}, disclosures = {};
    root.append(heading, subtitle, imports);
    const button = (text, action) => { const el = node('button', text); el.type = 'button'; el.className = 'secondary-button'; el.addEventListener('click', action); return el; };
    const editors = {}, files = {}, reads = {definition: 0, ledger: 0};
    let revision = 0, report = null, current = false;
    const pending = {definition: false, ledger: false};
    const notice = node('p', 'Import a definition, then add a ledger or create an empty one.', 'vm-tool-status');
    notice.setAttribute('role', 'status'); notice.setAttribute('aria-live', 'polite');
    const coverageState = node('p', '', 'vm-tool-subtitle');
    const results = node('section', '', 'vm-tool-results'); results.setAttribute('aria-label', 'Opcode ledger coverage');
    const controls = node('div'); controls.className = 'vm-tool-toolbar';
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
        editors[kind].value = text; inputSummaries[kind].textContent = `${file.name || 'Local JSON'} · ${bytes.byteLength.toLocaleString()} bytes`; invalidate();
        notice.textContent = `${kind === 'definition' ? 'Definition' : 'Ledger'} loaded locally. Validate the draft to check schema and exact definition identity.`;
      } catch (error) { if (serial === reads[kind]) notice.textContent = `Import refused: ${error.message}`; }
      finally { if (serial === reads[kind]) pending[kind] = false; }
    }
    for (const [kind, title] of [['definition', 'Exact definition JSON'], ['ledger', 'Opcode ledger JSON editor']]) {
      const card = node('section', '', 'vm-tool-import-card');
      const fileLabel = node('label', kind === 'definition' ? '1. VM definition' : '2. Evidence ledger');
      const summary = node('span', 'No file selected', 'vm-tool-subtitle'); inputSummaries[kind] = summary;
      const file = node('input'); file.type = 'file'; file.accept = '.json,application/json'; file.setAttribute('aria-label', `Import ${kind} JSON`);
      file.addEventListener('change', () => { const selected = file.files?.[0]; file.value = ''; void importFile(kind, selected); });
      fileLabel.append(file, summary); card.append(fileLabel); imports.append(card);
      const disclosure = node('details', '', 'vm-tool-editor'); disclosures[kind] = disclosure;
      disclosure.setAttribute('data-ledger-editor', kind);
      disclosure.append(node('summary', kind === 'definition' ? 'View or edit definition JSON' : 'Edit ledger JSON'));
      const label = node('label', title), editor = node('textarea'); editor.rows = 10; editor.spellcheck = false;
      editor.maxLength = model.ledgerLimits.input_bytes; editor.setAttribute('aria-label', title);
      editor.addEventListener('input', () => { reads[kind]++; pending[kind] = false; inputSummaries[kind].textContent = editor.value ? 'Edited local draft · validate before export' : 'Empty draft'; invalidate(); });
      label.append(editor); disclosure.append(label); editorArea.append(disclosure);
      editors[kind] = editor; files[kind] = file;
    }
    const empty = () => { results.replaceChildren(node('h3', 'No validated ledger yet'), node('p', 'Import local JSON above, or create an empty ledger from a definition. Validation will reveal opcode coverage here.', 'vm-tool-empty')); };
    empty();
    function render() {
      results.replaceChildren();
      const counts = report.coverage.counts;
      results.append(node('h3', `${report.coverage.total} declared opcodes`));
      results.append(node('p', `${counts.observed} observed · ${counts.inferred} inferred · ${counts.unmodeled} unmodeled · ${counts.missing_entries} missing entries`, 'vm-tool-subtitle'));
      results.append(node('p', 'Researcher assertions only. Coverage does not establish runtime execution; references and supplied test outcomes are unverified.', 'vm-tool-subtitle'));
      const table = node('table', '', 'vm-tool-table'), head = node('thead'), header = node('tr'), body = node('tbody');
      for (const title of ['Opcode', 'Evidence status', 'Asserted meaning', 'Supplied tests']) { const cell = node('th', title); cell.setAttribute('scope', 'col'); header.append(cell); }
      head.append(header);
      for (const entry of report.coverage.opcodes) {
        const row = node('tr');
        row.append(node('td', entry.opcode), node('td', `${entry.status}${entry.entry_present ? '' : ' · missing entry'}`));
        const meaning = node('td'); meaning.append(node('span', entry.meaning ?? 'No asserted meaning'), node('small', `Declared operation: ${entry.declared_operation}`));
        row.append(meaning, node('td', entry.test_status)); body.append(row);
      }
      table.append(head, body); results.append(table);
      const identity = node('details', '', 'vm-tool-editor'); identity.append(node('summary', `Definition identity · ${report.ledger.definition_id}`));
      identity.append(node('p', `Exact source SHA-256 ${report.definition_source_sha256}`)); results.append(identity);

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
        editors.ledger.value = JSON.stringify(next, null, 2); inputSummaries.ledger.textContent = 'New local draft · no asserted entries'; disclosures.ledger.open = true; invalidate();
        notice.textContent = 'Created an empty ledger bound to these exact definition bytes. Add reviewed entries, then validate. No entries or meanings are inferred.';
      } catch (error) { if (serial === revision) notice.textContent = `Creation refused: ${error.message}`; }
    }
    function exportText() { return current ? JSON.stringify(report.ledger, null, 2) + '\n' : null; }
    const nativeShell = document.documentElement?.classList.contains('native-shell') === true;
    let copying = false;
    const download = button(nativeShell ? 'Copy validated ledger JSON' : 'Export validated ledger JSON', async () => {
      const text = exportText(); if (text === null || copying) return;
      if (nativeShell) {
        const serial = revision; copying = true;
        try {
          if (!globalThis.navigator?.clipboard?.writeText) throw new Error('Clipboard unavailable');
          await globalThis.navigator.clipboard.writeText(text);
          if (serial === revision) notice.textContent = 'Validated ledger JSON copied to the clipboard. Review private data before sharing.';
        } catch {
          if (serial === revision) notice.textContent = 'Could not copy validated ledger JSON. Clipboard access is unavailable or denied; the local draft is unchanged.';
        } finally { copying = false; }
        return;
      }
      let url;
      try {
        url = URL.createObjectURL(new Blob([text], {type: 'application/json'}));
        const link = node('a'); link.href = url; link.download = 'opcode-ledger.json'; root.append(link);
        try { link.click(); } finally { link.remove(); }
      } catch { notice.textContent = 'Could not download validated ledger JSON. The local draft is unchanged.'; }
      finally { if (url) setTimeout(() => URL.revokeObjectURL(url), 1000); }
    }); download.disabled = true;
    const validateButton = button('Validate ledger', () => void validate());
    validateButton.className += ' vm-tool-primary';
    const createButton = button('Create empty ledger', () => void create());
    const clear = button('Clear all ledger inputs', () => {
      reads.definition++; reads.ledger++; pending.definition = false; pending.ledger = false; editors.definition.value = ''; editors.ledger.value = ''; report = null;
      invalidate(); empty(); for (const kind of ['definition', 'ledger']) { inputSummaries[kind].textContent = 'No file selected'; disclosures[kind].open = false; } notice.textContent = 'Local inputs and coverage cleared.'; files.definition.focus();
    });
    clear.className += ' vm-tool-tertiary';
    controls.append(createButton, validateButton, download, clear);
    const help = node('details', '', 'vm-tool-editor'); help.append(node('summary', 'Entry schema and research boundaries'));
    help.append(node('p', 'Edit entries in the JSON editor. Each opcode must exist in the definition. Observed/inferred require meaning and source_refs. Unmodeled requires null meaning. Passed/failed/inconclusive tests require test_refs; not_run requires none. Handler offsets are byte offsets. Nothing is fetched, verified, executed, uploaded or automatically saved.'));
    const sample = node('pre', JSON.stringify({opcode: '00', status: 'unmodeled', meaning: null, handler_location: null, operand_format: null, source_refs: [], test_status: 'not_run', test_refs: [], unresolved_questions: []}, null, 2));
    sample.style.whiteSpace = 'pre-wrap'; sample.style.overflowWrap = 'anywhere'; help.append(sample);
    root.append(controls, notice, coverageState, results, editorArea, help);
    return {editors, files, notice, results, validate, create, importFile, exportText, download, clear, getReport: () => report};
  }
  return {mount};
})();
if (typeof module === 'object' && module?.exports) module.exports = RebVmOpcodeLedgerView;
