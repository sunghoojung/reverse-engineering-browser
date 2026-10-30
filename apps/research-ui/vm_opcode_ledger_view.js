/* Local researcher assertions only. Imports, edits and exports never execute code. */
const RebVmOpcodeLedgerView = (() => {
  let mountSequence = 0;
  function mount(root, model = vmOpcodeLedger) {
    const node = (tag, text = '', className = '') => { const el = document.createElement(tag); el.textContent = text; el.className = className; return el; };
    root.className = 'vm-tool-shell';
    const inspectorId = `vm-ledger-inspector-${++mountSequence}`;
    const heading = node('h2', 'Opcode evidence ledger', 'vm-tool-title');
    const subtitle = node('p', 'Track what each opcode means, what supports it, and what remains unknown.', 'vm-tool-subtitle');
    const imports = node('div', '', 'vm-tool-imports');
    const editorArea = node('div', '', 'vm-tool-imports');
    const inputSummaries = {}, disclosures = {};
    const inputs = node('details', '', 'vm-tool-editor'); inputs.open = true; inputs.setAttribute('data-ledger-inputs', '');
    inputs.append(node('summary', 'Inputs · definition and evidence ledger'), imports);
    root.append(heading, subtitle, inputs);
    const button = (text, action) => { const el = node('button', text); el.type = 'button'; el.className = 'secondary-button'; el.addEventListener('click', action); return el; };
    const editors = {}, files = {}, reads = {definition: 0, ledger: 0};
    let revision = 0, report = null, current = false;
    const pageSize = 32;
    let filterText = '', statusFilter = 'all', page = 0, selectedOpcode = null, inspectorTab = 'Entry';
    let filterInput = null, listingBody = null, inspector = null, inspectorState = null, pageState = null, previousPage = null, nextPage = null;
    let filtered = [], entryByOpcode = new Map(), rowButtons = new Map(), inspectorTabButtons = new Map();
    const pending = {definition: false, ledger: false};
    const notice = node('p', 'Import a definition, then add a ledger or create an empty one.', 'vm-tool-status');
    notice.setAttribute('role', 'status'); notice.setAttribute('aria-live', 'polite');
    const coverageState = node('p', '', 'vm-tool-subtitle');
    const results = node('section', '', 'vm-tool-results'); results.setAttribute('aria-label', 'Opcode ledger coverage');
    const controls = node('div'); controls.className = 'vm-tool-toolbar';
    const invalidate = () => {
      revision++; current = false; download.disabled = true;
      if (inspectorState) inspectorState.textContent = 'Stale validated snapshot · current draft has not been validated.';
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
    const empty = () => {
      filterInput = null; listingBody = null; inspector = null; inspectorState = null;
      filtered = []; rowButtons = new Map(); selectedOpcode = null; page = 0;
      results.replaceChildren(node('h3', 'No validated ledger yet'), node('p', 'Import local JSON above, or create an empty ledger from a definition. Validation will reveal opcode coverage here.', 'vm-tool-empty'));
    };
    empty();
    // Locate the exact validated entry without reformatting or rewriting the draft.
    // The strict schema permits second-level objects only as entries; nested
    // reference/handler objects are deeper. Strings may contain braces or escapes.
    function entryRange(text, opcode) {
      let quoted = false, escaped = false, depth = 0, start = -1;
      for (let i = 0; i < text.length; i++) {
        const character = text[i];
        if (quoted) {
          if (escaped) escaped = false;
          else if (character === '\\') escaped = true;
          else if (character === '"') quoted = false;
          continue;
        }
        if (character === '"') quoted = true;
        else if (character === '{') { depth++; if (depth === 2) start = i; }
        else if (character === '}') {
          if (depth === 2 && start >= 0) {
            try { if (JSON.parse(text.slice(start, i + 1)).opcode === opcode) return [start, i + 1]; }
            catch { return null; }
          }
          depth--;
        }
      }
      return null;
    }
    function editSelected() {
      disclosures.ledger.open = true;
      editors.ledger.focus();
      const range = current ? entryRange(editors.ledger.value, selectedOpcode) : null;
      if (range) editors.ledger.setSelectionRange?.(...range);
      editors.ledger.scrollIntoView?.({block: 'nearest'});
      notice.textContent = !current ? 'Ledger editor opened. The inspector is a stale snapshot; validate this draft before locating an entry.' :
        range ? `Selected opcode ${selectedOpcode} in the exact JSON draft. Edits require validation before export.` :
          `Opcode ${selectedOpcode} has no ledger entry. Add an entry deliberately in the JSON editor, then validate. No entry was inserted.`;
    }
    function renderInspector() {
      if (!inspector) return;
      inspector.replaceChildren(); inspectorTabButtons = new Map();
      const coverage = filtered.find(entry => entry.opcode === selectedOpcode);
      if (!coverage) {
        inspector.append(node('h3', 'No opcode selected'), node('p', 'No declared opcodes match these filters. Clear the filters to inspect coverage.', 'vm-tool-empty'));
        return;
      }
      const entry = entryByOpcode.get(coverage.opcode);
      inspector.append(node('h3', `Opcode ${coverage.opcode}`));
      inspectorState = node('p', current ? 'Validated snapshot · researcher assertions only.' : 'Stale validated snapshot · current draft has not been validated.', 'vm-tool-subtitle');
      const edit = button(entry ? 'Edit selected entry' : 'Open JSON editor to add entry', editSelected); edit.setAttribute('data-ledger-action', 'edit-selected');
      inspector.append(inspectorState, edit);
      const tabs = node('div', '', 'vm-review-tabs'); tabs.setAttribute('role', 'tablist'); tabs.setAttribute('aria-label', 'Opcode inspector');
      const sections = ['Entry', 'References', 'Questions', 'Identity', 'Exact JSON'];
      const activateTab = title => { inspectorTab = title; renderInspector(); inspectorTabButtons.get(title)?.focus(); };
      for (const title of sections) {
        const tab = button(title, () => activateTab(title));
        tab.id = `${inspectorId}-tab-${sections.indexOf(title)}`;
        tab.setAttribute('role', 'tab'); tab.setAttribute('aria-selected', String(inspectorTab === title));
        tab.setAttribute('aria-controls', `${inspectorId}-panel`); tab.tabIndex = inspectorTab === title ? 0 : -1;
        tab.addEventListener('keydown', event => {
          if (event.isComposing || event.altKey || event.ctrlKey || event.metaKey) return;
          if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
          event.preventDefault();
          const index = sections.indexOf(title);
          activateTab(sections[event.key === 'Home' ? 0 : event.key === 'End' ? sections.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + sections.length) % sections.length]);
        });
        inspectorTabButtons.set(title, tab); tabs.append(tab);
      }
      inspector.append(tabs);
      const panel = node('section'); panel.id = `${inspectorId}-panel`; panel.setAttribute('role', 'tabpanel'); panel.setAttribute('aria-label', inspectorTab); panel.setAttribute('aria-labelledby', `${inspectorId}-tab-${sections.indexOf(inspectorTab)}`);
      const field = (title, value) => { const item = node('div', '', 'vm-review-field'); item.append(node('h4', title), node('p', value)); panel.append(item); };
      const json = value => { const pre = node('pre', JSON.stringify(value, null, 2), 'vm-review-json'); pre.style.whiteSpace = 'pre-wrap'; pre.style.overflowWrap = 'anywhere'; panel.append(pre); };
      if (inspectorTab === 'Entry') {
        field('Evidence status', `${coverage.status}${entry ? ' · supplied researcher label' : ' · missing entry'}`);
        field('Asserted meaning', entry?.meaning ?? 'null · no asserted meaning');
        field('Declared operation', coverage.declared_operation);
        field('Handler location', entry?.handler_location ? `Artifact ${entry.handler_location.artifact_id} · byte offset ${entry.handler_location.byte_offset}` : 'null · no handler location supplied');
        field('Operand format note', entry?.operand_format ?? 'null · no operand note supplied');
        field('Definition operand endianness', coverage.operand_endianness);
        panel.append(node('h4', 'Definition operands')); json(coverage.definition_operands);
        field('Supplied test status', `${coverage.test_status} · tests were not executed here`);
        if (!entry) panel.append(node('p', 'This declared opcode has no ledger entry. Missing entries are not inserted into exports.', 'vm-tool-empty'));
      } else if (inspectorTab === 'References') {
        field('Supplied test status', `${coverage.test_status} · unverified supplied outcome; tests were not executed here`);
        for (const [title, refs] of [['Source references', entry?.source_refs ?? []], ['Test references', entry?.test_refs ?? []]]) {
          panel.append(node('h4', `${title} (${refs.length})`));
          if (!refs.length) panel.append(node('p', 'None supplied.'));
          const list = node('ul');
          for (const ref of refs) list.append(node('li', `Artifact ${ref.artifact_id} · event ${ref.event_id === null ? 'null (not supplied)' : ref.event_id}`));
          panel.append(list);
        }
        panel.append(node('p', 'References are unresolved researcher citations. They are not fetched or independently verified.', 'vm-tool-subtitle'));
      } else if (inspectorTab === 'Questions') {
        const questions = entry?.unresolved_questions ?? [];
        panel.append(node('h4', `Unresolved questions (${questions.length})`));
        if (!questions.length) panel.append(node('p', 'No questions supplied. This does not establish that the opcode is understood.'));
        const list = node('ol'); for (const question of questions) list.append(node('li', question)); panel.append(list);
      } else if (inspectorTab === 'Identity') {
        field('Ledger format', report.ledger.format);
        field('Definition identity', report.ledger.definition_id);
        field('Exact definition source SHA-256', report.definition_source_sha256);
        field('Exact ledger source SHA-256', report.source_sha256);
        field('Coverage denominator', `${report.coverage.denominator} · ${report.coverage.total} declared opcodes`);
        panel.append(node('p', 'This identity binds exact definition bytes, not a runtime trace, bytecode image, session or authenticity claim.', 'vm-tool-subtitle'));
      } else {
        panel.append(node('h4', 'Complete validated entry JSON'));
        if (entry) json(entry);
        else panel.append(node('p', 'No entry exists. Coverage defaults are not a stored ledger entry.'));
      }
      inspector.append(panel);
    }
    function selectOpcode(opcode, focus = false) {
      const index = filtered.findIndex(entry => entry.opcode === opcode);
      if (index < 0) return;
      selectedOpcode = opcode; page = Math.floor(index / pageSize);
      renderListing(); renderInspector();
      if (focus) rowButtons.get(opcode)?.focus();
    }
    function moveSelection(delta, focus = false) {
      if (!filtered.length) return;
      const index = Math.max(0, filtered.findIndex(entry => entry.opcode === selectedOpcode));
      selectOpcode(filtered[Math.max(0, Math.min(filtered.length - 1, index + delta))].opcode, focus);
    }
    function renderListing() {
      if (!listingBody) return;
      listingBody.replaceChildren(); rowButtons = new Map();
      const start = page * pageSize, visible = filtered.slice(start, start + pageSize);
      pageState.textContent = filtered.length ? `${start + 1}–${start + visible.length} of ${filtered.length} matching opcodes · ${report.coverage.total} declared` : `0 matching opcodes · ${report.coverage.total} declared`;
      previousPage.disabled = page === 0; nextPage.disabled = start + pageSize >= filtered.length;
      for (const entry of visible) {
        const row = node('tr'); const selected = entry.opcode === selectedOpcode;
        row.className = selected ? 'is-selected' : ''; row.setAttribute('data-ledger-opcode', entry.opcode);
        row.setAttribute('aria-current', String(selected)); row.setAttribute('aria-selected', String(selected));
        const opcodeCell = node('td'), pick = button(entry.opcode, () => selectOpcode(entry.opcode, true));
        pick.setAttribute('aria-label', `Inspect opcode ${entry.opcode}`); pick.setAttribute('aria-pressed', String(selected)); pick.tabIndex = selected ? 0 : -1;
        pick.addEventListener('keydown', event => {
          if (event.isComposing || event.altKey || event.ctrlKey || event.metaKey) return;
          if (!['ArrowDown', 'ArrowUp', 'Home', 'End', 'PageDown', 'PageUp'].includes(event.key)) return;
          event.preventDefault();
          if (event.key === 'Home' || event.key === 'End') selectOpcode(filtered[event.key === 'Home' ? 0 : filtered.length - 1].opcode, true);
          else moveSelection(({ArrowDown: 1, ArrowUp: -1, PageDown: pageSize, PageUp: -pageSize})[event.key], true);
        });
        rowButtons.set(entry.opcode, pick); opcodeCell.append(pick);
        row.addEventListener('click', event => { if (event.target !== pick) selectOpcode(entry.opcode, true); });
        row.append(opcodeCell, node('td', `${entry.status}${entry.entry_present ? '' : ' · missing entry'}`));
        const meaning = node('td'); meaning.append(node('span', entry.meaning ?? 'No asserted meaning'), node('small', `Declared operation: ${entry.declared_operation}`));
        row.append(meaning, node('td', entry.test_status)); listingBody.append(row);
      }
      if (!visible.length) { const row = node('tr'), cell = node('td', 'No opcodes match. Change or clear the filters.'); cell.setAttribute('colspan', '4'); row.append(cell); listingBody.append(row); }
    }
    function applyFilters() {
      const query = filterText.trim().toLowerCase();
      filtered = report.coverage.opcodes.filter(entry => (statusFilter === 'all' || (statusFilter === 'missing' ? !entry.entry_present : entry.status === statusFilter)) &&
        (!query || JSON.stringify([entry, entryByOpcode.get(entry.opcode) ?? null]).toLowerCase().includes(query)));
      if (!filtered.some(entry => entry.opcode === selectedOpcode)) selectedOpcode = filtered[0]?.opcode ?? null;
      page = Math.max(0, Math.floor(filtered.findIndex(entry => entry.opcode === selectedOpcode) / pageSize));
      renderListing(); renderInspector();
    }
    function render() {
      results.replaceChildren(); entryByOpcode = new Map(report.ledger.entries.map(entry => [entry.opcode, entry]));
      const counts = report.coverage.counts;
      results.append(node('h3', `${report.coverage.total} declared opcodes`));
      results.append(node('p', `${counts.observed} observed · ${counts.inferred} inferred · ${counts.unmodeled} unmodeled · ${counts.missing_entries} missing entries`, 'vm-tool-subtitle'));
      results.append(node('p', 'Researcher assertions only. Coverage does not establish runtime execution; references and supplied test outcomes are unverified.', 'vm-tool-subtitle'));
      const filters = node('div', '', 'vm-tool-toolbar vm-review-filter'), searchLabel = node('label', 'Filter opcode coverage');
      filterInput = node('input'); filterInput.type = 'search'; filterInput.maxLength = 1024; filterInput.value = filterText; filterInput.placeholder = 'Opcode, meaning, artifact or question'; filterInput.setAttribute('aria-label', 'Filter opcode coverage');
      filterInput.addEventListener('input', () => { filterText = filterInput.value; applyFilters(); }); searchLabel.append(filterInput);
      const statusLabel = node('label', 'Evidence status'), status = node('select'); status.setAttribute('aria-label', 'Filter evidence status');
      for (const [value, label] of [['all', 'All statuses'], ['observed', 'Observed'], ['inferred', 'Inferred'], ['unmodeled', 'Unmodeled'], ['missing', 'Missing entries']]) { const option = node('option', label); option.value = value; status.append(option); }
      status.value = statusFilter; status.addEventListener('change', () => { statusFilter = status.value; applyFilters(); }); statusLabel.append(status);
      filters.append(searchLabel, statusLabel, button('Clear coverage filters', () => { filterText = ''; statusFilter = 'all'; filterInput.value = ''; status.value = 'all'; applyFilters(); filterInput.focus(); }));
      results.append(filters);
      const workbench = node('div', '', 'vm-review-workbench'), listing = node('section', '', 'vm-review-listing'); listing.setAttribute('aria-label', 'Declared opcode listing');
      const paging = node('div', '', 'vm-tool-toolbar');
      pageState = node('p', '', 'vm-tool-subtitle'); pageState.setAttribute('role', 'status'); pageState.setAttribute('aria-live', 'polite');
      previousPage = button('Previous page', () => { if (page > 0) selectOpcode(filtered[(page - 1) * pageSize].opcode, true); });
      nextPage = button('Next page', () => { if ((page + 1) * pageSize < filtered.length) selectOpcode(filtered[(page + 1) * pageSize].opcode, true); });
      previousPage.setAttribute('aria-label', 'Previous opcode coverage page'); nextPage.setAttribute('aria-label', 'Next opcode coverage page');
      paging.append(previousPage, pageState, nextPage); listing.append(paging);
      const table = node('table', '', 'vm-tool-table'), head = node('thead'), header = node('tr'); listingBody = node('tbody');
      for (const title of ['Opcode', 'Evidence status', 'Asserted meaning', 'Supplied tests']) { const cell = node('th', title); cell.setAttribute('scope', 'col'); header.append(cell); }
      head.append(header); table.append(head, listingBody); listing.append(table);
      inspector = node('aside', '', 'vm-review-inspector'); inspector.setAttribute('aria-label', 'Selected opcode inspector');
      workbench.append(listing, inspector); results.append(workbench); applyFilters();
    }
    root.addEventListener('vm-workspace-query', event => {
      if (!event.detail) return;
      const index = filtered.findIndex(entry => entry.opcode === selectedOpcode);
      Object.assign(event.detail, {search: !!filterInput, previous: index > 0, next: index >= 0 && index < filtered.length - 1});
    });
    root.addEventListener('vm-workspace-search', () => { filterInput?.focus(); });
    root.addEventListener('vm-workspace-next', () => moveSelection(1, true));
    root.addEventListener('vm-workspace-previous', () => moveSelection(-1, true));
    async function validate() {
      if (pending.definition || pending.ledger) { notice.textContent = 'Wait for the selected file to finish loading.'; return; }
      const serial = ++revision; current = false; download.disabled = true;
      if (inspectorState) inspectorState.textContent = 'Stale validated snapshot · current draft has not been validated.';
      coverageState.textContent = report ? 'Previous coverage is stale and does not describe the current draft.' : '';
      notice.textContent = 'Validating schema and exact definition identity…';
      try {
        const next = await model.inspectLedger(editors.ledger.value, editors.definition.value);
        if (serial !== revision) return;
        report = next; current = true; render(); inputs.open = false; download.disabled = false; coverageState.textContent = 'Validated coverage for the current draft.';
        notice.textContent = 'Valid ledger. References are unverified and tests were not executed. Review private data before exporting.';
      } catch (error) { if (serial === revision) notice.textContent = `Validation refused: ${error.message}${report ? ' Previous coverage is stale.' : ''}`; }
    }
    async function create() {
      if (pending.definition || pending.ledger) { notice.textContent = 'Wait for the selected file to finish loading.'; return; }
      if (editors.ledger.value.trim()) { notice.textContent = 'Clear the ledger editor deliberately before creating a new ledger; existing work was kept.'; return; }
      const serial = ++revision; current = false; download.disabled = true;
      if (inspectorState) inspectorState.textContent = 'Stale validated snapshot · current draft has not been validated.';
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
      filterText = ''; statusFilter = 'all'; inspectorTab = 'Entry'; inputs.open = true;
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
