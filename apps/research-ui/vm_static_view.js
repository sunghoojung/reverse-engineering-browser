/* Local, bounded declarative decoding. This view never evaluates imported code,
 * creates a live session, or treats a supplied definition as recovered truth. */
function vmStaticOwnedExample() {
  const operand = (name, kind, width = 1, signed = false) => ({name, kind, width, signed});
  const instruction = (code, mnemonic, operands, operation, args, flow = {kind: 'next'}) =>
    ({code, mnemonic, operands, semantics: {operation, args}, flow});
  const definition = {format: 'reb-vm-definition-v1', definition_id: 'owned-static-example',
    architecture: 'register', opcode_bytes: 1, operand_endianness: 'little', register_count: 4,
    opcodes: [
      instruction('01', 'CONST', [operand('dst', 'register'), operand('value', 'immediate', 1, true)], 'register_const', ['dst', 'value']),
      instruction('02', 'ADD', [operand('dst', 'register'), operand('left', 'register'), operand('right', 'register')], 'register_add', ['dst', 'left', 'right']),
      instruction('03', 'JZ', [operand('test', 'register'), operand('target', 'address', 2)], 'branch_zero', ['test'], {kind: 'branch', target: {operand: 'target', base: 'absolute'}}),
      instruction('04', 'JMP', [operand('target', 'address', 2)], 'jump', [], {kind: 'jump', target: {operand: 'target', base: 'absolute'}}),
      instruction('ff', 'HALT', [], 'halt', [], {kind: 'halt'})
    ]};
  const bytes = [];
  for (let index = 0; index < 12; index++) bytes.push(1, index % 4, index);
  bytes.push(2, 0, 1, 2, 3, 0, 47, 0, 4, 0, 0, 255);
  return {definition, image: {format: 'reb-vm-bytecode-v1', image_id: 'owned-static-loop',
    definition_id: definition.definition_id, entry_offsets: [0], bytes_hex: bytes.map(value => value.toString(16).padStart(2, '0')).join('')}};
}

function mountVmStatic(root, model = vmStatic) {
  const pageSize = 64, graphPageSize = 32, maximumFileBytes = 1048576;
  const node = (tag, text = '', className = '') => {
    const element = document.createElement(tag); element.textContent = text; element.className = className; return element;
  };
  const button = (text, action) => {
    const element = node('button', text, 'secondary-button'); element.type = 'button'; element.addEventListener('click', action); return element;
  };
  const hex = offset => `0x${offset.toString(16).padStart(4, '0')}`;
  const inputs = {definition: null, image: null}, serials = {definition: 0, image: 0};
  const pending = {definition: false, image: false};
  let report = null, analysisSerial = 0, analyzing = false, selected = null, page = 0, graphPage = 0;
  let tab = 'pseudocode', panel = 'listing', layout = 'wide', auditPage = 0, diagnosticPage = 0, auditText = '', renderedSelection = null;
  const fileInputs = {}, inputStatus = {}, tabButtons = {}, panelButtons = {};
  const toolbar = node('div', '', 'vm-static-toolbar');
  const summary = node('div', '', 'vm-static-summary');
  const notice = node('p', '', 'vm-static-notice'); notice.setAttribute('role', 'status'); notice.setAttribute('aria-live', 'polite');
  const modeLabel = node('strong', 'Static bytecode · declared semantics');
  const sourceSummary = node('p', 'Select a definition and bytecode image JSON, then Analyze. Files stay local.');
  summary.append(modeLabel, sourceSummary, notice);
  const body = node('div', '', 'vm-static-body');
  const listing = node('section', '', 'vm-static-listing'); listing.setAttribute('aria-label', 'Static address listing');
  const listingHead = node('div', '', 'vm-static-listing-head');
  const filter = node('input'); filter.type = 'search'; filter.maxLength = 256; filter.placeholder = 'Find address, bytes or instruction';
  filter.setAttribute('aria-label', 'Filter static bytecode instructions');
  const listingStatus = node('p', '', 'vm-static-muted');
  const columns = node('div', '', 'vm-static-columns');
  for (const text of ['Byte offset', 'Bytes', 'Instruction', 'Meaning']) columns.append(node('span', text));
  const listingRows = node('div', '', 'vm-static-rows'); listingRows.setAttribute('role', 'listbox'); listingRows.setAttribute('aria-label', 'Decoded bytecode instructions');
  const listingPager = node('div', '', 'vm-static-pager');
  const inspector = node('section', '', 'vm-static-inspector'); inspector.setAttribute('aria-label', 'Static instruction details');
  const selectedTitle = node('h2', 'No decoded instruction selected');
  const tabs = node('div', '', 'vm-static-tabs'); tabs.setAttribute('role', 'tablist'); tabs.setAttribute('aria-label', 'Static analysis detail');
  const detail = node('div', '', 'vm-static-detail'); detail.id = 'vm-static-detail-panel'; detail.setAttribute('role', 'tabpanel'); detail.tabIndex = 0;
  const inside = (parent, element) => parent.contains?.(element) === true;
  const instructions = () => report?.instructions ?? [];
  const selectedInstruction = () => instructions().find(instruction => instruction.offset === selected);
  const matches = () => {
    const query = filter.value.trim().toLowerCase();
    return instructions().filter(instruction => !query || [instruction.offset, hex(instruction.offset), instruction.bytes_hex,
      instruction.mnemonic, instruction.semantics_status, ...instruction.operands.map(operand => `${operand.name} ${operand.value}`)].join(' ').toLowerCase().includes(query));
  };
  const setPanel = (next, focus = false) => {
    panel = next; root.setAttribute('data-panel', panel);
    for (const [key, element] of Object.entries(panelButtons)) element.setAttribute('aria-pressed', String(key === panel));
    if (focus) (next === 'listing' ? filter : tabButtons[tab]).focus();
  };
  const focusRow = () => {
    setPanel('listing');
    const match = Array.from(listingRows.children).find(element => element.getAttribute('data-vm-static-offset') === String(selected));
    if (match) { match.focus(); match.scrollIntoView?.({block: 'nearest'}); } else filter.focus();
  };
  function select(offset, options = {}) {
    if (!instructions().some(instruction => instruction.offset === offset)) return;
    selected = offset;
    if (options.reveal) {
      filter.value = ''; const index = instructions().findIndex(instruction => instruction.offset === offset); page = Math.floor(index / pageSize);
    }
    const graphIndex = report.cfg.nodes.findIndex(item => item.offset === offset); graphPage = Math.max(0, Math.floor(graphIndex / graphPageSize));
    renderListing(); renderDetails();
    if (options.focus) focusRow();
  }
  const reveal = button('Reveal selected', () => { if (selected !== null) select(selected, {reveal: true, focus: true}); });
  const rowKey = (event, offset) => {
    if (event.isComposing || event.altKey || event.ctrlKey || event.metaKey) return;
    const rows = matches(), index = rows.findIndex(instruction => instruction.offset === offset); let next = index;
    if (event.key === 'ArrowDown') next = Math.min(rows.length - 1, index + 1);
    else if (event.key === 'ArrowUp') next = Math.max(0, index - 1);
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = rows.length - 1;
    else if (event.key === 'PageDown') next = Math.min(rows.length - 1, index + pageSize);
    else if (event.key === 'PageUp') next = Math.max(0, index - pageSize);
    else if (event.key === 'Enter') { event.preventDefault(); setPanel('details', true); return; }
    else return;
    event.preventDefault(); if (!rows[next]) return; page = Math.floor(next / pageSize); select(rows[next].offset, {focus: true});
  };
  function pager(target, total, current, size, label, choose) {
    const pages = Math.max(1, Math.ceil(total / size));
    const previous = button(`Previous ${label} page`, () => choose(current - 1, 'previous'));
    const next = button(`Next ${label} page`, () => choose(current + 1, 'next'));
    previous.disabled = current === 0; next.disabled = current >= pages - 1;
    target.append(previous, node('span', `${total ? current * size + 1 : 0}–${Math.min(total, (current + 1) * size)} of ${total} · ${current + 1}/${pages}`), next);
    return direction => { if (direction) (direction === 'previous' ? previous.disabled ? next : previous : next.disabled ? previous : next).focus(); };
  }
  function renderListing(direction) {
    const rows = matches(); page = Math.min(page, Math.max(0, Math.ceil(rows.length / pageSize) - 1));
    const rowFocused = inside(listingRows, document.activeElement);
    listingRows.replaceChildren(); listingPager.replaceChildren();
    reveal.disabled = selected === null;
    listingStatus.textContent = report ? `${rows.length}/${instructions().length} decoded instructions${selected !== null && !rows.some(instruction => instruction.offset === selected) ? ' · selected instruction hidden by filter' : ''}` : 'No analysis loaded';
    if (!rows.length) listingRows.append(node('p', report ? 'No matching decoded instructions. Clear the filter or inspect Inputs and limits.' : 'No bytecode is decoded until you choose Analyze.', 'vm-static-empty'));
    const visible = rows.slice(page * pageSize, (page + 1) * pageSize);
    for (const instruction of visible) {
      const row = button('', () => select(instruction.offset)); row.className = 'vm-static-row'; row.setAttribute('role', 'option');
      row.setAttribute('data-vm-static-offset', String(instruction.offset)); row.setAttribute('aria-selected', String(instruction.offset === selected));
      row.tabIndex = instruction.offset === selected || !visible.some(item => item.offset === selected) && instruction === visible[0] ? 0 : -1;
      const values = [hex(instruction.offset), instruction.bytes_hex.match(/.{1,2}/g).slice(0, 8).join(' ') + (instruction.size > 8 ? ' …' : ''),
        `${instruction.mnemonic} ${instruction.operands.map(operand => `${operand.name}=${operand.value}`).join(', ')}`.trim(), instruction.semantics_status === 'unknown' ? 'Unknown' : 'Declared'];
      values.forEach((text, index) => { const cell = node('span', text); cell.setAttribute('data-label', ['Byte offset', 'Bytes', 'Instruction', 'Meaning'][index]); row.append(cell); });
      row.addEventListener('keydown', event => rowKey(event, instruction.offset)); listingRows.append(row);
    }
    const restore = pager(listingPager, rows.length, page, pageSize, 'instructions', (next, focus) => { page = next; renderListing(focus); });
    restore(direction); if (rowFocused && !direction) focusRow();
  }
  const field = (target, label, value) => { const item = node('div', '', 'vm-static-field'); item.append(node('dt', label), node('dd', value)); target.append(item); };
  const raw = (target, label, value, exactText = false) => {
    const disclosure = node('details', '', 'vm-static-audit'); disclosure.append(node('summary', label));
    const content = node('pre'); disclosure.append(content);
    disclosure.addEventListener('toggle', () => { content.textContent = disclosure.open ? exactText ? value : JSON.stringify(value, null, 2) : ''; }); target.append(disclosure);
  };
  function addressLink(offset, label = hex(offset), focusListing = false) {
    return button(label, () => { select(offset, {reveal: true, focus: focusListing}); if (!focusListing) { setPanel('details'); tabButtons[tab].focus(); } });
  }
  function renderInstruction(instruction) {
    if (!instruction) { detail.append(node('p', 'No decoded instruction is selected. Undecoded bytes have no inferred instruction or semantics.')); return; }
    const fields = node('dl');
    field(fields, 'Byte range', `[${instruction.offset}, ${instruction.offset + instruction.size}) · ${instruction.size} bytes`);
    field(fields, 'Complete instruction bytes', instruction.bytes_hex.match(/.{1,2}/g).join(' '));
    field(fields, 'Opcode', instruction.opcode);
    field(fields, 'Semantics', instruction.semantics_status === 'declared' ? `${instruction.operation} · supplied declaration, unverified` : 'Unknown · pseudocode unavailable');
    field(fields, 'Declared flow', instruction.flow.kind);
    detail.append(fields, node('h3', 'Decoded operands'));
    if (!instruction.operands.length) detail.append(node('p', 'No operands declared.'));
    for (const operand of instruction.operands) detail.append(node('p', `${operand.name}: ${operand.value} · ${operand.kind} · ${operand.signed ? 'signed' : 'unsigned'} ${operand.width * 8}-bit · bytes [${operand.offset}, ${operand.offset + operand.width}) = ${operand.bytes_hex}`));
    raw(detail, 'Raw selected instruction', instruction);
  }
  function renderPseudocode(instruction) {
    detail.append(node('p', 'Instruction-linked pseudocode from declared operations. It is unverified and does not establish runtime behavior or equivalence.', 'vm-static-muted'));
    if (!report?.pseudocode.length) { detail.append(node('p', 'Pseudocode unavailable. No supported instruction semantics were decoded.')); return; }
    const selectedIndex = instructions().findIndex(item => item.offset === selected), start = Math.max(0, Math.floor(selectedIndex / pageSize) * pageSize);
    const offsets = new Set(instructions().slice(start, start + pageSize).map(item => item.offset));
    detail.append(node('p', `Instruction window ${start + 1}–${Math.min(instructions().length, start + pageSize)} of ${instructions().length}. Address listing pages independently.`, 'vm-static-muted'));
    for (const line of report.pseudocode.filter(item => offsets.has(item.offset))) {
      const row = addressLink(line.offset, `${hex(line.offset)}  ${line.status === 'unknown' ? 'Pseudocode unavailable · unknown semantics' : line.text}`);
      row.className = 'vm-static-code-line'; row.setAttribute('data-vm-static-pseudocode', String(line.offset)); row.setAttribute('aria-pressed', String(line.offset === selected)); detail.append(row);
    }
    if (instruction) raw(detail, 'Raw selected pseudocode', instruction.pseudocode);
  }
  function renderGraph(direction) {
    detail.append(node('p', 'Declared static CFG · instruction-level nodes. Arrows are declared alternatives, not observed transitions. Indirect targets and return destinations remain unknown.', 'vm-static-muted'));
    if (!report) { detail.append(node('p', 'No static CFG is available.')); return; }
    const nodes = report.cfg.nodes; graphPage = Math.min(graphPage, Math.max(0, Math.ceil(nodes.length / graphPageSize) - 1));
    const graphPager = node('div', '', 'vm-static-pager'); detail.append(graphPager);
    const restore = pager(graphPager, nodes.length, graphPage, graphPageSize, 'CFG nodes', (next, focus) => { graphPage = next; renderDetails(focus); });
    for (const item of nodes.slice(graphPage * graphPageSize, (graphPage + 1) * graphPageSize)) {
      const card = node('article', '', 'vm-static-cfg-node'); card.setAttribute('data-vm-static-node', String(item.offset)); card.setAttribute('data-selected', String(item.offset === selected));
      const instruction = instructions().find(candidate => candidate.offset === item.offset);
      card.append(addressLink(item.offset, `${hex(item.offset)} · ${instruction.mnemonic}`), node('span', item.reachable ? 'Reachable under declarations' : 'Not reached by declared entry graph', 'vm-static-muted'));
      const edges = report.cfg.edges.filter(edge => edge.from_offset === item.offset);
      if (!edges.length) card.append(node('p', instruction.flow.kind === 'halt' ? 'Declared halt · no successor' : 'No declared outgoing edge'));
      for (const edge of edges) {
        const row = node('p', '', 'vm-static-edge'), label = `${edge.kind.replaceAll('_', ' ')} → `;
        row.append(node('span', label));
        if (edge.status === 'resolved') row.append(addressLink(edge.to_offset));
        else row.append(node('span', `${edge.to_offset === null ? 'unknown destination' : hex(edge.to_offset)} · ${edge.status.replaceAll('_', ' ')}`));
        card.append(row);
      }
      detail.append(card);
    }
    if (!nodes.length) detail.append(node('p', 'No decoded CFG nodes.'));
    restore(direction);
  }
  function renderInputs(direction) {
    detail.append(node('p', 'Definitions and image IDs are supplied claims. Imports do not attach to captured findings or authenticate an origin. Only fixed declarative operations are supported; imported text is never executed.'));
    const fields = node('dl');
    for (const kind of ['definition', 'image']) field(fields, `${kind === 'definition' ? 'Definition' : 'Bytecode image'} input`, inputs[kind] ? `${inputs[kind].name} · ${inputs[kind].bytes} UTF-8 bytes · ${inputs[kind].source}` : 'Not loaded');
    if (report) {
      field(fields, 'Definition ID', report.definition.definition_id); field(fields, 'Image ID', report.image.image_id);
      field(fields, 'Exact definition JSON SHA-256', report.provenance.definition_source_sha256 ?? 'Unavailable: no exact source text');
      field(fields, 'Canonical definition SHA-256', report.provenance.definition_canonical_sha256);
      field(fields, 'Exact image JSON SHA-256', report.provenance.image_source_sha256 ?? 'Unavailable: no exact source text');
      field(fields, 'Decoded image bytes SHA-256', report.provenance.image_bytes_sha256);
      field(fields, 'Decode coverage', `${report.coverage.decoded_bytes}/${report.coverage.total_bytes} bytes · ${report.coverage.instruction_count} instructions · stop: ${report.coverage.stop_reason} · ${report.coverage.undecoded_bytes} bytes undecoded`);
      field(fields, 'CFG completeness', 'Unknown. Declared reachability does not prove actual control flow.');
    }
    detail.append(fields);
    if (!report) { detail.append(node('p', 'Choose Analyze to compute source hashes, decode coverage, CFG and declared pseudocode.')); return; }
    detail.append(node('h3', 'Limits and unsupported state'));
    for (const warning of report.warnings) detail.append(node('p', warning));
    diagnosticPage = Math.min(diagnosticPage, Math.max(0, Math.ceil(report.diagnostics.length / pageSize) - 1));
    const diagnosticPager = node('div', '', 'vm-static-pager'); detail.append(diagnosticPager);
    const restore = pager(diagnosticPager, report.diagnostics.length, diagnosticPage, pageSize, 'diagnostics', (next, focus) => { diagnosticPage = next; renderDetails(focus); });
    for (const diagnostic of report.diagnostics.slice(diagnosticPage * pageSize, (diagnosticPage + 1) * pageSize)) {
      const row = node('p', `${diagnostic.offset === null ? '' : hex(diagnostic.offset) + ' · '}${diagnostic.code}: ${diagnostic.message}`);
      row.setAttribute('data-vm-static-diagnostic', 'true'); detail.append(row);
    }
    restore(direction);
    for (const entry of report.cfg.entries) detail.append(node('p', `Entry ${hex(entry.offset)} · ${entry.status}`));
    raw(detail, 'Exact definition JSON text', inputs.definition.text, true); raw(detail, 'Exact bytecode JSON text', inputs.image.text, true);
    const audit = node('details', '', 'vm-static-audit'); audit.append(node('summary', 'Complete analysis raw audit'));
    const auditContent = node('pre'), auditPager = node('div', '', 'vm-static-pager'); audit.append(auditPager, auditContent);
    const drawAudit = direction => {
      auditPager.replaceChildren(); const size = 32768;
      const restore = pager(auditPager, auditText.length, auditPage, size, 'raw audit characters', (next, focus) => { auditPage = next; drawAudit(focus); });
      auditContent.textContent = auditText.slice(auditPage * size, (auditPage + 1) * size); restore(direction);
    };
    audit.addEventListener('toggle', () => { if (audit.open) { if (!auditText) auditText = JSON.stringify(report, null, 2); drawAudit(); } else { auditPager.replaceChildren(); auditContent.textContent = ''; } }); detail.append(audit);
  }
  function renderDetails(direction) {
    const scroll = detail.scrollTop, instruction = selectedInstruction(); detail.replaceChildren();
    selectedTitle.textContent = instruction ? `${hex(instruction.offset)} · ${instruction.mnemonic}` : 'No decoded instruction selected';
    detail.setAttribute('aria-labelledby', `vm-static-tab-${tab}`);
    if (tab === 'instruction') renderInstruction(instruction);
    else if (tab === 'pseudocode') renderPseudocode(instruction);
    else if (tab === 'cfg') renderGraph(direction);
    else renderInputs(direction);
    detail.scrollTop = scroll;
    if (selected !== renderedSelection && (tab === 'pseudocode' || tab === 'cfg')) {
      const attribute = tab === 'cfg' ? 'data-vm-static-node' : 'data-vm-static-pseudocode';
      Array.from(detail.children).find(element => element.getAttribute(attribute) === String(selected))?.scrollIntoView?.({block: 'nearest'});
    }
    renderedSelection = selected;
  }
  const setTab = (next, focus = false) => {
    tab = next;
    for (const [key, element] of Object.entries(tabButtons)) { element.setAttribute('aria-selected', String(key === tab)); element.tabIndex = key === tab ? 0 : -1; }
    detail.scrollTop = 0; renderedSelection = null; renderDetails(); setPanel('details'); if (focus) tabButtons[tab].focus();
  };
  for (const [key, label] of [['instruction', 'Instruction'], ['pseudocode', 'Pseudocode'], ['cfg', 'Static CFG'], ['inputs', 'Inputs and limits']]) {
    const control = button(label, () => setTab(key)); control.id = `vm-static-tab-${key}`; control.setAttribute('role', 'tab'); control.setAttribute('aria-controls', detail.id);
    control.addEventListener('keydown', event => {
      if (event.isComposing || event.altKey || event.ctrlKey || event.metaKey) return;
      const keys = Object.keys(tabButtons), index = keys.indexOf(key); let next;
      if (event.key === 'ArrowRight') next = (index + 1) % keys.length;
      else if (event.key === 'ArrowLeft') next = (index + keys.length - 1) % keys.length;
      else if (event.key === 'Home') next = 0; else if (event.key === 'End') next = keys.length - 1; else return;
      event.preventDefault(); setTab(keys[next], true);
    }); tabButtons[key] = control; tabs.append(control);
  }
  const back = button('Back to selected address', () => { if (selected !== null) select(selected, {reveal: true, focus: true}); else setPanel('listing', true); });
  const update = () => {
    analyze.disabled = !inputs.definition || !inputs.image || pending.definition || pending.image || analyzing;
    analyze.textContent = analyzing ? 'Analyzing…' : 'Analyze';
    for (const kind of ['definition', 'image']) inputStatus[kind].textContent = pending[kind] ? 'Reading…' : inputs[kind] ? 'Loaded' : 'Choose JSON';
    sourceSummary.textContent = report ? `${report.definition.definition_id} / ${report.image.image_id} · ${report.coverage.decoded_bytes}/${report.coverage.total_bytes} bytes decoded · ${report.coverage.undecoded_bytes ? 'Unsupported bytes remain' : 'Declared semantics remain unverified'} · No code runs here.` :
      `${inputs.definition ? 'Definition ready' : 'Definition required'} · ${inputs.image ? 'Bytecode ready' : 'Bytecode required'} · Local static analysis only`;
    if (report && report.coverage.stop_reason !== 'end') sourceSummary.textContent += ` · stopped: ${report.coverage.stop_reason}`;
  };
  function invalidate() { analysisSerial++; analyzing = false; report = null; selected = null; page = graphPage = auditPage = diagnosticPage = 0; auditText = ''; renderListing(); renderDetails(); }
  async function importFile(kind, file) {
    if (!file) return;
    const owner = ++serials[kind]; pending[kind] = true; analysisSerial++; analyzing = false; update();
    try {
      if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > maximumFileBytes) throw Error('Select a JSON file from 1 byte to 1 MiB');
      const bytes = await file.arrayBuffer(); if (bytes.byteLength > maximumFileBytes || !bytes.byteLength) throw Error('File exceeds the 1 MiB bound or is empty');
      const text = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(bytes);
      if (owner !== serials[kind]) return;
      (kind === 'definition' ? model.parseDefinition : model.parseImage)(text);
      inputs[kind] = {text, name: String(file.name || `${kind}.json`).slice(0, 256), bytes: bytes.byteLength, source: 'selected local file'};
      invalidate(); notice.textContent = `${kind === 'definition' ? 'Definition' : 'Bytecode'} loaded. Choose Analyze when both inputs are ready.`;
    } catch (error) { if (owner === serials[kind]) notice.textContent = `Import refused: ${error.message}. Previous valid inputs${report ? ' and analysis' : ''} remain available.`; }
    finally { if (owner === serials[kind]) { pending[kind] = false; fileInputs[kind].value = ''; update(); } }
  }
  for (const [kind, label] of [['definition', 'Definition…'], ['image', 'Bytecode…']]) {
    const control = node('label', '', 'vm-static-file secondary-button'); control.append(node('span', label));
    const input = node('input'); input.type = 'file'; input.accept = '.json,application/json'; input.setAttribute('aria-label', `Import static VM ${kind === 'definition' ? 'definition' : 'bytecode image'} JSON`);
    input.addEventListener('change', () => importFile(kind, input.files?.[0])); fileInputs[kind] = input;
    const status = node('span', '', 'vm-static-input-state'); inputStatus[kind] = status; control.append(status, input); toolbar.append(control);
  }
  async function analyzeInputs() {
    if (!inputs.definition || !inputs.image || pending.definition || pending.image || analyzing) return;
    const owner = ++analysisSerial, definition = inputs.definition, image = inputs.image; analyzing = true; notice.textContent = 'Computing hashes and bounded static analysis…'; update();
    try {
      const result = await model.analyze(definition.text, image.text);
      if (owner !== analysisSerial || definition !== inputs.definition || image !== inputs.image) return;
      report = result; selected = instructions()[0]?.offset ?? null; page = graphPage = auditPage = diagnosticPage = 0; auditText = ''; filter.value = '';
      renderListing(); renderDetails(); notice.textContent = `${result.coverage.instruction_count} instructions decoded. ${result.coverage.undecoded_bytes ? `${result.coverage.undecoded_bytes} bytes unavailable; see Inputs and limits.` : 'Pseudocode and CFG reflect declarations only.'}`;
    } catch (error) { if (owner === analysisSerial) notice.textContent = `Analysis unavailable: ${error.message}. Inputs remain available; no code was executed.`; }
    finally { if (owner === analysisSerial) { analyzing = false; update(); } }
  }
  const analyze = button('Analyze', analyzeInputs); analyze.setAttribute('data-vm-static-action', 'analyze');
  const clear = button('Clear', () => {
    for (const kind of ['definition', 'image']) { serials[kind]++; pending[kind] = false; inputs[kind] = null; fileInputs[kind].value = ''; }
    filter.value = ''; invalidate(); notice.textContent = 'Local static inputs and analysis cleared.'; update(); setPanel('listing'); fileInputs.definition.focus();
  });
  const demo = button('Owned example', () => {
    const example = vmStaticOwnedExample();
    for (const kind of ['definition', 'image']) { serials[kind]++; pending[kind] = false; const text = JSON.stringify(example[kind]); inputs[kind] = {text, name: `${kind}-owned-example.json`, bytes: new TextEncoder().encode(text).length, source: 'authored example generated locally; not a capture'}; fileInputs[kind].value = ''; }
    invalidate(); notice.textContent = 'Owned authored example loaded. Choose Analyze to decode its declared loop and branch. This is not captured execution.'; update();
  });
  toolbar.append(analyze, demo, clear);
  const panelControls = node('nav', '', 'vm-static-panels'); panelControls.setAttribute('aria-label', 'Static analysis pane');
  for (const [key, label] of [['listing', 'Addresses'], ['details', 'Details']]) {
    const control = button(label, () => setPanel(key, true)); control.setAttribute('data-vm-static-panel', key); panelButtons[key] = control; panelControls.append(control);
  }
  toolbar.append(panelControls);
  const filterBar = node('div', '', 'vm-static-filter'); filterBar.append(filter, reveal);
  filter.addEventListener('input', () => { page = 0; renderListing(); });
  listingHead.append(node('h2', 'Bytecode addresses'), filterBar, listingStatus, columns); listing.append(listingHead, listingRows, listingPager);
  const detailHead = node('div', '', 'vm-static-detail-head'); detailHead.append(selectedTitle, tabs); inspector.append(detailHead, detail, back);
  body.append(listing, inspector); root.append(toolbar, summary, body);
  root.addEventListener('keydown', event => { if (event.key === 'Escape' && layout === 'narrow' && panel === 'details' && !event.isComposing) { event.preventDefault(); selected !== null ? select(selected, {reveal: true, focus: true}) : setPanel('listing', true); } });
  function changeLayout(width) {
    const next = width >= 1100 ? 'wide' : width >= 760 ? 'medium' : 'narrow'; if (next === layout) return;
    const focused = document.activeElement; layout = next; root.setAttribute('data-layout', layout);
    if (layout === 'narrow') { if (inside(inspector, focused)) setPanel('details'); else if (inside(listing, focused)) setPanel('listing'); }
    else if (Object.values(panelButtons).includes(focused)) (panel === 'details' ? tabButtons[tab] : filter).focus();
  }
  root.setAttribute('data-layout', layout); setPanel('listing');
  for (const [key, control] of Object.entries(tabButtons)) { control.setAttribute('aria-selected', String(key === tab)); control.tabIndex = key === tab ? 0 : -1; }
  if (typeof ResizeObserver !== 'undefined') { const observer = new ResizeObserver(entries => { const width = entries[0]?.contentRect.width; if (width) changeLayout(width); }); observer.observe(root); }
  const adjacent = direction => {
    const visible = matches(), index = visible.findIndex(row => row.offset === selected);
    return visible[index < 0 ? direction > 0 ? 0 : visible.length - 1 : index + direction];
  };
  root.addEventListener('vm-workspace-query', event => Object.assign(event.detail, {search: true, previous: !!adjacent(-1), next: !!adjacent(1)}));
  root.addEventListener('vm-workspace-search', () => { setPanel('listing'); filter.focus(); });
  for (const [action, direction] of [['previous', -1], ['next', 1]]) root.addEventListener(`vm-workspace-${action}`, () => {
    const row = adjacent(direction); if (!row) return;
    page = Math.floor(matches().indexOf(row) / pageSize); select(row.offset, {focus: true});
  });
  update(); renderListing(); renderDetails();
  return {fileInputs, analyze, demo, clear, notice, sourceSummary, filter, reveal, listingRows, listingPager, detail, tabButtons, panelButtons,
    select, setTab, setPanel, changeLayout, importFile, analyzeInputs, getReport: () => report, getSelected: () => selected};
}
if (typeof module === 'object' && module?.exports) module.exports = {mountVmStatic, vmStaticOwnedExample};
