/* Trace value: a bounded static value-flow slice for one Wasm Inspect row.
 * The backend owns the analysis (protocol/wasm-value-flow-v1.md); this module
 * follows the selected instruction row, reads one slice at a time, lists it
 * with offset links and marks the slice's rows in the Inspect listing.
 * Instruction text from the module reaches the DOM only as text. */
(() => {
  const split = document.querySelector('#source-view-split');
  const code = document.querySelector('#source-code');
  if (!split || !code) return;

  const MAX_NODES = 512, REQUEST_TIMEOUT_MS = 10000, MAX_TEXT = 160;
  const ROLE_LABELS = {seed: 'seed', source: 'source', sink: 'sink', interior: 'step', frontier: 'depth cap'};
  const KIND_LABELS = {param: 'param', local_init: 'local zero', phi: 'join', exception_value: 'exception', unknown: 'unknown', const: 'const',
    local_get: 'local.get', local_set: 'local.set', local_tee: 'local.tee', global_get: 'global.get', global_set: 'global.set', load: 'load',
    store: 'store', atomic: 'atomic', memory: 'memory', table: 'table', call: 'call', import_call: 'import call', call_indirect: 'call_indirect',
    call_ref: 'call_ref', select: 'select', operation: 'op', branch: 'branch', return: 'return', throw: 'throw', drop: 'drop'};

  const panel = document.createElement('section');
  panel.id = 'value-flow';
  panel.className = 'value-flow';
  panel.setAttribute('aria-label', 'Trace value');
  panel.hidden = true;
  panel.innerHTML = `<div class="value-flow-head">
      <strong class="value-flow-title">Trace value</strong>
      <span id="value-flow-target" class="value-flow-target">Select an instruction row</span>
      <label class="value-flow-field">Operand <select id="value-flow-operand" aria-label="Operand to trace"><option value="">Whole instruction</option></select></label>
      <label class="value-flow-field">Direction <select id="value-flow-direction" aria-label="Trace direction"><option value="both">Both</option><option value="backward">Backward</option><option value="forward">Forward</option></select></label>
      <button id="value-flow-run" class="source-tool" type="button" disabled>Trace value</button>
      <button id="value-flow-clear" class="value-flow-clear" type="button" aria-label="Clear trace" title="Clear trace" hidden>×</button>
    </div>
    <p id="value-flow-status" class="value-flow-status" role="status" aria-live="polite">Static flow inside one function, from the module bytes. Nothing is executed.</p>
    <ol id="value-flow-list" class="value-flow-list" aria-label="Value-flow slice" hidden></ol>`;
  split.append(panel);
  const $ = id => panel.querySelector(`#${id}`);
  const elements = {target: $('value-flow-target'), operand: $('value-flow-operand'), direction: $('value-flow-direction'), run: $('value-flow-run'),
    clear: $('value-flow-clear'), status: $('value-flow-status'), list: $('value-flow-list')};

  let selected = null, trace = null, controller = null, generation = 0, marked = new Map(), sourceKey = null;
  const hex = value => `0x${Number(value).toString(16)}`;
  const node = (tag, className, text) => {const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = String(text); return element;};
  const clip = text => {const value = String(text ?? ''); return value.length > MAX_TEXT ? `${value.slice(0, MAX_TEXT)}…` : value;};
  const currentSource = () => typeof selectedSource === 'function' ? selectedSource() : null;
  const inspectRows = () => (typeof state !== 'undefined' && state.sourceWasm) ? state.sourceEditorView?.view?.wasmRows ?? null : null;
  const keyOf = source => source ? `${source.artifact_id}:${source.sha256 ?? ''}` : null;
  const editor = split.closest('.sources-editor');
  const graphOpen = () => Boolean(editor?.hasAttribute?.('data-graph'));

  // Only an artifact module shown as Inspect rows can be traced.
  function available() {
    const source = currentSource();
    return Boolean(source && source.kind === 'wasm' && source.source_type === 'artifact' && inspectRows());
  }

  // Operands of an instruction with a fixed stack effect, from its mnemonic,
  // so one operand can be chosen before the first trace. Calls, branches and
  // returns depend on types; their count arrives with the first trace.
  function operandCount(text) {
    const mnemonic = String(text ?? '').split(/[\s{]/, 1)[0];
    if (/^(i32|i64|f32|f64|v128)\.const$|^(local|global)\.get$|^(memory|table)\.size$|^ref\.(null|func)$|^nop$/.test(mnemonic)) return 0;
    if (/^(local\.(set|tee)|global\.set|drop|if|memory\.grow|table\.get|ref\.is_null)$/.test(mnemonic)) return 1;
    if (/^(select|memory\.(fill|copy|init)|table\.(fill|copy|init))$/.test(mnemonic)) return 3;
    if (/^(table\.(set|grow))$/.test(mnemonic)) return 2;
    if (/\.atomic\.rmw.*cmpxchg|\.atomic\.wait/.test(mnemonic)) return 3;
    if (/\.extract_lane/.test(mnemonic)) return 1;
    if (/\.atomic\.(rmw|notify)|\.store|_lane$/.test(mnemonic) && !/^v128\.load\d+_lane$/.test(mnemonic)) return 2;
    if (/^v128\.load\d+_lane$/.test(mnemonic)) return 2;
    if (/\.load/.test(mnemonic)) return 1;
    if (/^(i32|i64|f32|f64)\.(eqz|clz|ctz|popcnt|abs|neg|sqrt|ceil|floor|trunc|nearest|wrap_|extend|convert|demote|promote|reinterpret|trunc_sat)/.test(mnemonic)) return 1;
    if (/^(i32|i64|f32|f64)\.(eq|ne|lt|gt|le|ge|add|sub|mul|div|rem|and|or|xor|shl|shr|rotl|rotr|min|max|copysign)/.test(mnemonic)) return 2;
    return null;
  }

  function setStatus(text, kind = '') {
    elements.status.textContent = text;
    if (elements.status.dataset) elements.status.dataset.kind = kind;
  }

  function reset(message) {
    controller?.abort();
    controller = null;
    generation += 1;
    trace = null;
    marked = new Map();
    elements.list.replaceChildren();
    elements.list.hidden = true;
    elements.clear.hidden = true;
    setStatus(message ?? 'Static flow inside one function, from the module bytes. Nothing is executed.');
    paintRows();
  }

  // The header names the trace shown; a row chosen since (by a click or by a
  // reveal from the list) is named on the button that would trace it.
  function renderTarget() {
    const shown = trace?.target ?? null;
    const named = shown ?? selected;
    const fresh = selected && (!shown || selected.offset !== shown.offset || selected.functionIndex !== shown.functionIndex);
    elements.run.disabled = !selected;
    elements.run.textContent = shown && fresh ? `Trace ${hex(selected.offset)}` : 'Trace value';
    elements.run.title = selected ? `Trace values at ${hex(selected.offset)} in function ${selected.functionIndex}` : 'Select an instruction row in Inspect first';
    elements.target.textContent = named ? `func ${named.functionIndex} · ${hex(named.offset)} · ${clip(named.text)}` : 'Select an instruction row';
    elements.target.title = elements.target.textContent;
  }

  function setOperands(count) {
    const keep = elements.operand.value;
    elements.operand.replaceChildren(node('option', '', 'Whole instruction'));
    elements.operand.options[0].value = '';
    for (let index = 0; index < Math.min(count ?? 0, 16); index += 1) {
      const option = node('option', '', `Operand ${index}`);
      option.value = String(index);
      elements.operand.append(option);
    }
    elements.operand.value = [...elements.operand.options].some(option => option.value === keep) ? keep : '';
  }

  // Follows the page: hides off Inspect and while the block graph is open
  // (the graph owns that pane), and a different module drops the trace.
  function sync() {
    const traceable = available();
    const show = traceable && !graphOpen();
    if (panel.hidden === show) panel.hidden = !show;
    const key = traceable ? keyOf(currentSource()) : null;
    if (key !== sourceKey) {
      sourceKey = key;
      selected = null;
      setOperands(0);
      renderTarget();
      reset();
    }
    paintRows();
  }

  function noteRow(event) {
    if (!available()) return;
    const element = event.target.closest?.('.source-line');
    if (!element) return;
    const row = inspectRows()?.[Number(element.dataset.localLine)];
    if (!row || row.kind !== 'instruction' || !Number.isSafeInteger(row.byte_offset) || !Number.isSafeInteger(row.function_index)) return;
    if (selected?.offset === row.byte_offset && selected.functionIndex === row.function_index) return;
    selected = {functionIndex: row.function_index, offset: row.byte_offset, text: row.text};
    setOperands(operandCount(row.text) ?? 0);
    renderTarget();
  }

  function valid(document, source) {
    return document && document.schema === 'wasm-value-flow-v1' && document.artifact_id === source.artifact_id &&
      (!source.sha256 || document.sha256 === source.sha256) && Array.isArray(document.nodes) && document.nodes.length <= 4096 &&
      Array.isArray(document.edges) && Array.isArray(document.joins) && document.nodes.every((item, index) => item?.id === index && Number.isSafeInteger(item.byte_offset));
  }

  async function run() {
    const source = currentSource();
    if (!selected || !source) return;
    controller?.abort();
    const mine = ++generation;
    controller = new AbortController();
    const timer = setTimeout(() => controller?.abort(), REQUEST_TIMEOUT_MS);
    const target = selected;
    const params = new URLSearchParams({artifact_id: source.artifact_id, function: String(target.functionIndex), offset: String(target.offset),
      direction: elements.direction.value, max_nodes: String(MAX_NODES)});
    if (elements.operand.value !== '') params.set('operand', elements.operand.value);
    setStatus(`Tracing ${hex(target.offset)}…`, 'loading');
    elements.run.disabled = true;
    try {
      const response = await fetch(`/api/wasm/value-flow?${params}`, {cache: 'no-store', signal: controller.signal});
      const body = await response.json().catch(() => null);
      if (mine !== generation) return;
      if (!response.ok) throw new Error(body?.error ? String(body.error) : `Value flow failed (${response.status})`);
      if (!valid(body, source)) throw new Error('The value-flow response did not match this module.');
      trace = {document: body, target};
      setOperands(body.seed?.operand_count);
      render();
    } catch (error) {
      if (mine !== generation) return;
      const message = error?.name === 'AbortError' ? 'Value flow timed out.' : clip(error?.message ?? 'Value flow failed.');
      setStatus(`${message} The last trace is unchanged.`, 'error');
    } finally {
      clearTimeout(timer);
      if (mine === generation) { controller = null; renderTarget(); }
    }
  }

  // Row text: kind, the index it names and the instruction text as inert text.
  // The identifying part leads (import name, index, join kind) so a narrow
  // row keeps it when the kind label is cut.
  function describe(item) {
    const parts = [];
    if (item.import) parts.push(`${item.import.module}.${item.import.name}`);
    if (item.kind === 'phi') parts.push(`${item.join ?? ''} join`.trim());
    if (item.local !== undefined) parts.push(`local ${item.local}`);
    if (item.global !== undefined) parts.push(`global ${item.global}`);
    if (item.function !== undefined && !item.import) parts.push(`func ${item.function}`);
    if (item.kind !== 'phi') parts.push(KIND_LABELS[item.kind] ?? item.kind);
    return parts.join(' · ');
  }


  function rowLine(offset) {
    const rows = inspectRows();
    if (!rows) return -1;
    return rows.findIndex(row => row.kind === 'instruction' && row.byte_offset === offset);
  }

  function reveal(offset) {
    const line = rowLine(offset);
    if (line < 0 || typeof moveSourceWindow !== 'function') return false;
    moveSourceWindow(line, 0, {focus: false});
    const element = code.querySelector(`[data-local-line="${line}"]`);
    element?.scrollIntoView?.({block: 'center'});
    element?.querySelector?.('.source-gutter')?.focus?.({preventScroll: true});
    return true;
  }

  function render() {
    const flow = trace.document;
    const joins = new Map(flow.joins.map(join => [join.node, join]));
    const order = {seed: 0, backward: 1, both: 1, forward: 2};
    const items = [...flow.nodes].sort((a, b) => (order[a.direction] - order[b.direction]) || (a.depth - b.depth) || (a.byte_offset - b.byte_offset));
    marked = new Map();
    for (const item of flow.nodes) {
      const role = item.role === 'seed' ? 'seed' : item.source ? 'source' : item.sink ? 'sink' : 'step';
      if (!marked.has(item.byte_offset) || role === 'seed') marked.set(item.byte_offset, role);
    }
    const rows = items.map(item => {
      const entry = node('li', `value-flow-row is-${item.role}${item.sink && item.role !== 'sink' ? ' is-sink' : ''}`);
      const button = node('button', 'value-flow-link');
      button.type = 'button';
      const line = rowLine(item.byte_offset);
      button.disabled = line < 0;
      const kind = describe(item), text = clip(item.expression || item.text);
      button.title = `${kind} · ${text}\n${line < 0 ? `Byte ${item.byte_offset} has no retained Inspect row` : `Show the Inspect row at ${hex(item.byte_offset)}`}`;
      // Kind and text share one column so the index, import or join kind
      // stays visible at the minimum window, ahead of the instruction text.
      const detail = node('span', 'value-flow-detail');
      detail.append(node('span', 'value-flow-kind', kind), node('span', 'value-flow-text', text));
      // Both ends of the slice at once (a call that feeds its own loop value).
      const ends = item.source && item.sink ? 'source · sink' : ROLE_LABELS[item.role] ?? item.role;
      button.append(node('span', 'value-flow-offset', hex(item.byte_offset)), node('span', 'value-flow-role', ends), detail);
      button.addEventListener('click', () => reveal(item.byte_offset));
      entry.append(button);
      const join = joins.get(item.id);
      if (join) {
        const listed = join.incoming.map(edge => `${edge.via ?? 'in'} ${hex(edge.from_offset)}`).join(', ');
        const total = Number.isSafeInteger(join.incoming_count) ? join.incoming_count : join.incoming.length;
        const incoming = total > join.incoming.length ? `${listed}, and ${total - join.incoming.length} more` : listed;
        const open = join.incomplete ? ' · incomplete: its loop was still open where simulation stopped' : '';
        entry.append(node('span', 'value-flow-join', `${total} incoming: ${clip(incoming)}${open}`));
      }
      return entry;
    });
    elements.list.replaceChildren(...rows);
    elements.list.hidden = rows.length === 0;
    elements.clear.hidden = false;
    const counts = `${flow.node_count} nodes · ${flow.sources.length} sources · ${flow.sinks.length} sinks · ${flow.joins.length} joins`;
    const partial = flow.status === 'partial' ? ` · partial: ${clip(flow.omissions.join(' '))}` : '';
    setStatus(`${hex(trace.target.offset)} in function ${flow.function_index} · ${counts}${partial}. Declared static flow, not observed.`, flow.status);
    paintRows();
  }

  // Inspect rows are mounted in windows; marks are reapplied to whatever is mounted.
  function paintRows() {
    const rows = inspectRows();
    for (const line of code.querySelectorAll('.source-line[data-value-flow]')) {
      if (line.dataset) delete line.dataset.valueFlow;
    }
    if (!rows || marked.size === 0 || panel.hidden) return;
    for (const line of code.querySelectorAll('.source-line')) {
      const row = rows[Number(line.dataset?.localLine)];
      const role = row?.kind === 'instruction' ? marked.get(row.byte_offset) : undefined;
      if (role && line.dataset) line.dataset.valueFlow = role;
    }
  }

  elements.run.addEventListener('click', run);
  elements.clear.addEventListener('click', () => { reset(); elements.run.focus(); });
  elements.list.addEventListener('keydown', event => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    const links = [...elements.list.querySelectorAll('.value-flow-link:not(:disabled)')];
    if (!links.length) return;
    const at = links.indexOf(document.activeElement);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? links.length - 1 : Math.max(0, Math.min(links.length - 1, at + (event.key === 'ArrowDown' ? 1 : -1)));
    event.preventDefault();
    links[next].focus();
  });
  code.addEventListener('click', noteRow);
  code.addEventListener('focusin', noteRow);
  let pending = 0;
  const schedule = () => { if (!pending) pending = requestAnimationFrame(() => { pending = 0; sync(); }); };
  if (typeof MutationObserver === 'function') {
    new MutationObserver(schedule).observe(code, {childList: true});
    if (editor) new MutationObserver(schedule).observe(editor, {attributes: true, attributeFilter: ['data-graph']});
  }
  document.querySelector('#source-wasm')?.addEventListener('click', () => setTimeout(schedule, 0));
  sync();
})();
