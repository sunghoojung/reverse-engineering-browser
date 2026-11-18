/* Trace value: the complete static value-flow slice for one Wasm Inspect row,
 * shown as a path view rooted at the seed. The backend owns the analysis
 * (protocol/wasm-value-flow-v2.md); this module follows the selected
 * instruction row, reads the slice a page at a time, groups its sources and
 * sinks by kind with exact counts, shows any row's path to the seed on demand,
 * lists the function's callers, and marks the slice's rows in the Inspect
 * listing. Rows are virtualized: a slice of a million nodes and one of ten are
 * drawn the same way. Instruction text from the module reaches the DOM only
 * as text. */
(() => {
  const split = document.querySelector('#source-view-split');
  const code = document.querySelector('#source-code');
  if (!split || !code) return;

  // One page of ends or callers per read, the first node page's size, and
  // the fixed row height the virtual window is measured in.
  const PAGE = 200, FIRST_PAGE = 100, ROW = 24, OVERSCAN = 8, MAX_TEXT = 160;
  // Groups whose section is this small open on their own.
  const AUTO_EXPAND = 200;
  const KIND_LABELS = {param: 'param', local_init: 'local zero', phi: 'join', exception_value: 'exception', unknown: 'unknown', const: 'const',
    local_get: 'local.get', local_set: 'local.set', local_tee: 'local.tee', global_get: 'global.get', global_set: 'global.set', load: 'load',
    store: 'store', atomic: 'atomic', memory: 'memory', table: 'table', call: 'call', import_call: 'import call', call_indirect: 'call_indirect',
    call_ref: 'call_ref', select: 'select', operation: 'op', branch: 'branch', return: 'return', throw: 'throw', drop: 'drop', memory_cell: 'memory cell'};
  const CLASS_LABELS = {value: '', address: 'address', memory_may: 'may', control: 'decides'};
  const ROLE_LABELS = {seed: 'seed', source: 'source', sink: 'sink', boundary: 'boundary', interior: 'step'};
  const EDGE_LABELS = {operand: 'operand', local: 'local', local_set: 'local.set', global_set: 'global.set', address: 'address', stored_value: 'stored value',
    forwarded_store: 'forwarded store', forwarded_global: 'forwarded global', argument: 'argument', callee_index: 'callee index', callee_ref: 'callee ref',
    selector: 'selector', return: 'return', drop: 'drop', merge: 'join', memory_may: 'may (memory)', control: 'decided by', call_param: 'into param',
    call_result: 'from return', summary: 'through callee'};

  const panel = document.createElement('section');
  panel.id = 'value-flow';
  panel.className = 'value-flow';
  panel.setAttribute('aria-label', 'Trace value');
  panel.hidden = true;
  panel.dataset.empty = '';
  panel.innerHTML = `<div class="value-flow-head">
      <strong class="value-flow-title">Trace value</strong>
      <span id="value-flow-target" class="value-flow-target">Select an instruction row</span>
      <label class="value-flow-field"><span class="value-flow-field-name">Operand</span> <select id="value-flow-operand" aria-label="Operand to trace"><option value="">Whole instruction</option></select></label>
      <label class="value-flow-field"><span class="value-flow-field-name">Direction</span> <select id="value-flow-direction" aria-label="Trace direction"><option value="both">Both</option><option value="backward">Backward</option><option value="forward">Forward</option></select></label>
      <label class="value-flow-check" title="Follow control edges backward: the decisions behind each join"><input id="value-flow-control" type="checkbox"> <span>Decisions</span></label>
      <label class="value-flow-check" title="Enter the functions calls name"><input id="value-flow-calls" type="checkbox" checked> <span>Calls</span></label>
      <button id="value-flow-run" class="source-tool" type="button" disabled>Trace value</button>
      <button id="value-flow-clear" class="value-flow-clear" type="button" aria-label="Clear trace" title="Clear trace" hidden>×</button>
    </div>
    <p id="value-flow-status" class="value-flow-status" role="status" aria-live="polite">Static flow from the module bytes, complete for the seed. Nothing is executed.</p>
    <details id="value-flow-omissions" class="value-flow-omissions" hidden><summary></summary><ul></ul></details>
    <div id="value-flow-scroll" class="value-flow-scroll" hidden><ol id="value-flow-list" class="value-flow-list" role="tree" aria-label="Value-flow slice"></ol></div>`;
  split.append(panel);
  const $ = id => panel.querySelector(`#${id}`);
  const elements = {target: $('value-flow-target'), operand: $('value-flow-operand'), direction: $('value-flow-direction'), control: $('value-flow-control'),
    calls: $('value-flow-calls'), run: $('value-flow-run'), clear: $('value-flow-clear'), status: $('value-flow-status'), omissions: $('value-flow-omissions'),
    scroll: $('value-flow-scroll'), list: $('value-flow-list')};

  let selected = null, trace = null, controller = null, generation = 0, marked = new Map(), sourceKey = null;
  // Reads of pages and paths, aborted together when the trace goes.
  let readers = new Set();
  const hex = value => `0x${Number(value).toString(16)}`;
  const node = (tag, className, text) => {const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = String(text); return element;};
  const clip = text => {const value = String(text ?? ''); return value.length > MAX_TEXT ? `${value.slice(0, MAX_TEXT)}…` : value;};
  const currentSource = () => typeof selectedSource === 'function' ? selectedSource() : null;
  // The Inspect page mounted in Sources; its row(line) reads one row.
  const inspectRows = () => (typeof state !== 'undefined' && state.sourceWasm) ? state.sourceEditorView?.view?.wasm ?? null : null;
  const keyOf = source => source ? `${source.artifact_id}:${source.sha256 ?? ''}` : null;
  const editor = split.closest('.sources-editor');
  const graphOpen = () => Boolean(editor?.hasAttribute?.('data-graph'));
  // Backend offsets in omissions are written as hex; older messages said
  // "byte 123" and read as hex here too, as the listing shows them.
  const hexed = text => String(text).replace(/\bbyte (\d+)\b/g, (_, digits) => `byte ${hex(digits)}`);

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

  function abortReaders() {
    for (const reader of readers) reader.abort();
    readers = new Set();
  }

  function reset(message) {
    controller?.abort();
    controller = null;
    abortReaders();
    generation += 1;
    trace = null;
    marked = new Map();
    drawn = new Map();
    elements.list.replaceChildren();
    elements.list.style.paddingTop = '';
    elements.list.style.paddingBottom = '';
    elements.scroll.hidden = true;
    elements.omissions.hidden = true;
    elements.clear.hidden = true;
    panel.dataset.empty = '';
    setStatus(message ?? 'Static flow from the module bytes, complete for the seed. Nothing is executed.');
    paintRows();
  }

  // The header names the trace shown; a row chosen since (by a click or by a
  // reveal from the list) is named on the button that would trace it.
  function renderTarget() {
    const shown = trace?.target ?? null;
    const named = shown ?? selected;
    const fresh = selected && (!shown || selected.offset !== shown.offset || selected.functionIndex !== shown.functionIndex);
    // A trace has no deadline; while one runs the button stops it.
    elements.run.disabled = !selected && !controller;
    elements.run.textContent = controller ? 'Cancel' : shown && fresh ? `Trace ${hex(selected.offset)}` : 'Trace value';
    elements.run.title = controller ? 'Stop this trace on the backend' : selected ? `Trace values at ${hex(selected.offset)} in function ${selected.functionIndex}` : 'Select an instruction row in Inspect first';
    elements.target.textContent = named ? `func ${named.functionIndex} · ${hex(named.offset)} · ${clip(named.text)}` : 'Select an instruction row';
    elements.target.title = elements.target.textContent;
  }

  // Every operand the instruction has; a call with forty arguments lists forty.
  function setOperands(count) {
    const keep = elements.operand.value;
    elements.operand.replaceChildren(node('option', '', 'Whole instruction'));
    elements.operand.options[0].value = '';
    for (let index = 0; index < (count ?? 0); index += 1) {
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
    const row = inspectRows()?.row(Number(element.dataset.localLine));
    if (!row || row.kind !== 'instruction' || !Number.isSafeInteger(row.byte_offset) || !Number.isSafeInteger(row.function_index)) return;
    if (selected?.offset === row.byte_offset && selected.functionIndex === row.function_index) return;
    selected = {functionIndex: row.function_index, offset: row.byte_offset, text: row.text};
    setOperands(operandCount(row.text) ?? 0);
    renderTarget();
  }

  function valid(document, source) {
    return document && document.schema === 'wasm-value-flow-v2' && document.artifact_id === source.artifact_id &&
      (!source.sha256 || document.sha256 === source.sha256) && Array.isArray(document.nodes) && Array.isArray(document.path_nodes) &&
      Array.isArray(document.joins) && document.sources && Array.isArray(document.sources.items) && document.sinks && Array.isArray(document.sinks.items) &&
      document.nodes.every(item => Number.isSafeInteger(item?.id) && Number.isSafeInteger(item.byte_offset) && Number.isSafeInteger(item.walk));
  }

  // The query every read of this trace shares: seed, direction and flags.
  function baseParams(source, target) {
    const params = new URLSearchParams({artifact_id: source.artifact_id, function: String(target.functionIndex), offset: String(target.offset),
      direction: elements.direction.value, control: String(elements.control.checked), interprocedural: String(elements.calls.checked)});
    if (elements.operand.value !== '') params.set('operand', elements.operand.value);
    return params;
  }

  async function run() {
    if (controller) {
      controller.abort();
      return;
    }
    const source = currentSource();
    if (!selected || !source) return;
    const mine = ++generation;
    const started = Date.now();
    controller = new AbortController();
    const target = selected;
    const params = baseParams(source, target);
    params.set('node_limit', String(FIRST_PAGE));
    params.set('source_limit', String(FIRST_PAGE));
    params.set('sink_limit', String(FIRST_PAGE));
    params.set('join_limit', '16');
    let timer = 0;
    const tick = () => {
      if (mine !== generation) return;
      setStatus(`Tracing ${hex(target.offset)}… ${Math.floor((Date.now() - started) / 1000)} s. Cancel stops the backend analysis.`, 'loading');
      timer = setTimeout(tick, 1000);
    };
    tick();
    renderTarget();
    try {
      const response = await fetch(`/api/wasm/value-flow?${params}`, {cache: 'no-store', signal: controller.signal});
      const body = await response.json().catch(() => null);
      if (mine !== generation) return;
      if (!response.ok) throw new Error(body?.error ? String(body.error) : `Value flow failed (${response.status})`);
      if (!valid(body, source)) throw new Error('The value-flow response did not match this module.');
      abortReaders();
      trace = model(body, target, source, params);
      setOperands(body.seed?.operand_count);
      render();
    } catch (error) {
      if (mine !== generation) return;
      const message = error?.name === 'AbortError' ? 'Value flow cancelled; its backend analysis was stopped.' : clip(hexed(error?.message ?? 'Value flow failed.'));
      setStatus(`${message} The last trace is unchanged.`, 'error');
    } finally {
      clearTimeout(timer);
      if (mine === generation) { controller = null; renderTarget(); }
    }
  }

  // The view's model of one trace: the seeds, each direction's groups of
  // ends by kind with the items read so far, the paths opened, the callers.
  function model(document, target, source, params) {
    const groupsOf = (list, side) => {
      const byKind = new Map();
      for (const row of list.kinds) {
        const group = byKind.get(row.kind) ?? {kind: row.kind, side, count: 0, classes: new Map(), items: new Map(), loading: new Set(), expanded: false};
        group.count += row.count;
        group.classes.set(row.class, (group.classes.get(row.class) ?? 0) + row.count);
        byKind.set(row.kind, group);
      }
      const groups = [...byKind.values()].sort((a, b) => b.count - a.count);
      // The first page in walk order is a prefix of every kind's filtered list.
      const seen = new Map();
      for (const item of list.items) {
        const group = byKind.get(item.kind);
        if (!group) continue;
        const index = seen.get(item.kind) ?? 0;
        group.items.set(index, item);
        seen.set(item.kind, index + 1);
      }
      const total = list.count;
      for (const group of groups) group.expanded = total <= AUTO_EXPAND;
      return {side, label: side === 'backward' ? 'Comes from' : 'Goes to', count: total, groups, expanded: true};
    };
    const sections = [];
    if (document.request.direction !== 'forward') sections.push(groupsOf(document.sources, 'backward'));
    if (document.request.direction !== 'backward') sections.push(groupsOf(document.sinks, 'forward'));
    const nodes = new Map(document.nodes.concat(document.path_nodes).map(item => [item.id, item]));
    const seeds = document.nodes.filter(item => item.seed);
    const callers = document.callers ? {count: document.callers.count, indirect: document.callers.indirect, sites: new Map(), loading: new Set(), expanded: false} : null;
    return {document, target, source, params, sections, nodes, seeds, callers, paths: new Map(), joins: new Map(document.joins.map(join => [join.node, join]))};
  }

  // ---- Reads of more of the slice ----

  async function read(url, apply) {
    if (!trace) return;
    const mine = generation;
    const reader = new AbortController();
    readers.add(reader);
    try {
      const response = await fetch(url, {cache: 'no-store', signal: reader.signal});
      const body = await response.json().catch(() => null);
      if (mine !== generation || !trace) return;
      if (!response.ok) throw new Error(body?.error ? String(body.error) : `Value flow failed (${response.status})`);
      apply(body);
      render();
    } catch (error) {
      if (mine !== generation || error?.name === 'AbortError') return;
      setStatus(`${clip(hexed(error?.message ?? 'A read failed.'))} The trace shown is unchanged.`, 'error');
    } finally {
      readers.delete(reader);
    }
  }

  // One page of one kind's ends, for the group rows scrolled into view.
  function readGroupPage(group, page) {
    if (group.loading.has(page)) return;
    group.loading.add(page);
    const params = new URLSearchParams(trace.params);
    const prefix = group.side === 'backward' ? 'source' : 'sink';
    params.set('node_limit', '1');
    params.set('source_limit', '1');
    params.set('sink_limit', '1');
    params.set(`${prefix}_kind`, group.kind);
    params.set(`${prefix}_offset`, String(page * PAGE));
    params.set(`${prefix}_limit`, String(PAGE));
    read(`/api/wasm/value-flow?${params}`, body => {
      const list = group.side === 'backward' ? body.sources : body.sinks;
      if (!list || !Array.isArray(list.items)) return;
      list.items.forEach((item, index) => group.items.set(page * PAGE + index, item));
    });
  }

  // A node's path to the seed: the node page at its walk position carries
  // every listed ancestor.
  function readPath(item) {
    if (trace.paths.has(item.id)) return;
    trace.paths.set(item.id, {steps: null, expanded: true});
    const params = new URLSearchParams(trace.params);
    params.set('node_offset', String(item.walk));
    params.set('node_limit', '1');
    params.set('source_limit', '1');
    params.set('sink_limit', '1');
    params.set('join_limit', '32');
    read(`/api/wasm/value-flow?${params}`, body => {
      if (!Array.isArray(body.nodes) || !Array.isArray(body.path_nodes)) return;
      for (const row of body.nodes.concat(body.path_nodes)) trace.nodes.set(row.id, row);
      for (const join of body.joins ?? []) trace.joins.set(join.node, join);
      const steps = [];
      let current = body.nodes.find(row => row.id === item.id) ?? trace.nodes.get(item.id);
      const seen = new Set();
      while (current && current.parent !== null && current.parent !== undefined && !seen.has(current.id)) {
        seen.add(current.id);
        const parent = trace.nodes.get(current.parent);
        if (!parent) break;
        steps.push({edge: current.edge, node: parent});
        current = parent;
      }
      const path = trace.paths.get(item.id);
      if (path) path.steps = steps;
    });
  }

  function readCallers(page) {
    const callers = trace.callers;
    if (!callers || callers.loading.has(page)) return;
    callers.loading.add(page);
    const params = new URLSearchParams({artifact_id: trace.source.artifact_id, function: String(trace.target.functionIndex), offset: String(page * PAGE), limit: String(PAGE)});
    read(`/api/wasm/call-sites?${params}`, body => {
      if (!Array.isArray(body.sites)) return;
      body.sites.forEach((site, index) => callers.sites.set(page * PAGE + index, site));
    });
  }

  // ---- Rows ----

  // Row text: kind, the index it names and the function when it is another.
  function describe(item, functionIndex) {
    const parts = [];
    if (item.import) parts.push(`${item.import.module}.${item.import.name}`);
    if (item.kind === 'phi') parts.push(`${item.join ?? ''} join`.trim());
    if (item.local !== undefined) parts.push(`local ${item.local}`);
    if (item.global !== undefined) parts.push(`global ${item.global}`);
    if (item.callee !== undefined && !item.import) parts.push(`func ${item.callee}`);
    if (item.kind === 'memory_cell' && item.cell) parts.push(item.cell.address !== undefined ? `at ${hex(item.cell.address + (item.cell.offset ?? 0))}` : `base ${hex(item.cell.base_offset)}+${item.cell.offset ?? 0}`);
    if (item.kind !== 'phi') parts.push(KIND_LABELS[item.kind] ?? item.kind);
    if (item.kind === 'param' || item.kind === 'local_init') parts.push('(declaration)');
    if (Number.isSafeInteger(item.function) && item.function !== functionIndex) parts.push(`in func ${item.function}`);
    return parts.join(' · ');
  }

  // The connector between a path step and the node above it: how the value
  // got there, the locals it passed through, the branch that carried it. A
  // chain of locals is implied by "through local N"; the hop that consumed or
  // produced the value is the one named.
  function connector(edge) {
    if (!edge) return '';
    const name = kind => EDGE_LABELS[kind] ?? kind;
    const viaLocal = /^(local|local_set)$/.test(edge.kind);
    const own = viaLocal && edge.through ? edge.through : edge;
    const parts = [];
    if (edge.through && !viaLocal && edge.through.kind !== edge.kind) parts.push(`${name(edge.through.kind)}, ${name(edge.kind)}`);
    else parts.push(name(own.kind));
    const summary = edge.kind === 'summary' ? edge : edge.through?.kind === 'summary' ? edge.through : null;
    if (summary) parts.push(`arg ${summary.operand} → result ${summary.result}`);
    else if (['operand', 'argument', 'stored_value', 'address'].includes(own.kind)) parts.push(String(own.operand));
    const via = edge.via ? edge : edge.through?.via ? edge.through : null;
    if (via?.via) parts.push(via.via_offset !== undefined && via.via_offset !== null ? `via ${via.via} @${hex(via.via_offset)}` : `via ${via.via}`);
    if (edge.locals?.length) parts.push(`through local ${edge.locals.join(', ')}`);
    return parts.join(' · ');
  }

  // The virtual rows of the tree in order: seeds, then each section with its
  // groups and their items (and open paths), then callers.
  function rows() {
    const out = [];
    const functionIndex = trace.document.function_index;
    for (const seed of trace.seeds) out.push({type: 'node', node: seed, role: 'seed', depth: 0});
    for (const section of trace.sections) {
      out.push({type: 'section', section, depth: 0});
      if (!section.expanded) continue;
      for (const group of section.groups) {
        out.push({type: 'group', group, depth: 1});
        if (!group.expanded) continue;
        for (let index = 0; index < group.count; index += 1) {
          const item = group.items.get(index);
          out.push({type: 'item', group, index, item, depth: 2});
          const path = item && trace.paths.get(item.id);
          if (path?.expanded) {
            if (!path.steps) out.push({type: 'note', text: 'reading the path…', depth: 3});
            else if (!path.steps.length) out.push({type: 'note', text: 'this row is the seed', depth: 3});
            else path.steps.forEach((step, position) => out.push({type: 'step', step, depth: 3 + Math.min(position, 6)}));
          }
        }
      }
    }
    if (trace.callers) {
      out.push({type: 'callers', depth: 0});
      if (trace.callers.expanded) {
        for (let index = 0; index < trace.callers.count; index += 1) out.push({type: 'site', index, site: trace.callers.sites.get(index), depth: 1});
        if (trace.callers.indirect) out.push({type: 'note', text: 'also reachable indirectly: exported, the start function, in a table or named by ref.func', depth: 1});
      }
    }
    return out;
  }

  const roleOf = row => row.type === 'node' ? row.role : row.type === 'item' ? (row.group.side === 'backward' ? 'source' : 'sink') : row.type === 'step' ? (row.step.node.seed ? 'seed' : row.step.node.role === 'source' || row.step.node.role === 'sink' ? row.step.node.role : 'step') : null;

  // Inspect holds one page of rows; the backend finds the page of a slice
  // node's instruction, which every node of a decoded body has.
  async function reveal(offset) {
    const source = currentSource();
    if (!inspectRows() || typeof revealWasmInspectionByte !== 'function' || !await revealWasmInspectionByte(source, offset)) return false;
    const line = [...code.querySelectorAll('.source-line')].find(element => inspectRows()?.row(Number(element.dataset.localLine))?.byte_offset === offset);
    line?.querySelector?.('.source-gutter')?.focus?.({preventScroll: true});
    return true;
  }

  // A node's link: offset, role and class, then the detail column with the
  // connector of a path step (how the value reached the row above), the kind
  // and the instruction text, so offsets line up down the tree.
  function link(item, role, classLabel, text, functionIndex, edgeText = '') {
    const button = node('button', 'value-flow-link');
    button.type = 'button';
    const kind = describe(item, functionIndex);
    button.title = `${edgeText ? `${edgeText}\n` : ''}${kind} · ${text}\nShow the Inspect row at ${hex(item.byte_offset)}`;
    const detail = node('span', 'value-flow-detail');
    if (edgeText) {
      const edge = node('span', 'value-flow-edge', edgeText);
      edge.title = edgeText;
      detail.append(edge);
    }
    detail.append(node('span', 'value-flow-kind', kind), node('span', 'value-flow-text', text));
    const roleText = [ROLE_LABELS[role] ?? role, classLabel].filter(Boolean).join(' · ');
    button.append(node('span', 'value-flow-offset', hex(item.byte_offset)), node('span', 'value-flow-role', roleText), detail);
    button.addEventListener('click', () => reveal(item.byte_offset));
    return button;
  }

  function toggle(label, expanded, onToggle, extraClass = '') {
    const button = node('button', `value-flow-toggle ${extraClass}`.trim());
    button.type = 'button';
    button.setAttribute('aria-expanded', String(expanded));
    button.append(node('span', 'value-flow-caret', expanded ? '▾' : '▸'), node('span', 'value-flow-toggle-label', label));
    button.addEventListener('click', onToggle);
    return button;
  }

  function renderRow(row, index) {
    const functionIndex = trace.document.function_index;
    const entry = node('li', 'value-flow-row');
    entry.setAttribute('role', 'treeitem');
    entry.dataset.index = String(index);
    entry.style.setProperty('--depth', String(row.depth));
    const role = roleOf(row);
    if (role) entry.classList.add(`is-${role}`);
    switch (row.type) {
      case 'node': {
        const text = clip(row.node.expression || row.node.text);
        entry.append(link(row.node, 'seed', CLASS_LABELS[row.node.class], text, functionIndex));
        break;
      }
      case 'section': {
        const {section} = row;
        const label = `${section.label} · ${section.count} ${section.side === 'backward' ? 'sources' : 'sinks'}`;
        entry.classList.add('is-section');
        entry.setAttribute('aria-expanded', String(section.expanded));
        entry.append(toggle(label, section.expanded, () => { section.expanded = !section.expanded; render(); }, 'value-flow-section'));
        break;
      }
      case 'group': {
        const {group} = row;
        const classes = [...group.classes].filter(([name]) => name !== 'value').map(([name, count]) => `${count} ${CLASS_LABELS[name]}`).join(', ');
        const label = `${KIND_LABELS[group.kind] ?? group.kind} · ${group.count}${classes ? ` (${classes})` : ''}`;
        entry.classList.add('is-group');
        entry.setAttribute('aria-expanded', String(group.expanded));
        entry.append(toggle(label, group.expanded, () => { group.expanded = !group.expanded; render(); }, 'value-flow-group'));
        break;
      }
      case 'item': {
        const {group, item} = row;
        if (!item) {
          entry.classList.add('is-pending');
          entry.append(node('span', 'value-flow-note', 'reading…'));
          readGroupPage(group, Math.floor(row.index / PAGE));
          break;
        }
        const path = trace.paths.get(item.id);
        entry.setAttribute('aria-expanded', String(Boolean(path?.expanded)));
        const open = toggle('', Boolean(path?.expanded), () => {
          if (path) path.expanded = !path.expanded; else readPath(item);
          render();
        }, 'value-flow-path');
        open.title = path?.expanded ? 'Hide the path to the seed' : 'Show the path to the seed';
        open.setAttribute('aria-label', `Path to the seed of ${hex(item.byte_offset)}`);
        entry.append(open, link(item, role, CLASS_LABELS[item.class], clip(item.text), functionIndex));
        break;
      }
      case 'step': {
        const {step} = row;
        entry.classList.add('is-step');
        const join = trace.joins.get(step.node.id);
        const text = clip(step.node.expression || step.node.text);
        const stepRole = step.node.seed ? 'seed' : step.node.role;
        const button = link(step.node, stepRole, CLASS_LABELS[step.node.class], text, functionIndex, connector(step.edge));
        if (join) {
          const listed = join.incoming.map(incoming => `${incoming.via ?? 'in'}${incoming.via_offset !== null && incoming.via_offset !== undefined ? ` @${hex(incoming.via_offset)}` : ''} ← ${hex(incoming.from_offset)}`).join(', ');
          const more = join.incoming_count > join.incoming.length ? `, and ${join.incoming_count - join.incoming.length} more` : '';
          const open = join.incomplete ? ' · incomplete: its loop was still open where simulation stopped' : '';
          const summary = node('span', 'value-flow-join', `${join.incoming_count} incoming: ${listed}${more}${open}`);
          summary.title = summary.textContent;
          button.querySelector('.value-flow-detail').append(summary);
        }
        entry.append(button);
        break;
      }
      case 'callers': {
        const {callers} = trace;
        entry.classList.add('is-section');
        entry.setAttribute('aria-expanded', String(callers.expanded));
        entry.append(toggle(`Callers · ${callers.count} direct call sites of function ${functionIndex}${callers.indirect ? ' · also reachable indirectly' : ''}`, callers.expanded, () => {
          callers.expanded = !callers.expanded;
          render();
        }, 'value-flow-section'));
        break;
      }
      case 'site': {
        const {site} = row;
        if (!site) {
          entry.classList.add('is-pending');
          entry.append(node('span', 'value-flow-note', 'reading…'));
          readCallers(Math.floor(row.index / PAGE));
          break;
        }
        const button = node('button', 'value-flow-link');
        button.type = 'button';
        button.title = `Show the ${site.tail ? 'tail call' : 'call'} at ${hex(site.byte_offset)} in function ${site.caller}`;
        const detail = node('span', 'value-flow-detail');
        detail.append(node('span', 'value-flow-kind', `func ${site.caller} · ${site.tail ? 'return_call' : 'call'}`));
        button.append(node('span', 'value-flow-offset', hex(site.byte_offset)), node('span', 'value-flow-role', 'caller'), detail);
        button.addEventListener('click', () => reveal(site.byte_offset));
        entry.append(button);
        break;
      }
      case 'note':
        entry.classList.add('is-note');
        entry.append(node('span', 'value-flow-note', row.text));
        break;
      default:
        break;
    }
    return entry;
  }

  // What makes a drawn row the same row: its identity and the state its
  // element shows. A row whose signature holds across renders keeps its
  // element, so the focused row is never detached by a scroll or a resize.
  function signature(row) {
    switch (row.type) {
      case 'node': return `n:${row.node.id}`;
      case 'section': return `s:${row.section.side}:${row.section.expanded}:${row.section.count}`;
      case 'group': return `g:${row.group.side}:${row.group.kind}:${row.group.expanded}:${row.group.count}`;
      case 'item': {
        const path = row.item && trace.paths.get(row.item.id);
        const state = !path ? 'closed' : !path.expanded ? 'folded' : path.steps ? 'open' : 'reading';
        return `i:${row.group.side}:${row.group.kind}:${row.index}:${row.item ? row.item.id : '-'}:${state}`;
      }
      case 'step': return `t:${row.step.node.id}:${row.depth}:${trace.joins.has(row.step.node.id)}`;
      case 'callers': return `c:${trace.callers.expanded}:${trace.callers.count}`;
      case 'site': return `x:${row.index}:${row.site ? 1 : 0}`;
      case 'note': return `o:${row.depth}:${row.text}`;
      default: return `?:${row.type}`;
    }
  }

  // The window of rows that fits the scroller, drawn with spacers for the
  // rest, so the list's height is the whole tree's and its DOM is a screen.
  // Rows already drawn stay where they are; only rows entering or leaving
  // the window, or changing state, touch the DOM.
  let allRows = [];
  let drawn = new Map();
  function render() {
    if (!trace) return;
    allRows = rows();
    const total = allRows.length;
    const height = elements.scroll.clientHeight || ROW * 12;
    const top = elements.scroll.scrollTop || 0;
    const first = Math.max(0, Math.floor(top / ROW) - OVERSCAN);
    const last = Math.min(total, Math.ceil((top + height) / ROW) + OVERSCAN);
    elements.list.style.paddingTop = `${first * ROW}px`;
    elements.list.style.paddingBottom = `${Math.max(0, total - last) * ROW}px`;
    const focused = document.activeElement?.closest?.('.value-flow-row');
    const focusedButton = focused ? String(document.activeElement.className).split(' ')[0] : '';
    const keep = new Map();
    let cursor = elements.list.firstElementChild;
    let refocus = null;
    for (let index = first; index < last; index += 1) {
      const row = allRows[index];
      const key = signature(row);
      let element = drawn.get(key);
      if (element) {
        drawn.delete(key);
      } else {
        element = renderRow(row, index);
        // The focused row changed state (a path opened): its new element
        // takes the focus its old one held.
        if (focused && focused.dataset.index === String(index) && focused.isConnected) refocus = element;
      }
      element.dataset.index = String(index);
      keep.set(key, element);
      if (element === cursor) cursor = cursor.nextElementSibling;
      else elements.list.insertBefore(element, cursor);
    }
    for (const element of drawn.values()) {
      if (element.isConnected) element.remove();
    }
    if (focused && !focused.isConnected && keep.size && !refocus) {
      // A focused row left the window: keep the keyboard in the tree.
      const again = elements.list.querySelector(`[data-index="${focused.dataset.index}"]`) ?? elements.list.firstElementChild;
      refocus = again;
    }
    if (refocus) (refocus.querySelector(focusedButton ? `.${focusedButton}` : 'button') ?? refocus.querySelector('button'))?.focus?.({preventScroll: true});
    drawn = keep;
    elements.scroll.hidden = total === 0;
    elements.clear.hidden = false;
    delete panel.dataset.empty;
    const flow = trace.document;
    const counts = `${flow.node_count} nodes · ${flow.source_count} sources · ${flow.sink_count} sinks · ${flow.join_count} joins · ${flow.functions.length} ${flow.functions.length === 1 ? 'function' : 'functions'}`;
    const partial = flow.status === 'partial' ? ' · partial' : '';
    setStatus(`${hex(trace.target.offset)} in function ${flow.function_index} · ${counts}${partial}. Declared static flow, not observed.`, flow.status);
    const omissions = flow.omissions ?? [];
    elements.omissions.hidden = omissions.length === 0;
    if (omissions.length) {
      elements.omissions.querySelector('summary').textContent = `${omissions.length} ${omissions.length === 1 ? 'omission' : 'omissions'}: what the slice could not follow`;
      elements.omissions.querySelector('ul').replaceChildren(...omissions.map(text => node('li', '', hexed(text))));
    }
    // Marks for every node read so far, by role; the seed wins its row.
    marked = new Map();
    const mark = (offset, role) => { if (!Number.isSafeInteger(offset)) return; if (!marked.has(offset) || role === 'seed') marked.set(offset, role); };
    for (const seed of trace.seeds) mark(seed.byte_offset, 'seed');
    for (const section of trace.sections) for (const group of section.groups) for (const item of group.items.values()) mark(item.byte_offset, section.side === 'backward' ? 'source' : 'sink');
    for (const row of trace.nodes.values()) mark(row.byte_offset, row.seed ? 'seed' : row.source ? 'source' : row.sink ? 'sink' : 'step');
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
      const row = rows.row(Number(line.dataset?.localLine));
      const role = row?.kind === 'instruction' ? marked.get(row.byte_offset) : undefined;
      if (role && line.dataset) line.dataset.valueFlow = role;
    }
  }

  // Keyboard: arrows move through the tree's rows, including rows not drawn
  // yet; Left and Right close and open a row; Home and End jump.
  function focusRow(index) {
    if (!trace) return;
    const bounded = Math.max(0, Math.min(allRows.length - 1, index));
    const top = bounded * ROW, bottom = top + ROW;
    const scrollTop = elements.scroll.scrollTop || 0, height = elements.scroll.clientHeight || ROW * 12;
    if (top < scrollTop) elements.scroll.scrollTop = top;
    else if (bottom > scrollTop + height) elements.scroll.scrollTop = bottom - height;
    render();
    const row = elements.list.querySelector(`[data-index="${bounded}"]`);
    (row?.querySelector('.value-flow-link') ?? row?.querySelector('button'))?.focus?.({preventScroll: true});
  }
  elements.list.addEventListener('keydown', event => {
    const current = Number(event.target.closest?.('.value-flow-row')?.dataset?.index ?? NaN);
    if (!Number.isSafeInteger(current)) return;
    const row = allRows[current];
    if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      focusRow(event.key === 'Home' ? 0 : event.key === 'End' ? allRows.length - 1 : current + (event.key === 'ArrowDown' ? 1 : -1));
      return;
    }
    if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
      const open = event.key === 'ArrowRight';
      if (row?.type === 'section') { if (row.section.expanded !== open) { row.section.expanded = open; render(); event.preventDefault(); } }
      else if (row?.type === 'group') { if (row.group.expanded !== open) { row.group.expanded = open; render(); event.preventDefault(); } }
      else if (row?.type === 'callers') { if (trace.callers.expanded !== open) { trace.callers.expanded = open; render(); event.preventDefault(); } }
      else if (row?.type === 'item' && row.item) {
        const path = trace.paths.get(row.item.id);
        if (open && !path) { readPath(row.item); render(); event.preventDefault(); }
        else if (path && path.expanded !== open) { path.expanded = open; render(); event.preventDefault(); }
      }
    }
  });
  elements.scroll.addEventListener('scroll', () => { if (trace) render(); });
  if (typeof ResizeObserver === 'function') new ResizeObserver(() => { if (trace) render(); }).observe(elements.scroll);

  elements.run.addEventListener('click', run);
  elements.clear.addEventListener('click', () => { reset(); elements.run.focus(); });
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
