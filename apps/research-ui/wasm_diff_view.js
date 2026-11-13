/* Module comparison for one captured WASM artifact: "Compare with" another
 * captured module and read the function match table from /api/wasm/diff
 * (wasm-module-diff-v1). Matches are static hypotheses with a method and a
 * score; each function opens in Graph on its own module. Captured names are
 * inserted as text only. */
const WASM_DIFF_PAGE_ROWS = 200;
/* Reports kept in the page, keyed by both identities and the filter. */
const WASM_DIFF_CACHE = 4;
const WASM_DIFF_FILTERS = [
  {key: 'all', label: 'All', statuses: null},
  {key: 'changed', label: 'Changed', statuses: 'changed'},
  {key: 'added', label: 'Added', statuses: 'added'},
  {key: 'removed', label: 'Removed', statuses: 'removed'},
  {key: 'ambiguous', label: 'Ambiguous', statuses: 'ambiguous'},
  {key: 'same', label: 'Unchanged', statuses: 'renumbered,identical'},
  {key: 'unclassified', label: 'Unclassified', statuses: 'unclassified'}
];
const WASM_DIFF_STATUS_LABEL = {changed: 'Changed', added: 'Added', removed: 'Removed', ambiguous: 'Ambiguous', unclassified: 'Unclassified', renumbered: 'Renumbered', identical: 'Identical'};
const WASM_DIFF_METHOD_LABEL = {identical: 'same bytes', normalized: 'normalized', import_name: 'import name', export_name: 'export name', name: 'name section', call_graph: 'call graph', structural: 'structure'};

/** Checks the parts of a wasm-module-diff-v1 page this view reads. */
function isWasmDiffDocument(doc, a, b) {
  return doc?.schema === 'wasm-module-diff-v1' && String(doc.artifact_id) === String(a) && String(doc.compare_artifact_id) === String(b) &&
    Array.isArray(doc.rows) && doc.rows.length <= 1000 && doc.summary && typeof doc.summary.statuses === 'object' && doc.row_window && Array.isArray(doc.omissions);
}

/** One function side as short text: its name when the module has one, and its index. */
function wasmDiffFunctionLabel(side) {
  if (!side || !Number.isSafeInteger(side.function)) return '';
  const name = typeof side.name === 'string' && side.name ? side.name : side.import ? `${side.import.module}.${side.import.name}` : '';
  return name ? `${name} · func ${side.function}` : `func ${side.function}`;
}

/** What a function's tooltip says: signature, body range and size. */
function wasmDiffFunctionDetail(side) {
  const parts = [typeof side.type === 'string' ? side.type : ''];
  if (side.import) parts.push(`import ${side.import.module}.${side.import.name}`);
  else parts.push(`bytes 0x${side.byte_offset.toString(16)}–0x${side.byte_end.toString(16)}`, `${side.instructions ?? 0} instructions`);
  return parts.filter(Boolean).join(' · ');
}

/** Characters two URLs share from their start: a rotated build usually keeps
 * its host and path and changes only a hash or version near the end. */
function wasmDiffSharedPrefix(a, b) {
  const x = String(a ?? ''), y = String(b ?? '');
  let index = 0;
  while (index < x.length && index < y.length && x[index] === y[index]) index += 1;
  return index;
}

/** The other modules, most similar URL first, then newest artifact first. */
function wasmDiffCandidates(modules, source) {
  return modules.filter(module => module.artifact_id !== source?.artifact_id)
    .map(module => ({module, shared: wasmDiffSharedPrefix(module.url, source?.url)}))
    .sort((x, y) => y.shared - x.shared || (BigInt(y.module.artifact_id) > BigInt(x.module.artifact_id) ? 1 : -1))
    .map(entry => entry.module);
}

/** The summary sentence for a page's whole report. */
function wasmDiffSummaryText(doc) {
  const counts = doc.summary.statuses, parts = [];
  for (const status of ['changed', 'added', 'removed', 'ambiguous', 'unclassified', 'renumbered', 'identical']) {
    if (counts[status]) parts.push(`${Number(counts[status]).toLocaleString()} ${WASM_DIFF_STATUS_LABEL[status].toLowerCase()}`);
  }
  return parts.length ? parts.join(' · ') : 'Neither module has functions to compare.';
}

function createWasmDiffPanel({button, root, split, exclusive = [], closeOn = [], getSource, nameOf = source => `artifact ${source.artifact_id}`, listModules, openFunction}) {
  root.hidden = true;
  let isOpen = false, source = null, other = null, filter = 'all', rows = [], doc = null, generation = 0, abort = null, lastPair = null, screenVisible = true;
  const cache = new Map();
  const isWasm = candidate => candidate?.kind === 'wasm' && candidate?.source_type === 'artifact';
  const el = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };

  const head = el('div', 'wasm-diff-head');
  const title = el('span', 'wasm-diff-title', 'Compare');
  const current = el('span', 'wasm-diff-current');
  const withLabel = el('label', 'wasm-diff-with');
  withLabel.append(el('span', 'wasm-diff-with-text', 'with'));
  const picker = el('select', 'wasm-diff-picker'); picker.setAttribute('aria-label', 'Module to compare with');
  withLabel.append(picker);
  const run = el('button', 'source-tool wasm-diff-run', 'Compare'); run.type = 'button';
  const close = el('button', 'source-tool wasm-diff-close', 'Close'); close.type = 'button'; close.setAttribute('aria-label', 'Close module comparison');
  head.append(title, current, withLabel, run, close);
  const summary = el('p', 'wasm-diff-summary'); summary.setAttribute('role', 'status');
  const filters = el('div', 'wasm-diff-filters'); filters.setAttribute('role', 'group'); filters.setAttribute('aria-label', 'Show rows');
  const filterButtons = new Map();
  for (const entry of WASM_DIFF_FILTERS) {
    const chip = el('button', 'wasm-diff-filter', entry.label); chip.type = 'button'; chip.setAttribute('aria-pressed', String(entry.key === filter));
    chip.addEventListener('click', () => { if (filter === entry.key) return; filter = entry.key; for (const [key, node] of filterButtons) node.setAttribute('aria-pressed', String(key === filter)); load(); });
    filterButtons.set(entry.key, chip); filters.append(chip);
  }
  const notes = el('ul', 'wasm-diff-notes');
  const stateBox = el('div', 'wasm-diff-state');
  const stateText = el('p', 'wasm-diff-state-text');
  const retry = el('button', 'source-tool', 'Retry comparison'); retry.type = 'button'; retry.hidden = true;
  stateBox.append(stateText, retry);
  const body = el('div', 'wasm-diff-body'); body.tabIndex = -1;
  const table = el('table', 'wasm-diff-table');
  const headRow = el('tr');
  for (const [label, className] of [['Status', 'status'], ['This module (A)', 'side'], ['Compared module (B)', 'side'], ['Method', 'method'], ['Score', 'score']]) {
    const cell = el('th', `wasm-diff-col-${className}`, label); cell.scope = 'col'; headRow.append(cell);
  }
  const thead = el('thead'); thead.append(headRow);
  const tbody = el('tbody');
  table.append(thead, tbody);
  const more = el('button', 'source-tool wasm-diff-more', 'Show more rows'); more.type = 'button'; more.hidden = true;
  const limits = el('p', 'wasm-diff-limits', 'Static match hypotheses from declared bodies, with method and score. A match is not proof of equal behavior; neither module ran.');
  body.append(table, more);
  root.replaceChildren(head, summary, filters, notes, stateBox, body, limits);

  function setState(kind, text, canRetry = false) {
    stateBox.hidden = kind === 'ready';
    stateBox.dataset && (stateBox.dataset.state = kind);
    stateText.textContent = text;
    retry.hidden = !canRetry;
    body.hidden = kind !== 'ready';
  }
  function moduleLabel(module) {
    const hash = typeof module.sha256 === 'string' ? module.sha256.slice(0, 8) : '';
    return `${module.name}${hash ? ` · ${hash}` : ''} · artifact ${module.artifact_id}`;
  }
  function fillPicker() {
    const modules = wasmDiffCandidates(listModules() ?? [], source);
    const previous = other?.artifact_id ?? (lastPair && lastPair.a === source?.artifact_id ? lastPair.b : lastPair && lastPair.b === source?.artifact_id ? lastPair.a : null);
    picker.replaceChildren();
    const chosen = modules.find(module => module.artifact_id === previous) ?? modules[0] ?? null;
    for (const module of modules) {
      const option = el('option', '', moduleLabel(module)); option.value = module.artifact_id;
      if (module === chosen) option.selected = true;
      picker.append(option);
    }
    other = chosen;
    picker.disabled = run.disabled = !chosen;
    return modules;
  }
  function sideButton(side, artifactId) {
    const cell = el('td', 'wasm-diff-side');
    if (!side) { cell.append(el('span', 'wasm-diff-absent', '—')); return cell; }
    cell.append(functionButton(side, artifactId));
    return cell;
  }
  function functionButton(side, artifactId) {
    const jump = el('button', 'wasm-diff-fn', wasmDiffFunctionLabel(side)); jump.type = 'button';
    jump.title = `${wasmDiffFunctionDetail(side)}. ${side.import ? 'An import has no body to draw.' : 'Open in Graph.'}`;
    if (side.import) jump.disabled = true;
    else jump.addEventListener('click', () => openFunction(artifactId, side.function));
    return jump;
  }
  function candidateCell(list, artifactId, truncated) {
    const cell = el('td', 'wasm-diff-side wasm-diff-candidates');
    for (const side of list ?? []) cell.append(functionButton(side, artifactId));
    if (truncated) cell.append(el('span', 'wasm-diff-absent', 'more candidates not listed'));
    return cell;
  }
  function renderRows(pair) {
    const fragment = document.createDocumentFragment();
    for (const row of rows) {
      const tr = el('tr', 'wasm-diff-row');
      if (tr.dataset) tr.dataset.status = row.status;
      const status = el('td', 'wasm-diff-status');
      status.append(el('span', `wasm-diff-pill wasm-diff-pill-${row.status}`, WASM_DIFF_STATUS_LABEL[row.status] ?? row.status));
      tr.append(status);
      if (row.status === 'ambiguous') {
        tr.append(candidateCell(row.candidates?.a, pair.a, row.candidates?.truncated), candidateCell(row.candidates?.b, pair.b, false));
      } else {
        tr.append(sideButton(row.a, pair.a), sideButton(row.b, pair.b));
      }
      tr.append(el('td', 'wasm-diff-method', row.method ? WASM_DIFF_METHOD_LABEL[row.method] ?? row.method : ''));
      tr.append(el('td', 'wasm-diff-score', typeof row.score === 'number' ? row.score.toFixed(3) : ''));
      fragment.append(tr);
    }
    tbody.replaceChildren(fragment);
    if (!rows.length) {
      const tr = el('tr'), cell = el('td', 'wasm-diff-empty', filter === 'all' ? 'No functions to compare.' : 'No rows with this status.');
      cell.colSpan = 5; tr.append(cell); tbody.append(tr);
    }
    more.hidden = doc?.row_window?.next_offset === null || doc?.row_window?.next_offset === undefined;
  }
  function renderDocument(pair) {
    summary.textContent = `${wasmDiffSummaryText(doc)}${doc.status === 'partial' ? ' · partial' : ''}`;
    summary.title = `${Number(doc.summary.matched).toLocaleString()} matched of ${Number(doc.a.analyzed_functions).toLocaleString()} functions in A and ${Number(doc.b.analyzed_functions).toLocaleString()} in B`;
    for (const [key, chip] of filterButtons) {
      if (key === 'unclassified') chip.hidden = !doc.summary.statuses.unclassified;
    }
    notes.replaceChildren(...doc.omissions.slice(0, 4).map(text => el('li', '', text)));
    notes.hidden = !doc.omissions.length;
    renderRows(pair);
    setState('ready', '');
  }
  function claim() { const owner = ++generation; abort?.abort(); abort = new AbortController(); return () => owner === generation; }
  async function read(pair, offset) {
    const statuses = WASM_DIFF_FILTERS.find(entry => entry.key === filter).statuses;
    const query = new URLSearchParams({artifact_id: pair.a, compare_artifact_id: pair.b, row_offset: String(offset), row_limit: String(WASM_DIFF_PAGE_ROWS)});
    if (statuses) query.set('status', statuses);
    const response = await fetch(`/api/wasm/diff?${query}`, {cache: 'no-store', signal: abort.signal});
    if (!response.ok) {
      let message = `The module comparison returned ${response.status}.`;
      try { message = (await response.json()).error || message; } catch {}
      throw Error(message);
    }
    const next = await response.json();
    if (!isWasmDiffDocument(next, pair.a, pair.b)) throw Error('The module comparison returned an invalid document.');
    return next;
  }
  function pairKey(pair) { return `${pair.a}:${pair.aHash}:${pair.b}:${pair.bHash}:${filter}`; }
  async function load() {
    if (!isOpen || !source || !other) return;
    const pair = {a: source.artifact_id, aHash: source.sha256, b: other.artifact_id, bHash: other.sha256};
    lastPair = pair;
    const key = pairKey(pair), hit = cache.get(key);
    if (hit) { doc = hit.doc; rows = hit.rows; renderDocument(pair); return; }
    const current = claim();
    setState('loading', 'Matching functions from immutable module bytes…');
    summary.textContent = '';
    try {
      const next = await read(pair, 0);
      if (!current()) return;
      doc = next; rows = next.rows.slice();
      remember(key);
      renderDocument(pair);
    } catch (error) {
      if (!current() || error.name === 'AbortError') return;
      setState('error', error instanceof TypeError ? 'The evidence service is unreachable. Check that the session is still running.' : error.message, true);
    }
  }
  function remember(key) {
    cache.delete(key); cache.set(key, {doc, rows});
    while (cache.size > WASM_DIFF_CACHE) cache.delete(cache.keys().next().value);
  }
  async function loadMore() {
    if (!doc || doc.row_window.next_offset === null || !lastPair) return;
    const pair = lastPair, key = pairKey(pair), current = claim();
    more.disabled = true;
    try {
      const next = await read(pair, doc.row_window.next_offset);
      if (!current()) return;
      doc = next; rows = rows.concat(next.rows);
      remember(key);
      renderDocument(pair);
    } catch (error) {
      if (current() && error.name !== 'AbortError') { notes.hidden = false; notes.append(el('li', '', error instanceof TypeError ? 'The evidence service is unreachable.' : error.message)); }
    } finally { more.disabled = false; }
  }
  function open() {
    source = getSource();
    if (!isWasm(source)) return;
    // Graph and Map draw over the same pane, so they close first.
    for (const view of exclusive) if (view?.getAttribute('aria-pressed') === 'true') view.click();
    isOpen = true; root.hidden = false; split.hidden = true;
    button.setAttribute('aria-pressed', 'true');
    current.textContent = nameOf(source);
    current.title = `A: artifact ${source.artifact_id} · ${source.sha256 ?? ''}`;
    const modules = fillPicker();
    if (!modules.length) {
      summary.textContent = '';
      notes.hidden = true;
      setState('empty', 'No other captured WebAssembly module to compare with. Capture another build, then compare.');
      return;
    }
    load();
    picker.focus();
  }
  function closePanel() {
    if (!isOpen) return;
    isOpen = false; root.hidden = true; split.hidden = false;
    abort?.abort(); generation += 1;
    button.setAttribute('aria-pressed', 'false');
  }
  button.addEventListener('click', () => { if (isOpen) closePanel(); else open(); });
  close.addEventListener('click', () => { closePanel(); button.closest('details')?.querySelector('summary')?.focus(); });
  run.addEventListener('click', () => load());
  retry.addEventListener('click', () => load());
  more.addEventListener('click', () => loadMore());
  picker.addEventListener('change', () => { other = (listModules() ?? []).find(module => module.artifact_id === picker.value) ?? null; load(); });
  // Graph, Map and Inspect are other views of the same artifact; choosing one closes this.
  for (const trigger of closeOn) trigger?.addEventListener('click', () => { if (isOpen) closePanel(); });
  root.addEventListener('keydown', event => { if (event.key === 'Escape' && isOpen) { event.stopPropagation(); closePanel(); } });
  return {
    /** Called when the selected source may have changed. */
    sync(next) {
      const valid = isWasm(next);
      button.hidden = !valid; button.disabled = !valid;
      if (isOpen && (!valid || next.artifact_id !== source?.artifact_id || next.sha256 !== source?.sha256)) closePanel();
    },
    setScreenVisible(visible) { if (screenVisible === visible) return; screenVisible = visible; if (!visible) closePanel(); },
    isOpen: () => isOpen,
    open,
    close: closePanel
  };
}

if (typeof module !== 'undefined') module.exports = {wasmDiffCandidates, isWasmDiffDocument, wasmDiffFunctionLabel, wasmDiffFunctionDetail, wasmDiffSummaryText, createWasmDiffPanel};
