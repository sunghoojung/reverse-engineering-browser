/* Library identification for the Wasm module open in Sources Inspect: one
 * compact summary (toolchain, constant matches, labeled functions) above the
 * listing, and the per-function badges the Graph's Functions menu shows.
 * The report is wasm-identification-v1 from /api/wasm/identification. Every
 * value from it is captured or derived from captured bytes, so it is inserted
 * as text only, and every chip reveals the module byte it rests on. */
const WASM_IDENTIFICATION_CACHE = 4;
const WASM_IDENTIFICATION_TIMEOUT_MS = 10000;
/* Chips shown on one summary line before the rest go to Details. */
const WASM_IDENTIFICATION_CHIPS = 3;
/* Function rows Details lists; the agent API pages the rest. */
const WASM_IDENTIFICATION_ROWS = 200;
const WASM_IDENTIFICATION_CATEGORY = {
  js_glue: 'JS glue', export_glue: 'glue', runtime: 'runtime', allocator: 'alloc', libc: 'libc', wasi: 'WASI',
  syscall: 'syscall', entry: 'entry', std: 'std', library: 'library', crypto: 'crypto', checksum: 'checksum',
  hash_mix: 'hash', encoding: 'encoding'
};
const wasmIdentificationReports = new Map();

function wasmIdentificationKey(source) {
  return `${source.artifact_id}:${source.sha256}`;
}

/** A report this view can trust: its identity matches the selected bytes and
 * every part it reads has the declared shape. */
function isWasmIdentification(report, source) {
  return report?.schema === 'wasm-identification-v1' && String(report.artifact_id) === String(source.artifact_id) &&
    report.sha256 === source.sha256 && Array.isArray(report.toolchain?.conclusions) &&
    Array.isArray(report.functions?.suggestions) && Array.isArray(report.constants?.matches) && Array.isArray(report.omissions);
}

/* Badges by function index, built once per report: the Functions filter
 * asks for every function on each keystroke, so one lookup each. */
const wasmIdentificationBadges = new WeakMap();

function wasmIdentificationBadgeMap(report) {
  let badges = wasmIdentificationBadges.get(report);
  if (badges) return badges;
  const rank = {high: 0, medium: 1, low: 2};
  const rows = new Map(), constants = new Map();
  const add = (map, key, value) => { const list = map.get(key); if (list) list.push(value); else map.set(key, [value]); };
  for (const row of report.functions.suggestions) add(rows, row[0], row);
  for (const match of report.constants.matches) {
    const named = new Set([match.function_index, ...(match.referenced_by ?? []).map(reference => reference.function_index)]);
    for (const index of named) if (Number.isSafeInteger(index)) add(constants, index, match);
  }
  badges = new Map();
  for (const index of new Set([...rows.keys(), ...constants.keys()])) {
    const own = (rows.get(index) ?? []).sort((a, b) => rank[a[4]] - rank[b[4]]);
    const named = constants.get(index) ?? [];
    const text = own.length ? WASM_IDENTIFICATION_CATEGORY[own[0][2]] ?? own[0][2] : 'constant';
    const title = [...own.map(row => `${row[1]} (${row[4]}, ${row[5]} at byte ${row[6]})`),
      ...named.map(match => `${match.label}: ${match.matched}/${match.total} ${match.match}`)].join('\n');
    badges.set(index, {text, title, search: `${text} ${title}`});
  }
  wasmIdentificationBadges.set(report, badges);
  return badges;
}

/** The badge for one function in the Functions menu, or null: the strongest
 * suggestion's category, then a constant the function names. */
function wasmIdentificationBadge(source, functionIndex) {
  const report = source && wasmIdentificationReports.get(wasmIdentificationKey(source));
  return report ? wasmIdentificationBadgeMap(report).get(functionIndex) ?? null : null;
}

const wasmIdentificationRequests = new Map();
const wasmIdentificationListeners = new Set();

/** Reads the report for `source` once (again with `retry`). Inspect and the
 * Graph's Functions menu share it; both are explicit actions, so selecting a
 * module alone never starts an analysis. */
async function wasmIdentificationLoad(source, retry = false) {
  const key = wasmIdentificationKey(source);
  const requests = wasmIdentificationRequests;
  if (requests.get(key)?.status === 'loading' || (!retry && wasmIdentificationReports.has(key))) return;
  requests.set(key, {status: 'loading'});
  while (requests.size > 64) {
    const retired = [...requests].find(([id, request]) => id !== key && request.status !== 'loading');
    if (!retired) break;
    requests.delete(retired[0]);
  }
  const notify = () => { for (const listener of wasmIdentificationListeners) listener(); };
  notify();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), WASM_IDENTIFICATION_TIMEOUT_MS);
  try {
    const response = await fetch(`/api/wasm/identification?artifact_id=${encodeURIComponent(source.artifact_id)}`, {cache: 'no-store', signal: controller.signal});
    const report = await response.json();
    if (!response.ok) throw new Error(report.error || `Identification returned ${response.status}`);
    if (!isWasmIdentification(report, source)) throw new Error('The identification report did not match these module bytes.');
    wasmIdentificationReports.delete(key);
    wasmIdentificationReports.set(key, report);
    // An evicted report's request goes with it, so returning to that module
    // reads it again instead of showing a ready state with nothing to show.
    while (wasmIdentificationReports.size > WASM_IDENTIFICATION_CACHE) {
      const evicted = wasmIdentificationReports.keys().next().value;
      wasmIdentificationReports.delete(evicted);
      requests.delete(evicted);
    }
    requests.set(key, {status: 'ready'});
  } catch (error) {
    // A failed refresh keeps the last report for these bytes on screen.
    requests.set(key, {status: 'error', error: error.name === 'AbortError' ? 'Identification timed out. Original bytes are preserved.'
      : error instanceof TypeError ? 'The evidence service is unreachable.' : error.message});
  } finally {
    clearTimeout(timeout);
    notify();
  }
}

function createWasmIdentificationPanel({root, getSource, inspecting, reveal}) {
  if (!root) return {sync() {}, report: () => null};
  const requests = wasmIdentificationRequests;
  let shownKey = null, detailsOpen = false;

  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const chip = (text, title, offset, source) => {
    const button = element('button', 'wasm-id-chip', text);
    button.type = 'button';
    button.title = `${title}\nShow byte ${offset}`;
    if (button.dataset) button.dataset.byteOffset = String(offset);
    button.addEventListener('click', () => reveal(source, offset));
    return button;
  };

  const load = (source, retry = false) => wasmIdentificationLoad(source, retry);

  function row(label, ...children) {
    const line = element('div', 'wasm-id-row');
    line.append(element('span', 'wasm-id-key', label), ...children);
    return line;
  }

  function summary(report, source) {
    const toolchains = report.toolchain.conclusions;
    const constants = report.constants.matches;
    const fns = report.functions;
    const total = fns.imported_functions + fns.defined_functions;
    const values = element('span', 'wasm-id-values');
    if (!toolchains.length) values.append(element('span', 'wasm-id-none', 'No toolchain evidence; nothing is concluded from absence.'));
    for (const conclusion of toolchains.slice(0, WASM_IDENTIFICATION_CHIPS)) {
      const first = conclusion.evidence[0];
      const button = chip(`${conclusion.label} · ${conclusion.confidence}`,
        conclusion.evidence.map(item => `${item.detail} (byte ${item.byte_offset})`).join('\n'), first?.byte_offset ?? 0, source);
      if (button.dataset) button.dataset.confidence = conclusion.confidence;
      values.append(button);
    }
    const constantValues = element('span', 'wasm-id-values');
    if (!constants.length) constantValues.append(element('span', 'wasm-id-none', 'No known constants matched.'));
    for (const match of constants.slice(0, WASM_IDENTIFICATION_CHIPS)) {
      const where = match.location === 'immediate' ? `immediates in func ${match.function_index}` : `data segment ${match.data_segment}`;
      // The chip names the set; the tooltip keeps every algorithm sharing it.
      const short = match.label.replace(/ \(.*\)$/, '');
      const button = chip(`${short} ${match.matched}/${match.total}`, `${match.label}\n${match.match} match in ${where}`, match.byte_offset, source);
      if (button.dataset) button.dataset.match = match.match;
      constantValues.append(button);
    }
    const more = toolchains.length + constants.length - Math.min(toolchains.length, WASM_IDENTIFICATION_CHIPS) - Math.min(constants.length, WASM_IDENTIFICATION_CHIPS);
    const toggle = element('button', 'wasm-id-toggle', detailsOpen ? 'Hide details' : more > 0 ? `Details (+${more})` : 'Details');
    toggle.type = 'button';
    toggle.setAttribute('aria-expanded', String(detailsOpen));
    toggle.addEventListener('click', () => { detailsOpen = !detailsOpen; render(); root.querySelector('.wasm-id-toggle')?.focus(); });
    const status = report.status === 'partial' ? element('span', 'wasm-id-partial', 'partial') : null;
    if (status) status.title = report.omissions.join('\n');
    const counts = element('span', 'wasm-id-count', `${fns.labeled_functions.toLocaleString()} of ${total.toLocaleString()} functions labeled`);
    return [row('Toolchain', values), row('Constants', constantValues), row('Functions', counts, ...(status ? [status] : []), toggle)];
  }

  function details(report, source) {
    const list = element('div', 'wasm-id-details');
    list.setAttribute('role', 'region');
    list.setAttribute('aria-label', 'Identification details');
    list.tabIndex = 0;
    const group = (title, items) => {
      list.append(element('h3', 'wasm-id-group', title));
      if (!items.length) list.append(element('p', 'wasm-id-none', 'None.'));
      for (const item of items) list.append(item);
    };
    group('Toolchain evidence', report.toolchain.conclusions.map(conclusion => {
      const line = element('div', 'wasm-id-detail');
      line.append(element('span', 'wasm-id-label', `${conclusion.label} · ${conclusion.confidence}`),
        ...conclusion.evidence.slice(0, 4).map(item => chip(`${item.record.replace("_", " ")} · byte ${item.byte_offset}`, item.detail, item.byte_offset, source)));
      if (conclusion.evidence_count > 4) line.append(element('span', 'wasm-id-more', `${conclusion.evidence_count - 4} more`));
      return line;
    }));
    group('Constants', report.constants.matches.map(match => {
      const line = element('div', 'wasm-id-detail');
      const refs = match.location === 'immediate' ? [`func ${match.function_index}`]
        : (match.referenced_by ?? []).map(reference => `func ${reference.function_index}`);
      line.append(element('span', 'wasm-id-label', `${match.label} · ${match.matched}/${match.total} ${match.match}`),
        chip(`${match.location} · byte ${match.byte_offset}`, refs.length ? `Named by ${[...new Set(refs)].join(', ')}` : 'No function names its address', match.byte_offset, source));
      if (refs.length) line.append(element('span', 'wasm-id-more', `named by ${[...new Set(refs)].slice(0, 4).join(', ')}`));
      return line;
    }));
    const rows = report.functions.suggestions.slice(0, WASM_IDENTIFICATION_ROWS);
    group('Function labels (suggestions)', rows.map(([fn, label, category, library, confidence, record, offset]) => {
      const line = element('div', 'wasm-id-detail');
      const badge = element('span', 'wasm-id-badge', WASM_IDENTIFICATION_CATEGORY[category] ?? category);
      badge.title = `${library} · ${confidence}`;
      line.append(element('span', 'wasm-id-fn', `func ${fn}`), badge, element('span', 'wasm-id-label', label),
        chip(`${record} · byte ${offset}`, `${library} · ${confidence} confidence`, offset, source));
      return line;
    }));
    const listed = report.functions.suggestion_window.total_rows;
    if (listed > rows.length) list.append(element('p', 'wasm-id-none', `First ${rows.length} of ${listed.toLocaleString()} suggestions shown.`));
    list.append(element('p', 'wasm-id-notice', 'Static suggestions from the cited bytes. They never replace captured or analyst names; a constant match is not proof an algorithm runs.'));
    return list;
  }

  function render() {
    const source = getSource();
    const active = Boolean(source && inspecting(source));
    root.hidden = !active;
    if (!active) { shownKey = null; root.replaceChildren(); return; }
    const key = wasmIdentificationKey(source);
    if (key !== shownKey) { shownKey = key; detailsOpen = false; }
    const report = wasmIdentificationReports.get(key);
    const request = requests.get(key);
    // Ready with no report means it was evicted: read it again.
    if (!report && (!request || request.status === 'ready')) { load(source); return; }
    if (!report) {
      if (request.status === 'loading') { root.replaceChildren(element('p', 'wasm-id-state', 'Identifying toolchain, functions and constants…')); return; }
      const retry = element('button', 'wasm-id-toggle', 'Retry identification');
      retry.type = 'button';
      retry.addEventListener('click', () => load(source, true));
      const message = element('p', 'wasm-id-state', request.error || 'Identification failed. Original bytes are preserved.');
      message.setAttribute('role', 'alert');
      root.replaceChildren(message, retry);
      return;
    }
    root.replaceChildren(...summary(report, source), ...(detailsOpen ? [details(report, source)] : []));
  }

  wasmIdentificationListeners.add(render);
  return {sync: render, report: source => (source ? wasmIdentificationReports.get(wasmIdentificationKey(source)) ?? null : null)};
}

// tools/check-wasm-identification-ui.mjs loads this file in a DOM model.
if (typeof module === 'object' && module?.exports) module.exports = {isWasmIdentification, wasmIdentificationBadge, wasmIdentificationReports, wasmIdentificationRequests, wasmIdentificationLoad, createWasmIdentificationPanel};
