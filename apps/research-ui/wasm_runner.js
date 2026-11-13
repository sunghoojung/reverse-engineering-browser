/* Run offline: one function of a captured Wasm module, run by the backend's
 * wasmi interpreter with every import stubbed (protocol/wasm-run-v1.md).
 * Nothing runs until the researcher confirms and presses Run. Captured names,
 * values and bytes are inserted as text only. */
const WASM_RUN_TYPES = ['i32', 'i64', 'f32', 'f64', 'v128', 'funcref', 'externref'];
const WASM_RUN_HEX_PREVIEW = 64;
const WASM_RUN_TIMEOUT_MS = 20000;

/** "i32 7, f64 1.5" as typed values. Throws an Error naming the bad entry. */
function wasmRunValues(text) {
  const entries = text.split(',').map(part => part.trim()).filter(Boolean);
  return entries.map((entry, index) => {
    const [type, value, extra] = entry.split(/\s+/);
    if (!WASM_RUN_TYPES.includes(type) || !value || extra !== undefined) throw Error(`Argument ${index + 1} must be a type and a value, such as i32 7.`);
    return {type, value};
  });
}

/** "offset:length" or "offset:hex" pairs, comma separated. */
function wasmRunPairs(text, label, second) {
  return text.split(',').map(part => part.trim()).filter(Boolean).map((entry, index) => {
    const match = /^(\d+):(\S+)$/.exec(entry);
    if (!match) throw Error(`${label} ${index + 1} must be offset:${second}.`);
    return [Number(match[1]), match[2]];
  });
}

/** The request body from the dialog fields, or an Error for the first bad field. */
function wasmRunRequest(source, fields) {
  const request = {artifact_id: String(source.artifact_id), sha256: source.sha256, function_index: Number(fields.func.value), args: wasmRunValues(fields.args.value)};
  const stubs = fields.imports.value.trim();
  if (stubs) {
    let parsed;
    try { parsed = JSON.parse(stubs); } catch { throw Error('Import stubs must be a JSON array.'); }
    if (!Array.isArray(parsed)) throw Error('Import stubs must be a JSON array.');
    request.imports = parsed;
  }
  const writes = wasmRunPairs(fields.writes.value, 'Memory write', 'hex');
  if (writes.length) request.memory_writes = writes.map(([offset, hex]) => ({offset, hex}));
  const reads = wasmRunPairs(fields.reads.value, 'Memory read', 'length');
  if (reads.length) request.memory_reads = reads.map(([offset, length]) => ({offset, length: Number(length)}));
  const limits = {};
  for (const key of ['fuel', 'deadline_ms', 'memory_pages', 'call_depth']) {
    const raw = fields[key].value.trim();
    if (!raw) continue;
    if (!/^[1-9]\d*$/.test(raw)) throw Error(`${fields[key].dataset.label} must be a positive whole number.`);
    limits[key] = Number(raw);
  }
  if (Object.keys(limits).length) request.limits = limits;
  if (fields.start.checked) request.run_start = true;
  request.confirm_offline_execution = fields.confirm.checked;
  return request;
}

/** A readable outcome line for a wasm-run-v1 record. */
function wasmRunOutcomeText(record) {
  const outcome = record.outcome ?? {};
  const label = {returned: 'Returned', trap: 'Trapped', import_trap: 'Import trapped', fuel_exhausted: 'Fuel exhausted', deadline_exceeded: 'Deadline exceeded',
    call_depth_exceeded: 'Call depth exceeded', memory_limit: 'Memory limit', table_limit: 'Table limit', instantiation_failed: 'Instantiation failed',
    memory_write_out_of_bounds: 'Memory write out of bounds'}[outcome.status] ?? 'Unknown outcome';
  return `${label}${outcome.trap_kind ? ` (${outcome.trap_kind})` : ''} · ${outcome.phase ?? 'unknown'} phase`;
}

/** What a failed response without a server message means, by status: a 4xx
 * or 503 was refused before the module ran; a 500 may come after it ran. */
function wasmRunFailureText(status) {
  if (status === 503) return 'The runner is unavailable (503). Nothing ran.';
  if (status >= 400 && status < 500) return `The run was refused (${status}). Nothing ran.`;
  return `The run failed in the backend (${status}). The function may have run, but no record was returned.`;
}

function wasmRunTyped(values) {
  return Array.isArray(values) && values.length ? values.map(v => `${v.type} ${v.value}`).join(', ') : 'none';
}

function createWasmRunDialog({button, getSource}) {
  if (!button) return null;
  const el = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };
  const dialog = el('dialog', 'wasm-run-dialog');
  dialog.setAttribute('aria-labelledby', 'wasm-run-title');
  const form = el('form', 'wasm-run-form'); form.method = 'dialog';
  const title = el('h2', '', 'Run function offline'); title.id = 'wasm-run-title';
  const banner = el('p', 'wasm-run-banner', 'Captured code runs in a local sandbox: the wasmi interpreter in this backend, offline, with every import stubbed. Nothing reaches the network, files, clock or the page. Nothing runs until you confirm and press Run. The result is a derived experiment record, not evidence.');
  banner.setAttribute('role', 'note');
  const moduleLine = el('p', 'wasm-run-module');
  const fields = {};
  const field = (key, label, control, hint) => {
    const wrap = el('label', 'wasm-run-field');
    wrap.append(el('span', 'wasm-run-label', label), control);
    if (hint) wrap.append(el('small', 'wasm-run-hint', hint));
    control.dataset.label = label;
    fields[key] = control;
    return wrap;
  };
  const input = (placeholder) => { const node = el('input'); node.type = 'text'; node.placeholder = placeholder; node.spellcheck = false; node.autocomplete = 'off'; return node; };
  const func = el('select'); func.setAttribute('aria-describedby', 'wasm-run-func-status');
  const funcStatus = el('small', 'wasm-run-hint', ''); funcStatus.id = 'wasm-run-func-status';
  const funcField = field('func', 'Function', func); funcField.append(funcStatus);
  const imports = el('textarea'); imports.rows = 3; imports.spellcheck = false;
  imports.placeholder = '[{"module":"env","field":"now","results":[{"type":"f64","value":"0"}]}]';
  const limits = el('div', 'wasm-run-limits');
  for (const [key, label, placeholder] of [['fuel', 'Fuel', '100000000'], ['deadline_ms', 'Deadline (ms)', '2000'], ['memory_pages', 'Memory pages', '256'], ['call_depth', 'Call depth', '1000']]) {
    const node = input(placeholder); node.inputMode = 'numeric';
    limits.append(field(key, label, node));
  }
  const start = el('input'); start.type = 'checkbox';
  const startField = el('label', 'wasm-run-check'); startField.append(start, el('span', '', 'Run the start function first'));
  fields.start = start;
  const confirm = el('input'); confirm.type = 'checkbox';
  const confirmField = el('label', 'wasm-run-check wasm-run-confirm'); confirmField.append(confirm, el('span', '', 'I confirm this captured function runs offline in the local sandbox'));
  fields.confirm = confirm;
  const error = el('p', 'wasm-run-error'); error.setAttribute('role', 'alert'); error.hidden = true;
  const run = el('button', 'primary-button', 'Run'); run.type = 'button'; run.disabled = true;
  const close = el('button', 'secondary-button', 'Close'); close.type = 'button';
  const actions = el('div', 'wasm-run-actions'); actions.append(close, run);
  const output = el('section', 'wasm-run-output'); output.setAttribute('aria-label', 'Run result'); output.setAttribute('aria-live', 'polite'); output.hidden = true;
  form.append(title, banner, moduleLine, funcField,
    field('args', 'Arguments', input('i32 7, i32 5'), 'Type and value per parameter, comma separated.'),
    field('imports', 'Import stubs (JSON)', imports, 'A function import without a stub traps when called. Supply every clock or random source.'),
    field('writes', 'Memory writes before the call', input('16:01020304'), 'offset:hex, comma separated; memory 0.'),
    field('reads', 'Memory reads after the call', input('0:32'), 'offset:length, comma separated; 256 KiB in total.'),
    limits, startField, confirmField, error, actions, output);
  dialog.append(form);
  document.body.append(dialog);

  let source = null, generation = 0, abort = null;
  const isWasm = candidate => candidate?.kind === 'wasm' && candidate?.source_type === 'artifact';
  const sync = () => { run.disabled = !confirm.checked || !func.value || run.dataset.busy === 'true'; };
  confirm.addEventListener('change', sync);
  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => { abort?.abort(); abort = null; generation += 1; run.dataset.busy = 'false'; button.focus({preventScroll: true}); });

  async function loadFunctions(owner) {
    func.replaceChildren(); funcStatus.textContent = 'Reading the function index…'; sync();
    try {
      const response = await fetch(`/api/wasm/functions?artifact_id=${encodeURIComponent(source.artifact_id)}`, {cache: 'no-store'});
      const doc = await response.json();
      if (owner !== generation) return;
      if (!response.ok) throw Error(doc?.error || `The function index read returned ${response.status}.`);
      if (doc?.schema !== 'wasm-function-index-v1' || String(doc.artifact_id) !== String(source.artifact_id) || !Array.isArray(doc.functions)) throw Error('The function index returned an invalid document.');
      const names = new Map();
      for (const entry of doc.names ?? []) if (Array.isArray(entry) && Number.isSafeInteger(entry[0]) && typeof entry[1] === 'string' && !names.has(entry[0])) names.set(entry[0], entry[1]);
      const rows = doc.functions.filter(row => Array.isArray(row) && Number.isSafeInteger(row[0]));
      // Named functions (exports first) lead the list; the rest follow in index order.
      rows.sort((a, b) => Number(names.has(b[0])) - Number(names.has(a[0])) || a[0] - b[0]);
      for (const row of rows) {
        const option = el('option', '', names.has(row[0]) ? `${names.get(row[0])} (func ${row[0]})` : `func ${row[0]}`);
        option.value = String(row[0]);
        func.append(option);
      }
      funcStatus.textContent = rows.length ? `${rows.length.toLocaleString()} defined functions${doc.status === 'partial' ? ' · partial index' : ''}` : 'This module defines no functions.';
    } catch (failure) {
      if (owner === generation) funcStatus.textContent = failure instanceof TypeError ? 'The evidence service is unreachable.' : failure.message;
    }
    sync();
  }

  function renderRecord(record) {
    const rows = [];
    const outcome = el('p', 'wasm-run-outcome', wasmRunOutcomeText(record));
    outcome.dataset.status = String(record.outcome?.status ?? 'unknown');
    rows.push(outcome, el('p', 'wasm-run-message', String(record.outcome?.message ?? '')));
    const facts = el('dl', 'wasm-run-facts');
    const fact = (term, value) => facts.append(el('dt', '', term), el('dd', '', value));
    fact('Function', `${record.function?.export ? `${record.function.export} ` : ''}func ${record.function?.index} · bytes ${record.function?.byte_offset}–${record.function?.byte_end}`);
    fact('Results', record.results ? wasmRunTyped(record.results) : 'none (did not return)');
    fact('Fuel', `${Number(record.fuel_consumed ?? 0).toLocaleString()} of ${Number(record.provenance?.limits?.fuel ?? 0).toLocaleString()}`);
    fact('Elapsed', `${record.elapsed_ms} ms`);
    if (record.memory_grow_denied) fact('Growth denied', `${record.memory_grow_denied} memory.grow call(s) past the limit returned -1`);
    fact('Record', `${record.run_id}${record.stored === false ? ` · not stored: ${record.store_error}` : ' · stored as a derived run'}`);
    rows.push(facts);
    const calls = Array.isArray(record.import_calls) ? record.import_calls : [];
    const callTitle = el('h3', '', `Import calls · ${Number(record.import_calls_total ?? 0).toLocaleString()} attempted${record.import_calls_truncated ? `, first ${calls.length} recorded` : ''}`);
    rows.push(callTitle);
    if (calls.length) {
      const table = el('table', 'wasm-run-calls');
      const head = el('tr'); for (const label of ['#', 'Import', 'Arguments', 'Outcome']) head.append(el('th', '', label));
      table.append(head);
      for (const call of calls) {
        const row = el('tr');
        row.append(el('td', '', String(call.sequence)), el('td', '', `${call.module}.${call.field} (func ${call.function_index})`),
          el('td', '', `${wasmRunTyped(call.args)}${call.args_truncated ? ' …' : ''}`),
          el('td', '', call.outcome === 'returned' ? `returned ${wasmRunTyped(call.results)}` : 'trapped (no stub value)'));
        table.append(row);
      }
      rows.push(table);
    } else rows.push(el('p', 'wasm-run-hint', 'No import was called.'));
    const reads = Array.isArray(record.memory_reads) ? record.memory_reads : [];
    if (reads.length) {
      rows.push(el('h3', '', 'Memory reads'));
      const list = el('ul', 'wasm-run-reads');
      for (const read of reads) {
        const hex = typeof read.hex === 'string' ? read.hex : '';
        const preview = hex.slice(0, WASM_RUN_HEX_PREVIEW * 2) + (hex.length > WASM_RUN_HEX_PREVIEW * 2 ? ' …' : '');
        list.append(el('li', '', `${read.offset}:${read.length} · ${read.status}${hex ? ` · ${preview}` : ''}`));
      }
      rows.push(list);
    }
    output.replaceChildren(...rows);
    output.hidden = false;
    // The result follows the fields, below the dialog's visible area; bring
    // its outcome line into view.
    output.scrollIntoView?.({block: 'start'});
  }

  run.addEventListener('click', async () => {
    error.hidden = true;
    // The disabled state is not the gate: a click that still arrives without
    // the confirmation sends nothing.
    if (!confirm.checked || run.dataset.busy === 'true') {
      if (!confirm.checked) { error.textContent = 'Confirm that the function runs offline in the local sandbox first. Nothing ran.'; error.hidden = false; }
      return;
    }
    let body;
    try { body = wasmRunRequest(source, fields); } catch (failure) { error.textContent = failure.message; error.hidden = false; return; }
    const owner = ++generation;
    abort?.abort(); abort = new AbortController();
    const timer = setTimeout(() => abort?.abort(), WASM_RUN_TIMEOUT_MS);
    run.dataset.busy = 'true'; run.textContent = 'Running…'; sync();
    try {
      const response = await fetch('/api/wasm/runs', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body), signal: abort.signal, cache: 'no-store'});
      const record = await response.json();
      if (owner !== generation) return;
      if (!response.ok) throw Error(record?.error || wasmRunFailureText(response.status));
      if (record?.schema !== 'wasm-run-v1' || record.provenance?.module_sha256 !== source.sha256) throw Error('The runner returned an invalid record.');
      renderRecord(record);
    } catch (failure) {
      if (owner !== generation) return;
      // A failed run has no result, so the previous one must not look like its result.
      output.hidden = true; output.replaceChildren();
      error.textContent = failure.name === 'AbortError' ? 'The run did not answer in time, so its outcome is unknown: it may still finish and be stored as a derived run. Wait at least 10 seconds before running it again.' : failure instanceof TypeError ? 'The evidence service is unreachable.' : failure.message;
      error.hidden = false;
    } finally {
      clearTimeout(timer);
      if (owner === generation) { run.dataset.busy = 'false'; run.textContent = 'Run'; sync(); }
    }
  });

  button.addEventListener('click', () => {
    source = getSource();
    if (!isWasm(source)) return;
    generation += 1;
    moduleLine.textContent = `Artifact ${source.artifact_id} · SHA-256 ${source.sha256.slice(0, 16)}…`;
    confirm.checked = false; error.hidden = true; output.hidden = true; output.replaceChildren();
    dialog.showModal();
    loadFunctions(generation);
    func.focus({preventScroll: true});
  });
  return {
    /** Called when the selected source may have changed. */
    sync(next) {
      const valid = isWasm(next);
      button.hidden = !valid; button.disabled = !valid;
    }
  };
}

if (typeof module === 'object' && module?.exports) module.exports = {wasmRunValues, wasmRunPairs, wasmRunRequest, wasmRunOutcomeText, wasmRunFailureText};
