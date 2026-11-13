/* Readable view: one Wasm function's lifted listing (wasm-pseudocode-v1),
 * read one window of lines at a time beside the disassembly and the hex.
 * Captured text is inserted only as text. Each line names the module byte
 * ranges it covers, and choosing a line reveals its first byte in the linear
 * view below. */
const WASM_READABLE_PAGE = 400;
/* A few windows are kept, never a whole module's functions. */
const WASM_READABLE_CACHE = 6;
const WASM_READABLE_KINDS = ['header', 'statement', 'open', 'middle', 'close', 'case', 'fallback'];

/** Validates one readable document against the window it was asked for. */
function wasmReadableDocument(doc, artifactId, functionIndex, offset) {
  const valid = doc?.schema === 'wasm-pseudocode-v1' && String(doc.artifact_id) === String(artifactId) && doc.function_index === functionIndex &&
    Array.isArray(doc.lines) && typeof doc.text === 'string' && doc.window?.line_offset === offset && Number.isSafeInteger(doc.line_count);
  if (!valid) throw Error('The readable view returned an invalid document.');
  const texts = doc.text.split('\n');
  if (texts.at(-1) === '') texts.pop();
  if (texts.length !== doc.lines.length) throw Error('The readable view returned lines that do not match their text.');
  const lines = doc.lines.map((line, index) => {
    if (!Array.isArray(line) || line.length !== 4 || !Array.isArray(line[3])) throw Error('The readable view returned a malformed line.');
    const ranges = line[3].filter(range => Array.isArray(range) && Number.isSafeInteger(range[0]) && Number.isSafeInteger(range[1]) && range[0] < range[1] && range[1] <= doc.byte_size);
    return {number: offset + index, depth: line[0], kind: WASM_READABLE_KINDS[line[1]] ?? 'statement', owned: line[2], ranges, text: texts[index]};
  });
  return {doc, lines};
}

/** Reads one window of one function's readable lift. */
async function readWasmReadable(artifactId, functionIndex, offset, signal) {
  const query = `artifact_id=${encodeURIComponent(artifactId)}&function=${functionIndex}&line_offset=${offset}&line_limit=${WASM_READABLE_PAGE}`;
  const response = await fetch(`/api/wasm/pseudocode?${query}`, {cache: 'no-store', signal});
  if (!response.ok) {
    let message = `The readable view returned ${response.status}.`;
    try { message = (await response.json()).error || message; } catch {}
    throw Error(message);
  }
  return wasmReadableDocument(await response.json(), artifactId, functionIndex, offset);
}

/** What the header says about one document: size, fallbacks and limits. */
function wasmReadableSummary(doc) {
  const parts = [`${doc.line_count.toLocaleString()} lines`, `${doc.instruction_count.toLocaleString()} instructions`];
  if (doc.fallback_count) parts.push(`${doc.fallback_count.toLocaleString()} raw`);
  if (doc.spill_count) parts.push(`${doc.spill_count.toLocaleString()} temporaries`);
  if (doc.status !== 'complete') parts.push('partial');
  return parts.join(' · ');
}

function createWasmReadablePanel({host, editor, button, closeOn = [], revealOffset, initialFunction}) {
  host.hidden = true;
  host.classList.add('wasm-readable');
  const header = document.createElement('div'); header.className = 'wasm-readable-header';
  const previous = document.createElement('button'); previous.type = 'button'; previous.className = 'source-tool'; previous.textContent = '‹'; previous.setAttribute('aria-label', 'Previous function');
  const label = document.createElement('label'); label.className = 'wasm-readable-function';
  const labelText = document.createElement('span'); labelText.textContent = 'Function';
  const input = document.createElement('input'); input.type = 'number'; input.min = '0'; input.step = '1'; input.setAttribute('aria-label', 'Function index');
  label.append(labelText, input);
  const next = document.createElement('button'); next.type = 'button'; next.className = 'source-tool'; next.textContent = '›'; next.setAttribute('aria-label', 'Next function');
  const title = document.createElement('span'); title.className = 'wasm-readable-title';
  const stats = document.createElement('span'); stats.className = 'wasm-readable-stats';
  header.append(previous, label, next, title, stats);
  const status = document.createElement('p'); status.className = 'wasm-readable-status'; status.setAttribute('role', 'status');
  const list = document.createElement('div'); list.className = 'wasm-readable-lines'; list.tabIndex = 0;
  list.setAttribute('role', 'listbox'); list.setAttribute('aria-label', 'Readable lines');
  const pager = document.createElement('div'); pager.className = 'wasm-readable-pager';
  const earlier = document.createElement('button'); earlier.type = 'button'; earlier.className = 'source-tool'; earlier.textContent = 'Earlier lines';
  const later = document.createElement('button'); later.type = 'button'; later.className = 'source-tool'; later.textContent = 'Later lines';
  const notice = document.createElement('span'); notice.className = 'wasm-readable-notice';
  notice.textContent = 'Static lift, not executed. Raw lines keep the instruction the lift did not fold.';
  pager.append(earlier, later, notice);
  host.replaceChildren(header, status, list, pager);

  let source = null, isOpen = false, screenVisible = true, functions = null, functionIndex = null, offset = 0, current = null, selected = -1, abort = null, generation = 0;
  const cache = new Map();
  const isWasmSource = candidate => candidate?.kind === 'wasm' && candidate?.source_type === 'artifact';
  const key = (index, start) => `${source?.artifact_id}:${source?.sha256}:${index}:${start}`;

  function setStatus(text, kind = 'info') { status.textContent = text; status.dataset && (status.dataset.kind = kind); status.hidden = !text; }
  function claim() { const owner = ++generation; abort?.abort(); abort = new AbortController(); return () => owner === generation; }

  function renderLines() {
    list.replaceChildren();
    if (!current) return;
    const {doc, lines} = current;
    title.textContent = `${doc.name} (func ${doc.function_index})`;
    stats.textContent = wasmReadableSummary(doc);
    for (const line of lines) {
      const row = document.createElement('div');
      row.className = `wasm-readable-line wasm-readable-${line.kind}`;
      row.id = `wasm-readable-line-${line.number}`;
      row.setAttribute('role', 'option'); row.setAttribute('aria-selected', 'false');
      const at = document.createElement('span'); at.className = 'wasm-readable-offset';
      at.textContent = line.ranges.length ? line.ranges[0][0].toString(16).padStart(6, '0') : '';
      const body = document.createElement('span'); body.className = 'wasm-readable-text';
      body.textContent = line.text;
      row.append(at, body);
      if (line.kind === 'fallback') {
        const chip = document.createElement('span'); chip.className = 'wasm-readable-raw'; chip.textContent = 'raw';
        chip.title = 'The lift did not fold this instruction; it is the disassembly text.';
        row.append(chip);
      }
      row.title = line.ranges.map(range => `${range[0].toString(16)}-${range[1].toString(16)}`).join(', ');
      row.addEventListener('click', () => { select(line.number - doc.window.line_offset); reveal(); });
      list.append(row);
    }
    earlier.disabled = doc.window.line_offset === 0;
    later.disabled = doc.window.next_line_offset === null;
    pager.hidden = earlier.disabled && later.disabled;
    const omissions = (doc.omissions ?? []).filter(text => !text.includes('raw fallback'));
    setStatus(omissions[0] ?? '', omissions.length ? 'warning' : 'info');
  }
  function select(position) {
    if (!current?.lines.length) return;
    const rows = list.children;
    if (rows[selected]) rows[selected].setAttribute('aria-selected', 'false');
    selected = Math.max(0, Math.min(current.lines.length - 1, position));
    const row = rows[selected];
    row.setAttribute('aria-selected', 'true');
    list.setAttribute('aria-activedescendant', row.id);
    row.scrollIntoView?.({block: 'nearest'});
  }
  function reveal() {
    const line = current?.lines[selected];
    if (line?.ranges.length) revealOffset?.(line.ranges[0][0]);
  }

  async function load(index, start = 0, focusLast = false) {
    if (!source || !isOpen || !Number.isSafeInteger(index) || index < 0) return;
    functionIndex = index; offset = start; input.value = String(index);
    const owned = claim(), cacheKey = key(index, start);
    const hit = cache.get(cacheKey);
    try {
      if (!hit) { list.replaceChildren(); setStatus('Lifting the function from immutable module bytes…'); }
      const result = hit ?? await readWasmReadable(source.artifact_id, index, start, abort.signal);
      if (!owned()) return;
      cache.delete(cacheKey); cache.set(cacheKey, result);
      while (cache.size > WASM_READABLE_CACHE) cache.delete(cache.keys().next().value);
      current = result; selected = -1; renderLines();
      if (result.lines.length) select(focusLast ? result.lines.length - 1 : 0);
    } catch (error) {
      if (!owned() || error.name === 'AbortError') return;
      current = null; list.replaceChildren(); title.textContent = `func ${index}`; stats.textContent = '';
      pager.hidden = true;
      setStatus(error instanceof TypeError ? 'The evidence service is unreachable. Check that the session is still running.' : error.message, 'error');
    }
  }
  async function start() {
    const owned = claim();
    setStatus('Listing functions from immutable module bytes…');
    try {
      functions = await readWasmFunctionIndex(source.artifact_id, abort.signal);
      if (!owned()) return;
      if (!functions.index.length) { setStatus(functions.omissions[0] || 'This module declares no function bodies.'); return; }
      const wanted = initialFunction?.();
      const largest = functions.index.reduce((best, candidate) => (functions.size.get(candidate) > functions.size.get(best) ? candidate : best), functions.index[0]);
      load(functions.index.includes(wanted) ? wanted : largest);
    } catch (error) {
      if (owned() && error.name !== 'AbortError') setStatus(graphReadMessage(error), 'error');
    }
  }
  function step(direction) {
    if (!functions?.index.length) return;
    const position = functions.index.indexOf(functionIndex);
    const target = functions.index[Math.max(0, Math.min(functions.index.length - 1, (position < 0 ? 0 : position) + direction))];
    if (target !== undefined && target !== functionIndex) load(target);
  }

  previous.addEventListener('click', () => step(-1));
  next.addEventListener('click', () => step(1));
  input.addEventListener('change', () => { const value = Number(input.value); if (Number.isSafeInteger(value)) load(value); });
  earlier.addEventListener('click', () => { if (current) load(functionIndex, Math.max(0, offset - WASM_READABLE_PAGE)); });
  later.addEventListener('click', () => { const after = current?.doc.window.next_line_offset; if (after !== null && after !== undefined) load(functionIndex, after); });
  list.addEventListener('keydown', event => {
    if (!current?.lines.length) return;
    const page = Math.max(1, Math.floor(list.clientHeight / 20) - 1);
    const moves = {ArrowDown: 1, ArrowUp: -1, PageDown: page, PageUp: -page};
    if (event.key in moves) {
      event.preventDefault();
      const target = selected + moves[event.key];
      // Moving past a window's edge reads the neighbouring window.
      if (target >= current.lines.length && current.doc.window.next_line_offset !== null) load(functionIndex, current.doc.window.next_line_offset);
      else if (target < 0 && offset > 0) load(functionIndex, Math.max(0, offset - WASM_READABLE_PAGE), true);
      else select(target);
    } else if (event.key === 'Home') { event.preventDefault(); select(0); }
    else if (event.key === 'End') { event.preventDefault(); select(current.lines.length - 1); }
    else if (event.key === 'Enter') { event.preventDefault(); reveal(); }
  });

  function open() {
    isOpen = true; host.hidden = false; editor.setAttribute('data-readable', 'true'); button.setAttribute('aria-pressed', 'true');
    if (functions && functionIndex !== null) load(functionIndex, offset); else start();
  }
  function close() {
    isOpen = false; host.hidden = true; editor.removeAttribute('data-readable'); button.setAttribute('aria-pressed', 'false');
    abort?.abort(); abort = null; generation += 1;
  }
  function release() { close(); cache.clear(); functions = null; functionIndex = null; offset = 0; current = null; list.replaceChildren(); }
  button.addEventListener('click', () => { if (isOpen) close(); else if (isWasmSource(source)) open(); });
  for (const other of closeOn) other?.addEventListener('click', () => { if (isOpen) close(); });
  return {
    /** Called when the selected source may have changed. */
    sync(nextSource) {
      const valid = isWasmSource(nextSource);
      button.hidden = !valid; button.disabled = !valid;
      const changed = !nextSource || nextSource.artifact_id !== source?.artifact_id || nextSource.sha256 !== source?.sha256;
      if (changed) release();
      source = nextSource ?? null;
    },
    setScreenVisible(visible) { if (screenVisible === visible) return; screenVisible = visible; if (!visible && isOpen) close(); },
    isOpen: () => isOpen,
    close
  };
}

// The offline check reads the document validator.
if (typeof module === 'object' && module?.exports) module.exports = {wasmReadableDocument, wasmReadableSummary, WASM_READABLE_KINDS};
