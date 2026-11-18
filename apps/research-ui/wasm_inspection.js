// Client for inspect_wasm and search_wasm_inspection: a module of any size
// read one 1,000-row page at a time, its byte offsets located on the backend,
// and Find counted over every row there.

// Cache sizes only: every row of a module is reachable, and an evicted page
// or match page is read again.
const WASM_INSPECTION_LIMITS = Object.freeze({modules: 4, pageRows: 1000, pages: 16, searches: 4, matchPage: 1000, matchPages: 8, located: 64});

function wasmInspectionLabel(row) {
  return row.kind === 'instruction' ? `func ${row.function_index}` : row.kind;
}

// The editor line for one row: its kind (or function) column, then its text.
function wasmInspectionLine(row) {
  return `${wasmInspectionLabel(row).padEnd(11)} ${row.text}`;
}

// Where a row's text starts in its editor line, so a match in the text maps to a column.
function wasmInspectionTextColumn(row) {
  return Math.max(11, wasmInspectionLabel(row).length) + 1;
}

function createWasmInspectionClient({request = (...args) => fetch(...args), validate = (document, source) => isWasmInspection(document, source),
  onChange = () => {}, onSearch = () => {}} = {}) {
  const modules = new Map();
  const key = source => `${source.artifact_id}:${source.sha256}`;
  const stride = WASM_INSPECTION_LIMITS.pageRows;
  const failure = error => error?.name === 'AbortError' ? null : String(error?.message ?? error).slice(0, 1024);

  async function read(source, query, signal) {
    const response = await request(`/api/wasm?artifact_id=${encodeURIComponent(source.artifact_id)}${query}`, {cache: 'no-store', signal});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || `Inspection returned ${response.status}`);
    if (!validate(payload, source)) throw new Error('The WASM inspector returned an invalid document.');
    return payload;
  }

  // The summary a page was read with must stay the module's: a different row
  // count means the rows of two different indexes would be joined.
  function adopt(entry, document) {
    const {rows: _rows, row_window: window, ...summary} = document;
    if (entry.summary && entry.totalRows !== window.total_rows) throw new Error('The inspection changed while it was read.');
    entry.summary = summary;
    entry.totalRows = window.total_rows;
  }

  // One page is up to 1,000 rows; the backend's window may stop early to stay
  // small, so a page reads windows until it is whole.
  async function loadPage(entry, block) {
    const controller = new AbortController();
    const page = {status: 'loading', controller};
    entry.pages.set(block, page);
    try {
      const rows = [];
      const start = block * stride;
      let next = start;
      do {
        const document = await read(entry.source, `&row_offset=${next}&row_limit=${stride - rows.length}`, controller.signal);
        adopt(entry, document);
        if (document.row_window.offset !== next) throw new Error('The inspection window does not start where it was asked to.');
        rows.push(...document.rows);
        next = document.row_window.next_offset;
      } while (next !== null && rows.length < stride);
      if (rows.length !== Math.min(stride, entry.totalRows - start)) throw new Error('The inspection page is incomplete.');
      page.view = {rows, lineBase: start, lineCount: Math.max(1, entry.totalRows), block,
        text: rows.map(wasmInspectionLine).join('\n'),
        row: line => rows[line - start] ?? null};
      page.status = 'ready';
      entry.status = 'ready';
      entry.error = null;
      for (const [other, value] of entry.pages) {
        if (entry.pages.size <= WASM_INSPECTION_LIMITS.pages) break;
        if (other !== block && value.status !== 'loading' && other !== entry.shown) entry.pages.delete(other);
      }
    } catch (error) {
      const message = failure(error);
      if (message !== null) {
        entry.pages.delete(block);
        if (entry.status === 'loading') Object.assign(entry, {status: 'error', error: message});
        else entry.pageError = message;
      }
    } finally {
      page.controller = null;
      if (entry.pages.get(block) === page && page.status === 'loading') entry.pages.delete(block);
      if (modules.get(entry.key) === entry) onChange(entry.source);
    }
  }

  function retire(keep) {
    for (const [name, entry] of modules) {
      if (modules.size <= WASM_INSPECTION_LIMITS.modules) break;
      if (name === keep) continue;
      cancelAll(entry);
      modules.delete(name);
    }
  }

  function cancelAll(entry) {
    for (const page of entry.pages.values()) page.controller?.abort();
    for (const search of entry.searches.values()) search.controller?.abort();
    for (const pages of entry.searches.values()) for (const page of pages.pages.values()) page.controller?.abort();
  }

  // The empty view of a module the researcher asked to inspect; its first page
  // loads now. The promise settles once that page is read or has failed.
  function open(source, line = 0, retry = false) {
    const name = key(source);
    let entry = modules.get(name);
    if (entry && retry && ['error', 'cancelled'].includes(entry.status)) {
      modules.delete(name);
      entry = null;
    }
    if (!entry) {
      entry = {key: name, source, status: 'loading', started: Date.now(), summary: null, totalRows: undefined, error: null,
        pages: new Map(), shown: null, searches: new Map(), located: new Map()};
      modules.set(name, entry);
      retire(name);
    }
    page(source, line);
    return entry.pages.get(blockOf(entry, line))?.done ?? Promise.resolve();
  }

  function blockOf(entry, line) {
    if (entry.totalRows === undefined) return 0;
    return Math.max(0, Math.min(Math.max(0, Math.ceil(entry.totalRows / stride) - 1), Math.floor(line / stride)));
  }

  // The page holding row `line`, or {pending, previous} while it is read.
  function page(source, line = 0) {
    const entry = modules.get(key(source));
    if (!entry || ['error', 'cancelled'].includes(entry.status)) return null;
    entry.source = source;
    const block = blockOf(entry, line);
    const found = entry.pages.get(block);
    if (!found) {
      const done = loadPage(entry, block);
      const added = entry.pages.get(block);
      if (added) added.done = done;
    }
    if (found?.status !== 'ready') return {pending: true, previous: entry.pages.get(entry.shown)?.view ?? null};
    entry.pages.delete(block);
    entry.pages.set(block, found);
    entry.shown = block;
    return found.view;
  }

  // Stops the first read; Retry opens the module again.
  function cancel(source) {
    const entry = modules.get(key(source));
    if (!entry || entry.status !== 'loading') return;
    cancelAll(entry);
    Object.assign(entry, {status: 'cancelled', error: 'Inspection cancelled. Its backend decode was stopped; original bytes are preserved.'});
    onChange(source);
  }

  // The row for an original byte: the first row at it, or else the last one before it.
  function locate(source, byte) {
    const entry = modules.get(key(source));
    if (!entry || entry.status !== 'ready' || !Number.isSafeInteger(byte) || byte < 0) return Promise.resolve(null);
    if (entry.located.has(byte)) return entry.located.get(byte);
    const found = read(source, `&byte_offset=${byte}&row_limit=1`).then(document => {
      adopt(entry, document);
      return document.row_window.offset;
    }).catch(() => {
      entry.located.delete(byte);
      return null;
    });
    entry.located.set(byte, found);
    while (entry.located.size > WASM_INSPECTION_LIMITS.located) entry.located.delete(entry.located.keys().next().value);
    return found;
  }

  async function readMatches(entry, search, rank) {
    const controller = new AbortController();
    const block = Math.floor(rank / WASM_INSPECTION_LIMITS.matchPage);
    const page = {status: 'loading', controller};
    search.pages.set(block, page);
    const first = !search.status || search.status === 'loading';
    if (first) search.controller = controller;
    try {
      const response = await request(`/api/wasm/search?artifact_id=${encodeURIComponent(entry.source.artifact_id)}&q=${encodeURIComponent(search.query)}` +
        `&match_offset=${block * WASM_INSPECTION_LIMITS.matchPage}&match_limit=${WASM_INSPECTION_LIMITS.matchPage}`, {cache: 'no-store', signal: controller.signal});
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error || `Find returned ${response.status}`);
      const matches = payload?.matches;
      if (payload?.schema !== 'wasm-inspection-search-v1' || payload.artifact_id !== entry.source.artifact_id || payload.sha256 !== entry.source.sha256 ||
          payload.total_rows !== entry.totalRows || !Number.isSafeInteger(payload.total_matches) || !Array.isArray(matches) ||
          payload.match_window?.offset !== block * WASM_INSPECTION_LIMITS.matchPage ||
          matches.some(match => !Number.isSafeInteger(match?.row) || match.row < 0 || match.row >= entry.totalRows ||
            !Number.isSafeInteger(match.column) || match.column < 0 || !Number.isSafeInteger(match.length) || match.length < 1)) {
        throw new Error('Find returned matches that do not belong to this inspection.');
      }
      if (search.total !== undefined && search.total !== payload.total_matches) throw new Error('The match count changed while Find read it.');
      search.total = payload.total_matches;
      page.matches = matches;
      page.status = 'ready';
      search.status = 'ready';
      for (const [other, value] of search.pages) {
        if (search.pages.size <= WASM_INSPECTION_LIMITS.matchPages) break;
        if (other !== block && value.status !== 'loading') search.pages.delete(other);
      }
    } catch (error) {
      search.pages.delete(block);
      const message = failure(error);
      if (message !== null) Object.assign(search, {status: 'error', error: message});
    } finally {
      page.controller = null;
      if (search.controller === controller) search.controller = null;
      if (entry.searches.get(search.query) === search) onSearch(entry.source, search.query);
    }
  }

  // Find over every row. The first call reads the count and the first page of
  // matches; a query typed past is stopped on the backend.
  function search(source, query) {
    const entry = modules.get(key(source));
    if (!entry || entry.status !== 'ready') return null;
    let found = entry.searches.get(query);
    if (!found) {
      for (const [other, value] of entry.searches) if (other !== query && value.status === 'loading') {
        value.controller?.abort();
        entry.searches.delete(other);
      }
      found = {query, status: 'loading', started: Date.now(), total: undefined, pages: new Map(), controller: null, error: null};
      entry.searches.set(query, found);
      while (entry.searches.size > WASM_INSPECTION_LIMITS.searches) entry.searches.delete(entry.searches.keys().next().value);
      readMatches(entry, found, 0);
    }
    return found;
  }

  // Match `rank` of a ready search, or null while its page of matches is read.
  function match(source, query, rank) {
    const entry = modules.get(key(source));
    const found = entry?.searches.get(query);
    if (!found || found.status !== 'ready' || !Number.isSafeInteger(rank) || rank < 0 || rank >= found.total) return null;
    const block = Math.floor(rank / WASM_INSPECTION_LIMITS.matchPage);
    const page = found.pages.get(block);
    if (!page) readMatches(entry, found, rank);
    return page?.status === 'ready' ? page.matches[rank - block * WASM_INSPECTION_LIMITS.matchPage] ?? null : null;
  }

  // Matches already read for rows lineStart..lineEnd, so mounted rows can be marked.
  function matchesIn(source, query, lineStart, lineEnd) {
    const found = modules.get(key(source))?.searches.get(query);
    const listed = [];
    for (const page of found?.pages.values() ?? []) for (const value of page.matches ?? []) if (value.row >= lineStart && value.row < lineEnd) listed.push(value);
    return listed;
  }

  return {
    open, page, cancel, locate, search, match, matchesIn,
    // {status: loading|ready|error|cancelled, summary, totalRows, error, started}, or null when never opened.
    state(source) {
      const entry = source && modules.get(key(source));
      return entry ? {status: entry.status, summary: entry.summary, totalRows: entry.totalRows, error: entry.error, pageError: entry.pageError ?? null, started: entry.started} : null;
    },
    // The loaded row at an absolute line, or null.
    row(source, line) {
      const entry = source && modules.get(key(source));
      const found = entry?.pages.get(blockOf(entry, line));
      return found?.status === 'ready' ? found.view.row(line) : null;
    }
  };
}
