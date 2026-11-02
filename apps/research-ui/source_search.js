/* Search inside every retained source. Text is literal: captured scripts are
 * adversarial, so no pattern language is offered (a regular expression could
 * backtrack catastrophically on crafted input). Matching reuses the editor's
 * Find index, so a result's line and column are the ones Sources displays.
 * Reads go through the caller's artifact reader, bounded per file and per
 * search, and every file that was not fully searched is named. */
const SOURCE_SEARCH_LIMITS = Object.freeze({
  fileBytes: 2 * 1024 * 1024,   // the Sources preview window, one content request
  totalBytes: 32 * 1024 * 1024, // per search, cached or fetched
  fileMatches: 100,
  totalMatches: 1000,
  before: 12,                   // characters of context kept before a match
  snippet: 120
});

// Matches of one literal in one text. Line separators and over-long queries
// are refused exactly as Find refuses them.
function sourceSearchText(text, query, {matchCase = false, limit = SOURCE_SEARCH_LIMITS.fileMatches} = {}) {
  const index = sourceDocumentIndex(text);
  const found = sourceDocumentMatches(index, query, limit, null, matchCase);
  if (found.error) return {matches: [], truncated: false, error: found.error};
  return {matches: found.matches.map(match => ({line: match.line, column: match.column, length: match.length,
    snippet: sourceSearchSnippet(index, match)})), truncated: found.truncated, error: ''};
}

// One display line around a match, split so the caller can mark the match
// with text nodes. Leading whitespace is dropped; clipped ends are flagged.
function sourceSearchSnippet(index, match, {before = SOURCE_SEARCH_LIMITS.before, maximum = SOURCE_SEARCH_LIMITS.snippet} = {}) {
  const excerpt = sourceDocumentExcerpt(index, match.line, Math.max(0, match.column - before), maximum + before);
  const start = match.column - excerpt.columnStart, end = Math.min(excerpt.text.length, start + match.length);
  let head = excerpt.text.slice(0, start), clippedStart = excerpt.columnStart > 0;
  if (head.length > before) {head = head.slice(head.length - before); clippedStart = true;}
  head = head.replace(/^\s+/, '');
  const tail = excerpt.text.slice(end, end + maximum);
  return {before: head, match: excerpt.text.slice(start, end), after: tail.replace(/\s+$/, ''),
    clippedStart, clippedEnd: excerpt.columnEnd < excerpt.fullLength || end + maximum < excerpt.text.length};
}

// One search at a time. A new run, or cancel(), retires the previous run's
// generation and aborts its reads; late results are dropped.
function createSourceSearch({list, read, onChange, limits = SOURCE_SEARCH_LIMITS, pause = () => new Promise(resolve => setTimeout(resolve, 0))}) {
  const model = {generation: 0, query: '', matchCase: false, status: 'idle', error: '', files: [], total: 0, completed: 0, matches: 0, bytes: 0};
  let controller = null;
  function cancel() {
    model.generation += 1;
    controller?.abort(); controller = null;
    if (model.status === 'running') model.status = 'cancelled';
  }
  async function run(query, matchCase = false) {
    cancel();
    const token = model.generation, own = controller = new AbortController();
    const current = () => token === model.generation;
    Object.assign(model, {query, matchCase: Boolean(matchCase), status: 'running', error: '', files: [], total: 0, completed: 0, matches: 0, bytes: 0});
    if (!query) {model.status = 'idle'; onChange(model, null); return model;}
    const refused = sourceSearchText('', query).error;
    if (refused) {model.status = 'error'; model.error = refused; onChange(model, null); return model;}
    const entries = list();
    model.total = entries.length;
    onChange(model, null);
    for (const entry of entries) {
      const file = {...entry, state: 'searched', matches: [], matchLimit: '', partial: false, lossy: false, error: ''};
      model.files.push(file);
      const size = Math.min(entry.byteSize, limits.fileBytes);
      if (entry.binary) file.state = 'binary';
      else if (model.matches >= limits.totalMatches) file.state = 'match-limit';
      else if (model.bytes + size > limits.totalBytes) file.state = 'byte-limit';
      else {
        try {
          const loaded = await read(entry, own.signal, limits.fileBytes);
          if (!current()) return model;
          model.bytes += loaded.bytes;
          const remaining = limits.totalMatches - model.matches;
          const found = sourceSearchText(loaded.text, query, {matchCase, limit: Math.min(limits.fileMatches, remaining)});
          file.matches = found.matches; file.partial = Boolean(loaded.partial); file.lossy = Boolean(loaded.lossy);
          if (found.truncated) file.matchLimit = remaining < limits.fileMatches ? 'total' : 'file';
          model.matches += found.matches.length;
        } catch (error) {
          if (!current()) return model;
          file.state = 'failed'; file.error = String(error?.message ?? error).slice(0, 256);
        }
      }
      model.completed += 1;
      onChange(model, file);
      // Yield between files so typing and cancellation stay responsive.
      await pause();
      if (!current()) return model;
    }
    model.status = 'done'; controller = null;
    onChange(model, null);
    return model;
  }
  return {model, run, cancel};
}

// Every file that was not searched completely, by reason. Nothing is dropped
// silently: the panel shows each line that applies.
function sourceSearchNotes(model, limits = SOURCE_SEARCH_LIMITS) {
  const names = files => `${files.slice(0, 3).map(file => file.name).join(', ')}${files.length > 3 ? ` and ${files.length - 3} more` : ''}`;
  const count = (files, one, many) => `${files.length} ${files.length === 1 ? one : many}`;
  const by = predicate => model.files.filter(predicate);
  const mib = bytes => `${bytes / (1024 * 1024)} MiB`;
  const notes = [];
  const binary = by(file => file.state === 'binary'), failed = by(file => file.state === 'failed');
  const partial = by(file => file.state === 'searched' && file.partial), lossy = by(file => file.state === 'searched' && file.lossy);
  const capped = by(file => file.matchLimit === 'file'), total = by(file => file.matchLimit === 'total');
  const unsearched = by(file => file.state === 'match-limit'), budget = by(file => file.state === 'byte-limit');
  if (binary.length) notes.push({kind: 'binary', text: `${count(binary, 'binary file', 'binary files')}, not searched: ${names(binary)}.`});
  if (failed.length) notes.push({kind: 'failed', text: `${count(failed, 'file', 'files')} failed to load and ${failed.length === 1 ? 'was' : 'were'} not searched: ${failed.slice(0, 3).map(file => `${file.name} (${file.error})`).join(', ')}${failed.length > 3 ? ` and ${failed.length - 3} more` : ''}. Search again to retry.`});
  if (partial.length) notes.push({kind: 'partial', text: `${count(partial, 'file is', 'files are')} over the ${mib(limits.fileBytes)} size cap; only ${partial.length === 1 ? 'its' : 'their'} first ${mib(limits.fileBytes)} ${partial.length === 1 ? 'was' : 'were'} searched: ${names(partial)}.`});
  if (lossy.length) notes.push({kind: 'lossy', text: `${count(lossy, 'file is', 'files are')} not valid UTF-8 and ${lossy.length === 1 ? 'was' : 'were'} searched with replacement characters, so a miss there is not proof of absence: ${names(lossy)}.`});
  if (capped.length) notes.push({kind: 'file-limit', text: `${count(capped, 'file', 'files')} stopped at ${limits.fileMatches} matches; refine the query to see the rest: ${names(capped)}.`});
  if (total.length || unsearched.length) notes.push({kind: 'match-limit', text: `Results stopped at ${limits.totalMatches.toLocaleString('en-US')} matches${unsearched.length ? `; ${count(unsearched, 'file was', 'files were')} not searched` : ''}. Refine the query.`});
  if (budget.length) notes.push({kind: 'byte-limit', text: `${count(budget, 'file was', 'files were')} not searched: this search reached its ${mib(limits.totalBytes)} read budget: ${names(budget)}.`});
  return notes;
}

function sourceSearchStatus(model) {
  const files = value => `${value} ${value === 1 ? 'file' : 'files'}`;
  const matches = value => `${value.toLocaleString('en-US')} ${value === 1 ? 'match' : 'matches'}`;
  if (model.status === 'idle') return 'Literal text in every retained text file. Nothing is read until you search.';
  if (model.status === 'error') return model.error;
  if (!model.total) return 'No retained files to search.';
  const searched = model.files.filter(file => file.state === 'searched').length;
  const holding = model.files.filter(file => file.matches.length).length;
  if (model.status === 'running') return `Searching… ${model.completed} of ${files(model.total)} · ${matches(model.matches)}`;
  return `Searched ${searched} of ${files(model.total)} · ${matches(model.matches)}${holding ? ` in ${files(holding)}` : ''}${model.matchCase ? ' · case-sensitive' : ''}`;
}

// The Sources panel: query field, Match case, status, partial-result notes and
// results grouped by file. Captured text is inserted as text nodes.
function createSourceSearchPanel({input, matchCase, status, notes, results, list, read, open, limits = SOURCE_SEARCH_LIMITS, delay = 250}) {
  let timer = null, renderedFiles = 0;
  const element = (tag, className, text) => {
    const node = document.createElement(tag); if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const buttons = () => [...results.querySelectorAll('.source-search-all-match')];
  function fileGroup(file) {
    const group = element('section', 'source-search-all-file');
    const heading = element('div', 'source-search-all-heading');
    heading.id = `source-search-all-file-${renderedFiles}`;
    group.setAttribute('aria-labelledby', heading.id);
    heading.append(element('span', 'source-file-icon', file.icon ?? ''), element('span', 'source-search-all-name', file.name),
      element('span', 'source-search-all-count', `${file.matches.length}${file.matchLimit ? '+' : ''}`));
    const url = element('div', 'source-search-all-url', file.url || '(anonymous)'); url.title = file.url || '';
    group.append(heading, url);
    for (const match of file.matches) {
      const button = element('button', 'source-search-all-match'); button.type = 'button'; button.tabIndex = -1;
      button.dataset.sourceMatch = `${file.artifactId}:${match.line}:${match.column}`;
      const snippet = element('span', 'source-search-all-snippet');
      snippet.append(document.createTextNode(`${match.snippet.clippedStart ? '…' : ''}${match.snippet.before}`),
        element('mark', '', match.snippet.match), document.createTextNode(`${match.snippet.after}${match.snippet.clippedEnd ? '…' : ''}`));
      button.append(element('span', 'source-search-all-location', `${match.line + 1}:${match.column + 1}`), snippet);
      button.addEventListener('click', () => open(file, match));
      group.append(button);
    }
    renderedFiles += 1;
    return group;
  }
  function render(model, file) {
    status.textContent = sourceSearchStatus(model);
    if (!file && model.completed === 0) {results.replaceChildren(); renderedFiles = 0;}
    if (file?.matches.length) {
      results.append(fileGroup(file));
      const all = buttons();
      if (!all.some(button => button.tabIndex === 0)) all[0].tabIndex = 0;
    }
    const lines = sourceSearchNotes(model, limits);
    notes.hidden = !lines.length;
    notes.replaceChildren(...lines.map(note => { const line = element('li', 'source-search-all-note', note.text); line.dataset.note = note.kind; return line; }));
    if (model.status === 'done' && !model.matches && model.total) {
      results.replaceChildren(element('p', 'source-search-all-empty', `No match for “${model.query}” in the searched files.`));
    }
  }
  const search = createSourceSearch({list, read, limits, onChange: render});
  const run = () => { clearTimeout(timer); timer = null; return search.run(input.value, matchCase.checked); };
  input.addEventListener('input', () => {
    clearTimeout(timer);
    // A changed query retires the running search at once, even before the
    // delayed run starts, so stale results never keep arriving.
    search.cancel();
    timer = setTimeout(run, delay);
  });
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter') {event.preventDefault(); run();}
    else if (event.key === 'ArrowDown') { const first = buttons()[0]; if (first) {event.preventDefault(); first.focus();} }
  });
  matchCase.addEventListener('change', () => { if (input.value) run(); });
  results.addEventListener('keydown', event => {
    const all = buttons(), index = all.indexOf(event.target);
    if (index < 0 || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'ArrowUp' && index === 0) {input.focus(); return;}
    const next = all[event.key === 'Home' ? 0 : event.key === 'End' ? all.length - 1 : Math.min(all.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1))];
    for (const button of all) button.tabIndex = button === next ? 0 : -1;
    next.focus();
    next.scrollIntoView?.({block: 'nearest'});
  });
  return {
    model: search.model,
    cancel: () => { clearTimeout(timer); timer = null; search.cancel(); },
    search(query, {focus = true} = {}) {
      input.value = String(query ?? '').slice(0, 512);
      if (focus) input.focus();
      return run();
    }
  };
}
