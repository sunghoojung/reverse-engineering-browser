/* Search inside every retained text file through the backend's artifact search
 * (search_artifact_text, reb-artifact-search-v2). The backend reads each file
 * whole, whatever its size, verifies it against its manifest digest and counts
 * every match; results arrive a page at a time. Text is literal unless Regex
 * is on, and a regular expression runs on the backend's linear-time engine, so
 * captured text cannot make a search backtrack. A result's line and column are
 * the ones Sources displays (UTF-16 units). Every file that was not searched,
 * and why, is named. */
const SOURCE_SEARCH_PAGE = 200;
// Characters of context shown before a match, so a narrow navigator never
// pushes the match itself out of view.
const SOURCE_SEARCH_BEFORE = 12;

// Matches are per line, as Find in the editor finds them.
function sourceSearchQueryError(query) {
  return /[\r\n\u2028\u2029]/u.test(query) ? 'Search uses text on one line; line separators are not supported.' : '';
}

// One backend match as a result: the editor's 0-based line and UTF-16 column,
// and same-line context split so the caller can mark the match.
function sourceSearchRow(match) {
  const characters = Array.from(match.before);
  const kept = characters.slice(-SOURCE_SEARCH_BEFORE).join('');
  return {line: match.line - 1, column: match.utf16_column - 1, length: match.utf16_length, byteOffset: match.byte_offset,
    snippet: {before: kept.replace(/^\s+/, ''), match: match.match, after: match.match_complete ? match.after : '',
      clippedStart: match.clipped_before || characters.length > SOURCE_SEARCH_BEFORE, clippedEnd: match.clipped_after || !match.match_complete}};
}

function sourceSearchDocument(body) {
  return body?.format === 'reb-artifact-search-v2' && Number.isSafeInteger(body.total_matches) && Array.isArray(body.matches) &&
    Array.isArray(body.files) && body.coverage && typeof body.coverage === 'object';
}

async function sourceSearchRequest(url, signal) {
  const response = await fetch(url, {cache: 'no-store', signal});
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.error ?? `Search returned HTTP ${response.status}`);
  return body;
}

// One search at a time. A new run, or cancel(), retires the previous run's
// generation and aborts its request, which stops the backend's work; late
// pages are dropped. `kinds` names the artifact kinds Sources shows as text,
// `binary` counts the files it shows as hex, and `describe` names a file.
function createSourceSearch({request = sourceSearchRequest, kinds, binary = () => 0, describe, onChange, now = () => Date.now()}) {
  const model = {generation: 0, query: '', matchCase: false, regex: false, status: 'idle', error: '', started: 0,
    total: 0, filesWithMatches: 0, files: [], loaded: 0, nextOffset: null, coverage: null, binary: 0, loadingMore: false, moreError: ''};
  let controller = null;
  // `pending` says a new query waits for typing to pause; otherwise a
  // running search becomes `cancelled`.
  function cancel(next = 'cancelled') {
    model.generation += 1;
    controller?.abort(); controller = null;
    if (model.status === 'running' || next === 'pending') model.status = next;
    model.loadingMore = false;
  }
  function url(offset) {
    const params = new URLSearchParams({q: model.query, offset: String(offset), limit: String(SOURCE_SEARCH_PAGE)});
    if (model.regex) params.set('regex', 'true');
    if (model.matchCase) params.set('match_case', 'true');
    params.set('kind', model.kinds.join(','));
    return `/api/artifacts/search?${params}`;
  }
  // Appends one page: a file continues the group the previous page ended with.
  function apply(body) {
    const groups = new Map(model.files.map(file => [file.artifactId, file]));
    const added = [];
    for (const entry of body.files) {
      if (groups.has(entry.artifact_id)) continue;
      const named = describe(entry.artifact_id) ?? {identity: null, name: `artifact ${entry.artifact_id}`, url: '', icon: '?'};
      const file = {artifactId: entry.artifact_id, count: entry.matches, validUtf8: entry.valid_utf8, matches: [], ...named};
      groups.set(file.artifactId, file); model.files.push(file); added.push(file);
    }
    for (const match of body.matches) groups.get(match.artifact_id)?.matches.push(sourceSearchRow(match));
    Object.assign(model, {total: body.total_matches, filesWithMatches: body.files_with_matches, coverage: body.coverage,
      loaded: model.loaded + body.matches.length, nextOffset: body.next_offset});
    return added;
  }
  async function run(query, {matchCase = false, regex = false} = {}) {
    cancel();
    const token = model.generation, own = controller = new AbortController();
    Object.assign(model, {query, matchCase: Boolean(matchCase), regex: Boolean(regex), status: 'running', error: '', started: now(),
      total: 0, filesWithMatches: 0, files: [], loaded: 0, nextOffset: null, coverage: null, binary: binary(), kinds: kinds(), moreError: ''});
    if (!query) {model.status = 'idle'; onChange(model, 'reset'); return model;}
    const refused = sourceSearchQueryError(query);
    if (refused) {model.status = 'error'; model.error = refused; onChange(model, 'reset'); return model;}
    if (!model.kinds.length) {model.status = 'done'; onChange(model, 'reset'); return model;}
    onChange(model, 'reset');
    try {
      const body = await request(url(0), own.signal);
      if (token !== model.generation) return model;
      if (!sourceSearchDocument(body)) throw new Error('Search returned a document this page does not read.');
      apply(body);
      model.status = 'done';
    } catch (error) {
      if (token !== model.generation) return model;
      model.status = 'error';
      model.error = `Search failed: ${String(error?.message ?? error).replace(/\.$/, '')}. Search again to retry.`;
    }
    if (controller === own) controller = null;
    onChange(model, 'page');
    return model;
  }
  // The next page of the same search. The backend kept the count, so it
  // reads only the files this page lists.
  async function more() {
    if (model.status !== 'done' || model.nextOffset === null || model.loadingMore) return model;
    const token = model.generation, own = controller = new AbortController();
    model.loadingMore = true; model.moreError = '';
    onChange(model, 'more');
    let added = [];
    try {
      const body = await request(url(model.nextOffset), own.signal);
      if (token !== model.generation) return model;
      if (!sourceSearchDocument(body)) throw new Error('Search returned a document this page does not read.');
      added = apply(body);
    } catch (error) {
      if (token !== model.generation) return model;
      model.moreError = `The next matches did not load: ${String(error?.message ?? error).replace(/\.$/, '')}.`;
    }
    model.loadingMore = false;
    if (controller === own) controller = null;
    onChange(model, 'page', added);
    return model;
  }
  return {model, run, more, cancel};
}

// Every file a finished search did not search, or did not search as valid
// text, by reason. Nothing is dropped silently: the panel shows each line that
// applies.
function sourceSearchNotes(model, describe = id => ({name: `artifact ${id}`})) {
  const notes = [];
  if (model.status !== 'done') return notes;
  const named = (ids, count) => `${ids.slice(0, 3).map(id => describe(id)?.name ?? `artifact ${id}`).join(', ')}${count > 3 ? ` and ${count - 3} more` : ''}`;
  const files = (count, one, many) => `${count.toLocaleString('en-US')} ${count === 1 ? one : many}`;
  if (model.binary) notes.push({kind: 'binary', text: `${files(model.binary, 'binary file is', 'binary files are')} not searched as text; Find in their Hex or Inspect view searches every byte or row.`});
  const coverage = model.coverage;
  if (coverage?.not_searched_count) {
    notes.push({kind: 'failed', text: `${files(coverage.not_searched_count, 'file', 'files')} could not be read or verified against ${coverage.not_searched_count === 1 ? 'its' : 'their'} SHA-256 and ${coverage.not_searched_count === 1 ? 'was' : 'were'} not searched: ${named(coverage.not_searched.map(entry => entry.artifact_id), coverage.not_searched_count)}. Search again to retry.`});
  }
  if (coverage?.not_valid_utf8_count) {
    notes.push({kind: 'lossy', text: `${files(coverage.not_valid_utf8_count, 'file is', 'files are')} not valid UTF-8; text there is searched as decoded with replacement characters, so a miss is not proof of absence: ${named(coverage.not_valid_utf8, coverage.not_valid_utf8_count)}.`});
  }
  return notes;
}

function sourceSearchStatus(model, now = Date.now()) {
  const count = (value, one, many) => `${value.toLocaleString('en-US')} ${value === 1 ? one : many}`;
  const mode = `${model.regex ? ' · regular expression' : ''}${model.matchCase ? ' · case-sensitive' : ''}`;
  if (model.status === 'idle') return 'Text, or a regular expression with Regex, in every retained text file. Nothing is read until you search.';
  if (model.status === 'error') return model.error;
  if (model.status === 'cancelled') return 'Search cancelled. Press Enter to search again.';
  if (model.status === 'pending') return 'Searching when typing pauses…';
  if (model.status === 'running') return `Searching every retained text file, each read whole… ${Math.max(0, Math.floor((now - model.started) / 1000))} s`;
  if (!model.coverage) return 'No retained text files to search.';
  const searched = `searched ${model.coverage.artifacts_searched.toLocaleString('en-US')} of ${count(model.coverage.artifacts_selected, 'file', 'files')}`;
  if (!model.total) return `No match · ${searched}${mode}`;
  return `${count(model.total, 'match', 'matches')} in ${count(model.filesWithMatches, 'file', 'files')} · ${searched}${mode}`;
}

// The Sources panel: query field, Match case, Regex, status with Cancel,
// coverage notes, and results grouped by file with the next page on request.
// Captured text is inserted as text nodes.
function createSourceSearchPanel({input, matchCase, regex, status, cancel, notes, results, kinds, binary, describe, open, request,
  delay = 250, every = (callback, ms) => setInterval(callback, ms), stop = timer => clearInterval(timer)}) {
  let timer = null, ticker = null, renderedFiles = 0, moreButton = null;
  const groups = new Map();
  const element = (tag, className, text) => {
    const node = document.createElement(tag); if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const buttons = () => [...results.querySelectorAll('.source-search-all-match')];
  function matchButton(file, match) {
    const button = element('button', 'source-search-all-match'); button.type = 'button'; button.tabIndex = -1;
    button.dataset.sourceMatch = `${file.artifactId}:${match.line}:${match.column}`;
    const snippet = element('span', 'source-search-all-snippet');
    snippet.append(document.createTextNode(`${match.snippet.clippedStart ? '…' : ''}${match.snippet.before}`),
      element('mark', '', match.snippet.match), document.createTextNode(`${match.snippet.after}${match.snippet.clippedEnd ? '…' : ''}`));
    button.append(element('span', 'source-search-all-location', `${match.line + 1}:${match.column + 1}`), snippet);
    button.addEventListener('click', () => open(file, match));
    return button;
  }
  function fileGroup(file) {
    const group = element('section', 'source-search-all-file');
    const heading = element('div', 'source-search-all-heading');
    heading.id = `source-search-all-file-${renderedFiles}`;
    group.setAttribute('aria-labelledby', heading.id);
    heading.append(element('span', 'source-file-icon', file.icon ?? ''), element('span', 'source-search-all-name', file.name),
      element('span', 'source-search-all-count', file.count.toLocaleString('en-US')));
    heading.title = `${file.count.toLocaleString('en-US')} ${file.count === 1 ? 'match' : 'matches'} in this file`;
    const url = element('div', 'source-search-all-url', file.url || '(anonymous)'); url.title = file.url || '';
    group.append(heading, url);
    renderedFiles += 1;
    return {group, shown: 0};
  }
  // Mounts the matches a page added: new groups, and the continuation of the
  // group the previous page ended with.
  function mountMatches(model) {
    let first = null;
    for (const file of model.files) {
      let entry = groups.get(file.artifactId);
      if (!entry) {entry = fileGroup(file); groups.set(file.artifactId, entry); results.insertBefore(entry.group, moreButton);}
      for (const match of file.matches.slice(entry.shown)) {
        const button = matchButton(file, match);
        first ??= button;
        entry.group.append(button);
      }
      entry.shown = file.matches.length;
    }
    return first;
  }
  function renderMore(model) {
    const remaining = model.total - model.loaded;
    if (model.nextOffset === null || model.status !== 'done') {moreButton?.remove(); moreButton = null; return;}
    if (!moreButton) {
      moreButton = element('button', 'secondary-button source-search-all-more'); moreButton.type = 'button';
      moreButton.addEventListener('click', () => search.more());
      results.append(moreButton);
    }
    moreButton.disabled = model.loadingMore;
    moreButton.textContent = model.loadingMore ? 'Loading matches…'
      : `Show the next ${Math.min(SOURCE_SEARCH_PAGE, remaining).toLocaleString('en-US')} of ${remaining.toLocaleString('en-US')} remaining matches`;
    if (model.moreError) moreButton.title = model.moreError; else moreButton.removeAttribute('title');
  }
  function renderStatus(model) {
    status.textContent = model.moreError ? `${sourceSearchStatus(model)} · ${model.moreError}` : sourceSearchStatus(model);
    cancel.hidden = model.status !== 'running';
    if (model.status === 'running' && ticker === null) ticker = every(() => renderStatus(model), 1000);
    if (model.status !== 'running' && ticker !== null) {stop(ticker); ticker = null;}
  }
  function render(model, change) {
    if (change === 'reset') {results.replaceChildren(); groups.clear(); renderedFiles = 0; moreButton = null;}
    renderStatus(model);
    const lines = sourceSearchNotes(model, describe);
    notes.hidden = !lines.length;
    notes.replaceChildren(...lines.map(note => { const line = element('li', 'source-search-all-note', note.text); line.dataset.note = note.kind; return line; }));
    if (change === 'more') {renderMore(model); return;}
    if (change !== 'page') return;
    const focusMore = document.activeElement === moreButton && moreButton !== null;
    const first = mountMatches(model);
    renderMore(model);
    const all = buttons();
    if (all.length && !all.some(button => button.tabIndex === 0)) all[0].tabIndex = 0;
    // The next page continues where keyboard focus was: on its first match.
    if (focusMore && first) {
      for (const button of all) button.tabIndex = button === first ? 0 : -1;
      first.focus();
    }
    if (model.status === 'done' && !model.total && model.coverage) {
      results.replaceChildren(element('p', 'source-search-all-empty', `No match for “${model.query}” in the searched files.`));
    }
  }
  const search = createSourceSearch({request, kinds, binary, describe, onChange: render});
  const run = () => { clearTimeout(timer); timer = null; return search.run(input.value, {matchCase: matchCase.checked, regex: regex.checked}); };
  input.addEventListener('input', () => {
    clearTimeout(timer);
    // A changed query retires the running search at once, even before the
    // delayed run starts, so stale results never keep arriving.
    search.cancel('pending');
    renderStatus(search.model);
    timer = setTimeout(run, delay);
  });
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter') {event.preventDefault(); run();}
    else if (event.key === 'Escape' && search.model.status === 'running') {event.preventDefault(); search.cancel(); renderStatus(search.model);}
    else if (event.key === 'ArrowDown') { const first = buttons()[0]; if (first) {event.preventDefault(); first.focus();} }
  });
  for (const option of [matchCase, regex]) option.addEventListener('change', () => { if (input.value) run(); });
  cancel.addEventListener('click', () => { clearTimeout(timer); timer = null; search.cancel(); renderStatus(search.model); input.focus(); });
  results.addEventListener('keydown', event => {
    const all = buttons(), index = all.indexOf(event.target);
    if (index < 0 || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'ArrowUp' && index === 0) {input.focus(); return;}
    if (event.key === 'ArrowDown' && index === all.length - 1 && moreButton) {moreButton.focus(); return;}
    const next = all[event.key === 'Home' ? 0 : event.key === 'End' ? all.length - 1 : Math.min(all.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1))];
    for (const button of all) button.tabIndex = button === next ? 0 : -1;
    next.focus();
    next.scrollIntoView?.({block: 'nearest'});
  });
  return {
    model: search.model,
    more: search.more,
    cancel: () => { clearTimeout(timer); timer = null; search.cancel(); renderStatus(search.model); },
    search(query, {focus = true} = {}) {
      input.value = String(query ?? '');
      if (focus) input.focus();
      return run();
    }
  };
}
