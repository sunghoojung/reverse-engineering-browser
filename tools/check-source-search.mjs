// Search all files checks. The search controller, result rows and panel run
// from source_search.js; the catalog wiring, open path and palette entry run
// from app.js. Only DOM leaves, fetch and owner functions are faked, and the
// fake search route answers as reb-artifact-search-v2 documents do. With
// --backend <origin-trace-backend>, the same controller searches a real store
// through the Rust route, including a file larger than the old 16 MiB skip.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp, mkdir, readFile, rm, writeFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
// The offline DOM model writes its inert timers through to the process
// globals, so keep real ones for this module and restore them afterwards.
import {setTimeout, clearTimeout} from 'node:timers';
import {runInContext, runInNewContext} from 'node:vm';
import {fakeDocument} from './check-command-palette.mjs';

const plain = value => JSON.parse(JSON.stringify(value));
const settle = () => new Promise(resolve => setTimeout(resolve, 0));
const until = async (predicate, message) => { for (let turn = 0; turn < 500 && !predicate(); turn++) await settle(); assert(predicate(), message); };
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return {promise, resolve, reject}; };

async function searchModel(root, context = {}) {
  const search = await readFile(join(root, 'apps/research-ui/source_search.js'), 'utf8');
  return runInNewContext(`${search}\n;({SOURCE_SEARCH_PAGE, sourceSearchQueryError, sourceSearchRow, createSourceSearch, sourceSearchNotes, sourceSearchStatus, createSourceSearchPanel})`,
    {URL, URLSearchParams, setTimeout, clearTimeout, AbortController, ...context});
}

// The search route over in-memory texts, answering as reb-artifact-search-v2
// does: every match counted, a page from offset, same-line context, UTF-16
// columns. It reads `kind`, `regex`, `match_case`, `offset` and `limit`.
function fakeSearchRoute(files, {invalid = [], unreadable = []} = {}) {
  const requests = [];
  async function request(url, signal) {
    requests.push({url, signal});
    assert(signal && !signal.aborted, 'Every request can be aborted');
    const params = new URL(url, 'http://fixture.invalid').searchParams;
    assert.equal(new URL(url, 'http://fixture.invalid').pathname, '/api/artifacts/search');
    const q = params.get('q'), regex = params.get('regex') === 'true', matchCase = params.get('match_case') === 'true';
    const offset = Number(params.get('offset')), limit = Number(params.get('limit')), kinds = params.get('kind').split(',');
    const pattern = new RegExp(regex ? q : q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), matchCase ? 'gmu' : 'gimu');
    const selected = files.filter(file => kinds.includes(file.kind));
    const all = [], counts = new Map();
    for (const file of selected.filter(file => !unreadable.includes(file.id))) {
      for (const found of file.text.matchAll(pattern)) {
        if (!found[0]) continue;
        const lineStart = file.text.lastIndexOf('\n', found.index - 1) + 1, lineEnd = file.text.indexOf('\n', found.index);
        const end = found.index + found[0].length, stop = lineEnd < 0 ? file.text.length : lineEnd;
        all.push({artifact_id: file.id, session_id: '1', kind: file.kind, byte_offset: found.index, byte_length: found[0].length,
          line: file.text.slice(0, found.index).split('\n').length, column: found.index - lineStart + 1, utf16_column: found.index - lineStart + 1,
          utf16_length: found[0].length, before: file.text.slice(Math.max(lineStart, found.index - 48), found.index), match: found[0], match_complete: true,
          after: file.text.slice(end, Math.min(stop, end + 48)), clipped_before: found.index - 48 > lineStart, clipped_after: end + 48 < stop});
        counts.set(file.id, (counts.get(file.id) ?? 0) + 1);
      }
    }
    const page = all.slice(offset, offset + limit), firsts = new Map();
    all.forEach((match, rank) => { if (!firsts.has(match.artifact_id)) firsts.set(match.artifact_id, rank); });
    const ids = [...new Set(page.map(match => match.artifact_id))];
    return {format: 'reb-artifact-search-v2', query: {q_bytes: q.length, regex, match_case: matchCase, filters: {kind: kinds}, offset, limit},
      total_matches: all.length, files_with_matches: counts.size, matches: page,
      files: ids.map(id => ({artifact_id: id, matches: counts.get(id), first_match: firsts.get(id), valid_utf8: !invalid.includes(id)})),
      next_offset: offset + page.length < all.length ? offset + page.length : null,
      coverage: {artifacts_selected: selected.length, artifacts_searched: selected.length - unreadable.length, bytes_searched: 1,
        not_searched: unreadable.map(id => ({artifact_id: id, reason: 'unreadable_or_integrity'})), not_searched_count: unreadable.length,
        not_valid_utf8: invalid, not_valid_utf8_count: invalid.length, complete: !unreadable.length}};
  }
  return {request, requests};
}

const describer = names => id => names[id] ? {identity: `identity-${id}`, name: names[id], url: `https://fixture.invalid/${names[id]}`, icon: 'JS'} : null;

async function checkRows(root) {
  const model = await searchModel(root);
  assert.equal(model.sourceSearchQueryError('fetch('), '');
  for (const query of ['a\nb', 'a\rb', 'a\u2028b']) assert.match(model.sourceSearchQueryError(query), /one line/);
  const row = model.sourceSearchRow({line: 3, utf16_column: 5, utf16_length: 6, byte_offset: 90, before: `   ${'x'.repeat(20)}😀`, match: 'fetch(',
    match_complete: true, after: 'a); ', clipped_before: false, clipped_after: false});
  assert.deepEqual(plain(row), {line: 2, column: 4, length: 6, byteOffset: 90,
    snippet: {before: `${'x'.repeat(11)}😀`, match: 'fetch(', after: 'a); ', clippedStart: true, clippedEnd: false}},
    'The editor’s 0-based line and UTF-16 column; twelve characters before the match, never half a surrogate pair');
  assert.equal(model.sourceSearchRow({line: 1, utf16_column: 1, utf16_length: 400, byte_offset: 0, before: '  ', match: 'x'.repeat(256),
    match_complete: false, after: 'tail', clipped_before: false, clipped_after: false}).snippet.after, '', 'A long match shows its start, then an ellipsis');
  console.log('PASS source search rows: one-line queries, editor line and UTF-16 column, twelve characters of context, the start of a long match (production module, not rendered QA)');
}

async function checkController(root) {
  const model = await searchModel(root);
  const files = [{id: '1', kind: 'javascript', text: 'fetch(a)\nfetch(b)'}, {id: '2', kind: 'javascript', text: 'fetch '.repeat(250)},
    {id: '3', kind: 'javascript', text: 'no match here'}, {id: '4', kind: 'wasm', text: 'fetch'}];
  const route = fakeSearchRoute(files, {invalid: ['2']});
  const changes = [];
  const describe = describer({1: 'cart.js', 2: 'noisy.js', 3: 'quiet.js'});
  const search = model.createSourceSearch({request: route.request, kinds: () => ['javascript'], binary: () => 1, describe,
    onChange: (value, change) => changes.push([change, value.status]), now: () => 1000});
  let result = await search.run('fetch');
  assert.equal(result.status, 'done');
  const first = new URL(route.requests[0].url, 'http://fixture.invalid').searchParams;
  assert.deepEqual(Object.fromEntries(first), {q: 'fetch', offset: '0', limit: '200', kind: 'javascript'}, 'Literal and case-folded unless asked; hex kinds never requested');
  assert.deepEqual([result.total, result.filesWithMatches, result.loaded, result.nextOffset], [252, 2, 200, 200], 'Every match counted; the first page loaded');
  assert.deepEqual(plain(result.files.map(file => [file.name, file.count, file.matches.length, file.validUtf8])), [['cart.js', 2, 2, true], ['noisy.js', 250, 198, false]]);
  assert.deepEqual(plain(result.files[0].matches[1]), {line: 1, column: 0, length: 5, byteOffset: 9, snippet: {before: '', match: 'fetch', after: '(b)', clippedStart: false, clippedEnd: false}});
  assert.deepEqual(changes, [['reset', 'running'], ['page', 'done']]);
  assert.equal(model.sourceSearchStatus(result), '252 matches in 2 files · searched 3 of 3 files');
  assert.deepEqual(plain(model.sourceSearchNotes(result, describe).map(note => note.kind)), ['binary', 'lossy']);
  assert.match(model.sourceSearchNotes(result, describe)[1].text, /1 file is not valid UTF-8.*not proof of absence: noisy\.js\./);

  // The next page continues the last file's group and reads from next_offset.
  result = await search.more();
  assert.equal(new URL(route.requests[1].url, 'http://fixture.invalid').searchParams.get('offset'), '200');
  assert.deepEqual([result.loaded, result.nextOffset, result.files.length, result.files[1].matches.length], [252, null, 2, 250]);
  assert.equal((await search.more()).loaded, 252, 'Nothing more after the last page');
  assert.equal(route.requests.length, 2);

  // Regex and Match case reach the route; the status names them.
  result = await search.run('FETCH\\((a|b)\\)', {regex: true, matchCase: false});
  assert.equal(new URL(route.requests.at(-1).url, 'http://fixture.invalid').searchParams.get('regex'), 'true');
  assert.equal(result.total, 2); assert.equal(model.sourceSearchStatus(result), '2 matches in 1 file · searched 3 of 3 files · regular expression');
  result = await search.run('FETCH', {matchCase: true});
  assert.equal(new URL(route.requests.at(-1).url, 'http://fixture.invalid').searchParams.get('match_case'), 'true');
  assert.equal(model.sourceSearchStatus(result), 'No match · searched 3 of 3 files · case-sensitive');

  // A new query retires the running one: its request is aborted and its late
  // page never appears.
  const held = deferred(), slowRequests = [];
  const slow = model.createSourceSearch({kinds: () => ['javascript'], describe, onChange() {}, request: (url, signal) => {
    slowRequests.push(signal);
    return slowRequests.length === 1 ? held.promise : route.request(url, signal);
  }});
  const pending = slow.run('fetch');
  await settle();
  assert.equal(model.sourceSearchStatus({...slow.model, started: 1000}, 4600), 'Searching every retained text file, each read whole… 3 s');
  const second = await slow.run('match');
  assert.equal(slowRequests[0].aborted, true, 'The previous request is aborted, which stops the backend search');
  held.resolve(await route.request('/api/artifacts/search?q=fetch&offset=0&limit=200&kind=javascript', new AbortController().signal));
  await pending;
  assert.equal(second.query, 'match'); assert.equal(second.total, 1, 'Late results from the retired query never appear');
  const third = slow.run('again'); slow.cancel(); await third;
  assert.equal(slow.model.status, 'cancelled'); assert.equal(model.sourceSearchStatus(slow.model), 'Search cancelled. Press Enter to search again.');
  slow.cancel('pending'); assert.equal(model.sourceSearchStatus(slow.model), 'Searching when typing pauses…');

  // Failures say so and keep nothing stale; refused queries and an empty
  // catalog send nothing.
  const failing = model.createSourceSearch({kinds: () => ['javascript'], describe, onChange() {}, request: async () => { throw new Error('artifact store returned 500.'); }});
  result = await failing.run('fetch');
  assert.equal(result.status, 'error'); assert.equal(model.sourceSearchStatus(result), 'Search failed: artifact store returned 500. Search again to retry.');
  result = await model.createSourceSearch({kinds: () => ['javascript'], describe, onChange() {}, request: async () => ({format: 'reb-artifact-search-v1'})}).run('fetch');
  assert.match(result.error, /does not read/);
  const silent = model.createSourceSearch({kinds: () => { throw new Error('a refused query reads nothing'); }, describe, onChange() {},
    request: async () => { throw new Error('must not be requested'); }});
  result = await silent.run('a\nb').catch(error => error);
  assert(result instanceof Error, 'kinds are read only for a query that is sent');
  const empty = model.createSourceSearch({kinds: () => [], describe, onChange() {}, request: async () => { throw new Error('must not be requested'); }});
  result = await empty.run('fetch');
  assert.equal(model.sourceSearchStatus(result), 'No retained text files to search.');
  assert.equal(model.sourceSearchStatus({...result, status: 'idle'}), 'Text, or a regular expression with Regex, in every retained text file. Nothing is read until you search.');

  // Unreadable files are named, with an exact count beyond the listed ones.
  const broken = fakeSearchRoute(files, {unreadable: ['3']});
  result = await model.createSourceSearch({request: broken.request, kinds: () => ['javascript'], describe, onChange() {}}).run('fetch');
  assert.match(model.sourceSearchNotes(result, describe)[0].text, /1 file could not be read or verified against its SHA-256 and was not searched: quiet\.js\. Search again/);
  const many = model.sourceSearchNotes({status: 'done', binary: 0, coverage: {not_searched_count: 40, not_searched: Array.from({length: 32}, (_, index) => ({artifact_id: String(index + 10)})),
    not_valid_utf8_count: 0, not_valid_utf8: []}});
  assert.match(many[0].text, /^40 files could not be read .*: artifact 10, artifact 11, artifact 12 and 37 more\./);
  console.log('PASS source search controller: one backend search per query with exact totals, pages that continue a file, Regex and Match case, cancellation drops late pages, failures, refusals and coverage notes (production module, not rendered QA)');
}

async function checkPanel(root) {
  const {document, create, fire} = fakeDocument();
  const model = await searchModel(root, {document});
  const input = create('input', 'input'), matchCase = create('input', 'case'), regex = create('input', 'regex'), status = create('p', 'status');
  const cancel = create('button', 'cancel'), notes = create('ul', 'notes'), results = create('div', 'results');
  const markup = '<img src=x onerror="globalThis.__rebInjected=1">';
  const files = [{id: '1', kind: 'javascript', text: 'const a = fetch(x);\nreturn fetch(y);'}, {id: '8', kind: 'javascript', text: `${markup} fetch`},
    {id: '9', kind: 'javascript', text: 'fetch '.repeat(240)}];
  const route = fakeSearchRoute(files);
  let hold = null;
  const request = (url, signal) => hold ? hold.promise.then(() => route.request(url, signal)) : route.request(url, signal);
  const opened = [], tickers = [];
  const panel = model.createSourceSearchPanel({input, matchCase, regex, status, cancel, notes, results, delay: 5, request,
    kinds: () => ['javascript'], binary: () => 1, describe: describer({1: 'cart.js', 8: 'markup.js', 9: 'noisy.js'}),
    every: callback => { tickers.push({callback, stopped: false}); return tickers.length - 1; }, stop: index => { tickers[index].stopped = true; },
    open: (file, match) => opened.push([file.artifactId, match.line, match.column, match.length])});
  await panel.search('fetch');
  assert.equal(document.activeElement, input);
  assert.equal(status.textContent, '243 matches in 3 files · searched 3 of 3 files');
  assert.equal(cancel.hidden, true);
  assert.deepEqual(notes.children.map(node => node.dataset.note), ['binary']);
  let buttons = results.all.filter(node => node.className === 'source-search-all-match');
  assert.equal(buttons.length, 200);
  assert.deepEqual(buttons.slice(0, 3).map(button => button.dataset.sourceMatch), ['1:0:10', '1:1:7', `8:0:${markup.length + 1}`]);
  assert.deepEqual(buttons.slice(0, 3).map(button => button.tabIndex), [0, -1, -1], 'One tab stop for the results');
  const groups = results.all.filter(node => node.className === 'source-search-all-file');
  assert.deepEqual(groups.map(group => group.children[0].textContent), ['JScart.js2', 'JSmarkup.js1', 'JSnoisy.js240'], 'Each file shows its exact count');
  assert.equal(groups[0].children[1].textContent, 'https://fixture.invalid/cart.js');
  assert.equal(buttons[0].textContent, '1:11const a = fetch(x);');
  assert.equal(buttons[2].all.find(node => node.tagName === 'MARK').textContent, 'fetch');
  assert.equal(buttons[2].all.filter(node => node.tagName === 'IMG').length, 0, 'Captured markup stays text');
  assert(buttons[2].all.some(node => node.nodeType === 3 && node.textContent === '…njected=1"> '), 'Context is a text node, clipped to 12 characters before the match');
  const more = results.all.find(node => node.className === 'secondary-button source-search-all-more');
  assert.equal(more.textContent, 'Show the next 43 of 43 remaining matches');
  assert.equal(results.children.at(-1), more, 'The next page control ends the results');

  // Keyboard: Down from the field, through the results, onto the next page
  // control; the next page continues on its first match.
  fire(input, 'keydown', {key: 'ArrowDown'}); assert.equal(document.activeElement, buttons[0]);
  fire(buttons[0], 'keydown', {key: 'ArrowDown'}); assert.equal(document.activeElement, buttons[1]);
  fire(buttons[1], 'keydown', {key: 'End'}); assert.equal(document.activeElement, buttons[199]);
  fire(buttons[199], 'keydown', {key: 'ArrowDown'}); assert.equal(document.activeElement, more);
  fire(more, 'click');
  assert.equal(more.disabled, true); assert.equal(more.textContent, 'Loading matches…');
  await until(() => panel.model.loaded === 243, 'The next page loads');
  buttons = results.all.filter(node => node.className === 'source-search-all-match');
  assert.equal(buttons.length, 243); assert.equal(document.activeElement, buttons[200], 'Focus moves to the first match of the new page');
  assert.equal(groups[2].children.filter(node => node.className === 'source-search-all-match').length, 240, 'The page continued the same file group');
  assert.equal(results.all.some(node => node.className === 'secondary-button source-search-all-more'), false);
  fire(buttons[200], 'keydown', {key: 'Home'}); assert.equal(document.activeElement, buttons[0]);
  fire(buttons[0], 'keydown', {key: 'ArrowUp'}); assert.equal(document.activeElement, input);
  fire(buttons[1], 'click');
  assert.deepEqual(opened, [['1', 1, 7, 5]], 'A result opens its file at the match');

  // A running search shows elapsed seconds and Cancel; Cancel and Escape stop it.
  hold = deferred();
  const running = panel.search('return');
  assert.equal(cancel.hidden, false); assert.match(status.textContent, /^Searching every retained text file, each read whole… 0 s$/);
  assert.equal(tickers.at(-1).stopped, false, 'Elapsed time ticks while it runs');
  fire(cancel, 'click');
  assert.equal(status.textContent, 'Search cancelled. Press Enter to search again.'); assert.equal(cancel.hidden, true);
  assert.equal(tickers.at(-1).stopped, true); assert.equal(document.activeElement, input);
  assert.equal(route.requests.length, 2, 'The held request was never answered');
  hold.resolve(); await running; await settle();
  assert.equal(status.textContent, 'Search cancelled. Press Enter to search again.', 'A late answer is dropped');
  hold = deferred();
  const escaped = panel.search('return');
  fire(input, 'keydown', {key: 'Escape'});
  assert.equal(panel.model.status, 'cancelled');
  hold.resolve(); await escaped; hold = null;

  // Regex and Match case rerun; a typed query waits for a pause.
  input.value = 'f.tch'; regex.checked = true; fire(regex, 'change');
  await until(() => panel.model.status === 'done' && panel.model.regex, 'Regex reruns the search');
  assert.equal(panel.model.total, 243);
  matchCase.checked = true; input.value = 'FETCH'; regex.checked = false; fire(matchCase, 'change');
  await until(() => panel.model.status === 'done' && panel.model.query === 'FETCH', 'Match case reruns the search');
  assert.equal(results.textContent, 'No match for “FETCH” in the searched files.');
  const before = route.requests.length;
  input.value = 'return'; fire(input, 'input'); fire(input, 'input');
  assert.equal(status.textContent, 'Searching when typing pauses…'); assert.equal(route.requests.length, before, 'Typing sends nothing until the pause');
  await until(() => panel.model.status === 'done' && panel.model.query === 'return', 'The typed query runs after the pause');
  assert.equal(route.requests.length, before + 1, 'One request after the pause');
  input.value = ''; fire(input, 'keydown', {key: 'Enter'}); await until(() => panel.model.status === 'idle');
  assert.equal(results.children.length, 0); assert.equal(notes.hidden, true);
  assert.match(status.textContent, /Nothing is read until you search/);
  console.log('PASS source search panel: exact counts per file, marked text-node snippets, the next page on request with focus on its first match, one tab stop with arrow keys, elapsed time with Cancel and Escape, Regex and Match case reruns, typing debounce, opening at the match (production module, not rendered QA)');
}

// The app.js catalog wiring, open path and pane switch with owners faked.
async function checkAppWiring(root) {
  const app = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
  const start = app.indexOf("      // Search all files: the backend's artifact search");
  const end = app.indexOf("      document.querySelector('#source-quick-open').addEventListener('click', openQuickOpen);");
  assert(start >= 0 && end > start, 'Missing Search all files block');
  const syntax = await readFile(join(root, 'apps/research-ui/source_syntax.js'), 'utf8');
  const artifact = (id, kind = 'javascript', extra = {}) => ({artifact_id: id, session_id: '1', kind, url: `https://fixture.invalid/${id}`, byte_size: 10, sha256: id.repeat(64).slice(0, 64), ...extra});
  const calls = [];
  let screen = 'sources';
  const control = {addEventListener() {}, focus() {}};
  const sandbox = {
    URL, console, state: {artifacts: [], sourcePane: 'files', sourceNotice: null},
    document: {querySelector: selector => { assert(selector.startsWith('#source-')); return control; }},
    createSourceSearchPanel: options => { sandbox.panelOptions = options; return {search: query => { calls.push(['search', query]); return query; }}; },
    renderSourcePane: () => calls.push(['pane', sandbox.state.sourcePane]),
    capturedSources: (id = null) => sandbox.state.artifacts.filter(value => value.kind !== 'canvas_data_url' && (id === null || value.artifact_id === id)).map(value => ({...value, source_type: 'artifact'})),
    sourceIdentity: source => source ? `${source.artifact_id}:${source.sha256}` : null,
    sourceDisplayName: source => `${source.artifact_id}.js`, sourceIcon: source => source.kind === 'wasm' ? 'W' : 'JS',
    selectArtifact: (id, line, options) => { calls.push(['select', id, line, plain(options)]); return true; },
    showScreen: name => { calls.push(['screen', name]); screen = name; },
    investigationScreen: () => screen, renderSourceHealth: () => calls.push(['health', sandbox.state.sourceNotice])
  };
  runInNewContext(`${syntax}\n${app.slice(start, end)}\n;investigationNavigation = {record: () => calls.push(['record'])};
    globalThis.wiring = {sourceSearchDescribe, sourceSearchKinds, sourceSearchBinaryFiles, openSourceSearchMatch, openSourceSearch};`,
  Object.assign(sandbox, {calls, investigationNavigation: null}));
  const {sourceSearchDescribe, sourceSearchKinds, sourceSearchBinaryFiles, openSourceSearchMatch, openSourceSearch} = sandbox.wiring;
  assert.equal(sandbox.panelOptions.kinds, sourceSearchKinds); assert.equal(sandbox.panelOptions.binary, sourceSearchBinaryFiles);
  assert.equal(sandbox.panelOptions.describe, sourceSearchDescribe); assert.equal(sandbox.panelOptions.open, openSourceSearchMatch);
  assert.equal(sandbox.panelOptions.request, undefined, 'The panel uses the shipped search route');
  sandbox.state.artifacts = [artifact('300'), artifact('301', 'wasm'), artifact('302', 'canvas_data_url'), artifact('303', 'source_map'),
    artifact('304', 'bytecode_buffer'), artifact('305')];
  assert.deepEqual(plain(sourceSearchKinds()), ['javascript', 'source_map'], 'The text kinds Sources lists, each once; hex kinds are not text');
  assert.equal(sourceSearchBinaryFiles(), 2);
  assert.deepEqual(plain(sourceSearchDescribe('300')), {identity: `300:${'300'.repeat(22).slice(0, 64)}`, name: '300.js · artifact 300', url: 'https://fixture.invalid/300', icon: 'JS'});
  assert.equal(sourceSearchDescribe('999'), null, 'A file outside the catalog has no Sources name');

  // Opening a result selects its file at the match; inside Sources the
  // previous view becomes the Back stop.
  const file = {artifactId: '300', ...sourceSearchDescribe('300')}, match = {line: 1, column: 9, length: 5};
  calls.length = 0; assert.equal(openSourceSearchMatch(file, match), true);
  assert.deepEqual(plain(calls), [['record'], ['select', '300', 1, {passive: true, column: 9, length: 5}]]);
  screen = 'traffic'; calls.length = 0; openSourceSearchMatch(file, match);
  assert.deepEqual(plain(calls), [['select', '300', 1, {passive: true, column: 9, length: 5}], ['screen', 'sources']]);
  for (const stale of [{...file, identity: null}, (sandbox.state.artifacts[0] = artifact('300', 'javascript', {sha256: 'f'.repeat(64)}), file)]) {
    calls.length = 0; assert.equal(openSourceSearchMatch(stale, match), false);
    assert.deepEqual(plain(calls.map(call => call[0])), ['health'], 'A file outside the catalog or changed after the search is refused'); assert.match(calls[0][1], /Search again/);
  }
  calls.length = 0; openSourceSearch('fetch');
  assert.deepEqual(plain(calls), [['screen', 'sources'], ['pane', 'search'], ['search', 'fetch']]);
  console.log('PASS source search app wiring: the text kinds Sources lists, hex files counted, names from the catalog, opening at the match with a Back stop, stale and outside files refused (production app.js block, not rendered QA)');
}

// Every shipped script in the offline DOM model: the palette entry opens
// Search all files, a result reveals its line through the real Sources
// selection and renderer, and Back restores the search pane. Only layout
// leaves the model lacks (ranges and timers) and the search route are supplied.
async function checkShippedSources() {
  const {loadShippedUi} = createRequire(import.meta.url)('./check-native-only-startup.cjs');
  const {window, context, asyncErrors, release} = loadShippedUi();
  try {
    Object.assign(window, {setTimeout, clearTimeout, NodeFilter: window.NodeFilter ?? {SHOW_TEXT: 4}});
    window.document.createRange = () => ({setStart() {}, setEnd() {}, getBoundingClientRect: () => ({left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0})});
    const text = (name, body) => ({protocol_version: 1, artifact_id: name, session_id: '7', navigation_id: '1', frame_id: '1', parent_artifact_id: '0',
      creator_event_id: '0', execution_context_id: '0', capture_origin: 'network_response', kind: 'javascript', url: `https://fixture.invalid/${name}.js`,
      mime_type: 'text/javascript', byte_size: Buffer.byteLength(body), sha256: createHash('sha256').update(body).digest('hex'), sensitive: false, origin: 'demo',
      content: body, sourceTextLength: body.length, contentLossy: false, contentTruncated: false});
    const cart = 'export function cart() {\n  return fetch("/cart");\n}\n', quiet = '// no network here\n';
    context.searchArtifacts = [text('300', cart), {...text('301', 'binary'), kind: 'wasm', mime_type: 'application/wasm', content: undefined, sourceTextLength: undefined}, text('302', quiet)];
    const route = fakeSearchRoute([{id: '300', kind: 'javascript', text: cart}, {id: '301', kind: 'wasm', text: 'binary'}, {id: '302', kind: 'javascript', text: quiet}]);
    const shippedFetch = window.fetch;
    window.fetch = async (input, options) => {
      const url = typeof input === 'string' ? input : input.url;
      if (!url.startsWith('/api/artifacts/search?')) return shippedFetch(input, options);
      return new Response(JSON.stringify(await route.request(url, options.signal)), {status: 200, headers: {'Content-Type': 'application/json'}});
    };
    runInContext(`state.artifacts = searchArtifacts; state.selectedArtifactId = '302'; state.openArtifactIds = ['302']; showScreen('sources');`, context);
    const value = expression => runInContext(expression, context);
    const entry = value("RebCommandPalette.results('fetch').find(group => group.id === 'source-text').items[0]");
    assert.equal(entry.title, 'Search all sources for “fetch”');
    await entry.run();
    assert.equal(new URL(route.requests[0].url, 'http://fixture.invalid').searchParams.get('kind'), 'javascript');
    assert.equal(value("document.querySelector('#source-search-all-panel').hidden"), false);
    assert.equal(value("document.querySelector('#source-tree').hidden"), true);
    assert.equal(value("document.querySelector('#source-tab-search').getAttribute('aria-selected')"), 'true');
    assert.equal(value("document.querySelector('#source-search-all-input').value"), 'fetch');
    assert.equal(value("document.querySelector('#source-search-all-status').textContent"), '1 match in 1 file · searched 2 of 2 files');
    assert.equal(value("document.querySelector('#source-search-all-cancel').hidden"), true);
    assert.match(value("document.querySelector('#source-search-all-notes').textContent"), /1 binary file is not searched as text/);
    assert.equal(value("document.querySelectorAll('#source-search-all-results .source-search-all-match').length"), 1);
    value("document.querySelector('#source-search-all-results .source-search-all-match').click()");
    assert.equal(value('state.selectedArtifactId'), '300');
    assert.equal(value('state.sourceEditorView.window.line'), 1, 'The editor opened at the match line');
    assert.equal(value('state.sourceReveal'), null, 'The requested location was consumed once');
    assert.equal(value('elements.sourcePosition.textContent'), 'Line 2, Column 10 · match from Search all files');
    value("document.querySelector('#source-tab-captured').click()");
    assert.equal(value('state.sourcePane'), 'files');
    assert.equal(value('investigationNavigation.back()'), true);
    assert.equal(value('state.selectedArtifactId'), '302', 'Back returns to the file shown before the result');
    assert.equal(value('state.sourcePane'), 'search', 'Back returns to the search results');
    assert.equal(value("document.querySelector('#source-search-all-panel').hidden"), false);
    assert.equal(value("document.querySelectorAll('#source-search-all-results .source-search-all-match').length"), 1, 'The results are still there');
    assert.deepEqual(asyncErrors, []);
  } finally { release(); Object.assign(globalThis, {setTimeout, clearTimeout}); }
  console.log('PASS source search in the shipped scripts: palette entry opens Search all files through the search route, a result reveals its line through the Sources selection and renderer, Back restores the search pane and results (offline DOM model; not rendered QA)');
}

// The production controller against the built Rust backend over a real
// store: a file far past the old 16 MiB skip, exact totals, a later page,
// UTF-16 columns after an astral character, Regex, invalid UTF-8 named, hex
// and header kinds never searched, and a cancelled search.
export async function checkSourceSearchBackend(root, binary) {
  const directory = await mkdtemp(join(tmpdir(), 'reb-source-search-'));
  const endpoint = join(directory, 'endpoint');
  let child, errors = '';
  try {
    await mkdir(join(directory, 'artifacts/blobs'), {recursive: true});
    const big = Buffer.concat([Buffer.from('var a=1;'.repeat(17 * 1024 * 1024 / 8)), Buffer.from('\nconst 😀 = fetch("/big");\n')]);
    const stored = [['1', 'javascript', big], ['2', 'javascript', Buffer.from(`fetch(a)\nFETCH(b)\n${'fetch '.repeat(450)}`)],
      ['3', 'javascript', Buffer.from([0x66, 0x65, 0x74, 0x63, 0x68, 0xff])], ['4', 'wasm', Buffer.from('\0asm fetch')],
      ['5', 'request_headers', Buffer.from('cookie: fetch=SECRET\r\n')]];
    const manifest = [];
    for (const [id, kind, bytes] of stored) {
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      await writeFile(join(directory, `artifacts/blobs/${sha256}.bin`), bytes);
      const record = {protocol_version: 1, artifact_id: id, session_id: '1', navigation_id: '1', frame_id: '1', parent_artifact_id: '0', creator_event_id: '0',
        kind, url: `https://fixture.invalid/${id}`, mime_type: 'text/plain', byte_size: bytes.length, sha256, sensitive: kind === 'request_headers', content_path: `blobs/${sha256}.bin`};
      if (kind === 'request_headers') Object.assign(record, {capture_origin: 'network_request', execution_context_id: '0', creator_event_id: '5'});
      manifest.push(JSON.stringify(record));
    }
    await writeFile(join(directory, 'artifacts/manifest.jsonl'), `${manifest.join('\n')}\n`);
    await writeFile(join(directory, 'events'), '');
    child = spawn(binary, ['--port', '0', '--store', join(directory, 'events'), '--trace-store', join(directory, 'trace'), '--signal-store', join(directory, 'signals'),
      '--artifacts', join(directory, 'artifacts'), '--api-collection', join(directory, 'collection'), '--local-analyst', join(directory, 'analyst.json'),
      '--endpoint-file', endpoint], {cwd: root, stdio: ['ignore', 'ignore', 'pipe']});
    child.stderr.on('data', value => {errors = (errors + String(value)).slice(-4096);});
    let url = null;
    for (let index = 0; index < 400 && !url; index++) {
      if (child.exitCode !== null) throw new Error(`Backend exited: ${errors}`);
      try {const candidate = (await readFile(endpoint, 'utf8')).trim(); if ((await fetch(`${candidate}/api/health`)).ok) url = candidate;} catch {}
      if (!url) await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert(url, 'Search backend startup deadline exceeded.');
    const model = await searchModel(root, {fetch: (route, options) => fetch(url + route, options)});
    const describe = describer({1: 'big.js', 2: 'many.js', 3: 'lossy.js'});
    const search = model.createSourceSearch({kinds: () => ['javascript'], binary: () => 1, describe, onChange() {}});
    let started = performance.now();
    let result = await search.run('fetch');
    const firstMs = performance.now() - started;
    assert.equal(result.status, 'done', result.error);
    assert.deepEqual([result.total, result.filesWithMatches, result.loaded, result.nextOffset], [454, 3, 200, 200]);
    assert.deepEqual(plain(result.files.map(file => [file.artifactId, file.count, file.validUtf8])), [['1', 1, true], ['2', 452, true]]);
    assert.deepEqual(plain(result.files[0].matches[0]), {line: 1, column: 11, length: 5, byteOffset: big.length - 15,
      snippet: {before: 'const 😀 = ', match: 'fetch', after: '("/big");', clippedStart: false, clippedEnd: false}}, 'A match at the end of a 17 MiB file, at the editor’s UTF-16 column');
    assert.deepEqual([result.coverage.artifacts_selected, result.coverage.complete, plain(result.coverage.not_valid_utf8)], [3, true, ['3']]);
    started = performance.now();
    while (result.nextOffset !== null) result = await search.more();
    const pagesMs = performance.now() - started;
    assert.deepEqual([result.loaded, result.files.length, result.files[2].artifactId, result.files[1].matches.length], [454, 3, '3', 452]);
    result = await search.run('^FETCH\\(\\w\\)$', {regex: true, matchCase: true});
    assert.deepEqual([result.total, result.files[0].matches[0].line, result.files[0].matches[0].column], [1, 1, 0], 'A case-sensitive line-anchored regular expression');
    const cancelled = search.run('a');
    search.cancel(); await cancelled;
    assert.equal(search.model.status, 'cancelled');
    result = await search.run('secret');
    assert.equal(result.total, 0, 'Header blocks are never searched');
    console.log(`PASS source search through the Rust backend: a 17 MiB file searched whole (first page ${Math.round(firstMs)} ms, ${Math.round(pagesMs)} ms for the other pages), exact totals, pages continuing a file, UTF-16 columns after an astral character, Regex, invalid UTF-8 named, hex and header kinds never searched, cancellation (debug build over loopback HTTP)`);
  } finally {
    if (child?.pid && child.exitCode === null) {
      const exited = new Promise(resolve => child.once('exit', resolve));
      child.kill('SIGTERM'); const timer = setTimeout(() => child.kill('SIGKILL'), 1000);
      await exited; clearTimeout(timer);
    }
    await rm(directory, {recursive: true, force: true});
  }
}

export async function checkSourceSearch(root) {
  await checkRows(root);
  await checkController(root);
  await checkPanel(root);
  await checkAppWiring(root);
  await checkShippedSources();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const root = fileURLToPath(new URL('..', import.meta.url));
  if (process.argv[2] === '--backend') {
    assert(process.argv[3], 'Pass the built origin-trace-backend executable.');
    await checkSourceSearchBackend(root, process.argv[3]);
  } else await checkSourceSearch(root);
}
