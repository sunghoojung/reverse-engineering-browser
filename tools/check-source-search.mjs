// Search all files checks. The literal matcher, bounded search controller and
// results panel run from source_search.js; the reader, open path and palette
// entry run from app.js. Only DOM leaves, fetch and owner functions are faked.
// The last section drives every shipped script in the offline DOM model.
// Requires: npm ci --prefix tools/ui-startup-deps --ignore-scripts --no-audit --no-fund
import assert from 'node:assert/strict';
import {createHash, webcrypto} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
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
  const syntax = await readFile(join(root, 'apps/research-ui/source_syntax.js'), 'utf8');
  const search = await readFile(join(root, 'apps/research-ui/source_search.js'), 'utf8');
  return runInNewContext(`${syntax}\n${search}\n;({SOURCE_SEARCH_LIMITS, sourceSearchText, sourceSearchSnippet, createSourceSearch, sourceSearchNotes, sourceSearchStatus, createSourceSearchPanel})`,
    {URL, setTimeout, clearTimeout, AbortController, ...context});
}

async function checkMatcher(root) {
  const model = await searchModel(root);
  const text = 'a.b(c\nxa.b(c A.B(C axb(\n\t  İstanbul fetch(\n';
  const found = model.sourceSearchText(text, 'a.b(');
  assert.deepEqual(plain(found.matches.map(match => [match.line, match.column, match.length])), [[0, 0, 4], [1, 1, 4], [1, 7, 4]],
    'Literal, case-insensitive by default; a dot never matches another character');
  assert.deepEqual(plain(model.sourceSearchText(text, 'a.b(', {matchCase: true}).matches.map(match => [match.line, match.column])), [[0, 0], [1, 1]], 'Match case');
  assert.equal(model.sourceSearchText(text, 'a.*').matches.length, 0, 'Pattern syntax is text');
  assert.deepEqual(plain(model.sourceSearchText(text, 'fetch(').matches.map(match => [match.line, match.column])), [[2, 12]], 'Columns are the editor’s UTF-16 columns after a dotted capital I');
  const snippet = model.sourceSearchText(text, 'fetch(').matches[0].snippet;
  assert.deepEqual(plain(snippet), {before: 'İstanbul ', match: 'fetch(', after: '', clippedStart: false, clippedEnd: false}, 'Indentation is dropped; nothing is clipped');
  const long = `${'x'.repeat(400)}needle${'y'.repeat(400)}`;
  const clipped = model.sourceSearchText(long, 'needle').matches[0].snippet;
  assert.equal(clipped.before, 'x'.repeat(12)); assert.equal(clipped.match, 'needle'); assert(clipped.clippedStart && clipped.clippedEnd);
  assert(clipped.after.length <= model.SOURCE_SEARCH_LIMITS.snippet);
  for (const query of ['a\nb', 'a\rb', 'x'.repeat(513)]) assert(model.sourceSearchText(text, query).error, 'Line separators and over-long queries are refused like Find');
  const many = model.sourceSearchText('a '.repeat(150), 'a', {limit: 100});
  assert.equal(many.matches.length, 100); assert.equal(many.truncated, true);
  const hostile = model.sourceSearchText(`${'a'.repeat(50000)}b`, 'a'.repeat(30) + 'c');
  assert.equal(hostile.matches.length, 0, 'A near-miss literal in adversarial text completes');
  console.log('PASS source search matcher: literal text with escaped pattern syntax, Unicode case folding or Match case, editor line/column, bounded snippets, Find refusals, per-file cap (production module, not rendered QA)');
}

function fileEntry(id, name, extra = {}) {
  return {identity: `identity-${id}`, artifactId: id, name, url: `https://fixture.invalid/${name}`, icon: 'JS', byteSize: 1000, binary: false, ...extra};
}

async function checkController(root) {
  const model = await searchModel(root);
  const texts = new Map([['1', 'fetch(a)\nfetch(b)'], ['4', 'fetch big'], ['5', 'fetch � lossy'], ['6', 'fetch '.repeat(150)], ['7', 'no match here']]);
  const entries = [fileEntry('1', 'cart.js'), fileEntry('2', 'module.wasm', {binary: true}), fileEntry('3', 'broken.js'), fileEntry('4', 'bundle.js', {byteSize: 5 * 1024 * 1024}),
    fileEntry('5', 'body.bin'), fileEntry('6', 'noisy.js'), fileEntry('7', 'quiet.js')];
  const reads = [], changes = [];
  const read = async (entry, signal, limit) => {
    reads.push(entry.artifactId); assert.equal(limit, 2 * 1024 * 1024); assert(signal && !signal.aborted);
    if (entry.artifactId === '3') throw new Error('artifact store returned 500');
    return {text: texts.get(entry.artifactId), bytes: Math.min(entry.byteSize, limit), partial: entry.byteSize > limit, lossy: entry.artifactId === '5'};
  };
  const search = model.createSourceSearch({list: () => entries, read, onChange: (value, file) => changes.push([value.completed, file?.artifactId ?? null, value.status])});
  let result = await search.run('fetch', false);
  assert.equal(result.status, 'done');
  assert.deepEqual(reads, ['1', '3', '4', '5', '6', '7'], 'Binary files are never read');
  assert.deepEqual(plain(result.files.map(file => [file.name, file.state, file.matches.length, file.matchLimit])),
    [['cart.js', 'searched', 2, ''], ['module.wasm', 'binary', 0, ''], ['broken.js', 'failed', 0, ''], ['bundle.js', 'searched', 1, ''], ['body.bin', 'searched', 1, ''], ['noisy.js', 'searched', 100, 'file'], ['quiet.js', 'searched', 0, '']]);
  assert.deepEqual(changes.map(change => change[0]), [0, 1, 2, 3, 4, 5, 6, 7, 7], 'Progress after every file');
  assert.equal(model.sourceSearchStatus(result), 'Searched 5 of 7 files · 104 matches in 4 files');
  const notes = plain(model.sourceSearchNotes(result));
  assert.deepEqual(notes.map(note => note.kind), ['binary', 'failed', 'partial', 'lossy', 'file-limit']);
  assert.match(notes[0].text, /1 binary file, not searched: module\.wasm/);
  assert.match(notes[1].text, /broken\.js \(artifact store returned 500\)/);
  assert.match(notes[2].text, /over the 2 MiB size cap; only its first 2 MiB was searched: bundle\.js/);
  assert.match(notes[3].text, /not proof of absence: body\.bin/);
  assert.match(notes[4].text, /stopped at 100 matches/);

  // Overall caps: matches and bytes per search.
  const capped = model.createSourceSearch({list: () => entries, read, onChange() {}, limits: {...model.SOURCE_SEARCH_LIMITS, totalMatches: 102}});
  result = await capped.run('fetch');
  assert.deepEqual(plain(result.files.map(file => [file.state, file.matches.length, file.matchLimit])),
    [['searched', 2, ''], ['binary', 0, ''], ['failed', 0, ''], ['searched', 1, ''], ['searched', 1, ''], ['searched', 98, 'total'], ['match-limit', 0, '']]);
  assert.match(model.sourceSearchNotes(result, capped.limits ?? {...model.SOURCE_SEARCH_LIMITS, totalMatches: 102}).at(-1).text, /Results stopped at 102 matches; 1 file was not searched/);
  const budget = model.createSourceSearch({list: () => entries, read, onChange() {}, limits: {...model.SOURCE_SEARCH_LIMITS, totalBytes: 2500}});
  result = await budget.run('fetch');
  assert.deepEqual(plain(result.files.map(file => file.state)), ['searched', 'binary', 'failed', 'byte-limit', 'searched', 'byte-limit', 'byte-limit'],
    'A file that would pass the read budget is not read; smaller later files still are');
  assert.match(model.sourceSearchNotes(result, {...model.SOURCE_SEARCH_LIMITS, totalBytes: 2500}).find(note => note.kind === 'byte-limit').text, /3 files were not searched: this search reached its/);

  // A new query retires the running search: its reads are aborted and late
  // results are dropped.
  const held = deferred(), signals = [];
  const slow = model.createSourceSearch({list: () => entries.slice(0, 1), onChange() {}, read: (entry, signal) => {
    signals.push(signal);
    return signals.length === 1 ? held.promise : Promise.resolve({text: 'second fetch', bytes: 12, partial: false, lossy: false});
  }});
  const first = slow.run('fetch');
  await settle();
  const second = await slow.run('second');
  assert.equal(signals[0].aborted, true, 'The previous read is aborted');
  held.resolve({text: 'fetch fetch fetch', bytes: 17, partial: false, lossy: false});
  await first;
  assert.equal(slow.model.query, 'second'); assert.equal(second.status, 'done');
  assert.deepEqual(plain(slow.model.files.map(file => file.matches.length)), [1], 'Late results from the retired query never appear');
  const third = slow.run('again'); slow.cancel(); await third;
  assert.equal(slow.model.status, 'cancelled');
  assert.equal(model.sourceSearchStatus({...slow.model, status: 'idle'}), 'Literal text in every retained text file. Nothing is read until you search.');
  result = await model.createSourceSearch({list: () => { throw new Error('list must not be read for a refused query'); }, read, onChange() {}}).run('a\nb');
  assert.equal(result.status, 'error'); assert.match(model.sourceSearchStatus(result), /single-line literal/);
  console.log('PASS source search controller: binary skip, failures, size-capped prefix, lossy, per-file/total match and byte caps named, progress per file, cancellation drops late results (production module, not rendered QA)');
}

async function checkPanel(root) {
  const {document, create, fire} = fakeDocument();
  const model = await searchModel(root, {document});
  const input = create('input', 'input'), matchCase = create('input', 'case'), status = create('p', 'status');
  const notes = create('ul', 'notes'), results = create('div', 'results');
  const markup = '<img src=x onerror="globalThis.__rebInjected=1">';
  const entries = [fileEntry('1', 'cart.js'), fileEntry('2', 'module.wasm', {binary: true}), fileEntry('3', 'broken.js'), fileEntry('8', 'markup.js')];
  const texts = {1: 'const a = fetch(x);\nreturn fetch(y);', 8: `${markup} fetch`};
  const opened = [];
  let reads = 0;
  const panel = model.createSourceSearchPanel({input, matchCase, status, notes, results, delay: 5, list: () => entries,
    read: async entry => { reads++; if (entry.artifactId === '3') throw new Error('timed out after 10 seconds'); return {text: texts[entry.artifactId], bytes: 10, partial: false, lossy: false}; },
    open: (file, match) => opened.push([file.artifactId, match.line, match.column, match.length])});
  await panel.search('fetch');
  assert.equal(document.activeElement, input);
  assert.equal(status.textContent, 'Searched 2 of 4 files · 3 matches in 2 files');
  assert.equal(notes.hidden, false);
  assert.deepEqual(notes.children.map(node => node.dataset.note), ['binary', 'failed']);
  assert.match(notes.textContent, /module\.wasm/); assert.match(notes.textContent, /broken\.js \(timed out after 10 seconds\)/);
  const buttons = results.all.filter(node => node.className === 'source-search-all-match');
  assert.deepEqual(buttons.map(button => button.dataset.sourceMatch), ['1:0:10', '1:1:7', `8:0:${markup.length + 1}`]);
  assert.deepEqual(buttons.map(button => button.tabIndex), [0, -1, -1], 'One tab stop for the results');
  const groups = results.all.filter(node => node.className === 'source-search-all-file');
  assert.deepEqual(groups.map(group => group.children[0].textContent), ['JScart.js2', 'JSmarkup.js1']);
  assert.equal(groups[0].children[1].textContent, 'https://fixture.invalid/cart.js');
  assert.equal(buttons[0].textContent, '1:11const a = fetch(x);');
  const mark = buttons[2].all.find(node => node.tagName === 'MARK');
  assert.equal(mark.textContent, 'fetch');
  assert.equal(buttons[2].all.filter(node => node.tagName === 'IMG').length, 0, 'Captured markup stays text');
  assert(buttons[2].all.some(node => node.nodeType === 3 && node.textContent === '…njected=1"> '), 'Context is a text node, clipped to 12 characters before the match');

  // Keyboard: Down from the field, then through the results; Up from the first returns.
  fire(input, 'keydown', {key: 'ArrowDown'}); assert.equal(document.activeElement, buttons[0]);
  fire(buttons[0], 'keydown', {key: 'ArrowDown'}); assert.equal(document.activeElement, buttons[1]);
  assert.deepEqual(buttons.map(button => button.tabIndex), [-1, 0, -1]);
  fire(buttons[1], 'keydown', {key: 'End'}); assert.equal(document.activeElement, buttons[2]);
  fire(buttons[2], 'keydown', {key: 'Home'}); assert.equal(document.activeElement, buttons[0]);
  fire(buttons[0], 'keydown', {key: 'ArrowUp'}); assert.equal(document.activeElement, input);
  fire(buttons[1], 'click');
  assert.deepEqual(opened, [['1', 1, 7, 5]], 'A result opens its file at the match');

  // Match case reruns; a typed query retires the old run at once and runs after a pause.
  matchCase.checked = true; input.value = 'FETCH'; fire(matchCase, 'change');
  await until(() => panel.model.status === 'done' && panel.model.query === 'FETCH', 'Match case reruns the search');
  assert.equal(panel.model.matchCase, true);
  assert.equal(results.textContent, 'No match for “FETCH” in the searched files.');
  const before = reads;
  input.value = 'return'; fire(input, 'input'); fire(input, 'input');
  assert.equal(reads, before, 'Typing does not read until the pause');
  await until(() => panel.model.status === 'done' && panel.model.query === 'return', 'The typed query runs after the pause');
  assert.equal(panel.model.query, 'return'); assert.equal(reads, before + 3, 'One run after the pause, three text files read');
  input.value = ''; fire(input, 'keydown', {key: 'Enter'}); await until(() => panel.model.status === 'idle');
  assert.equal(results.children.length, 0); assert.equal(notes.hidden, true);
  assert.match(status.textContent, /Nothing is read until you search/);
  console.log('PASS source search panel: status and partial-result notes, results grouped by file with marked text-node snippets, one tab stop with arrow keys, Match case rerun, typing debounce, opening at the match (production module, not rendered QA)');
}

// The app.js reader, open path and pane switch with fetch and owners faked.
async function checkAppWiring(root) {
  const app = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
  const start = app.indexOf('      // Search all files. Reads use the artifact content route');
  const end = app.indexOf("      document.querySelector('#source-quick-open').addEventListener('click', openQuickOpen);");
  assert(start >= 0 && end > start, 'Missing Search all files block');
  const facts = await readFile(join(root, 'apps/research-ui/source_facts.js'), 'utf8');
  const syntax = await readFile(join(root, 'apps/research-ui/source_syntax.js'), 'utf8');
  const bytes = text => new TextEncoder().encode(text);
  const artifact = (id, body, extra = {}) => ({protocol_version: 1, artifact_id: id, session_id: '1', kind: 'javascript', url: `https://fixture.invalid/${id}.js`,
    mime_type: 'text/javascript', byte_size: body.length, sha256: createHash('sha256').update(body).digest('hex'), ...extra});
  const bodies = new Map(), calls = [], requests = [];
  let screen = 'sources';
  const response = (status, body, total = body.length) => ({ok: status === 200, status,
    headers: {get: name => name === 'X-Artifact-Total-Bytes' ? String(total) : null},
    body: {getReader() { let sent = false; return {read: async () => sent ? {done: true} : (sent = true, {done: false, value: body}), releaseLock() {}, cancel: async () => {}}; },
      cancel: async () => {}}});
  const control = {addEventListener() {}, focus() {}};
  const sandbox = {
    URL, TextEncoder, TextDecoder, AbortController, setTimeout, clearTimeout, crypto: webcrypto, console, Uint8Array,
    state: {artifacts: [], sourcePane: 'files', sourceNotice: null},
    fetch: async (url, options) => {
      requests.push(url); assert.equal(options.cache, 'no-store'); assert(options.signal);
      const id = /^\/api\/artifacts\/([0-9]+)\/content\?limit=2097152$/.exec(url)?.[1];
      assert(id, `Only the artifact content route with the preview limit: ${url}`);
      const body = bodies.get(id);
      return body ? response(200, body.bytes, body.total) : response(404, new Uint8Array());
    },
    document: {querySelector: selector => { assert(selector.startsWith('#source-')); return control; }},
    createSourceSearchPanel: options => { sandbox.panelOptions = options; return {search: query => { calls.push(['search', query]); return query; }}; },
    renderSourcePane: () => calls.push(['pane', sandbox.state.sourcePane]),
    capturedSources: () => sandbox.state.artifacts.filter(value => value.kind !== 'canvas_data_url').map(value => ({...value, source_type: 'artifact'})),
    sourceIdentity: source => source ? sandbox.sourceFactsIdentity({...source, source_type: 'artifact'}) : null,
    sourceDisplayName: source => `${source.artifact_id}.js`, sourceIcon: source => source.kind === 'wasm' ? 'W' : 'JS',
    selectArtifact: (id, line, options) => { calls.push(['select', id, line, plain(options)]); return true; },
    showScreen: name => { calls.push(['screen', name]); screen = name; },
    investigationScreen: () => screen, renderSourceHealth: () => calls.push(['health', sandbox.state.sourceNotice])
  };
  runInNewContext(`${syntax}\n${facts}\n${app.slice(start, end)}\n;investigationNavigation = {record: () => calls.push(['record'])};
    globalThis.wiring = {sourceSearchFiles, readSourceSearchText, openSourceSearchMatch, openSourceSearch, sourceSearchCache};`,
  Object.assign(sandbox, {calls, investigationNavigation: null}));
  const {sourceSearchFiles, readSourceSearchText, openSourceSearchMatch, openSourceSearch, sourceSearchCache} = sandbox.wiring;
  assert.equal(sandbox.panelOptions.list, sourceSearchFiles); assert.equal(sandbox.panelOptions.read, readSourceSearchText);
  assert.equal(sandbox.panelOptions.open, openSourceSearchMatch);

  const cart = bytes('export function cart() {\n  return fetch("/cart");\n}\n');
  sandbox.state.artifacts = [artifact('300', cart), artifact('301', new Uint8Array([0, 97, 115, 109]), {kind: 'wasm', mime_type: 'application/wasm'}),
    artifact('302', bytes('canvas'), {kind: 'canvas_data_url'})];
  bodies.set('300', {bytes: cart});
  let files = sourceSearchFiles();
  assert.deepEqual(plain(files.map(file => [file.artifactId, file.name, file.icon, file.binary, file.byteSize])),
    [['300', '300.js · artifact 300', 'JS', false, cart.length], ['301', '301.js · artifact 301', 'W', true, 4]], 'Sources files only; binary kinds flagged');
  const signal = new AbortController().signal, limit = 2 * 1024 * 1024;
  let read = await readSourceSearchText(files[0], signal, limit);
  assert.equal(read.text, new TextDecoder().decode(cart)); assert.equal(read.partial, false); assert.equal(read.lossy, false);
  assert.deepEqual(requests, ['/api/artifacts/300/content?limit=2097152']);
  assert.equal((await readSourceSearchText(files[0], signal, limit)).text, read.text);
  assert.equal(requests.length, 1, 'A searched file is cached for the next query');

  // A loaded Sources preview is reused without a request, excluding its viewer note.
  Object.assign(sandbox.state.artifacts[0], {content: 'preview fetch\n\n[Viewer preview limited]', sourceTextLength: 13, contentTruncated: true, contentLossy: false});
  sourceSearchCache.clear();
  read = await readSourceSearchText(files[0], signal, limit);
  assert.deepEqual(plain(read), {text: 'preview fetch', bytes: cart.length, partial: true, lossy: false}); assert.equal(requests.length, 1);
  delete sandbox.state.artifacts[0].content;

  // Every read is checked like the preview: status, size and SHA-256.
  const refuse = async (body, total, pattern, extra = {}) => {
    sandbox.state.artifacts = [artifact('300', cart, extra)]; sourceSearchCache.clear();
    bodies.set('300', {bytes: body, total});
    await assert.rejects(readSourceSearchText(sourceSearchFiles()[0], signal, limit), pattern);
  };
  await refuse(bytes('export function cart() {\n  return fetch("/evil");\n}\n'), undefined, /bytes do not match the retained SHA-256/);
  await refuse(cart, cart.length + 1, /retained byte size changed/);
  bodies.delete('300'); sandbox.state.artifacts = [artifact('300', cart)];
  await assert.rejects(readSourceSearchText(sourceSearchFiles()[0], signal, limit), /artifact store returned 404/);
  const invalid = new Uint8Array([0x66, 0x65, 0x74, 0x63, 0x68, 0xff]);
  sandbox.state.artifacts = [artifact('300', invalid)]; bodies.set('300', {bytes: invalid});
  read = await readSourceSearchText(sourceSearchFiles()[0], signal, limit);
  assert.equal(read.lossy, true); assert.equal(read.text, 'fetch\ufffd');
  const stale = sourceSearchFiles()[0];
  sandbox.state.artifacts = [artifact('300', cart)];
  await assert.rejects(readSourceSearchText(stale, signal, limit), /changed or left the retained catalog/);
  sourceSearchFiles();
  assert.equal(sourceSearchCache.size, 0, 'Files that leave the catalog leave the search cache');

  // Opening a result selects its file at the match; inside Sources the
  // previous view becomes the Back stop.
  files = sourceSearchFiles();
  const match = {line: 1, column: 9, length: 5};
  calls.length = 0; assert.equal(openSourceSearchMatch(files[0], match), true);
  assert.deepEqual(plain(calls), [['record'], ['select', '300', 1, {passive: true, column: 9, length: 5}]]);
  screen = 'traffic'; calls.length = 0; openSourceSearchMatch(files[0], match);
  assert.deepEqual(plain(calls), [['select', '300', 1, {passive: true, column: 9, length: 5}], ['screen', 'sources']]);
  sandbox.state.artifacts = [artifact('300', bytes('changed'))];
  calls.length = 0; assert.equal(openSourceSearchMatch(files[0], match), false);
  assert.deepEqual(plain(calls.map(call => call[0])), ['health'], 'A file that changed after the search is refused'); assert.match(calls[0][1], /Search again/);
  calls.length = 0; openSourceSearch('fetch');
  assert.deepEqual(plain(calls), [['screen', 'sources'], ['pane', 'search'], ['search', 'fetch']]);
  console.log('PASS source search app wiring: Sources files with binary kinds flagged, one content route at the preview limit, preview and search caches reused, status/size/SHA-256 checks, lossy decode, stale refusal, opening at the match with a Back stop (production app.js block, not rendered QA)');
}

// Every shipped script in the offline DOM model: the palette entry opens
// Search all files, a result reveals its line through the real Sources
// selection and renderer, and Back restores the search pane. Only layout
// leaves the model lacks (ranges and timers) are supplied.
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
    context.searchArtifacts = [text('300', 'export function cart() {\n  return fetch("/cart");\n}\n'),
      {...text('301', 'binary'), kind: 'wasm', mime_type: 'application/wasm', content: undefined, sourceTextLength: undefined},
      text('302', '// no network here\n')];
    runInContext(`state.artifacts = searchArtifacts; state.selectedArtifactId = '302'; state.openArtifactIds = ['302']; showScreen('sources');`, context);
    const value = expression => runInContext(expression, context);
    const entry = value("RebCommandPalette.results('fetch').find(group => group.id === 'source-text').items[0]");
    assert.equal(entry.title, 'Search all sources for “fetch”');
    await entry.run();
    assert.equal(value("document.querySelector('#source-search-all-panel').hidden"), false);
    assert.equal(value("document.querySelector('#source-tree').hidden"), true);
    assert.equal(value("document.querySelector('#source-tab-search').getAttribute('aria-selected')"), 'true');
    assert.equal(value("document.querySelector('#source-search-all-input').value"), 'fetch');
    assert.equal(value("document.querySelector('#source-search-all-status').textContent"), 'Searched 2 of 3 files · 1 match in 1 file');
    assert.match(value("document.querySelector('#source-search-all-notes').textContent"), /1 binary file, not searched: [^.]*artifact 301\./);
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
  console.log('PASS source search in the shipped scripts: palette entry opens Search all files, a result reveals its line through the Sources selection and renderer, Back restores the search pane and results (offline DOM model; not rendered QA)');
}

export async function checkSourceSearch(root) {
  await checkMatcher(root);
  await checkController(root);
  await checkPanel(root);
  await checkAppWiring(root);
  await checkShippedSources();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await checkSourceSearch(fileURLToPath(new URL('..', import.meta.url)));
