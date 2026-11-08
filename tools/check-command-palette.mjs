// Command palette checks. They run the production registry, matcher and dialog
// controller from command_palette.js, and the provider block from app.js, in a
// small DOM model with only leaves and owner functions faked. Not rendered QA.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {runInNewContext} from 'node:vm';

// Just enough DOM for the palette and Search all files: a tree with text,
// attributes, focus, bubbling events and modal dialogs. Text is never parsed
// as markup.
export function fakeDocument() {
  const document = {listeners: {}, activeElement: null};
  class FakeText {
    constructor(text) { this.nodeType = 3; this._text = String(text); this.parentNode = null; this.children = []; this.listeners = {}; }
    get textContent() { return this._text; }
    get all() { return [this]; }
    matches() { return false; }
  }
  class FakeNode {
    constructor(tag) {
      this.nodeType = 1; this.tagName = tag.toUpperCase(); this.children = []; this.parentNode = null; this.attributes = {}; this.listeners = {};
      this.dataset = {}; this._text = ''; this.id = ''; this.className = ''; this.value = ''; this.open = false; this.modal = false;
    }
    get isConnected() { for (let node = this; node; node = node.parentNode) if (node === document.body) return true; return false; }
    set textContent(value) { this._text = String(value); for (const child of this.children) child.parentNode = null; this.children = []; }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    append(...nodes) {
      for (const node of nodes) {
        if (node.parentNode) node.parentNode.children.splice(node.parentNode.children.indexOf(node), 1);
        node.parentNode = this; this.children.push(node);
      }
    }
    replaceChildren(...nodes) { for (const child of this.children) child.parentNode = null; this.children = []; this.append(...nodes); }
    setAttribute(name, value) { this.attributes[name] = String(value); }
    getAttribute(name) { return this.attributes[name] ?? null; }
    removeAttribute(name) { delete this.attributes[name]; }
    addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); }
    focus() { document.activeElement = this; }
    select() { this.selected = true; }
    scrollIntoView() {}
    contains(node) { for (; node; node = node.parentNode) if (node === this) return true; return false; }
    matches(selector) {
      return selector.split(',').map(part => part.trim()).some(part => part === this.tagName.toLowerCase() ||
        part === '[contenteditable="true"]' && this.attributes.contenteditable === 'true');
    }
    closest(selector) { for (let node = this; node; node = node.parentNode) if (node.matches(selector)) return node; return null; }
    querySelectorAll(selector) {
      assert.match(selector, /^\.[a-z-]+$/, 'The fake DOM resolves single class selectors only');
      return this.all.slice(1).filter(node => node.className?.split?.(' ').includes(selector.slice(1)));
    }
    showModal() { this.open = true; this.modal = true; }
    close() { this.open = false; this.modal = false; }
    get all() { return [this, ...this.children.flatMap(child => child.all)]; }
  }
  const create = (tag, id, parent = document.body) => { const node = new FakeNode(tag); if (id) node.id = id; parent.append(node); return node; };
  Object.assign(document, {
    body: new FakeNode('body'),
    createElement: tag => new FakeNode(tag),
    createTextNode: text => new FakeText(text),
    addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); },
    getElementById: id => document.body.all.find(node => node.id === id) ?? null,
    querySelector: selector => selector === 'dialog:modal' ? document.body.all.find(node => node.tagName === 'DIALOG' && node.modal) ?? null : null
  });
  const fire = (target, type, init = {}) => {
    const event = {type, target, defaultPrevented: false, stopped: false, metaKey: false, ctrlKey: false, altKey: false, shiftKey: false,
      repeat: false, isComposing: false, key: '', code: '', preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; }, ...init};
    for (let node = target; node && !event.stopped; node = node === document ? null : node.parentNode ?? document) {
      for (const listener of node.listeners[type] ?? []) listener(event);
    }
    return event;
  };
  return {document, create, fire};
}

function loadPalette(source) {
  const {document, create, fire} = fakeDocument();
  const opener = create('button', 'opener'), field = create('input', 'field'), editor = create('div', 'editor');
  editor.setAttribute('contenteditable', 'true');
  const otherDialog = create('dialog', 'other-dialog');
  const dialog = create('dialog', 'command-palette'), head = create('div', '', dialog);
  const input = create('input', 'command-palette-input', head), list = create('div', 'command-palette-results', dialog);
  const status = create('span', 'command-palette-status', create('footer', '', dialog));
  const trigger = create('button', 'command-palette-open');
  const errors = [];
  const context = {document, console: {error: (...values) => errors.push(values)}};
  runInNewContext(source, context);
  return {palette: context.RebCommandPalette, document, fire, opener, field, editor, otherDialog, dialog, input, list, status, trigger, errors};
}

const options = list => list.all.filter(node => node.attributes.role === 'option');
const titles = list => options(list).map(option => option.children[0].textContent);
const item = (title, detail, run = () => {}) => ({title, detail, run});
// Values from the script context have its own prototypes; compare as data.
const plain = value => JSON.parse(JSON.stringify(value));

async function checkPaletteModule(root) {
  const source = await readFile(join(root, 'apps/research-ui/command_palette.js'), 'utf8');
  assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\bfetch\s*\(/, 'Results are text; the palette never fetches');
  let ui = loadPalette(source);
  const {palette} = ui;
  assert.equal(palette.open(), false, 'open() before mount is refused, not thrown');
  for (const bad of [null, {}, {id: 'x', group: 'X'}, {id: '', group: 'X', search() {}}, {id: 'x', group: ' ', search() {}}, {id: 'x'.repeat(65), group: 'X', search() {}}])
    assert.throws(() => palette.addProvider(bad), {name: 'TypeError'});

  // Registration before mount works, so a module may load before app.js.
  let externalCalls = 0;
  const removeEarly = palette.addProvider({id: 'names', group: 'Names', search: query => { externalCalls++; return [item(`alias ${query}`, 'researcher name')]; }});
  const ran = [];
  const workspaces = {id: 'workspaces', group: 'Workspaces', empty: true, search: () =>
    ['Traffic', 'Sources', 'VM'].map(name => item(name, 'Workspace', () => ran.push([name, ui.document.activeElement])))};
  const api = palette.mount({trigger: ui.trigger, providers: [workspaces]});
  assert(api && palette.mount() === api, 'Mounting is idempotent');

  // Empty query: built-in workspaces and actions only; providers are not asked.
  let groups = palette.results('');
  assert.deepEqual(plain(groups.map(group => group.label)), ['Workspaces']);
  assert.equal(externalCalls, 0, 'An empty query never runs providers');
  assert.deepEqual(plain(palette.results('  ').map(group => group.label)), ['Workspaces'], 'Whitespace is an empty query');

  // Case-insensitive substring over title and detail; prefixes rank first.
  palette.addProvider({id: 'rank', group: 'Ranked', search: () => [
    item('prefetch', ''), item('a fetch b', ''), item('xyz', 'detail mentions FETCH'), item('FetchAll', ''), item('nothing', 'here'),
    item('xyz', 'fetch first in detail'), item('refetch', 'fetch'), item('fetch()', ''), item('w', 'prefetching')
  ]});
  groups = palette.results('fEtCh');
  const ranked = plain(groups.find(group => group.label === 'Ranked').items.map(value => `${value.title}|${value.detail}`));
  assert.deepEqual(ranked, ['FetchAll|', 'fetch()|', 'a fetch b|', 'prefetch|', 'refetch|fetch', 'xyz|detail mentions FETCH', 'xyz|fetch first in detail', 'w|prefetching'],
    'Title prefix, title word start, title substring, detail prefix, detail substring; ties keep provider order');
  assert.deepEqual(plain(groups.find(group => group.label === 'Names').items.map(value => value.title)), ['alias fEtCh'], 'Providers receive the trimmed query');
  assert.deepEqual(plain(palette.results('zzz').map(group => group.label)), ['Names'], 'Groups without matches are omitted');

  // At most 50 per group, with an explicit remainder; candidate scans are bounded.
  palette.addProvider({id: 'many', group: 'Many', search: () => Array.from({length: 120}, (_, index) => item(`match ${index}`))});
  palette.addProvider({id: 'huge', group: 'Huge', search: () => Array.from({length: 10005}, (_, index) => item(`match huge ${index}`))});
  groups = palette.results('match');
  const many = groups.find(group => group.label === 'Many'), huge = groups.find(group => group.label === 'Huge');
  assert.equal(many.items.length, 50); assert.equal(many.more, 70); assert.equal(many.items[49].title, 'match 49');
  assert.equal(huge.items.length, 50); assert.equal(huge.more, 9950);
  assert.match(huge.notes.join(' '), /Only the first 10,000 of 10,005 candidates were matched/);

  // A provider that throws, returns a non-list or malformed items stays in its group.
  const hostile = {};
  Object.defineProperty(hostile, 'title', {get() { throw new Error('getter'); }});
  palette.addProvider({id: 'throws', group: 'Throws', search: () => { throw new Error('provider failure'); }});
  palette.addProvider({id: 'object', group: 'Not a list', search: () => ({title: 'match'})});
  palette.addProvider({id: 'getter', group: 'Getter', search: () => [item('match ok'), hostile]});
  palette.addProvider({id: 'malformed', group: 'Malformed', search: () => [item('match good'), {title: 'match no run'}, {title: '', run() {}},
    {title: 'match bad detail', detail: 7, run() {}}, null, 'match']});
  groups = palette.results('match');
  for (const label of ['Throws', 'Not a list', 'Getter']) {
    const group = groups.find(value => value.label === label);
    assert.deepEqual(plain(group.items), [], `${label}: no partial results from a failed provider`);
    assert.match(group.notes[0], /unavailable: its search failed/);
  }
  const malformed = groups.find(group => group.label === 'Malformed');
  assert.deepEqual(plain(malformed.items.map(value => value.title)), ['match good']); assert.match(malformed.notes[0], /5 malformed results were ignored/);
  assert.equal(groups.find(group => group.label === 'Many').items.length, 50, 'Other groups are unaffected');

  // Same id replaces in place; the remover only removes its own registration.
  const replaceNames = palette.addProvider({id: 'names', group: 'Names v2', search: () => [item('match renamed')]});
  removeEarly();
  assert(palette.results('match').some(group => group.label === 'Names v2'), 'A stale remover cannot drop the replacement');
  replaceNames();
  assert(!palette.results('match').some(group => group.label.startsWith('Names')));
  for (const id of ['rank', 'many', 'huge', 'throws', 'object', 'getter', 'malformed']) palette.addProvider({id, group: 'Gone', search: () => []});
  console.log('PASS command palette registry: provider contract, empty query, case-insensitive ranking, 50-per-group caps with remainder, bounded scans, failing and malformed providers isolated, replace/remove (production module, not rendered QA)');

  // Key guards. Cmd+K opens anywhere; Ctrl+K stays with text fields.
  const {document, fire, opener, field, editor, otherDialog, dialog, input, list, status, trigger} = ui;
  const key = (target, init) => fire(target, 'keydown', {code: 'KeyK', key: 'k', ...init});
  const reset = () => { if (dialog.open) api.close(); opener.focus(); };
  for (const [target, init, opens, reason] of [
    [opener, {metaKey: true}, true, 'Cmd+K on a control'],
    [field, {metaKey: true}, true, 'Cmd+K inside a text field'],
    [editor, {metaKey: true}, true, 'Cmd+K inside an editor'],
    [opener, {ctrlKey: true}, true, 'Ctrl+K outside text fields'],
    [field, {ctrlKey: true}, false, 'Ctrl+K deletes to end of line in text fields'],
    [editor, {ctrlKey: true}, false, 'Ctrl+K in a contenteditable editor'],
    [opener, {metaKey: true, shiftKey: true}, false, 'Shift changes the shortcut'],
    [opener, {metaKey: true, altKey: true}, false, 'Alt changes the shortcut'],
    [opener, {metaKey: true, repeat: true}, false, 'Key repeat'],
    [opener, {}, false, 'Plain K'],
    [opener, {metaKey: true, code: 'KeyJ', key: 'j'}, false, 'Another letter']
  ]) {
    reset();
    const event = key(target, init);
    assert.equal(dialog.open, opens, reason); assert.equal(event.defaultPrevented, opens, `${reason}: default handling`);
  }
  reset(); otherDialog.showModal();
  assert.equal(key(opener, {metaKey: true}).defaultPrevented, false); assert.equal(dialog.open, false, 'Never stacks over another modal dialog');
  assert.equal(api.open(), false); otherDialog.close();

  // Opening focuses the field, lists workspaces, and makes the palette the
  // modal that keeps the Cmd/Ctrl+digit listener out.
  reset(); key(opener, {metaKey: true});
  assert.equal(document.activeElement, input); assert.equal(document.querySelector('dialog:modal'), dialog);
  assert.equal(trigger.getAttribute('aria-expanded'), 'true');
  assert.deepEqual(titles(list), ['Traffic', 'Sources', 'VM']);
  assert.equal(input.getAttribute('aria-activedescendant'), options(list)[0].id);
  let leaked = 0; document.addEventListener('keydown', () => { leaked++; });
  fire(input, 'keydown', {code: 'Digit2', key: '2', metaKey: true});
  fire(input, 'keydown', {code: 'KeyJ', key: 'j', ctrlKey: true});
  assert.equal(leaked, 0, 'Keys typed in the palette never reach workspace, Console or sidebar shortcuts');
  const selected = () => options(list).findIndex(option => option.getAttribute('aria-selected') === 'true');
  for (const [name, expected] of [['ArrowDown', 1], ['ArrowDown', 2], ['ArrowDown', 0], ['ArrowUp', 2], ['Home', 0], ['End', 2]]) {
    assert.equal(fire(input, 'keydown', {key: name}).defaultPrevented, true, name);
    assert.equal(selected(), expected, `${name} moves the active result`);
    assert.equal(input.getAttribute('aria-activedescendant'), options(list)[expected].id);
  }
  ran.length = 0;
  fire(input, 'keydown', {key: 'Enter'});
  assert.equal(dialog.open, false); assert.equal(trigger.getAttribute('aria-expanded'), 'false');
  assert.deepEqual(ran.map(([name]) => name), ['VM'], 'Enter runs the active result once');
  assert.equal(ran[0][1], opener, 'Focus is back where it was before the result moves it');
  assert.equal(options(list).length, 0, 'Closing drops result closures');

  // Escape (key or dialog cancel) closes and restores focus without running.
  for (const close of [() => fire(input, 'keydown', {key: 'Escape'}), () => fire(dialog, 'cancel'), () => key(input, {metaKey: true})]) {
    field.focus(); key(field, {metaKey: true}); assert.equal(document.activeElement, input);
    ran.length = 0; close();
    assert.equal(dialog.open, false); assert.equal(document.activeElement, field, 'Focus returns to the text field it came from'); assert.deepEqual(ran, []);
  }
  opener.focus(); key(opener, {metaKey: true}); fire(input, 'keydown', {key: 'Escape', isComposing: true});
  assert.equal(dialog.open, true, 'Escape during IME composition belongs to the composition'); api.close();

  // Typed queries filter; captured text stays text; clicks run results.
  const markup = '<img src=x onerror="globalThis.__rebInjected=1">';
  let capturedRuns = 0;
  palette.addProvider({id: 'captured', group: 'Captured', search: () => [item(`${markup} payload`, `GET ${markup}`, () => { capturedRuns++; })]});
  palette.addProvider({id: 'broken-run', group: 'Broken', search: () => [item('payload failure', '', () => { throw new Error('run failed'); })]});
  assert.equal(api.open('payload'), true); assert.equal(input.value, 'payload');
  assert.deepEqual(titles(list), [`${markup} payload`, 'payload failure']);
  assert.equal(options(list)[0].children.length, 2, 'Title and detail are two text spans, no parsed markup');
  assert.equal(options(list)[0].children[0].children.length, 0);
  fire(options(list)[0], 'click'); assert.equal(capturedRuns, 1); assert.equal(dialog.open, false);
  api.open('payload failure'); fire(input, 'keydown', {key: 'Enter'});
  assert.equal(dialog.open, false); assert.equal(ui.errors.length, 1, 'A failing result is reported, not thrown into the page');
  assert.equal(api.open('payload'), true, 'The palette still opens after a failing result'); api.close();

  // Typing re-renders, states truncation, and an empty result says what was searched.
  palette.addProvider({id: 'many', group: 'Many', search: () => Array.from({length: 75}, (_, index) => item(`row ${index}`))});
  api.open(); input.value = 'row'; fire(input, 'input');
  assert.equal(options(list).length, 50); assert.match(list.textContent, /25 more, refine the query/);
  assert.match(status.textContent, /50 results · Many shows 50 of 75; refine the query/);
  input.value = 'qqqq'; fire(input, 'input');
  assert.equal(options(list).length, 0); assert.match(list.textContent, /Nothing matches “qqqq”/);
  assert.equal(input.getAttribute('aria-activedescendant'), null);
  fire(input, 'keydown', {key: 'Enter'}); assert.equal(dialog.open, true, 'Enter without a result does nothing');
  api.close();
  trigger.focus(); fire(trigger, 'click'); assert.equal(dialog.open, true, 'The sidebar trigger opens it');
  fire(input, 'keydown', {key: 'Escape'}); assert.equal(document.activeElement, trigger);
  console.log('PASS command palette controller: Cmd+K anywhere, Ctrl+K outside text fields, modal guard and contained shortcuts, Arrow/Home/End, Enter and click run once after focus returns, Escape/cancel restore focus, inert text, failing results contained, explicit remainders (production module, not rendered QA)');
}

// The app.js provider block, run against fakes of the owners it calls. Each
// result must use the owner's existing navigation, not a copy of it.
async function checkPaletteProviders(root) {
  const app = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
  const start = app.indexOf('      // Command palette (Cmd/Ctrl + K).');
  assert(start >= 0, 'Missing command palette provider block');
  const block = app.slice(start, app.indexOf('\n      })();\n', start) + '\n      })();\n'.length);
  const requestRoot = app.slice(app.indexOf('      function requestTraceRoot('), app.indexOf('      function requestSignalProfileSelection('));
  const navigation = await readFile(join(root, 'apps/research-ui/investigation_navigation.js'), 'utf8');
  const traffic = await readFile(join(root, 'apps/research-ui/traffic_view.js'), 'utf8');
  const calls = [];
  let mounted = null;
  const button = (id, attributes = {}) => ({id, attributes, clicks: 0, hidden: false, getAttribute(name) { return this.attributes[name] ?? null; },
    click() { this.clicks++; calls.push(['click', id]); }, focus() { calls.push(['focus', id]); }});
  const nav = [['traffic', 'Traffic'], ['sources', 'Sources'], ['vm', 'VM']].map(([name, label]) => button(`nav-${name}`, {'aria-label': label}));
  const controls = Object.fromEntries(['#native-console-toggle', '#open-investigation-notebook', '#theme-toggle', '#sidebar-toggle', '#vm-show-findings',
    '#console-traffic-back', '#console-experiment-traffic', '#command-palette-open'].map(selector => [selector, button(selector.slice(1))]));
  controls['#native-console-toggle'].attributes['aria-pressed'] = 'false';
  controls['#sidebar-toggle'].attributes['aria-label'] = 'Collapse sidebar';
  controls['#console-experiment-traffic'].hidden = true;
  const vmRows = [], requestRows = [];
  let screen = 'vm';
  const event = (session, sequence, request) => ({session_id: session, process_id: 17, sequence_number: sequence, request_id: request, type: 'request_started', category: 'network'});
  const context = {
    URL,
    document: {documentElement: {dataset: {}}, querySelector: selector => selector === '.screen:not([hidden])' ? {id: `screen-${screen}`} : controls[selector] ?? null,
      querySelectorAll: selector => { assert.equal(selector, '.primary-nav .nav-button[data-screen]'); return nav; }},
    state: {requests: [], vmFindings: []},
    elements: {vmList: {querySelectorAll: selector => { assert.equal(selector, '.vm-row'); return vmRows; }},
      requestRows: {querySelectorAll: selector => { assert.equal(selector, '.request-row'); return requestRows; }},
      requestFilter: {focus() { calls.push(['focus', 'request-filter']); }}},
    RebCommandPalette: {mount: options => { mounted = options; return {open() {}}; }},
    integerText: (value, field) => String(value[field]),
    showScreen: name => { calls.push(['showScreen', name]); screen = name; },
    selectRequest: id => { calls.push(['selectRequest', id]); context.state.selectedRequestId = id; },
    selectArtifact: id => calls.push(['selectArtifact', id]),
    requestAnimationFrame: callback => calls.push(['frame', callback]),
    capturedSources: () => [{artifact_id: '300', session_id: '1', sha256: 'a'.repeat(64), byte_size: 396, kind: 'javascript', url: 'https://checkout.acme.test/assets/cart.js', mime_type: 'text/javascript'},
      {artifact_id: '301', session_id: '0', sha256: 'b'.repeat(64), byte_size: 8, kind: 'wasm', url: '', mime_type: 'application/wasm'}],
    sourceDisplayName: source => `file ${source.artifact_id}`,
    sourceKindLabel: kind => ({javascript: ['JS', 'JavaScript'], wasm: ['W', 'WebAssembly']})[kind],
    formatByteSize: bytes => `${bytes} B`,
    sourceHexArtifact: source => source.kind === 'wasm',
    openSourceSearch: query => calls.push(['openSourceSearch', query])
  };
  runInNewContext(`${traffic}\n${requestRoot}\n${navigation}\n${block}\n;investigationNavigation = {record: () => calls.push(['record'])};`, context);
  context.calls = calls;
  context.openInvestigation = link => { calls.push(['openInvestigation', link]); return true; };
  context.investigationNotice = (message, status) => calls.push(['notice', status, message]);
  assert(mounted, 'app.js mounts the palette');
  assert.equal(mounted.trigger, controls['#command-palette-open'], 'The sidebar Search button is the trigger');
  const provider = id => mounted.providers.find(value => value.id === id);
  assert.deepEqual(plain(mounted.providers.map(value => [value.id, value.group, value.empty === true])),
    [['workspaces', 'Workspaces', true], ['actions', 'Actions', true], ['requests', 'Requests', false], ['files', 'Files', false], ['vm-findings', 'VM findings', false],
      ['source-text', 'Search in sources', false]]);

  // Workspaces and actions click their real controls, like Cmd/Ctrl + digit.
  const spaces = provider('workspaces').search('');
  assert.deepEqual(plain(spaces.map(value => value.title)), ['Traffic', 'Sources', 'VM']);
  assert.equal(spaces[1].detail, 'Workspace · ⌘ / Ctrl + 2');
  calls.length = 0; spaces[1].run(); assert.deepEqual(calls, [['click', 'nav-sources'], ['focus', 'nav-sources']]);
  let actions = provider('actions').search('');
  assert.deepEqual(plain(actions.map(value => value.title)), ['Open Console', 'Open investigation notebook', 'Switch to light theme', 'Collapse sidebar']);
  context.document.documentElement.dataset.theme = 'light'; controls['#native-console-toggle'].attributes['aria-pressed'] = 'true';
  controls['#sidebar-toggle'].attributes['aria-label'] = 'Expand sidebar';
  actions = provider('actions').search('');
  assert.deepEqual(plain(actions.map(value => value.title)), ['Close Console', 'Open investigation notebook', 'Switch to dark theme', 'Expand sidebar'], 'Action titles follow current state');
  for (const [index, id] of [[0, 'native-console-toggle'], [1, 'open-investigation-notebook'], [2, 'theme-toggle'], [3, 'sidebar-toggle']]) {
    calls.length = 0; actions[index].run(); assert.deepEqual(calls, [['click', id]]);
  }

  // Requests: exact native identity uses the linked opener; other rows open
  // like a row click after the same uniqueness check.
  const live = {id: 'live-1', origin: 'live', method: 'POST', path: 'https://api.example.test/v1/collect?x=1', status: 200, type: 'xhr', events: [event('11', '9', '91')]};
  const demo = {id: 'demo-1', origin: 'demo', method: 'GET', path: 'collector.example.test', hostOnly: true, status: 'pending', type: 'other', events: [event('1', '2', '3')]};
  context.state.requests = [live, demo];
  const rows = provider('requests').search('collect');
  assert.equal(provider('requests').search('x'), rows, 'Request items are reused until the retained window changes');
  assert.deepEqual(plain(rows.map(value => value.title)), ['POST api.example.test/v1/collect?x=1', 'GET collector.example.test']);
  assert.equal(rows[0].detail, '200 · Fetch/XHR · request 91 · session 11 · process 17 · sequence 9');
  assert.equal(rows[1].detail, 'pending · Other · host only · no exact retained identity');
  calls.length = 0; rows[0].run();
  assert.deepEqual(plain(calls), [['openInvestigation', {kind: 'request', identity: {type: 'captured-request', session: '11', process: '17', sequence: '9', request: '91'}}]]);
  const frame = () => { const index = calls.findIndex(call => call[0] === 'frame'); assert(index >= 0, 'Focus waits for the next frame'); calls.splice(index, 1)[0][1](); };
  calls.length = 0; rows[1].run(); frame();
  assert.deepEqual(plain(calls), [['showScreen', 'traffic'], ['selectRequest', 'demo-1'], ['focus', 'request-filter']], 'A row outside the window leaves focus on the filter, as Traffic does');
  requestRows.push({dataset: {requestId: 'demo-1'}, focus() { calls.push(['row focus', 'demo-1']); }});
  screen = 'traffic'; controls['#console-experiment-traffic'].hidden = false;
  calls.length = 0; rows[1].run(); frame();
  assert.deepEqual(plain(calls), [['record'], ['showScreen', 'traffic'], ['click', 'console-traffic-back'], ['selectRequest', 'demo-1'], ['row focus', 'demo-1']],
    'Within Traffic the previous selection becomes a Back stop; a Console activity view gives way through its own Back button; the row takes focus');
  screen = 'vm';
  context.state.requests = [live, demo, {...demo}];
  calls.length = 0; rows[1].run(); assert.deepEqual(plain(calls.map(call => call.slice(0, 2))), [['notice', 'stale']], 'An ambiguous row is refused, not guessed');
  assert.notEqual(provider('requests').search('x'), rows, 'A new retained window rebuilds the items');

  // Files open through the exact artifact link, or Quick Open's selection.
  const files = provider('files').search('file');
  assert.deepEqual(plain(files.map(value => [value.title, value.detail])), [['file 300', 'https://checkout.acme.test/assets/cart.js · JavaScript · 396 B · artifact 300'], ['file 301', '(anonymous) · WebAssembly · 8 B · artifact 301']]);
  calls.length = 0; files[0].run();
  assert.deepEqual(plain(calls), [['openInvestigation', {kind: 'artifact', identity: {type: 'captured-artifact', session: '1', artifact: '300', sha256: 'a'.repeat(64), bytes: 396}}]]);
  calls.length = 0; files[1].run(); assert.deepEqual(calls, [['showScreen', 'sources'], ['selectArtifact', '301']]);

  // VM findings select the listed row through its own click handler, then
  // keep focus there after the workspace's own focus pass.
  context.state.vmFindings = [{findingId: '7', investigationId: '3', label: 'Dispatch loop', kind: 'dispatch_loop', hostRuntime: 'javascript', confidence: 'observed'},
    {findingId: 'analysis:abc:artifact:302', investigationId: '4', analysis: true, kind: 'x', hostRuntime: 'javascript', confidence: 'inferred'}];
  const found = provider('vm-findings').search('dispatch');
  assert.deepEqual(plain(found.map(value => value.title)), ['Dispatch loop', 'VM patterns in source']);
  assert.equal(found[1].detail, 'Code analysis · finding analysis:abc:artifact:302 · investigation 4 · javascript · inferred');
  vmRows.push({dataset: {findingId: '7'}, click() { calls.push(['row click', '7']); }, focus() { calls.push(['row focus', '7']); }});
  calls.length = 0; found[0].run();
  assert.deepEqual(plain(calls.slice(0, 3)), [['showScreen', 'vm'], ['click', 'vm-show-findings'], ['row click', '7']]);
  calls.find(call => call[0] === 'frame')[1]();
  assert.deepEqual(calls.at(-1), ['row focus', '7'], 'The chosen finding keeps focus');
  calls.length = 0; found[1].run();
  assert.deepEqual(plain(calls.map(call => call.slice(0, 2))), [['showScreen', 'vm'], ['click', 'vm-show-findings'], ['notice', 'stale']], 'A finding that left the list is refused');
  // Searching every source is one entry; typing never reads artifact bytes
  // (this context has no fetch at all).
  const sourceText = provider('source-text').search('payload');
  assert.deepEqual(plain(sourceText.map(value => [value.title, value.detail])), [['Search all sources for “payload”', 'Literal text in 1 retained text file · Sources']]);
  calls.length = 0; sourceText[0].run(); assert.deepEqual(plain(calls), [['openSourceSearch', 'payload']]);
  const sources = context.capturedSources; context.capturedSources = () => [];
  assert.equal(provider('source-text').search('payload').length, 0, 'Nothing to search, no entry'); context.capturedSources = sources;
  console.log('PASS command palette providers: workspaces and actions click their own controls, exact request/artifact identities use the linked opener, identity-less rows reuse row and Quick Open selection, VM findings select their own row, stale and ambiguous items refused, Search all sources entry without reads (production app.js block, not rendered QA)');
}

export async function checkCommandPalette(root) {
  await checkPaletteModule(root);
  await checkPaletteProviders(root);
  const html = await readFile(join(root, 'apps/research-ui/index.html'), 'utf8');
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map(match => match[1]);
  assert.equal(scripts[0], 'command_palette.js', 'The registry loads before every module that may add a provider');
  const sidebar = html.slice(html.search(/<aside\b[^>]*class="sidebar"/), html.indexOf('</aside>'));
  const trigger = sidebar.match(/<button id="command-palette-open"[^>]*>/)?.[0];
  assert(trigger && sidebar.indexOf(trigger) < sidebar.indexOf('<nav class="primary-nav"'), 'Search sits at the top of the sidebar, outside the numbered workspaces');
  for (const attribute of ['aria-label="Search"', 'aria-keyshortcuts="Meta+K Control+K"', 'aria-haspopup="dialog"', 'title="Search workspaces and evidence (⌘ / Ctrl + K)"'])
    assert(trigger.includes(attribute), `Trigger keeps ${attribute} for the icon-only rail`);
  assert.match(html, /<dialog id="command-palette"[^>]*aria-label="Search Origin Trace"/);
  for (const path of ['apps/origin-trace-backend/src/app.rs', 'apps/research-ui/macos/OriginTraceApp.swift', 'scripts/build-research-app.sh'])
    assert((await readFile(join(root, path), 'utf8')).includes('command_palette.js'), `${path} packages command_palette.js`);
  console.log('PASS command palette wiring: registry loads first, sidebar Search trigger with accessible name and shortcut, packaged asset lists (not rendered QA)');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await checkCommandPalette(fileURLToPath(new URL('..', import.meta.url)));
