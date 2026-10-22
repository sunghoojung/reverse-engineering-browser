// Live capture documents fill the native console selector without a disposable
// browser. This fixture never navigates and never executes page JavaScript.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {runInNewContext} from 'node:vm';

export async function checkNativeConsoleLiveDocuments(root) {
  class Node {
    constructor(tag = 'div') {
      this.tagName = tag; this.children = []; this.parentNode = null; this.dataset = {}; this.style = {};
      this.attributes = {}; this.listeners = {}; this._text = ''; this.className = ''; this.value = '';
      this.hidden = false; this.disabled = false; this.scrollTop = 0; this.clientHeight = 100;
      this.clientWidth = 600; this.scrollHeight = 100; this.selectionStart = 0; this.selectionEnd = 0;
    }
    get isConnected() { return this === document.body || !!this.parentNode?.isConnected; }
    get firstElementChild() { return this.children[0]; }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    set textContent(text) { this.replaceChildren(); this._text = String(text); }
    get options() { return this.children; }
    get selectedOptions() { return this.children.filter(child => child.value === this.value); }
    append(...children) {
      for (let child of children) {
        if (typeof child === 'string') { const text = new Node('text'); text.textContent = child; child = text; }
        if (child.tagName === 'fragment') { this.append(...child.children); continue; }
        child.remove(); child.parentNode = this; this.children.push(child);
      }
    }
    replaceChildren(...children) {
      for (const child of this.children) child.parentNode = null;
      this.children = []; this._text = ''; this.append(...children);
      if (this.tagName === 'select' && !this.children.some(child => child.value === this.value)) this.value = this.children[0]?.value || '';
    }
    remove() { if (this.parentNode) { this.parentNode.children.splice(this.parentNode.children.indexOf(this), 1); this.parentNode = null; } }
    setAttribute(name, value) { this.attributes[name] = String(value); }
    getAttribute(name) { return this.attributes[name] ?? null; }
    querySelectorAll(selector) { return this.children.flatMap(child => [...(child.matches(selector) ? [child] : []), ...child.querySelectorAll(selector)]); }
    querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
    closest(selector) { return this.matches(selector) ? this : this.parentNode?.closest(selector) ?? null; }
    contains(node) { return node === this || this.children.some(child => child.contains(node)); }
    matches(selector) {
      return selector === '*' && this.tagName !== 'text' || selector[0] === '.' ? this.className.split(' ').includes(selector.slice(1)) : selector[0] === '#' ? this.id === selector.slice(1) : this.tagName === selector;
    }
    addEventListener(name, callback) { (this.listeners[name] ??= []).push(callback); }
    async emit(name, fields = {}) {
      for (const callback of this.listeners[name] ?? []) await callback({target: this, currentTarget: this, preventDefault() {}, stopPropagation() {}, ...fields});
    }
    click() { return this.disabled ? Promise.resolve() : this.emit('click'); }
    focus() { document.activeElement = this; }
    select() {}
    reportValidity() { return true; }
    setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }
    getBoundingClientRect() { return {top: 0, bottom: 100, left: 0, right: 600, width: 600, height: 100}; }
  }
  const body = new Node('body');
  const document = {
    body, activeElement: null,
    querySelector: selector => body.querySelector(selector),
    createElement: tag => new Node(tag),
    createTextNode: text => { const node = new Node('text'); node.textContent = text; return node; },
    createDocumentFragment: () => new Node('fragment'),
    addEventListener() {},
    dispatchEvent() {},
  };
  const html = await readFile(join(root, 'apps/research-ui/index.html'), 'utf8');
  const ids = [...html.matchAll(/<(\w+)[^>]*\bid="(native-console-[\w-]+)"[^>]*>/g)];
  const panel = new Node('section'); panel.id = 'native-console-panel'; body.append(panel);
  for (const [, tag, id] of ids) {
    if (id === panel.id) continue;
    const node = new Node(tag); node.id = id; panel.append(node);
  }
  const get = id => document.querySelector(`#native-console-${id}`);
  const workspace = new Node(); workspace.id = 'workspace'; body.append(workspace);
  const summary = new Node('summary');
  const menu = new Node(); menu.className = 'native-console-connection-body';
  get('connection').append(summary, menu);
  menu.append(get('start'), get('stop'), get('refresh'));
  get('target').append(new Node('option'));
  get('level').value = 'all';
  get('scroll').append(get('output'));
  get('source').value = '';
  let documents = [
    {id: '11', origin: 'https://alpha.test', label: 'Alpha', url: 'https://alpha.test/a', main_frame: true, truncated: false},
    {id: '22', origin: 'https://alpha.test', label: 'Beta', url: 'https://alpha.test/a', main_frame: true, truncated: false},
  ];
  const calls = [];
  let session = null, selected = null, liveAvailable = true, nextSession = 42, binding = '7';
  const state = () => ({contract_version: 2, state: session ? 'ready' : 'idle', session_id: session, available: true});
  const listing = () => ({...state(), document_source: 'live_capture', live_available: liveAvailable, binding_id: binding, targets: documents, truncated: false, selected_target_id: session && documents.some(item => item.id === selected) ? selected : null});
  const fetch = async (path, options) => {
    const action = options?.body ? JSON.parse(options.body) : null;
    if (path === '/api/native-console') {
      return {ok: true, status: 200, json: async () => ({...listing(), message: liveAvailable ? 'These documents come from the live capture.' : 'Live capture binding unavailable. Restart the capture.'})};
    }
    calls.push(action);
    assert.notEqual(action.action, 'start', 'live selection must never silently launch a disposable browser');
    if (action.action === 'connect_live') {
      assert.equal(action.confirm_live, true); assert.equal(action.binding_id, binding);
      assert.equal(Object.hasOwn(action, 'url'), false);
      assert.equal(Object.hasOwn(action, 'session_id'), false);
      assert.ok(documents.some(item => item.id === action.target_id));
      selected = action.target_id; session = String(nextSession++);
      return {ok: true, status: 200, json: async () => listing()};
    }
    assert.equal(action.session_id, session);
    if (action.action === 'stop') {
      session = null;
      return {ok: true, status: 200, json: async () => state()};
    }
    if (action.action === 'targets') return {ok: true, status: 200, json: async () => listing()};
    assert.equal(action.target_id, selected, 'runtime must address the explicitly authorized native document');
    const command = action.command;
    let runtime = {status: 'ok', text: 'Complete'};
    if (command.operation === 'evaluate') {
      assert.equal(command.source, 'location.href');
      runtime = {status: 'ok', value: {type: 'string', text: `document ${selected}`, truncated: false}};
    }
    if (command.operation === 'poll') runtime = {status: 'ok', messages: [], dropped: 0};
    return {ok: true, status: 200, json: async () => ({...state(), request_id: '1', runtime})};
  };
  const source = await readFile(join(root, 'apps/research-ui/native_console.js'), 'utf8');
  const context = {
    document, TextEncoder, console, setTimeout, clearTimeout, setInterval() {},
    ResizeObserver: class { observe() {} }, MutationObserver: class { observe() {} }, CustomEvent: class {},
    navigator: {clipboard: {writeText: async () => {}}},
    createNativeConsoleCompletion: () => ({close() {}, keydown() { return false; }}),
    createSourceTokenizer: () => ({}), SOURCE_HIGHLIGHT_TOKEN_LIMIT: 8192,
    sourceSyntaxTokens: text => [{type: 'plain', text}], sourcePrettyTokens: () => [], fetch,
  };
  runInNewContext(source.replace(/\}\)\(\);\s*$/, 'globalThis.testConsole = {initialize, refreshLiveDocuments, runtime};})();'), context);
  const settle = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
  const select = async id => { get('target').value = id; await get('target').emit('change'); };
  const consent = async () => { get('live-consent').checked = true; await get('live-consent').emit('change'); };
  await context.testConsole.initialize();
  assert.equal(get('mode').value, 'disposable', 'live discovery cannot change the default execution mode');
  assert.equal(get('target').options.filter(option => option.value).length, 0);
  get('url').value = 'https://disposable.test/retained-url';
  get('mode').value = 'live_capture'; await get('mode').emit('change');
  const labels = [...get('target').options].map(option => option.textContent);
  assert.match(labels.join('\n'), /Alpha/); assert.match(labels.join('\n'), /Beta/);
  assert.match(get('notice').textContent, /cannot set breakpoints, step, or inspect paused frames/);
  assert.match(get('mode-description').textContent, /not read-only/);
  assert.equal(get('start').disabled, true);
  await select('22');
  assert.equal(get('start').disabled, true, 'selection alone is not mutation consent');
  await get('start').click(); await settle(); assert.equal(calls.length, 0);
  await consent(); assert.equal(get('start').disabled, false);
  await get('start').click(); await settle();
  assert.equal(calls[0].action, 'connect_live'); assert.equal(calls[0].target_id, '22');
  assert.equal(get('target').value, '22');
  assert.equal(get('target').disabled, true, 'changing an authorized live document requires disconnect');
  get('source').value = 'location.href'; await get('source').emit('input'); await get('form').emit('submit');
  const evaluation = calls.find(call => call.command?.operation === 'evaluate');
  assert.ok(evaluation); assert.equal(evaluation.target_id, '22');
  assert.match(get('output').textContent, /document 22/);
  await get('refresh').click(); await settle();
  assert.equal(get('target').value, '22', 'refresh preserves the exact surviving document');
  documents = [{...documents[1], id: '33'}]; // Same-URL reload, new native generation.
  await get('refresh').click(); await settle();
  assert.equal(get('target').value, '22'); assert.equal(get('target').selectedOptions[0].disabled, true);
  assert.match(get('target').selectedOptions[0].textContent, /unavailable/);
  assert.equal(get('live-consent').checked, false);
  const beforeStale = calls.length;
  get('source').value = 'location.href'; await get('form').emit('submit');
  assert.equal(calls.length, beforeStale, 'invalidated selection must not dispatch');
  assert.equal(get('run').disabled, true);
  await get('stop').click(); await settle();
  assert.equal(get('mode').value, 'live_capture');
  assert.equal(get('start').disabled, true);
  await select('33'); await consent(); await get('start').click(); await settle();
  assert.equal(calls.filter(call => call.action === 'connect_live').at(-1).target_id, '33');
  assert.equal(session, '43');
  const beforeOldHandle = calls.length;
  await context.testConsole.runtime({operation: 'inspect', handle: '7', offset: 0}, '22', false, '42', 0);
  assert.equal(calls.length, beforeOldHandle, 'old value actions cannot cross reconnect');
  await get('stop').click(); await settle(); await consent();
  binding = '8'; // New browser/backend binding reuses the same numeric document ID.
  const beforeRebind = calls.length;
  await context.testConsole.refreshLiveDocuments(true);
  assert.equal(get('target').selectedOptions[0].disabled, true);
  assert.equal(get('live-consent').checked, false); assert.equal(get('start').disabled, true);
  await get('start').click(); await settle(); assert.equal(calls.length, beforeRebind);
  await select('33'); await consent(); // Explicit selection and fresh consent can use the new binding.
  documents = [];
  await context.testConsole.refreshLiveDocuments(true);
  assert.equal(get('mode').value, 'live_capture', 'disappearance must not switch to disposable mode');
  assert.equal(get('target').value, '33'); assert.equal(get('target').selectedOptions[0].disabled, true);
  assert.equal(get('live-consent').checked, false); assert.equal(get('start').disabled, true);
  await get('start').click(); await settle();
  liveAvailable = false; await context.testConsole.refreshLiveDocuments(true);
  assert.match(get('notice').textContent, /binding unavailable/); assert.equal(get('mode').value, 'live_capture');
  assert.equal(calls.some(call => call.action === 'start'), false);
  console.log('PASS native live mode requires exact document consent, preserves selection, revokes stale authorization, and never launches a fallback');

}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  await checkNativeConsoleLiveDocuments(new URL('..', import.meta.url).pathname);
}
