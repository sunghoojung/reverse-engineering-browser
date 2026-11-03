// The shipped Console panel drives the document-start experiment: a disabled
// control, explicit consent, an exact rule, inert output text, and a cleared
// state. This fixture never launches a browser and never executes page
// JavaScript; it asserts what the panel sends and what a researcher sees.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {runInNewContext} from 'node:vm';

export async function checkNativeConsoleDocumentStart(root) {
  class Node {
    constructor(tag = 'div') {
      this.tagName = tag; this.children = []; this.parentNode = null; this.dataset = {}; this.style = {};
      this.attributes = {}; this.listeners = {}; this._text = ''; this.className = ''; this.value = '';
      this.hidden = false; this.disabled = false; this.checked = false; this.open = false;
      this.scrollTop = 0; this.clientHeight = 100; this.clientWidth = 600; this.scrollHeight = 100;
      this.selectionStart = 0; this.selectionEnd = 0;
    }
    get isConnected() { return this === document.body || !!this.parentNode?.isConnected; }
    get firstElementChild() { return this.children[0]; }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    set textContent(text) { this.replaceChildren(); this._text = String(text); }
    set innerHTML(value) { throw new Error(`Captured output must be inserted as text, never markup: ${value}`); }
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
    removeAttribute(name) { delete this.attributes[name]; }
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
  const ds = name => get(`ds-${name}`);
  const workspace = new Node(); workspace.id = 'workspace'; body.append(workspace);
  const summary = new Node('summary');
  const menu = new Node(); menu.className = 'native-console-connection-body';
  get('connection').append(summary, menu);
  menu.append(get('start'), get('stop'), get('refresh'), get('ds'));
  get('target').append(new Node('option'));
  get('level').value = 'all';
  get('scroll').append(get('output'));
  get('source').value = '';

  // Synthetic owner. It never compiles or runs a snippet; it records what the
  // panel asked for and replays bounded records the browser would have sent.
  const calls = [];
  const reads = [];
  let session = null, permitted = false, generation = 0, armed = [], output = [], nextSequence = 1;
  let readFails = false, malformed = false, armRefused = false, stopUnconfirmed = false, unconfirmed = false, refusedProcesses = 0;
  // A live capture's binding as /api/native-console lists it before any Console
  // connection: the browser's own report of its launch-time permission.
  let liveSupported = null;
  const record = (sequence, kind, text, script = '1') => ({
    sequence: String(sequence), record: kind, provenance: 'console-document-start-script',
    script_id: script, document_id: '7', frame_id: '99', top_frame: true,
    time: 1700000000000, truncated: false, text,
  });
  const documentStartState = after => ({
    status: permitted ? 'ok' : 'unavailable', permitted, generation: String(generation),
    renderer_processes: permitted ? 1 : 0, pending_renderer_processes: armed.length ? refusedProcesses : 0,
    refused_renderer_processes: refusedProcesses,
    scripts: armed,
    message: permitted ? undefined : 'Rebuild the pinned browser, then start a session with document_start enabled, or relaunch the live capture with REB_CONSOLE_DOCUMENT_START=1.',
    output: {
      records: output.filter(entry => Number(entry.sequence) > Number(after)).slice(0, 32),
      next_sequence: String(nextSequence), oldest_sequence: output[0]?.sequence || '0',
      retained: output.length, dropped: 0, unattributed: 0, stale: 0,
    },
  });
  const fetch = async (path, options) => {
    if (path.startsWith('/api/native-console/document-start')) {
      reads.push(path);
      if (readFails) return {ok: false, status: 503, json: async () => ({error: 'Document-start read unavailable'})};
      const after = new URL(path, 'http://127.0.0.1').searchParams.get('after_sequence');
      assert.match(after, /^(0|[1-9][0-9]{0,19})$/, 'the cursor must stay a canonical decimal');
      const value = !session && unconfirmed
        ? {status: 'unconfirmed', permitted: false, scripts: [],
          message: 'The capture browser did not confirm that it cleared the armed document-start scripts. Restart the capture before relying on documents running nothing.'}
        : documentStartState(after);
      if (malformed) value.output.records = [{...record(nextSequence, 'report', 'x'), provenance: 'native-capture'}];
      return {ok: true, status: 200, json: async () => ({contract_version: 3, available: true,
        state: session ? 'ready' : 'idle', session_id: session, document_start: value,
        limits: {scripts: 4, source_bytes: 4096, total_source_bytes: 8192, rule_bytes: 256, report_bytes: 512,
          records_per_document: 64, retained_records: 128, records_per_read: 32, execution_millis: 50},
        unsupported: [{context: 'service_worker', reason: 'The injector observes documents only.'},
          {context: 'already_open_document', reason: 'Reload a document that was open when the set was armed.'}]})};
    }
    if (path === '/api/native-console') {
      if (liveSupported !== null && !session) {
        return {ok: true, status: 200, json: async () => ({contract_version: 2, state: 'idle', session_id: null,
          available: true, live_available: true, document_source: 'live_capture', binding_id: '5',
          targets: [{id: '21', origin: 'http://127.0.0.1:8080', label: 'top #21', url: 'http://127.0.0.1:8080/lab/',
            main_frame: true, truncated: false}], truncated: false, selected_target_id: null,
          document_start_supported: liveSupported, message: 'live capture'})};
      }
      return {ok: true, status: 200, json: async () => ({contract_version: 2, state: session ? 'ready' : 'idle',
        session_id: session, available: true, message: ''})};
    }
    const action = JSON.parse(options.body);
    calls.push(action);
    if (action.action === 'start') {
      permitted = action.document_start === true;
      session = '42';
      return {ok: true, status: 200, json: async () => ({contract_version: 2, state: 'ready', session_id: session,
        targets: [{id: '11', origin: 'http://127.0.0.1:8080', label: 'top #11', url: 'http://127.0.0.1:8080/lab/',
          main_frame: true, truncated: false}], truncated: false, document_start_supported: permitted})};
    }
    if (action.action === 'arm_document_start') {
      assert.equal(action.confirm_document_start, true, 'arming must carry explicit consent');
      if (armRefused) {
        const refusal = documentStartState('0');
        delete refusal.output;
        return {ok: true, status: 200, json: async () => ({contract_version: 3, state: 'ready', session_id: session,
          document_start: {...refusal, status: 'error', text: 'Synthetic browser refused this rule'},
          code: 'application_failed', details: {}})};
      }
      ++generation;
      armed = action.scripts.map((script, index) => ({
        script_id: String(index + 1), rule: {origin: script.origin, frame: script.frame,
          ...(script.path_prefix ? {path_prefix: script.path_prefix} : {})},
        source_bytes: script.source.length, digest: 'a1b2c3d4e5f60718',
        records: 2, injected_documents: 1, refused: 0,
      }));
      output = [record(nextSequence++, 'injected', "Snippet ran before this document's own scripts"),
                record(nextSequence++, 'report', '<img src=x onerror=alert(1)> kinds=string:12')];
      return {ok: true, status: 200, json: async () => ({contract_version: 3, state: 'ready', session_id: session,
        document_start: documentStartState('0')})};
    }
    if (action.action === 'clear_document_start') {
      ++generation; armed = []; output = [];
      return {ok: true, status: 200, json: async () => ({contract_version: 3, state: 'ready', session_id: session,
        document_start: documentStartState('0')})};
    }
    if (action.action === 'stop') {
      if (stopUnconfirmed && armed.length) {
        // The owner ended the binding but the browser never confirmed the clear.
        session = null; permitted = false; armed = []; output = []; unconfirmed = true;
        return {ok: false, status: 409, json: async () => ({error: 'The capture browser did not confirm that it cleared the armed document-start scripts.',
          code: 'state_conflict', details: {}})};
      }
      session = null; permitted = false; armed = []; output = [];
      return {ok: true, status: 200, json: async () => ({contract_version: 2, state: 'idle', session_id: null})};
    }
    return {ok: true, status: 200, json: async () => ({contract_version: 2, state: 'ready', session_id: session,
      request_id: '1', runtime: {status: 'ok', messages: [], dropped: 0}})};
  };

  const source = await readFile(join(root, 'apps/research-ui/native_console.js'), 'utf8');
  const context = {
    document, TextEncoder, console, setTimeout, clearTimeout, setInterval() {}, URL,
    ResizeObserver: class { observe() {} }, MutationObserver: class { observe() {} }, CustomEvent: class {},
    navigator: {clipboard: {writeText: async () => {}}},
    createNativeConsoleCompletion: () => ({close() {}, keydown() { return false; }}),
    createSourceTokenizer: () => ({}), SOURCE_HIGHLIGHT_TOKEN_LIMIT: 8192,
    sourceSyntaxTokens: text => [{type: 'plain', text}], sourcePrettyTokens: () => [], fetch,
  };
  runInNewContext(source.replace(/\}\)\(\);\s*$/, 'globalThis.testConsole = {initialize, documentStart};})();'), context);
  const settle = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
  const rows = () => get('output').children.filter(row => row.className.includes('native-console-ds-record'));

  await context.testConsole.initialize();
  await context.testConsole.documentStart.refresh(true); await settle();

  // Disabled control: no session, nothing permitted, nothing armable.
  assert.equal(ds('badge').hidden, true, 'an unarmed experiment with no session shows no indicator');
  assert.match(ds('state').textContent, /REB_CONSOLE_DOCUMENT_START/);
  assert.equal(ds('arm').disabled, true);
  assert.equal(ds('clear').disabled, true);
  await ds('arm').click(); await settle();
  assert.equal(calls.length, 0, 'a disabled control must never dispatch');

  // A live capture the packaged app launched with the permission shows it
  // before any Console connection, and still arms nothing on its own.
  liveSupported = true;
  await context.testConsole.initialize(true); await context.testConsole.documentStart.refresh(true); await settle();
  assert.equal(ds('badge').hidden, false, 'a permitted live capture is visible without opening anything');
  assert.equal(ds('badge').dataset.state, 'permitted');
  assert.equal(ds('badge').textContent, 'Doc-start: permitted');
  assert.match(ds('badge').title, /permitted for this live capture, none armed/, 'a narrow header keeps the state in the hover title');
  assert.equal(ds('badge').getAttribute('aria-label'), ds('badge').title);
  assert.match(ds('state').textContent, /This live capture permits document-start scripts.*Nothing runs until you arm one/);
  assert.equal(ds('arm').disabled, true, 'permission is not a connection or consent');
  await ds('arm').click(); await settle();
  assert.equal(calls.length, 0, 'a permitted live capture arms nothing without a connection');
  // An older browser, or an explicit REB_CONSOLE_DOCUMENT_START=0, lists no
  // permission: no indicator, and the settings say why.
  liveSupported = false;
  await context.testConsole.initialize(true); await context.testConsole.documentStart.refresh(true); await settle();
  assert.equal(ds('badge').hidden, true);
  assert.match(ds('state').textContent, /lacks the rebuilt overlay, or it was started with REB_CONSOLE_DOCUMENT_START=0/);
  liveSupported = null;
  await context.testConsole.initialize(true); await context.testConsole.documentStart.refresh(true); await settle();
  assert.equal(ds('badge').hidden, true);

  // Permission is a launch-time decision carried by the explicit opt-in.
  get('url').value = 'http://127.0.0.1:8080/lab/';
  await get('start').click(); await settle();
  assert.equal(calls.at(-1).document_start, false, 'start defaults to no document-start permission');
  await get('stop').click(); await settle();
  ds('enable').checked = true; await ds('enable').emit('change');
  assert.match(ds('state').textContent, /Nothing runs until you arm one/);
  await get('start').click(); await settle();
  assert.equal(calls.at(-1).action, 'start');
  assert.equal(calls.at(-1).document_start, true);
  await context.testConsole.documentStart.refresh(true); await settle();
  assert.match(ds('state').textContent, /Armed scripts: 0/);

  // An exact rule plus explicit consent before anything is armed.
  ds('origin').value = 'http://127.0.0.1:8080';
  ds('frame').value = 'child';
  ds('path').value = '/lab/';
  await ds('origin').emit('input');
  assert.equal(ds('arm').disabled, true, 'a rule without a snippet cannot be armed');
  ds('source').value = "report('kinds=string:12');";
  await ds('source').emit('input');
  assert.equal(ds('arm').disabled, true, 'a rule and a snippet are not consent');
  ds('consent').checked = true; await ds('consent').emit('change');
  assert.equal(ds('arm').disabled, false);
  await ds('arm').click(); await settle();
  const arm = calls.at(-1);
  assert.equal(arm.action, 'arm_document_start');
  assert.equal(arm.confirm_document_start, true);
  assert.deepEqual(arm.scripts, [{origin: 'http://127.0.0.1:8080', frame: 'child', path_prefix: '/lab/',
    source: "report('kinds=string:12');"}]);
  assert.equal(ds('consent').checked, false, 'consent is spent, not remembered');

  // The indicator is visible without opening anything, and the armed rule is
  // shown exactly as declared.
  assert.equal(ds('badge').hidden, false);
  assert.equal(ds('badge').dataset.state, 'armed');
  assert.match(ds('badge').textContent, /1 armed/);
  assert.equal(panel.dataset.documentStart, 'armed');
  assert.match(ds('armed').textContent, /http:\/\/127\.0\.0\.1:8080/);
  assert.match(ds('armed').textContent, /child frame/);
  assert.match(ds('armed').textContent, /path \/lab\/\*/);
  assert.match(ds('counters').textContent, /every renderer holds this set/);
  assert.match(ds('rule-help').textContent, /Never reached: service worker, already open document/);

  // Output is labeled page JavaScript and stays inert text.
  const first = rows();
  assert.equal(first.length, 2, 'both the injection and the report are visible');
  assert.match(first[0].textContent, /console-document-start-script/);
  assert.match(first[0].textContent, /page JavaScript/);
  assert.match(first[1].textContent, /<img src=x onerror=alert\(1\)>/);
  assert.equal(first[1].querySelector('img'), null, 'captured text is never parsed as markup');
  assert.equal(first[0].dataset.level, 'info');

  // A renderer refused at the process limit is never reported as ready.
  refusedProcesses = 1;
  await context.testConsole.documentStart.refresh(true); await settle();
  assert.match(ds('counters').textContent, /1 renderer processes not ready yet/);
  assert.match(ds('counters').textContent, /1 renderer processes over the 64-process limit never receive a set/);
  assert.doesNotMatch(ds('counters').textContent, /every renderer holds this set/);
  refusedProcesses = 0;
  await context.testConsole.documentStart.refresh(true); await settle();

  // Reads are non-draining and cursor-based: no record is replayed or lost.
  await context.testConsole.documentStart.refresh(true); await settle();
  assert.equal(rows().length, 2, 'a repeated read must not duplicate records');
  assert.equal(reads.at(-1), '/api/native-console/document-start?after_sequence=2');

  // A failed read preserves the last understandable state.
  readFails = true;
  await context.testConsole.documentStart.refresh(true); await settle();
  assert.match(ds('notice').textContent, /not retried/);
  assert.match(ds('state').textContent, /state unavailable/);
  assert.match(ds('armed').textContent, /http:\/\/127\.0\.0\.1:8080/, 'the armed set is preserved');
  assert.equal(rows().length, 2);
  readFails = false;

  // A malformed record is refused without discarding the previous state.
  malformed = true;
  await context.testConsole.documentStart.refresh(true); await settle();
  assert.match(ds('notice').dataset.kind, /error/);
  assert.equal(rows().length, 2, 'a malformed page must not be rendered');
  malformed = false;
  await context.testConsole.documentStart.refresh(true); await settle();

  // A browser-side refusal keeps the armed set and re-renders no record.
  armRefused = true;
  ds('origin').value = 'https://refused.test';
  ds('source').value = "report('x');";
  await ds('source').emit('input');
  ds('consent').checked = true; await ds('consent').emit('change');
  await ds('arm').click(); await settle();
  assert.match(ds('notice').textContent, /Synthetic browser refused/);
  assert.match(get('output').textContent, /previously armed set is unchanged/);
  assert.match(ds('armed').textContent, /http:\/\/127\.0\.0\.1:8080/, 'a refusal preserves the armed rule');
  assert.equal(rows().length, 2, 'a refusal must not re-render retained records');
  armRefused = false;

  // The badge is a keyboard-reachable route into the experiment settings.
  await ds('badge').click();
  assert.equal(get('connection').open, true);
  assert.equal(get('ds').open, true);
  assert.equal(document.activeElement, ds('origin'));

  // Clearing removes the set and its output and says what is not rolled back.
  await ds('clear').click(); await settle();
  assert.equal(calls.at(-1).action, 'clear_document_start');
  assert.equal(ds('armed').children.length, 0);
  assert.equal(ds('badge').dataset.state, 'ready');
  assert.match(ds('notice').textContent, /retained report function is inert/);
  assert.match(get('output').textContent, /not rolled back/);

  // Disconnecting forgets the experiment view without arming anything.
  await get('stop').click(); await settle();
  await context.testConsole.documentStart.refresh(true); await settle();
  assert.equal(ds('badge').hidden, true);
  assert.equal(ds('arm').disabled, true);
  // One accepted arm and one refused arm; a disconnected panel adds neither.
  assert.equal(calls.filter(call => call.action === 'arm_document_start').length, 2);

  // A Disconnect whose clear the browser never confirmed must not read as off:
  // the indicator stays visible and says the scripts may still run.
  await get('start').click(); await settle();
  ds('origin').value = 'http://127.0.0.1:8080'; ds('source').value = "report('x');";
  await ds('source').emit('input');
  ds('consent').checked = true; await ds('consent').emit('change');
  await ds('arm').click(); await settle();
  assert.equal(ds('badge').dataset.state, 'armed');
  stopUnconfirmed = true;
  await get('stop').click(); await settle();
  assert.match(get('notice').textContent, /did not confirm/);
  assert.equal(ds('badge').hidden, false, 'an unconfirmed removal stays visible');
  assert.equal(ds('badge').dataset.state, 'unconfirmed');
  assert.match(ds('badge').getAttribute('aria-label'), /may still run/);
  assert.match(ds('state').textContent, /Restart the capture/);
  assert.equal(ds('arm').disabled, true, 'nothing can be armed through an ended binding');
  // A later Stop that finds no session still cannot turn it into "off".
  await get('stop').click(); await settle();
  assert.equal(ds('badge').dataset.state, 'unconfirmed');
  stopUnconfirmed = false; unconfirmed = false;

  // The shipped example snippet, wrapped exactly as the browser wraps it and
  // driven against a synthetic window. It must observe the definition it was
  // installed before, and report only kinds, lengths and a digest.
  const example = await readFile(join(root, 'tools/fixtures/console-document-start/observe-synthetic-transform.js'), 'utf8');
  assert.ok(new TextEncoder().encode(example).length <= 4096, 'the example snippet fits the per-script limit');
  const reports = [];
  const sandbox = {window: {}, report: value => reports.push(value)};
  runInNewContext(`(function(report){"use strict";\n${example}\n})(report)`, sandbox);
  sandbox.window.syntheticTransform = (text, rounds) => String(text).repeat(rounds);
  const produced = sandbox.window.syntheticTransform('authored-secret', 2);
  assert.equal(produced, 'authored-secretauthored-secret', 'the observer must not change the result');
  assert.deepEqual(reports.slice(0, 2), ['observer=installed', 'defined=function']);
  assert.match(reports[2], /^call=1 args=string:15,number return=string:30 digest=[0-9a-f]{8}$/);
  assert.ok(reports.every(entry => !String(entry).includes('authored-secret')),
    'the example snippet must never log a raw observed value');

  console.log('PASS Console document-start panel: disabled control, launch-time permission, a live capture permission shown before connecting, explicit consent, exact rule, inert page-JavaScript output, non-draining cursor, preserved state on failure, a cleared set, an unconfirmed removal that never reads as off, and an example snippet that logs no observed value');
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  await checkNativeConsoleDocumentStart(new URL('..', import.meta.url).pathname);
}
