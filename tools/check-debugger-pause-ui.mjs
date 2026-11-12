// The paused-state sidebar sections against protocol/native-debugger-pause-v1.md:
// the production debugger_pause.js module with only DOM leaves and fetch
// faked. It checks what a researcher sees and what the controls send, that a
// value from a page reaches the DOM as text, and that a new lease drops every
// value read under the previous one.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
import {fakeDocument} from './check-command-palette.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const read = path => readFile(join(root, path), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));
const source = await read('apps/research-ui/debugger_pause.js');

function load(fetch) {
  const {document, create, fire} = fakeDocument();
  const context = {document, globalThis: undefined, fetch, AbortSignal: {timeout: () => null},
    console: {error() {}}};
  context.globalThis = context;
  runInNewContext(source, context);
  const panel = context.RebDebuggerPause.create({fetch});
  return {panel, document, create, fire, context};
}

const sectionOf = (panel, id) => panel.sections.find(section => section.id === id);
const texts = node => node.all.slice(1).filter(child => child.className?.includes?.('debugger-pause-value'))
  .map(child => child.textContent);
const buttons = node => node.all.slice(1).filter(child => child.tagName === 'BUTTON');
const buttonNamed = (node, text) => buttons(node).find(button => button.textContent.includes(text));

const DOCUMENT = Object.freeze({target_id: '22', frame: 'top'});
const FRAME = Object.freeze({
  index: 0, function_name: 'collect', script_id: 11, line: 7, column: 4, this_object_id: null,
  scopes: [{type: 'local', name: 'collect', object_id: '2'}, {type: 'global', object_id: '1'}]
});

function paused(overrides = {}) {
  return {
    contract_version: 1, availability: 'available', reason: null, policy: 'approved', detectable: true,
    lease_limit_ms: 60000, active_indication: 'Debugger active (detectable)',
    quiet_mode: true, document: DOCUMENT, last_clear: null, exceptions: 'uncaught',
    breakpoints: [{breakpoint_id: '1', kind: 'conditional', resolved: true, hits: 1, script_id: 11,
      line: 7, column: 4, condition_set: true, logpoint: false}],
    lease: {lease_id: '4', state: 'active', expires_in_ms: 58000},
    paused: true,
    pause: {reason: 'breakpoint', breakpoint_id: '1', lease_id: '4', frames_recorded: 2, async_frames: 0,
      frames_truncated: false, frames: [FRAME, {...FRAME, index: 1, function_name: '', line: 11}]},
    ...overrides
  };
}

// Unsupported says so plainly; it is never an idle debugger with no breakpoints.
{
  const {panel} = load(async () => { throw new Error('no request is sent'); });
  const {create} = load(async () => { throw new Error('unused'); });
  for (const [reason, text] of [['browser_debugger_unsupported', 'No browser serves'],
    ['peer_unavailable', 'did not answer']]) {
    const body = create('div', 'body');
    sectionOf(panel, 'pause').render(body, {status: 'ready', document: {contract_version: 1, availability: 'unsupported',
      reason, active_indication: null, document: null, paused: false, pause: null, breakpoints: []}});
    assert(body.textContent.includes(text), reason);
    assert(!body.textContent.includes('Debugger active'), reason);
  }
  const stack = create('div', 'stack');
  sectionOf(panel, 'call-stack').render(stack, {status: 'ready', document: {availability: 'unsupported', paused: false, pause: null}});
  assert(stack.textContent.includes('not paused'));
}

// A pause names the reason, the document, quiet mode and the lease, and says
// the page can tell. The step controls send exactly one command each.
{
  const sent = [];
  const {panel, create} = load(async (url, options) => {
    sent.push([url, JSON.parse(options.body)]);
    return {ok: true, status: 200, json: async () => ({action: JSON.parse(options.body).action, status: 'ok',
      paused: false, resumed: true, lease: null, pause: null, breakpoint: null, value: null, properties: null})};
  });
  const body = create('div', 'body');
  const view = {status: 'ready', document: paused()};
  sectionOf(panel, 'pause').render(body, view);
  assert(body.textContent.includes('Debugger active (detectable)'));
  assert(body.textContent.includes('target 22, the top frame'));
  assert(body.textContent.includes('ignored (quiet mode)'));
  assert(body.textContent.includes('active, 58 s left'));
  assert(body.textContent.includes('paused at a breakpoint'));
  for (const [label, action] of [['Resume', 'resume'], ['Step over', 'step_over'], ['Step into', 'step_into'],
    ['Step out', 'step_out'], ['Release lease', 'release_lease']]) {
    const button = buttonNamed(body, label);
    assert(button && !button.disabled, label);
    sent.length = 0;
    button.listeners.click[0]();
    await settle();
    assert.equal(sent.length, 1, label);
    assert.equal(sent[0][0], '/api/native-debugger/actions');
    assert.deepEqual(sent[0][1], {action, target_id: '22', lease_id: '4'});
  }
  assert(buttonNamed(body, 'Pause').disabled, 'Pause is for a page that is running');
}

// Running: every stepping control is disabled and nothing can be sent.
{
  const {panel, create} = load(async () => { throw new Error('no request is sent while running'); });
  const body = create('div', 'body');
  const running = paused({paused: false, pause: null, lease: {lease_id: '4', state: 'released', expires_in_ms: 0}});
  sectionOf(panel, 'pause').render(body, {status: 'ready', document: running});
  assert(body.textContent.includes('released; the page is running'));
  for (const label of ['Resume', 'Step over', 'Step into', 'Step out', 'Release lease']) {
    assert(buttonNamed(body, label).disabled, label);
  }
  assert(!buttonNamed(body, 'Pause').disabled);
  const expired = paused({paused: false, pause: null, lease: {lease_id: '4', state: 'expired', expires_in_ms: 0}});
  const second = create('div', 'second');
  sectionOf(panel, 'pause').render(second, {status: 'ready', document: expired});
  assert(second.textContent.includes('expired; the browser resumed the page'));
}

// The call stack is every recorded frame, innermost first, and says when the
// stack was deeper than the bound.
{
  const {panel, create} = load(async () => { throw new Error('unused'); });
  const body = create('div', 'body');
  const deep = paused();
  deep.pause.frames_recorded = 1024;
  deep.pause.async_frames = 32;
  deep.pause.frames_truncated = true;
  sectionOf(panel, 'call-stack').render(body, {status: 'ready', document: deep});
  const frames = body.all.slice(1).filter(node => node.className === 'debugger-pause-frame');
  assert.equal(frames.length, 2);
  assert.equal(buttonNamed(body, 'Show all'), undefined, 'a short stack needs no control');
  assert(frames[0].textContent.includes('collect · script 11 line 7:4'));
  assert(frames[1].textContent.includes('(anonymous)'));
  assert(body.textContent.includes('1024 recorded'));
  assert(body.textContent.includes('32 async'));
  assert(body.textContent.includes('deeper than the 1,024 frame bound'));

  // Only the rows a reader can use are mounted until they ask for the rest.
  const long = paused();
  long.pause.frames = Array.from({length: 200}, (value, index) => ({...FRAME, index}));
  long.pause.frames_recorded = 200;
  const wide = create('div', 'wide');
  const section = sectionOf(panel, 'call-stack');
  section.render(wide, {status: 'ready', document: long});
  assert.equal(wide.all.slice(1).filter(node => node.className === 'debugger-pause-frame').length, 64);
  buttonNamed(wide, 'Show all 200 frames').listeners.click[0]();
  section.render(wide, {status: 'ready', document: long});
  assert.equal(wide.all.slice(1).filter(node => node.className === 'debugger-pause-frame').length, 200);
}

// A scope is read only when it is opened, in pages, and a value that looks
// like markup is still only text.
{
  const sent = [];
  const pages = [
    {object_id: '2', offset: 0, next_offset: '1', total: 2,
      items: [{name: 'item', kind: 'number', text: '2', truncated: false, object_id: null}]},
    {object_id: '2', offset: 1, next_offset: null, total: 2,
      items: [{name: 'title', kind: 'string', text: '"<img src=x onerror=alert(1)>"', truncated: true, object_id: null}]}
  ];
  const {panel, create} = load(async (url, options) => {
    const body = JSON.parse(options.body);
    sent.push(body);
    return {ok: true, status: 200, json: async () => ({action: body.action, status: 'ok', paused: true,
      resumed: false, lease: null, pause: null, breakpoint: null, value: null, properties: pages[sent.length - 1]})};
  });
  const view = {status: 'ready', document: paused()};
  const body = create('div', 'body');
  const scope = sectionOf(panel, 'scope');
  scope.render(body, view);
  assert.equal(sent.length, 0, 'a closed scope reads nothing');
  buttonNamed(body, 'local').listeners.click[0]();
  await settle();
  assert.deepEqual(sent[0], {action: 'get_properties', target_id: '22',
    lease_id: '4', object_id: '2', offset: 0});
  // The section painted itself again when the read landed, with no second
  // render from the sidebar and without losing the scope just opened.
  assert(body.textContent.includes('item'), 'the opened scope shows at once');
  buttonNamed(body, 'Show more of 2').listeners.click[0]();
  await settle();
  assert.equal(sent[1].offset, 1);
  const markup = body.all.slice(1).find(node => node.className === 'debugger-pause-value' &&
    node.textContent.includes('onerror'));
  assert.equal(markup.children.length, 0, 'a captured value is a text node, never parsed markup');
  assert(markup.textContent.endsWith('(cut)'), 'a cut value says so');

  // A new lease is a new pause: nothing read under the old one survives.
  const next = paused();
  next.lease = {lease_id: '5', state: 'active', expires_in_ms: 60000};
  scope.render(body, {status: 'ready', document: next});
  assert(!body.textContent.includes('onerror'), 'values do not cross a pause');
}

// A watch is evaluated on the innermost frame, an exception is shown as one,
// and nothing is read while the page runs.
{
  const replies = [
    {kind: 'number', text: '3', truncated: false, object_id: null, threw: false},
    {kind: 'error', text: 'nope is not defined', truncated: false, object_id: null, threw: true}
  ];
  const sent = [];
  const {panel, create} = load(async (url, options) => {
    const body = JSON.parse(options.body);
    sent.push(body);
    return {ok: true, status: 200, json: async () => ({action: body.action,
      status: replies[sent.length - 1].threw ? 'evaluation_error' : 'ok', paused: true, resumed: false,
      lease: null, pause: null, breakpoint: null, value: replies[sent.length - 1], properties: null})};
  });
  const view = {status: 'ready', document: paused()};
  const body = create('div', 'body');
  const watch = sectionOf(panel, 'watch');
  watch.render(body, view);
  const fieldOf = () => body.all.slice(1).find(node => node.className === 'debugger-pause-watch-input');
  fieldOf().value = 'total + item';
  buttonNamed(body, 'Watch').listeners.click[0]();
  await settle();
  assert.deepEqual(sent[0], {action: 'evaluate_on_frame', target_id: '22',
    lease_id: '4', call_frame_index: 0, expression: 'total + item'});
  assert(texts(body).includes('3'), 'the result shows without another sidebar render');
  fieldOf().value = 'nope';
  buttonNamed(body, 'Watch').listeners.click[0]();
  await settle();
  const threw = body.all.slice(1).find(node => node.className === 'debugger-pause-threw');
  assert(threw && threw.textContent.includes('not defined'));
  assert.equal(panel.state.watches.length, 2);

  const running = paused({paused: false, pause: null, lease: {lease_id: '4', state: 'released', expires_in_ms: 0}});
  watch.render(body, {status: 'ready', document: running});
  assert(body.textContent.includes('the page is running'));
  for (const button of buttons(body).filter(node => node.textContent === 'Read')) {
    assert(button.disabled, 'a watch cannot be read while the page runs');
  }
}

// A refusal from the backend is shown, and nothing is retried.
{
  const {panel, create} = load(async () => ({ok: false, status: 503,
    json: async () => ({error: 'No Brave build serves the native debugger.', code: 'dependency_unavailable'})}));
  const body = create('div', 'body');
  const view = {status: 'ready', document: paused()};
  const section = sectionOf(panel, 'pause');
  section.render(body, view);
  buttonNamed(body, 'Resume').listeners.click[0]();
  await settle();
  section.render(body, view);
  assert(body.textContent.includes('No Brave build serves the native debugger.'));
}

// A status the command did not expect is reported as a refusal that changed
// nothing, not as a success.
{
  const {panel, create} = load(async (url, options) => ({ok: true, status: 200,
    json: async () => ({action: JSON.parse(options.body).action, status: 'stale_lease', paused: true,
      resumed: false, lease: null, pause: null, breakpoint: null, value: null, properties: null})}));
  const body = create('div', 'body');
  const view = {status: 'ready', document: paused()};
  const section = sectionOf(panel, 'pause');
  section.render(body, view);
  buttonNamed(body, 'Step over').listeners.click[0]();
  await settle();
  section.render(body, view);
  assert(body.textContent.includes('step_over: stale lease; nothing else changed'));
}

// Breakpoints of every kind are listed with what they match, and a logpoint
// says it never pauses.
{
  const sent = [];
  const {panel, create} = load(async (url, options) => {
    sent.push(JSON.parse(options.body));
    return {ok: true, status: 200, json: async () => ({action: 'remove_breakpoint', status: 'ok',
      paused: true, resumed: false, lease: null, pause: null, breakpoint: null, value: null, properties: null})};
  });
  const answer = paused();
  answer.breakpoints = [
    {breakpoint_id: '1', kind: 'logpoint', resolved: true, hits: 0, script_id: 11, line: 7, column: 4,
      condition_set: false, logpoint: true},
    {breakpoint_id: '2', kind: 'conditional', resolved: true, hits: 3, script_id: 11, line: 9, column: 2,
      condition_set: true, logpoint: false},
    {breakpoint_id: '3', kind: 'line', resolved: false, hits: 1, script_id: 12, line: 2, column: 0,
      condition_set: false, logpoint: false}
  ];
  const body = create('div', 'body');
  sectionOf(panel, 'breakpoints').render(body, {status: 'ready', document: answer});
  assert(body.textContent.includes('Logpoint · script 11 line 7:4'));
  assert(body.textContent.includes('never pauses'));
  assert(body.textContent.includes('Conditional · script 11 line 9:2'));
  assert(body.textContent.includes('Line · script 12 line 2:0'));
  assert(body.textContent.includes('0 hits'));
  assert(body.textContent.includes('not bound yet'));
  assert(body.textContent.includes('3 hits'));
  assert(body.textContent.includes('1 hit'));
  buttons(body).find(button => button.textContent === 'Remove').listeners.click[0]();
  await settle();
  assert.deepEqual(sent[0], {action: 'remove_breakpoint', target_id: '22',
    breakpoint_id: '1'});
  const empty = create('div', 'empty');
  sectionOf(panel, 'breakpoints').render(empty, {status: 'ready', document: paused({breakpoints: []})});
  assert(empty.textContent.includes('No breakpoint is set'));
}

// Without an authorized document nothing can be sent at all.
{
  const {panel, create} = load(async () => { throw new Error('no request is sent'); });
  const body = create('div', 'body');
  sectionOf(panel, 'pause').render(body, {status: 'ready', document: paused({document: null, active_indication: null,
    paused: false, pause: null, last_clear: 'navigated', lease: null})});
  assert(body.textContent.includes('Debugger attached to no document'));
  assert(body.textContent.includes('cleared: navigated'));
  for (const button of buttons(body)) assert(button.disabled, button.textContent);
}

// The active indication the state carries is what the interface shows, so a
// client reading HTTP or MCP sees the same words.
{
  const {panel, create} = load(async () => { throw new Error('unused'); });
  const body = create('div', 'body');
  sectionOf(panel, 'pause').render(body, {status: 'ready', document: paused({
    active_indication: 'Debugger active (detectable)',
    document: {target_id: '23', frame: 'child'}})});
  assert(body.textContent.includes('Debugger active (detectable)'));
  assert(body.textContent.includes('target 23, a same-process iframe'));
}

// The registry is the only way these sections exist, and the five are the
// ones this contract adds.
{
  const added = [];
  const registry = {addSection(section) { added.push(section); return () => {}; }};
  const {context} = load(async () => { throw new Error('unused'); });
  context.RebDebuggerPause.register(registry);
  assert.deepEqual(added.map(section => section.id), ['pause', 'breakpoints', 'call-stack', 'scope', 'watch']);
  assert.deepEqual(added.map(section => section.order), [50, 51, 52, 53, 54]);
  assert.equal(context.RebDebuggerPause.register({}), null, 'no registry, no sections');
}

// The sidebar's contract for a later section: every one of these is a
// pausing section, and the real registry refuses anything else.
{
  const added = [];
  const registry = {addSection(section) { added.push(section); return () => {}; }};
  const {context} = load(async () => { throw new Error('unused'); });
  context.RebDebuggerPause.register(registry);
  for (const section of added) {
    assert.equal(section.native, 'pausing', section.id);
    assert(section.order >= 50, section.id);
    assert(typeof section.render === 'function' && typeof section.release === 'function', section.id);
  }
  assert(!added.some(section => section.id === 'pausing'), 'pausing is the sidebar\'s own id');
}

// Nothing is operable unless the last read is good and a browser serves the
// debugger: every control is a form control with disabled set, which is what
// the sidebar's guard checks. No control is a link, a summary or anything
// else that cannot be disabled.
{
  const {panel, create} = load(async () => { throw new Error('nothing is sent while frozen'); });
  const frozen = [
    ['loading', null],
    ['disconnected', null],
    ['malformed', null],
    ['unavailable', null],
    ['ready', {...paused(), availability: 'unsupported', reason: 'browser_debugger_unsupported'}],
    ['loading', paused()],
    ['disconnected', paused()]
  ];
  for (const [status, document_] of frozen) {
    for (const id of ['pause', 'breakpoints', 'call-stack', 'scope', 'watch']) {
      const body = create('div', `${id}-${status}`);
      sectionOf(panel, id).render(body, {status, document: document_});
      const operable = body.all.slice(1).filter(node => ['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA'].includes(node.tagName));
      for (const node of operable) assert(node.disabled === true, `${id} ${status} ${node.textContent}`);
      const unreachable = body.all.slice(1).filter(node => ['A', 'SUMMARY', 'DETAILS'].includes(node.tagName) ||
        node.getAttribute?.('tabindex') !== null && node.getAttribute?.('tabindex') !== undefined ||
        node.getAttribute?.('role') !== null && node.getAttribute?.('role') !== undefined ||
        node.getAttribute?.('contenteditable') !== null && node.getAttribute?.('contenteditable') !== undefined);
      assert.equal(unreachable.length, 0, `${id} ${status} draws only controls that can be disabled`);
      if (!document_) {
        assert(body.textContent.length > 0, `${id} ${status} says why it has nothing`);
        assert(!body.textContent.includes('No breakpoint is set'), `${id} ${status} claims nothing about a document it has not read`);
      }
    }
  }
  // The Watch expression field is a control too.
  const watch = create('div', 'watch-frozen');
  sectionOf(panel, 'watch').render(watch, {status: 'ready',
    document: {...paused(), availability: 'unsupported', reason: 'peer_unavailable'}});
  const field = watch.all.slice(1).find(node => node.tagName === 'INPUT');
  assert(field && field.disabled === true, 'the watch expression field is disabled');
}

// The shipped asset lists name the module, and app.js loads nothing of its own.
{
  const html = await read('apps/research-ui/index.html');
  assert(html.includes('debugger_pause.js'), 'index.html serves the module');
  const assets = await read('apps/origin-trace-backend/src/app.rs');
  assert(assets.includes('"debugger_pause.js"'), 'UI_ASSETS serves the module');
}

console.log('PASS debugger pause UI: sections, controls, bounded text values and refusals');
