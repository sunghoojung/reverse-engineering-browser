#!/usr/bin/env node
// Deterministic controller/DOM checks use authored synthetic responses. The
// separately exported rendered flow requires the actual backend/native helper.
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFile, writeFile, mkdtemp, mkdir, rm} from 'node:fs/promises';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
import debuggerUI from '../apps/research-ui/vm_debugger.js';
import {platformEditEvent, selectRenderedOption} from './rendered-keyboard.mjs';

// Match the integrated browser driver's native CDP event contract. In
// particular, macOS select type-ahead requires a character-producing keyDown;
// rawKeyDown deliberately omits the text/keypress phase even if text is supplied.
export function ownedVmRenderedKeyEvents(key, code = key, native = {}, platform = process.platform) {
  return [platformEditEvent({type: native.text ? 'keyDown' : 'rawKeyDown', key, code, ...native}, platform),
    {type: 'keyUp', key, code, windowsVirtualKeyCode: native.windowsVirtualKeyCode}];
}

const copy = value => JSON.parse(JSON.stringify(value));
const unknown = () => ({bits: '0', evidence: 'unknown'});
const observed = bits => ({bits, evidence: 'observed'});
const initial = fixture => ({pc: '0', pc_evidence: 'observed', partial: false, halted: false,
  registers: fixture === 'register' ? [unknown(), unknown(), unknown()] : [], stack: [], memory: []});
function session(fixture = 'register', count = 0, state = 'paused') {
  const first = initial(fixture), records = []; let current = copy(first);
  for (let index = 0; index < count; index++) {
    const before = copy(current), bits = index === 0 ? '7' : '5'; current.pc = String(index + 1);
    if (fixture === 'register') current.registers[index] = observed(bits); else current.stack.push(observed(bits));
    records.push({sequence: String(index + 1), tick: String(index + 3), opcode: 1, opcode_evidence: 'observed', partial: false,
      operands: [{location: 'immediate', index: '0', value: observed(bits)}],
      effects: [{access: 'write', location: fixture === 'register' ? 'register' : 'stack', index: String(index), value: observed(bits)}], before, after: copy(current)});
  }
  return {backend_instance_id: 'instance', session_id: 'session', run_id: 'run', run_generation: '1', provider: 'live-owned-native-fixture',
    target_kind: 'owned_fixture', fixture, program_id: `owned-${fixture}-v1`, fixture_revision: 1, program_sha256: 'a'.repeat(64),
    program_manifest_scope: 'declared-two-program-manifest-sha256', build_id: 'b'.repeat(64), build_id_scope: 'configured-helper-file-sha256',
    pc_units: 'instruction-index', value_semantics: 'unsigned-64-bit-bits', tick_units: 'monotonic-nanoseconds', state,
    control_revision: String(count + 1), snapshot_revision: String(count + 1), executed_count: String(count), retained_count: String(count),
    execution_state_known: true, termination_reason: null, initial_snapshot: first, current_snapshot: current, records,
    recorder: {session_id: '1', document_id: '2', invocation_id: '3', generation: '1',
      stats: {attempted: String(count), recorded: String(count), full: '0', malformed: '0', wrong_document: '0', stale_generation: '0', exhausted: '0', expired: '0', partial: '0'}},
    last_command: null, diagnostics: {stderr_bytes: '0', stderr_truncated: false}, disposal_failed: false};
}
const envelope = (state = null) => ({schema: 'reb-owned-vm-debug-session-v1', available: true, unavailable_reason: null, backend_instance_id: 'instance', session: state});
const ack = (value, command, status = 'completed') => ({...copy(value), command_id: command.command_id, ack: status});
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; };
function timers() {
  let now = 0, next = 0; const entries = new Map();
  return {setTimeout(callback, delay) { const id = ++next; entries.set(id, {callback, at: now + delay}); return id; },
    clearTimeout(id) { entries.delete(id); },
    async advance(ms) { const target = now + ms;
      for (;;) { const due = [...entries].filter(([, item]) => item.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break; now = due[1].at; entries.delete(due[0]); due[1].callback(); await flush(); }
      now = target; await flush(); }, size: () => entries.size};
}
function harness(start = envelope()) {
  let current = copy(start), post = async request => ack(current, request), get = async () => copy(current), sequence = 0;
  const log = [], clock = timers(), modelChanges = [], controller = debuggerUI.createOwnedVmController({
    ...clock, commandId: () => `command-${++sequence}`, onChange: value => modelChanges.push(value),
    request: async (path, options) => { log.push({path, ...options}); return options.method === 'POST' ? post(JSON.parse(options.body)) : get(path, options); },
  });
  return {controller, log, clock, modelChanges, set(value) { current = copy(value); }, setPost(handler) { post = handler; }, setGet(handler) { get = handler; }};
}

export async function checkOwnedVmDebuggerController() {
  const api = debuggerUI;
  const letter = ownedVmRenderedKeyEvents('S', 'KeyS', {text: 'S', unmodifiedText: 'S', windowsVirtualKeyCode: 83}, 'darwin');
  assert.deepEqual(letter, [{type: 'keyDown', key: 'S', code: 'KeyS', text: 'S', unmodifiedText: 'S', windowsVirtualKeyCode: 83}, {type: 'keyUp', key: 'S', code: 'KeyS', windowsVirtualKeyCode: 83}], 'macOS native Stack select type-ahead must produce text');
  assert.equal(ownedVmRenderedKeyEvents('ArrowDown', 'ArrowDown', {windowsVirtualKeyCode: 40}, 'darwin')[0].type, 'rawKeyDown');
  assert.equal(ownedVmRenderedKeyEvents('Enter', 'Enter', {text: '\r', windowsVirtualKeyCode: 13}, 'darwin')[0].type, 'keyDown');
  assert.deepEqual(ownedVmRenderedKeyEvents('a', 'KeyA', {modifiers: 4}, 'darwin')[0].commands, ['selectAll']);
  for (const fixture of ['register', 'stack']) for (const count of [0, 1, 2]) assert.equal(api.ownedVmValidateView(envelope(session(fixture, count))).session.executed_count, String(count));
  for (const value of ['0', '9007199254740993', '18446744073709551615']) assert(api.ownedVmU64(value));
  for (const value of [0, -1, '01', '-0', '1.0', '1e3', '18446744073709551616', '']) assert(!api.ownedVmU64(value));
  const max = copy(envelope(session('register', 1)));
  max.session.current_snapshot.registers[0] = observed('18446744073709551615');
  max.session.current_snapshot.memory = [{guest_address: '18446744073709551615', value: observed('0')}];
  max.session.recorder.stats.full = '18446744073709551615';
  assert(api.ownedVmValidateView(api.ownedVmParseJSON(JSON.stringify(max))));
  assert.equal(api.ownedVmFormatValue(observed('18446744073709551615')), '18446744073709551615 (0xffffffffffffffff; observed)');
  assert.equal(api.ownedVmFormatValue(unknown()), 'unknown'); assert.equal(api.ownedVmFormatValue(null), 'absent');
  assert.equal(api.ownedVmFormatValue(observed('0')), '0 (0x0; observed)');
  assert.equal(api.ownedVmFormatValue({bits: '9', evidence: 'inferred'}), '9 (0x9; inferred)');
  for (const source of ['{"a":1,"a":2}', '{"a":1.0}', '{"a":1e3}', '{"a":9007199254740993}', '[1,]', '{"a":true}x', '[[['.repeat(33), ' '.repeat(1048577)]) assert.throws(() => api.ownedVmParseJSON(source));
  for (const mutate of [v => v.extra = 0, v => v.session.program_sha256 = ['a'.repeat(64)], v => v.session.run_generation = '01', v => v.session.current_snapshot.registers[0].bits = 7,
    v => v.session.current_snapshot.registers[0] = {bits: '7', evidence: 'unknown'}, v => v.session.current_snapshot.extra = true,
    v => v.session.current_snapshot.memory = [{guest_address: '1', value: unknown()}, {guest_address: '1', value: unknown()}],
    v => v.session.records[0].effects[0].access = 'execute', v => v.session.records[0].operands[0].location = 'pointer',
    v => v.session.records[0].before.registers = Array(9).fill(unknown()), v => v.session.retained_count = '0',
    v => v.session.records[0].sequence = '0', v => v.session.diagnostics.stderr_bytes = 0,
    v => v.session.records[0].operands = Array(5).fill(v.session.records[0].operands[0])]) {
    const bad = envelope(session('register', 1)); mutate(bad); assert.throws(() => api.ownedVmValidateView(bad));
  }
  const paused = envelope(session('register', 1));
  assert.deepEqual(api.ownedVmBuildAction(paused, 'step', 'c'), {action: 'step', command_id: 'c', backend_instance_id: 'instance', session_id: 'session', run_id: 'run', run_generation: '1', expected_control_revision: '2', expected_executed_count: '1'});
  for (const action of ['pause', 'stop', 'reset', 'close']) {
    const result = api.ownedVmBuildAction(paused, action, 'c'); assert.equal(result.expected_control_revision, undefined); assert.equal(result.expected_executed_count, undefined);
  }
  assert.equal(api.ownedVmBuildAction(paused, 'run', 'c').expected_control_revision, '2');
  assert.deepEqual(api.ownedVmBuildAction(envelope(), 'create', 'c', 'stack'), {action: 'create', command_id: 'c', fixture: 'stack'});
  const annotation = {code: 'command_outcome_unknown', details: {phase: 'command_exchange', cause: 'disconnected'}};
  assert(api.ownedVmValidateView({...ack(paused, {command_id: 'c'}, 'outcome_unknown'), ...annotation}));
  assert.throws(() => api.ownedVmValidateView({...ack(paused, {command_id: 'c'}), ...annotation}));
  assert.throws(() => api.ownedVmValidateView({...ack(paused, {command_id: 'c'}, 'outcome_unknown'), ...annotation, details: {phase: 'command_exchange', cause: 'disconnected', extra: true}}));

  const h = harness(); await h.controller.refresh(); await h.clock.advance(999);
  assert.equal(h.log.length, 4, 'Only four bounded GETs across the first second'); assert(h.log.every(row => row.method === 'GET'));
  h.controller.setVisible(false); const hiddenReads = h.log.length; await h.clock.advance(2000); assert.equal(h.log.length, hiddenReads);
  h.controller.setVisible(true); await flush(); assert.equal(h.log.length, hiddenReads + 1);
  const created = envelope(session()); h.setPost(async command => { h.set(created); return ack(created, command); });
  assert(await h.controller.action('create', 'register')); await flush();
  assert.equal(h.controller.model().view.session.executed_count, '0'); assert.equal(h.controller.model().view.session.records.length, 0);
  const beforePause = h.log.filter(row => row.method === 'POST').length; await h.clock.advance(1000); assert.equal(h.log.filter(row => row.method === 'POST').length, beforePause, 'No implicit run or step');
  const block = deferred(); let sent;
  h.setPost(command => { sent = command; return block.promise; }); const step = h.controller.action('step'); await flush();
  assert(!h.controller.model().allowed.step); assert(h.controller.model().allowed.pause); assert(h.controller.model().allowed.stop);
  assert.equal(await h.controller.action('step'), false, 'Duplicate step stays disabled');
  const stepped = envelope(session('register', 1)); stepped.session.last_command = {action: 'step', command_id: sent.command_id, ack: 'completed'};
  h.set(stepped); block.resolve(ack(stepped, sent)); assert(await step); await flush(); assert.equal(h.controller.model().view.session.executed_count, '1');
  assert.equal(sent.expected_executed_count, '0'); assert.equal(sent.run_id, 'run');
  h.controller.destroy(); await h.clock.advance(5000); assert.equal(h.clock.size(), 0);

  // A pre-command read must never put an old run back after Reset.
  const late = harness(paused); await late.controller.refresh(); const stale = deferred(); late.setGet(() => stale.promise);
  const pendingRead = late.controller.refresh(), replacement = envelope(session()); replacement.session.run_id = 'new-run'; replacement.session.run_generation = '2';
  late.setPost(async command => ack(replacement, command)); assert(await late.controller.action('reset')); stale.resolve(copy(paused)); await pendingRead;
  assert.equal(late.controller.model().view.session.run_id, 'new-run'); late.controller.destroy();

  // Only one poll can be outstanding, and a lower revision cannot regress state.
  const single = harness(paused); await single.controller.refresh(); const slow = deferred(); single.setGet(() => slow.promise);
  const held = single.controller.refresh(); single.controller.refresh(); single.controller.refresh(); await single.clock.advance(1500);
  assert.equal(single.log.length, 2); slow.resolve(envelope(session())); await held; assert.equal(single.controller.model().view.session.executed_count, '1'); single.controller.destroy();

  const unknownResult = harness(paused); await unknownResult.controller.refresh(); unknownResult.setPost(async () => { throw new Error('connection lost'); });
  assert.equal(await unknownResult.controller.action('step'), false); await flush(); assert(unknownResult.controller.model().uncertain);
  assert(!unknownResult.controller.model().allowed.step); assert(unknownResult.controller.model().allowed.stop); assert(unknownResult.controller.model().allowed.reset);
  const postCount = unknownResult.log.filter(row => row.method === 'POST').length; await unknownResult.clock.advance(1000);
  assert.equal(unknownResult.log.filter(row => row.method === 'POST').length, postCount, 'Lost acknowledgment never retries');
  assert.match(unknownResult.controller.model().notice, /cancellation is not rollback/);
  const reconcile = envelope(session('register', 2)); reconcile.session.last_command = {action: 'step', command_id: 'command-1', ack: 'completed'};
  unknownResult.set(reconcile); await unknownResult.controller.refresh(); assert.equal(unknownResult.controller.model().uncertain, null); assert(unknownResult.controller.model().allowed.step); unknownResult.controller.destroy();

  const uncertainState = envelope(session('register', 1, 'failed')); uncertainState.session.execution_state_known = false;
  uncertainState.session.termination_reason = 'outcome_unknown'; const failed = harness(uncertainState); await failed.controller.refresh();
  assert(!failed.controller.model().allowed.run); assert.match(failed.controller.model().notice, /last confirmed/); failed.controller.destroy();
  const expiry = harness(envelope(session('register', 1, 'expired'))); await expiry.controller.refresh(); assert(!expiry.controller.model().allowed.run); assert.match(expiry.controller.model().notice, /60-second/); expiry.controller.destroy();
  const disposal = envelope(session('register', 1, 'failed')); disposal.session.disposal_failed = true;
  const blocked = harness(disposal); await blocked.controller.refresh(); assert(!blocked.controller.model().allowed.reset); blocked.controller.destroy();
  const unavailable = {...envelope(), available: false, unavailable_reason: 'static_demo_has_no_native_helper'};
  const demo = harness(unavailable); await demo.controller.refresh(); assert(!demo.controller.model().allowed.create); assert.equal(await demo.controller.action('create'), false); assert(demo.log.every(row => row.method === 'GET')); demo.controller.destroy();
  const other = harness(paused); await other.controller.refresh(); const restarted = envelope(); restarted.backend_instance_id = 'restarted'; other.set(restarted); await other.controller.refresh();
  assert.equal(other.controller.model().view.session, null); assert(!other.controller.model().allowed.step); other.controller.destroy();
  const startingState = envelope(session('register', 0, 'starting'));
  Object.assign(startingState.session, {build_id: null, initial_snapshot: null, current_snapshot: null, execution_state_known: false, snapshot_revision: '0'});
  const starting = harness(startingState); await starting.controller.refresh(); assert.match(starting.controller.model().notice, /initial snapshot/);
  assert.doesNotMatch(starting.controller.model().notice, /outcome is unknown/); assert(!starting.controller.model().allowed.run); starting.controller.destroy();
  const concurrent = harness(paused); await concurrent.controller.refresh(); const oldStep = deferred(); let oldCommand;
  const stopped = envelope(session('register', 2, 'stopped')); stopped.session.control_revision = '5';
  concurrent.setPost(command => { if (command.action === 'step') { oldCommand = command; return oldStep.promise; } concurrent.set(stopped); return ack(stopped, command); });
  const lateStep = concurrent.controller.action('step'); await flush(); assert(await concurrent.controller.action('stop')); await flush();
  oldStep.resolve(ack(envelope(session('register', 2)), oldCommand)); await lateStep; await flush();
  assert.equal(concurrent.controller.model().view.session.state, 'stopped', 'Late Step acknowledgment cannot undo Stop'); concurrent.controller.destroy();
  const malformed = harness(paused); await malformed.controller.refresh(); malformed.setGet(async () => ({schema: 'wrong'})); await malformed.controller.refresh();
  assert.equal(malformed.controller.model().view.session.executed_count, '1'); assert.match(malformed.controller.model().notice, /Last confirmed/); malformed.controller.destroy();
  const lostCreate = harness(); await lostCreate.controller.refresh(); const freshNull = deferred();
  lostCreate.setPost(async () => { throw Error('response lost'); }); lostCreate.setGet(() => freshNull.promise);
  assert.equal(await lostCreate.controller.action('create'), false); assert(!lostCreate.controller.model().canRecoverCreate, 'Recovery waits for a new confirmed same-backend null-session read');
  assert.equal(await lostCreate.controller.recoverCreate('register'), false);
  freshNull.resolve(envelope()); await flush(); assert(lostCreate.controller.model().canRecoverCreate); assert(!lostCreate.controller.model().allowed.create);
  const originalCommand = lostCreate.controller.model().uncertain.command_id; const beforeRecovery = lostCreate.log.filter(row => row.method === 'POST').length;
  await lostCreate.clock.advance(1000); assert.equal(lostCreate.log.filter(row => row.method === 'POST').length, beforeRecovery, 'Fresh null poll never retries Create');
  lostCreate.setPost(async () => ({error: 'First create may be queued', code: 'state_conflict'}));
  for (let i = 0; i < 2; i++) {
    assert.equal(await lostCreate.controller.recoverCreate('register'), false); await flush(); assert(lostCreate.controller.model().canRecoverCreate);
    assert.equal(lostCreate.controller.model().uncertain.command_id, originalCommand, 'A rejected fresh attempt does not erase earlier ambiguity');
    assert.match(lostCreate.controller.model().notice, /earlier Create may still take effect/);
  }
  const attempts = lostCreate.log.filter(row => row.method === 'POST').map(row => JSON.parse(row.body).command_id); assert.equal(new Set(attempts).size, attempts.length);
  lostCreate.setGet(async () => envelope(session())); await lostCreate.controller.refresh(); assert(!lostCreate.controller.model().canRecoverCreate); assert.equal(lostCreate.controller.model().uncertain, null);
  assert(!lostCreate.controller.model().allowed.create, 'An admitted earlier session is not replaced'); lostCreate.controller.destroy();
  const closeUnknown = harness(paused); await closeUnknown.controller.refresh();
  closeUnknown.setPost(async command => { closeUnknown.set(envelope()); return {...ack(envelope(), command, 'outcome_unknown'), ...annotation}; });
  assert.equal(await closeUnknown.controller.action('close'), false); await flush(); assert.equal(closeUnknown.controller.model().view.session, null); assert(closeUnknown.controller.model().allowed.create); closeUnknown.controller.destroy();
  const hangStatus = (options) => new Promise((_, reject) => {
    const fail = () => {
      const reason = options?.signal?.reason;
      reject(reason instanceof Error ? reason : Object.assign(new Error('The status read timed out.'), {name: 'TimeoutError'}));
    };
    if (options?.signal?.aborted) fail();
    else options?.signal?.addEventListener('abort', fail, {once: true});
  });
  const hung = harness(paused); await hung.controller.refresh();
  const retained = hung.controller.model().view.session.executed_count;
  hung.setGet((_path, options) => hangStatus(options));
  const hungRead = hung.controller.refresh();
  await hung.clock.advance(6000);
  await hungRead;
  assert.equal(hung.controller.model().view.session.executed_count, retained);
  assert.match(hung.controller.model().notice, /Status refresh timed out\. The last confirmed fixture state is still shown\./);
  assert.doesNotMatch(hung.controller.model().notice, /aborted without reason/);
  hung.controller.destroy();
  const cold = harness();
  cold.setGet((_path, options) => hangStatus(options));
  const coldRead = cold.controller.refresh();
  await cold.clock.advance(6000);
  await coldRead;
  assert.equal(cold.controller.model().view, null);
  assert.equal(cold.controller.model().notice, 'The status read timed out.');
  cold.controller.destroy();
  console.log('PASS owned VM strict native codec, full uint64, real-action scopes, inert GET/visibility, pending controls, stale reads, unknown reconciliation, no retries, expiry and capability gating');
}

export async function checkOwnedVmDebuggerDOM() {
  const doc = {activeElement: null, visibilityState: 'visible', handlers: {}, addEventListener(name, fn) { this.handlers[name] = fn; }, removeEventListener(name) { delete this.handlers[name]; }};
  class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.attributes = {}; this.events = {}; this.text = ''; this.ownerDocument = doc; this.classList = {add() {}}; this.value = ''; }
    set textContent(value) { this.text = String(value); this.children = []; } get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
    append(...nodes) { for (const node of nodes) { node.parent = this; this.children.push(node); } }
    prepend(...nodes) { for (const node of nodes) node.parent = this; this.children.unshift(...nodes); }
    contains(node) { return this === node || this.children.some(child => child.contains(node)); }
    replaceChildren(...nodes) { if (this.children.some(child => child.contains(doc.activeElement))) doc.activeElement = doc.body; this.children = []; this.append(...nodes); }
    remove() { if (this.contains(doc.activeElement)) doc.activeElement = doc.body; if (this.parent) this.parent.children = this.parent.children.filter(node => node !== this); }
    set disabled(value) { this.isDisabled = value; if (value && doc.activeElement === this) doc.activeElement = doc.body; } get disabled() { return this.isDisabled; }
    set hidden(value) { this.isHidden = value; if (value && this.contains(doc.activeElement)) doc.activeElement = doc.body; } get hidden() { return this.isHidden; }
    setAttribute(key, value) { this.attributes[key] = String(value); }
    addEventListener(key, fn) { this.events[key] = fn; }
    focus() { doc.activeElement = this; doc.handlers.focusin?.({target: this}); }
  }
  doc.body = new Element('body');
  doc.createElement = tag => new Element(tag);
  const clock = timers(), log = [], source = await readFile(new URL('../apps/research-ui/vm_debugger.js', import.meta.url), 'utf8');
  const api = runInNewContext(`${source};({mountOwnedVmDebugger})`, {document: doc, TextEncoder, AbortController, crypto: webcrypto, ...clock});
  let current = envelope(session()), nextId = 0;
  const root = new Element('section'), ui = api.mountOwnedVmDebugger(root, {commandId: () => `dom-${++nextId}`, request: async (path, options) => {
    log.push({path, ...options}); if (options.method === 'POST') return ack(current, JSON.parse(options.body)); return copy(current);
  }});
  await flush(); assert.equal(ui.history.children.length, 0); assert.match(ui.inspector.textContent, /Initial|Current native snapshot/); assert.match(ui.status.textContent, /executed 0/);
  assert.equal(ui.fixture.disabled, true); ui.buttons.step.focus(); current = envelope(session('register', 1)); await ui.refresh();
  assert.equal(doc.activeElement, ui.buttons.step, 'Polling keeps button focus'); assert.equal(ui.history.children.length, 1);
  ui.history.children[0].children[0].events.click(); assert.match(ui.inspector.textContent, /Retained instruction #1/);
  const row = ui.history.children[0].children[0]; row.focus(); current = envelope(session('register', 2, 'running')); await ui.refresh();
  assert.equal(doc.activeElement, row); assert.match(ui.inspector.textContent, /Retained instruction #1/); assert.match(ui.status.textContent, /executed 2/);
  const posts = log.filter(item => item.method === 'POST').length;
  let prevented = false; row.events.keydown({key: 'ArrowDown', preventDefault() { prevented = true; }});
  assert(prevented); assert.equal(doc.activeElement, ui.history.children[1].children[0]); assert.match(ui.inspector.textContent, /Retained instruction #2/);
  assert.equal(log.filter(item => item.method === 'POST').length, posts, 'History keyboard never executes');
  const menuCapabilities = {}; root.events['vm-workspace-query']({detail: menuCapabilities});
  assert.equal(menuCapabilities.search, true); assert.equal(menuCapabilities.previous, true); assert.equal(menuCapabilities.next, false);
  root.events['vm-workspace-previous'](); assert.match(ui.inspector.textContent, /Retained instruction #1/);
  root.events['vm-workspace-next'](); assert.match(ui.inspector.textContent, /Retained instruction #2/);
  root.events['vm-workspace-next'](); assert.match(ui.inspector.textContent, /Retained instruction #2/);
  root.events['vm-workspace-search'](); assert.equal(doc.activeElement.textContent, 'All retained opcodes');
  assert.equal(log.filter(item => item.method === 'POST').length, posts, 'Workspace menus only inspect retained history and never execute');
  ui.tabs.instruction.events.keydown({key: 'ArrowRight', preventDefault() {}}); assert.equal(doc.activeElement, ui.tabs.registers);
  const tabFocused = doc.activeElement; await ui.refresh(); assert.equal(doc.activeElement, tabFocused);
  ui.follow.events.click(); assert.match(ui.inspector.textContent, /Following live/); ui.initial.events.click(); assert.match(ui.inspector.textContent, /zero completed instructions/);
  current.session.current_snapshot.memory = [{guest_address: '18446744073709551615', value: observed('0')}]; current.session.recorder.stats.full = '18446744073709551615';
  current.session.executed_count = '3'; current.session.snapshot_revision = '4'; current.session.recorder.stats.attempted = '3';
  await ui.refresh(); ui.follow.events.click(); assert.match(ui.inspector.textContent, /18446744073709551615/); assert.match(ui.inspector.textContent, /0x0; observed/);
  assert.match(ui.inspector.textContent, /Loss counters are separate/); assert.match(ui.inspector.textContent, /no retained transition/);
  ui.setVisible(false); assert.equal(ui.panes.hidden, true); assert.notEqual(ui.toolbar.hidden, true); const reads = log.length; await clock.advance(1000); assert.equal(log.length, reads);
  assert(ui.buttons.pause.disabled === false && ui.buttons.stop.disabled === false, 'Quiescing controls remain available when details hidden');
  ui.destroy(); await clock.advance(1000); assert.equal(log.length, reads);
  current = envelope(session()); let pending = deferred(), command;
  const focusUI = api.mountOwnedVmDebugger(new Element('section'), {commandId: () => `focus-${++nextId}`, request: async (path, options) => {
    if (options.method === 'POST') { command = JSON.parse(options.body); return pending.promise; } return copy(current);
  }});
  await flush(); focusUI.buttons.step.focus(); const firstStep = focusUI.buttons.step.events.click(); await flush();
  assert.equal(doc.activeElement, focusUI.refreshButton, 'Focused command transfers before native disabling blurs it'); assert(focusUI.buttons.step.disabled);
  current = envelope(session('register', 1)); pending.resolve(ack(current, command)); await firstStep; await flush();
  assert.equal(doc.activeElement, focusUI.buttons.step, 'Settled Step restores its owned focus without another focus call');
  pending = deferred(); const secondStep = focusUI.buttons.step.events.click(); await flush(); const elsewhere = new Element('input'); elsewhere.focus();
  current = envelope(session('register', 2)); pending.resolve(ack(current, command)); await secondStep; await flush(); assert.equal(doc.activeElement, elsewhere, 'Completion never steals newer user focus');
  focusUI.history.children[0].children[0].events.click(); focusUI.history.children[0].children[0].focus(); current = envelope(); await focusUI.refresh();
  assert.equal(doc.activeElement, focusUI.refreshButton, 'Scope replacement relocates only a focus owner whose row is removed');
  assert.equal(focusUI.controller.model().view.session, null); focusUI.destroy();
  current = envelope(session()); const expiryUI = api.mountOwnedVmDebugger(new Element('section'), {request: async () => copy(current)}); await flush();
  expiryUI.buttons.stop.focus(); current.session.state = 'expired'; current.session.control_revision = '9'; await expiryUI.refresh();
  assert.equal(doc.activeElement, expiryUI.refreshButton, 'A focused control invalidated by expiry relocates before native blur');
  expiryUI.initial.focus(); current = envelope(); await expiryUI.refresh(); assert.equal(doc.activeElement, expiryUI.refreshButton, 'A removed initial snapshot keeps focus reachable'); expiryUI.destroy();
  const recoveryUI = api.mountOwnedVmDebugger(new Element('section'), {commandId: () => `recovery-${++nextId}`, request: async (path, options) => {
    if (options.method === 'POST') throw Error('Create response lost'); return copy(current);
  }});
  await flush(); recoveryUI.buttons.create.focus(); await recoveryUI.buttons.create.events.click(); await flush();
  assert.equal(doc.activeElement, recoveryUI.refreshButton); assert(!recoveryUI.recoverCreate.hidden); recoveryUI.recoverCreate.focus();
  current = envelope(session()); await recoveryUI.refresh(); assert.equal(doc.activeElement, recoveryUI.recoverCreate, 'A disappearing recovery control retains focus inertly until the user leaves it');
  assert.equal(recoveryUI.recoverCreate.attributes['aria-disabled'], 'true'); assert.equal(await recoveryUI.recoverCreate.events.click(), false);
  recoveryUI.buttons.step.focus(); await recoveryUI.refresh(); assert(recoveryUI.recoverCreate.hidden); assert.equal(doc.activeElement, recoveryUI.buttons.step); recoveryUI.destroy();
  assert(!source.includes('addEventListener(\'keydown\', event => {\n      if (event.key === \'F8\''), 'No global function-key binding');
  console.log('PASS owned VM DOM: explicit initial snapshot, live/history independence, focus preservation, scoped arrows, unknown/absent/zero/loss display, and hidden-pane quiescence controls (not rendered acceptance)');
}

// Invoke from the repository browser driver after the real backend has loaded
// the mounted component. This never installs a fake server or JS interpreter.
export async function checkOwnedVmDebuggerInteractions({evaluate, viewport, click, key, screenshot, root = '#vm-owned-debugger', toolbarRoot = root}) {
  const selector = suffix => `${root} ${suffix}`;
  const toolbarSelector = suffix => `${toolbarRoot} ${suffix}`;
  const control = action => `[data-owned-vm-action="${action}"]`;
  const visibleClick = async suffix => { await evaluate(`document.querySelector(${JSON.stringify(selector(suffix))}).scrollIntoView({block:'nearest'})`); await click(selector(suffix)); };
  const data = async () => evaluate(`JSON.parse(document.querySelector(${JSON.stringify(selector('.owned-vm-debugger-audit pre'))}).textContent).view || JSON.parse(document.querySelector(${JSON.stringify(selector('.owned-vm-debugger-audit pre'))}).textContent)`);
  const wait = async (state, count = null) => evaluate(`(async()=>{const deadline=performance.now()+8000;for(;;){const e=document.querySelector(${JSON.stringify(root)});if(e.getAttribute('data-owned-vm-state')===${JSON.stringify(state)}&&(${JSON.stringify(count)}===null||e.getAttribute('data-owned-vm-executed')===${JSON.stringify(count)}))return;if(performance.now()>deadline)throw Error('Native UI did not acknowledge expected ${state}');await new Promise(r=>setTimeout(r,25));}})()`);
  const delay = ms => evaluate(`new Promise(resolve=>setTimeout(resolve,${ms}))`);
  const activate = async action => { await evaluate(`document.querySelector(${JSON.stringify(toolbarSelector(control(action)))}).focus()`); await key('Enter', 'Enter', {windowsVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r'}); };
  await viewport(1440, 900);
  if (await evaluate('!!document.querySelector("#vm-show-owned")')) await click('#vm-show-owned');
  const capability = await data(); assert(capability.available, 'Rendered live acceptance requires the actual native helper'); assert.equal(capability.session, null, 'Use an isolated owned-fixture backend');
  await activate('create'); await wait('paused', '0'); const created = await data(); assert.equal(created.session.records.length, 0);
  assert.equal(await evaluate("document.querySelector('#nav-vm-workspace').textContent"),'VM','Native state polling keeps the primary label compact');
  assert.match(await evaluate("document.querySelector('#nav-vm-workspace').getAttribute('aria-label')"),/paused/);
  assert(await evaluate(`document.activeElement===document.querySelector(${JSON.stringify(toolbarSelector('[data-owned-vm-refresh]'))})`), 'Completed Create keeps the stable enabled fallback');
  await delay(800); assert.equal((await data()).session.executed_count, '0', 'Creation and reads do not execute');
  const originalTheme=await evaluate("document.documentElement.getAttribute('data-theme')");
  for(const theme of ['dark','light']){
    await evaluate(`document.documentElement.setAttribute('data-theme',${JSON.stringify(theme)})`);
    const roles=await evaluate(`(()=>{const style=getComputedStyle(document.querySelector('#screen-vm'));const rgb=hex=>'rgb('+hex.trim().slice(1).match(/../g).map(x=>parseInt(x,16)).join(', ')+')';return [...document.querySelectorAll('#vm-owned-controls [data-owned-vm-action]')].map(button=>{const action=button.getAttribute('data-owned-vm-action'),role=button.disabled?'disabled':['create','run','step'].includes(action)?'action':['pause','reset'].includes(action)?'change':'stop';return {action,actual:getComputedStyle(button).backgroundColor,expected:rgb(style.getPropertyValue('--vm-'+role+'-bg'))};});})()`);
    assert.equal(roles.length,7);for(const role of roles)assert.equal(role.actual,role.expected,`${theme} native ${role.action} must use its semantic color`);
  }
  await evaluate(originalTheme===null?"document.documentElement.removeAttribute('data-theme')":`document.documentElement.setAttribute('data-theme',${JSON.stringify(originalTheme)})`);

  let reachedStep = false;
  for (let i = 0; i < 20; i++) {
    if (await evaluate(`document.activeElement===document.querySelector(${JSON.stringify(toolbarSelector(control('step')))})`)) { reachedStep = true; break; }
    await key('Tab', 'Tab', {windowsVirtualKeyCode: 9, modifiers: 8});
  }
  assert(reachedStep, 'Step is reachable by native reverse Tab from the stable fallback');
  const enter = () => key('Enter', 'Enter', {windowsVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r'});
  await enter(); await wait('paused', '1'); assert.equal((await data()).session.current_snapshot.registers[0].bits, '7');
  assert(await evaluate(`document.activeElement===document.querySelector(${JSON.stringify(toolbarSelector(control('step')))})`), 'Step focus returns after acknowledgment without refocusing');
  await enter(); await wait('paused', '2'); assert.equal((await data()).session.current_snapshot.registers[1].bits, '5');
  assert(await evaluate(`document.activeElement===document.querySelector(${JSON.stringify(toolbarSelector(control('step')))})`));
  await enter(); await wait('paused', '3'); assert.equal((await data()).session.current_snapshot.registers[0].bits, '12');
  for (const [width, height] of [[1440, 900], [1024, 768], [390, 844]]) {
    await viewport(width, height); await visibleClick('[role="tab"]');
    assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'), 'No horizontal page overflow');
    await screenshot(`owned-vm-paused-${width}.png`);
  }
  await viewport(1440, 900); await activate('run'); await wait('running'); await visibleClick('[data-owned-vm-sequence="1"]'); await delay(350);
  assert.equal(await evaluate(`document.querySelector(${JSON.stringify(root)}).getAttribute('data-owned-vm-selection')`), '1');
  await activate('pause'); await wait('paused'); const paused = await data(); assert(BigInt(paused.session.executed_count) >= 4n && BigInt(paused.session.executed_count) < 9n);
  await delay(800); assert.deepEqual((await data()).session.current_snapshot, paused.session.current_snapshot); assert.equal((await data()).session.executed_count, paused.session.executed_count);
  await visibleClick('[data-owned-vm-sequence="1"]'); await key('ArrowDown', 'ArrowDown', {windowsVirtualKeyCode: 40}); assert.equal((await data()).session.executed_count, paused.session.executed_count);
  await activate('step'); await wait('paused', String(BigInt(paused.session.executed_count) + 1n)); await activate('run'); await wait('halted', '9');
  assert.equal((await data()).session.current_snapshot.pc, '10'); assert(await evaluate(`document.querySelector(${JSON.stringify(toolbarSelector(control('step')))}).disabled`));
  await activate('reset'); await wait('paused', '0'); const reset = await data(); assert.notEqual(reset.session.run_id, created.session.run_id); assert.equal(reset.session.records.length, 0);
  await activate('stop'); await wait('stopped', '0'); await activate('close'); await wait('idle', '0');
  await selectRenderedOption({evaluate, click, key, selector: toolbarSelector('[aria-label="Owned native fixture"]'), index: 1});
  await activate('create'); await wait('paused', '0'); assert.equal((await data()).session.fixture, 'stack');
  await activate('step'); await wait('paused', '1'); assert.deepEqual((await data()).session.current_snapshot.stack, [observed('7')]);
  await activate('stop'); await wait('stopped', '1'); await delay(600); assert.equal((await data()).session.executed_count, '1');
  const integrated = await evaluate('!!document.querySelector("#vm-show-execution")');
  if (integrated) {
    const retainedRun = (await data()).session.run_id;
    await click('#vm-show-findings'); assert(await evaluate('!document.querySelector("#vm-owned-controls").hidden'));
    await click('#vm-show-owned'); await click('#vm-show-execution');
    assert(await evaluate('!document.querySelector("#vm-owned-controls").hidden && document.querySelector("#vm-owned-debugger").hidden'));
    assert.equal((await data()).session.run_id, retainedRun, 'Provider switches preserve the exact stopped native run');
    await viewport(1440, 900);
    const densityTrace = {format: 'reb-vm-trace-v1', identity: {trace_id: 'owned-live-controls-density', investigation_id: '1', finding_id: '2', artifact_id: '3', artifact_sha256: 'a'.repeat(64), scope_id: 'owned-density', backend: 'fixture'}, architecture: 'register', coverage: {complete: true, dropped_steps: 0, limitations: ['Authored imported layout fixture; unrelated to the native run.']}, steps: Array.from({length: 32}, (_, sequence) => ({sequence, opcode: '00', operands: [], instruction_size: 1, before: {pc: sequence, halted: false, registers: [], stack: [], memory: []}, after: {pc: sequence + 1, halted: false, registers: [], stack: [], memory: []}, evidence_refs: ['owned-density:' + sequence]}))};
    await evaluate(`(async()=>{const input=document.querySelector('[aria-label="Import VM execution trace"]'),transfer=new DataTransfer();transfer.items.add(new File([${JSON.stringify(JSON.stringify(densityTrace))}],'owned-density.json',{type:'application/json'}));input.files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));const deadline=performance.now()+5000;while(document.querySelector('[aria-label="Execution step"]').options.length!==32){if(performance.now()>deadline)throw Error('Owned density trace import did not settle');await new Promise(resolve=>setTimeout(resolve,10));}})()`);
    assert(await evaluate(`(()=>{const body=document.querySelector('.vm-listing-body'),box=body.getBoundingClientRect();return [...body.querySelectorAll('[data-vm-sequence]')].filter(row=>{const r=row.getBoundingClientRect();return r.top>=box.top&&r.bottom<=box.bottom&&r.top>=0&&r.bottom<=innerHeight;}).length>=12})()`), 'Imported listing with retained native controls must show at least12 complete rows');
    assert(await evaluate(`[...document.querySelectorAll('#vm-owned-controls [data-owned-vm-action]')].every(e=>{const r=e.getBoundingClientRect();return r.width>0&&r.height>0&&r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight})`), 'All native execution actions remain visible beside imported evidence');
    assert.equal((await data()).session.run_id, retainedRun);assert.equal((await data()).session.executed_count, '1');
    await screenshot('owned-vm-imported-live-controls-density.png');
    const importedClick=async target=>{await evaluate(`document.querySelector(${JSON.stringify(target)}).scrollIntoView({block:'nearest'})`);await click(target);};
    await viewport(360, 740);
    await evaluate(`(async()=>{const deadline=performance.now()+3000;while(document.querySelector('#vm-semantics-workflow').dataset.layout!=='narrow'){if(performance.now()>deadline)throw Error('Imported narrow layout did not settle');await new Promise(resolve=>setTimeout(resolve,10));}})()`);
    await evaluate(`(()=>{const row=document.querySelector('#vm-semantics-workflow [data-vm-sequence="0"]');row.focus();row.scrollIntoView({block:'center'});})()`);
    assert(await evaluate(`(()=>{const screen=document.querySelector('#screen-vm'),body=document.querySelector('#vm-semantics-workflow .vm-listing-body'),box=body.getBoundingClientRect(),outer=screen.getBoundingClientRect();return box.height>=240&&screen.scrollHeight>screen.clientHeight&&[...body.querySelectorAll('[data-vm-sequence]')].filter(row=>{const r=row.getBoundingClientRect();return r.top>=Math.max(0,box.top,outer.top)&&r.bottom<=Math.min(innerHeight,box.bottom,outer.bottom)}).length>=2})()`), 'Phone coexistence must scroll vertically and retain at least two complete imported rows');
    assert(await evaluate(`(()=>{const e=document.activeElement,r=e.getBoundingClientRect();return e.getAttribute('data-vm-sequence')==='0'&&r.top>=0&&r.bottom<=innerHeight&&getComputedStyle(e).outlineStyle!=='none'})()`), 'Phone imported selection remains visibly focused with live controls retained');
    await key('ArrowDown','ArrowDown',{windowsVirtualKeyCode:40});
    assert.equal(await evaluate(`document.querySelector('[aria-label="Execution step"]').value`),'1');
    assert.equal((await data()).session.run_id,retainedRun);assert.equal((await data()).session.executed_count,'1');
    await screenshot('owned-vm-imported-live-controls-phone.png');
    await key('Enter','Enter',{windowsVirtualKeyCode:13,text:'\r',unmodifiedText:'\r'});
    await evaluate(`(()=>{const cell=document.querySelector('#vm-semantics-workflow [data-vm-location="pc"] button');cell.focus();cell.scrollIntoView({block:'center'});})()`);
    assert(await evaluate(`(()=>{const e=document.activeElement,r=e.closest('.vm-state-row').getBoundingClientRect();return e.textContent==='pc'&&r.top>=0&&r.bottom<=innerHeight&&getComputedStyle(e).outlineStyle!=='none'})()`), 'Phone coexistence preserves a complete focused state cell');
    await screenshot('owned-vm-imported-live-controls-phone-state.png');
    await importedClick('#vm-semantics-workflow .vm-step-inspector > button');
    assert.equal(await evaluate(`document.activeElement.getAttribute('data-vm-sequence')`),'1');
    await importedClick('#vm-semantics-workflow [data-vm-panel="evidence"]');
    await importedClick('#vm-semantics-workflow .vm-context-header > button');
    assert.equal(await evaluate(`document.activeElement.getAttribute('data-vm-panel')`),'listing');
    assert.equal((await data()).session.run_id,retainedRun);assert.equal((await data()).session.executed_count,'1');
    // CSS viewport equivalent of a1440x900 window at200%; actual browser zoom
    // remains a separate native acceptance gate. Use real pointer hit testing.
    await viewport(720,450);await activate('reset');await wait('paused','0');
    const pointerControl=async(action,invoke=false)=>{const target=toolbarSelector(action==='refresh'?'[data-owned-vm-refresh]':control(action));await evaluate(`document.querySelector(${JSON.stringify(target)}).scrollIntoView({block:'center'})`);assert(await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(target)}),r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2,hit=document.elementFromPoint(x,y),owner=document.querySelector('#vm-owned-controls').getBoundingClientRect();return !e.disabled&&owner.height>0&&r.width>0&&r.height>0&&x>=0&&x<innerWidth&&y>=0&&y<innerHeight&&(hit===e||e.contains(hit))})()`), 'Native '+action+' must remain pointer-reachable beside imported evidence');if(invoke)await click(target);};
    assert(await evaluate(`(()=>{const root=document.querySelector('#vm-semantics-workflow'),pane=root.querySelector('.vm-execution-body').getBoundingClientRect(),controls=document.querySelector('#vm-owned-controls').getBoundingClientRect(),listing=root.querySelector('.vm-listing-body');return Math.abs(pane.height-600)<=1&&controls.height>0&&root.getBoundingClientRect().top>=controls.bottom-1&&listing.scrollHeight>listing.clientHeight})()`),'Coexisting analysis has a bounded pane independent of retained row count');
    await pointerControl('stop');await pointerControl('run',true);await wait('running');
    await pointerControl('stop');await pointerControl('pause',true);await wait('paused');
    await pointerControl('stop',true);await wait('stopped');await pointerControl('refresh',true);
    await pointerControl('reset',true);await wait('paused','0');await pointerControl('step',true);await wait('paused','1');
    await pointerControl('stop',true);await wait('stopped','1');await pointerControl('close');
    await screenshot('owned-vm-imported-live-controls-zoom-pointer.png');
    await viewport(1440,450);await pointerControl('close');await pointerControl('refresh',true);
    assert(await evaluate(`(()=>{const controls=document.querySelector('#vm-owned-controls').getBoundingClientRect(),root=document.querySelector('#vm-semantics-workflow');return controls.height>0&&root.getBoundingClientRect().top>=controls.bottom-1&&Math.abs(root.querySelector('.vm-execution-body').getBoundingClientRect().height-600)<=1})()`),'Wide-short coexistence keeps controls separate from bounded analysis');




  }
  await activate('close'); await wait('idle', '0');
  if (integrated) assert(await evaluate('(()=>{const e=document.activeElement,r=e.getBoundingClientRect();return e.id==="vm-show-execution"&&document.querySelector("#vm-owned-controls").hidden&&r.width>0&&r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight&&getComputedStyle(e).outlineStyle!=="none"})()'), 'Close from imported evidence restores visible provider focus');
  await screenshot('owned-vm-closed.png');
}

async function checkAuthoredBrowser() {
  const repository = fileURLToPath(new URL('..', import.meta.url)), output = process.env.REB_OWNED_VM_UI_OUTPUT || join(tmpdir(), 'reb-owned-vm-ui-authored');
  await mkdir(output, {recursive: true}); const profile = await mkdtemp(join(tmpdir(), 'reb-owned-vm-chromium-'));
  const source = await readFile(join(repository, 'apps/research-ui/vm_debugger.js'), 'utf8'), css = await readFile(join(repository, 'apps/research-ui/app.css'), 'utf8');
  let current = envelope(), ordinal = 0, browser = null, socket = null, diagnostics = '', sequence = 0, closed = false;
  const requests = [], commands = new Map(), errors = [], pause = ms => new Promise(done => setTimeout(done, ms));
  const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authored owned VM response QA</title><link rel="stylesheet" href="/app.css"><style>html,body{overflow:auto;height:auto;min-height:100%}body{margin:0;padding:12px}main{min-width:0}</style></head><body><p>Authored test responses only. No native execution or browser capture.</p><main id="fixture"><section id="vm-owned-debugger"></section></main><script src="/vm_debugger.js"></script><script>window.owned=mountOwnedVmDebugger(document.querySelector("#vm-owned-debugger"));</script></body></html>';
  const server = createServer(async (request, response) => {
    try {
      requests.push({method: request.method, path: request.url});
      if (request.url === '/vm_debugger.js' || request.url === '/app.css' || request.url === '/') {
        response.setHeader('Content-Type', request.url === '/' ? 'text/html' : request.url.endsWith('.js') ? 'text/javascript' : 'text/css');
        response.end(request.url === '/' ? html : request.url.endsWith('.js') ? source : css); return;
      }
      response.setHeader('Content-Type', 'application/json');
      if (request.method === 'GET' && request.url === '/api/vm-debugger') { response.end(JSON.stringify(current)); return; }
      if (request.method === 'POST' && request.url === '/api/vm-debugger/actions') {
        const chunks = []; for await (const chunk of request) chunks.push(chunk); const command = JSON.parse(Buffer.concat(chunks).toString());
        const fixture = command.fixture || current.session?.fixture || 'register';
        if (command.action === 'create' || command.action === 'reset') { current = envelope(session(fixture)); current.session.run_id = `run-${++ordinal}`; current.session.run_generation = String(ordinal); }
        else if (command.action === 'step') {
          const prior = current.session; current = envelope(session(fixture, prior.executed_count === '0' ? 1 : 2));
          Object.assign(current.session, {run_id: prior.run_id, run_generation: prior.run_generation});
        } else if (command.action === 'close') current = envelope();
        else current.session.state = {run: 'running', pause: 'paused', stop: 'stopped'}[command.action];
        if (current.session) { current.session.control_revision = String(++ordinal + 4); current.session.last_command = {action: command.action, command_id: command.command_id, ack: 'completed'}; }
        response.end(JSON.stringify(ack(current, command))); return;
      }
      response.statusCode = 404; response.end('{}');
    } catch (error) { response.statusCode = 500; response.end(JSON.stringify({error: String(error), code: 'application_failed'})); }
  });
  const send = (method, params = {}) => new Promise((resolveCall, reject) => {
    const id = ++sequence, timer = setTimeout(() => { commands.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    commands.set(id, {resolve: resolveCall, reject, timer}); socket.send(JSON.stringify({id, method, params}));
  });
  const evaluate = async expression => { const reply = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true}); if (reply.exceptionDetails) throw Error(JSON.stringify(reply.exceptionDetails)); return reply.result.value; };
  const until = async (test, label) => { const end = Date.now() + 10000; while (Date.now() < end) { if (await test()) return; await pause(40); } throw Error(`Timed out: ${label}`); };
  const click = async selector => { const point = await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});e.scrollIntoView({block:'nearest'});const r=e.getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2}})()`); await send('Input.dispatchMouseEvent', {type: 'mousePressed', ...point, button: 'left', clickCount: 1}); await send('Input.dispatchMouseEvent', {type: 'mouseReleased', ...point, button: 'left', clickCount: 1}); };
  const key = async (key, code, extra = {}) => { for (const event of ownedVmRenderedKeyEvents(key, code, extra)) await send('Input.dispatchKeyEvent', event); };
  const viewport = (width, height) => send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile: false});
  const screenshot = async name => { const result = await send('Page.captureScreenshot', {format: 'png'}); await writeFile(join(output, name), Buffer.from(result.data, 'base64')); };
  try {
    await new Promise((ready, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ready); });
    browser = spawn(process.env.REB_UI_CHROMIUM || '/usr/bin/chromium', ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-sync', 'about:blank'], {detached: process.platform !== 'win32', stdio: ['ignore', 'ignore', 'pipe']});
    browser.once('close', () => { closed = true; }); browser.on('error', error => { diagnostics += String(error); }); browser.stderr.on('data', chunk => { diagnostics = (diagnostics + chunk).slice(-8192); });
    let port;
    await until(async () => { if (browser.exitCode !== null || browser.signalCode !== null) throw Error(`Sandboxed Chromium startup failed (${browser.exitCode ?? browser.signalCode}): ${diagnostics}`); try { port = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; return !!port; } catch { return false; } }, 'sandboxed Chromium startup');
    const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json(); socket = new WebSocket(pages.find(page => page.type === 'page').webSocketDebuggerUrl);
    await new Promise((ready, reject) => { socket.addEventListener('open', ready, {once: true}); socket.addEventListener('error', reject, {once: true}); });
    socket.addEventListener('message', event => { const message = JSON.parse(event.data); if (message.method === 'Runtime.exceptionThrown') errors.push(message.params); const waiting = commands.get(message.id); if (waiting) { clearTimeout(waiting.timer); commands.delete(message.id); if (message.error) waiting.reject(Error(message.error.message)); else waiting.resolve(message.result); } });
    await send('Runtime.enable'); await send('Page.enable'); await viewport(1440, 900); await send('Page.navigate', {url: `http://127.0.0.1:${server.address().port}/`});
    await until(() => evaluate('window.owned?.controller.model().view?.available'), 'authored capability'); assert.equal(requests.filter(item => item.method === 'POST').length, 0);
    await click('[data-owned-vm-action="create"]'); await until(() => evaluate('owned.controller.model().view.session?.state === "paused"'), 'paused authored create');
    assert.equal(await evaluate('owned.history.children.length'), 0);
    assert(await evaluate('document.activeElement===owned.refreshButton'));
    let reachedStep = false;
    for (let i = 0; i < 20; i++) { if (await evaluate('document.activeElement===owned.buttons.step')) { reachedStep = true; break; } await key('Tab', 'Tab', {windowsVirtualKeyCode: 9, modifiers: 8}); }
    assert(reachedStep); await key('Enter', 'Enter', {windowsVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r'});
    await until(() => evaluate('owned.controller.model().view.session?.executed_count === "1"'), 'single authored step');
    assert(await evaluate('document.activeElement === owned.buttons.step'));
    await key('Enter', 'Enter', {windowsVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r'});
    await until(() => evaluate('owned.controller.model().view.session?.executed_count === "2"'), 'second authored observation');
    assert(await evaluate('document.activeElement===owned.buttons.step'), 'Repeated Enter uses restored focus; no intervening programmatic focus');
    await click('[data-owned-vm-sequence="1"]');
    assert.equal(await evaluate('document.querySelector("#vm-owned-debugger").getAttribute("data-owned-vm-selection")'), '1');
    const posts = requests.filter(item => item.method === 'POST').length;
    await click('[data-owned-vm-sequence="1"]'); await key('ArrowDown', 'ArrowDown', {windowsVirtualKeyCode: 40});
    assert.equal(await evaluate('document.activeElement.getAttribute("data-owned-vm-sequence")'), '2'); assert.equal(requests.filter(item => item.method === 'POST').length, posts);
    for (const [width, height] of [[1440, 900], [1024, 768], [390, 844]]) {
      await viewport(width, height); await click('[role="tab"]');
      assert(await evaluate('document.documentElement.scrollWidth<=innerWidth'), 'Authored view stays inside page width');
      for (const action of ['run', 'pause', 'step', 'stop', 'reset', 'close']) {
        await evaluate(`owned.buttons.${action}.scrollIntoView({block:'nearest'})`);
        assert(await evaluate(`(()=>{const r=owned.buttons.${action}.getBoundingClientRect();return r.width>0&&r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight})()`));
      }
      await screenshot(`authored-${width}.png`);
    }
    await click('[data-owned-vm-action="run"]'); await until(() => evaluate('owned.controller.model().view.session.state === "running"'), 'authored run acknowledgment');
    await evaluate('owned.setVisible(false)'); assert(await evaluate('!owned.buttons.pause.disabled && !owned.buttons.stop.disabled'));
    await click('[data-owned-vm-action="pause"]'); await until(() => evaluate('owned.controller.model().view.session.state === "paused"'), 'authored pause acknowledgment');
    await click('[data-owned-vm-action="reset"]'); await until(() => evaluate('owned.controller.model().view.session.executed_count === "0"'), 'authored reset');
    await click('[data-owned-vm-action="stop"]'); await until(() => evaluate('owned.controller.model().view.session.state === "stopped"'), 'authored stop');
    await click('[data-owned-vm-action="close"]'); await until(() => evaluate('owned.controller.model().view.session === null'), 'authored close'); assert.deepEqual(errors, []);
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'passed', scope: 'authored HTTP responses only; no native execution', viewports: [[1440, 900], [1024, 768], [390, 844]], requests, errors, native_macos: 'not run'}, null, 2));
    console.log(`PASS authored owned VM browser UI; not native acceptance. Evidence: ${output}`);
  } catch (error) {
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'failed', scope: 'authored HTTP responses only; no native execution', error: String(error.stack || error), browser_stderr: diagnostics, requests, errors}, null, 2));
    throw error;
  } finally {
    for (const command of commands.values()) clearTimeout(command.timer); socket?.close();
    let safeToRemove = !browser?.pid;
    if (browser?.pid) {
      for (const signal of ['SIGTERM', 'SIGKILL']) {
        try { if (process.platform !== 'win32') process.kill(-browser.pid, signal); else if (!closed) browser.kill(signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
        const deadline = Date.now() + 2000; while (!closed && Date.now() < deadline) await pause(25);
        if (closed) { safeToRemove = true; break; }
      }
    }
    server.closeAllConnections(); await new Promise(done => server.close(done));
    if (safeToRemove) await rm(profile, {recursive: true, force: true, maxRetries: 5, retryDelay: 100});
    else throw Error(`Browser did not close; retained its owned profile at ${profile}`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await checkOwnedVmDebuggerController(); await checkOwnedVmDebuggerDOM();
  if (process.argv.includes('--browser')) await checkAuthoredBrowser();
}
