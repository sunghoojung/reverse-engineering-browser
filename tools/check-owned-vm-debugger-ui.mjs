#!/usr/bin/env node
// Deterministic controller/DOM checks use authored synthetic responses. The
// tests do not launch or control a browser.
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
import debuggerUI from '../apps/research-ui/vm_debugger.js';

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
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await checkOwnedVmDebuggerController(); await checkOwnedVmDebuggerDOM();
  if (process.argv.includes('--browser')) throw new Error('CDP browser automation was removed; controller/DOM checks above are not rendered QA.');
}
