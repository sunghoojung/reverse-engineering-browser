/* Real, cooperative, repository-owned native fixtures only. No interpreter or
 * imported-trace adapter lives here. GETs observe; only explicit buttons POST. */
const ownedVmU64Max = 18446744073709551615n;
const ownedVmEvidence = ['observed', 'inferred', 'unknown'];
const ownedVmStates = ['idle', 'starting', 'paused', 'running', 'pausing', 'stepping', 'stopping', 'halted', 'stopped', 'expired', 'failed'];
const ownedVmObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const ownedVmKeys = (value, keys) => ownedVmObject(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const ownedVmText = (value, max = 256) => typeof value === 'string' && value.length <= max;
const ownedVmU64 = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= ownedVmU64Max;
const ownedVmArray = (value, max, check) => Array.isArray(value) && value.length <= max && value.every(check);
const ownedVmBool = value => typeof value === 'boolean';
function ownedVmAssert(condition, message = 'Invalid owned VM debugger response. Last confirmed evidence is preserved.') {
  if (!condition) throw new Error(message);
}

// Detect duplicate keys before interpretation, and cap input, nesting and work.
// Guest u64 data remain strings; only small JSON metadata can be numeric.
function ownedVmParseJSON(source) {
  ownedVmAssert(typeof source === 'string' && new TextEncoder().encode(source).length <= 1048576);
  let cursor = 0, nodes = 0;
  const white = () => { while (/[ \t\r\n]/.test(source[cursor] || '') && cursor < source.length) cursor++; };
  const string = () => {
    const start = cursor++;
    while (cursor < source.length) {
      if (source[cursor++] === '"') return JSON.parse(source.slice(start, cursor));
      if (source[cursor - 1] === '\\') cursor++;
    }
    throw new Error('Unterminated VM response string.');
  };
  const value = depth => {
    ownedVmAssert(depth <= 32 && ++nodes <= 40000); white();
    if (source[cursor] === '"') return string();
    if (source[cursor] === '{') {
      cursor++; white(); const result = Object.create(null);
      if (source[cursor] === '}') { cursor++; return result; }
      for (;;) {
        ownedVmAssert(source[cursor] === '"'); const key = string();
        ownedVmAssert(!Object.hasOwn(result, key), 'Duplicate key in owned VM response.');
        white(); ownedVmAssert(source[cursor++] === ':'); result[key] = value(depth + 1); white();
        if (source[cursor] === '}') { cursor++; return result; }
        ownedVmAssert(source[cursor++] === ','); white();
      }
    }
    if (source[cursor] === '[') {
      cursor++; white(); const result = [];
      if (source[cursor] === ']') { cursor++; return result; }
      for (;;) {
        result.push(value(depth + 1)); white();
        if (source[cursor] === ']') { cursor++; return result; }
        ownedVmAssert(source[cursor++] === ',');
      }
    }
    for (const [token, result] of [['true', true], ['false', false], ['null', null]]) {
      if (source.startsWith(token, cursor)) { cursor += token.length; return result; }
    }
    const token = source.slice(cursor).match(/^(0|[1-9][0-9]*)/);
    ownedVmAssert(token); cursor += token[0].length; const result = Number(token[0]);
    ownedVmAssert(Number.isSafeInteger(result)); return result;
  };
  const result = value(0); white(); ownedVmAssert(cursor === source.length); return result;
}
function ownedVmValue(value) {
  return ownedVmKeys(value, ['bits', 'evidence']) && ownedVmU64(value.bits) && ownedVmEvidence.includes(value.evidence) &&
    (value.evidence !== 'unknown' || value.bits === '0');
}
function ownedVmSnapshot(value) {
  if (!ownedVmKeys(value, ['pc', 'pc_evidence', 'partial', 'halted', 'registers', 'stack', 'memory']) ||
      !ownedVmU64(value.pc) || !ownedVmEvidence.includes(value.pc_evidence) || value.pc_evidence === 'unknown' && value.pc !== '0' ||
      !ownedVmBool(value.partial) || !ownedVmBool(value.halted) || !ownedVmArray(value.registers, 8, ownedVmValue) ||
      !ownedVmArray(value.stack, 8, ownedVmValue) || !ownedVmArray(value.memory, 8, cell =>
        ownedVmKeys(cell, ['guest_address', 'value']) && ownedVmU64(cell.guest_address) && ownedVmValue(cell.value))) return false;
  return new Set(value.memory.map(cell => cell.guest_address)).size === value.memory.length;
}
function ownedVmOperand(value, effect = false) {
  return ownedVmKeys(value, effect ? ['location', 'index', 'value', 'access'] : ['location', 'index', 'value']) &&
    (effect ? ['register', 'stack', 'memory'] : ['immediate', 'register', 'stack', 'memory']).includes(value.location) &&
    ownedVmU64(value.index) && (!['register', 'stack'].includes(value.location) || BigInt(value.index) < 8n) &&
    ownedVmValue(value.value) && (!effect || ['read', 'write'].includes(value.access));
}
function ownedVmRecord(value) {
  return ownedVmKeys(value, ['sequence', 'tick', 'opcode', 'opcode_evidence', 'partial', 'operands', 'effects', 'before', 'after']) &&
    ownedVmU64(value.sequence) && value.sequence !== '0' && ownedVmU64(value.tick) && Number.isInteger(value.opcode) &&
    value.opcode >= 0 && value.opcode <= 8 && ownedVmEvidence.includes(value.opcode_evidence) &&
    (value.opcode_evidence !== 'unknown' || value.opcode === 0) && ownedVmBool(value.partial) &&
    ownedVmArray(value.operands, 4, operand => ownedVmOperand(operand)) &&
    ownedVmArray(value.effects, 8, effect => ownedVmOperand(effect, true)) && ownedVmSnapshot(value.before) && ownedVmSnapshot(value.after);
}
function ownedVmFormatValue(value) {
  if (!value) return 'absent';
  if (value.evidence === 'unknown') return 'unknown';
  return `${value.bits} (0x${BigInt(value.bits).toString(16)}; ${value.evidence})`;
}
function ownedVmPC(snapshot) {
  return snapshot.pc_evidence === 'unknown' ? 'unknown' : `${snapshot.pc} (${snapshot.pc_evidence})`;
}
const ownedVmIdentityKeys = ['backend_instance_id', 'session_id', 'run_id', 'run_generation'];
const ownedVmIdentifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const ownedVmStatsKeys = ['attempted', 'recorded', 'full', 'malformed', 'wrong_document', 'stale_generation', 'exhausted', 'expired', 'partial'];
const ownedVmActions = ['create', 'run', 'pause', 'step', 'stop', 'reset', 'close'];
const ownedVmAcks = ['pending', 'completed', 'rejected', 'outcome_unknown'];
function ownedVmSameRun(a, b) {
  return !!a && !!b && ownedVmIdentityKeys.every(key => a[key] === b[key]);
}
function ownedVmScope(session) {
  return Object.fromEntries(ownedVmIdentityKeys.map(key => [key, session[key]]));
}
function ownedVmSession(value) {
  const keys = ['backend_instance_id', 'session_id', 'run_id', 'run_generation', 'provider', 'target_kind', 'fixture',
    'program_id', 'fixture_revision', 'program_sha256', 'program_manifest_scope', 'build_id', 'build_id_scope', 'pc_units',
    'value_semantics', 'tick_units', 'state', 'control_revision', 'snapshot_revision', 'executed_count', 'retained_count',
    'execution_state_known', 'termination_reason', 'initial_snapshot', 'current_snapshot', 'records', 'recorder',
    'last_command', 'diagnostics', 'disposal_failed'];
  if (!ownedVmKeys(value, keys) || !ownedVmIdentityKeys.slice(0, 3).every(key => ownedVmIdentifier(value[key])) ||
      !['run_generation', 'control_revision', 'snapshot_revision', 'executed_count', 'retained_count'].every(key => ownedVmU64(value[key])) ||
      !['register', 'stack'].includes(value.fixture) || value.target_kind !== 'owned_fixture' ||
      value.provider !== 'live-owned-native-fixture' || value.program_id !== `owned-${value.fixture}-v1` || value.fixture_revision !== 1 ||
      !(typeof value.program_sha256 === 'string' && /^[a-f0-9]{64}$/.test(value.program_sha256)) || value.program_manifest_scope !== 'declared-two-program-manifest-sha256' ||
      !(value.build_id === null || typeof value.build_id === 'string' && /^[a-f0-9]{64}$/.test(value.build_id)) ||
      value.build_id_scope !== 'configured-helper-file-sha256' || value.pc_units !== 'instruction-index' ||
      value.value_semantics !== 'unsigned-64-bit-bits' || value.tick_units !== 'monotonic-nanoseconds' ||
      !ownedVmStates.includes(value.state) || value.state === 'idle' || !ownedVmBool(value.execution_state_known) ||
      !ownedVmBool(value.disposal_failed) || !(value.termination_reason === null || ownedVmText(value.termination_reason, 256)) ||
      !(value.initial_snapshot === null || ownedVmSnapshot(value.initial_snapshot)) ||
      !(value.current_snapshot === null || ownedVmSnapshot(value.current_snapshot)) ||
      !ownedVmArray(value.records, 64, ownedVmRecord) || value.retained_count !== String(value.records.length) ||
      BigInt(value.executed_count) < BigInt(value.retained_count) ||
      !ownedVmKeys(value.recorder, ['session_id', 'document_id', 'invocation_id', 'generation', 'stats']) ||
      !['session_id', 'document_id', 'invocation_id', 'generation'].every(key => ownedVmU64(value.recorder[key])) ||
      !ownedVmKeys(value.recorder.stats, ownedVmStatsKeys) || !ownedVmStatsKeys.every(key => ownedVmU64(value.recorder.stats[key])) ||
      value.recorder.stats.recorded !== value.retained_count ||
      !ownedVmKeys(value.diagnostics, ['stderr_bytes', 'stderr_truncated']) || !ownedVmU64(value.diagnostics.stderr_bytes) ||
      !ownedVmBool(value.diagnostics.stderr_truncated)) return false;
  if (value.last_command !== null && (!ownedVmKeys(value.last_command, ['command_id', 'action', 'ack']) ||
      !ownedVmIdentifier(value.last_command.command_id) || !ownedVmActions.includes(value.last_command.action) ||
      !ownedVmAcks.includes(value.last_command.ack))) return false;
  let prior = 0n;
  for (const record of value.records) {
    const sequence = BigInt(record.sequence);
    if (sequence <= prior || sequence > BigInt(value.recorder.stats.attempted)) return false;
    prior = sequence;
  }
  return true;
}
function ownedVmValidateView(value) {
  const keys = ['schema', 'available', 'unavailable_reason', 'backend_instance_id', 'session'];
  const action = Object.hasOwn(value || {}, 'command_id') || Object.hasOwn(value || {}, 'ack');
  const annotated = Object.hasOwn(value || {}, 'code') || Object.hasOwn(value || {}, 'details');
  const expected = action ? [...keys, 'command_id', 'ack'] : keys;
  ownedVmAssert(ownedVmKeys(value, annotated ? [...expected, 'code', 'details'] : expected) &&
    value.schema === 'reb-owned-vm-debug-session-v1' && ownedVmBool(value.available) &&
    (value.unavailable_reason === null || ownedVmText(value.unavailable_reason, 256)) && ownedVmIdentifier(value.backend_instance_id) &&
    (value.session === null || ownedVmSession(value.session) && value.session.backend_instance_id === value.backend_instance_id) &&
    (!action || ownedVmIdentifier(value.command_id) && ownedVmAcks.includes(value.ack)) &&
    (!annotated || action && value.ack === 'outcome_unknown' && value.code === 'command_outcome_unknown' &&
      ownedVmKeys(value.details, ['phase', 'cause']) && value.details.phase === 'command_exchange' && value.details.cause === 'disconnected'));
  return value;
}
function ownedVmBuildAction(view, action, commandId, fixture) {
  ownedVmAssert(ownedVmActions.includes(action) && ownedVmIdentifier(commandId) && commandId.length <= 64);
  const request = {action, command_id: commandId};
  if (action === 'create') {
    ownedVmAssert(view?.available && !view.session && ['register', 'stack'].includes(fixture));
    request.fixture = fixture;
  } else {
    ownedVmAssert(view?.session); Object.assign(request, ownedVmScope(view.session));
    if (action === 'run' || action === 'step') request.expected_control_revision = view.session.control_revision;
    if (action === 'step') request.expected_executed_count = view.session.executed_count;
  }
  ownedVmAssert(new TextEncoder().encode(JSON.stringify(request)).length <= 2048); return request;
}
function ownedVmAllowed(view, pending, uncertain) {
  const session = view?.session, busy = pending.length > 0;
  const result = Object.fromEntries(ownedVmActions.map(action => [action, false]));
  result.create = !!view?.available && !session && !busy && !uncertain;
  if (!session) return result;
  const state = session.state, changing = ['starting', 'pausing', 'stepping', 'stopping'].includes(state);
  result.run = result.step = state === 'paused' && session.execution_state_known && !busy && !uncertain;
  result.pause = ['running', 'stepping', 'pausing'].includes(state) || pending.some(item => ['run', 'step'].includes(item.action));
  result.stop = !['stopped', 'expired'].includes(state) && !session.disposal_failed;
  result.reset = !busy && !changing && !session.disposal_failed;
  result.close = !busy && !changing;
  for (const action of ['pause', 'stop']) if (pending.some(item => item.action === action)) result[action] = false;
  return result;
}

function createOwnedVmController(options = {}) {
  const request = options.request || ((path, init) => fetch(path, init));
  const schedule = options.setTimeout || setTimeout, unschedule = options.clearTimeout || clearTimeout;
  let view = null, notice = '', uncertain = null, visible = true, disposed = false, read = null, timer = null, epoch = 0;
  const pending = new Map();
  const emit = () => { if (!disposed) options.onChange?.(model()); };
  const model = () => ({view, notice, uncertain, pending: [...pending.values()], allowed: ownedVmAllowed(view, [...pending.values()], uncertain),
    canRecoverCreate: !!(uncertain?.action === 'create' && uncertain.recovery_ready && view?.available && !view.session &&
      view.backend_instance_id === uncertain.backend_instance_id && pending.size === 0)});
  const sameScope = (a, b) => a?.backend_instance_id === b?.backend_instance_id && (!a?.session && !b?.session || ownedVmSameRun(a?.session, b?.session));
  const poll = () => {
    if (timer !== null) unschedule(timer); timer = null;
    if (!disposed && visible) timer = schedule(() => { timer = null; void refresh(); }, 250);
  };
  const accept = (next, recoveryCommand = null) => {
    const before = view?.session, after = next.session;
    if (ownedVmSameRun(before, after) && (BigInt(after.control_revision) < BigInt(before.control_revision) ||
        BigInt(after.snapshot_revision) < BigInt(before.snapshot_revision) || BigInt(after.executed_count) < BigInt(before.executed_count))) return false;
    if (uncertain && (uncertain.rejected || !sameScope(view, next) || after?.last_command?.command_id === uncertain.command_id && after.last_command.ack !== 'pending')) {
      if (!uncertain.rejected) notice = '';
      uncertain = null;
    }
    if (uncertain?.action === 'create' && uncertain.command_id === recoveryCommand && next.session === null &&
        next.backend_instance_id === uncertain.backend_instance_id) uncertain.recovery_ready = true;
    view = next;
    if (after?.state === 'starting') notice = 'Starting the native helper. The initial snapshot is awaiting acknowledgment; creation does not execute an instruction.';
    else if (after && !after.execution_state_known) notice = 'Execution outcome is unknown. The cursor is the last confirmed snapshot. Use explicit Reset to start a new run.';
    else if (after?.state === 'expired') notice = 'This run expired. Polling does not extend its 60-second lifetime. Reset explicitly to start paused again.';
    else if (after?.disposal_failed) notice = 'The helper could not be confirmed disposed. Replacement is blocked; the last confirmed evidence is retained.';
    options.onState?.(next); emit(); return true;
  };
  const response = async (path, init, timeout) => {
    const abort = new AbortController(); const handle = schedule(() => abort.abort(), timeout);
    try {
      const reply = await request(path, {...init, signal: abort.signal, cache: 'no-store', credentials: 'same-origin'});
      const data = typeof reply?.text === 'function' ? ownedVmParseJSON(await reply.text()) : reply;
      if (reply?.ok === false || ownedVmObject(data) && Object.hasOwn(data, 'error')) {
        const error = new Error(ownedVmText(data?.error, 512) ? data.error : 'The debugger request was rejected.');
        error.code = ownedVmText(data?.code, 64) ? data.code : 'unspecified'; throw error;
      }
      return ownedVmValidateView(data);
    } finally { unschedule(handle); }
  };
  async function refresh() {
    if (disposed || read) return read;
    const token = epoch, recoveryCommand = pending.size === 0 ? uncertain?.command_id : null;
    read = (async () => {
      try {
        const next = await response('/api/vm-debugger', {method: 'GET'}, 6000);
        if (!disposed && token === epoch) { if (!uncertain) notice = ''; accept(next, recoveryCommand); }
      } catch (error) {
        if (!disposed && token === epoch) { notice = `Status unavailable. Last confirmed evidence is retained. ${error.message}`; emit(); }
      } finally { read = null; poll(); }
    })();
    return read;
  }
  async function action(action, fixture = 'register', recovery = false) {
    if (disposed || !(recovery && action === 'create' ? model().canRecoverCreate : model().allowed[action])) return false;
    const commandId = options.commandId ? options.commandId() : crypto.randomUUID();
    const body = ownedVmBuildAction(view, action, commandId, fixture), before = view, previousUncertain = uncertain;
    const token = ++epoch; pending.set(commandId, {action, command_id: commandId});
    if (recovery) { uncertain = {...uncertain, recovery_ready: false}; notice = 'The earlier Create may still take effect. A fresh command was explicitly requested; it may be rejected if the one allowed fixture already exists. This does not cancel the earlier request.'; }
    else notice = '';
    emit();
    try {
      const next = await response('/api/vm-debugger/actions', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}, 9000);
      ownedVmAssert(next.command_id === commandId && next.ack !== 'pending', 'The control acknowledgment has a different command identity.');
      ownedVmAssert(action === 'create' || next.backend_instance_id === body.backend_instance_id, 'The backend changed before the control was acknowledged.');
      if (!['create', 'reset', 'close'].includes(action)) ownedVmAssert(ownedVmSameRun(body, next.session), 'The acknowledgment belongs to another run.');
      if (action === 'reset') ownedVmAssert(next.session && next.session.session_id === body.session_id && !ownedVmSameRun(body, next.session), 'Reset did not acknowledge a new run.');
      if (action === 'close') ownedVmAssert(next.session === null, 'Close has not acknowledged disposal.');
      if (!disposed && (token === epoch || sameScope(view, before) && sameScope(before, next))) {
        if (next.ack === 'outcome_unknown') uncertain = {command_id: commandId, action};
        accept(next);
      }
      return next.ack === 'completed';
    } catch (error) {
      if (!disposed && (token === epoch || sameScope(view, before))) {
        // A lost HTTP response is not rollback. Even a generic 409 is not a
        // license to replay; status reconciliation is the only automatic step.
        const rejected = ['invalid_request', 'state_conflict', 'stale_generation', 'dependency_unavailable'].includes(error.code);
        uncertain = recovery && previousUncertain ? {...previousUncertain, recovery_ready: false} :
          {command_id: commandId, action, rejected, backend_instance_id: before.backend_instance_id, recovery_ready: false};
        notice = recovery ? `Fresh Create attempt ${rejected ? 'rejected' : 'unconfirmed'}. The earlier Create may still take effect. Neither request was automatically retried or cancelled. ${error.message}` :
          rejected ? `Control request rejected (${action}). Refresh status for current guards. No command was retried. ${error.message}` :
          `Control result unconfirmed (${action}). No command was retried. Refresh status to reconcile; cancellation is not rollback. ${error.message}`;
      }
      return false;
    } finally {
      pending.delete(commandId); emit();
      if (!disposed) { if (read) poll(); else void refresh(); }
    }
  }
  return {model, refresh, action, recoverCreate: fixture => action('create', fixture, true),
    setVisible(next) { visible = !!next; if (visible && !read) void refresh(); else if (!visible && timer !== null) { unschedule(timer); timer = null; } },
    destroy() { disposed = true; epoch++; if (timer !== null) unschedule(timer); timer = null; },
  };
}

let ownedVmMountCount = 0;
function mountOwnedVmDebugger(root, options = {}) {
  const doc = root.ownerDocument || document, prefix = `owned-vm-${++ownedVmMountCount}`;
  const element = (tag, text = '', className = '') => {
    const node = doc.createElement(tag); node.textContent = text; if (className) node.className = className; return node;
  };
  const button = (text, callback) => { const node = element('button', text); node.type = 'button'; node.addEventListener('click', callback); return node; };
  const paragraph = (owner, text, className = '') => { const node = element('p', text, className); owner.append(node); return node; };
  const same = (a, b) => a?.bits === b?.bits && a?.evidence === b?.evidence;
  const opName = (opcode, fixture) => ({1: fixture === 'stack' ? 'PUSH_IMMEDIATE' : 'LOAD_IMMEDIATE', 2: 'ADD', 3: 'STORE',
    4: 'LOAD', 5: 'BRANCH_ZERO', 6: 'JUMP', 7: 'BRANCH_NONZERO', 8: 'HALT'})[opcode] || 'unknown opcode';
  const table = (owner, headings, className) => {
    const node = element('table', '', className), head = element('thead'), row = element('tr'), body = element('tbody');
    for (const label of headings) { const th = element('th', label); th.scope = 'col'; row.append(th); }
    head.append(row); node.append(head, body); const scroll = element('div', '', 'owned-vm-debugger-table-scroll');
    scroll.append(node); owner.append(scroll); const rows = new Map();
    return values => {
      const keep = new Set();
      for (const [key, cells, changed] of values) {
        keep.add(key); let entry = rows.get(key);
        if (!entry) { const tr = element('tr'); entry = {node: tr, cells: cells.map(() => element('td'))}; tr.append(...entry.cells); rows.set(key, entry); body.append(tr); }
        entry.node.setAttribute('data-changed', String(!!changed));
        entry.cells.forEach((cell, i) => { if (cell.textContent !== cells[i]) cell.textContent = cells[i]; });
      }
      for (const [key, entry] of rows) if (!keep.has(key)) { entry.node.remove(); rows.delete(key); }
    };
  };
  root.classList?.add('owned-vm-debugger');
  const toolbar = element('section', '', 'owned-vm-debugger-toolbar'); toolbar.setAttribute('aria-label', 'Live owned native fixture controls');
  const heading = element('strong', 'Live owned native fixture');
  const fixtureLabel = element('label', 'Fixture '), fixture = element('select'); fixture.setAttribute('aria-label', 'Owned native fixture');
  for (const name of ['register', 'stack']) { const option = element('option', name === 'register' ? 'Register fixture' : 'Stack fixture'); option.value = name; fixture.append(option); }
  fixture.value = 'register'; fixtureLabel.append(fixture);
  const controls = element('div', '', 'owned-vm-debugger-actions');
  const status = paragraph(toolbar, 'Reading debugger capability…', 'owned-vm-debugger-status');
  const notice = paragraph(toolbar, '', 'owned-vm-debugger-notice'); notice.setAttribute('role', 'status'); notice.setAttribute('aria-live', 'polite');
  const announcement = element('span', '', 'owned-vm-debugger-announcement'); announcement.setAttribute('role', 'status'); announcement.setAttribute('aria-live', 'polite');
  const buttons = {}; let controller;
  for (const [action, text] of [['create', 'Create paused fixture'], ['run', 'Run'], ['pause', 'Pause'], ['step', 'Step instruction'], ['stop', 'Stop'], ['reset', 'Reset'], ['close', 'Close fixture']]) {
    const node = button(text, () => controller.action(action, fixture.value)); node.setAttribute('data-owned-vm-action', action); buttons[action] = node; controls.append(node);
  }
  const refresh = button('Refresh status', () => controller.refresh()); refresh.setAttribute('data-owned-vm-refresh', ''); controls.append(refresh);
  const recoverCreate = button('Create new attempt', () => controller.recoverCreate(fixture.value)); recoverCreate.setAttribute('data-owned-vm-recover-create', ''); recoverCreate.hidden = true; controls.append(recoverCreate);
  const recoveryWarning = paragraph(toolbar, '', 'owned-vm-debugger-recovery');
  toolbar.prepend(heading, fixtureLabel, controls); toolbar.append(announcement);
  paragraph(toolbar, 'Leaving this view does not pause the native fixture. A run expires after 60 seconds, including time paused. Only these two compiled programs can run.', 'owned-vm-debugger-disclosure');
  const panes = element('div', '', 'owned-vm-debugger-panes');
  const navigation = element('nav', '', 'owned-vm-debugger-navigation'); navigation.setAttribute('aria-label', 'Owned fixture and opcode navigation');
  navigation.append(element('h3', 'Fixture / opcodes')); const provenance = paragraph(navigation, 'No fixture has been created.');
  const opcodes = element('div', '', 'owned-vm-debugger-opcodes'); navigation.append(opcodes);
  paragraph(navigation, 'Opcode names are declared fixture semantics. This provider has no captured Traffic, browser document or site identity.');
  const listing = element('section', '', 'owned-vm-debugger-listing'); listing.setAttribute('aria-label', 'Retained native execution'); listing.append(element('h3', 'Retained execution'));
  const executionCursor = paragraph(listing, 'No execution cursor.', 'owned-vm-debugger-cursor');
  const initial = button('Initial snapshot · no completed instruction', () => select('initial'));
  initial.setAttribute('data-owned-vm-initial', ''); const follow = button('Return to live cursor', () => select('live'));
  follow.setAttribute('data-owned-vm-follow', ''); listing.append(initial, follow);
  const historyStatus = paragraph(listing, 'Retained history is empty.');
  const history = element('ol', '', 'owned-vm-debugger-history'); history.setAttribute('aria-label', 'Completed retained instructions'); listing.append(history);
  const inspector = element('section', '', 'owned-vm-debugger-inspector'); inspector.setAttribute('aria-label', 'Owned native state inspector');
  const selectionLabel = element('h3', 'Live snapshot'); inspector.append(selectionLabel);
  const tabs = element('div', '', 'owned-vm-debugger-tabs'); tabs.setAttribute('role', 'tablist'); tabs.setAttribute('aria-label', 'Native instruction and state');
  const tabButtons = {}, panels = {}; let tab = 'instruction';
  const showTab = name => {
    tab = name;
    for (const key of Object.keys(panels)) { panels[key].hidden = key !== tab; tabButtons[key].setAttribute('aria-selected', String(key === tab)); tabButtons[key].tabIndex = key === tab ? 0 : -1; }
  };
  for (const name of ['instruction', 'registers', 'stack', 'memory']) {
    const node = button(name[0].toUpperCase() + name.slice(1), () => showTab(name)); node.id = `${prefix}-tab-${name}`;
    node.setAttribute('role', 'tab'); node.setAttribute('aria-controls', `${prefix}-panel-${name}`); tabButtons[name] = node; tabs.append(node);
    const panel = element('div', '', 'owned-vm-debugger-state-panel'); panel.id = `${prefix}-panel-${name}`; panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', node.id); panels[name] = panel;
    node.addEventListener('keydown', event => {
      if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || event.isComposing || event.repeat) return;
      const names = Object.keys(tabButtons), index = names.indexOf(name);
      const next = event.key === 'ArrowRight' ? (index + 1) % names.length : event.key === 'ArrowLeft' ? (index + names.length - 1) % names.length : event.key === 'Home' ? 0 : event.key === 'End' ? names.length - 1 : -1;
      if (next < 0) return; event.preventDefault(); showTab(names[next]); tabButtons[names[next]].focus();
    });
  }
  inspector.append(tabs, ...Object.values(panels)); showTab(tab);
  const instructionSummary = paragraph(panels.instruction, 'Create a paused fixture to inspect its initial state.');
  panels.instruction.append(element('h4', 'Typed operands')); const paintOperands = table(panels.instruction, ['Location', 'Index', 'Value / evidence'], 'owned-vm-debugger-operands');
  panels.instruction.append(element('h4', 'Explicit effects')); const paintEffects = table(panels.instruction, ['Access', 'Location', 'Index', 'Value / evidence'], 'owned-vm-debugger-effects');
  const stateEmpty = {}, paintState = {};
  for (const name of ['registers', 'stack', 'memory']) {
    stateEmpty[name] = paragraph(panels[name], 'No snapshot is available.');
    paintState[name] = table(panels[name], ['Location', 'Before', 'After / snapshot', 'Change', 'Explicit accesses'], `owned-vm-debugger-${name}`);
  }
  paragraph(panels.memory, 'Addresses are guest addresses, never process pointers. Absent, unknown and observed zero are distinct.');
  const coverage = paragraph(inspector, '', 'owned-vm-debugger-coverage');
  const audit = element('details', '', 'owned-vm-debugger-audit'), auditSummary = element('summary', 'Raw native audit and provenance');
  const auditText = element('pre'); audit.append(auditSummary, auditText); inspector.append(audit);
  panes.append(navigation, listing, inspector); root.append(toolbar, panes);
  const rows = new Map(), opcodeButtons = new Map(); let selection = 'live', opcodeFilter = null, activeScope = null, lastAnnouncement = '', visible = true, focusTransfer = null;
  const trackFocus = event => { if (focusTransfer && event.target !== refresh) focusTransfer.userMoved = true; };
  doc.addEventListener?.('focusin', trackFocus);
  const select = target => { selection = target; render(controller.model()); };
  function render(model) {
    const view = model.view, session = view?.session, scope = session ? JSON.stringify(ownedVmScope(session)) : null;
    root.setAttribute('data-owned-vm-state', session?.state || 'idle');
    root.setAttribute('data-owned-vm-executed', session?.executed_count || '0');
    if (scope !== activeScope) {
      // A replaced exact run removes these controls. Move focus only if its
      // current owner is one of the nodes that will actually disappear.
      const removedFocus = [...rows.values()].some(row => row.button === doc.activeElement) || [...opcodeButtons.values()].includes(doc.activeElement);
      if (removedFocus) refresh.focus();
      activeScope = scope; selection = 'live'; opcodeFilter = null;
      for (const row of rows.values()) row.item.remove(); rows.clear();
      opcodes.replaceChildren(); opcodeButtons.clear();
    }
    root.setAttribute('data-owned-vm-selection', selection);
    const focusedAction = Object.entries(buttons).find(([, node]) => node === doc.activeElement)?.[0];
    const recoveryFocused = doc.activeElement === recoverCreate;
    const startingCommand = model.pending.find(item => item.action === (recoveryFocused ? 'create' : focusedAction));
    if (focusedAction && !model.allowed[focusedAction] || startingCommand && recoveryFocused) {
      const source = recoveryFocused ? recoverCreate : buttons[focusedAction];
      // Handoff occurs before native disabled/hidden changes can blur. The
      // stable fallback itself never executes and remains enabled on failures.
      refresh.focus(); focusTransfer = startingCommand ? {source, commandId: startingCommand.command_id, userMoved: false} : null;
    }
    for (const action of ownedVmActions) buttons[action].disabled = !model.allowed[action];
    recoverCreate.hidden = !model.canRecoverCreate && !recoveryFocused;
    recoverCreate.disabled = !model.canRecoverCreate && !recoveryFocused;
    recoverCreate.setAttribute('aria-disabled', String(!model.canRecoverCreate));
    if (!model.canRecoverCreate && recoveryFocused && !startingCommand) recoverCreate.textContent = 'Create recovery no longer needed';
    else recoverCreate.textContent = 'Create new attempt';
    recoveryWarning.textContent = model.canRecoverCreate ? 'The earlier Create may still take effect. A new explicit command may be rejected if it already created the one allowed fixture. This does not cancel the earlier request.' : '';
    if (focusTransfer && !model.pending.some(item => item.command_id === focusTransfer.commandId)) {
      const transfer = focusTransfer; focusTransfer = null;
      if (!transfer.userMoved && doc.activeElement === refresh && !transfer.source.disabled && !transfer.source.hidden) transfer.source.focus();
    }
    const fixtureDisabled = !!session || model.pending.length > 0 || !view?.available;
    if (doc.activeElement === fixture && fixtureDisabled || doc.activeElement === initial && !session?.initial_snapshot || doc.activeElement === follow && !session) refresh.focus();
    fixture.disabled = fixtureDisabled;
    if (session) fixture.value = session.fixture;
    const pendingText = model.pending.map(item => `${item.action} requested; awaiting acknowledgment`).join('; ');
    const state = session?.state || 'idle';
    status.textContent = !view ? (model.notice ? 'Live fixture status unavailable.' : 'Reading debugger capability…') : !view.available ? `Live fixture unavailable: ${view.unavailable_reason || 'this server does not provide native execution'}.` :
      session ? `${state} · PC ${session.current_snapshot ? ownedVmPC(session.current_snapshot) : 'unavailable'} · executed ${session.executed_count} · retained ${session.retained_count}${session.execution_state_known ? '' : state === 'starting' ? ' · awaiting initial snapshot' : ' · execution state unknown'}${pendingText ? ` · ${pendingText}` : ''}${visible && doc.visibilityState !== 'hidden' ? '' : ' · last observed; details hidden'}` : 'Available · no fixture created · Create starts paused.';
    if (notice.textContent !== model.notice) notice.textContent = model.notice;
    const announced = session && !['running', 'starting', 'pausing', 'stepping', 'stopping'].includes(state) ? `${scope}:${state}:${session.last_command?.command_id || ''}` : '';
    if (announced && announced !== lastAnnouncement) { announcement.textContent = `Native fixture ${state}. ${session.executed_count} instructions confirmed.`; lastAnnouncement = announced; }
    initial.disabled = !session?.initial_snapshot; follow.disabled = !session; follow.setAttribute('aria-pressed', String(selection === 'live'));
    if (!session) {
      executionCursor.textContent = 'No execution cursor.'; historyStatus.textContent = 'Retained history is empty. Creation does not execute instruction zero.';
      provenance.textContent = 'Choose one of the two fixed repository-owned fixtures. No program, input or address can be supplied.';
      selectionLabel.textContent = 'No live fixture'; instructionSummary.textContent = 'Create a paused fixture to inspect its initial state.';
      paintOperands([]); paintEffects([]); for (const name of Object.keys(paintState)) { paintState[name]([]); stateEmpty[name].textContent = 'No snapshot is available.'; }
      coverage.textContent = ''; auditText.textContent = view ? JSON.stringify(view, null, 2) : ''; return;
    }
    provenance.textContent = `${session.fixture} · ${session.program_id} · revision ${session.fixture_revision}\nProvider: ${session.provider}\nTarget: owned_fixture\nRun: ${session.run_id}\nGeneration: ${session.run_generation}`;
    executionCursor.textContent = `Live execution cursor: ${session.current_snapshot ? `PC ${ownedVmPC(session.current_snapshot)}` : 'not yet confirmed'} · ${session.executed_count} completed${session.execution_state_known ? '' : ' · stale, outcome unknown'}. Selected history never moves this cursor.`;
    if (selection !== 'live' && selection !== 'initial' && !session.records.some(record => record.sequence === selection)) selection = 'live';
    root.setAttribute('data-owned-vm-selection', selection);
    const opcodeSet = [...new Set(session.records.map(record => record.opcode))];
    if (!opcodeButtons.has('all')) {
      const all = button('All retained opcodes', () => { opcodeFilter = null; render(controller.model()); }); opcodeButtons.set('all', all); opcodes.append(all);
    }
    for (const opcode of opcodeSet) if (!opcodeButtons.has(opcode)) {
      const node = button(`${opcode} · ${opName(opcode, session.fixture)}`, () => { opcodeFilter = opcode; render(controller.model()); }); opcodeButtons.set(opcode, node); opcodes.append(node);
    }
    for (const [opcode, node] of opcodeButtons) node.setAttribute('aria-pressed', String(opcode === 'all' ? opcodeFilter === null : opcodeFilter === opcode));
    const displayed = session.records.filter(record => opcodeFilter === null || record.opcode === opcodeFilter);
    historyStatus.textContent = `${displayed.length} shown / ${session.retained_count} retained / ${session.executed_count} executed. ${selection === 'live' ? 'Following live.' : 'History selection pinned; live execution continues independently.'}`;
    let previousSequence = 0n;
    for (const record of session.records) {
      let row = rows.get(record.sequence);
      if (!row) {
        const item = element('li'), node = button('', () => select(record.sequence)); node.setAttribute('data-owned-vm-sequence', record.sequence);
        node.addEventListener('keydown', event => {
          if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || event.isComposing || event.repeat) return;
          const current = controller.model().view?.session?.records.filter(value => opcodeFilter === null || value.opcode === opcodeFilter) || [];
          const index = current.findIndex(value => value.sequence === record.sequence);
          const next = event.key === 'ArrowDown' ? Math.min(current.length - 1, index + 1) : event.key === 'ArrowUp' ? Math.max(0, index - 1) : event.key === 'Home' ? 0 : event.key === 'End' ? current.length - 1 : -1;
          if (next < 0 || !current[next]) return; event.preventDefault(); select(current[next].sequence); rows.get(current[next].sequence)?.button.focus();
        });
        item.append(node); row = {item, button: node}; rows.set(record.sequence, row); history.append(item);
      }
      row.item.hidden = opcodeFilter !== null && record.opcode !== opcodeFilter;
      row.button.textContent = `#${record.sequence} · PC ${ownedVmPC(record.before)} → ${ownedVmPC(record.after)} · ${opName(record.opcode, session.fixture)} · opcode ${record.opcode_evidence}${record.partial ? ' · partial' : ''}${BigInt(record.sequence) > previousSequence + 1n ? ' · retained sequence gap before this row' : ''}`;
      previousSequence = BigInt(record.sequence);
      row.button.setAttribute('aria-pressed', String(selection === record.sequence));
      row.button.setAttribute('aria-current', String(selection === record.sequence));
    }
    const record = selection === 'live' ? session.records.find(value => value.sequence === session.executed_count) : session.records.find(value => value.sequence === selection);
    const snapshot = selection === 'initial' ? session.initial_snapshot : record ? record.after : session.current_snapshot;
    const before = record?.before || null, after = record?.after || snapshot;
    selectionLabel.textContent = selection === 'initial' ? 'Initial snapshot · zero completed instructions' : selection === 'live' ? 'Following live cursor' : `Retained instruction #${selection}`;
    instructionSummary.textContent = record ? `Completed #${record.sequence} · ${opName(record.opcode, session.fixture)} (declared fixture semantics) · opcode ${record.opcode}, ${record.opcode_evidence} · PC ${ownedVmPC(record.before)} → ${ownedVmPC(record.after)} · tick ${record.tick} ${session.tick_units} · partial: ${record.partial || before.partial || after.partial}` :
      snapshot ? `${selection === 'initial' ? 'Initial snapshot, not a completed instruction.' : 'Current native snapshot; no retained transition for this cursor.'} PC ${ownedVmPC(snapshot)} · halted ${snapshot.halted} · partial ${snapshot.partial}` : 'The native initial snapshot has not been acknowledged.';
    paintOperands((record?.operands || []).map((operand, index) => [String(index), [operand.location, operand.index, ownedVmFormatValue(operand.value)]]));
    paintEffects((record?.effects || []).map((effect, index) => [String(index), [effect.access, effect.location, effect.index, ownedVmFormatValue(effect.value)]]));
    for (const name of Object.keys(paintState)) {
      const location = name === 'registers' ? 'register' : name;
      const entries = state => new Map(!state ? [] : name === 'memory' ? state.memory.map(cell => [cell.guest_address, cell.value]) : state[name].map((value, index) => [String(index), value]));
      const left = entries(before), right = entries(after), keys = [...new Set([...left.keys(), ...right.keys()])].sort((a, b) => BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0);
      paintState[name](keys.map(key => {
        const changed = !!before && !same(left.get(key), right.get(key));
        const accesses = (record?.effects || []).filter(effect => effect.location === location && effect.index === key).map(effect => `${effect.access}: ${ownedVmFormatValue(effect.value)}`).join('; ');
        return [key, [`${location}:${key}`, before ? ownedVmFormatValue(left.get(key)) : 'not applicable', ownedVmFormatValue(right.get(key)), before ? changed ? 'changed' : 'unchanged' : 'snapshot', accesses || (record ? 'none reported' : 'not a transition')], changed];
      }));
      stateEmpty[name].textContent = !snapshot ? 'No confirmed snapshot.' : keys.length ? `${keys.length} active or before/after locations. Values retain their evidence classification.` : `No active ${name} cells in this snapshot. This is absence, not zero.`;
    }
    const stats = session.recorder.stats;
    coverage.textContent = `Recorder attempted ${stats.attempted}, retained ${stats.recorded}; full ${stats.full}, malformed ${stats.malformed}, wrong document ${stats.wrong_document}, stale generation ${stats.stale_generation}, exhausted ${stats.exhausted}, expired ${stats.expired}, partial ${stats.partial}. Loss counters are separate facts, not a summed gap count. Control termination: ${session.termination_reason || 'none'}.`;
    if (session.disposal_failed) coverage.textContent += ' Helper disposal failed; replacement blocked.';
    if (session.diagnostics.stderr_truncated) coverage.textContent += ' Native diagnostic stream was truncated.';
    auditText.textContent = JSON.stringify({view, selection: {mode: selection === 'live' || selection === 'initial' ? selection : 'retained', sequence: record?.sequence || null}, selected_record: record || null}, null, 2);
  }
  const adjacent = direction => {
    const retained = (controller.model().view?.session?.records || []).filter(record => opcodeFilter === null || record.opcode === opcodeFilter);
    const index = retained.findIndex(record => record.sequence === selection);
    return retained[index < 0 ? direction > 0 ? 0 : retained.length - 1 : index + direction];
  };
  root.addEventListener('vm-workspace-query', event => Object.assign(event.detail, {search: opcodeButtons.size > 0, previous: !!adjacent(-1), next: !!adjacent(1)}));
  root.addEventListener('vm-workspace-search', () => { opcodeButtons.values().next().value?.focus(); });
  for (const [action, direction] of [['previous', -1], ['next', 1]]) root.addEventListener(`vm-workspace-${action}`, () => {
    const record = adjacent(direction); if (!record) return;
    select(record.sequence); const target = rows.get(record.sequence)?.button; target?.focus(); target?.scrollIntoView?.({block: 'nearest'});
  });
  controller = createOwnedVmController({...options, onChange: render});
  const visibility = () => { controller.setVisible(visible && doc.visibilityState !== 'hidden'); render(controller.model()); };
  doc.addEventListener?.('visibilitychange', visibility); render(controller.model()); visibility();
  return {toolbar, panes, buttons, fixture, status, notice, history, inspector, tabs: tabButtons, follow, initial, recoverCreate, refreshButton: refresh, controller,
    refresh: () => controller.refresh(),
    setVisible(next) { visible = !!next; panes.hidden = !visible; visibility(); },
    destroy() { controller.destroy(); doc.removeEventListener?.('visibilitychange', visibility); doc.removeEventListener?.('focusin', trackFocus); },
  };
}
if (typeof module === 'object' && module?.exports) module.exports = {
  mountOwnedVmDebugger, createOwnedVmController, ownedVmParseJSON, ownedVmValidateView, ownedVmSnapshot,
  ownedVmRecord, ownedVmU64, ownedVmFormatValue, ownedVmBuildAction, ownedVmSameRun,
};
