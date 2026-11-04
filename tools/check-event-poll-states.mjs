// Event poll connection states and the Stop/Clear capture actions, exercised
// through the production refresh(), setEventConnection() and
// performCaptureAction() with a scripted loopback backend. Deadlines are fired
// by the script instead of waiting 10 or 15 seconds. This is a function model,
// not rendered UI; make rendered-ui-check covers the packaged window.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';

const read = name => readFile(new URL(`../apps/research-ui/${name}`, import.meta.url), 'utf8');
const [models, app, appState] = await Promise.all([read('evidence_models.js'), read('app.js'), read('app_state.js')]);
const section = (start, end) => {
  const first = app.indexOf(start), last = app.indexOf(end, first);
  assert(first >= 0 && last > first, `Missing production boundary: ${start}`);
  return app.slice(first, last);
};

// The real initial state, so new fields cannot be missing from it.
const stub = () => ({});
const initialState = () => runInNewContext(`${appState};state`, {
  location: {search: '', protocol: 'http:'}, URLSearchParams, Map, Set,
  document: {querySelector: stub, querySelectorAll: () => [], documentElement: {classList: {add() {}}}}
});

const event = sequence => ({
  protocol_version: 3, session_id: '7', sequence_number: String(sequence), monotonic_time_ns: String(sequence),
  navigation_id: '1', frame_id: '1', artifact_id: '0', parent_event_id: '0', request_id: String(sequence),
  process_id: 11, thread_id: 1, tab_id: 1, category: 'network', type: 'request_initiated',
  payload_encoding: 'hex', payload: '', payload_size: 0, browser_context_id_high: '0', browser_context_id_low: '0',
  encoded_data_length: '0', decoded_body_length: '0', status_code: 0, error_code: 0, resource_type: 1, flags: 0,
  payload_truncated: false, initiator_request_id: 0, initiator_process_id: 0
});
const answer = (events, extra = {}) => ({events, count: events.length, capture_mode: 'live', broker_connected: true,
  capture_stopped: false, capture_controls_available: true, ...extra});

function harness() {
  const state = initialState();
  const pending = [];
  const deadlines = [];
  const calls = {posts: 0, dependents: 0, vm: 0, renders: 0, confirms: 0};
  let holdVm = null;
  // A deadline the script fires. The production code passes it to fetch and
  // reads its aborted flag, exactly as with AbortSignal.timeout().
  const AbortSignal = {timeout(ms) {
    const controller = new AbortController();
    deadlines.push({ms, fire: () => controller.abort(new DOMException('The operation timed out.', 'TimeoutError')), signal: controller.signal});
    return controller.signal;
  }};
  const fetch = (path, options = {}) => new Promise((resolve, reject) => {
    const request = {path, options, resolve, reject, body: options.body ? JSON.parse(options.body) : null};
    if (options.method === 'POST') calls.posts += 1;
    options.signal?.addEventListener('abort', () => {
      if (pending.includes(request)) pending.splice(pending.indexOf(request), 1);
      reject(options.signal.reason);
    }, {once: true});
    pending.push(request);
  });
  const reply = (request, value, status = 200) => request.resolve({ok: status < 400, status,
    headers: {get: () => `"poll-${pending.length}"`},
    text: async () => typeof value === 'string' ? value : JSON.stringify(value), json: async () => value});
  const button = () => ({disabled: false});
  const elements = {gaps: {textContent: ''}, signalStopCapture: button(), signalClearEvents: button()};
  const noop = () => {};
  const context = {
    state, elements, AbortSignal, fetch, TextEncoder, TextDecoder, TypeError, DOMException,
    window: {confirm: () => { calls.confirms += 1; return true; }},
    document: {querySelector: () => ({hidden: true})},
    fingerprintEventsFromEvents: () => [], signalEventKey: value => value,
    vmFindingsFromEvents: () => ({findings: [], malformedCount: 0}),
    rebuildTrafficRequests: () => { state.requests = state.nativeRequests; },
    resetRequestSelection: noop, updateSelectionSummary: noop, renderShellStatus: noop, renderNetworkNotice: noop,
    renderRequests: noop, renderInspector: noop, renderEvidence: noop, renderVmLab: noop, refreshSelectedRequestBody: noop,
    // Production renders re-enable these buttons from state on every poll;
    // the stub does the same, so only explicit action state can refuse a click.
    renderFingerprintActivity: () => { calls.renders += 1; elements.signalStopCapture.disabled = false; elements.signalClearEvents.disabled = false; },
    refreshRequestSignalProfile: async () => { calls.dependents += 1; },
    refreshArtifacts: async () => {},
    refreshVmAnalysis: async () => { calls.vm += 1; if (holdVm) await holdVm.promise; }
  };
  const api = runInNewContext(`${models}\n${section('      async function refresh()', '      function useStandalonePreview()')}\n` +
    `${section('      async function performCaptureAction(', "      elements.signalStopCapture.addEventListener('click'")}\n` +
    ';({refresh, performCaptureAction, setEventConnection})', context);
  const next = path => {
    const index = pending.findIndex(request => request.path.startsWith(path));
    assert(index >= 0, `No pending ${path}; pending: ${pending.map(request => request.path).join(', ')}`);
    return pending.splice(index, 1)[0];
  };
  const settle = () => new Promise(resolve => setTimeout(resolve, 0));
  const hold = () => { let release; const promise = new Promise(resolve => { release = resolve; }); holdVm = {promise, release}; return holdVm; };
  return {state, api, calls, deadlines, pending, next, reply, settle, hold, elements};
}

// A hung backend: the poll gives up after 10 seconds, names that, keeps the
// last valid evidence and withdraws the capture controls it reported.
{
  const t = harness();
  const first = t.api.refresh();
  t.reply(t.next('/api/events'), answer([event(1), event(2)]));
  await first;
  assert.equal(t.state.connection, 'connected');
  assert.equal(t.state.captureControlsAvailable, true);
  assert.equal(t.calls.dependents, 1, 'A valid poll runs its dependent reads');
  const hung = t.api.refresh();
  assert.equal(t.state.refreshing, true);
  const deadline = t.deadlines.at(-1);
  assert.equal(deadline.ms, 10000, 'The event poll is bounded by 10 seconds');
  deadline.fire();
  await hung;
  assert.equal(t.state.refreshing, false, 'A hung backend cannot hold the poll guard');
  assert.equal(t.state.connection, 'unresponsive');
  assert.equal(t.state.broker, 'unavailable');
  assert.equal(t.state.eventFailureKind, 'disconnected');
  assert.equal(t.state.captureControlsAvailable, false, 'Stop and Clear wait for a valid answer');
  assert.equal(t.state.events.length, 2, 'The last valid evidence remains');
  assert.equal(t.state.lastUpdatedLabel, 'last valid evidence retained');
  assert.equal(t.state.eventEtag, null);
  assert.equal(t.calls.dependents, 1, 'A failed poll starts no dependent reads');
  const recovered = t.api.refresh();
  const retry = t.next('/api/events');
  assert.equal(retry.options.headers['If-None-Match'], undefined, 'Recovery reads a complete answer');
  t.reply(retry, answer([event(1), event(2), event(3)]));
  await recovered;
  assert.equal(t.state.connection, 'connected');
  assert.equal(t.state.captureControlsAvailable, true, 'A valid answer restores the controls it reports');
}
{
  const t = harness();
  for (const [failure, connection, kind] of [
    [request => request.reject(new TypeError('Load failed')), 'unreachable', 'disconnected'],
    [request => t.reply(request, '{"events":', 200), 'malformed', 'malformed'],
    [request => t.reply(request, {error: 'busy'}, 503), 'unreachable', 'disconnected']
  ]) {
    t.state.captureControlsAvailable = true;
    const poll = t.api.refresh();
    failure(t.next('/api/events'));
    await poll;
    assert.equal(t.state.connection, connection);
    assert.equal(t.state.eventFailureKind, kind);
    assert.equal(t.state.captureControlsAvailable, false);
  }
  // A broker that is offline after Stop still answers; that is not a failure.
  const poll = t.api.refresh();
  t.reply(t.next('/api/events'), answer([event(1)], {broker_connected: false, capture_stopped: true}));
  await poll;
  assert.equal(t.state.connection, 'broker-offline');
  assert.equal(t.state.broker, 'unavailable');
  assert.equal(t.state.eventFailureKind, null);
  assert.equal(t.state.captureStopped, true);
  assert.equal(t.state.captureControlsAvailable, true);
  t.api.setEventConnection('preview');
  assert.deepEqual([t.state.broker, t.state.eventFailureKind], ['preview', null]);
}
console.log('PASS event poll: 10 s deadline, unresponsive/unreachable/malformed failures withdraw capture controls and keep evidence; broker-offline stays a valid answer');

// A slow dependent read (a cold VM analysis) neither blocks the next poll nor
// is restarted by it, so a later failure is still reported.
{
  const t = harness();
  const vm = t.hold();
  const first = t.api.refresh();
  t.reply(t.next('/api/events'), answer([event(1)]));
  await t.settle();
  assert.equal(t.calls.vm, 1);
  assert.equal(t.state.refreshing, false, 'The poll guard is released before dependent reads');
  const second = t.api.refresh();
  t.reply(t.next('/api/events'), answer([event(1), event(2)]));
  await second;
  assert.equal(t.calls.vm, 1, 'A running chain is not restarted');
  const third = t.api.refresh();
  t.next('/api/events').reject(new TypeError('Load failed'));
  await third;
  assert.equal(t.state.connection, 'unreachable', 'Failure is reported while the chain still runs');
  vm.release();
  await first;
  assert.equal(t.state.refreshingDependents, false);
}
console.log('PASS dependent reads: a running chain is neither awaited by later polls nor restarted');

// Stop: one POST however often the user clicks, and a poll that overlapped the
// action cannot write back the pre-stop state.
{
  const t = harness();
  const initial = t.api.refresh();
  t.reply(t.next('/api/events'), answer([event(1), event(2)]));
  await initial;
  const stalePoll = t.api.refresh();
  const stop = t.api.performCaptureAction('stop');
  assert.equal(t.state.captureAction, 'stop');
  assert.equal(t.elements.signalStopCapture.disabled, false, 'The stub render re-enabled the button');
  await t.api.performCaptureAction('stop');
  await t.api.performCaptureAction('clear');
  assert.equal(t.calls.posts, 1, 'Only one capture action runs');
  t.reply(t.next('/api/events'), answer([event(1), event(2), event(3)], {capture_stopped: false}));
  await stalePoll;
  assert.equal(t.state.events.length, 2, 'The overlapping poll is discarded');
  assert.equal(t.state.captureStopped, false);
  const action = t.next('/api/capture/actions');
  assert.deepEqual(action.body, {action: 'stop'});
  assert.equal(t.deadlines.at(-1).ms, 15000);
  t.reply(action, {ok: true, capture_stopped: true, broker_connected: false});
  await t.settle();
  assert.equal(t.state.captureAction, null);
  assert.equal(t.state.captureStopped, true);
  const fresh = t.next('/api/events');
  assert.equal(fresh.options.headers['If-None-Match'], undefined, 'The action reads a complete fresh answer');
  t.reply(fresh, answer([event(1), event(2), event(3)], {broker_connected: false, capture_stopped: true}));
  await stop;
  assert.equal(t.state.connection, 'broker-offline');
  assert.equal(t.state.captureStopped, true);
  assert.equal(t.state.events.length, 3);
}
// Clear: a poll that began before the clear returns the old events after the
// clear finished; it is discarded and read again.
{
  const t = harness();
  const initial = t.api.refresh();
  t.reply(t.next('/api/events'), answer([event(1), event(2)], {broker_connected: false, capture_stopped: true}));
  await initial;
  const stalePoll = t.api.refresh();
  const clear = t.api.performCaptureAction('clear');
  assert.equal(t.calls.confirms, 1, 'Clear asks first');
  const action = t.next('/api/capture/actions');
  assert.deepEqual(action.body, {action: 'clear', confirm: true});
  t.reply(action, {ok: true, capture_stopped: true, broker_connected: false});
  await t.settle();
  assert.equal(t.pending.length, 1, 'The in-flight poll is the only read; the action does not start a second');
  t.reply(t.next('/api/events'), answer([event(1), event(2), event(3)], {broker_connected: false, capture_stopped: true}));
  await t.settle();
  assert.equal(t.state.events.length, 2, 'The pre-clear answer was not admitted');
  const repeat = t.next('/api/events');
  assert.equal(repeat.options.headers['If-None-Match'], undefined);
  t.reply(repeat, answer([], {broker_connected: false, capture_stopped: true}));
  await stalePoll;
  await clear;
  assert.equal(t.state.events.length, 0, 'The repeated poll shows the cleared session');
  assert.equal(t.calls.posts, 1);
}
// A failed or timed-out action is reported from state, so a re-render cannot
// erase it, and the controls return.
{
  const t = harness();
  const initial = t.api.refresh();
  t.reply(t.next('/api/events'), answer([event(1)]));
  await initial;
  const refused = t.api.performCaptureAction('clear');
  t.reply(t.next('/api/capture/actions'), {error: 'Stop native capture before clearing events'}, 409);
  await t.settle();
  t.reply(t.next('/api/events'), answer([event(1)]));
  await refused;
  assert.equal(t.state.captureActionError, 'Stop native capture before clearing events');
  assert.equal(t.state.captureAction, null);
  const timedOut = t.api.performCaptureAction('stop');
  assert.equal(t.state.captureActionError, null, 'A new action clears the previous outcome');
  t.next('/api/capture/actions');
  t.deadlines.at(-1).fire();
  await t.settle();
  t.reply(t.next('/api/events'), answer([event(1)]));
  await timedOut;
  assert.match(t.state.captureActionError, /Stop did not answer within 15 seconds; its outcome is unknown/);
  assert.equal(t.state.captureAction, null);
  assert.equal(t.state.captureStopped, false, 'An unknown outcome does not claim a stop');
}
console.log('PASS capture actions: one POST per action despite re-renders, overlapping polls discarded and repeated, refused and timed-out outcomes kept in state');
