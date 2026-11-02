import assert from 'node:assert/strict';
import {runInNewContext} from 'node:vm';
import {readFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {selfTest} from './saved-traffic-fixture.mjs';
const root=resolve(process.argv[2]||'.');
await checkTrafficActivation(root);
await selfTest(root);
// Exercise production refresh and navigation functions, not a copied rendering
// condition. Other workspaces are spies: this checks the Traffic lifecycle only.
async function checkTrafficActivation(root) {
  const app = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
  const extract = (start, end) => {
    const first = app.indexOf(start), last = app.indexOf(end, first);
    assert(first >= 0 && last > first, `Missing production boundary: ${start}`);
    return app.slice(first, last);
  };
  const refresh = extract('      async function refresh()', '      function useStandalonePreview()');
  const show = extract('      function showScreen(', '      async function refresh()');
  const screens = ['traffic', 'sources', 'signals', 'api-collection'].map(name =>
    ({id: 'screen-' + name, hidden: name !== 'sources'}));
  const old = {id: 'old'}, added = {id: 'captured-while-hidden'};
  const state = {events: [], requests: [old], nativeRequests: [old], selectedRequestId: old.id,
    signalKnownKeys: null, signalNewKeys: new Set(), refreshing: false};
  let painted = [old], summary = old, inspector = old, status = 200, fetches = 0;
  let body = {events: [], network_events: [old, added], capture_mode: 'live', broker_connected: true};
  const context = {
    state, location: {protocol: 'http:'}, elements: {gaps: {}},
    document: {hidden: false, activeElement: null,
      getElementById: id => screens.find(screen => screen.id === id),
      querySelector(selector) {
        if (selector === '#advanced-navigation') return {contains: () => false};
        return screens.find(screen => '#' + screen.id === selector);
      },
      querySelectorAll: selector => selector === '.screen' ? screens : []},
    fetch: async path => {
      assert.equal(path, '/api/events?limit=5000', 'Refresh must use native broker events, not a debugger endpoint');
      fetches++;
      return {status, ok: status < 400, text: async () => JSON.stringify(body), headers: {get: () => '"native-fixture"'}};
    },
    isBrokerResponse: value => Array.isArray(value.events),
    fingerprintEventsFromEvents: () => [], signalEventKey: value => value,
    vmFindingsFromEvents: () => ({findings: [], malformedCount: 0}), vmVisibleFindings: () => [],
    requestsFromEvents: rows => rows,
    rebuildTrafficRequests: () => {state.requests = state.nativeRequests;},
    resetRequestSelection: () => {state.selectedRequestId = null;},
    shownSequenceGaps: () => 0n, shownQueueDrops: () => 0n, shownNamedGaps: () => [], eventGapLabel: () => '',
    renderRequests: () => {painted = state.requests.slice();},
    updateSelectionSummary: selected => {summary = selected ?? null;},
    renderInspector: () => {inspector = state.requests.find(row => row.id === state.selectedRequestId) ?? null;},
    evidenceWorkspace: {setVisible() {}}, sourceFactsPanel: {cancel() {}}, float32Panel: {cancel() {}}
  };
  for (const name of ['acceptEventWindow', 'refreshRequestSignalProfile', 'refreshArtifacts',
    'refreshVmAnalysis', 'renderShellStatus', 'renderNetworkNotice', 'renderEvidence',
    'renderVmLab', 'renderFingerprintActivity', 'investigationBeforeScreen', 'retireCanvasPreviews']) context[name] = () => {};
  const api = runInNewContext(refresh + '\n' + show + '\n;({refresh, showScreen})', context);
  const navigationButton = {classList: {contains: () => true}};
  await api.refresh();
  assert.equal(state.eventFailureKind, null);
  assert.deepEqual(JSON.parse(JSON.stringify(state.requests)), [old, added], 'Native refresh retains requests received while Traffic is hidden');
  const beforeActivation = fetches;
  api.showScreen('traffic', navigationButton);
  assert.equal(screens[0].hidden, false);
  assert.deepEqual(JSON.parse(JSON.stringify(painted)), [old, added]);
  assert.equal(summary.id, old.id); assert.equal(inspector.id, old.id);
  assert.equal(fetches, beforeActivation, 'Activation needs no request or capture action');
  status = 304;
  await api.refresh();
  assert.deepEqual(JSON.parse(JSON.stringify(painted)), [old, added], 'Quiet native 304 responses preserve the ledger');
  status = 503;
  await api.refresh();
  assert.equal(state.eventFailureKind, 'disconnected');
  assert.deepEqual(JSON.parse(JSON.stringify(state.requests)), [old, added], 'Failed native refresh preserves last valid evidence');
  screens[0].hidden = true; screens[1].hidden = false;
  status = 200; body = {...body, network_events: []};
  await api.refresh();
  assert.equal(state.eventFailureKind, null); assert.equal(state.selectedRequestId, null);
  api.showScreen('traffic', navigationButton);
  assert.deepEqual(JSON.parse(JSON.stringify(painted)), []); assert.equal(summary, null); assert.equal(inspector, null);
  api.showScreen('traffic', navigationButton);
  assert.deepEqual(JSON.parse(JSON.stringify(painted)), [], 'Repeated activation keeps the empty state');
  console.log('PASS native Traffic refresh/activation, quiet 304, failed-refresh retention, expired selection and repeated navigation (function model; not rendered runtime)');
}
