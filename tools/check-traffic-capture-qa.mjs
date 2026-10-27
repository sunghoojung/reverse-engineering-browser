import assert from 'node:assert/strict';
import {request} from 'node:http';
import {runInNewContext} from 'node:vm';
import {readFile,mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {fixtureServer,selfTest} from './traffic-capture-qa.mjs';
const root=resolve(process.argv[2]||'.');
await checkTrafficActivation(root);
await selfTest(root);
const {server,change}=await fixtureServer(root);
function get(path,method='GET',host) {
  return new Promise((resolveResponse,reject)=>{
    const call=request({hostname:'127.0.0.1',port:server.address().port,path,method,headers:host?{Host:host}:{}},response=>{
      const chunks=[];response.on('data',chunk=>chunks.push(chunk));response.on('end',()=>resolveResponse({status:response.statusCode,body:Buffer.concat(chunks),headers:response.headers}));
    });call.on('error',reject);call.end();
  });
}
try {
  await new Promise((ready,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',ready);});
  for(const variant of ['baseline','epoch','instance','target','truncated','states','clear','off']) {
    change(variant);const response=await get('/api/debugger?wait_ms=25000'),data=JSON.parse(response.body);
    assert.equal(response.status,200);
    assert.equal(data.network.requests.length,['clear','off'].includes(variant)?0:variant==='truncated'?1:variant==='states'?4:3);
  }
  for (const [path,status] of [['/',200],['/?native=1',200],['/traffic_view.js',200],['/api/events',200],['/api/artifacts',200],['/api/unknown',503],['/analyst_runner_core.js',404],['/%69ndex.html',404],['//index.html',404],['/../index.html',404],['/index.html/extra',404]]) assert.equal((await get(path)).status,status,path);
  assert.deepEqual((await get('/traffic_view.js')).body,await readFile(join(root,'apps/research-ui/traffic_view.js')));
  change('disconnect');assert.equal((await get('/api/debugger')).status,503);
  change('malformed');assert.deepEqual(JSON.parse((await get('/api/debugger')).body),{malformed:true});
  change('baseline');assert.equal((await get('/api/debugger')).status,200);
  assert.equal((await get('/api/debugger','POST')).status,405);
  assert.equal((await get('/','GET','foreign.example')).status,400);
  console.log('PASS loopback HTTP variants, failure/recovery, exact public assets, rejected writes/foreign Host/private/encoded/ambiguous paths');
} finally {server.closeAllConnections();await new Promise(done=>server.close(done));}
const temporary=await mkdtemp(join(tmpdir(),'reb-qa-assets-'));
const original=process.env.REB_QA_ASSET_DIR;
try {
  process.env.REB_QA_ASSET_DIR=temporary;
  await writeFile(join(temporary,'index.html'),'Synthetic mismatched bundle');
  await assert.rejects(fixtureServer(root),/Bundle\/source mismatch: index.html|ENOENT/);
  console.log('PASS missing or mismatched packaged assets refuse fixture startup');
} finally {
  if(original===undefined)delete process.env.REB_QA_ASSET_DIR;else process.env.REB_QA_ASSET_DIR=original;
  await rm(temporary,{recursive:true,force:true});
}

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
    shownSequenceGaps: () => 0n, shownQueueDrops: () => 0n, eventGapLabel: () => '',
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
