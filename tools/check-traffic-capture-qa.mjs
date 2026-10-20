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
  const refresh = extract('      async function refreshDebugger(', '      async function refreshArtifacts()');
  const show = extract('      function showScreen(', '      async function refresh()');
  const screens = ['traffic', 'sources', 'experiments', 'api-collection'].map(name =>
    ({id: 'screen-' + name, hidden: name !== 'sources'}));
  const old = {id: 'old'}, added = {id: 'captured-while-hidden'};
  const state = {debuggerSession: {scripts: [], breakpoints: [], state: 'running'},
    requests: [old], openScriptIds: [], openArtifactIds: [], selectedScriptId: null,
    selectedRequestId: old.id, editingBreakpointId: null};
  let painted = [old], summary = old, inspector = old, status = 200, fetches = 0;
  let body = {scripts: [], breakpoints: [], state: 'running', network: {requests: [old, added]}};
  const context = {
    state, location: {protocol: 'http:'},
    document: {hidden: false, activeElement: null,
      querySelector(selector) {
        if (selector === '#advanced-navigation') return {contains: () => false};
        return screens.find(screen => '#' + screen.id === selector);
      },
      querySelectorAll: selector => selector === '.screen' ? screens : []},
    fetch: async () => {
      fetches++;
      return {status, ok: true, json: async () => body, headers: {get: () => '"debugger-fixture"'}};
    },
    isDebuggerResponse: () => true, debuggerScriptCatalogSignature: () => '',
    syncExperimentSession: (_, next) => next,
    rebuildTrafficRequests: () => { state.requests = body.network.requests; },
    resetRequestSelection: () => { state.selectedRequestId = null; },
    renderRequests: () => { painted = state.requests.slice(); },
    updateSelectionSummary: selected => { summary = selected; },
    renderInspector: () => { inspector = state.requests.find(row => row.id === state.selectedRequestId) ?? null; },
    evidenceWorkspace: {setVisible() {}}, sourceFactsPanel: {cancel() {}}, float32Panel: {cancel() {}}
  };
  for (const name of ['syncMemorySession', 'applyMemoryOriginTrace', 'renderLiveBrowserTabCount',
    'pruneLiveScriptContent', 'renderDebugger', 'renderShellStatus', 'renderNetworkNotice',
    'renderMemory', 'renderFieldProvenance', 'scheduleDebuggerRefresh', 'investigationBeforeScreen',
    'retireCanvasPreviews', 'renderRuntimeHookTraffic']) context[name] = () => {};
  const api = runInNewContext(refresh + '\n' + show + '\n;({refreshDebugger, showScreen})', context);
  const navigationButton = {classList: {contains: () => true}};
  await api.refreshDebugger();
  assert.equal(state.debuggerError, null);
  assert.deepEqual(painted, [old], 'Hidden refresh must not repaint the ledger');
  assert.deepEqual(state.requests, [old, added], 'Hidden refresh retains new requests');
  const beforeActivation = fetches;
  api.showScreen('traffic', navigationButton);
  assert.equal(screens[0].hidden, false);
  assert.deepEqual(painted, [old, added], 'Traffic activation paints already retained requests');
  assert.equal(summary, old); assert.equal(inspector, old);
  assert.equal(fetches, beforeActivation, 'Activation needs no request or capture action');
  status = 304;
  await api.refreshDebugger();
  assert.deepEqual(painted, [old, added], 'Quiet 304 responses preserve the current ledger');
  // A reconnect/clear while hidden also invalidates the old detail selection.
  screens[0].hidden = true; screens[1].hidden = false;
  status = 200; body = {...body, network: {requests: []}};
  await api.refreshDebugger();
  assert.equal(state.debuggerError, null); assert.equal(state.selectedRequestId, null);
  assert.equal(summary, old, 'Hidden refresh has not repainted the old summary');
  api.showScreen('traffic', navigationButton);
  assert.deepEqual(painted, []); assert.equal(summary, null); assert.equal(inspector, null);
  api.showScreen('traffic', navigationButton);
  assert.deepEqual(painted, [], 'Repeated activation keeps the empty state');
  console.log('PASS Traffic activation after hidden capture/clear, quiet 304, retained/expired selection and repeated navigation (function harness; not rendered/native runtime)');
}
