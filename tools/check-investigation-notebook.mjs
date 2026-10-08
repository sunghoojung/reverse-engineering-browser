import assert from 'node:assert/strict';
import {readFile, mkdtemp, stat, rm} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';
import {webcrypto} from 'node:crypto';
import {investigationFixture} from './check-investigation-navigation.mjs';
const copy = value => JSON.parse(JSON.stringify(value));

export async function notebookModels(root, overrides = {}) {
  const read = path => readFile(join(root, path), 'utf8');
  const app = await read('apps/research-ui/app.js'), state = await read('apps/research-ui/app_state.js');
  const empty = state.slice(state.indexOf('      const emptyLocalAnalystWorkspace'), state.indexOf('      const emptyDecoderEngine'));
  const validator = app.slice(app.indexOf('      const analystExactKeys'), app.indexOf('      function isLocalAnalystRunner'));
  const context = {console, TextEncoder, TextDecoder, Uint8Array, Response, AbortController, setTimeout, clearTimeout, structuredClone, crypto: webcrypto, ...overrides};
  return runInNewContext((await read('apps/research-ui/evidence_models.js'))+'\n'+empty+'\n'+validator+'\n'+
    (await read('apps/research-ui/evidence_package.js'))+'\n'+(await read('apps/research-ui/investigation_navigation.js'))+'\n'+
    (await read('apps/research-ui/investigation_notebook.js'))+'\n;({api:RebInvestigationNotebook,empty:emptyLocalAnalystWorkspace,validateLibrary:isLocalAnalystWorkspace})', context);
}
function fixtureLibrary(empty) {
  const library = copy(empty()); library.generation = 1; library.updated_at_ms = 1000;
  library.files = [{id: 1, folder_id: 1, name: 'Existing research script', kind: 'analyst-script', language: 'javascript', content: 'return "never run by a notebook";', created_at_ms: 1000, updated_at_ms: 1000},
    {id: 2, folder_id: 1, name: 'Existing private note', kind: 'scratchpad', language: 'text', content: 'Synthetic ordinary note stays unchanged.', created_at_ms: 1000, updated_at_ms: 1000}]
    .map(file => ({...file, content_bytes: Buffer.byteLength(file.content)})); return library;
}
function replaceLibrary(library, request) {
  assert.equal(request.action, 'replace_local_analyst_workspace');
  return {...copy(library), generation: library.generation + 1, updated_at_ms: library.updated_at_ms + 1, folders: copy(request.folders),
    files: copy(request.files).map(file => ({...file, content_bytes: Buffer.byteLength(file.content),
      created_at_ms: library.files.find(old => old.id === file.id)?.created_at_ms ?? library.updated_at_ms + 1, updated_at_ms: library.files.find(old => old.id === file.id && ['id','folder_id','name','kind','language','content'].every(key => old[key] === file[key]))?.updated_at_ms ?? library.updated_at_ms + 1}))};
}
const baselineEvent = () => copy(investigationFixture({artifacts: [], handle: async () => false, release() {}}).event);
export async function checkNotebookCore(root) {
  const {api, empty, validateLibrary} = await notebookModels(root);
  assert(api.validate(api.empty()));
  const artifact = {session_id: '11', artifact_id: '7', sha256: 'a'.repeat(64), byte_size: 90, kind: 'javascript'};
  const reference = api.artifactReference(artifact, {start: 1, end: 4});
  const doc = {...copy(api.empty()), next_pin_id: 2, pins: [{id: 1, name: 'Evidence', note: '<script>inert</script>', reference: copy(reference)}]};
  assert(api.validate(doc));
  for (const candidate of [{...doc, permissions: []}, {...doc, next_pin_id: 1}, {...doc, pins: [doc.pins[0], doc.pins[0]]},
    {...doc, pins: [{...doc.pins[0], note: '雪'.repeat(683)}]}, {...doc, pins: [{...doc.pins[0], name: '\ud800'}]},
    {...doc, pins: [{...doc.pins[0], reference: {...reference, url: 'https://fixture.invalid'}}]}]) assert.equal(api.validate(candidate), false);
  const bounded = {...copy(api.empty()), next_pin_id: 65, pins: Array.from({length: 64}, (_, index) => ({...copy(doc.pins[0]), id: index + 1, note: ''}))};
  assert(api.validate(bounded)); assert.equal(api.validate({...bounded, next_pin_id: 66, pins: [...bounded.pins, {...copy(doc.pins[0]), id: 65}]}), false);
  let remaining = 32768 - Buffer.byteLength(JSON.stringify(bounded));
  for (const pin of bounded.pins) {const bytes = Math.min(remaining, 2048); pin.note = 'x'.repeat(bytes); remaining -= bytes;}
  assert.equal(remaining, 0); assert.equal(Buffer.byteLength(JSON.stringify(bounded)), 32768); assert(api.validate(bounded));
  bounded.pins.at(-1).note += 'x'; assert.equal(api.validate(bounded), false);
  assert.throws(() => api.strictParse('{"pins":[],"p\\u0069ns":[]}'), /duplicate/);
  assert.throws(() => api.strictParse('['.repeat(18)+'0'+']'.repeat(18)), /structure/);
  assert.equal(api.strictParse('{"content":"retained\x7ftext"}').content, 'retained\x7ftext');
  assert.throws(() => api.strictParse('{"content":"bad\x01text"}'), /./);
  assert.throws(() => api.strictParse('{"content":"\ud800"}'), /UTF-8/);
  assert.equal(api.validate({...doc, pins: [{...doc.pins[0], name: 'bad\x7fname'}]}), false);
  assert.equal(api.validate({...doc, pins: [{...doc.pins[0], note: 'bad\x7fnote'}]}), false);
  assert.equal(api.readNotebook({kind: 'analyst-script', language: 'javascript', content: JSON.stringify(doc)}), null);
  assert.equal(api.readNotebook({kind: 'scratchpad', language: 'json', content: '{"broken":'}), null);
  let context = {events: [baselineEvent()], artifacts: [artifact]}; const getContext = () => context;
  assert.equal((await api.resolve(reference, getContext)).status, 'ready');
  context.artifacts = [{...artifact, sha256: 'b'.repeat(64)}]; assert.equal((await api.resolve(reference, getContext)).status, 'changed');
  context.artifacts = [artifact, {...artifact, session_id: '12'}]; assert.equal((await api.resolve(reference, getContext)).status, 'ambiguous');
  context.artifacts = Array.from({length: 501}, (_, index) => ({...artifact, artifact_id: String(index + 100)})); context.artifacts.push(artifact);
  assert.equal((await api.resolve(reference, getContext)).status, 'ready', 'Catalog entries after 500 remain addressable');
  context.artifacts.push({...artifact, session_id: '12'}); assert.equal((await api.resolve(reference, getContext)).status, 'ambiguous');
  context.artifacts = []; assert.equal((await api.resolve(reference, getContext)).status, 'missing');
  const event = context.events[0], eventRef = await api.eventReference(event, getContext);
  const ready = await api.resolve(eventRef, getContext); assert.equal(ready.status, 'ready');
  context.events = [{...event, payload: event.payload.replace(/^../, '41')}];
  assert.equal(api.stillMatches(eventRef, ready, getContext), false, 'Late microtask replacement fails receiving guard');
  assert.equal((await api.resolve(eventRef, getContext)).status, 'changed');
  await assert.rejects(api.eventReference(event, getContext), /changed/);
  context.events = [event, {...event}]; assert.equal((await api.resolve(eventRef, getContext)).status, 'ambiguous');
  assert.throws(() => api.eventCanonical({...event, unknown_extension: {payload: 'unbounded'}}), /identity/);
  context.events = []; assert.equal((await api.resolve(eventRef, getContext)).status, 'missing');
  let releaseHash;
  const delayed = await notebookModels(root, {crypto: {subtle: {digest: async (...args) => {await new Promise(resolve => {releaseHash = resolve;}); return webcrypto.subtle.digest(...args);}}}});
  context.events = [event]; const pinning = delayed.api.eventReference(event, getContext); context.events = [{...event, status_code: 201}]; releaseHash(); await assert.rejects(pinning, /changed/);
  let library = fixtureLibrary(empty), mode = 'ready', pending = [], calls = [];
  library.files[1].content += '\x7f'; library.files[1].content_bytes++;
  assert(validateLibrary(library), 'Existing Analyst scratchpads permit DEL content');
  assert(JSON.stringify(library).includes('\x7f'), 'The normal JSON encoder retains legal DEL text');
  const initialFiles = copy(library.files);
  const fetcher = async (url, options = {}) => {
    calls.push({url, method: options.method ?? 'GET'});
    const captured = copy(library);
    if (mode === 'hold') await new Promise(resolve => pending.push(resolve));
    if (options.method === 'POST') {
      if (mode === 'conflict') return Response.json({error: 'fixture'}, {status: 409});
      if (mode === 'error') return Response.json({error: 'fixture'}, {status: 503});
      const request = JSON.parse(options.body); assert.equal(request.expected_generation, library.generation);
      library = replaceLibrary(library, request);
      if (mode === 'wrong-receipt') return Response.json(captured);
      const response = copy(library); response.folders = response.folders.map(folder => ({parent_id: folder.parent_id, name: folder.name, id: folder.id}));
      return Response.json(response);
    }
    if (mode === 'malformed') return Response.json({bad: true});
    return Response.json(captured);
  };
  const store = api.createStore({fetcher, validateLibrary, timeout: 40});
  assert(await store.load());
  const file = {id: 3, folder_id: 1, name: 'Fixture.reb-notebook.json', kind: 'scratchpad', language: 'json', content: JSON.stringify(doc)};
  assert(await store.save(file), 'Object member order never invalidates a Swift-compatible receipt');
  assert.deepEqual(library.files.slice(0, 2).map(({updated_at_ms, ...file}) => file), initialFiles.map(({updated_at_ms, ...file}) => file));
  assert(calls.every(call => ['/api/local-analyst', '/api/local-analyst/actions'].includes(call.url)));
  for (const failure of ['conflict', 'error', 'wrong-receipt']) {
    file.name = `${failure}.reb-notebook.json`; mode = failure; assert.equal(await store.save(file), null); assert.equal(store.model.uncertain, true);
    const count = calls.length; assert.equal(await store.save(file), null); assert.equal(calls.length, count, 'Unknown POST outcomes cannot be retried automatically');
    mode = 'ready'; assert(await store.load());
  }
  mode = 'hold'; const loading = store.load(); store.cancel(); assert.equal(await loading, null); const generation = store.model.library.generation;
  for (const release of pending.splice(0)) release(); await new Promise(resolve => setTimeout(resolve, 0)); assert.equal(store.model.library.generation, generation);
  const saving = store.save(file); store.cancel(); assert.equal(await saving, null); assert(store.model.uncertain);
  for (const release of pending.splice(0)) release(); await new Promise(resolve => setTimeout(resolve, 0));
  mode = 'ready'; assert(await store.load());
  mode = 'hold'; assert.equal(await store.load(), null); assert.equal(store.model.busy, false); for (const release of pending.splice(0)) release();
  mode = 'malformed'; const last = store.model.library; assert.equal(await store.load(), null); assert.equal(store.model.library, last);
  mode = 'ready'; await store.load();
  const removed = await store.save(file, true); assert(removed); assert(!library.files.some(value => value.id === 3));
  for (const boundary of ['files', 'bytes']) {
    library = copy(empty()); library.generation = 1; library.updated_at_ms = 1000;
    library.files = Array.from({length: boundary === 'files' ? 64 : 16}, (_, index) => ({id: index + 1, folder_id: 1, name: `Existing ${index}`,
      kind: 'scratchpad', language: 'text', content: boundary === 'files' ? 'x' : 'x'.repeat(32768), content_bytes: boundary === 'files' ? 1 : 32768,
      created_at_ms: 1000, updated_at_ms: 1000}));
    assert(await store.load()); const before = calls.length;
    assert.equal(await store.save({...file, id: 65}), null); assert.equal(calls.length, before, `${boundary} quota must refuse before POST`);
  }
  library = fixtureLibrary(empty); library.files.push({...file, content: '{"broken":', content_bytes: 10, created_at_ms: 1000, updated_at_ms: 1000});
  assert(await store.load()); const beforeCorrupt = calls.length;
  assert.equal(await store.save(file), null); assert.equal(calls.length, beforeCorrupt, 'Malformed scratchpad must not be overwritten');
  const slowBody = api.createStore({fetcher: async () => new Response(new ReadableStream({start() {}, cancel: () => new Promise(() => {})})), validateLibrary, timeout: 20});
  assert.equal(await slowBody.load(), null); assert.equal(slowBody.model.busy, false, 'Body deadline does not wait for a stalled producer cleanup');
  for (const path of ['apps/origin-trace-backend/src/app.rs', 'apps/research-ui/macos/OriginTraceApp.swift', 'scripts/build-research-app.sh', 'apps/research-ui/index.html'])
    assert((await readFile(join(root, path), 'utf8')).includes('investigation_notebook.js'), path);
  await checkNotebookController(root);
  console.log('PASS notebook closed document, full scoped fingerprints, unknown extension refusal, async receiving guard, private library preservation, save receipts, cancellation/uncertainty, conflict and deadline (not rendered QA)');
}

export async function notebookFixture(base, root) {
  const {empty, validateLibrary} = await notebookModels(root);
  const fixture = {base, library: fixtureLibrary(empty), mode: 'ready', pending: [], calls: []};
  const handle = base.handle;
  base.notebook = fixture;
  base.handle = async (request, response) => {
    const path = new URL(request.url, 'http://127.0.0.1').pathname;
    if (path === '/api/events' && fixture.events) {response.writeHead(200, {'Content-Type':'application/json'}); response.end(JSON.stringify({count:fixture.events.length,events:fixture.events,capture_mode:'live',broker_connected:true})); return true;}
    if (path === '/api/artifacts' && fixture.artifacts) {response.writeHead(200, {'Content-Type':'application/json'}); response.end(JSON.stringify({count:fixture.artifacts.length,artifacts:fixture.artifacts})); return true;}
    if (!['/api/local-analyst', '/api/local-analyst/actions'].includes(path)) return handle(request, response);
    fixture.calls.push({path, method: request.method});
    const json = (status, value) => {if (!response.destroyed) {response.writeHead(status, {'Content-Type': 'application/json'}); response.end(JSON.stringify(value));}};
    const captured = copy(fixture.library), mode = fixture.mode;
    if (path.endsWith('/actions')) {
      let bytes = ''; for await (const chunk of request) {bytes += chunk; if (bytes.length > 1048576) {json(413, {error: 'fixture limit'}); return true;}}
      const action = JSON.parse(bytes); fixture.calls.at(-1).action = action.action;
      if (mode === 'error') {json(503, {error: 'Authored storage failure'}); return true;}
      if (action.expected_generation !== fixture.library.generation || mode === 'conflict') {json(409, {error: 'Authored stale generation'}); return true;}
      const next = replaceLibrary(fixture.library, action); assert(validateLibrary(next), 'Notebook writes must pass actual library validation');
      fixture.library = next;
      if (mode === 'hold') await new Promise(resolve => fixture.pending.push(resolve));
      json(200, next); return true;
    }
    if (mode === 'hold') await new Promise(resolve => fixture.pending.push(resolve));
    json(200, mode === 'malformed' ? {unsupported: true} : captured); return true;
  };
  fixture.release = () => {for (const resolve of fixture.pending.splice(0)) resolve();};
  const release = base.release; base.release = () => {fixture.release(); release();};
  return base;
}

export async function checkNotebookInteractions({evaluate, viewport, click, key, wheel, screenshot, typeText, fixture, reloadPage}) {
  const f = fixture.notebook, original = copy(f.library.files), receipts = [];
  const until = async (expression, message = expression) => {const start = Date.now(); while (Date.now() - start < 7000) {if (await evaluate(expression)) return; await new Promise(resolve => setTimeout(resolve, 25));} assert.fail(message);};
  const press = value => key(value, value, {windowsVirtualKeyCode: {Enter: 13, Escape: 27, Tab: 9, Home: 36, End: 35, ArrowDown: 40}[value], ...(value === 'Enter' ? {text: '\r', unmodifiedText: '\r'} : {})});
  const type = async (selector, value) => {await click(selector); await key('a', 'KeyA', {windowsVirtualKeyCode: 65, modifiers: 2}); await key('Backspace', 'Backspace', {windowsVirtualKeyCode: 8}); await typeText(value);};
  const chooseBook = async () => {await click('#notebook-select'); await press('Home'); await press('ArrowDown'); await press('Enter'); await until("!document.querySelector('#notebook-add').disabled");};
  const opened = async () => {await click('#open-investigation-notebook'); await until("document.querySelector('#investigation-notebook').open && !investigationNotebook.model.busy && investigationNotebook.model.library");};
  const saved = async count => {await until(`!investigationNotebook.model.busy && document.querySelectorAll('#notebook-list .notebook-pin').length===${count}`);};
  const hit = async selector => {
    const delta = await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)}),p=document.querySelector('#investigation-notebook'),r=n.getBoundingClientRect(),b=p.getBoundingClientRect();return r.top<b.top+6?r.top-b.top-12:r.bottom>b.bottom-6?r.bottom-b.bottom+12:0})()`);
    if (delta) await wheel('#investigation-notebook', delta, 'edge'); await click(selector);
  };
  const geometry = async label => {
    const value = await evaluate(`(()=>{const n=document.querySelector('#investigation-notebook'),r=n.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:innerWidth,height:innerHeight,overflow:n.scrollWidth-n.clientWidth,focus:document.activeElement.id,modal:n.open}})()`);
    assert(value.left >= 0 && value.right <= value.width && value.top >= 0 && value.bottom <= value.height && value.overflow <= 1, `${label}: notebook must fit without horizontal clipping`);
    receipts.push({label, ...value});
  };
  await viewport(1440, 900);
  await until('state.requests.length===1 && state.artifacts.length===2');
  await click('[data-screen="sources"]'); await click('[data-artifact-id="7"]');
  await until("selectedSource()?.content!==undefined");
  await click('#source-facts-toggle'); await until("document.querySelectorAll('#source-facts-report .source-fact').length>0");
  const sourceDelta = await evaluate(`(()=>{const n=document.querySelector('.source-fact > button'),p=n.closest('#source-sidebar .debug-panes'),r=n.getBoundingClientRect(),b=p.getBoundingClientRect();return r.top<b.top?r.top-b.top:r.bottom>b.bottom?r.bottom-b.bottom:0})()`);
  if (sourceDelta) await wheel('#source-sidebar .debug-panes', sourceDelta + Math.sign(sourceDelta) * 8, 'edge');
  await click('.source-fact > button'); await until("investigationRange!==null && !document.querySelector('#investigation-decode-range').disabled");
  const pinnedRange = await evaluate('({start:investigationRange.start,end:investigationRange.end})');
  const actionBaseline = fixture.calls.filter(call => call.method === 'POST').length;
  await opened();
  assert.match(await evaluate("document.querySelector('.notebook-scope').textContent"), /Library-wide.*sessions.*non-executable/);
  await type('#notebook-new-name', 'Authored case'); await click('#notebook-create'); await saved(0);
  assert.equal(f.library.files.length, 3); assert.equal(f.library.files[2].kind, 'scratchpad'); assert.equal(f.library.files[2].language, 'json');
  await click('#notebook-add'); await until("!document.querySelector('#notebook-pin-name').disabled && document.querySelector('#notebook-pin-name').value==='Artifact 7'");
  assert.equal(await evaluate('document.activeElement.id'), 'notebook-pin-name', 'New pin focus follows enabled editor');
  await type('#notebook-pin-name', 'Same label'); await type('#notebook-pin-note', 'Hypothesis: <img src=x onerror=alert(1)> stays inert.');
  await click('#notebook-save'); await saved(1);
  assert.deepEqual(JSON.parse(f.library.files[2].content).pins[0].reference.range, pinnedRange);
  assert.equal(JSON.parse(f.library.files[2].content).pins[0].note, 'Hypothesis: <img src=x onerror=alert(1)> stays inert.');
  assert(!/fixture\.invalid|payload_encoding|POST fixture/.test(f.library.files[2].content), 'Captured URL/payload content must not enter the notebook');
  assert.equal(await evaluate("document.querySelector('#investigation-notebook img')"), null);
  await geometry('1440 source pin'); await screenshot('notebook-wide-source');
  await click('#notebook-open'); await until("!document.querySelector('#investigation-notebook').open");
  assert.equal(await evaluate('state.selectedArtifactId'), '7');
  await until("document.querySelector('#source-position').textContent.includes('Original UTF-8 bytes')");
  await click('[data-screen="traffic"]'); await click('.request-row'); await opened();
  await click('#notebook-add'); await until("document.querySelector('#notebook-pin-name').value==='Event 41' && !document.querySelector('#notebook-pin-name').disabled");
  await type('#notebook-pin-name', 'Same label'); await type('#notebook-pin-note', 'Separate native observation. No causal claim.');
  await click('#notebook-save'); await saved(2);
  assert.equal(new Set(JSON.parse(f.library.files[2].content).pins.map(pin => pin.id)).size, 2, 'Duplicate labels retain distinct IDs');
  await click('#notebook-close');
  await reloadPage(); await until("typeof investigationNotebook!=='undefined' && state.events.length===1");
  await opened(); await chooseBook(); await click('#notebook-pin-2');
  assert.equal(await evaluate("document.querySelector('#notebook-pin-note').value"), 'Separate native observation. No causal claim.');
  await click('#notebook-open'); await until("!document.querySelector('#investigation-notebook').open && investigationScreen()==='evidence'");
  assert.equal(await evaluate('evidenceWorkspace.snapshot().selectedKey'), '11:17:41');
  await opened(); await click('#notebook-pin-2');
  f.events = [{...fixture.event, payload: fixture.event.payload.replace(/^../, '41')}]; await evaluate('refresh()');
  await click('#notebook-open'); await until("document.querySelector('#notebook-assurance').dataset.status==='changed'");
  assert(await evaluate("document.querySelector('#investigation-notebook').open"));
  f.events = [fixture.event, {...fixture.event}]; await evaluate('refresh()'); await click('#notebook-open');
  await until("document.querySelector('#notebook-assurance').dataset.status==='ambiguous'");
  f.events = []; await evaluate('refresh()'); await click('#notebook-open'); await until("document.querySelector('#notebook-assurance').dataset.status==='missing'");
  f.events = null; await evaluate('refresh()');
  await click('#notebook-pin-1');
  f.artifacts = [{...fixture.artifacts[0], sha256: 'b'.repeat(64)}, fixture.artifacts[1]]; await evaluate('refreshArtifacts()');
  await click('#notebook-open'); await until("document.querySelector('#notebook-assurance').dataset.status==='changed'");
  f.artifacts = [...fixture.artifacts, {...fixture.artifacts[0], session_id: '12'}]; await evaluate('refreshArtifacts()');
  await click('#notebook-open'); await until("document.querySelector('#notebook-assurance').dataset.status==='ambiguous'");
  f.artifacts = []; await evaluate('refreshArtifacts()'); await click('#notebook-open'); await until("document.querySelector('#notebook-assurance').dataset.status==='missing'");
  f.artifacts = null; await evaluate('refreshArtifacts()');
  await type('#notebook-pin-note', 'Edited note survives a refused save.'); f.mode = 'conflict'; await click('#notebook-save');
  await until("!investigationNotebook.model.busy && investigationNotebook.model.uncertain");
  assert.equal(await evaluate("document.querySelector('#notebook-pin-note').value"), 'Edited note survives a refused save.');
  assert(await evaluate("document.querySelector('#notebook-save').disabled"));
  f.mode = 'ready'; await click('#notebook-discard'); await click('#notebook-refresh'); await until('!investigationNotebook.model.busy && !investigationNotebook.model.uncertain');
  await click('#notebook-pin-1'); await type('#notebook-pin-note', 'Successfully edited locally.'); await click('#notebook-save'); await saved(2);
  assert.equal(JSON.parse(f.library.files[2].content).pins[0].note, 'Successfully edited locally.');
  f.mode = 'malformed'; await click('#notebook-refresh'); await until("!investigationNotebook.model.busy && investigationNotebook.model.notice.includes('malformed')");
  assert.equal(await evaluate("document.querySelectorAll('#notebook-list .notebook-pin').length"), 2, 'Malformed refresh preserves last understandable notes');
  f.mode = 'hold'; await click('#notebook-refresh'); await until('investigationNotebook.model.busy');
  await click('#notebook-cancel'); f.release(); f.mode = 'ready';
  await until('!investigationNotebook.model.busy'); assert.equal(await evaluate('document.activeElement.id'), 'notebook-close');
  await click('#notebook-pin-1'); await type('#notebook-pin-note', 'A committed save can outlive cancellation.'); f.mode = 'hold'; await click('#notebook-save');
  await until('investigationNotebook.model.busy');
  const started = Date.now(); while (!f.pending.length && Date.now() - started < 5000) await new Promise(resolve => setTimeout(resolve, 25));
  assert(f.pending.length); await click('#notebook-cancel'); assert(await evaluate('investigationNotebook.model.uncertain'));
  f.release(); f.mode = 'ready'; await click('#notebook-discard'); await click('#notebook-refresh'); await until('!investigationNotebook.model.busy && !investigationNotebook.model.uncertain');
  await click('#notebook-pin-1'); assert.equal(await evaluate("document.querySelector('#notebook-pin-note').value"), 'A committed save can outlive cancellation.');
  await type('#notebook-pin-note', 'A newer focus choice survives save completion.'); f.mode = 'hold'; await click('#notebook-save');
  await until('investigationNotebook.model.busy');
  const focusStarted = Date.now(); while (!f.pending.length && Date.now() - focusStarted < 5000) await new Promise(resolve => setTimeout(resolve, 25));
  assert(f.pending.length); assert.equal(await evaluate('document.activeElement.id'), 'notebook-cancel');
  await press('Tab'); assert.equal(await evaluate('document.activeElement.id'), 'notebook-close');
  f.release(); f.mode = 'ready'; await until('!investigationNotebook.model.busy');
  await evaluate('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))');
  assert.equal(await evaluate('document.activeElement.id'), 'notebook-close', 'Completion must not steal a newer keyboard focus choice');
  await click('#notebook-close'); await click('[data-screen="sources"]'); await click('[data-artifact-id="7"]'); await opened();
  await evaluate("window.notebookShortcutLeaks=0; document.addEventListener('keydown',event=>{if(['F8','F10','F11','ArrowLeft','Escape'].includes(event.key))window.notebookShortcutLeaks++;});");
  const screen = await evaluate('investigationScreen()'), consoleOpen = await evaluate('state.consoleOpen');
  await key('F8', 'F8', {windowsVirtualKeyCode: 119}); await key('F10', 'F10', {windowsVirtualKeyCode: 121});
  await key('ArrowLeft', 'ArrowLeft', {windowsVirtualKeyCode: 37, modifiers: 1});
  assert.equal(await evaluate('investigationScreen()'), screen, 'Modal isolates background navigation shortcuts');
  await press('Escape'); assert.equal(await evaluate("document.querySelector('#investigation-notebook').open"), false);
  assert.equal(await evaluate('state.consoleOpen'), consoleOpen, 'Escape closes notebook rather than toggling Sources console');
  assert.equal(await evaluate('window.notebookShortcutLeaks'),0,'Modal keys never reach background document handlers, even with an offline debugger');
  for (const size of [[760, 560], [360, 740]]) {
    await viewport(...size);
    if(size[0]===360) assert(await evaluate("document.querySelector('.toolbar').getBoundingClientRect().height<=62"),'Notebook trigger must not add a third phone navigation row');
    await opened(); await hit('#notebook-pin-1'); await geometry(`notebook ${size[0]}`);
    await screenshot(`notebook-${size[0]}-notes`);
    await hit('#notebook-pin-note'); await key('End', 'End', {windowsVirtualKeyCode: 35}); await typeText(' Keyboard edit.');
    await hit('#notebook-save'); await saved(2); await geometry(`saved ${size[0]}`); await screenshot(`notebook-${size[0]}-saved`);
    await press('Escape'); assert.equal(await evaluate('document.activeElement.id'), 'open-investigation-notebook');
  }
  await viewport(1440, 900); await opened(); await click('#notebook-pin-2'); await click('#notebook-delete-pin'); await click('#notebook-delete-pin'); await saved(1);
  await click('#notebook-delete-book'); await click('#notebook-delete-book'); await saved(0);
  assert.deepEqual(f.library.files, original, 'Create/edit/delete must preserve pre-existing files byte for byte and their metadata');
  await click('#notebook-close');
  assert.equal(fixture.calls.filter(call => call.method === 'POST').length, actionBaseline, 'Notebook never sends debugger, capture, runtime or analysis action POSTs');
  assert(f.calls.filter(call => call.method === 'POST').every(call => call.action === 'replace_local_analyst_workspace'));
  await reloadPage(); await until("typeof investigationNotebook!=='undefined' && state.requests.length===1 && state.artifacts.length===2");
  return {status: 'passed', viewports: [[1440, 900], [760, 560], [360, 740]], geometry: receipts,
    checks: ['explicit non-executable JSON scratchpad', 'pointer/keyboard create edit save reopen reload delete', 'pre-existing Analyst scripts/notes unchanged', 'same labels distinct IDs', 'event payload replacement and duplicates/eviction fail closed', 'source hash replacement cross-session ambiguity/eviction fail closed', '409 preserves draft', 'malformed load preserves notes', 'cancelled late read/write ownership and uncertain saves', 'Sources Escape/F8/F10/Alt shortcuts isolated', 'no runtime or capture action POSTs', 'inert text and narrow geometry'],
    persistence: 'synthetic HTTP library survives real document reload; actual Rust persistence has separate acceptance'};
}

// Explicit real-store check. The caller supplies the built backend; the normal
// browser fixture never presents its synthetic store as disk persistence proof.
export async function checkNotebookPersistence(root, binary) {
  const directory = await mkdtemp(join(tmpdir(), 'reb-notebook-store-'));
  const endpoint = join(directory, 'endpoint'), path = join(directory, 'library.json');
  let child, url, errors = '';
  const start = async () => {
    child = spawn(binary, ['--port', '0', '--store', join(directory, 'events'), '--trace-store', join(directory, 'trace'),
      '--signal-store', join(directory, 'signals'), '--artifacts', join(directory, 'artifacts'),
      '--api-collection', join(directory, 'collection'), '--local-analyst', path, '--endpoint-file', endpoint], {cwd: root, stdio: ['ignore', 'ignore', 'pipe']});
    child.stderr.on('data', value => {errors = (errors + String(value)).slice(-4096);});
    let spawnError; child.once('error', error => {spawnError = error;});
    for (let index = 0; index < 200; index++) {
      if (spawnError) throw spawnError;
      if (child.exitCode !== null) throw new Error(`Backend exited: ${errors}`);
      try {url = (await readFile(endpoint, 'utf8')).trim(); if ((await fetch(url + '/api/local-analyst')).ok) return;} catch {}
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    throw new Error('Notebook backend startup deadline exceeded.');
  };
  const stop = async () => {
    if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill('SIGTERM'); const timer = setTimeout(() => child.kill('SIGKILL'), 1000);
    await exited; clearTimeout(timer);
  };
  try {
    const {api, validateLibrary} = await notebookModels(root); await start();
    const connect = () => api.createStore({fetcher: (route, options) => fetch(url + route, options), validateLibrary});
    const store = connect(); assert(await store.load());
    const doc = copy(api.empty()); doc.next_pin_id = 2;
    doc.pins = [{id: 1, name: 'Authored persistent note', note: 'Synthetic only', reference: {type: 'captured-artifact', session: '11', artifact: '7', sha256: 'a'.repeat(64), bytes: 10, range: null}}];
    const file = {id: 1, folder_id: 1, name: 'Authored.reb-notebook.json', kind: 'scratchpad', language: 'json', content: JSON.stringify(doc)};
    assert(await store.save(file)); const persisted = JSON.parse(await readFile(path, 'utf8'));
    assert.equal(persisted.files[0].content, file.content); assert.equal((await stat(path)).mode & 0o777, 0o600);
    await stop(); await rm(endpoint, {force: true}); await start();
    const reopened = connect(); assert(await reopened.load()); assert.deepEqual(JSON.parse(reopened.model.library.files[0].content), doc);
    const stale = await fetch(url + '/api/local-analyst/actions', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: 'replace_local_analyst_workspace', expected_generation: 0, folders: persisted.folders, files: []})});
    assert.equal(stale.status, 409); assert.equal(JSON.parse(await readFile(path, 'utf8')).files[0].content, file.content);
    console.log('PASS actual Rust notebook HTTP save, user-only persistence, process restart/reload and stale generation refusal');
  } finally {await stop(); await rm(directory, {recursive: true, force: true});}
}
if (process.argv[2] === '--persistence') {
  assert(process.argv[3], 'Pass the built origin-trace-backend executable.');
  await checkNotebookPersistence(process.argv[4] || new URL('..', import.meta.url).pathname, process.argv[3]);
}

// Exercise the actual mounted editor handler as well as its pure helpers. This
// does not claim geometry, native input, focus visibility or browser acceptance.
export async function checkNotebookController(root) {
  const document = {activeElement: null};
  class Node {
    constructor(tag) {this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.listeners = new Map(); this.attributes = {}; this.value = ''; this.hidden = false; this.disabled = false; this.open = false; this.scrollTop = 0; this.className = ''; this.classList = {add: name => {this.className += ` ${name}`;}};}
    append(...nodes) {for (const node of nodes) {node.parentElement = this; this.children.push(node);}}
    replaceChildren(...nodes) {this.children = []; this.append(...nodes);}
    setAttribute(key, value) {this.attributes[key] = value;}
    addEventListener(type, fn) {this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);}
    async fire(type) {for (const fn of this.listeners.get(type) ?? []) await fn({type, target: this, preventDefault() {}, stopPropagation() {}});}
    contains(node) {return node === this || this.children.some(child => child.contains(node));}
    querySelector(selector) {return this.querySelectorAll(selector)[0] ?? null;}
    querySelectorAll(selector) {const match = node => selector.startsWith('#') ? node.id === selector.slice(1) : selector.startsWith('.') ? node.className.split(/\s+/).includes(selector.slice(1)) : selector.startsWith('[data-pin-id=') ? node.dataset.pinId === selector.match(/"([^"]+)"/)[1] : false; const found = []; const visit = node => {for (const child of node.children) {if (match(child)) found.push(child); visit(child);}}; visit(this); return found;}
    focus() {if (!this.disabled && !this.hidden) document.activeElement = this;}
    select() {}
    showModal() {this.open = true; this.querySelector('#notebook-close')?.focus();}
    close() {this.open = false;}
  }
  document.body = new Node('body'); document.createElement = tag => new Node(tag);
  const button = new Node('button'); document.body.append(button); button.focus();
  const {api, empty, validateLibrary} = await notebookModels(root, {document, window: {addEventListener() {}}, location: {protocol: 'http:'}});
  let library = fixtureLibrary(empty), failContext = false, posts = 0, opened = 0;
  const original = copy(library.files), artifact = {session_id: '11', artifact_id: '7', sha256: 'a'.repeat(64), byte_size: 90, kind: 'javascript'};
  const fetcher = async (_url, options = {}) => {if (options.method === 'POST') {posts++; library = replaceLibrary(library, JSON.parse(options.body));} return Response.json(library);};
  const ui = api.mount({button, protocol: 'http:', validateLibrary, fetcher,
    getContext: () => {if (failContext) throw new Error('Authored unavailable retained window'); return {artifacts: [artifact], events: [baselineEvent()]};},
    getSelection: () => ({kind: 'artifact', artifact, range: {start: 1, end: 4}}), openReference: () => {opened++; return true;}});
  const node = id => document.body.querySelector(`#notebook-${id}`);
  await ui.show(); node('new-name').value = 'Mounted case'; await document.body.querySelector('.notebook-create').fire('submit');
  assert.equal(library.files.length, 3); await node('add').fire('click');
  node('pin-name').value = 'Mounted source'; await node('pin-name').fire('input'); node('pin-note').value = 'Authored note'; await node('pin-note').fire('input');
  await node('editor').fire('submit');
  assert.equal(JSON.parse(library.files[2].content).pins.length, 1, 'Mounted Save must call its retained-context function, not pass its result as a function');
  assert(node('cancel').hidden, 'Successful verification releases its busy state');
  await node('open').fire('click'); assert.equal(opened, 1); assert.equal(ui.dialog.open, false);
  await ui.show(); await node('add').fire('click');
  failContext = true; const before = posts; await node('editor').fire('submit');
  assert.equal(posts, before, 'Failed new-pin verification makes no persistence request');
  assert(node('cancel').hidden, 'Rejected verification releases busy state and preserves the editor'); assert.equal(node('save').disabled, false);
  failContext = false; await node('editor').fire('submit'); assert.equal(JSON.parse(library.files[2].content).pins.length, 2);
  await node('delete-pin').fire('click'); await node('delete-pin').fire('click'); assert.equal(JSON.parse(library.files[2].content).pins.length, 1);
  await node('delete-book').fire('click'); await node('delete-book').fire('click'); assert.deepEqual(library.files, original);
  console.log('PASS mounted Notebook create/pin/Save/open/delete handlers, failed verification recovery and unrelated-file preservation (DOM/controller fixture; not rendered QA)');
}
