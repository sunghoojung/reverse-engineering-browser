#!/usr/bin/env node
// Full shipped page with authored loopback responses; never native capture.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {startSandboxedChromium} from './sandboxed-chromium-startup.mjs';
import {mkdtemp, readFile, writeFile, rm, mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {runInNewContext, Script} from 'node:vm';
import ledgerModel from '../apps/research-ui/vm_opcode_ledger.js';
import staticModel from '../apps/research-ui/vm_static.js';
import staticView from '../apps/research-ui/vm_static_view.js';
import contextualEvidence from '../apps/research-ui/vm_contextual_evidence.js';
import debuggerModel from '../apps/research-ui/vm_debugger.js';
import {recordCompatibilityDemo} from './generate-vm-compatibility-demo.mjs';
import {contextualFixture} from './check-vm-contextual-ui.mjs';
import {candidateWaitForUIStartup} from './check-candidate-experiment-journey.mjs';

// Decode source literals without evaluating their contents. Compile the cooked
// browser expression: node --check alone cannot catch a second-level quote loss.
function readExpressionLiteral(source, start) {
  const quote = source[start]; let value = '', dynamic = false;
  for (let index = start + 1; index < source.length; index++) {
    const character = source[index];
    if (character === quote) return {value, dynamic, end: index + 1};
    if (quote === '`' && character === '$' && source[index + 1] === '{') dynamic = true;
    if (character !== '\\') { value += character; continue; }
    const escaped = source[++index];
    if (escaped === '\n') continue;
    if (escaped === '\r') { if (source[index + 1] === '\n') index++; continue; }
    if (escaped === 'x' || escaped === 'u') {
      const braced = escaped === 'u' && source[index + 1] === '{';
      const end = braced ? source.indexOf('}', index + 2) : index + (escaped === 'x' ? 2 : 4) + 1;
      const hex = source.slice(index + (braced ? 2 : 1), end);
      assert(/^[0-9a-f]+$/i.test(hex) && (braced || hex.length === (escaped === 'x' ? 2 : 4)), 'Invalid source literal escape');
      value += String.fromCodePoint(parseInt(hex, 16)); index = braced ? end : end - 1; continue;
    }
    assert(escaped !== undefined && !/[1-9]/.test(escaped) && !(escaped === '0' && /[0-9]/.test(source[index + 1] || '')), 'Unsupported source literal escape');
    value += ({n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', v: '\v', 0: '\0'})[escaped] ?? escaped;
  }
  throw Error('Unterminated source literal');
}
function compileLiteralEvaluations(source) {
  const calls = /\bevaluate\s*\(\s*(?=["'`])/g; let count = 0, call;
  while ((call = calls.exec(source))) {
    const literal = readExpressionLiteral(source, calls.lastIndex);
    if (!literal.dynamic && /^\s*[),]/.test(source.slice(literal.end))) {
      new Script(literal.value, {filename: 'full-shell-browser-expression-at-line-' + (source.slice(0, call.index).split('\n').length)});
      count++;
    }
    calls.lastIndex = literal.end;
  }
  return count;
}
const root = fileURLToPath(new URL('..', import.meta.url));
const output = process.env.REB_VM_FULL_SHELL_OUTPUT || join(root, 'build/vm-workspace-ui-qa/full-shell');
const html = await readFile(join(root, 'apps/research-ui/index.html'), 'utf8');
const model = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const fixture = JSON.parse(await readFile(join(root, 'tests/research_ui/fixtures/vm-opcode-workspace-v2.json'), 'utf8'));
const workspace = fixture.workspaces[0];
// Source-backed diagnostic copy, not runtime evidence. The Rust producer test
// separately validates the actual emitted no-samples workspace.
const opcodeSource = await readFile(join(root, 'apps/origin-trace-backend/src/vm_opcode.rs'), 'utf8');
const samplerDetail = opcodeSource.match(/"reason":"sampler-unavailable", "detail":\s*("[^"\n]+")/);
assert(samplerDetail, 'The no-samples producer diagnostic must be available to the UI regression');
const samplerOmission = {reason: 'sampler-unavailable', detail: JSON.parse(samplerDetail[1])};
assert(samplerOmission.detail.startsWith('No runtime dispatch samples were retained. Automatic guest-interpreter sampling is not implemented.'), 'Observed missing samples and the automatic sampler limitation must lead, not follow secondary caveats');
assert(samplerOmission.detail.includes('A caller-fed writer still needs a runtime producer.'), 'A writer must remain distinct from a guest-interpreter sampler');
assert(!samplerOmission.detail.includes('no guest dispatch emitter'), 'Missing samples must not deny caller-fed writer capability');
const analysis = {
  contract_version: 1, document_kind: 'vm-analysis', document_digest: fixture.analysis_digest,
  profile_digest: fixture.profile_digest, profile: {profile_id: 'anti-bot-vm-detection-v1'},
  input_coverage: {complete: false, omissions: ['Authored UI fixture, not a live capture.']},
  results: [{artifact_id: workspace.interpreter_artifact_id, artifact_sha256: workspace.source_artifact_sha256,
    finding_id: workspace.finding_id, runtime: 'javascript', status: 'partial', tier: 'candidate',
    vm_score: 20, anti_bot_score: 0, evidence_families: ['authored-dispatch'], related_request_ids: [],
    observations: [{rule_id: 'authored-fixture', family: 'authored-dispatch', weight: 20,
      coordinate: {byte_offset: 0, byte_size: 1}, detail: 'Authored retained-workspace fixture. No browser capture or guest execution.'}],
    coverage: {complete: false, residual_unknowns: ['Guest semantics remain unconfirmed.']}}],
  mixed_findings: [], opcode_workspace: fixture
};
assert(runInNewContext(`${model}\nisVmAnalysisDocument(analysis) && isVmOpcodeWorkspaceDocument(fixture)`, {analysis, fixture, TextEncoder}));
const noSamplerFixture = structuredClone(fixture), noSamplerWorkspace = noSamplerFixture.workspaces[0];
noSamplerWorkspace.runtime = 'webassembly'; noSamplerWorkspace.model = 'unknown';
noSamplerWorkspace.samples = []; noSamplerWorkspace.sample_count = noSamplerFixture.summary.sample_count = 0;
for (const handler of noSamplerWorkspace.handlers) {
  handler.sample_count = 0;
  if (handler.state === 'observed') handler.state = 'inferred';
}
noSamplerWorkspace.coverage.complete = false;
noSamplerWorkspace.coverage.omissions.push(samplerOmission);
noSamplerFixture.document_digest = 'b'.repeat(64);
assert(runInNewContext(`${model}\nisVmOpcodeWorkspaceDocument(noSamplerFixture)`, {noSamplerFixture, TextEncoder}));
const assets = new Set(['index.html', ...[...html.matchAll(/(?:src|href)="([^"/]+\.(?:js|css))"/g)].map(match => match[1])]);
const compareInputs = {};
for (const [key, name] of [['pack','pack.json'],['left','build-a.workspace.json'],['right','build-b.workspace.json']]) {
  compareInputs[key] = JSON.parse(await readFile(join(root, 'tools/fixtures/vm-analysis-packs', name), 'utf8'));
}
const compareRequest = {...compareInputs, left_artifact: '1', right_artifact: '1'};
const compareReport = {contract_version: 1, document_kind: 'vm-instruction-set-comparison', document_digest: 'a'.repeat(64),
  behavioral_equivalence_proven: false, rows: [
    {status: 'moved', match_basis: 'unique-exact-effect-shape', left: {opcode: 1}, right: {opcode: 4}},
    {status: 'unknown', match_basis: 'unmatched', left: {opcode: 2}, right: null}
  ], limitations: ['Authored presentation fixture; not actual backend analysis.']};
const executionTrace = recordCompatibilityDemo();
const staticInputs = staticView.vmStaticOwnedExample();
const staticReport = await staticModel.analyze(JSON.stringify(staticInputs.definition), JSON.stringify(staticInputs.image));
const contextualInputs = await contextualFixture();
const contextualReport = await contextualEvidence.link(...['definition','image','evidence'].map(kind => JSON.stringify(contextualInputs[kind])));
// Independent checked-in goldens are presentation inputs, not a completed
// command or a claim that this browser test ran the native helper.
const golden = JSON.parse(await readFile(join(root, 'tools/fixtures/owned-vm-golden-transitions-v1.json'), 'utf8')).register;
const liveRecords = golden.transitions.slice(0, 5).map((record, index) => ({...record, tick: String(index + 1)}));
const idleLiveView = {schema: 'reb-owned-vm-debug-session-v1', available: true, unavailable_reason: null,
  backend_instance_id: 'authored-shell-no-native-execution', session: null};
const populatedLiveView = {...idleLiveView, session: {
  backend_instance_id: idleLiveView.backend_instance_id, session_id: 'authored-golden-presentation',
  run_id: 'authored-golden-no-command', run_generation: '1', provider: 'live-owned-native-fixture',
  target_kind: 'owned_fixture', fixture: 'register', program_id: 'owned-register-v1', fixture_revision: 1,
  program_sha256: 'a'.repeat(64), program_manifest_scope: 'declared-two-program-manifest-sha256',
  build_id: null, build_id_scope: 'configured-helper-file-sha256', pc_units: 'instruction-index',
  value_semantics: 'unsigned-64-bit-bits', tick_units: 'monotonic-nanoseconds', state: 'paused',
  control_revision: '1', snapshot_revision: '1', executed_count: String(liveRecords.length), retained_count: String(liveRecords.length),
  execution_state_known: true, termination_reason: null, initial_snapshot: golden.initial, current_snapshot: liveRecords.at(-1).after,
  records: liveRecords, recorder: {session_id: '1', document_id: '2', invocation_id: '3', generation: '1',
    stats: Object.fromEntries(['attempted','recorded','full','malformed','wrong_document','stale_generation','exhausted','expired','partial']
      .map(key => [key, ['attempted','recorded'].includes(key) ? String(liveRecords.length) : '0']))},
  last_command: null, diagnostics: {stderr_bytes: '0', stderr_truncated: false}, disposal_failed: false
}};
assert.equal(staticReport.coverage.instruction_count, 16);
assert.equal(contextualReport.analysis.instructions.length, 3);
assert.equal(contextualReport.observed_edges.length, 1);
assert.equal(debuggerModel.ownedVmValidateView(populatedLiveView).session.records.length, 5);
let liveView = idleLiveView;
const requests = [];
const server = createServer(async (request, response) => {
  const path = request.url.split('?')[0];
  const json = value => { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(value)); };
  if (path.startsWith('/api/')) {
    requests.push({method: request.method, path});
    if (request.method === 'POST' && path === '/api/analysis/vm/packs/compare') {
      let body = ''; let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 1048576) { response.statusCode = 413; json({error: 'Fixture request bound exceeded'}); return; }
        body += chunk.toString('utf8');
      }
      try { assert.deepEqual(JSON.parse(body), compareRequest); }
      catch { response.statusCode = 422; json({error: 'Only the exact authored comparison inputs are accepted'}); return; }
      return json(compareReport);
    }
    if (request.method !== 'GET') { response.statusCode = 405; json({error: 'Read-only authored fixture'}); return; }
    if (path === '/api/events') return json({count: 0, events: [], capture_mode: 'demo', broker_connected: false, capture_stopped: true});
    if (path === '/api/artifacts') return json({count: 0, artifacts: []});
    if (path === '/api/vm-debugger') return json(liveView);
    if (path === '/api/analysis/vm') return json(analysis);
    if (path === '/api/analysis/vm/opcodes') return json(fixture);
    response.statusCode = 503; json({error: 'Unavailable in authored full-shell fixture'}); return;
  }
  const name = path === '/' ? 'index.html' : path.slice(1);
  if (!/^[a-z][a-z0-9_]*\.(?:html|js|css)$/.test(name) || !assets.has(name)) { response.writeHead(404).end(); return; }
  try {
    response.setHeader('content-type', name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html');
    response.end(await readFile(join(root, 'apps/research-ui', name)));
  } catch { response.writeHead(500).end(); }
});
if (process.argv.includes('--fixture-only')) {
  const brokenSelector = 'document.querySelectorAll("[data-vm-paged-rows="retained samples"] > details").length';
  assert.throws(() => compileLiteralEvaluations('evaluate(' + JSON.stringify(brokenSelector) + ')'), SyntaxError);
  assert.equal(compileLiteralEvaluations('evaluate("1 + 2"); evaluate(\'3 + 4\'); evaluate(`5 + 6`); evaluate(`${neverRun()}`);'), 3);
  assert.equal(readExpressionLiteral("'line\\n\\x41\\u0042\\u{43}'", 0).value, 'line\nABC');
  const source = await readFile(fileURLToPath(import.meta.url), 'utf8');
  const browserStart = source.indexOf('\n  const profile =');
  assert(browserStart >= 0, 'Browser journey source boundary must exist');
  const compiledExpressions = compileLiteralEvaluations(source.slice(browserStart));
  assert(compiledExpressions > 100, 'Preflight must cover the browser journey, not just one selector');
  liveView = populatedLiveView;
  for (const [method, url, status] of [['GET', '/api/unavailable', 503], ['POST', '/api/analysis/vm', 405], ['GET', '/api/analysis/vm', 200], ['GET', '/api/vm-debugger', 200], ['POST', '/api/vm-debugger/actions', 405]]) {
    const response = {statusCode: 200, headersSent: false, headers: {},
      setHeader(name, value) { assert.equal(this.headersSent, false, 'Headers must precede body'); this.headers[name] = value; },
      writeHead(code) { this.statusCode = code; this.headersSent = true; },
      end(body) { this.headersSent = true; this.body = body; }};
    server.emit('request', {url, method}, response);
    assert.equal(response.statusCode, status);
    assert.equal(response.headers['content-type'], 'application/json');
    assert.doesNotThrow(() => JSON.parse(response.body));
    if (url === '/api/vm-debugger') assert.deepEqual(JSON.parse(response.body), populatedLiveView);
  }
  server.close();
  console.log(`PASS full-shell ${compiledExpressions} static browser expressions, authored HTTP contracts, populated execution/static/contextual/live inputs, read-only live refusal and response ordering (not rendered)`);
  process.exit(0);
}
  const profile = await mkdtemp(join(tmpdir(), 'reb-vm-workspace-'));
  let browser, socket, closed = false, diagnostics = '', sequence = 0;
  const pending = new Map(), errors = [], pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  const until = async (test, label, timeoutMs = 10000) => {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) { if (await test()) return; await pause(40); }
    throw Error(`Timed out: ${label}`);
  };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++sequence, timer = setTimeout(() => { pending.delete(id); reject(Error(`CDP timeout: ${method}`)); }, 10000);
    pending.set(id, {resolve, reject, timer}); socket.send(JSON.stringify({id, method, params}));
  });
  const evaluate = async expression => {
    new Script(expression, {filename: 'full-shell-expanded-browser-expression'});
    const result = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  await mkdir(output, {recursive: true});
  try {
    await new Promise((ready, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ready); });
    const chromium = startSandboxedChromium(process.env.REB_UI_CHROMIUM || '/usr/bin/chromium', profile, text => { diagnostics = text; });
    browser = chromium.browser;
    browser.once('close', () => { closed = true; });
    const port = await chromium.ready();
    const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    socket = new WebSocket(pages.find(page => page.type === 'page').webSocketDebuggerUrl);
    await new Promise((ready, reject) => { socket.addEventListener('open', ready, {once: true}); socket.addEventListener('error', reject, {once: true}); });
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data), request = pending.get(message.id);
      if (message.method === 'Runtime.exceptionThrown') errors.push(message.params);
      if (!request) return;
      pending.delete(message.id); clearTimeout(request.timer);
      if (message.error) request.reject(Object.assign(Error(message.error.message), {cdpError: message.error})); else request.resolve(message.result);
    });
    await send('Runtime.enable'); await send('Page.enable');
    const uiURL = `http://127.0.0.1:${server.address().port}/`;
    await send('Page.navigate', {url: uiURL});
    await candidateWaitForUIStartup(evaluate, uiURL);
    await until(() => evaluate("typeof state !== 'undefined' && state.vmFindings.length > 0"), 'authored finding through real HTTP loader');
    const click = async selector => {
      const point = await evaluate(`(async()=>{const node=document.querySelector(${JSON.stringify(selector)});node.scrollIntoView({block:'center'});await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));const b=node.getBoundingClientRect();return {x:b.x+b.width/2,y:b.y+b.height/2};})()`);
      for (const type of ['mousePressed','mouseReleased']) await send('Input.dispatchMouseEvent',{type,...point,button:'left',clickCount:1});
      await evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))');
    };
    const key = async (key, code, value) => {
      for (const type of ['rawKeyDown','keyUp']) await send('Input.dispatchKeyEvent',{type,key,code,windowsVirtualKeyCode:value});
    };
    const screenshot = async name => {
      await evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))');
      const {data} = await send('Page.captureScreenshot', {format: 'png'});
      await writeFile(join(output, name + '.png'), Buffer.from(data, 'base64'));
    };
    const clickLabel = async (rootSelector, label) => {
      const selector = await evaluate(`(()=>{const root=document.querySelector(${JSON.stringify(rootSelector)});const buttons=[...root.querySelectorAll('button')];const index=buttons.findIndex(node=>node.textContent===${JSON.stringify(label)});if(index<0)throw Error('Missing action');buttons[index].setAttribute('data-full-shell-action','target');return ${JSON.stringify(rootSelector)}+' [data-full-shell-action="target"]';})()`);
      await click(selector);
      await evaluate("document.querySelector('[data-full-shell-action]')?.removeAttribute('data-full-shell-action')");
    };
    const importFile = async (selector, path) => {
      const {root: doc} = await send('DOM.getDocument');
      const {nodeId} = await send('DOM.querySelector', {nodeId: doc.nodeId, selector});
      assert(nodeId, 'File input exists: ' + selector);
      await send('DOM.setFileInputFiles', {nodeId, files: [path]});
    };
    const importJSON = async (selector, name, value) => {
      const path = join(profile, name + '.json');
      await writeFile(path, JSON.stringify(value));
      await importFile(selector, path);
      await until(() => evaluate(`document.querySelector(${JSON.stringify(selector)}).value === ''`), name + ' import settled');
    };
    const resize = async width => {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      await evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))');
    };
    const menuAction = async action => {
      await click(`.vm-menu:nth-child(${action === 'filter' ? 3 : 2}) > summary`);
      const selector = `[data-vm-command="vm-handler-${action}"]`;
      await until(() => evaluate(`document.querySelector(${JSON.stringify(selector)}).closest('details').open&&!document.querySelector(${JSON.stringify(selector)}).disabled`), 'Current-mode ' + action + ' menu readiness');
      assert.equal(await evaluate(`document.querySelector(${JSON.stringify(selector)}).disabled`), false, 'Current-mode menu action is available');
      await click(selector);
    };
    const assertFits = async (selector, label) => {
      assert.equal(await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)});return document.documentElement.scrollWidth<=innerWidth&&n.scrollWidth<=n.clientWidth+1;})()`), true, label + ' fits without outer horizontal overflow');
    };
    const assertReachable = async (selector, label) => {
      assert.equal(await evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(selector)}),r=n.getBoundingClientRect();let left=0,top=0,right=innerWidth,bottom=innerHeight;for(let p=n.parentElement;p;p=p.parentElement){const b=p.getBoundingClientRect(),s=getComputedStyle(p);if(['auto','scroll','hidden','clip'].includes(s.overflowX)){left=Math.max(left,b.left+p.clientLeft);right=Math.min(right,b.left+p.clientLeft+p.clientWidth);}if(['auto','scroll','hidden','clip'].includes(s.overflowY)){top=Math.max(top,b.top+p.clientTop);bottom=Math.min(bottom,b.top+p.clientTop+p.clientHeight);}}return r.width>0&&r.height>0&&r.left>=left-1&&r.right<=right+1&&r.top>=top-1&&r.bottom<=bottom+1&&n.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2));})()`), true, label + ' is unclipped and hit-testable');
    };
    const inspectTableRightEdge = async (rootSelector, name, scrollSelector = '.vm-review-listing') => {
      const listing = rootSelector + ' ' + scrollSelector;
      await evaluate(`document.querySelector(${JSON.stringify(listing + ' table')}).scrollIntoView({block:'center',inline:'nearest'})`);
      await evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))');
      const readPoint = () => evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(listing)}),r=n.getBoundingClientRect(),h=n.querySelector('thead th').getBoundingClientRect(),x=(Math.max(0,r.left+n.clientLeft)+Math.min(innerWidth,r.left+n.clientLeft+n.clientWidth))/2,y=h.y+h.height/2,target=document.elementFromPoint(x,y);return {x,y,hit:y>=0&&y<innerHeight&&n.contains(target),hitTag:target?.tagName,overflow:n.scrollWidth-n.clientWidth,scrollLeft:n.scrollLeft,scrollWidth:n.scrollWidth,clientWidth:n.clientWidth};})()`);
      const initialPoint = await readPoint(); let point = initialPoint;
      const scroll = xDistance => send('Input.synthesizeScrollGesture', {x:point.x, y:point.y, xDistance, yDistance:0, gestureSourceType:'mouse', preventFling:true, speed:800});
      try {
        assert(point.hit && point.overflow > 0, name + ' exposes its local horizontal scroll owner');
        // An already-zero predicate cannot acknowledge a no-op wheel. Await
        // complete, bounded native gestures before changing scroll direction.
        if (point.scrollLeft > 1) await scroll(Math.ceil(point.scrollLeft));
        await until(() => evaluate(`document.querySelector(${JSON.stringify(listing)}).scrollLeft<=1`), name + ' native horizontal start');
        point = await readPoint();
        assert(point.hit && point.overflow > 0, name + ' scroll owner remains under the pointer');
        await scroll(-Math.ceil(point.overflow + 1));
        await until(() => evaluate(`(()=>{const n=document.querySelector(${JSON.stringify(listing)});return n.scrollLeft>0&&n.scrollLeft>=n.scrollWidth-n.clientWidth-1;})()`), name + ' native horizontal end');
        await assertReachable(listing + ' thead th:last-child', name + ' rightmost header');
        await assertReachable(listing + ' tbody tr:first-child td:last-child', name + ' rightmost retained cell');
      } catch (error) {
        const currentPoint = await readPoint().catch(failure => ({diagnosticError: String(failure)}));
        throw Error(error.message + '; scroll diagnostics: ' + JSON.stringify({initialPoint, currentPoint}), {cause:error});
      }
      await screenshot(name + '-right-edge-390');
    };
    const assertLiveStateLabels = async (selector, label) => {
      assert.deepEqual(await evaluate(`[...document.querySelectorAll(${JSON.stringify(selector + ' th')})].map(n=>n.textContent)`), ['Location','Before','After / snapshot','Change','Explicit accesses'], label + ' retains all state column labels');
      assert.equal(await evaluate(`(()=>{const table=document.querySelector(${JSON.stringify(selector)}),headers=[...table.querySelectorAll('th')],cells=[...table.querySelectorAll('th,td')];return table.getBoundingClientRect().width>=520&&table.querySelectorAll('tbody tr').length>0&&headers.every(n=>getComputedStyle(n).whiteSpace==='nowrap')&&cells.every(n=>{const s=getComputedStyle(n);return s.overflowWrap==='normal'&&s.wordBreak==='normal';});})()`), true, label + ' keeps complete header words and normal value wrapping in its local table');
      await assertFits('#vm-owned-debugger', label);
    };
    const modes = await evaluate("[...document.querySelectorAll('.vm-workspace-switch button')].map(node=>[node.id.replace('vm-show-',''),node.getAttribute('aria-controls')])");
    for (const expected of ['findings','execution','owned','static','contextual']) assert(modes.some(([mode]) => mode === expected));
    for (const width of [1440, 1280, 900, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      await click('#nav-vm-workspace');
      assert.equal(await evaluate("document.querySelector('#screen-vm').hidden"), false);
      assert.deepEqual(await evaluate("(()=>{const body=getComputedStyle(document.body),screen=getComputedStyle(document.querySelector('#screen-vm'));return {background:body.backgroundColor,text:body.color,base:screen.getPropertyValue('--bg').trim(),surface:screen.getPropertyValue('--panel').trim(),accent:screen.getPropertyValue('--accent').trim()};})()"),
        {background:'rgb(35, 33, 54)',text:'rgb(224, 222, 244)',base:'#232136',surface:'#2a273f',accent:'#c4a7e7'}, 'Actual full shell retains Rosé Pine Moon theme');
      for (const [mode, panel] of modes) {
        await click('#vm-show-' + mode);
        assert.equal(await evaluate(`document.querySelector('#${panel}').hidden`), false, `${mode} panel at ${width}`);
        assert.equal(await evaluate(`document.querySelector('#vm-show-${mode}').getAttribute('aria-pressed')`), 'true');
        assert.equal(await evaluate(`(()=>{const n=document.querySelector('#vm-show-${mode}'),r=n.getBoundingClientRect();return r.width>0&&r.height>0&&r.left>=0&&r.right<=innerWidth+1&&r.top>=0&&r.bottom<=innerHeight&&n.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2));})()`), true, `${mode} control reachable at ${width}`);
        if (mode === 'static' && width === 390) {
          await until(() => evaluate("document.querySelector('#vm-static-workspace').dataset.layout === 'narrow'"), 'Static workspace resize observer applies narrow layout');
          assert.equal(await evaluate("[...document.querySelectorAll('#vm-static-workspace .vm-static-panels button')].every(button=>button.clientWidth>=80 && getComputedStyle(button).whiteSpace==='nowrap')"), true, 'Narrow static panel buttons retain complete readable labels');
        }
        await screenshot(`vm-mode-${mode}-empty-${width}`);
      }
      await click('#vm-show-findings');
      await click('#vm-list .vm-row');
      await key('ArrowDown', 'ArrowDown', 40);
      assert.equal(await evaluate("document.activeElement.classList.contains('vm-row')"), true);
      await until(() => evaluate("document.querySelectorAll('.vm-workbench-tabs button').length >= 6"), 'actual finding analysis tabs');
      assert.equal(await evaluate("document.querySelector('.vm-finding-provenance').open"), false);
      await evaluate("document.querySelector('#vm-detail').scrollTop=0;document.querySelector('#vm-findings-workspace').scrollTop=0");
      if (width >= 1280) assert.equal(await evaluate("['.vm-handler-head','.vm-handler-row'].every(selector=>{const r=document.querySelector(selector).getBoundingClientRect();return r.top>=0&&r.bottom<innerHeight;})"), true, 'Listing header and first handler remain above the fold');
      if (width >= 1280) {
        const columns = await evaluate("(()=>{const head=document.querySelector('.vm-handler-head'),list=document.querySelector('.vm-handler-list'),row=list.querySelector('.vm-handler-row');return {listWidth:list.clientWidth,rowWidth:row.getBoundingClientRect().width,offsets:[...head.children].map((cell,index)=>Math.abs(cell.getBoundingClientRect().left-row.children[index].getBoundingClientRect().left))};})()");
        assert(Math.abs(columns.listWidth - columns.rowWidth) <= 1, 'Handler rows fill the listing width');
        assert(columns.offsets.every(offset => offset <= 1), 'Handler cells align with their column headers');
      }
      assert.equal(await evaluate("document.querySelector('.vm-row').getBoundingClientRect().height < 100"), true, 'Program tree rows remain compact instead of stretching to fill the dock');
      await click('.vm-handler-row');
      await key('ArrowDown', 'ArrowDown', 40);
      assert.equal(await evaluate("document.querySelector('.vm-selection-inspector h3').textContent"),
        await evaluate("document.querySelector('.vm-handler-row[aria-selected=true] .vm-handler-label strong').textContent"));
      assert.equal(await evaluate("document.querySelectorAll('#vm-symbol-list [data-vm-symbol-key]').length"),
        await evaluate("document.querySelectorAll('.vm-handler-row').length"), 'Symbol dock reflects retained handlers');
      await click('.vm-symbol-row:last-child');
      assert.equal(await evaluate("document.querySelector('.vm-symbol-row[aria-pressed=true]').dataset.vmSymbolKey"),
        await evaluate("document.querySelector('.vm-handler-row[aria-selected=true]').dataset.handlerKey"), 'Symbol navigation selects the linked listing');
      await click('[aria-label="Previous handler"]');
      assert.equal(await evaluate("document.querySelector('.vm-symbol-row[aria-pressed=true]').dataset.vmSymbolKey"),
        await evaluate("document.querySelector('.vm-handler-row[aria-selected=true]').dataset.handlerKey"), 'Toolbar navigation keeps symbols synchronized');
      await click('.vm-symbol-row');
      await click('[aria-label="Filter retained handlers"]');
      await send('Input.insertText', {text: 'candidate'});
      await evaluate('renderVmLab()');
      assert.equal(await evaluate("document.querySelector('input[aria-label=\"Filter retained handlers\"]').value"), 'candidate', 'Identical poll retains filter after selection');
      await click('[aria-label="Previous handler"]');
      assert.equal(await evaluate("document.querySelector('.vm-handler-row[aria-selected=true]').dataset.handlerKey"),
        await evaluate("[...document.querySelectorAll('.vm-handler-row')].filter(row=>!row.hidden).at(-1).dataset.handlerKey"), 'Previous starts at last visible row when selection was excluded');
      await click('.vm-symbol-row:last-child');
      assert.equal(await evaluate("document.querySelector('input[aria-label=\"Filter retained handlers\"]').value"), 'candidate', 'Visible symbol keeps matching filter');
      await click('.vm-symbol-row');
      await click('.vm-menu:nth-child(3) > summary');
      await click('[data-vm-command="vm-handler-filter"]');
      assert.equal(await evaluate("document.activeElement.getAttribute('aria-label')"), 'Filter retained handlers', 'Search menu focuses real filter');
      await click('.vm-menu:nth-child(1) > summary');
      await key('Escape', 'Escape', 27);
      assert.equal(await evaluate("document.querySelector('.vm-menu').open"), false);
      assert.equal(await evaluate("document.activeElement === document.querySelector('.vm-menu > summary')"), true, 'Escape restores menu trigger focus');
      await click('.vm-menu:nth-child(4) > summary');
      await click('[data-vm-command="vm-show-execution"]');
      assert.equal(await evaluate("document.querySelector('#vm-semantics-workflow').hidden"), false, 'Window menu opens existing Execution workspace');
      await click('#vm-show-findings');
      await click('[aria-label="Filter retained handlers"]');
      await send('Input.insertText', {text: 'no-retained-handler-matches-this'});
      assert.equal(await evaluate("[...document.querySelectorAll('.vm-handler-row')].filter(row=>!row.hidden).length"), 0);
      assert.equal(await evaluate("document.querySelector('[aria-label=\"Next handler\"]').disabled"), true, 'No-result navigation is disabled');
      assert.equal(await evaluate("document.querySelector('.vm-listing-count').getBoundingClientRect().height > 0"), true, 'No-match count stays visible on narrow layouts');
      await click('.vm-menu:nth-child(2) > summary');
      assert.equal(await evaluate("document.querySelector('[data-vm-command=\"vm-handler-next\"]').disabled"), true, 'Menu respects empty filter navigation');
      await click('.vm-listing-count');
      assert.equal(await evaluate("document.querySelector('.vm-menu[open]') === null"), true, 'Outside click closes menu');
      await click('.vm-symbol-row');
      assert.equal(await evaluate("document.querySelector('input[aria-label=\"Filter retained handlers\"]').value"), '', 'Symbol navigation clears an excluding filter');
      assert.equal(await evaluate("document.querySelector('.vm-handler-row[aria-selected=true]').hidden"), false);
      const panels = await evaluate("[...document.querySelectorAll('.vm-workbench-tabs [data-vm-panel]')].map(node=>node.dataset.vmPanel)");
      for (const expected of ['bytecode','reachability','coverage','unknowns','experiment','effects']) assert(panels.includes(expected));
      for (const panel of panels) {
        await click(`[data-vm-panel="${panel}"]`);
        assert.equal(await evaluate(`document.querySelector('[data-vm-panel-content="${panel}"]').hidden`), false);
      }
      await click('.vm-handler-list .vm-handler-row:nth-child(2)');
      assert.equal(await evaluate(`document.querySelectorAll('[data-vm-paged-rows="retained samples"] > details').length`), workspace.samples.length, 'Selected handler exposes every retained authored sample');
      for (let index = 1; index <= workspace.samples.length; index++) {
        const selector = `[data-vm-paged-rows="retained samples"] > details:nth-child(${index})`;
        await click(selector + ' > summary');
        assert.equal(await evaluate(`document.querySelector(${JSON.stringify(selector)}).open`), true, 'Retained sample audit expands');
        await click(selector + ' > summary');
      }
      await click('[data-vm-panel="bytecode"]');
      await click('[aria-label="Retained byte evidence"]');
      await key('Escape', 'Escape', 27);
      assert.deepEqual(await evaluate("[...document.querySelector('[aria-label=\"Retained byte evidence\"]').options].map(option=>option.textContent)"), workspace.snapshots.map(snapshot => `Artifact ${snapshot.artifact_id} · ${snapshot.byte_count} bytes`));
      await assertReachable('[aria-label="Retained byte evidence"]', 'Retained byte evidence control ' + width);
      await screenshot(`vm-findings-bytes-${width}`);
      await click('[data-vm-panel="reachability"]');
      assert.equal(await evaluate("[...document.querySelectorAll('[aria-label=\"reachable instructions pages\"] button')].every(button=>button.disabled)"), true, 'Empty reachability cannot imply more retained rows');
      assert.match(await evaluate("document.querySelector('[aria-label=\"reachable instructions pages\"]').textContent"), /0–0 of 0/);
      await click('[data-vm-panel="effects"]');
      assert.equal(await evaluate("document.querySelector('.vm-program-example').open"), false, 'Example stays opt-in');
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
      await evaluate("document.querySelector('#vm-detail').scrollTop=0;document.querySelector('#vm-findings-workspace').scrollTop=0");
      await evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))');
      const {data} = await send('Page.captureScreenshot', {format: 'png'});
      await writeFile(join(output, `vm-full-shell-${width}.png`), Buffer.from(data, 'base64'));
      await evaluate("document.querySelector('.vm-workspace').scrollIntoView({block:'start'});");
      await evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))');
      const dock = await send('Page.captureScreenshot', {format: 'png'});
      await writeFile(join(output, `vm-full-shell-dock-${width}.png`), Buffer.from(dock.data, 'base64'));
    }
    // Populate independent workspaces through real file inputs and explicit
    // shipped Analyze controls. DOM reads below never install reports/state.
    await resize(1440);
    await click('#vm-show-execution');
    await importJSON('input[aria-label="Import VM execution trace"]', 'authored-execution-trace', executionTrace);
    await until(() => evaluate(`document.querySelector('[aria-label="Execution step"]').options.length===${executionTrace.steps.length}`), 'Exact authored execution trace admitted');
    await click('#vm-show-static');
    for (const [kind, label] of [['definition','definition'],['image','bytecode image']]) {
      await importJSON(`input[aria-label="Import static VM ${label} JSON"]`, 'authored-static-' + kind, staticInputs[kind]);
    }
    assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.getReport()'), null, 'Static import cannot imply Analyze');
    await click('[data-vm-static-action="analyze"]');
    await until(() => evaluate('vmExecutionWorkspace.staticAnalysis.getReport()?.coverage.instruction_count===16'), 'Static production analysis');
    await click('#vm-show-contextual');
    for (const kind of ['definition','image','evidence']) await importJSON(`input[aria-label="Import contextual ${kind} JSON"]`, 'authored-contextual-' + kind, contextualInputs[kind]);
    assert.equal(await evaluate('vmExecutionWorkspace.contextualAnalysis.getReport()'), null, 'Contextual import cannot imply Analyze');
    await clickLabel('#vm-contextual-workspace', 'Analyze build');
    await until(() => evaluate('vmExecutionWorkspace.contextualAnalysis.getLinked()?.observed_edges.length===1'), 'Contextual production analysis and evidence link');
    if (await evaluate("document.querySelector('#vm-contextual-workspace .vm-review-imports').open")) await click('#vm-contextual-workspace .vm-review-imports > summary');
    for (const width of [1440,1280,900,390]) {
      await resize(width);
      await click('#vm-show-execution');
      await menuAction('filter');
      assert.equal(await evaluate("document.activeElement.getAttribute('aria-label')"), 'Filter retained execution rows', 'Execution Search routes to its actual listing');
      assert.equal(await evaluate("document.querySelector('#vm-show-execution').getAttribute('aria-pressed')"), 'true');
      await click('#vm-semantics-workflow [data-vm-sequence="0"]');
      await menuAction('next');
      assert.equal(await evaluate("document.querySelector('[aria-label=\"Execution step\"]').value"), '1');
      await menuAction('previous');
      assert.equal(await evaluate("document.querySelector('[aria-label=\"Execution step\"]').value"), '0');
      await key('ArrowDown','ArrowDown',40);
      assert.equal(await evaluate("document.querySelector('[aria-label=\"Execution step\"]').value"), '1', 'Execution row keyboard navigation uses retained sequence');
      await assertFits('#vm-semantics-workflow', 'Populated Execution ' + width);
      await assertReachable('#vm-semantics-workflow [data-vm-sequence="1"]', 'Selected execution row ' + width);
      await screenshot(`vm-execution-populated-${width}`);
      await click('#vm-execution-view-path');
      assert.equal(await evaluate("document.querySelectorAll('#vm-semantics-workflow [data-vm-path-edge]').length"), executionTrace.steps.length - 1, 'Path draws only actual adjacent retained sequences');
      assert.match(await evaluate("document.querySelector('.vm-path-summary').textContent"), /not a static CFG/);
      await screenshot(`vm-execution-path-populated-${width}`);
      await click('#vm-execution-view-listing');
      if (await evaluate("document.querySelector('#vm-semantics-workflow').dataset.layout==='narrow'")) await click('#vm-semantics-workflow [data-vm-panel="state"]');
      await click('#vm-state-tab-registers');
      assert.equal(await evaluate("document.querySelector('#vm-state-panel [data-vm-location]').getAttribute('data-vm-location')"), 'registers:1');
      await assertReachable('#vm-state-tab-registers', 'Execution state tab ' + width);
      await screenshot(`vm-execution-state-populated-${width}`);

      await click('#vm-show-static');
      await menuAction('filter');
      assert.equal(await evaluate("document.activeElement.getAttribute('aria-label')"), 'Filter static bytecode instructions');
      assert.equal(await evaluate("document.querySelector('#vm-show-static').getAttribute('aria-pressed')"), 'true');
      await click('[data-vm-static-offset="0"]');
      await menuAction('next');
      assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.getSelected()'), staticReport.instructions[1].offset);
      await menuAction('previous');
      assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.getSelected()'), 0);
      await key('ArrowDown','ArrowDown',40);
      assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.getSelected()'), staticReport.instructions[1].offset);
      await assertFits('#vm-static-workspace', 'Populated Static ' + width);
      await assertReachable('[data-vm-static-offset="3"]', 'Selected static row ' + width);
      await screenshot(`vm-static-populated-${width}`);
      if (await evaluate("document.querySelector('#vm-static-workspace').dataset.layout==='narrow'")) await click('[data-vm-static-panel="details"]');
      await click('#vm-static-tab-pseudocode');
      assert.equal(await evaluate('document.querySelectorAll("[data-vm-static-pseudocode]").length'), 16, 'Pseudocode remains instruction-linked');
      await screenshot(`vm-static-pseudocode-populated-${width}`);
      await click('#vm-static-tab-cfg');
      assert.equal(await evaluate('document.querySelectorAll("[data-vm-static-node]").length'), staticReport.cfg.nodes.length);
      await screenshot(`vm-static-cfg-populated-${width}`);

      await click('#vm-show-contextual');
      await menuAction('filter');
      assert.equal(await evaluate("document.activeElement.getAttribute('aria-label')"), 'Filter decoder contexts');
      assert.equal(await evaluate("document.querySelector('#vm-show-contextual').getAttribute('aria-pressed')"), 'true');
      await click('[data-vm-contextual-id="context:0:start"]');
      await menuAction('next');
      assert.equal(await evaluate('vmExecutionWorkspace.contextualAnalysis.getSelected()'), contextualReport.analysis.instructions[1].id);
      await menuAction('previous');
      assert.equal(await evaluate('vmExecutionWorkspace.contextualAnalysis.getSelected()'), 'context:0:start');
      await click('[aria-label="Filter decoder contexts"]');
      await send('Input.insertText', {text: 'alternate'});
      assert.equal(await evaluate("document.querySelectorAll('[data-vm-contextual-id]').length"), 1);
      assert.equal(await evaluate('vmExecutionWorkspace.contextualAnalysis.getSelected()'), 'context:0:start', 'Filtering retains exact selected context');
      await clickLabel('#vm-contextual-workspace', 'Reveal selected context');
      assert.equal(await evaluate("document.querySelector('[aria-label=\"Filter decoder contexts\"]').value"), '');
      await click('[data-contextual-tab="instruction"]');
      await assertFits('#vm-contextual-workspace', 'Populated Contextual ' + width);
      await assertReachable('[data-contextual-tab="instruction"]', 'Contextual inspector tab ' + width);
      await screenshot(`vm-contextual-populated-${width}`);
      await click('[data-contextual-tab="edges"]');
      assert.match(await evaluate("document.querySelector('#vm-contextual-panel-edges').textContent"), /matches_declared/);
      await screenshot(`vm-contextual-edges-populated-${width}`);
      await click('[data-contextual-destination="context:3:done"]');
      assert.equal(await evaluate('vmExecutionWorkspace.contextualAnalysis.getSelected()'), 'context:3:done', 'Declared jump follows exact destination PC and decoder state');
      await click('[data-contextual-tab="instruction"]');
      assert.match(await evaluate("document.querySelector('#vm-contextual-panel-instruction').textContent"), /HALT/);
    }
    // Real File inputs and local actions, with an explicitly authored pack response.
    await send('Emulation.setDeviceMetricsOverride', {width: 1440, height: 900, deviceScaleFactor: 1, mobile: false});
    await click('#vm-show-packs');
    await click('[data-pack-inputs="compare"] > summary');
    for (const [label, name] of [['Analysis pack','pack.json'],['Left opcode workspace','build-a.workspace.json'],['Right opcode workspace','build-b.workspace.json']]) {
      await importFile(`input[aria-label="${label}"]`, join(root, 'tools/fixtures/vm-analysis-packs', name));
      await until(() => evaluate(`document.querySelector('input[aria-label="${label}"]').parentElement.textContent.includes('bytes')`), label + ' import');
    }
    for (const side of ['left','right']) { await click(`input[aria-label="${side} interpreter artifact ID"]`); await send('Input.insertText', {text: '1'}); }
    await clickLabel('#vm-packs-workspace', 'Compare builds');
    await until(() => evaluate("document.querySelector('#vm-packs-workspace .vm-tool-table tbody tr') !== null"), 'Structured comparison report');
    assert.equal(await evaluate("document.querySelector('[data-pack-inputs=all]').open"), false, 'Accepted pack result collapses outer inputs');
    const rawClosed = "[...document.querySelectorAll('#vm-packs-workspace details')].filter(node=>node.querySelector('.vm-pack-output')).every(node=>!node.open)";
    assert.equal(await evaluate(rawClosed), true);
    for (const width of [1440,1280,900,390]) {
      await resize(width);
      await menuAction('filter');
      assert.equal(await evaluate("document.activeElement.getAttribute('aria-label')"), 'Filter pack report rows');
      assert.equal(await evaluate("document.querySelector('#vm-show-packs').getAttribute('aria-pressed')"), 'true');
      await click('[data-pack-row="0"]');
      await menuAction('next');
      assert.equal(await evaluate("document.querySelector('[data-pack-row][aria-selected=true]').dataset.packRow"), '1');
      await menuAction('previous');
      assert.equal(await evaluate("document.querySelector('[data-pack-row][aria-selected=true]').dataset.packRow"), '0');
      await evaluate("document.querySelector('#vm-packs-workspace').scrollTop=0");
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true, `Populated packs fit at ${width}`);
      assert.equal(await evaluate("(()=>{const panel=document.querySelector('#vm-packs-workspace .vm-tool-results'),row=panel.querySelector('tbody tr');return row.getBoundingClientRect().bottom<=panel.getBoundingClientRect().bottom;})()"), true, 'Comparison rows are not hidden in a shrunken result viewport');
      await screenshot(`vm-packs-populated-${width}`);
      await clickLabel('#vm-packs-workspace .vm-review-tabs', 'Selected row');
      await assertReachable('#vm-packs-workspace .vm-review-tabs button:first-child', 'Packs selected-row tab ' + width);
      await assertReachable('#vm-packs-workspace .vm-review-detail h3', 'Packs selected-row detail ' + width);
      await screenshot(`vm-packs-inspector-${width}`);
      if (width === 390) await inspectTableRightEdge('#vm-packs-workspace', 'vm-packs');
    }
    await send('Emulation.setDeviceMetricsOverride', {width: 1440, height: 900, deviceScaleFactor: 1, mobile: false});
    await click('#vm-show-ledger');
    const definition = JSON.stringify({format: 'reb-vm-definition-v1', definition_id: 'authored-shell-fixture', architecture: 'stack',
      opcode_bytes: 1, operand_endianness: 'little', register_count: 0,
      opcodes: ['00','01','ff'].map(code => ({code, mnemonic: 'OP_' + code, operands: [], semantics: {operation: 'unknown', args: []}, flow: {kind: 'unknown'}}))});
    const ledger = await ledgerModel.createLedger(definition);
    ledger.entries.push({opcode: '00', status: 'inferred', meaning: 'Candidate constant handler', handler_location: null, operand_format: null,
      source_refs: [{artifact_id: 'authored-shell-fixture', event_id: null}], test_status: 'not_run', test_refs: [], unresolved_questions: ['Operand layout remains unknown.']});
    for (const [kind, text] of [['definition', definition], ['ledger', JSON.stringify(ledger)]]) {
      const path = join(profile, 'authored-' + kind + '.json'); await writeFile(path, text);
      await importFile(`input[aria-label="Import ${kind} JSON"]`, path);
      await until(() => evaluate(`document.querySelector('[data-ledger-editor="${kind}"] textarea').value.length > 0`), kind + ' import');
    }
    await clickLabel('#vm-ledger-workspace', 'Validate ledger');
    await until(() => evaluate("document.querySelector('#vm-ledger-workspace .vm-tool-table tbody tr') !== null"), 'Structured ledger report');
    assert.equal(await evaluate("[...document.querySelectorAll('[data-ledger-editor]')].every(node=>!node.open)"), true);
    for (const width of [1440,1280,900,390]) {
      await resize(width);
      await menuAction('filter');
      assert.equal(await evaluate("document.activeElement.getAttribute('aria-label')"), 'Filter opcode coverage');
      assert.equal(await evaluate("document.querySelector('#vm-show-ledger').getAttribute('aria-pressed')"), 'true');
      await click('[aria-label="Inspect opcode 00"]');
      await menuAction('next');
      assert.equal(await evaluate("document.querySelector('[data-ledger-opcode][aria-selected=true]').dataset.ledgerOpcode"), '01');
      await menuAction('previous');
      assert.equal(await evaluate("document.querySelector('[data-ledger-opcode][aria-selected=true]').dataset.ledgerOpcode"), '00');
      await evaluate("document.querySelector('#vm-ledger-workspace').scrollTop=0");
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true, `Populated ledger fits at ${width}`);
      assert.equal(await evaluate("(()=>{const panel=document.querySelector('#vm-ledger-workspace .vm-tool-results'),row=panel.querySelector('tbody tr');return row.getBoundingClientRect().bottom<=panel.getBoundingClientRect().bottom;})()"), true, 'Ledger rows are not hidden in a shrunken result viewport');
      await screenshot(`vm-ledger-populated-${width}`);
      await clickLabel('#vm-ledger-workspace .vm-review-tabs', 'Entry');
      await assertReachable('#vm-ledger-workspace .vm-review-tabs button:first-child', 'Ledger Entry tab ' + width);
      await assertReachable('#vm-ledger-workspace .vm-review-inspector [role="tabpanel"] h4', 'Ledger selected-entry detail ' + width);
      await screenshot(`vm-ledger-inspector-${width}`);
      if (width === 390) await inspectTableRightEdge('#vm-ledger-workspace', 'vm-ledger');
    }
    // Live presentation receives only the checked-in authored read response.
    // Every native action endpoint remains 405; selection never executes a VM.
    liveView = populatedLiveView;
    await resize(1440); await click('#vm-show-owned');
    await click('[data-owned-vm-refresh]');
    await until(() => evaluate("document.querySelectorAll('[data-owned-vm-sequence]').length===5"), 'Read-only authored Live records admitted');
    for (const width of [1440,1280,900,390]) {
      await resize(width);
      await menuAction('filter');
      assert.equal(await evaluate('document.activeElement.textContent'), 'All retained opcodes', 'Live Search focuses its actual opcode filter');
      assert.equal(await evaluate("document.querySelector('#vm-show-owned').getAttribute('aria-pressed')"), 'true');
      await click('[data-owned-vm-sequence="1"]');
      await menuAction('next');
      assert.equal(await evaluate("document.querySelector('#vm-owned-debugger').dataset.ownedVmSelection"), '2');
      await menuAction('previous');
      assert.equal(await evaluate("document.querySelector('#vm-owned-debugger').dataset.ownedVmSelection"), '1');
      await key('ArrowDown','ArrowDown',40);
      assert.equal(await evaluate("document.querySelector('#vm-owned-debugger').dataset.ownedVmSelection"), '2');
      assert.equal(await evaluate("document.querySelector('#vm-owned-debugger').dataset.ownedVmExecuted"), '5', 'History navigation cannot move execution cursor');
      await assertFits('#vm-owned-debugger', 'Populated read-only Live ' + width);
      await assertReachable('[data-owned-vm-sequence="2"]', 'Selected Live record ' + width);
      await screenshot(`vm-live-authored-populated-${width}`);
      await clickLabel('#vm-owned-debugger .owned-vm-debugger-tabs', 'Registers');
      assert.match(await evaluate("document.querySelector('.owned-vm-debugger-registers').textContent"), /5 \(0x5; observed\)/);
      assert.match(await evaluate("document.querySelector('.owned-vm-debugger-registers').textContent"), /unknown/);
      await assertLiveStateLabels('.owned-vm-debugger-registers', 'Live registers ' + width);
      await screenshot(`vm-live-authored-registers-${width}`);
      await click('[data-owned-vm-sequence="4"]');
      await clickLabel('#vm-owned-debugger .owned-vm-debugger-tabs', 'Memory');
      assert.match(await evaluate("document.querySelector('.owned-vm-debugger-memory').textContent"), /memory:16/);
      assert.match(await evaluate("document.querySelector('.owned-vm-debugger-memory').textContent"), /12 \(0xc; observed\)/);
      await assertLiveStateLabels('.owned-vm-debugger-memory', 'Live memory ' + width);
      await screenshot(`vm-live-authored-memory-${width}`);
      if (width === 390) await inspectTableRightEdge('#vm-owned-debugger .owned-vm-debugger-state-panel:not([hidden])', 'vm-live-authored-memory', '.owned-vm-debugger-table-scroll');
      await click('[data-owned-vm-initial]');
      assert.equal(await evaluate("document.querySelector('#vm-owned-debugger').dataset.ownedVmSelection"), 'initial');
      await click('[data-owned-vm-follow]');
      assert.equal(await evaluate("document.querySelector('#vm-owned-debugger').dataset.ownedVmSelection"), 'live');
      await evaluate("document.querySelector('[data-owned-vm-action=stop]').scrollIntoView({block:'center'})");
      await evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))');
      await assertReachable('[data-owned-vm-action="stop"]', 'Live Stop control remains reachable ' + width);
      assert.equal(await evaluate("document.querySelector('[data-owned-vm-action=stop]').disabled"), false);
      assert.equal(await evaluate("document.querySelector('[data-owned-vm-action=create]').disabled"), true, 'An existing authored run cannot expose Create');
      await screenshot(`vm-live-authored-controls-${width}`);
    }
    // Exercise the actual HTTP loader and Coverage tab with zero authored samples.
    // Canvas, a retained snapshot and static handlers do not create guest evidence.
    Object.assign(fixture, noSamplerFixture);
    analysis.results[0].runtime = 'webassembly';
    await evaluate('refreshVmAnalysis()');
    await click('#vm-show-findings');
    await until(() => evaluate("state.vmOpcodeWorkspace?.summary.sample_count === 0"), 'no-samples workspace through HTTP');
    for (const width of [1440, 390]) {
      await resize(width);
      await click('[data-vm-panel="coverage"]');
      await key('Enter', 'Enter', 13);
      assert.equal(await evaluate("document.activeElement.dataset.vmPanel"), 'coverage', 'Coverage remains keyboard operable');
      const omissionSelector = '[data-vm-panel-content="coverage"] .vm-coverage-omissions li:last-child';
      assert.equal(await evaluate(`document.querySelector(${JSON.stringify(omissionSelector)}).textContent`),
        'sampler-unavailable: ' + samplerOmission.detail, 'Complete diagnostic survives the shipped renderer');
      await evaluate(`document.querySelector(${JSON.stringify(omissionSelector)}).scrollIntoView({block:'center',inline:'nearest'})`);
      await evaluate('new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))');
      await assertReachable(omissionSelector, 'Complete no-sampler diagnostic ' + width);
      await assertFits('[data-vm-panel-content="coverage"]', 'No-sampler Coverage ' + width);
      assert.equal(await evaluate("document.querySelector('.vm-selection-inspector').textContent.includes('No retained PC or guest-byte position.')"), true);
      await screenshot(`vm-no-sampler-coverage-${width}`);
    }
    assert.equal(requests.some(request => request.path === '/api/vm-debugger/actions'), false, 'No native command was sent by read-only Live presentation');
    assert.deepEqual(errors, []);
    assert.equal(requests.some(request => request.method !== 'GET' && !(request.method === 'POST' && request.path === '/api/analysis/vm/packs/compare')), false, 'Only exact authored comparison may POST');
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'passed', viewports: [1440,1280,900,390],
      scope: 'Actual index.html and shipped scripts. Authored retained Findings, imported fixed-program Execution trace, actual local Static/Contextual analysis, declared versus supplied jump linkage, real File imports, current-mode menu routing, and authored pack/ledger results at every viewport. No-sampler Coverage exposes the complete producer diagnostic with the observed missing samples and automatic sampler limitation first at wide and narrow widths. Live is a read-only presentation of checked-in independent golden transitions; no native command or command completion was fabricated. No live capture, native-helper execution or imported-code execution.',
      populated_modes: ['findings','execution','static','contextual','packs','ledger','owned'],
      fixture_counts: {execution_steps: executionTrace.steps.length, static_instructions: staticReport.coverage.instruction_count, contextual_contexts: contextualReport.analysis.instructions.length, contextual_observed_edges: contextualReport.observed_edges.length, live_golden_records: liveRecords.length}, requests}, null, 2));
    console.log(`PASS full VM product shell: ${output}`);
  } catch (error) {
    if (socket?.readyState === 1) {
      try { const {data} = await send('Page.captureScreenshot', {format: 'png'}); await writeFile(join(output, 'failure.png'), Buffer.from(data, 'base64')); } catch { /* Preserve the original failure. */ }
    }
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'failed', error: String(error.stack || error), diagnostics, errors}, null, 2));
    throw error;
  } finally {
    for (const request of pending.values()) clearTimeout(request.timer);
    socket?.close();
    if (browser?.pid) {
      for (const signal of ['SIGTERM', 'SIGKILL']) {
        try { if (process.platform !== 'win32') process.kill(-browser.pid, signal); else if (!closed) browser.kill(signal); }
        catch (error) { if (error.code !== 'ESRCH') throw error; }
        const end = Date.now() + 2000; while (!closed && Date.now() < end) await pause(25);
        if (closed) break;
      }
    }
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    if (!browser?.pid || closed) await rm(profile, {recursive: true, force: true, maxRetries: 5, retryDelay: 100});
    else throw Error(`Browser did not close; retained its owned profile at ${profile}`);
  }
