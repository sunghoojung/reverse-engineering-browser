#!/usr/bin/env node
// Authored fixtures and shipped rendering functions only. No captured WASM is executed.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, writeFile, rm, mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
import {workspaceUiCases} from './vm-workspace-ui-cases.mjs';
import {ownedOpcodeExperimentUiCase, checkOwnedOpcodeExperimentUi} from './owned-opcode-experiment-ui-cases.mjs';
import {pressRenderedEnter} from './rendered-keyboard.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const output = process.env.REB_VM_WORKSPACE_UI_OUTPUT || join(root, 'build/vm-workspace-ui-qa');
const app = await readFile(join(root, 'apps/research-ui/app.js'), 'utf8');
const model = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const fixture = JSON.parse(await readFile(join(root, 'tests/research_ui/fixtures/vm-opcode-workspace-v2.json'), 'utf8'));
const hostWorkspace = structuredClone(fixture), hostSource = hostWorkspace.workspaces[0], sample = hostSource.samples[0];
const hostLinks = {contract_version: 1, document_kind: 'vm-host-links', workspace_document_digest: hostWorkspace.document_digest,
  document_digest: 'e'.repeat(64), workspaces: [{interpreter_artifact_id: hostSource.interpreter_artifact_id,
    source_artifact_sha256: hostSource.source_artifact_sha256, omissions: [], links: [{
      host_event: {...sample.event, sequence_number: '50'}, category: 'runtime', type: 'api_call', state: 'observed',
      reason: 'direct-dispatch-parent', guest_position: {sample_event: sample.event, invocation_event: sample.invocation_event,
        invocation_id: sample.invocation_id, instruction_pointer: sample.instruction_pointer,
        instruction_pointer_units: sample.instruction_pointer_units}}]}]};
assert(runInNewContext(`${model}\nisVmHostLinksDocument(hostLinks, hostWorkspace)`, {hostLinks, hostWorkspace, TextEncoder}));
const workspaceCases = await workspaceUiCases();
await ownedOpcodeExperimentUiCase();
const workspace = fixture.workspaces[0];
workspace.runtime = 'webassembly'; workspace.model = 'unknown'; workspace.samples = []; workspace.sample_count = 0;
workspace.handlers = [
  {opcode: 0, state: 'inferred', source: {byte_offset: 45, byte_size: 5}, label: 'br_table selector 0', operand_width: 0,
    sample_count: 0, effects: [], notes: 'Dispatch selector only; guest opcode binding is unproven.'},
  {opcode: null, state: 'unknown', source: {byte_offset: 50, byte_size: 3}, label: 'call_indirect target', operand_width: 0,
    sample_count: 0, effects: [], notes: '<img src=x onerror=alert(1)> is inert captured text. No static index.'},
  {opcode: 0, state: 'inferred', source: {byte_offset: 70, byte_size: 5}, label: 'br_table selector 0', operand_width: 0,
    sample_count: 0, effects: [], notes: 'A separate dispatch site has its own selector 0.'}
];
workspace.coverage.handler_count = fixture.summary.handler_count = 3; fixture.summary.sample_count = 0;
assert(runInNewContext(`${model}\nisVmOpcodeWorkspaceDocument(fixture)`, {fixture, TextEncoder}));
const helper = app.slice(app.indexOf('      function textElement('), app.indexOf('      function emptyListboxOption('));
const renders = app.slice(app.indexOf('      function vmField('), app.indexOf('      function renderVmOpcodeWorkspaceInPlace('));
assert(helper.includes('function textElement')); assert(renders.includes('function renderVmOpcodeWorkspace'));
console.log('PASS authored WASM, host links, coverage, effects, traversal and experiment fixtures plus shipped-renderer boundaries (model check, not rendered QA)');

if (process.argv.includes('--browser')) {
  const selected = {findingId: 'analysis:c5e529342af22aafd3d7ddbc', sourceArtifactId: '302'};
  const setup = `const fixture=${JSON.stringify(fixture)};const selected=${JSON.stringify(selected)};
const hostWorkspace=${JSON.stringify(hostWorkspace)},hostLinks=${JSON.stringify(hostLinks)};
const state={vmOpcodeWorkspace:fixture,lastValidVmOpcodeWorkspace:fixture,vmOpcodeWorkspaceStatus:'ready',selectedVmHandlerKey:null,vmFindings:[selected],selectedVmFindingId:selected.findingId,
vmAnalysisDocument:{document_digest:fixture.analysis_digest,capture_mode:'unknown'}};
const elements={vmSessionStatus:document.querySelector('#status')};
function render(){document.querySelector('#workspace').replaceChildren(renderVmOpcodeWorkspace(selected));renderVmSessionStatus();}
render();`;
  const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/app.css"><style>html,body{overflow:auto;height:auto;min-height:100%}body{margin:0}main{padding:16px;max-width:1100px;margin:auto;min-width:0}</style>
</head><body><main><p>Authored VM workspace states and experiment HTTP receipts. No captured source execution or browser capture.</p><div id="status" class="vm-session-status"></div><div id="workspace"></div></main>
<script>${model}\n${helper}\n${renders}\n${setup}</script></body></html>`;
  const css = await readFile(join(root, 'apps/research-ui/app.css'));
  const server = createServer((request, response) => {
    if (request.url === '/') { response.setHeader('content-type', 'text/html'); response.end(html); }
    else if (request.url === '/app.css') { response.setHeader('content-type', 'text/css'); response.end(css); }
    else response.writeHead(404).end();
  });
  const profile = await mkdtemp(join(tmpdir(), 'reb-vm-workspace-'));
  let browser, socket, closed = false, diagnostics = '', sequence = 0;
  const startup = {executable: process.env.REB_UI_CHROMIUM || '/usr/bin/chromium', pid: null,
    elapsed_ms: 0, exit_code: null, signal: null, spawn_error: null, port_file: 'not checked'};
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
    const result = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    if (result.exceptionDetails) throw Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  const exerciseDisclosure = async selector => {
    const row = `document.querySelector(${JSON.stringify(selector)})`;
    await evaluate(`${row}.querySelector('summary').focus()`);
    assert.equal(await evaluate(`${row}.open`), false, `${selector}: initially closed`);
    for (const open of [true, false, true]) {
      assert.equal(await evaluate(`document.activeElement === ${row}.querySelector('summary')`), true, `${selector}: keyboard focus`);
      await pressRenderedEnter(send);
      assert.equal(await evaluate(`${row}.open`), open, `${selector}: Enter toggles native disclosure`);
    }
  };
  await mkdir(output, {recursive: true});
  try {
    await new Promise((ready, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ready); });
    const startupStarted = Date.now();
    browser = spawn(startup.executable, ['--headless=new', '--remote-debugging-port=0',
      `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
      '--disable-component-update', '--disable-sync', 'about:blank'], {detached: process.platform !== 'win32', stdio: ['ignore', 'ignore', 'pipe']});
    startup.pid = browser.pid ?? null;
    browser.once('close', () => { closed = true; });
    browser.once('exit', (code, signal) => { startup.exit_code = code; startup.signal = signal; });
    browser.on('error', error => { startup.spawn_error = String(error).slice(0, 2048); });
    browser.stderr.on('data', chunk => { diagnostics = (diagnostics + chunk).slice(-8192); });
    let port;
    await until(async () => {
      startup.elapsed_ms = Date.now() - startupStarted;
      if (startup.spawn_error || closed || browser.exitCode !== null || browser.signalCode !== null) {
        throw Error(`Sandboxed Chromium startup failed: ${JSON.stringify(startup)}; ${diagnostics}`);
      }
      try {
        port = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0];
        const ready = /^[1-9][0-9]{0,4}$/.test(port) && Number(port) <= 65535;
        startup.port_file = ready ? 'ready' : 'incomplete or invalid port';
        return ready;
      } catch (error) {
        startup.port_file = String(error.code ?? error.message).slice(0, 256);
        if (error.code !== 'ENOENT') throw error;
        return false;
      }
    }, 'sandboxed Chromium startup', 30000);
    console.log(`Sandboxed Chromium ready after ${startup.elapsed_ms} ms`);
    const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    socket = new WebSocket(pages.find(page => page.type === 'page').webSocketDebuggerUrl);
    await new Promise((ready, reject) => { socket.addEventListener('open', ready, {once: true}); socket.addEventListener('error', reject, {once: true}); });
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data), request = pending.get(message.id);
      if (message.method === 'Runtime.exceptionThrown') errors.push(message.params);
      if (!request) return;
      pending.delete(message.id); clearTimeout(request.timer);
      if (message.error) request.reject(Error(message.error.message)); else request.resolve(message.result);
    });
    await send('Runtime.enable'); await send('Page.enable');
    await send('Page.navigate', {url: `http://127.0.0.1:${server.address().port}/`});
    await until(() => evaluate("document.querySelectorAll('.vm-handler-row').length === 3"), 'WASM handler rows');
    const text = await evaluate('document.body.textContent');
    assert(text.includes('WebAssembly')); assert(text.includes('3 dispatch-arm candidates')); assert(text.includes('unknown'));
    assert.equal(await evaluate("document.querySelectorAll('#workspace img').length"), 0);
    for (const width of [1440, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      const point = await evaluate("(async()=>{const e=document.querySelector('.vm-handler-row');e.scrollIntoView({block:'center'});await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));const b=e.getBoundingClientRect();return{x:b.x+b.width/2,y:b.y+b.height/2};})()");
      for (const type of ['mousePressed', 'mouseReleased']) await send('Input.dispatchMouseEvent', {type, ...point, button: 'left', clickCount: 1});
      for (const type of ['rawKeyDown', 'keyUp']) await send('Input.dispatchKeyEvent', {type, key: 'ArrowDown', code: 'ArrowDown', windowsVirtualKeyCode: 40});
      assert.equal(await evaluate("document.activeElement === document.querySelectorAll('.vm-handler-row')[1]"), true);
      assert.equal(await evaluate("document.activeElement.getAttribute('aria-selected')"), 'true');
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
      await evaluate('scrollTo(0,0)');
      const {data} = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
      await writeFile(join(output, `wasm-${width}.png`), Buffer.from(data, 'base64'));
      for (const [mode, label] of [['native-stealth', 'Native stealth'], ['cdp-attached', 'CDP attached'], ['unknown', 'Recorded evidence']]) {
        await evaluate(`fixture.workspaces[0].capture_mode=${JSON.stringify(mode)};state.debuggerSession={state:'running',target:{}};renderVmSessionStatus()`);
        assert.equal(await evaluate("document.querySelector('.vm-session-chip').textContent"), label);
        assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
        const capture = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
        await writeFile(join(output, `capture-${mode}-${width}.png`), Buffer.from(capture.data, 'base64'));
      }
      await evaluate("fixture.workspaces[0].capture_mode='native-stealth';state.vmAnalysisDocument.document_digest='stale';renderVmSessionStatus()");
      assert.equal(await evaluate("document.querySelector('.vm-session-chip').textContent"), 'Recorded evidence');
      await evaluate("delete state.vmAnalysisDocument.capture_mode;state.broker='connected';state.sessionMode='live';renderVmSessionStatus()");
      assert.equal(await evaluate("document.querySelector('.vm-session-chip').textContent"), 'Recorded evidence');
      await evaluate("state.vmAnalysisDocument={document_digest:fixture.analysis_digest,capture_mode:'unknown'};renderVmSessionStatus()");

    }
    await evaluate("state.vmOpcodeWorkspace=hostWorkspace;state.vmHostLinks=hostLinks;state.vmHostLinksStatus='ready';render()");
    assert((await evaluate('document.body.textContent')).includes('event 1:1:50'));
    assert((await evaluate('document.body.textContent')).includes('exact request-value provenance'));
    for (const width of [1440, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
      const {data} = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
      await writeFile(join(output, `host-links-${width}.png`), Buffer.from(data, 'base64'));
    }
    await evaluate("hostLinks.workspace_document_digest='stale';render()");
    assert((await evaluate('document.body.textContent')).includes('Guest position unknown'));
    for (const width of [1440, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      for (const [name, value] of Object.entries(workspaceCases).filter(([name]) => name !== 'malformed')) {
        await evaluate(`state.vmOpcodeWorkspace=${JSON.stringify(value)};state.vmOpcodeWorkspaceStatus='ready';state.vmHostLinks=null;render()`);
        const current = value.workspaces[0], coverage = current.coverage;
        assert.equal(await evaluate("document.querySelector('.vm-coverage-line strong').textContent"),
          `${coverage.characterized_bytes} / ${coverage.retained_snapshot_bytes}`);
        assert.equal(await evaluate("document.querySelector('.vm-coverage-bar').getAttribute('aria-valuenow')"),
          String(coverage.retained_snapshot_bytes ? coverage.characterized_bytes * 100 / coverage.retained_snapshot_bytes : 0));
        const body = await evaluate('document.body.textContent');
        assert(body.includes(`${coverage.uncharacterized_bytes} uncharacterized bytes`));
        for (const omission of coverage.omissions) assert(body.includes(omission.reason));
        if (name === 'contradicted') {
          assert(body.includes('conflicting effects')); assert(body.includes('none is selected for traversal'));
          assert(body.includes('register[unknown] = unknown'));
          assert.equal(await evaluate("document.querySelectorAll('[aria-label=\"Declarative opcode effects\"] .vm-effect-row').length"), 3);
          await exerciseDisclosure('[aria-label="Declarative opcode effects"] details');
        }
        if (name.startsWith('walk_')) {
          assert.equal(await evaluate("document.querySelectorAll('.vm-reachable-list details').length"), current.traversal.instructions.length);
          assert(body.includes(`branch_taken → ${name === 'walk_frontier' ? 99 : 2}`));
          assert(body.includes('branch_not_taken → 2'));
          assert(body.includes(name === 'walk_frontier' ? 'frontier remains' : 'walk complete'));
          if (name === 'walk_frontier') assert(body.includes('byte 99: past-snapshot'));
          await exerciseDisclosure('.vm-reachable-list details');
          assert.equal(await evaluate("(()=>{const e=document.querySelector('.vm-reachable-list .vm-effect-detail');return e.getBoundingClientRect().height>0 && getComputedStyle(e).visibility==='visible';})()"), true);
          const visibleEdges = await evaluate("document.querySelector('.vm-reachable-list .vm-effect-detail').innerText");
          assert(visibleEdges.includes(`branch_taken → ${name === 'walk_frontier' ? 99 : 2}`));
          assert(visibleEdges.includes('branch_not_taken → 2'));
        }
        assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true);
        await evaluate('scrollTo(0,0)');
        const {data} = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
        await writeFile(join(output, `workspace-${name}-${width}.png`), Buffer.from(data, 'base64'));
      }
      await checkOwnedOpcodeExperimentUi({evaluate, send});
      await evaluate('scrollTo(0,0)');
      const {data} = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: true});
      await writeFile(join(output, `owned-experiment-${width}.png`), Buffer.from(data, 'base64'));
    }
    await evaluate("state.vmOpcodeWorkspace=fixture;state.lastValidVmOpcodeWorkspace=fixture;state.vmHostLinks=null;render()");
    await evaluate(`if(!isVmOpcodeWorkspaceDocument(${JSON.stringify(workspaceCases.malformed)})) retainVmOpcodeWorkspaceOnFailure(state,'malformed','synthetic malformed fixture');render()`);
    assert.equal(await evaluate('state.vmOpcodeWorkspace === fixture'), true);
    assert((await evaluate('document.body.textContent')).includes('last valid workspace is retained'));
    await evaluate("state.vmOpcodeWorkspace={...fixture,workspaces:[]};state.vmOpcodeWorkspaceStatus='ready';render()");
    assert.equal(await evaluate("document.querySelectorAll('.vm-handler-row').length"), 0);
    assert((await evaluate('document.body.textContent')).includes('Workspace unavailable for this finding'));
    assert.deepEqual(errors, []);
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'passed', startup, viewports: [1440, 390],
      cases: ['wasm', 'capture-mode', 'host-links', ...Object.keys(workspaceCases), 'owned-experiment'],
      scope: 'Shipped workspace rendering and authored experiment HTTP failures; no native execution, browser capture or full-app polling acceptance'}, null, 2));
    console.log(`PASS rendered VM workspace states, authored experiment failure, keyboard selection, inert text, narrow layout, retained error and empty states: ${output}`);
  } catch (error) {
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'failed', error: String(error.stack || error), diagnostics, startup, errors}, null, 2));
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
}
