#!/usr/bin/env node
// Full shipped page with authored loopback responses; never native capture.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, writeFile, rm, mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {runInNewContext} from 'node:vm';
const root = fileURLToPath(new URL('..', import.meta.url));
const output = process.env.REB_VM_FULL_SHELL_OUTPUT || join(root, 'build/vm-workspace-ui-qa/full-shell');
const html = await readFile(join(root, 'apps/research-ui/index.html'), 'utf8');
const model = await readFile(join(root, 'apps/research-ui/evidence_models.js'), 'utf8');
const fixture = JSON.parse(await readFile(join(root, 'tests/research_ui/fixtures/vm-opcode-workspace-v2.json'), 'utf8'));
const workspace = fixture.workspaces[0];
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
const assets = new Set(['index.html', ...[...html.matchAll(/(?:src|href)="([^"/]+\.(?:js|css))"/g)].map(match => match[1])]);
const requests = [];
const server = createServer(async (request, response) => {
  const path = request.url.split('?')[0];
  const json = value => { response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(value)); };
  if (path.startsWith('/api/')) {
    requests.push({method: request.method, path});
    if (request.method !== 'GET') { response.statusCode = 405; json({error: 'Read-only authored fixture'}); return; }
    if (path === '/api/events') return json({count: 0, events: [], capture_mode: 'demo', broker_connected: false, capture_stopped: true});
    if (path === '/api/artifacts') return json({count: 0, artifacts: []});
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
  for (const [method, url, status] of [['GET', '/api/unavailable', 503], ['POST', '/api/analysis/vm', 405], ['GET', '/api/analysis/vm', 200]]) {
    const response = {statusCode: 200, headersSent: false, headers: {},
      setHeader(name, value) { assert.equal(this.headersSent, false, 'Headers must precede body'); this.headers[name] = value; },
      writeHead(code) { this.statusCode = code; this.headersSent = true; },
      end(body) { this.headersSent = true; this.body = body; }};
    server.emit('request', {url, method}, response);
    assert.equal(response.statusCode, status);
    assert.equal(response.headers['content-type'], 'application/json');
    assert.doesNotThrow(() => JSON.parse(response.body));
  }
  server.close();
  console.log('PASS full-shell authored HTTP contracts and response ordering (not rendered)');
  process.exit(0);
}
  const profile = await mkdtemp(join(tmpdir(), 'reb-vm-workspace-'));
  let browser, socket, closed = false, diagnostics = '', sequence = 0;
  const pending = new Map(), errors = [], pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  const until = async (test, label) => {
    const end = Date.now() + 10000;
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
  await mkdir(output, {recursive: true});
  try {
    await new Promise((ready, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ready); });
    browser = spawn(process.env.REB_UI_CHROMIUM || '/usr/bin/chromium', ['--headless=new', '--remote-debugging-port=0',
      `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
      '--disable-component-update', '--disable-sync', 'about:blank'], {detached: process.platform !== 'win32', stdio: ['ignore', 'ignore', 'pipe']});
    browser.once('close', () => { closed = true; }); browser.on('error', error => { diagnostics += String(error); });
    browser.stderr.on('data', chunk => { diagnostics = (diagnostics + chunk).slice(-8192); });
    let port;
    await until(async () => {
      if (closed) throw Error(`Sandboxed Chromium startup failed: ${diagnostics}`);
      try { port = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; return !!port; }
      catch { return false; }
    }, 'sandboxed Chromium startup');
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
    await until(() => evaluate("typeof state !== 'undefined' && state.vmFindings.length > 0"), 'authored finding through real HTTP loader');
    const click = async selector => {
      const point = await evaluate(`(async()=>{const node=document.querySelector(${JSON.stringify(selector)});node.scrollIntoView({block:'center'});await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));const b=node.getBoundingClientRect();return {x:b.x+b.width/2,y:b.y+b.height/2};})()`);
      for (const type of ['mousePressed','mouseReleased']) await send('Input.dispatchMouseEvent',{type,...point,button:'left',clickCount:1});
    };
    const key = async (key, code, value) => {
      for (const type of ['rawKeyDown','keyUp']) await send('Input.dispatchKeyEvent',{type,key,code,windowsVirtualKeyCode:value});
    };
    const modes = await evaluate("[...document.querySelectorAll('.vm-workspace-switch button')].map(node=>[node.id.replace('vm-show-',''),node.getAttribute('aria-controls')])");
    for (const expected of ['findings','execution','owned','static','contextual']) assert(modes.some(([mode]) => mode === expected));
    for (const width of [1440, 900, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      await click('#nav-vm-workspace');
      assert.equal(await evaluate("document.querySelector('#screen-vm').hidden"), false);
      for (const [mode, panel] of modes) {
        await click('#vm-show-' + mode);
        assert.equal(await evaluate(`document.querySelector('#${panel}').hidden`), false, `${mode} panel at ${width}`);
        assert.equal(await evaluate(`document.querySelector('#vm-show-${mode}').getAttribute('aria-pressed')`), 'true');
        assert.equal(await evaluate(`(()=>{const n=document.querySelector('#vm-show-${mode}'),r=n.getBoundingClientRect();return r.width>0&&r.height>0&&r.left>=0&&r.right<=innerWidth+1&&r.top>=0&&r.bottom<=innerHeight&&n.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2));})()`), true, `${mode} control reachable at ${width}`);
      }
      await click('#vm-show-findings');
      await click('#vm-list .vm-row');
      await key('ArrowDown', 'ArrowDown', 40);
      assert.equal(await evaluate("document.activeElement.classList.contains('vm-row')"), true);
      await until(() => evaluate("document.querySelectorAll('.vm-workbench-tabs button').length >= 6"), 'actual finding analysis tabs');
      const panels = await evaluate("[...document.querySelectorAll('.vm-workbench-tabs [data-vm-panel]')].map(node=>node.dataset.vmPanel)");
      for (const expected of ['bytecode','reachability','coverage','unknowns','experiment','effects']) assert(panels.includes(expected));
      for (const panel of panels) {
        await click(`[data-vm-panel="${panel}"]`);
        assert.equal(await evaluate(`document.querySelector('[data-vm-panel-content="${panel}"]').hidden`), false);
      }
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
    assert.deepEqual(errors, []);
    assert.equal(requests.some(request => request.method !== 'GET'), false, 'Navigation never executes or mutates');
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'passed', viewports: [1440,900,390],
      scope: 'Actual index.html, shipped scripts, HTTP admission of authored retained finding, five mode controls and six analysis panels. No live capture, native runtime or VM execution.', requests}, null, 2));
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
