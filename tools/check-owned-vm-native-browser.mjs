#!/usr/bin/env node
// Real Rust API + real native fixture + integrated UI. No response fixtures,
// browser emulation of VM execution, or sandbox-disabling launch flags.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {constants} from 'node:fs';
import {access, mkdir, mkdtemp, readFile, realpath, rm, stat, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {checkOwnedVmDebuggerInteractions, ownedVmRenderedKeyEvents} from './check-owned-vm-debugger-ui.mjs';
import debuggerUI from '../apps/research-ui/vm_debugger.js';

const usage = 'Usage: node tools/check-owned-vm-native-browser.mjs --backend PATH --helper PATH --browser PATH --output DIR';
function argumentsForRun(args) {
  if (args.length === 1 && args[0] === '--help') return null;
  const result = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    if (!['--backend', '--helper', '--browser', '--output'].includes(name) || result[name.slice(2)] || !args[index + 1] || args[index + 1].startsWith('--')) throw Error(usage);
    result[name.slice(2)] = resolve(args[index + 1]);
  }
  if (Object.keys(result).length !== 4) throw Error(usage);
  return result;
}
const delay = ms => new Promise(done => setTimeout(done, ms));
const bound = value => String(value).slice(-8192);
async function executable(path, name) {
  try { const resolved = await realpath(path); assert((await stat(resolved)).isFile()); await access(resolved, constants.X_OK); return resolved; }
  catch (error) { throw Error(`${name} executable unavailable: ${path} (${error.code || error.message})`); }
}
function ownedProcess(path, args, cwd) {
  const child = spawn(path, args, {cwd, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe']});
  const state = {child, closed: false, error: null, stdout: '', stderr: '', forced: false};
  child.stdout.on('data', bytes => { state.stdout = bound(state.stdout + bytes); });
  child.stderr.on('data', bytes => { state.stderr = bound(state.stderr + bytes); });
  child.once('error', error => { state.error = error; }); child.once('close', () => { state.closed = true; });
  return state;
}
function groupAlive(processState) {
  if (!processState?.child.pid) return false;
  if (process.platform === 'win32') return !processState.closed;
  try { process.kill(-processState.child.pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}
function signalOwned(processState, signal, group = false) {
  if (!processState?.child.pid) return;
  try {
    if (group && process.platform !== 'win32') process.kill(-processState.child.pid, signal);
    else if (!processState.closed) processState.child.kill(signal);
  } catch (error) { if (error.code !== 'ESRCH') throw error; }
}
async function waitStopped(processState, timeout) {
  const deadline = Date.now() + timeout;
  while ((!processState.closed || groupAlive(processState)) && Date.now() < deadline) await delay(25);
  return processState.closed && !groupAlive(processState);
}

export async function runOwnedVmNativeBrowser(options) {
  if (process.platform === 'win32') throw Error('This native process-lifecycle gate requires macOS or Linux.');
  const repository = fileURLToPath(new URL('..', import.meta.url));
  await mkdir(options.output, {recursive: true});
  const output = await mkdtemp(join(options.output, 'run-'));
  const receipt = {schema: 'reb-owned-vm-native-browser-validation-v1', status: 'running',
    scope: 'actual Rust backend, native owned fixture, and integrated research UI; no mocked responses',
    started_at: new Date().toISOString(), requested_binaries: options, output,
    viewports: [[1440, 900], [1024, 768], [390, 844]], screenshots: [], runtime_errors: [], http_errors: [], controls: [], cleanup: {}};
  let temporary = null, backend = null, browser = null, endpoint = null, socket = null, sequence = 0, phase = 'executable preflight', failure = null, abortReason = null;
  const commands = new Map();
  const cancel = message => {
    abortReason ||= Error(message);
    for (const command of commands.values()) { clearTimeout(command.timer); command.reject(abortReason); } commands.clear();
  };
  const interrupted = () => cancel('Native browser validation was interrupted; owned processes will be disposed.');
  process.once('SIGINT', interrupted); process.once('SIGTERM', interrupted);
  const deadline = setTimeout(() => cancel('Native browser validation exceeded its 120-second deadline.'), 120000);
  const ensureActive = () => { if (abortReason) throw abortReason; };
  const checkProcess = (state, label) => {
    if (state.error) throw Error(`${label} could not start: ${state.error.message}`);
    if (state.closed || state.child.exitCode !== null || state.child.signalCode !== null) throw Error(`${label} exited (${state.child.exitCode ?? state.child.signalCode}): ${state.stderr}`);
  };
  const until = async (test, label, timeout = 10000) => {
    phase = label; const end = Date.now() + timeout;
    while (Date.now() < end) { ensureActive(); if (await test()) return; await delay(40); }
    throw Error(`Timed out: ${label}`);
  };
  const requestView = async (path, init = {}) => {
    const response = await fetch(new URL(path, endpoint), {...init, cache: 'no-store', signal: AbortSignal.timeout(10000)});
    const text = await response.text();
    if (!response.ok) throw Error(`Owned VM API ${response.status}: ${bound(text)}`);
    return debuggerUI.ownedVmValidateView(debuggerUI.ownedVmParseJSON(text));
  };
  const send = (method, params = {}) => new Promise((resolveCall, reject) => {
    try { ensureActive(); if (!socket || socket.readyState !== WebSocket.OPEN) throw Error('Owned browser DevTools connection is closed.'); }
    catch (error) { reject(error); return; }
    const id = ++sequence, timer = setTimeout(() => { commands.delete(id); reject(Error(`DevTools command timeout: ${method}`)); }, 10000);
    commands.set(id, {resolve: resolveCall, reject, timer}); socket.send(JSON.stringify({id, method, params}));
  });
  const evaluate = async expression => {
    const reply = await send('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
    if (reply.exceptionDetails) throw Error(`Browser evaluation failed: ${bound(JSON.stringify(reply.exceptionDetails))}`);
    return reply.result.value;
  };
  const click = async selector => {
    const point = await evaluate(`(()=>{const element=document.querySelector(${JSON.stringify(selector)});if(!element)throw Error('Missing control');element.scrollIntoView({block:'nearest'});const r=element.getBoundingClientRect();if(r.width<=0||r.height<=0||r.left<0||r.top<0||r.right>innerWidth||r.bottom>innerHeight)throw Error('Clipped or hidden control');const x=r.x+r.width/2,y=r.y+r.height/2,hit=document.elementFromPoint(x,y);if(!hit||!element.contains(hit))throw Error('Control is obscured at its click point');return{x,y};})()`);
    await send('Input.dispatchMouseEvent', {type: 'mousePressed', ...point, button: 'left', clickCount: 1});
    await send('Input.dispatchMouseEvent', {type: 'mouseReleased', ...point, button: 'left', clickCount: 1});
  };
  const key = async (key, code, extra = {}) => {
    for (const event of ownedVmRenderedKeyEvents(key, code, extra)) await send('Input.dispatchKeyEvent', event);
  };
  const viewport = (width, height) => send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile: false});
  const screenshot = async filename => {
    assert(/^[a-z0-9-]+\.png$/.test(filename)); const result = await send('Page.captureScreenshot', {format: 'png'});
    await writeFile(join(output, filename), Buffer.from(result.data, 'base64'), {flag: 'wx', mode: 0o600}); receipt.screenshots.push(filename);
  };
  try {
    const binaries = {backend: await executable(options.backend, 'Rust backend'), helper: await executable(options.helper, 'Native helper'), browser: await executable(options.browser, 'Chromium browser')};
    receipt.binaries = binaries; temporary = await mkdtemp(join(tmpdir(), 'reb-owned-vm-native-browser-'));
    const endpointFile = join(temporary, 'endpoint'), profile = join(temporary, 'browser-profile');
    await mkdir(profile); await mkdir(join(temporary, 'artifacts'));
    const backendArgs = ['--host', '127.0.0.1', '--port', '0', '--endpoint-file', endpointFile,
      '--owned-vm-fixture', binaries.helper, '--ui-directory', join(repository, 'apps/research-ui'), '--analyst-runner', binaries.backend];
    for (const [flag, name] of [['--store', 'events.jsonl'], ['--trace-store', 'trace.jsonl'], ['--signal-store', 'signals.jsonl'],
      ['--artifacts', 'artifacts'], ['--api-collection', 'collection.json'], ['--local-analyst', 'analyst.json']]) backendArgs.push(flag, join(temporary, name));
    phase = 'Rust backend launch'; backend = ownedProcess(binaries.backend, backendArgs, temporary);
    await until(async () => {
      checkProcess(backend, 'Rust backend');
      let text; try { text = (await readFile(endpointFile, 'utf8')).trim(); } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
      const url = new URL(text);
      assert(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'Backend must publish its exact fresh loopback endpoint');
      endpoint = url.origin; return true;
    }, 'fresh backend endpoint');
    receipt.endpoint = endpoint;
    let initial;
    await until(async () => { checkProcess(backend, 'Rust backend'); try { initial = await requestView('/api/vm-debugger'); return true; } catch (error) { if (error.cause?.code === 'ECONNREFUSED') return false; throw error; } }, 'real native capability');
    assert(initial.available, `Configured native helper is unavailable: ${initial.unavailable_reason}`); assert.equal(initial.session, null, 'Read-only capability must not create a fixture');
    receipt.backend_instance_id = initial.backend_instance_id;
    phase = 'sandboxed Chromium launch';
    browser = ownedProcess(binaries.browser, ['--headless=new', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
      `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-component-update', '--disable-sync', 'about:blank'], temporary);
    let devtoolsPort;
    await until(async () => {
      checkProcess(browser, 'Sandboxed Chromium'); checkProcess(backend, 'Rust backend');
      try { const port = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; assert(/^[1-9][0-9]{0,4}$/.test(port) && BigInt(port) <= 65535n); devtoolsPort = port; return true; }
      catch (error) { if (error.code === 'ENOENT') return false; throw error; }
    }, 'sandboxed Chromium DevTools endpoint');
    const pages = await (await fetch(`http://127.0.0.1:${devtoolsPort}/json/list`, {signal: AbortSignal.timeout(5000)})).json();
    const page = pages.find(candidate => candidate.type === 'page'); assert(page?.webSocketDebuggerUrl);
    const ws = new URL(page.webSocketDebuggerUrl); assert(ws.protocol === 'ws:' && ['127.0.0.1', 'localhost'].includes(ws.hostname) && ws.port === devtoolsPort);
    socket = new WebSocket(ws);
    await new Promise((ready, reject) => { const timer = setTimeout(() => reject(Error('DevTools WebSocket did not open')), 5000);
      socket.addEventListener('open', () => { clearTimeout(timer); ready(); }, {once: true}); socket.addEventListener('error', () => { clearTimeout(timer); reject(Error('DevTools WebSocket failed')); }, {once: true}); });
    socket.addEventListener('message', event => {
      const message = JSON.parse(event.data);
      if (message.method === 'Runtime.exceptionThrown' && receipt.runtime_errors.length < 32) receipt.runtime_errors.push(bound(JSON.stringify(message.params.exceptionDetails)));
      if (message.method === 'Network.responseReceived' && message.params.response.status >= 400 && receipt.http_errors.length < 64)
        receipt.http_errors.push({url: message.params.response.url, status: message.params.response.status});
      if (message.method === 'Network.requestWillBeSent') {
        const request = message.params.request;
        if (request.url === `${endpoint}/api/vm-debugger/actions` && request.method === 'POST' && receipt.controls.length < 64) {
          try { const command = JSON.parse(request.postData || '{}'); receipt.controls.push({action: command.action, command_id: command.command_id}); }
          catch { receipt.controls.push({action: 'unreadable'}); }
        }
      }
      const command = commands.get(message.id);
      if (command) { clearTimeout(command.timer); commands.delete(message.id); if (message.error) command.reject(Error(message.error.message)); else command.resolve(message.result); }
    });
    socket.addEventListener('close', () => { for (const command of commands.values()) { clearTimeout(command.timer); command.reject(Error('DevTools closed before acknowledgment')); } commands.clear(); });
    await send('Runtime.enable'); await send('Page.enable'); await send('Network.enable'); await viewport(1440, 900);
    await send('Page.navigate', {url: endpoint});
    await until(() => evaluate('document.readyState === "complete" && typeof vmExecutionWorkspace !== "undefined" && !!vmExecutionWorkspace?.owned'), 'integrated application load');
    await click('#nav-vm-workspace'); await click('#vm-show-owned');
    await until(() => evaluate('vmExecutionWorkspace.owned.controller.model().view?.available && !document.querySelector("#screen-vm").hidden && !document.querySelector("#vm-owned-debugger").hidden'), 'VM tab → Live owned fixture');
    assert.equal(receipt.controls.length, 0, 'Opening integrated UI does not issue VM controls');
    phase = 'real rendered cooperative fixture flow';
    await checkOwnedVmDebuggerInteractions({evaluate, viewport, click, key, screenshot, root: '#vm-owned-debugger', toolbarRoot: '#vm-owned-controls'});
    const closedView = await requestView('/api/vm-debugger'); assert.equal(closedView.session, null, 'Rendered Close must acknowledge disposal');
    receipt.cleanup.rendered_close_confirmed = true;
    assert.deepEqual(receipt.runtime_errors, [], 'The actual integrated page has no uncaught runtime exceptions');
    assert.deepEqual(receipt.http_errors.filter(item => new URL(item.url).pathname.startsWith('/api/vm-debugger')), [], 'Real VM requests succeeded');
    receipt.status = 'passed';
  } catch (error) {
    failure = error; receipt.status = 'failed'; receipt.phase = phase; receipt.error = bound(error.stack || error);
    if (socket?.readyState === WebSocket.OPEN && !abortReason) {
      try { await screenshot('failure.png'); } catch (captureError) { receipt.screenshot_error = bound(captureError); }
    }
  } finally {
    clearTimeout(deadline);
    const cleanupErrors = [];
    // Teardown is explicit and exact-scoped. A failed flow is never followed by
    // Run/Step/Reset or a generic retry of its last control.
    if (endpoint && backend && !backend.closed) {
      try {
        const view = await requestView('/api/vm-debugger');
        if (view.session) {
          const command = debuggerUI.ownedVmBuildAction(view, 'close', randomUUID());
          const closedView = await requestView('/api/vm-debugger/actions', {method: 'POST', headers: {'Content-Type': 'application/json', Origin: endpoint}, body: JSON.stringify(command)});
          assert.equal(closedView.command_id, command.command_id); assert.equal(closedView.session, null);
          receipt.cleanup.teardown_close_confirmed = true;
        } else receipt.cleanup.no_session_before_shutdown = true;
      } catch (error) { cleanupErrors.push(`Exact-scope Close: ${bound(error)}`); }
    }
    if (backend?.child.pid) {
      try {
        signalOwned(backend, 'SIGTERM');
        if (!await waitStopped(backend, 8000)) {
          backend.forced = true; signalOwned(backend, 'SIGKILL', true); await waitStopped(backend, 2000);
          throw Error('Backend failed graceful shutdown; forced termination cannot prove native-helper disposal.');
        }
        assert.equal(backend.child.exitCode, 0, 'Backend graceful SIGTERM must complete successfully');
        receipt.cleanup.backend_graceful_exit = true;
      } catch (error) { cleanupErrors.push(bound(error)); }
    }
    for (const command of commands.values()) { clearTimeout(command.timer); command.reject(Error('Validation teardown')); } commands.clear(); socket?.close();
    if (browser?.child.pid) {
      try {
        signalOwned(browser, 'SIGTERM', true);
        if (!await waitStopped(browser, 2000)) { browser.forced = true; signalOwned(browser, 'SIGKILL', true); }
        if (!await waitStopped(browser, 2000)) throw Error('Owned Chromium group did not terminate; profile retained.');
        receipt.cleanup.browser_reaped = true;
      } catch (error) { cleanupErrors.push(bound(error)); }
    }
    receipt.backend = backend ? {exit_code: backend.child.exitCode, signal: backend.child.signalCode, forced: backend.forced, stdout: backend.stdout, stderr: backend.stderr} : null;
    receipt.browser = browser ? {exit_code: browser.child.exitCode, signal: browser.child.signalCode, forced: browser.forced, stdout: browser.stdout, stderr: browser.stderr} : null;
    if (temporary && cleanupErrors.length === 0) {
      try { await rm(temporary, {recursive: true, force: true, maxRetries: 5, retryDelay: 100}); receipt.cleanup.temporary_files_removed = true; }
      catch (error) { cleanupErrors.push(bound(error)); }
    }
    if (cleanupErrors.length) { receipt.status = 'failed'; receipt.cleanup.errors = cleanupErrors; receipt.cleanup.retained_temporary_directory = temporary; failure ||= Error(cleanupErrors.join('; ')); }
    receipt.finished_at = new Date().toISOString();
    await writeFile(join(output, 'validation.json'), JSON.stringify(receipt, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    process.removeListener('SIGINT', interrupted); process.removeListener('SIGTERM', interrupted);
    console.log(`Native owned VM browser validation ${receipt.status}: ${join(output, 'validation.json')}`);
  }
  if (failure) throw failure;
  return receipt;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { const options = argumentsForRun(process.argv.slice(2)); if (!options) console.log(usage); else await runOwnedVmNativeBrowser(options); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
