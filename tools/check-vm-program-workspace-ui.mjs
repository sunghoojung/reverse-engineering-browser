#!/usr/bin/env node
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, writeFile, rm, mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
const root = fileURLToPath(new URL('..', import.meta.url));
const output = process.env.REB_VMP_OUTPUT || join(root, 'build/vm-program-ui');
const script = await readFile(join(root, 'apps/research-ui/vm_program_workspace.js'), 'utf8');
const css = await readFile(join(root, 'apps/research-ui/app.css'));
const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/app.css"><style>html,body{overflow:auto;height:auto;min-height:100%}body{margin:0}main{min-width:0}</style></head><body><main><div id="vm-session-status"><span class="vm-session-chip">Native stealth</span></div><div id="vm-program-workspace" class="vm-program-workspace"></div><div id="vm-detail"></div></main><script>const state={};${script}</script></body></html>`;
const server = createServer((request,response)=>{response.setHeader('content-type',request.url==='/app.css'?'text/css':'text/html');response.end(request.url==='/app.css'?css:html);});
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
    await until(() => evaluate("document.querySelectorAll('.vmp-row').length > 0"), 'program rows');
    assert.equal(await evaluate("document.querySelector('#vm-program-workspace .vmp-capture')"), null);
    assert((await evaluate("document.querySelector('.vmp-provenance').textContent")).includes('does not execute a VM'));
    const click = async selector => {
      const point = await evaluate(`(async()=>{const node=document.querySelector(${JSON.stringify(selector)});node.scrollIntoView({block:'center'});await new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)));const b=node.getBoundingClientRect();return {x:b.x+b.width/2,y:b.y+b.height/2};})()`);
      for (const type of ['mousePressed','mouseReleased']) await send('Input.dispatchMouseEvent',{type,...point,button:'left',clickCount:1});
    };
    const key = async (key, code, value) => {
      for (const type of ['rawKeyDown','keyUp']) await send('Input.dispatchKeyEvent',{type,key,code,windowsVirtualKeyCode:value});
    };
    for (const width of [1440, 900, 390]) {
      await send('Emulation.setDeviceMetricsOverride', {width,height:900,deviceScaleFactor:1,mobile:false});
      await click('#vmp-reset');
      await click('[data-act="row"][data-pc="2"]');
      assert.equal(await evaluate('document.activeElement.dataset.pc'), '2');
      await key('ArrowDown','ArrowDown',40);
      assert.equal(await evaluate('document.activeElement.dataset.pc'), '3');
      assert.equal(await evaluate('document.activeElement.getAttribute("aria-pressed")'), 'true');
      await key('End','End',35); assert.equal(await evaluate('document.activeElement.dataset.pc'), '10');
      await click('#vmp-back'); assert.equal(await evaluate('document.querySelector(".vmp-row.pin").dataset.pc'),'3');
      await click('#vmp-forward'); assert.equal(await evaluate('document.querySelector(".vmp-row.pin").dataset.pc'),'10');
      await click('[data-act="op"][data-op="1"]');
      assert.equal(await evaluate('document.activeElement.dataset.op'), '1');
      await click('#vmp-follow');
      assert.equal(await evaluate('document.querySelectorAll("button.vmp-row").length'),9);
      assert.equal(await evaluate('document.querySelector(".vmp-row.pin").dataset.pc'),'3');
      await evaluate("document.querySelector('#vmp-address').value='7';document.querySelector('#vmp-goto').requestSubmit()");
      assert((await evaluate("document.querySelector('#vmp-navigation-status').textContent")).includes('No instruction'));
      await evaluate("document.querySelector('#vmp-address').value='8';document.querySelector('#vmp-goto').requestSubmit()");
      assert.equal(await evaluate('document.activeElement.dataset.pc'),'8');
      await click('#vmp-declared'); assert.equal(await evaluate('document.querySelector("#vmp-step").disabled'),true);
      await click('#vmp-run'); await click('#vmp-reset');
      assert.equal(await evaluate('document.querySelector(".vmp-row.pin").dataset.pc'), '2');
      assert.equal(await evaluate('document.querySelector("#vmp-navigation-status").textContent'), 'Selected PC 2 · ↑ ↓ Home End');
      await evaluate("document.querySelector('#vmp-address').value='7';document.querySelector('#vmp-goto').requestSubmit()");
      await click('[data-act="tab"][data-tab="evidence"]');
      assert((await evaluate("document.querySelector('#vmp-navigation-status').textContent")).includes('No instruction'));
      await click('[data-act="row"][data-pc="3"]');
      assert.equal(await evaluate('document.querySelector("#vmp-navigation-status").textContent'), 'Selected PC 3 · ↑ ↓ Home End');
      await click('#vmp-reset');
      assert.equal(await evaluate('document.querySelector("#vmp-navigation-status").textContent'), 'Selected PC 2 · ↑ ↓ Home End');
      await click('[data-act="tab"][data-tab="evidence"]');
      assert.equal(await evaluate('document.activeElement.dataset.tab'),'evidence');
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'),true);
      await evaluate('scrollTo(0,0)');
      const {data} = await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
      await writeFile(join(output, `program-${width}.png`),Buffer.from(data,'base64'));
      await click('[data-act="tab"][data-tab="state"]');
    }
    await evaluate("state.vmOpcodeWorkspace={workspaces:[{source_artifact_sha256:'a'.repeat(64)}]};document.querySelector('#vm-detail').replaceChildren(document.createElement('p'))");
    await until(()=>evaluate("!document.querySelector('#vmp-refusal').hidden"),'mismatched source refusal');
    await evaluate("state.vmOpcodeWorkspace={workspaces:[{source_artifact_sha256:'32f42d2408c8b2b77539c49ad458f3923d819fedc323e6529bbff7e83b14a52e',handlers:[{opcode:2,source:{byte_offset:null,byte_size:null}}]}]};document.querySelector('#vm-detail').replaceChildren(document.createElement('p'))");
    await until(()=>evaluate("document.querySelector('#vmp-inspector').textContent.includes('no handler coordinate')"),'unknown source coordinate');
    assert.equal(await evaluate('document.querySelectorAll("#vmp-queue button").length'),0);
    await writeFile(join(output,'validation.json'),JSON.stringify({status:'passed',viewports:[1440,900,390],scope:'Deterministic fixture rendering, real pointer/keyboard navigation, history, filters, unknown coordinates and source refusal. Not native capture or execution.'},null,2));
    assert.deepEqual(errors, []);
    console.log(`PASS rendered program: ${output}`);
  } catch (error) {
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
