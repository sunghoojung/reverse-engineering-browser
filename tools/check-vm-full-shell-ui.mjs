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
import ledgerModel from '../apps/research-ui/vm_opcode_ledger.js';
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
    await click('[data-pack-inputs="compare"] > summary');
    await click('[data-pack-inputs="apply"] > summary');
    const rawClosed = "[...document.querySelectorAll('#vm-packs-workspace details')].filter(node=>node.querySelector('.vm-pack-output')).every(node=>!node.open)";
    assert.equal(await evaluate(rawClosed), true);
    for (const width of [1440,1280,900,390]) {
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      await evaluate("document.querySelector('#vm-packs-workspace').scrollTop=0");
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true, `Populated packs fit at ${width}`);
      assert.equal(await evaluate("(()=>{const panel=document.querySelector('#vm-packs-workspace .vm-tool-results'),row=panel.querySelector('tbody tr');return row.getBoundingClientRect().bottom<=panel.getBoundingClientRect().bottom;})()"), true, 'Comparison rows are not hidden in a shrunken result viewport');
      await screenshot(`vm-packs-populated-${width}`);
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
      await send('Emulation.setDeviceMetricsOverride', {width, height: 900, deviceScaleFactor: 1, mobile: false});
      await evaluate("document.querySelector('#vm-ledger-workspace').scrollTop=0");
      assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true, `Populated ledger fits at ${width}`);
      assert.equal(await evaluate("(()=>{const panel=document.querySelector('#vm-ledger-workspace .vm-tool-results'),row=panel.querySelector('tbody tr');return row.getBoundingClientRect().bottom<=panel.getBoundingClientRect().bottom;})()"), true, 'Ledger rows are not hidden in a shrunken result viewport');
      await screenshot(`vm-ledger-populated-${width}`);
    }
    assert.deepEqual(errors, []);
    assert.equal(requests.some(request => request.method !== 'GET' && !(request.method === 'POST' && request.path === '/api/analysis/vm/packs/compare')), false, 'Only exact authored comparison may POST');
    await writeFile(join(output, 'validation.json'), JSON.stringify({status: 'passed', viewports: [1440,1280,900,390],
      scope: 'Actual index.html, shipped scripts, HTTP admission of authored retained finding, all mode controls and analysis panels, selected handler linkage, real File inputs and authored pack/ledger result presentation. Pack response is a synthetic display fixture, not real backend analysis. No live capture, native runtime or VM execution.', requests}, null, 2));
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
