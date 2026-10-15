#!/usr/bin/env node
// Authored static bytecode and DOM-controller checks. Rendered assertions are
// exported for the integrated browser gate; neither establishes macOS pixels.
import assert from 'node:assert/strict';
import {createHash, webcrypto} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {runInNewContext} from 'node:vm';
import {createRequire} from 'node:module';
import view from '../apps/research-ui/vm_static_view.js';
const require = createRequire(import.meta.url);
const model = require(process.env.REB_VM_STATIC_MODEL || '../apps/research-ui/vm_static.js');
const copy = value => JSON.parse(JSON.stringify(value));
const fixture = view.vmStaticOwnedExample();
const bytes = text => new TextEncoder().encode(text);
const file = (value, name = 'owned.json') => {
  const text = typeof value === 'string' ? value : JSON.stringify(value), data = bytes(text);
  return {name, size: data.byteLength, arrayBuffer: async () => data.buffer};
};
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; };
const source = await readFile(new URL('../apps/research-ui/vm_static_view.js', import.meta.url), 'utf8');
function harness(selectedModel = model) {
  const document = {activeElement: null, querySelector: () => null};
  class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.attributes = {}; this.style = {}; this.text = ''; this.value = ''; this.files = []; this.scrollTop = 0; }
    set textContent(value) { this.text = String(value); this.children = []; } get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
    append(...items) { this.children.push(...items); } replaceChildren(...items) { this.text = ''; this.children = items; }
    contains(element) { return this === element || this.children.some(child => child.contains(element)); }
    setAttribute(key, value) { this.attributes[key] = String(value); } getAttribute(key) { return this.attributes[key] ?? null; }
    addEventListener(key, action) { this.events[key] = action; } focus() { document.activeElement = this; } scrollIntoView() { this.scrolled = true; }
  }
  document.createElement = tag => new Element(tag);
  const api = runInNewContext(source + ';({mountVmStatic})', {document, TextEncoder, TextDecoder, crypto: webcrypto, vmStatic: selectedModel});
  const root = new Element('section'); return {document, root, ui: api.mountVmStatic(root), Element};
}
const descendants = element => [element, ...element.children.flatMap(descendants)];
const findButton = (root, label) => descendants(root).find(element => element.tagName === 'button' && element.textContent === label);
const press = (element, key, extra = {}) => { let prevented = false; element.events.keydown({key, preventDefault() { prevented = true; }, ...extra}); return prevented; };
const rows = ui => ui.listingRows.children.filter(element => element.getAttribute('data-vm-static-offset') !== null);
async function load(ui, definition = fixture.definition, image = fixture.image) { await ui.importFile('definition', file(definition)); await ui.importFile('image', file(image)); await ui.analyzeInputs(); }

export async function checkVmStaticController() {
  const {ui, root, document} = harness();
  assert(ui.analyze.disabled); assert.equal(ui.getReport(), null); assert.match(root.textContent, /No code|No bytecode/);
  await ui.importFile('image', file(fixture.image)); assert(ui.analyze.disabled); assert.equal(rows(ui).length, 0);
  await ui.importFile('definition', file(fixture.definition)); assert(!ui.analyze.disabled); assert.equal(rows(ui).length, 0, 'Import does not implicitly analyze or execute');
  await ui.analyzeInputs(); const report = ui.getReport(); assert.equal(report.coverage.instruction_count, 16); assert.equal(rows(ui).length, 16);
  assert.equal(report.provenance.definition_source_sha256, createHash('sha256').update(JSON.stringify(fixture.definition)).digest('hex'));
  ui.select(40); ui.setTab('instruction'); assert.match(ui.detail.textContent, /branch_zero.*unverified/); assert.match(ui.detail.textContent, /target: 47/);
  ui.setTab('pseudocode'); assert(descendants(ui.detail).some(element => element.getAttribute('data-vm-static-pseudocode') === '40' && element.getAttribute('aria-pressed') === 'true'));
  ui.setTab('cfg'); assert.match(ui.detail.textContent, /branch taken/); assert.match(ui.detail.textContent, /branch not taken/); assert.match(ui.detail.textContent, /jump/);
  ui.filter.value = 'HALT'; ui.filter.events.input(); assert.equal(rows(ui).length, 1); assert.match(root.textContent, /selected instruction hidden by filter/);
  findButton(ui.detail, '0x0000').events.click(); assert.equal(ui.getSelected(), 0); assert.equal(ui.filter.value, '', 'CFG links reveal exact hidden addresses');
  ui.setTab('inputs'); assert.match(ui.detail.textContent, /Exact definition JSON SHA-256/); assert.match(ui.detail.textContent, /Canonical definition SHA-256/);
  const raw = descendants(ui.detail).find(element => element.tagName === 'details' && element.children[0].textContent === 'Complete analysis raw audit');
  raw.open = true; raw.events.toggle(); assert.match(raw.textContent, /reb-vm-static-analysis-v1/); raw.open = false; raw.events.toggle(); assert(!raw.textContent.includes('"instructions"'));
  const invalid = ['{"format":1,"format":2}', '{}', '<img src=x onerror=alert(1)>'];
  for (const text of invalid) { await ui.importFile('definition', file(text)); assert.equal(ui.getReport(), report); assert.match(ui.notice.textContent, /Import refused/); }
  await ui.importFile('definition', file(fixture.definition, '<img src=x onerror=alert(1)>.json')); await ui.analyzeInputs(); ui.setTab('inputs');
  assert(ui.detail.textContent.includes('<img src=x onerror=alert(1)>.json')); assert(!descendants(root).some(element => element.tagName === 'img'));
  let read = false; await ui.importFile('image', {size: 1048577, arrayBuffer: async () => { read = true; }}); assert.equal(read, false);
  await ui.importFile('image', {size: 1, arrayBuffer: async () => new ArrayBuffer(1048577)}); assert.match(ui.notice.textContent, /bound/);
  await ui.importFile('image', {size: 1, arrayBuffer: async () => new Uint8Array([255]).buffer}); assert.match(ui.notice.textContent, /Import refused/);
  await ui.importFile('definition', file('\uFEFF' + JSON.stringify(fixture.definition))); assert.match(ui.notice.textContent, /Import refused/, 'BOM is not silently stripped before exact source hashing');
  const previous = ui.getReport(); await ui.importFile('image', null); assert.equal(ui.getReport(), previous, 'Cancel does not clear existing evidence');
  const mismatch = {...fixture.image, definition_id: 'different'}; await ui.importFile('image', file(mismatch)); assert.equal(ui.getReport(), null);
  await ui.analyzeInputs(); assert.equal(ui.getReport(), null); assert.match(ui.notice.textContent, /definition.*(?:match|disagree)|match.*definition/i);
  const unknown = {...fixture.image, bytes_hex: 'aa01'}; await load(ui, fixture.definition, unknown); assert.equal(rows(ui).length, 0); assert.match(ui.sourceSummary.textContent, /unknown_opcode/); ui.setTab('inputs'); assert.match(ui.detail.textContent, /2 bytes undecoded/);
  const declaredUnknown = copy(fixture.definition); declaredUnknown.opcodes[0].semantics = {operation: 'unknown', args: []}; await load(ui, declaredUnknown); ui.setTab('pseudocode'); assert.match(ui.detail.textContent, /Pseudocode unavailable · unknown semantics/);
  const many = {...fixture.image, bytes_hex: '010001'.repeat(256) + 'ff'}; await load(ui, fixture.definition, many); assert.equal(rows(ui).length, 64);
  rows(ui)[0].focus(); assert(press(rows(ui)[0], 'PageDown')); assert.equal(ui.getSelected(), 192); assert.equal(document.activeElement.getAttribute('data-vm-static-offset'), '192');
  assert(press(document.activeElement, 'End')); assert.equal(ui.getSelected(), 768); assert.equal(rows(ui).length, 1); assert.equal(document.activeElement.getAttribute('data-vm-static-offset'), '768');
  assert(!press(document.activeElement, 'ArrowUp', {altKey: true})); assert(!press(document.activeElement, 'ArrowUp', {isComposing: true})); assert.equal(ui.getSelected(), 768);
  ui.changeLayout(360); assert(press(document.activeElement, 'Enter')); assert.equal(root.getAttribute('data-panel'), 'details'); assert.equal(document.activeElement, ui.tabButtons.pseudocode);
  assert(press(ui.tabButtons.pseudocode, 'ArrowRight')); assert.equal(document.activeElement, ui.tabButtons.cfg);
  root.events.keydown({key: 'Escape', preventDefault() {}}); assert.equal(root.getAttribute('data-panel'), 'listing'); assert.equal(document.activeElement.getAttribute('data-vm-static-offset'), '768');
  ui.panelButtons.details.focus(); ui.changeLayout(1440); assert.equal(document.activeElement, ui.filter, 'Hidden responsive controls hand focus to a visible pane');
  for (let index = 0; index < 30; index++) { ui.select(index * 3, {reveal: true}); ui.setTab('cfg'); assert(descendants(ui.detail).filter(element => element.getAttribute('data-vm-static-node') !== null).length <= 32); assert(rows(ui).length <= 64); }
  const oldRead = deferred(); const reading = ui.importFile('definition', {size: 10, arrayBuffer: () => oldRead.promise}); ui.clear.events.click(); oldRead.resolve(bytes('{}').buffer); await reading;
  assert.equal(ui.getReport(), null); assert(ui.analyze.disabled); assert.equal(document.activeElement, ui.fileInputs.definition);
  const readFirst = deferred(); const first = ui.importFile('image', {size: 10, arrayBuffer: () => readFirst.promise}); await ui.importFile('image', file(fixture.image)); readFirst.resolve(bytes('{}').buffer); await first;
  assert(!ui.notice.textContent.includes('Import refused')); await ui.importFile('definition', file(fixture.definition)); await ui.analyzeInputs(); assert.equal(ui.getReport().image.image_id, fixture.image.image_id);
  const slow = deferred(); const delayed = harness({...model, analyze: () => slow.promise}).ui; delayed.demo.events.click(); const analyzing = delayed.analyzeInputs(); assert(delayed.analyze.disabled);
  await delayed.importFile('image', file({...fixture.image, image_id: 'replacement'})); slow.resolve(report); await analyzing; assert.equal(delayed.getReport(), null, 'New input invalidates in-flight hashes/analysis');
  const slowClear = deferred(); const cleared = harness({...model, analyze: () => slowClear.promise}).ui; cleared.demo.events.click(); const clearing = cleared.analyzeInputs(); cleared.clear.events.click(); slowClear.resolve(report); await clearing; assert.equal(cleared.getReport(), null);
  const maximalReport = copy(report); maximalReport.diagnostics = Array.from({length:8257}, (_, index) => ({offset:null, code:'authored_diagnostic', message:`Owned diagnostic ${index}`}));
  const maximal = harness({...model, analyze: async () => maximalReport}); maximal.ui.demo.events.click(); await maximal.ui.analyzeInputs(); maximal.ui.setTab('inputs');
  for (let index = 0; index < 129; index++) {
    assert.equal(descendants(maximal.ui.detail).filter(element => element.getAttribute('data-vm-static-diagnostic')).length, 64);
    findButton(maximal.ui.detail, 'Next diagnostics page').events.click();
  }
  assert.equal(descendants(maximal.ui.detail).filter(element => element.getAttribute('data-vm-static-diagnostic')).length, 1);
  assert.match(maximal.ui.detail.textContent, /8257–8257 of 8257/); assert.equal(maximal.document.activeElement.textContent, 'Previous diagnostics page');
  assert.equal(maximal.ui.getReport().diagnostics.length, 8257, 'Paging never drops raw diagnostic evidence');
  const shellHarness = harness(), shellNodes = new Map(), visible = []; let onOwnedState;
  for (const id of ['vm-semantics-workflow','vm-findings-workspace','vm-show-findings','vm-show-execution','vm-show-owned','vm-owned-debugger','vm-owned-controls','nav-vm-workspace','vm-show-static','vm-static-workspace']) shellNodes.set('#'+id,new shellHarness.Element('section'));
  shellHarness.document.querySelector = selector => shellNodes.get(selector) ?? null;
  const shellSource = await readFile(new URL('../apps/research-ui/vm_semantics.js', import.meta.url),'utf8');
  const client = require('../apps/research-ui/captured_client.js');
  const owned = {toolbar:new shellHarness.Element('div'),panes:new shellHarness.Element('div'),setVisible:value=>visible.push(value)};
  const shell = runInNewContext(source+'\n'+shellSource+';vmExecutionWorkspace',{document:shellHarness.document,TextEncoder,TextDecoder,crypto:webcrypto,vmStatic:model,capturedClientJSON:client.capturedClientJSON,mountOwnedVmDebugger:(_root,options)=>{onOwnedState=options.onState;return owned;}});
  shell.staticAnalysis.demo.events.click(); await shell.staticAnalysis.analyzeInputs(); shell.staticAnalysis.select(40);
  shell.showWorkspace('static'); shell.setVisible(true); assert.equal(shellNodes.get('#vm-static-workspace').hidden,false); assert.equal(shellNodes.get('#vm-semantics-workflow').hidden,true);
  assert.equal(shellNodes.get('#vm-owned-controls').hidden,true); onOwnedState({session:{state:'paused'}});
  assert.equal(shellNodes.get('#vm-owned-controls').hidden,false,'Active owned safety controls coexist with static mode'); assert.equal(owned.panes.hidden,true); assert.equal(visible.at(-1),true);
  shell.showWorkspace('findings'); shell.showWorkspace('execution'); shell.showWorkspace('static'); assert.equal(shell.staticAnalysis.getSelected(),40);
  shell.setVisible(false); assert.equal(visible.at(-1),false,'Leaving VM pauses status polling through existing owner');
  shell.setVisible(true); onOwnedState({session:null}); assert.equal(shellNodes.get('#vm-owned-controls').hidden,true);
  assert(!/\b(?:fetch|eval|Function|XMLHttpRequest|WebSocket)\s*\(/.test(source)); assert(!/innerHTML|outerHTML|insertAdjacentHTML/.test(source));
  console.log('PASS static VM controller: independent strict imports; raw/canonical hashes; declared pseudocode/CFG links; unavailable/unknown state;64-row/32-node bounds; keyboard/filter/focus; stale reads/analysis; inert text; no execution (not rendered acceptance)');
}

// This response only exercises coexistence/layout through the real controller.
// It is deliberately labelled authored and never launches the native helper.
function authoredLiveView() {
  const snapshot = {pc: '0', pc_evidence: 'observed', partial: false, halted: false, registers: [], stack: [], memory: []};
  return {schema: 'reb-owned-vm-debug-session-v1', available: true, unavailable_reason: null, backend_instance_id: 'static-ui-authored', session: {
    backend_instance_id: 'static-ui-authored', session_id: 'authored', run_id: 'static-ui-authored', run_generation: '1', provider: 'live-owned-native-fixture', target_kind: 'owned_fixture', fixture: 'stack', program_id: 'owned-stack-v1', fixture_revision: 1,
    program_sha256: 'a'.repeat(64), program_manifest_scope: 'declared-two-program-manifest-sha256', build_id: 'b'.repeat(64), build_id_scope: 'configured-helper-file-sha256', pc_units: 'instruction-index', value_semantics: 'unsigned-64-bit-bits', tick_units: 'monotonic-nanoseconds', state: 'paused', control_revision: '1', snapshot_revision: '1', executed_count: '0', retained_count: '0', execution_state_known: true, termination_reason: null,
    initial_snapshot: snapshot, current_snapshot: snapshot, records: [], recorder: {session_id: '1', document_id: '2', invocation_id: '3', generation: '1', stats: Object.fromEntries(['attempted', 'recorded', 'full', 'malformed', 'wrong_document', 'stale_generation', 'exhausted', 'expired', 'partial'].map(key => [key, '0']))},
    last_command: null, diagnostics: {stderr_bytes: '0', stderr_truncated: false}, disposal_failed: false
  }};
}
export async function checkVmStaticInteractions({evaluate, viewport, click, key, screenshot}) {
  const root = '#vm-static-workspace';
  const visibleClick = async selector => { await evaluate(`document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block:'nearest'})`); await click(selector); };
  const settle = () => evaluate(`new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))`);
  const waitAnalysis = () => evaluate(`(async()=>{const end=performance.now()+5000;while(!vmExecutionWorkspace.staticAnalysis.getReport()){if(performance.now()>end)throw Error('Static analysis did not complete');await new Promise(resolve=>setTimeout(resolve,10));}})()`);
  const importFile = async (kind, value) => evaluate(`(async()=>{const input=vmExecutionWorkspace.staticAnalysis.fileInputs[${JSON.stringify(kind)}],transfer=new DataTransfer();transfer.items.add(new File([${JSON.stringify(JSON.stringify(value))}],${JSON.stringify(kind + '-owned.json')},{type:'application/json'}));input.files=transfer.files;input.dispatchEvent(new Event('change',{bubbles:true}));const end=performance.now()+5000;while(input.value){if(performance.now()>end)throw Error('Static import did not settle');await new Promise(resolve=>setTimeout(resolve,10));}})()`);
  const geometry = selector => evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)}),r=e.getBoundingClientRect(),hit=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);return{width:r.width,height:r.height,visible:r.left>=0&&r.right<=innerWidth&&r.top>=0&&r.bottom<=innerHeight,pointer:hit===e||e.contains(hit),focus:getComputedStyle(e).outlineStyle!=='none'}})()`);
  await viewport(1440, 900); await evaluate("showScreen('vm');"); await visibleClick('#vm-show-static'); await settle();
  assert.equal(await evaluate(`document.querySelector('${root}').hidden`), false);
  const oldTraceSelection = await evaluate(`vmExecutionWorkspace.execution.selector.value`);
  await importFile('image', fixture.image); assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.analyze.disabled'), true);
  await importFile('definition', fixture.definition); assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.getReport()'), null);
  await visibleClick(root + ' [data-vm-static-action="analyze"]'); await waitAnalysis();
  assert.equal(await evaluate(`document.querySelectorAll('${root} .vm-static-row').length`), 16);
  const completeRows = await evaluate(`(()=>{const body=document.querySelector('${root} .vm-static-rows'),b=body.getBoundingClientRect();return[...body.children].filter(e=>{const r=e.getBoundingClientRect();return r.top>=Math.max(0,b.top)&&r.bottom<=Math.min(innerHeight,b.bottom)}).length})()`);
  assert(completeRows >= 12, 'Desktop static listing retains at least12 complete rows');
  await visibleClick(root + ' [data-vm-static-offset="40"]'); await visibleClick('#vm-static-tab-cfg');
  assert.match(await evaluate(`document.querySelector('${root} .vm-static-detail').textContent`), /branch taken/);
  await visibleClick('#vm-static-tab-pseudocode'); assert.equal(await evaluate(`document.querySelector('${root} [data-vm-static-pseudocode="40"]').getAttribute('aria-pressed')`), 'true');
  await visibleClick('#vm-static-tab-instruction'); assert.match(await evaluate(`document.querySelector('${root} .vm-static-detail').textContent`), /target: 47/);
  await visibleClick('#vm-static-tab-inputs'); assert.match(await evaluate(`document.querySelector('${root} .vm-static-detail').textContent`), /Exact image JSON SHA-256/);
  await importFile('definition', {bad: '<img src=x onerror=alert(1)>'}); assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.getSelected()'), 40); assert.equal(await evaluate(`document.querySelectorAll('${root} img').length`), 0);
  await visibleClick('#vm-show-findings'); await visibleClick('#vm-show-execution'); assert.equal(await evaluate('vmExecutionWorkspace.execution.selector.value'), oldTraceSelection); await visibleClick('#vm-show-static'); assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.getSelected()'), 40);
  for (const [width, height] of [[1440,900],[1024,768],[760,700],[600,800],[360,740],[720,450]]) {
    await viewport(width, height); await settle();
    if (width < 760) await visibleClick(root + ' [data-vm-static-panel="listing"]');
    await visibleClick(root + ' [data-vm-static-offset="40"]'); await key('ArrowDown', 'ArrowDown', {windowsVirtualKeyCode: 40}); assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.getSelected()'), 44);
    const row = await geometry(root + ' [data-vm-static-offset="44"]'); assert(row.visible && row.pointer && row.focus, `Focused static row reachable at ${width}×${height}`);
    assert.equal(await evaluate('document.documentElement.scrollWidth<=innerWidth'), true);
    await key('Enter', 'Enter', {windowsVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r'}); assert((await geometry('#vm-static-tab-inputs')).visible);
    await screenshot(`vm-static-${width}x${height}.png`);
    if (width < 760) { await key('Escape', 'Escape', {windowsVirtualKeyCode: 27}); assert.equal(await evaluate(`document.querySelector('${root}').dataset.panel`), 'listing'); }
  }
  // Exercise actual workspace width, independently of viewport media queries.
  await viewport(1440,900); await evaluate(`document.querySelector('${root}').style.width='700px'`); await settle(); assert.equal(await evaluate(`document.querySelector('${root}').dataset.layout`), 'narrow');
  await evaluate(`document.querySelector('${root}').style.width=''`); await settle();
  // Synthetic response on the normal read path; all POSTs are forbidden here.
  await evaluate(`window.vmStaticSavedFetch=window.fetch;window.vmStaticPosts=0;window.vmStaticAuthored=${JSON.stringify(authoredLiveView())};window.fetch=(input,init={})=>{if(String(input)==='/api/vm-debugger'||String(input)==='/api/vm-debugger/actions'){if(init.method==='POST'){window.vmStaticPosts++;throw Error('Static fixture forbids native commands');}return Promise.resolve(new Response(JSON.stringify(window.vmStaticAuthored),{status:200,headers:{'Content-Type':'application/json'}}));}return window.vmStaticSavedFetch(input,init);};`);
  try {
    await evaluate(`(async()=>{const end=performance.now()+5000;while(vmExecutionWorkspace.owned.controller.model().view?.session?.run_id!=='static-ui-authored'){await vmExecutionWorkspace.owned.controller.refresh();if(performance.now()>end)throw Error('Authored live view not accepted');await new Promise(resolve=>setTimeout(resolve,20));}})()`);
    for (const [width,height] of [[1440,900],[360,740],[720,450]]) {
      await viewport(width,height); await settle(); assert.equal(await evaluate(`document.querySelector('#vm-owned-controls').hidden`), false);
      await evaluate(`vmExecutionWorkspace.owned.buttons.stop.focus();vmExecutionWorkspace.owned.buttons.stop.scrollIntoView({block:'nearest'})`);
      const stop = await geometry('#vm-owned-controls [data-owned-vm-action="stop"]'); assert(stop.visible && stop.pointer && stop.focus, 'Active live Stop stays reachable in static mode');
      await screenshot(`vm-static-with-owned-controls-${width}x${height}.png`);
      if(width<760) await visibleClick(root+' [data-vm-static-panel="listing"]');
      await visibleClick(root+' [data-vm-static-offset="44"]'); assert((await geometry(root+' [data-vm-static-offset="44"]')).pointer);
    }
    assert.equal(await evaluate('window.vmStaticPosts'),0,'Static mode never issues native commands');
  } finally {
    await evaluate(`(async()=>{try{window.vmStaticAuthored.session=null;const end=performance.now()+5000;while(vmExecutionWorkspace.owned.controller.model().view?.session){await vmExecutionWorkspace.owned.controller.refresh();if(performance.now()>end)throw Error('Authored live cleanup did not settle');await new Promise(resolve=>setTimeout(resolve,20));}}finally{window.fetch=window.vmStaticSavedFetch;delete window.vmStaticSavedFetch;delete window.vmStaticAuthored;}})()`);
  }
  await viewport(1440,900); await visibleClick(root+' .vm-static-toolbar > button:last-of-type'); assert.equal(await evaluate('vmExecutionWorkspace.staticAnalysis.getReport()'), null);
  return {status:'passed',source:'authored static JSON and authored live read response; no native fixture execution',checks:['independent imports and exact SHA provenance','16-row owned sample and12 visible desktop rows','declared CFG/pseudocode/instruction selection','invalid import retains report','existing mode round trip','1440/1024/760/600/360 and720×450 layouts','actual root-width responsiveness','visible keyboard focus and narrow Escape','coexisting live Stop controls','no native commands'],actual_browser_zoom:'requires separate macOS zoom gate'};
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await checkVmStaticController();
