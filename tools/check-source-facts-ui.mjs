import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

// Facts are UI projections over the Rust contract. The backend admits a whole
// report and answers summary and row-page queries; `sourceFactsServer` answers
// the same queries from an in-memory report so the panel runs offline. The
// adapter's own tests own admission and filter semantics. Not rendered QA.
const factsTables = ['scopes', 'bindings', 'callables', 'regions', 'operations', 'frontiers'];
const factsTarget = operation => {
  const target = operation.detail?.target;
  const exact = target?.kind === 'binding' && target.binding_ids.length === 1 && ['lexical-only', 'declaration'].includes(target.resolution);
  const candidates = target?.kind === 'ambiguous' && target.binding_ids.length >= 2 && target.resolution === 'duplicate-declarations';
  return ['reference', 'read', 'write', 'call', 'construct'].includes(operation.kind) && (exact || candidates) ? target.binding_ids : null;
};
export function sourceFactsServer(report) {
  const rows = table => table === 'frontiers' ? report.coverage.frontiers : report[table];
  const publicSource = source => Object.fromEntries(Object.entries(source).filter(([key]) => key !== 'source_type'));
  return {
    summary: (source, cached = false) => ({schema: 'reb-javascript-source-facts-v2', profile: 'lexical-effects-v1', offset_unit: 'utf-8-byte',
      source_bytes: source.byte_size, ok: report.coverage.status !== 'unavailable',
      coverage: {status: report.coverage.status, diagnostics: report.coverage.diagnostics, analyzed_range: report.coverage.analyzed_range},
      counts: Object.fromEntries(factsTables.map(table => [table, rows(table).length])), cached, source: publicSource(source)}),
    page(source, url) {
      const query = new URL(url, 'http://127.0.0.1').searchParams;
      const number = key => query.has(key) ? Number(query.get(key)) : null;
      const table = query.get('table'), offset = Number(query.get('offset')), limit = Number(query.get('limit'));
      const filter = {binding_id: number('binding_id'), kind: query.get('kind'), name: query.get('name'), candidates_of: number('candidates_of')};
      let selected = rows(table);
      if (filter.binding_id !== null) selected = selected.filter(operation => factsTarget(operation)?.includes(filter.binding_id));
      if (filter.kind !== null) selected = selected.filter(operation => operation.kind === filter.kind);
      if (filter.candidates_of !== null) selected = report.operations[filter.candidates_of].detail.target.binding_ids.map(id => report.bindings[id]);
      if (filter.name !== null) selected = selected.filter(binding => binding.name.toLowerCase().includes(filter.name.toLowerCase()));
      const page = selected.slice(offset, offset + limit), named = [];
      if (table === 'operations') {
        if (filter.binding_id !== null) named.push(filter.binding_id);
        for (const operation of page) {
          const ids = factsTarget(operation);
          if (ids?.length === 1 && !named.includes(ids[0])) named.push(ids[0]);
        }
      }
      return {schema: 'reb-javascript-source-fact-rows-v2', source: publicSource(source), analyzed_range: report.coverage.analyzed_range,
        table, filter, offset, total: selected.length, rows: page, bindings: named.map(id => report.bindings[id])};
    },
    response(source, url) { return Response.json(url.startsWith('/api/source-facts/rows?') ? this.page(source, url) : this.summary(source)); }
  };
}

function factsReferenceFixture() {
  const text = '﻿let 雪 = "😀";\nfunction shadow(雪) { return 雪; }\nfunction closure() { return 雪; }\n雪++;\nvar duplicate; var duplicate;\nduplicate(); new duplicate();\nconst spare = 0;\nunknown; object.雪;\n' + '雪;\n'.repeat(105);
  const bytes = new TextEncoder().encode(text);
  const range = (needle, after = 0) => {const index = text.indexOf(needle, after); assert(index >= 0); return {start:Buffer.byteLength(text.slice(0,index)),end:Buffer.byteLength(text.slice(0,index+needle.length))};};
  const full = {start:0,end:bytes.length};
  const target = id => ({kind:'binding',binding_ids:[id],resolution:'lexical-only',name:'雪'});
  const ambiguous = {kind:'ambiguous',binding_ids:[2,3],resolution:'duplicate-declarations',name:'duplicate'};
  const operation = (id, kind, range, target, region_id=0) => ({id,region_id,order:id,range,kind,detail:{target}});
  const operations = [
    operation(0,'read',range('雪',text.indexOf('closure')),target(0),2),
    operation(1,'read',range('雪',text.indexOf('return')),target(1),1),
    operation(2,'read',range('雪++'),target(0)),operation(3,'write',range('雪++'),target(0)),
    operation(4,'call',range('duplicate()'),ambiguous),operation(5,'construct',range('new duplicate()'),ambiguous),
    operation(6,'read',range('unknown'),{kind:'unresolved',binding_ids:[],resolution:'dynamic-scope',name:'雪'}),
    operation(7,'read',range('object.雪'),{kind:'property',object_range:range('object'),key_range:range('雪',text.indexOf('object')),computed:false}),
  ];
  let after=text.indexOf('object.雪;')+'object.雪;'.length;
  for(let i=0;i<105;i++){const start=text.indexOf('雪;',after);operations.push(operation(8+i,'read',range('雪',start),target(0)));after=start+2;}
  const scope = (id, needle) => ({id,parent_id:0,range:range(needle),kind:'function'});
  const scopes = [{id:0,parent_id:null,range:full,kind:'program'},scope(1,'function shadow(雪) { return 雪; }'),scope(2,'function closure() { return 雪; }')];
  const binding = (id,name,kind,scope_id,after=0) => ({id,name,kind,scope_id,range:range(name,after)});
  const report = {scopes,
    bindings:[binding(0,'雪','let',0),binding(1,'雪','parameter',1,text.indexOf('shadow')),binding(2,'duplicate','var',0),binding(3,'duplicate','var',0,text.indexOf('duplicate;')+10),binding(4,'spare','const',0)],callables:[],
    regions:scopes.map(({id,range})=>({id,parent_id:id?0:null,callable_id:null,range,kind:id?'conditional-then':'program',entry_order:id})),operations,
    coverage:{status:'partial',diagnostics:[],frontiers:[{range:range('duplicate()'),reason:'unknown-call-mutation-or-throw'}],analyzed_range:full}};
  return {text,bytes,report};
}

const digest = async bytes => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
const turns = async (count = 1) => { for (let turn = 0; turn < count; turn++) await new Promise(resolve => setTimeout(resolve, 0)); };
const artifactFor = async (id, bytes) => ({source_type:'artifact', protocol_version:1, artifact_id:id, session_id:'11', navigation_id:'13', frame_id:'17', parent_artifact_id:'0',
  creator_event_id:'19', execution_context_id:'23', capture_origin:'dynamic_javascript', kind:'javascript', url:`https://fixture.invalid/facts-${id}.js`,
  mime_type:'text/javascript', byte_size:bytes.length, sha256:await digest(bytes), sensitive:false});

function checkJoins(ui, reference) {
  const operations = reference.report.operations, count = reference.report.bindings.length;
  const target = operation => ui.sourceFactsReferenceTarget(operation, count);
  assert.equal(target(operations[0]), operations[0].detail.target, 'An exact target is the admitted target itself');
  assert.match(ui.sourceFactsOperationSummary(operations[4], target(operations[4])), /Ambiguous.*runtime call target unknown/);
  assert.match(ui.sourceFactsOperationSummary(operations[6], target(operations[6])), /Unresolved: dynamic-scope/);
  assert.match(ui.sourceFactsOperationSummary(operations[7], target(operations[7])), /Property target; runtime object unknown/);
  for (const invalid of [{kind:'binding',binding_ids:[0,1],resolution:'lexical-only'},{kind:'ambiguous',binding_ids:[2,2],resolution:'duplicate-declarations'},
    {kind:'binding',binding_ids:[count],resolution:'lexical-only'},{kind:'binding',binding_ids:[-1],resolution:'lexical-only'},{kind:'binding',binding_ids:[0],resolution:'runtime'}]) {
    assert.equal(target({...operations[0], detail:{target:invalid}}), null);
  }
  assert.equal(target({...operations[0], detail:{nested:{target:operations[0].detail.target}}}), null, 'Arbitrary nested JSON is never lexical evidence');
  const many = {kind:'ambiguous', binding_ids:Array.from({length:4097}, (_, id) => id), resolution:'duplicate-declarations'};
  assert.equal(ui.sourceFactsReferenceTarget({...operations[4], detail:{target:many}}, 4097), many, 'Every duplicate declaration stays a candidate');
}

async function checkPages(ui, reference) {
  const source = await artifactFor('12', reference.bytes), server = sourceFactsServer(reference.report);
  const summary = server.summary(source);
  assert(ui.isSourceFactsReport(summary, source));
  const view = {category:'operations', offset:0, binding:null, kind:'all', name:'', candidates:null, back:null};
  const byName = ui.sourceFactsRequest({...view, category:'bindings', name:'雪'});
  assert.deepEqual({...byName}, {table:'bindings', offset:0, binding_id:null, kind:null, name:'雪', candidates_of:null});
  assert.equal(ui.sourceFactsRowsURL(source, byName), '/api/source-facts/rows?session_id=11&artifact_id=12&table=bindings&offset=0&limit=100&name=%E9%9B%AA');
  const reads = ui.sourceFactsRequest({...view, category:'bindings', binding:reference.report.bindings[0], kind:'read', name:'ignored'});
  assert.deepEqual({...reads}, {table:'operations', offset:0, binding_id:0, kind:'read', name:null, candidates_of:null});
  const candidates = ui.sourceFactsRequest({...view, category:'bindings', candidates:{id:4, count:2}});
  assert.equal(ui.sourceFactsRowsURL(source, candidates), '/api/source-facts/rows?session_id=11&artifact_id=12&table=bindings&offset=0&limit=100&candidates_of=4');
  const page = server.page(source, ui.sourceFactsRowsURL(source, byName));
  assert(ui.isSourceFactsPage(page, source, summary, byName));
  assert.equal(page.total, 2);
  const all = ui.sourceFactsRequest(view), first = server.page(source, ui.sourceFactsRowsURL(source, all));
  assert(ui.isSourceFactsPage(first, source, summary, all));
  assert.equal(first.rows.length, 100); assert.equal(first.total, 113);
  for (const update of [{table:'operations'}, {offset:100}, {filter:{...page.filter, name:'other'}}, {filter:{...page.filter, kind:'read'}}, {total:3},
    {rows:[page.rows[0], page.rows[0]]}, {rows:[{...page.rows[0], id:summary.counts.bindings}, page.rows[1]]}, {rows:[{...page.rows[0], kind:'executed'}, page.rows[1]]},
    {rows:[{...page.rows[0], range:{start:0, end:source.byte_size + 1}}, page.rows[1]]}, {source:{...page.source, sha256:'b'.repeat(64)}},
    {analyzed_range:{start:1, end:2}}, {bindings:[{...reference.report.bindings[0], id:99}]}, {schema:'reb-javascript-source-facts-v1'}]) {
    assert.equal(ui.isSourceFactsPage({...page, ...update}, source, summary, byName), false, JSON.stringify(Object.keys(update)));
  }
  assert.equal(ui.isSourceFactsPage({...first, total:112, rows:first.rows}, source, summary, all), false, 'An unfiltered page agrees with the summary count');
  console.log('PASS Facts rows: request mapping, URL encoding, page identity, filter echo, row ranges and IDs, and report counts (not rendered QA)');
}

class FactsReviewNode {
  constructor(document, roots, tag) {
    this.document = document; this.roots = roots;
    this.tagName = tag; this.children = []; this.dataset = {}; this.attributes = {};
    this.listeners = {}; this._text = ''; this.value = ''; this.disabled = false; this.hidden = false;
    this.selectionStart = 0; this.selectionEnd = 0; this.parentNode = null;
  }
  set textContent(value) { this._text = String(value); this.replaceChildren(); }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...nodes) { for (const node of nodes) { node.parentNode?.children.splice(node.parentNode.children.indexOf(node), 1); node.parentNode = this; this.children.push(node); } }
  replaceChildren(...nodes) {
    for (const child of this.children) {
      if (child.contains(this.document.activeElement)) this.document.activeElement = null;
      child.parentNode = null;
    }
    this.children = []; this.append(...nodes);
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  addEventListener(name, handler) { (this.listeners[name] ??= []).push(handler); }
  fire(name, values = {}) { for (const handler of this.listeners[name] ?? []) handler({target: this, currentTarget: this, ...values}); }
  click() { if (!this.disabled) this.fire('click'); }
  contains(node) { return this === node || this.children.some(child => child.contains(node)); }
  get isConnected() { return this.roots.some(root => root.contains(this)); }
  focus() { if (this.isConnected) this.document.activeElement = this; }
  setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }
  getClientRects() { return this.isConnected ? [1] : []; }
  scrollIntoView() {}
  matches(selector) {
    if (selector.includes(',')) return selector.split(',').some(value => this.matches(value.trim()));
    if (selector.startsWith('.')) return this.className?.split(' ').includes(selector.slice(1)) ?? false;
    if (selector.startsWith('[')) {
      const match = selector.match(/^\[([^=\]]+)(?:="?([^"\]]*)"?)?\]$/);
      if (!match) return false;
      const name = match[1];
      const value = name.startsWith('data-') ? this.dataset[name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] : this.attributes[name];
      return match[2] === undefined ? value !== undefined : value === match[2];
    }
    return selector === this.tagName;
  }
  querySelectorAll(selector) { return this.children.flatMap(child => [...(child.matches(selector) ? [child] : []), ...child.querySelectorAll(selector)]); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
  closest(selector) { return this.matches(selector) ? this : this.parentNode?.closest(selector); }
}

async function checkPanel(root, reference) {
  const panelSource = await readFile(join(root, 'apps/research-ui/source_facts.js'), 'utf8');
  const roots = [], document = {activeElement: null};
  const element = tag => new FactsReviewNode(document, roots, tag);
  Object.assign(document, {createElement: element});
  const toggle = element('button'), details = element('details'), container = element('div');
  roots.push(toggle, details);
  details.append(element('summary'), container);
  details.open = true;
  document.querySelector = selector => ({'#source-facts-toggle': toggle, '#source-facts-details': details, '#source-facts-report': container}[selector]);
  let selected = await artifactFor('12', reference.bytes);
  let reportError = false, finishOriginal, navigations = 0, held = null;
  const requests = [];
  const create = Function('document', 'location', 'fetch', `${panelSource}; return createSourceFactsPanel;`)(document, {protocol: 'http:'}, async (url, {signal}) => {
    requests.push({url, signal});
    if (url.startsWith('/api/artifacts/')) return new Promise(resolve => { finishOriginal = () => resolve(new Response(reference.bytes, {headers: {'X-Artifact-Total-Bytes': String(reference.bytes.length), 'X-Artifact-Offset': '0', 'X-Artifact-Truncated': 'false'}})); });
    if (reportError) return Response.json({error: 'Authored retry failure'}, {status: 503});
    if (held) await held.promise;
    return sourceFactsServer(reference.report).response(selected, url);
  });
  const panel = create({getSource: () => selected, onNavigate() { navigations++; }, openSidebar() {}});
  const control = selector => { const node = container.querySelector(selector); assert(node, `Missing ${selector}`); return node; };
  const action = name => control(`[data-facts-action="${name}"]`);
  const articles = () => container.querySelectorAll('article').length;
  const category = value => { const node = control('[aria-label="JavaScript fact category"]'); node.value = value; node.fire('change'); };
  const row = id => control(`[data-fact-id="${id}"]`);
  const settled = async () => {
    for (let turn = 0; turn < 400 && (panel.model.pageStatus === 'loading' || ['loading', 'loading-source'].includes(panel.model.status)); turn++) await turns();
    assert.notEqual(panel.model.pageStatus, 'loading', 'A page read did not settle');
  };
  const pageStatus = () => control('.source-facts-page-status').textContent;
  try {
    panel.sync(selected);
    const idleArtifact = selected;
    selected = {source_type: 'script', kind: 'javascript'}; panel.sync(selected);
    selected = idleArtifact; assert.doesNotThrow(() => panel.sync(selected), 'Idle captured → unsupported → captured must rebuild the retained DOM');
    const loading = panel.load();
    assert.match(control('.source-facts-status').textContent, /Analyzing immutable JavaScript… 0 s\. The whole artifact is analyzed; Cancel stops the worker\./);
    assert.equal(action('cancel').hidden, false);
    await loading;
    assert.equal(articles(), 100);
    assert.match(pageStatus(), /^Showing 1–100 of 113\.$/);
    action('next').focus(); action('next').click(); await settled();
    assert.equal(articles(), 13); assert.match(pageStatus(), /^Showing 101–113 of 113\.$/);
    assert.equal(document.activeElement, action('previous'), 'Paging past the end keeps keyboard focus inside the pager');
    action('previous').click(); await settled(); assert.equal(articles(), 100);

    category('bindings'); await settled();
    assert.equal(articles(), 5);
    const input = control('[data-facts-binding-query]'); input.focus();
    input.fire('compositionstart'); input.value = '雪';
    input.fire('input', {isComposing: true});
    let escapePrevented = false, escapeStopped = false;
    details.fire('keydown', {key: 'Escape', isComposing: true, preventDefault() { escapePrevented = true; }, stopPropagation() { escapeStopped = true; }});
    assert.equal(escapeStopped, true, 'IME Escape must not bubble into the document Sources shortcut and toggle Console');
    assert.equal(details.open, true); assert.equal(escapePrevented, false, 'IME Escape must remain available to composition');
    assert(input.isConnected, 'Composition must not detach its input');
    assert.equal(panel.model.pageStatus, 'ready', 'Composing text does not query');
    input.fire('compositionend', {isComposing: false});
    // A page arriving mid-composition must not replace the input either.
    input.fire('compositionstart');
    await settled();
    assert.equal(articles(), 2);
    assert(input.isConnected, 'A page arriving never detaches the declaration input');
    assert.equal(document.activeElement, input); assert.equal(input.value, '雪');
    input.fire('compositionend', {isComposing: false}); await settled();

    row(1).querySelector('[data-facts-action="explore-binding"]').click(); await settled();
    assert.equal(articles(), 1);
    assert.equal(container.querySelector('article').dataset.factId, '1', 'Shadowed name must not join outer references');
    action('back-to-list').click(); await settled();
    assert.equal(articles(), 2); assert.equal(control('[data-facts-binding-query]').value, '雪', 'Back restores the declaration list it came from');
    row(0).querySelector('[data-facts-action="explore-binding"]').click(); await settled();
    assert.match(pageStatus(), /^Showing 1–100 of 108 lexical operations\.$/, 'Closure and outer reads share the exact binding ID');
    const kind = control('[aria-label="Lexical operation kind"]'); kind.value = 'write'; kind.fire('change'); await settled();
    assert.deepEqual(container.querySelectorAll('article').map(node => node.dataset.factId), ['3']);
    category('operations'); await settled();
    row(4).querySelector('[data-facts-action="choose-candidate"]').click(); await settled();
    assert.deepEqual(container.querySelectorAll('article').map(node => node.dataset.factId), ['2', '3']);
    assert.match(container.textContent, /2 ambiguous declaration candidates\. No unique binding is proven\./);
    row(3).querySelector('[data-facts-action="explore-binding"]').click(); await settled();
    assert.deepEqual(container.querySelectorAll('article').map(node => node.dataset.factId), ['4', '5']);
    assert.equal(action('back-to-list').textContent, 'Back to candidates');
    action('back-to-list').click(); await settled();
    action('clear-candidates').click(); await settled(); assert.equal(articles(), 5);
    category('operations'); await settled();
    row(0).querySelector('[data-facts-action="explore-binding"]').click(); await settled();
    assert.equal(action('back-to-list').textContent, 'Back to operations');

    // A newer page retires an older read, and Cancel stops a page read.
    held = Promise.withResolvers();
    category('scopes'); const older = requests.at(-1);
    category('regions'); assert.equal(older.signal.aborted, true, 'A newer view retires the older page read');
    assert.match(pageStatus(), /^Loading rows… 0 s\.$/); assert.equal(action('cancel').hidden, false);
    action('cancel').click(); assert.equal(requests.at(-1).signal.aborted, true);
    held.resolve(); held = null; await settled();
    assert.equal(control('[aria-label="JavaScript fact category"]').value, 'bindings', 'A cancelled page read returns the view to the rows it shows');
    assert.match(container.querySelector('article').querySelector('strong').textContent, /^#\d+ read/);

    action('reveal-declaration').click();
    for (let turn = 0; turn < 20 && !finishOriginal; turn++) await turns();
    assert(finishOriginal, 'Verified original read did not start');
    const pendingBack = action('back-to-list');
    panel.cancel('A newer interaction retired this original-range return.');
    assert(pendingBack.isConnected, 'Capture-phase cancellation must preserve the pending click target');
    pendingBack.click(); await settled(); assert(container.querySelector('[data-facts-action="choose-candidate"]'), 'The original click must still change the view after capture cancellation');
    finishOriginal(); await turns();
    assert.equal(navigations, 0, 'Changing lexical selection must retire a pending original range');

    category('bindings'); await settled();
    const retiredQuery = control('[data-facts-binding-query]');
    const retiredCategory = control('[aria-label="JavaScript fact category"]');
    const retiredExplore = action('explore-binding');
    selected = {...selected, artifact_id: '13'}; panel.sync(selected); await panel.load();
    const currentText = container.textContent;
    retiredQuery.value = 'must not leak'; retiredQuery.fire('input');
    retiredCategory.value = 'frontiers'; retiredCategory.fire('change'); retiredExplore.click(); await settled();
    assert.equal(container.textContent, currentText, 'Detached controls must not change the newer source/report');
    category('bindings'); await settled(); row(0).querySelector('[data-facts-action="explore-binding"]').click(); await settled();
    reportError = true; await panel.load();
    assert(container.querySelector('.source-facts-binding').textContent.includes('Binding #0'), 'Failed retry must preserve the selected declaration');
    assert.match(control('.source-facts-status').textContent, /Authored retry failure/);
    reportError = false; await panel.load();
    assert.equal(container.querySelector('.source-facts-binding'), null, 'Successful reanalysis must retire report-local binding selection');
    assert.equal(articles(), 100);
  } finally { details.open = false; details.fire('toggle'); }
  console.log('PASS offline Facts panel: paged rows, server-side binding joins, candidates, back navigation, read retirement, cancel, IME input lifetime across page arrivals, detached controls and retry selection. Not rendered QA.');
}

async function checkSummary(ui) {
  const bytes = new TextEncoder().encode('﻿const 雪 = "😀";\n雪++;');
  const artifact = await artifactFor('7', bytes);
  const server = sourceFactsServer({scopes:[{id:0,parent_id:null,range:{start:0,end:bytes.length},kind:'program'}], bindings:[], callables:[],
    regions:[{id:0,parent_id:null,callable_id:null,range:{start:0,end:bytes.length},kind:'program',entry_order:0}], operations:[],
    coverage:{status:'complete',frontiers:[],diagnostics:[],analyzed_range:{start:0,end:bytes.length}}});
  assert.equal(ui.sourceFactsUnavailable(artifact, 'http:'), '');
  assert.equal(ui.sourceFactsUnavailable({...artifact, byte_size:24 * 1024 * 1024 + 1}, 'http:'), '', 'A whole artifact of any size is analyzed');
  assert.match(ui.sourceFactsUnavailable(artifact, 'reb:'), /stored-evidence native mode/);
  assert.match(ui.sourceFactsUnavailable({...artifact, source_type:'script'}, 'http:'), /captured JavaScript/);
  for (const source of [{...artifact, artifact_id:'07'}, {...artifact, session_id:'18446744073709551616'}, {...artifact, byte_size:-1}]) assert(ui.sourceFactsUnavailable(source, 'http:'));
  const report = server.summary(artifact);
  assert(ui.isSourceFactsReport(report, artifact));
  for (const field of Object.keys(report.source)) {
    const foreign = structuredClone(report); foreign.source[field] = null;
    assert.equal(ui.isSourceFactsReport(foreign, artifact), false, field);
  }
  for (const update of [{offset_unit:'utf-16'}, {source_bytes:0}, {ok:false}, {cached:'no'}, {schema:'reb-javascript-source-facts-v1'},
    {counts:{...report.counts, operations:-1}}, {counts:{...report.counts, frontiers:undefined}},
    {coverage:{...report.coverage, analyzed_range:{start:0, end:bytes.length + 1}}},
    {coverage:{...report.coverage, analyzed_range:{start:1, end:bytes.length}}},
    {coverage:{...report.coverage, diagnostics:['Complete coverage has no diagnostics']}},
    {counts:{...report.counts, frontiers:1}}]) {
    assert.equal(ui.isSourceFactsReport({...report, ...update}, artifact), false, JSON.stringify(update));
  }
  const partial = {...report, coverage:{status:'partial', diagnostics:['Unknown effects remain'], analyzed_range:report.coverage.analyzed_range}, counts:{...report.counts, frontiers:200000}};
  assert(ui.isSourceFactsReport(partial, artifact), 'Frontier counts are not capped');
  const unavailable = {...report, ok:false, coverage:{status:'unavailable', diagnostics:['Malformed source'], analyzed_range:report.coverage.analyzed_range}, counts:{...report.counts, scopes:0, regions:0}};
  assert(ui.isSourceFactsReport(unavailable, artifact));
  assert.equal(ui.isSourceFactsReport({...unavailable, counts:report.counts}, artifact), false);
  const snowOffset = new TextEncoder().encode('﻿const ').length;
  const snow = ui.sourceFactsPosition(bytes, {start:snowOffset, end:snowOffset + 3});
  assert.equal(snow.line, 0); assert.equal(snow.column, 7); assert.equal(snow.length, 1);
  assert.throws(() => ui.sourceFactsPosition(bytes, {start:snowOffset + 1, end:snowOffset + 3}));
  assert.equal(ui.sourceFactsPosition(bytes, {start:0, end:bytes.length}).multiline, true);
  assert.equal(ui.sourceFactsPosition(new Uint8Array(), {start:0, end:0}).column, 0);
  return {bytes, artifact, server, snowOffset};
}

async function checkReader(ui, bytes) {
  await assert.rejects(ui.sourceFactsReadBytes(new Response(new Uint8Array(5)), 4), /byte limit/);
  // A response is copied into one owned buffer that grows with it, never a
  // retained list of producer chunks.
  const reader = (read, cancel = async () => {}) => {
    const counts = {reads:0, cancels:0, releases:0};
    return {counts, response:{body:{getReader:() => ({
      read:() => { counts.reads++; return read(counts.reads); },
      cancel:() => { counts.cancels++; return cancel(); },
      releaseLock:() => { counts.releases++; },
    })}}};
  };
  const fragmented = (count, width) => reader(async index => index > count ? {done:true} : {done:false, value:new Uint8Array(width).fill(index % 251)});
  for (const [count, width, maximum] of [[0, 0, 0], [65536, 0, 0], [65536, 1, 65536], [70000, 1, undefined], [3, 400000, undefined]]) {
    const fixture = fragmented(count, width);
    const result = await ui.sourceFactsReadBytes(fixture.response, maximum);
    assert.equal(result.length, count * width); assert.equal(result.buffer.byteLength, count * width, 'The owned buffer is exactly the response');
    for (let index = 0; index < result.length; index += Math.max(1, width)) assert.equal(result[index], (Math.floor(index / Math.max(1, width)) + 1) % 251);
    assert.deepEqual(fixture.counts, {reads:count + 1, cancels:0, releases:1});
  }
  const oversized = fragmented(1, 5);
  await assert.rejects(ui.sourceFactsReadBytes(oversized.response, 4), /byte limit/);
  assert.deepEqual(oversized.counts, {reads:1, cancels:1, releases:1});
  const nonbyte = reader(async () => ({done:false, value:[1]}));
  await assert.rejects(ui.sourceFactsReadBytes(nonbyte.response), /non-byte chunk/);
  assert.equal(nonbyte.counts.cancels, 1); assert.equal(nonbyte.counts.releases, 1);
  const reused = new Uint8Array(1024 * 1024);
  const aliased = reader(async index => {
    if (index > bytes.length) return {done:true};
    reused[17] = bytes[index - 1];
    return {done:false, value:reused.subarray(17, 18)};
  });
  const owned = await ui.sourceFactsReadBytes(aliased.response, bytes.length);
  assert.deepEqual(owned, bytes, 'Copy each fragmented UTF-8/BOM byte before its producer reuses the backing store');
  assert.equal(owned.buffer.byteLength, bytes.length); assert.notEqual(owned.buffer, reused.buffer);
  const aborted = new AbortController(); aborted.abort();
  const preCancelled = fragmented(1, 1);
  await assert.rejects(ui.sourceFactsReadBytes(preCancelled.response, 1, aborted.signal), /cancelled/);
  assert.deepEqual(preCancelled.counts, {reads:0, cancels:1, releases:1});
  const fragmentedSignal = new AbortController(), endless = reader(async () => ({done:false, value:new Uint8Array()}));
  const interrupt = setTimeout(() => fragmentedSignal.abort(), 0);
  try { await assert.rejects(ui.sourceFactsReadBytes(endless.response, undefined, fragmentedSignal.signal), /cancelled/); }
  finally { clearTimeout(interrupt); }
  assert(endless.counts.reads <= 256, 'Fragmented streams must yield to cancellation tasks');
  assert.equal(endless.counts.cancels, 1); assert.equal(endless.counts.releases, 1);
  const stalledSignal = new AbortController(); let stalledCancelled = 0;
  const stalled = new Response(new ReadableStream({cancel() { stalledCancelled++; return new Promise(() => {}); }}));
  const stalledRead = ui.sourceFactsReadBytes(stalled, undefined, stalledSignal.signal);
  stalledSignal.abort();
  let watchdog;
  try { await assert.rejects(Promise.race([stalledRead, new Promise((_, reject) => { watchdog = setTimeout(() => reject(new Error('Stalled reader did not cancel promptly')), 1000); })]), /cancelled/); }
  finally { clearTimeout(watchdog); }
  assert.equal(stalledCancelled, 1); assert.equal(stalled.body.locked, false);
}

async function checkController(ui, {bytes, artifact, server, snowOffset}) {
  let selected = artifact;
  const pending = [], navigations = [];
  const controller = ui.createSourceFactsController({getSource:() => selected, protocol:'http:', onChange:() => {}, onNavigate:(...args) => navigations.push(args), cryptoApi:crypto,
    fetcher:(url, options) => new Promise(resolve => pending.push({url, options, resolve}))});
  const next = async () => { for (let turn = 0; turn < 100 && !pending.length; turn++) await turns(); assert(pending.length, 'Expected a request'); return pending.shift(); };
  const deliver = (entry, source = selected) => entry.resolve(server.response(source, entry.url));
  const original = (body = bytes, headers = {'X-Artifact-Total-Bytes':String(bytes.length), 'X-Artifact-Offset':'0', 'X-Artifact-Truncated':'false'}) => new Response(body, {headers});
  controller.sync(selected);
  const first = controller.load(), firstRequest = await next();
  assert.equal(firstRequest.url, '/api/source-facts?session_id=11&artifact_id=7');
  assert.equal(controller.load(), first, 'A repeated load joins the analysis in flight'); assert.equal(pending.length, 0);
  controller.cancel(); assert.equal(firstRequest.options.signal.aborted, true);
  assert.match(controller.model.notice, /cancelled.*backend work was stopped/); assert.equal(controller.model.status, 'idle');
  const second = controller.load();
  deliver(await next());
  const rows = await next(); assert.equal(rows.url, '/api/source-facts/rows?session_id=11&artifact_id=7&table=operations&offset=0&limit=100');
  deliver(rows); await second;
  assert.equal(controller.model.page.total, 0); assert.equal(controller.model.pageStatus, 'ready');
  const retained = controller.model.report;
  deliver(firstRequest); await first;
  assert.equal(controller.model.report, retained, 'A cancelled older response cannot replace current facts');
  const stale = controller.load(), staleRequest = await next();
  selected = {...artifact, session_id:'12'}; controller.sync(selected);
  deliver(staleRequest, artifact); await stale;
  assert.equal(controller.model.report, null, 'Switching source clears facts and rejects delayed responses');
  selected = artifact; controller.sync(selected);
  const matching = controller.load(); deliver(await next()); deliver(await next()); await matching;
  const olderPage = controller.show({...controller.model.view, category:'scopes'}), older = await next();
  const newerPage = controller.show({...controller.model.view, category:'regions'}), newer = await next();
  assert.equal(older.options.signal.aborted, true, 'A newer page retires the older read');
  deliver(older); deliver(newer); await Promise.all([olderPage, newerPage]);
  assert.equal(controller.model.page.table, 'regions'); assert.equal(controller.model.page.rows.length, 1);
  const wrongPage = controller.show({...controller.model.view, category:'scopes'}), wrong = await next();
  wrong.resolve(Response.json({...server.page(selected, wrong.url), offset:100})); await wrongPage;
  assert.equal(controller.model.pageStatus, 'error'); assert.match(controller.model.pageError, /did not match/);
  assert.equal(controller.model.page.table, 'regions', 'The last understandable page stays');
  const failingPage = controller.show({...controller.model.view, category:'bindings'}), failing = await next();
  failing.resolve(new Response('{', {status:502})); await failingPage;
  assert.equal(controller.model.pageError, 'Source fact rows returned HTTP 502.');
  const navigation = controller.navigate({start:snowOffset, end:snowOffset + 3}), chunk = await next();
  assert.equal(chunk.url, '/api/artifacts/7/content?offset=0&limit=2097152');
  chunk.resolve(original()); await navigation;
  assert.equal(navigations.length, 1); assert.equal(navigations[0][2].column, 7);
  assert.equal(controller.original(artifact), '﻿const 雪 = "😀";\n雪++;');
  await controller.navigate({start:0, end:0}); assert.equal(pending.length, 0, 'Repeated navigation reuses verified original bytes');
  selected = {...artifact, sha256:'b'.repeat(64)}; controller.sync(selected);
  assert.equal(controller.original(selected), undefined, 'Changed hash invalidates original bytes');
  const mismatched = controller.load(); deliver(await next(), artifact); await mismatched;
  assert.equal(controller.model.status, 'error'); assert.equal(controller.model.report, null); assert.equal(pending.length, 0, 'A refused summary reads no rows');
  for (const body of [original(bytes, {'X-Artifact-Truncated':'1'}), original(new Uint8Array(bytes.length))]) {
    const attempt = controller.navigate({start:0, end:0}); (await next()).resolve(body); await attempt;
    assert.equal(controller.model.status, 'error'); assert.equal(controller.original(selected), undefined);
  }
  // No deadline: slow work keeps running with its start time for elapsed
  // progress, until it settles or is cancelled.
  const hanging = (_url, {signal}) => Promise.resolve(new Response(new ReadableStream({start(stream) { signal.addEventListener('abort', () => stream.error(new DOMException('Aborted', 'AbortError')), {once:true}); }})));
  const slow = ui.createSourceFactsController({getSource:() => artifact, protocol:'http:', now:() => 1234, onChange:() => {}, onNavigate:() => { throw new Error('Cancelled analysis navigated'); }, cryptoApi:crypto, fetcher:hanging});
  const slowLoad = slow.load(); await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(slow.model.status, 'loading'); assert.equal(slow.model.started, 1234);
  slow.cancel(); await slowLoad;
  assert.equal(slow.model.status, 'idle'); assert.equal(slow.model.report, null); assert.equal(slow.model.error, '');
  for (const mode of ['facts', 'source']) {
    let cancelledBody = 0, chunks = 0;
    const fragmented = ui.createSourceFactsController({getSource:() => artifact, protocol:'http:', onChange:() => {}, onNavigate:() => { throw new Error('Cancelled fragmented source navigated'); }, cryptoApi:crypto,
      fetcher:async () => new Response(new ReadableStream({
        pull(stream) { chunks++; stream.enqueue(new Uint8Array()); },
        cancel() { cancelledBody++; return new Promise(() => {}); },
      }), {headers:{'X-Artifact-Total-Bytes':String(bytes.length), 'X-Artifact-Offset':'0', 'X-Artifact-Truncated':'false'}})});
    const operation = mode === 'facts' ? fragmented.load() : fragmented.navigate({start:0, end:0});
    await new Promise(resolve => setTimeout(resolve, 20));
    assert(chunks > 256, 'An endless fragmented body keeps being read without a chunk budget');
    fragmented.cancel();
    let watchdog;
    try { await Promise.race([operation, new Promise((_, reject) => { watchdog = setTimeout(() => reject(new Error('Fragmented cancellation stalled')), 2000); })]); }
    finally { clearTimeout(watchdog); }
    assert.equal(fragmented.model.status, 'idle'); assert.equal(fragmented.model.report, null); assert.equal(fragmented.model.original, null);
    assert.equal(cancelledBody, 1);
  }
  let finishDigest, digestArrived;
  const arrival = new Promise(resolve => { digestArrived = resolve; });
  const digesting = ui.createSourceFactsController({getSource:() => artifact, protocol:'http:', onChange:() => {}, onNavigate:() => { throw new Error('Late digest navigated'); },
    cryptoApi:{subtle:{digest:() => new Promise(resolve => { finishDigest = resolve; digestArrived(); })}}, fetcher:async () => original()});
  const digestNavigation = digesting.navigate({start:0, end:0});
  await arrival;
  digesting.cancel();
  assert.equal(digesting.model.status, 'idle', 'Cancel ends the busy state while a non-abortable digest is pending');
  finishDigest(await crypto.subtle.digest('SHA-256', bytes)); await digestNavigation;
  assert.equal(digesting.model.original, null);
  console.log('PASS Sources facts identity, UTF-8/BOM ranges, owned streams without byte or chunk budgets, repeated loads, paged rows, cancellation, stale responses and hash checks');
}

export async function checkSourceFactsUI(root) {
  const ui = runInNewContext(
    (await readFile(join(root, 'apps/research-ui/source_facts.js'), 'utf8')) +
    ';({sourceFactsIdentity,sourceFactsUnavailable,isSourceFactsReport,isSourceFactsPage,sourceFactsRequest,sourceFactsRowsURL,sourceFactsPosition,sourceFactsReadBytes,createSourceFactsController,sourceFactsReferenceTarget,sourceFactsOperationSummary})',
    {TextEncoder, TextDecoder, Uint8Array, AbortController, setTimeout, clearTimeout, setInterval, clearInterval, fetch, crypto, Response},
  );
  const reference = factsReferenceFixture();
  checkJoins(ui, reference);
  console.log('PASS Facts lexical targets: exact and ambiguous joins, unresolved/property refusal, malformed joins and uncapped candidate sets (not rendered QA)');
  await checkPages(ui, reference);
  await checkPanel(root, reference);
  const summary = await checkSummary(ui);
  await checkReader(ui, summary.bytes);
  await checkController(ui, summary);
}
