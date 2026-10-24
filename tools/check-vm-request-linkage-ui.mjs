#!/usr/bin/env node
// Executes shipped models, refresh controllers, navigation and finding renderers.
// The small DOM below is a controller test adapter, NOT rendered Chromium QA.
// --pipeline additionally reads an actual native sink -> broker/receiver corpus
// over the production HTTP backend. It does not author positive join evidence.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp, readFile, rm, stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {runInNewContext} from 'node:vm';

const repository = fileURLToPath(new URL('..', import.meta.url));
const copy = value => structuredClone(value);
const plain = value => JSON.parse(JSON.stringify(value));
const digest = digit => digit.repeat(64);
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
};
function section(source, start, end) {
  const first = source.indexOf(start), last = source.indexOf(end, first + start.length);
  assert(first >= 0 && last > first, `Missing production boundary: ${start}`);
  return source.slice(first, last);
}

const selection = (changes = {}) => ({kind: 'request', request_id: '18446744073709551615',
  root_event: {session_id: '9007199254740993', process_id: 42, sequence_number: '9007199254740993'},
  edge_semantics: 'exact-captured-response-body', ...changes});
const A = selection();
const B = selection({root_event: {...A.root_event, process_id: 43}});
function nativeEvent(selected = A, changes = {}) {
  const payload = Buffer.from('GET same-host.invalid').toString('hex');
  return {protocol_version: 3, category: 'network', type: 'request_started',
    ...selected.root_event, request_id: selected.request_id, monotonic_time_ns: '10',
    navigation_id: '1', frame_id: '2', artifact_id: '0', parent_event_id: '0',
    thread_id: 1, tab_id: 1, initiator_request_id: 0, initiator_process_id: 0,
    resource_type: 3, flags: 0, status_code: 0, error_code: 0,
    encoded_data_length: '0', decoded_body_length: '0', payload_encoding: 'hex',
    payload_size: payload.length / 2, payload, payload_truncated: false, ...changes};
}
function linkFor(selected) {
  return {request_id: selected.request_id, root_event: copy(selected.root_event),
    response_event: {...selected.root_event, sequence_number: String(BigInt(selected.root_event.sequence_number) + 1n)},
    capture_event: {...selected.root_event, sequence_number: String(BigInt(selected.root_event.sequence_number) + 2n)},
    relation: 'captured-response-body'};
}
function opcodeDocument(tag = 'a') {
  return {contract_version: 2, document_kind: 'vm-opcode-workspace',
    producer: {id: 'origin-trace-vm-opcode', version: '1'}, capture_mode: 'native-stealth',
    profile_digest: digest('a'), analysis_digest: digest('b'), document_digest: digest(tag),
    inputs: {artifact_manifest_digest: null, event_store_digest: null, capture_provenance_digest: null},
    workspaces: [], summary: {workspace_count: 0, handler_count: 0, snapshot_count: 0, sample_count: 0, unknown_count: 0}};
}
function hostDocument(tag = 'a') {
  return {contract_version: 1, document_kind: 'vm-host-links', workspace_document_digest: digest(tag),
    workspaces: [], document_digest: digest('d')};
}
function analysisDocument(selected = A, id = '101', tag = 'a') {
  const result = {artifact_id: id, artifact_sha256: digest(tag), finding_id: tag.repeat(24),
    runtime: 'javascript', status: 'complete', tier: 'likely-vm', vm_score: 80,
    anti_bot_score: 0, evidence_families: ['dispatch'], observations: [],
    related_request_ids: [A.request_id], coverage: {complete: true},
    exact_request_links: [linkFor(selected ?? A)]};
  return {contract_version: 1, document_kind: 'vm-analysis', document_digest: digest(tag),
    profile_digest: digest('f'), profile: {profile_id: 'anti-bot-vm-detection-v1'},
    input_coverage: {complete: true, omissions: []}, results: [result], mixed_findings: [],
    opcode_workspace: opcodeDocument(tag), ...(selected ? {selection: copy(selected)} : {})};
}
function response(body, status = 200, etag = 'analysis-a') {
  return {status, ok: status >= 200 && status < 300,
    headers: {get: name => name.toLowerCase() === 'etag' ? etag : null},
    json: async () => copy(body)};
}

async function loadHarness(root) {
  const [app, model, initial] = await Promise.all(['app.js', 'evidence_models.js', 'app_state.js']
    .map(name => readFile(join(root, 'apps/research-ui', name), 'utf8')));
  const code = model + '\n' + initial.slice(0, initial.indexOf('      const elements =')) + '\n' +
    section(app, '      function acceptVmOpcodeWorkspace(', '      function setNetworkNotice(') +
    section(app, '      function textElement(', '      function emptyListboxOption(') +
    section(app, '      function setVmNotice(', '      function requestOriginLabel(') +
    section(app, '      function vmField(', '      function vmSessionPresentation(') +
    section(app, '      function renderVmDetail(', '      function requestDomain(') +
    section(app, '      function showScreen(', '      async function refresh()') +
    section(app, "      elements.requestVmCandidates.addEventListener(", '      elements.sourceWindowPrevious.addEventListener(') +
    `\n({state, refreshVmAnalysis, refreshVmOpcodeWorkspace, showScreen, renderVmLab, renderVmDetail,
      vmRequestSelection, vmRequestSelectionKey, isVmRequestSelection, isVmExactRequestLink,
      isVmAnalysisDocument, vmAnalysisMatchesSelection, vmFindingsFromAnalysis, vmVisibleFindings,
      vmSourceArtifactForFinding, vmOpcodeWorkspaceForFinding, isVmOpcodeWorkspaceDocument,
      isBrokerResponse, isBrokerEvent, isArtifactResponse, requestsFromEvents})`;
  return function fixture() {
    let api;
    const notices = [], calls = [], sourceSelections = [], pending = [];
    // Only DOM mechanics are substituted. No selection, cache or linkage logic is.
    class Element {
      constructor(tag = 'div') {
        this.tagName = tag; this.children = []; this.events = {}; this.attributes = {};
        this.dataset = {}; this.style = {}; this.className = ''; this.text = ''; this.hidden = false;
        this.classList = {contains: name => this.className.split(' ').includes(name), add: name => {this.className += ` ${name}`;}};
      }
      set textContent(value) { this.text = String(value); this.children = []; }
      get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
      append(...items) { this.children.push(...items); }
      replaceChildren(...items) { this.text = ''; this.children = items; }
      setAttribute(name, value) { this.attributes[name] = String(value); }
      removeAttribute(name) { delete this.attributes[name]; }
      addEventListener(name, callback) { this.events[name] = callback; }
      contains(node) { return this === node || this.children.some(child => child.contains(node)); }
      querySelectorAll(selector) { return descendants(this).slice(1).filter(node => selector.startsWith('.') && node.classList.contains(selector.slice(1))); }
      querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
      click() { return this.events.click?.(); }
      focus() { document.activeElement = this; }
    }
    const elements = Object.fromEntries(['requestVmCandidates', 'vmDetail', 'vmNotice', 'vmList', 'vmCount', 'requestRows', 'requestFilter'].map(name => [name, new Element()]));
    elements.requestVmCandidates.id = 'request-vm-candidates';
    const screens = ['traffic', 'vm', 'sources'].map(name => Object.assign(new Element(), {id: `screen-${name}`, hidden: name !== 'traffic'}));
    const nav = Object.assign(new Element('button'), {id: 'nav-vm', className: 'nav-button', dataset: {screen: 'vm'}});
    const navigation = Object.assign(new Element(), {open: false});
    const symbols = new Element();
    const document = {activeElement: null, createElement: tag => new Element(tag),
      querySelectorAll: selector => selector === '.screen' ? screens : selector === '.nav-button' ? [nav] : [],
      querySelector: selector => selector === '#advanced-navigation' ? navigation : selector === '#vm-symbol-list' ? symbols : null};
    const fixture = {calls, notices, sourceSelections, elements, nav, document,
      reply: (url) => url.includes('/opcodes') ? response(opcodeDocument()) : url.includes('/host-links') ? response(null, 404) : response(analysisDocument()),
      get screen() { return screens.find(screen => !screen.hidden)?.id.replace('screen-', ''); },
      async settle() { while (pending.length) await Promise.all(pending.splice(0)); }};
    const noop = () => {};
    api = runInNewContext(code, {
      TextEncoder, TextDecoder, Uint8Array, URLSearchParams, URL, TypeError, SyntaxError,
      location: {protocol: 'http:', search: ''}, document, elements,
      fetch: (url, options) => {
        calls.push({url, options: copy(options)});
        const result = Promise.resolve().then(() => fixture.reply(url, options));
        pending.push(result.catch(noop)); return result;
      },
      investigationNotice: (...args) => notices.push(args), investigationBeforeScreen: noop,
      retireCanvasPreviews: noop, evidenceWorkspace: {setVisible: noop}, sourceFactsPanel: {cancel: noop},
      float32Panel: {cancel: noop}, renderVmSessionStatus: noop, shownSequenceGaps: () => 0n,
      renderVmOpcodeWorkspaceInPlace: noop, investigationRevision: 0,
      requestAnimationFrame: noop, renderDebugger: noop, renderSources: noop, selectedSource: () => null,
      renderRequests: noop, updateSelectionSummary: noop, renderInspector: noop, renderRuntimeHookTraffic: noop,
      selectArtifact: (...args) => sourceSelections.push(args)
    });
    Object.assign(fixture, api);
    api.state.broker = 'connected';
    return fixture;
  };
}
const descendants = node => [node, ...node.children.flatMap(descendants)];
const sourceButton = fixture => descendants(fixture.elements.vmDetail).find(node => node.tagName === 'button' && node.textContent === 'Open in Sources');
function setNativeRow(fixture, selected = A) {
  const root = nativeEvent(selected);
  const terminal = nativeEvent(selected, {type: 'request_completed', sequence_number: String(BigInt(root.sequence_number) + 3n), parent_event_id: root.sequence_number, status_code: 200});
  fixture.state.requests = fixture.requestsFromEvents([root, terminal]);
  fixture.state.selectedRequestId = fixture.state.requests[0].id;
  return fixture.state.requests[0];
}
function checkedState(fixture) {
  const state = fixture.state;
  return plain(Object.fromEntries(Object.entries(state).filter(([key]) => key.startsWith('vm') || key.startsWith('lastValid') || key.startsWith('selectedVm'))));
}

export async function checkVmRequestLinkageUI(root = repository) {
  const create = await loadHarness(root);
  const base = create(), row = setNativeRow(base);
  assert(base.isBrokerEvent(row.events[0]));
  assert.equal(row.event.type, 'request_completed', 'Latest lifecycle event is deliberately not the native root');
  assert.deepEqual(plain(base.vmRequestSelection(base.state.requests, row.id)), A);
  assert(BigInt(A.request_id) > BigInt(Number.MAX_SAFE_INTEGER));
  assert(BigInt(A.root_event.sequence_number) > BigInt(Number.MAX_SAFE_INTEGER));

  const refusedRows = [
    ['CDP protocol ID', request => {request.protocolRequestId = 'raw';}],
    ['CDP operation marker', request => {request.operation = 'cdp_complete';}],
    ['demo row', request => {request.origin = 'demo';}],
    ['sample row', request => {request.origin = 'sample';}],
    ['bare ID', request => {delete request.events;}],
    ['latest event only', request => {request.events = [request.event];}],
    ['legacy root', request => {request.events[0].protocol_version = 1;}],
    ['foreign category', request => {request.events[0].category = 'runtime';}],
    ['duplicate identical root', request => {request.events.push(copy(request.events[0]));}],
    ['conflicting root', request => {request.events.push(nativeEvent(B));}],
    ['missing request ID', request => {delete request.events[0].request_id;}],
    ['missing session', request => {delete request.events[0].session_id;}],
    ['missing process', request => {delete request.events[0].process_id;}],
    ['missing sequence', request => {delete request.events[0].sequence_number;}]
  ];
  for (const [label, mutate] of refusedRows) {
    const request = copy(row); mutate(request);
    assert.equal(base.vmRequestSelection([request], request.id), null, label);
  }
  assert.equal(base.vmRequestSelection([row, copy(row)], row.id), null, 'Duplicate retained row IDs are ambiguous');
  assert.equal(base.vmRequestSelection([row], 'missing'), null);
  for (const field of ['request_id', 'session_id', 'sequence_number']) {
    for (const value of ['0', '01', '-1', '1e3', '18446744073709551616', 9007199254740992, null]) {
      const request = copy(row); request.events[0][field] = value;
      assert.equal(base.vmRequestSelection([request], request.id), null, `${field}=${value}`);
    }
  }
  for (const value of [0, -1, 1.5, '42', 4294967296, null]) {
    const request = copy(row); request.events[0].process_id = value;
    assert.equal(base.vmRequestSelection([request], request.id), null, `process=${value}`);
  }
  for (const variant of [B, selection({root_event: {...A.root_event, session_id: '9007199254740994'}}),
    selection({root_event: {...A.root_event, sequence_number: '9007199254740994'}}), selection({request_id: '9007199254740993'})]) {
    assert.notEqual(base.vmRequestSelectionKey(A), base.vmRequestSelectionKey(variant), 'Every full-scope component contributes to identity');
    const doc = analysisDocument(variant);
    assert(base.isVmAnalysisDocument(doc));
    assert(!base.vmAnalysisMatchesSelection(doc, A), 'Structurally valid foreign scope cannot authenticate the selected request');
  }
  const collisions = base.requestsFromEvents([nativeEvent(A), nativeEvent(B), nativeEvent(selection({root_event: {...A.root_event, session_id: '9007199254740994'}}))]);
  assert.equal(collisions.length, 3);
  assert.equal(new Set(collisions.map(request => base.vmRequestSelectionKey(base.vmRequestSelection(collisions, request.id)))).size, 3);

  const valid = analysisDocument();
  assert(base.isVmAnalysisDocument(valid)); assert(base.vmAnalysisMatchesSelection(valid, A));
  for (const [label, mutate] of [
    ['missing exact links', doc => {delete doc.results[0].exact_request_links;}],
    ['empty exact links', doc => {doc.results[0].exact_request_links = [];}],
    ['missing hash', doc => {delete doc.results[0].artifact_sha256;}],
    ['wrong request', doc => {doc.results[0].exact_request_links[0].request_id = '99';}],
    ['wrong root', doc => {doc.results[0].exact_request_links[0] = linkFor(B);}],
    ['unfiltered document', doc => {delete doc.selection;}],
    ['mixed constituent', doc => {doc.mixed_findings = [{finding_id: 'a'.repeat(24), runtime: 'mixed', tier: 'candidate', artifact_ids: ['101', '102']}];}]
  ]) {
    const doc = copy(valid); mutate(doc);
    assert(!base.vmAnalysisMatchesSelection(doc, A), label);
  }
  for (const [label, mutate] of [
    ['duplicate links', doc => {doc.results[0].exact_request_links.push(copy(doc.results[0].exact_request_links[0]));}],
    ['conflicting links', doc => {doc.results[0].exact_request_links.push(linkFor(B));}],
    ['wrong response process', doc => {doc.results[0].exact_request_links[0].response_event.process_id++;}],
    ['wrong capture session', doc => {doc.results[0].exact_request_links[0].capture_event.session_id = '9';}],
    ['response at root', doc => {doc.results[0].exact_request_links[0].response_event.sequence_number = A.root_event.sequence_number;}],
    ['capture before response', doc => {doc.results[0].exact_request_links[0].capture_event.sequence_number = A.root_event.sequence_number;}],
    ['incomplete chain', doc => {delete doc.results[0].exact_request_links[0].capture_event;}],
    ['extra chain metadata', doc => {doc.results[0].exact_request_links[0].extra = 'uncertain';}],
    ['correlated relation', doc => {doc.results[0].exact_request_links[0].relation = 'correlated';}],
    ['malformed hash', doc => {doc.results[0].artifact_sha256 = 'not-a-digest';}]
  ]) {
    const doc = copy(valid); mutate(doc); assert(!base.isVmAnalysisDocument(doc), label);
  }

  // Invoke the actual Related VM click handler and renderer, including refusal.
  const f = create(); setNativeRow(f);
  const artifact = {artifact_id: '101', session_id: A.root_event.session_id, sha256: digest('a'), byte_size: 123};
  f.state.artifacts = [artifact];
  f.state.eventVmFindings = [{...f.vmFindingsFromAnalysis(analysisDocument(null, '999'))[0], findingId: 'session-only'}];
  const held = deferred(); f.reply = () => held.promise;
  const clicking = f.elements.requestVmCandidates.click();
  assert.equal(f.screen, 'vm', 'Native pivot navigates synchronously, before HTTP settles');
  assert.equal(f.state.vmFindings.length, 0, 'Session findings disappear as soon as exact selection starts');
  assert.match(f.elements.vmNotice.textContent, /Loading candidates.*exact/);
  await Promise.resolve();
  const queried = new URL(f.calls[0].url, 'http://localhost');
  assert.deepEqual(Object.fromEntries(queried.searchParams), {request_id: A.request_id, session_id: A.root_event.session_id,
    root_process_id: '42', root_sequence_number: A.root_event.sequence_number});
  assert.equal(f.calls[0].options.headers['If-None-Match'], undefined);
  f.showScreen('sources', f.nav);
  held.resolve(response(valid)); await clicking;
  assert.equal(f.screen, 'sources', 'Late VM completion cannot reopen a pane after newer navigation');
  assert.equal(f.state.vmFindings.length, 1); assert.equal(f.state.vmFindings[0].sourceArtifactId, '101');
  assert.match(f.elements.vmNotice.textContent, /Exact captured response body/);
  assert.equal(f.state.selectedVmFindingId, f.state.vmFindings[0].findingId);
  assert(sourceButton(f)); sourceButton(f).click();
  assert.deepEqual(plain(f.sourceSelections), [['101', null, {identity: {type: 'captured-artifact', session: artifact.session_id,
    artifact: '101', sha256: artifact.sha256, bytes: artifact.byte_size}}]]);
  for (const badArtifacts of [[], [{...artifact, session_id: '99'}], [{...artifact, sha256: digest('b')}],
    [artifact, copy(artifact)], [artifact, {...artifact, session_id: '99', sha256: digest('b')}], [{...artifact, artifact_id: '102'}]]) {
    f.state.artifacts = badArtifacts; f.renderVmDetail();
    assert.equal(sourceButton(f), undefined, 'Missing/foreign/ambiguous source artifacts cannot offer Open in Sources');
  }
  f.state.artifacts = [artifact];
  const finding = f.state.vmFindings[0];
  const workspace = {interpreter_artifact_id: '101', source_artifact_sha256: digest('a'), finding_id: finding.analysis.finding_id};
  assert.equal(f.vmOpcodeWorkspaceForFinding({workspaces: [workspace]}, finding), workspace);
  for (const workspaces of [[], [{...workspace, interpreter_artifact_id: '102'}], [{...workspace, source_artifact_sha256: digest('b')}],
    [{...workspace, finding_id: 'b'.repeat(24)}], [workspace, copy(workspace)]]) {
    assert.equal(f.vmOpcodeWorkspaceForFinding({workspaces}, finding), null, 'Workspace requires unique artifact + hash + finding identity');
  }
  assert.equal(f.vmOpcodeWorkspaceForFinding({workspaces: [workspace]}, {...finding, sourceArtifactId: '102'}), null);
  const repeatedFinding = analysisDocument();
  repeatedFinding.results.push({...copy(repeatedFinding.results[0]), artifact_id: '102'});
  const distinctFindings = f.vmFindingsFromAnalysis(repeatedFinding);
  assert.equal(new Set(distinctFindings.map(item => item.findingId)).size, 2, 'Identical source findings on different artifacts keep distinct UI row identities');
  assert.equal(f.vmOpcodeWorkspaceForFinding({workspaces: [workspace]}, distinctFindings[1]), null, 'Identical finding/hash on another artifact is not this source workspace');

  f.reply = () => response(analysisDocument(null));
  f.showScreen('vm', f.nav); await f.settle();
  // Host/opcode await chains can outlive the fetch promise itself.
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.vmAnalysisSelection, null, 'Explicit VM navigation is still session-wide');
  assert(f.state.vmFindings.some(item => item.findingId === 'session-only'));
  assert.equal(f.calls.at(-1).url, '/api/analysis/vm');
  const beforeCalls = f.calls.length;
  for (const mutate of [request => {request.protocolRequestId = 'cdp-id';}, request => {request.operation = 'cdp_complete';}, request => {delete request.events;}]) {
    setNativeRow(f); mutate(f.state.requests[0]); f.showScreen('traffic', f.nav);
    await f.elements.requestVmCandidates.click();
    assert.equal(f.screen, 'traffic'); assert.equal(f.calls.length, beforeCalls);
    assert.match(f.notices.at(-1)[0], /Unlinked:.*unique retained native request start/);
    assert.match(f.notices.at(-1)[0], /VM navigation separately/);
  }

  // A DevTools join carries the native events, but the renderer id is not the
  // browser request_started id. Exact selection uses that start only.
  {
    const native = setNativeRow(f);
    const initiated = nativeEvent(A, {type: 'request_initiated', request_id: '345', sequence_number: '9'});
    const started = native.events.find(event => event.type === 'request_started');
    const joined = {
      id: 'cdp-joined', origin: 'live', protocolRequestId: '12.345', operation: 'cdp_complete',
      nativeLink: {kind: 'devtools-request-id', nativeRequestId: native.id, requestId: '345'},
      events: [initiated, started]
    };
    f.state.requests = [joined];
    f.state.selectedRequestId = joined.id;
    assert.deepEqual(plain(f.vmRequestSelection(f.state.requests, joined.id)), A);
    assert.notEqual(f.vmRequestSelection(f.state.requests, joined.id).request_id, '345');
    f.showScreen('traffic', f.nav);
    const callsBeforeJoin = f.calls.length;
    await f.elements.requestVmCandidates.click();
    assert.equal(f.screen, 'vm');
    const queried = new URL(f.calls.at(-1).url, 'http://localhost');
    assert.equal(queried.searchParams.get('request_id'), A.request_id);
    assert.equal(queried.searchParams.get('session_id'), A.root_event.session_id);
    assert.equal(queried.searchParams.get('root_process_id'), String(A.root_event.process_id));
    assert.equal(queried.searchParams.get('root_sequence_number'), A.root_event.sequence_number);
    assert.match(f.notices.at(-1)[0], /DevTools request id/);
    assert.match(f.notices.at(-1)[0], /joined native start/);
    assert.equal(f.notices.at(-1)[1], 'ready');
    for (const [label, events, link] of [
      ['missing initiated event', [started], joined.nativeLink],
      ['renderer id only', [initiated], joined.nativeLink],
      ['duplicate initiated events', [initiated, copy(initiated), started], joined.nativeLink],
      ['mismatched renderer id', [initiated, started], {...joined.nativeLink, requestId: '346'}],
      ['correlation without a join', [initiated, started], null]
    ]) {
      joined.events = events;
      joined.nativeLink = link;
      f.showScreen('traffic', f.nav);
      await f.elements.requestVmCandidates.click();
      assert.equal(f.screen, 'traffic', label);
      assert.equal(f.calls.length, callsBeforeJoin + 1, label);
      assert.equal(f.notices.at(-1)[1], 'unavailable', label);
    }
  }

  await checkCacheAndRaces(create);
  console.log('PASS exact Traffic→VM production models, click/navigation, finding/source DOM adapter, full-scope identity, cache and stale async isolation (not rendered browser QA)');
  return {create};
}

async function checkCacheAndRaces(create) {
  const f = create();
  await f.refreshVmAnalysis(A);
  const previous = f.state.vmAnalysisDocument;
  f.reply = () => response(null, 304);
  await f.refreshVmAnalysis(copy(A));
  assert.equal(f.state.vmAnalysisDocument, previous);
  assert.equal(f.calls.at(-1).options.headers['If-None-Match'], 'analysis-a');
  assert.equal(f.state.vmAnalysisStatus, 'ready');
  f.reply = () => response(null, 304); await f.refreshVmAnalysis(B);
  assert.equal(f.state.vmAnalysisStatus, 'malformed', '304 cannot authenticate another exact selection');
  assert.equal(f.state.vmAnalysisDocument, null); assert.equal(f.state.vmFindings.length, 0);
  assert.equal(f.calls.at(-1).options.headers['If-None-Match'], undefined);
  for (const invalid of ['7', {request_id: '7'}, {...A, root_event: {...A.root_event, process_id: 0}}]) {
    const before = checkedState(f), calls = f.calls.length;
    await f.refreshVmAnalysis(invalid); assert.deepEqual(checkedState(f), before); assert.equal(f.calls.length, calls);
  }

  for (const outcome of ['http', 'fetch', 'json', 'malformed', 'foreign']) {
    const current = create(); current.reply = () => response(analysisDocument(B, '102', 'b'), 200, 'etag-b');
    await current.refreshVmAnalysis(B);
    const previousDoc = current.state.vmAnalysisDocument, previousFindings = current.state.vmFindings;
    current.reply = () => outcome === 'fetch' ? Promise.reject(new Error('disconnected'))
      : outcome === 'json' ? {...response(null), json: async () => {throw new SyntaxError('broken JSON');}}
        : outcome === 'http' ? response(null, 503)
          : response(outcome === 'foreign' ? analysisDocument(selection({root_event: {...A.root_event, process_id: 44}})) : {});
    await current.refreshVmAnalysis(copy(B));
    assert.equal(current.state.vmAnalysisDocument, previousDoc, `Same-selection ${outcome} retains its validated document`);
    assert.deepEqual(plain(current.state.vmFindings), plain(previousFindings));
    assert(['malformed', 'unavailable'].includes(current.state.vmAnalysisStatus));
    await current.refreshVmAnalysis(A);
    assert.equal(current.state.vmAnalysisDocument, null);
    assert.equal(current.state.vmFindings.length, 0, 'Failed new selection never retains another request findings');
  }

  for (const phase of ['headers', 'json', 'opcode-headers', 'opcode-json', 'host-headers', 'host-json']) {
    for (const outcome of ['success', 'reject', 'http']) {
      const current = create(), held = deferred(), reached = deferred();
      const oldAnalysis = analysisDocument(A);
      if (phase.startsWith('opcode') || phase.startsWith('host')) delete oldAnalysis.opcode_workspace;
      current.reply = url => {
        if (url.includes('/host-links')) {
          if (phase === 'host-headers') {reached.resolve(); return held.promise;}
          return {...response(null), json: () => {reached.resolve(); return held.promise;}};
        }
        if (url.includes('/opcodes')) {
          if (phase.startsWith('host')) return response(opcodeDocument());
          if (phase === 'opcode-headers') {reached.resolve(); return held.promise;}
          return {...response(null), json: () => {reached.resolve(); return held.promise;}};
        }
        if (phase === 'headers') {reached.resolve(); return held.promise;}
        if (phase === 'json') return {...response(null), json: () => {reached.resolve(); return held.promise;}};
        return response(oldAnalysis);
      };
      const stale = current.refreshVmAnalysis(A); await reached.promise;
      current.reply = () => response(analysisDocument(B, '102', 'b'), 200, 'etag-b');
      await current.refreshVmAnalysis(B);
      const expected = checkedState(current), calls = current.calls.length;
      const oldBody = phase.startsWith('opcode') ? opcodeDocument('a') : phase.startsWith('host') ? hostDocument() : oldAnalysis;
      if (outcome === 'reject') held.reject(new Error('late transport/JSON failure'));
      else if (phase.endsWith('json')) held.resolve(outcome === 'http' ? {} : oldBody);
      else held.resolve(response(oldBody, outcome === 'http' ? 503 : 200, 'stale-etag'));
      await stale;
      assert.deepEqual(checkedState(current), expected, `${phase}/${outcome} cannot pollute new selection data, errors, ETags, opcode cache or host ownership`);
      assert.equal(current.calls.length, calls, 'A stale stage cannot initiate later opcode/host requests');
    }
  }
  // Same identity with a newer generation must also own the latest result.
  {
    const current = create(), held = deferred(); current.reply = () => held.promise;
    const stale = current.refreshVmAnalysis(A); await Promise.resolve();
    current.reply = () => response(analysisDocument(A, '103', 'c'), 200, 'new-generation');
    await current.refreshVmAnalysis(copy(A)); const expected = checkedState(current);
    held.resolve(response(analysisDocument(A), 200, 'old-generation')); await stale;
    assert.deepEqual(checkedState(current), expected);
  }
  // Changing only root scope invalidates both analysis and opcode caches even
  // when the browser has reused the same request number.
  for (const selected of [B, selection({root_event: {...A.root_event, session_id: '9007199254740994'}}),
    selection({root_event: {...A.root_event, sequence_number: '9007199254740994'}})]) {
    const current = create(); await current.refreshVmAnalysis(A);
    const held = deferred(); current.reply = () => held.promise;
    const pending = current.refreshVmAnalysis(selected);
    assert.equal(current.state.vmAnalysisEtag, null); assert.equal(current.state.vmOpcodeWorkspaceEtag, null);
    assert.equal(current.state.vmOpcodeWorkspace, null); assert.equal(current.state.vmHostLinks, null);
    assert.equal(current.state.selectedVmFindingId, null); assert.equal(current.state.vmFindings.length, 0);
    held.resolve(response(analysisDocument(selected, '102', 'b'), 200, 'fresh')); await pending;
    assert.equal(current.calls.at(-1).options.headers['If-None-Match'], undefined);
  }
}

export async function checkVmRequestLinkagePipeline(root = repository, options = {}) {
  const pipeline = options.pipeline ?? process.env.REB_VM_LINKAGE_PIPELINE;
  const binary = options.backend ?? process.env.REB_VM_LINKAGE_BACKEND;
  assert(pipeline && binary, '--pipeline requires REB_VM_LINKAGE_PIPELINE (manifest path/directory) and REB_VM_LINKAGE_BACKEND (built backend binary)');
  const pipelinePath = resolve(pipeline);
  const manifestPath = (await stat(pipelinePath)).isDirectory() ? join(pipelinePath, 'manifest.json') : pipelinePath;
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  assert(typeof manifest.session_dir === 'string' && Array.isArray(manifest.cases), 'Native pipeline manifest must supply session_dir and cases');
  const create = await loadHarness(root), dir = await mkdtemp(join(tmpdir(), 'reb-vm-linkage-http-'));
  const endpoint = join(dir, 'endpoint');
  const args = ['--port', '0', '--store', join(manifest.session_dir, 'events.jsonl'),
    '--trace-store', join(manifest.session_dir, 'origin-trace.jsonl'), '--signal-store', join(manifest.session_dir, 'request-signals.jsonl'),
    '--artifacts', join(manifest.session_dir, 'artifacts'), '--endpoint-file', endpoint,
    '--api-collection', join(dir, 'collection.json'), '--local-analyst', join(dir, 'analyst.json')];
  const child = spawn(resolve(binary), args, {stdio: ['ignore', 'pipe', 'pipe']});
  let output = '', spawnError;
  child.stdout.on('data', chunk => {output += chunk;}); child.stderr.on('data', chunk => {output += chunk;});
  child.on('error', error => {spawnError = error;});
  try {
    let base;
    for (let attempt = 0; attempt < 300; attempt++) {
      if (spawnError) throw spawnError;
      assert(child.exitCode === null, `Production HTTP backend exited ${child.exitCode}: ${output}`);
      try {base = (await readFile(endpoint, 'utf8')).trim(); break;} catch (error) {if (error.code !== 'ENOENT') throw error;}
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert(base, `Production HTTP endpoint not published: ${output}`);
    assert.match(base, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
    const f = create();
    f.reply = (url, options) => fetch(new URL(url, base), options);
    const eventsResponse = await fetch(`${base}/api/events?limit=5000`), artifactResponse = await fetch(`${base}/api/artifacts?limit=500`);
    assert.equal(eventsResponse.status, 200); assert.equal(artifactResponse.status, 200);
    const events = await eventsResponse.json(), artifacts = await artifactResponse.json();
    assert(f.isBrokerResponse(events), 'Actual broker corpus must pass shipped UI response validation');
    assert(f.isArtifactResponse(artifacts), 'Actual receiver catalog must pass shipped UI response validation');
    f.state.requests = f.requestsFromEvents(events.network_events ?? events.events, 'live');
    f.state.artifacts = artifacts.artifacts;
    const positives = manifest.cases.filter(item => item.expected_artifact_ids.length > 0);
    const negatives = manifest.cases.filter(item => item.expected_artifact_ids.length === 0);
    assert(positives.length >= 2 && negatives.length >= 1, 'Pipeline requires distinct positive artifacts and an unlinked actual native request');
    for (const item of [...positives, ...negatives]) {
      const rows = f.state.requests.filter(request => f.vmRequestSelectionKey(f.vmRequestSelection(f.state.requests, request.id)) === f.vmRequestSelectionKey(item.selection));
      assert.equal(rows.length, 1, `${item.name}: unique actual native request row; retained roots: ${JSON.stringify(f.state.requests.map(request => ({id: request.id, roots: request.events.filter(event => event.type === 'request_started').length})))}`);
      f.state.selectedRequestId = rows[0].id;
      await f.elements.requestVmCandidates.click();
      assert.equal(f.screen, 'vm'); assert.equal(f.state.vmAnalysisStatus, 'ready', `${item.name}: ${f.state.vmAnalysisError}`);
      assert.deepEqual(plain(f.state.vmAnalysisDocument.results.map(result => result.artifact_id).sort()), [...item.expected_artifact_ids].sort(), item.name);
      assert.deepEqual(plain(f.state.vmAnalysisSelection), item.selection);
      assert.equal(f.state.vmAnalysisDocument.mixed_findings.length, 0);
      // The opcode endpoint is a shared session document. Visible selection,
      // rather than that cache, must resolve only the selected finding's source.
      assert.equal(f.state.vmOpcodeWorkspaceStatus, 'ready', `${item.name}: opcode document is ready`);
      assert(f.isVmOpcodeWorkspaceDocument(f.state.vmOpcodeWorkspace));
      if (item.expected_artifact_ids.length) {
        assert(f.state.vmFindings.length > 0, `${item.name}: actual analyzed candidate finding required`);
        const finding = f.state.vmFindings.find(value => value.findingId === f.state.selectedVmFindingId);
        assert(item.expected_artifact_ids.includes(finding.sourceArtifactId));
        const artifact = f.vmSourceArtifactForFinding(f.state.artifacts, finding, item.selection);
        assert(artifact, `${item.name}: exact retained source ID/session/hash`);
        assert.equal(artifact.sha256, finding.analysis.artifact_sha256);
        assert(sourceButton(f), `${item.name}: actual finding renderer offers exact source navigation`);
        sourceButton(f).click();
        assert.equal(f.sourceSelections.at(-1)[0], finding.sourceArtifactId);
        assert.equal(f.sourceSelections.at(-1)[2].identity.sha256, artifact.sha256);
        const workspace = f.vmOpcodeWorkspaceForFinding(f.state.vmOpcodeWorkspace, finding);
        assert(workspace, `${item.name}: selected finding resolves its exact native-source opcode workspace`);
        assert.equal(workspace.interpreter_artifact_id, finding.sourceArtifactId);
        assert.equal(workspace.source_artifact_sha256, finding.analysis.artifact_sha256);
        assert.equal(workspace.finding_id, finding.analysis.finding_id);
      } else {
        assert.equal(f.state.vmFindings.length, 0);
        assert.match(f.elements.vmNotice.textContent, /No VM candidates are linked/);
        assert.equal(sourceButton(f), undefined);
        assert.equal(f.state.selectedVmFindingId, null);
        assert.equal(f.vmOpcodeWorkspaceForFinding(f.state.vmOpcodeWorkspace, null), null);
        assert.match(f.elements.vmDetail.textContent, /No valid VM findings/);
      }
    }
    await f.refreshVmAnalysis(null);
    assert.equal(f.state.vmAnalysisStatus, 'ready');
    const ids = new Set(f.state.vmAnalysisDocument.results.map(result => result.artifact_id));
    assert(ids.size > positives[0].expected_artifact_ids.length, 'Unfiltered session is broader than the exact request');
    for (const item of positives) for (const id of item.expected_artifact_ids) assert(ids.has(id));
    assert(f.state.requests.some(request => request.events.some(event => event.type === 'request_started' && BigInt(event.sequence_number) > BigInt(Number.MAX_SAFE_INTEGER))), 'Actual emitted native root exercises lossless uint64');
    console.log(`PASS actual native corpus → broker/receiver → production HTTP → shipped Traffic/VM controller and source model (${positives.length} positive, ${negatives.length} unlinked cases; not rendered browser QA)`);
  } finally {
    if (child.exitCode === null && !spawnError) {
      const stopped = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM');
      const kill = setTimeout(() => child.kill('SIGKILL'), 5000); kill.unref();
      await stopped; clearTimeout(kill);
    }
    await rm(dir, {recursive: true, force: true});
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const pipeline = process.argv.includes('--pipeline');
  const root = process.argv.slice(2).find(value => value !== '--pipeline') ?? repository;
  await checkVmRequestLinkageUI(root);
  if (pipeline) await checkVmRequestLinkagePipeline(root);
}
