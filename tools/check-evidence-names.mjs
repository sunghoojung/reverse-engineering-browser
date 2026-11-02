// Researcher names (docs/product/evidence-names-v1.md). Every case runs the shipped
// evidence_names.js and app.js wiring with the real identity helpers; only the
// DOM and HTTP transport are substituted. This is not rendered QA.
import assert from 'node:assert/strict';
import {readFile, mkdtemp, stat, rm} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runInNewContext} from 'node:vm';

const copy = value => JSON.parse(JSON.stringify(value));
const settle = () => new Promise(resolve => setTimeout(resolve, 0));
const sha = digit => digit.repeat(64);

export async function namesModels(root, overrides = {}, extra = '', exports = '') {
  const read = path => readFile(join(root, path), 'utf8');
  const app = await read('apps/research-ui/app.js'), state = await read('apps/research-ui/app_state.js');
  const section = (start, end) => {const from = app.indexOf(start), to = app.indexOf(end, from + 1); assert(from >= 0 && to > from, `Missing app boundary ${start}`); return app.slice(from, to);};
  const empty = state.slice(state.indexOf('      const emptyLocalAnalystWorkspace'), state.indexOf('      const emptyDecoderEngine'));
  const context = {console, TextEncoder, TextDecoder, Uint8Array, Response, AbortController, setTimeout, clearTimeout, structuredClone, Event,
    CustomEvent: class extends Event {constructor(type, init) {super(type); this.detail = init?.detail;}}, ...overrides};
  context.globalThis = context;
  return runInNewContext([await read('apps/research-ui/evidence_models.js'), empty, section('      const analystExactKeys', '      function isLocalAnalystRunner'),
    section('      function requestTraceRoot(', '      function requestSignalProfileSelection('),
    await read('apps/research-ui/evidence_package.js'), await read('apps/research-ui/investigation_navigation.js'),
    await read('apps/research-ui/investigation_notebook.js'), await read('apps/research-ui/evidence_names.js'), extra,
    `;({api: RebEvidenceNames, emptyLibrary: emptyLocalAnalystWorkspace, validateLibrary: isLocalAnalystWorkspace, requestRootEvent, global: globalThis${exports}})`].join('\n'), context);
}

// Authored retained records. Labels deliberately repeat across identities.
const requestOf = (id, {origin = 'demo', session = '1', process = 10, sequence = '6', request = '81', path = 'https://collector.example.test/mint'} = {}) => ({
  id, origin, method: 'POST', path, events: [{type: 'request_started', session_id: session, process_id: process, sequence_number: sequence, request_id: request}]});
const artifactOf = (id, {session = '1', digit = 'a', bytes = 488, url = 'https://checkout.acme.test/assets/loader.js', kind = 'javascript'} = {}) => ({
  artifact_id: id, session_id: session, sha256: sha(digit), byte_size: bytes, url, kind});
const workspaceOf = ({finding = 'c5e529342af22aafd3d7ddbc', artifact = '302', digit = 'a', offsets = [213, 247]} = {}) => ({
  finding_id: finding, interpreter_artifact_id: artifact, source_artifact_sha256: sha(digit), runtime: 'javascript', samples: [],
  handlers: offsets.map((offset, opcode) => ({opcode, handler_index: null, label: '', state: 'inferred', sample_count: 0, operand_width: 0, notes: '', source: {byte_offset: offset, byte_size: 34}}))});

function libraryOf(emptyLibrary, files = []) {
  const library = copy(emptyLibrary()); library.generation = 1; library.updated_at_ms = 1000;
  library.files = files.map((file, index) => ({id: index + 1, folder_id: 1, kind: 'scratchpad', language: 'text', created_at_ms: 1000, updated_at_ms: 1000, ...file,
    content_bytes: Buffer.byteLength(file.content)}));
  return library;
}
// The local route's replace semantics: one whole-library generation, refused
// with HTTP 409 when the expected generation is stale.
function storeServer(initial) {
  const server = {library: initial, calls: [], mode: 'ready', hold: null};
  server.fetcher = async (url, options = {}) => {
    server.calls.push({url, method: options.method ?? 'GET'});
    if (server.hold) await server.hold;
    if (options.method !== 'POST') return Response.json(server.library);
    const request = JSON.parse(options.body);
    assert.equal(request.action, 'replace_local_analyst_workspace');
    if (request.expected_generation !== server.library.generation || server.mode === 'conflict') return Response.json({error: 'stale'}, {status: 409});
    const before = server.library;
    server.library = {...copy(before), generation: before.generation + 1, updated_at_ms: before.updated_at_ms + 1, folders: copy(request.folders),
      files: request.files.map(file => ({...file, content_bytes: Buffer.byteLength(file.content),
        created_at_ms: before.files.find(old => old.id === file.id)?.created_at_ms ?? before.updated_at_ms + 1, updated_at_ms: before.updated_at_ms + 1}))};
    if (server.mode === 'lost-receipt') return new Response('{"truncated":', {status: 200});
    return Response.json(server.library);
  };
  return server;
}

export async function checkNamesCore(root) {
  const {api, requestRootEvent} = await namesModels(root);
  const {LIMITS} = api;
  assert(api.validate(api.empty()));
  // Names are plain single-line text; an empty input clears.
  assert.deepEqual(copy(api.normalizeName('  push_const  ')), {name: 'push_const'});
  assert.deepEqual(copy(api.normalizeName('   ')), {name: ''});
  assert.equal(api.normalizeName('𝒜'.repeat(LIMITS.characters)).name.length, 2 * LIMITS.characters, 'The bound counts characters, not UTF-16 units');
  for (const hostile of ['x'.repeat(LIMITS.characters + 1), 'a\tb', 'a‮b', 'a​b', 'a b', 'a\x7fb', '\ud800'])
    assert(api.normalizeName(hostile).error, `refused: ${JSON.stringify(hostile)}`);

  // Requests: exact root identity plus origin; a shared label never matches.
  const named = requestOf('row-1'), sameLabel = requestOf('row-2', {sequence: '7', request: '82'});
  const requestId = request => api.requestIdentity(request, requestRootEvent(request));
  const identity = requestId(named);
  assert.deepEqual(copy(identity), {type: 'captured-request', origin: 'demo', session: '1', process: '10', sequence: '6', request: '81'});
  assert.equal(named.path, sameLabel.path);
  let doc = api.apply(api.empty(), identity, 'session token mint');
  assert(api.validate(doc));
  const names = new Map([...api.index(doc)]);
  const nameOf = value => names.get(api.keyOf(value)) ?? null;
  let resolve = api.resolver([named, sameLabel], requestId, nameOf, request => request.id);
  assert.equal(resolve.name(named), 'session token mint');
  assert.equal(resolve.name(sameLabel), null, 'Same URL and method, different identity: no name');
  const live = requestOf('row-3', {origin: 'live'});
  assert.equal(api.resolver([live], requestId, nameOf).name(live), null, 'A demo identity never names a live request with the same numbers');
  resolve = api.resolver([named, {...requestOf('row-4')}], requestId, nameOf, request => request.id);
  assert.equal(resolve.name(named), null, 'Two retained rows with one identity are ambiguous');
  resolve = api.resolver([named, {...sameLabel, id: 'row-1'}], requestId, nameOf, request => request.id);
  assert.equal(resolve.name(named), null, 'A shared row ID cannot be opened exactly');
  assert.equal(requestId({...named, events: []}), null);
  assert.equal(requestId(requestOf('row-5', {request: '0'})), null);

  // Artifacts: session, ID, SHA-256 and size. Same file name and URL with other
  // bytes is a different artifact; a reused ID across sessions is ambiguous.
  const loader = artifactOf('302'), rebuilt = artifactOf('303', {digit: 'b'});
  doc = api.apply(doc, api.artifactIdentity(loader), 'obfuscated loader');
  names.clear(); for (const [key, value] of api.index(doc)) names.set(key, value);
  resolve = api.resolver([loader, rebuilt], api.artifactIdentity, nameOf, artifact => artifact.artifact_id);
  assert.equal(resolve.name(loader), 'obfuscated loader'); assert.equal(resolve.name(rebuilt), null);
  assert.equal(api.resolver([{...loader, sha256: sha('c')}], api.artifactIdentity, nameOf).name({...loader, sha256: sha('c')}), null, 'Changed bytes lose the name');
  resolve = api.resolver([loader, artifactOf('302', {session: '2'})], api.artifactIdentity, nameOf, artifact => artifact.artifact_id);
  assert.equal(resolve.name(loader), null, 'An artifact ID reused across sessions is ambiguous');

  // VM handlers: finding, source artifact identity, listing key and source range.
  const workspace = workspaceOf(), rows = workspace.handlers.map(handler => ({key: `${handler.opcode}:${handler.handler_index ?? ''}:${handler.source.byte_offset}`, label: 'handler',
    range: {start: handler.source.byte_offset, end: handler.source.byte_offset + handler.source.byte_size}}));
  const handlerId = (row, scope = workspace, artifact = loader) => api.handlerIdentity({workspace: scope, artifact, row});
  const pushConst = handlerId(rows[0]);
  assert.deepEqual(copy(pushConst), {type: 'vm-handler', finding: workspace.finding_id, session: '1', artifact: '302', sha256: sha('a'), bytes: 488, handler: '0::213', start: 213, end: 247});
  doc = api.apply(doc, pushConst, 'push_const');
  names.clear(); for (const [key, value] of api.index(doc)) names.set(key, value);
  assert.equal(nameOf(pushConst), 'push_const');
  assert.equal(nameOf(handlerId(rows[1])), null);
  const otherFinding = workspaceOf({finding: 'aaaaaaaaaaaaaaaaaaaaaaaa'});
  assert.equal(nameOf(handlerId(rows[0], otherFinding)), null, 'Same handler label and key in another finding: no name');
  assert.equal(nameOf(handlerId({...rows[0], range: {start: 213, end: 250}})), null, 'Another source range: no name');
  assert.equal(handlerId(rows[0], workspaceOf({digit: 'b'})), null, 'A workspace for other bytes cannot use this artifact');
  assert.equal(handlerId(rows[0], workspace, {...loader, artifact_id: '9'}), null);

  // Set, replace in place, clear by empty name; order of other entries is kept.
  const second = api.apply(doc, handlerId(rows[1]), 'load_local');
  assert.deepEqual(second.vm_programs[0].handlers.map(entry => entry.name), ['push_const', 'load_local']);
  const replaced = api.apply(second, pushConst, 'push_imm');
  assert.deepEqual(replaced.vm_programs[0].handlers.map(entry => entry.name), ['push_imm', 'load_local']);
  let cleared = api.apply(api.apply(replaced, pushConst, ''), handlerId(rows[1]), '');
  assert.deepEqual(cleared.vm_programs, [], 'Clearing the last handler removes its program group');
  cleared = api.apply(api.apply(cleared, identity, ''), api.artifactIdentity(loader), '');
  assert.deepEqual(copy(cleared), copy(api.empty()));

  // Closed document: unknown members, duplicates, malformed identities and names.
  for (const mutate of [d => {d.extra = true;}, d => {d.contract_version = 2;}, d => {d.requests.push(copy(d.requests[0]));},
    d => {d.requests[0].url = 'https://collector.example.test/';}, d => {d.requests[0].origin = 'sample';}, d => {d.requests[0].process = '4294967296';},
    d => {d.requests[0].session = '01';}, d => {d.artifacts[0].sha256 = 'A'.repeat(64);}, d => {d.artifacts[0].name = ' padded';},
    d => {d.artifacts[0].name = '';}, d => {d.vm_programs[0].handlers = [];}, d => {d.vm_programs.push(copy(d.vm_programs[0]));},
    d => {d.vm_programs[0].handlers[0].end = 213;}, d => {d.vm_programs[0].finding = 'not-a-finding';}, d => {d.vm_programs[0].handlers[0].name = '<b>‮</b>';}]) {
    const candidate = copy(doc); mutate(candidate); assert.equal(api.validate(candidate), false, mutate.toString());
  }
  // Exact bounds: the count, the program count and the Analyst file size.
  // Handler names share their program's identity, so the count bound is
  // reachable within 32 KiB there; request and source entries reach the byte bound first.
  const many = api.empty(), program = {finding: workspace.finding_id, session: '1', artifact: '302', sha256: sha('a'), bytes: 488, handlers: []};
  many.vm_programs.push(program);
  for (let index = 0; index < LIMITS.names; index++) program.handlers.push({handler: `${index}::${index * 8}`, start: index * 8, end: index * 8 + 4, name: 'n'});
  assert.equal(api.validate(many), true, `${LIMITS.names} names are admitted`);
  program.handlers.push({handler: '9999::99999', start: 99999, end: 100000, name: 'n'});
  assert.equal(api.validate(many), false, 'One more name is refused');
  const entry = (index, length) => ({session: '1', artifact: String(100000 + index), sha256: sha('a'), bytes: 488, name: 'x'.repeat(length)});
  const build = lengths => ({...api.empty(), artifacts: lengths.map((length, index) => entry(index, length))});
  const size = value => Buffer.byteLength(JSON.stringify(value));
  let count = 1;
  while (size(build(Array(count + 1).fill(LIMITS.characters))) <= LIMITS.bytes) count++;
  const lengths = Array(count + 1).fill(1);
  for (let index = 0, deficit = LIMITS.bytes - size(build(lengths)); deficit > 0; index++) {
    const grow = Math.min(deficit, LIMITS.characters - lengths[index]); lengths[index] += grow; deficit -= grow;
  }
  const exactFit = build(lengths);
  assert.equal(size(exactFit), LIMITS.bytes, 'Fixture reaches the byte bound exactly');
  assert.equal(api.validate(exactFit), true, 'A document of exactly 32 KiB is admitted');
  exactFit.artifacts.find(value => value.name.length < LIMITS.characters).name += 'z';
  assert.equal(api.validate(exactFit), false, 'One more byte is refused');

  // Discovery: suffix or valid content; ordinary JSON is never adopted by name.
  const file = (name, content, extra = {}) => ({name, content: typeof content === 'string' ? content : JSON.stringify(content), kind: 'scratchpad', language: 'json', ...extra});
  assert.equal(api.locate({files: []}).status, 'ready');
  assert.equal(api.locate({files: [file('Notes.json', {document_kind: 'something-else'})]}).file, null);
  assert.equal(api.locate({files: [file(api.FILE_NAME, '{"broken":')]}).status, 'malformed');
  assert.equal(api.locate({files: [file(api.FILE_NAME, doc), file('Copy.json', doc)]}).status, 'ambiguous');
  assert.equal(api.locate({files: [file('Script.js', doc, {kind: 'analyst-script', language: 'javascript'})]}).file, null, 'A script is never a names document');
  assert.equal(api.readDocument(file('x.reb-names.json', JSON.stringify(doc).replace('"requests"', '"requests":[],"r\\u0065quests"'))), null, 'Escaped duplicate members are refused');
  console.log('PASS evidence names: exact request/source/handler identities (same label, other identity gets no name; demo never names live), clear by empty, closed document and exact 500-name/32 KiB bounds, discovery (not rendered QA)');
}

export async function checkNamesStore(root) {
  const {api, emptyLibrary, validateLibrary} = await namesModels(root);
  const script = {name: 'Existing research script', kind: 'analyst-script', language: 'javascript', content: 'return "never run by names";'};
  const note = {name: 'Existing private note', content: 'Synthetic note\x7f stays unchanged.'};
  const server = storeServer(libraryOf(emptyLibrary, [script, note]));
  const originals = copy(server.library.files);
  const identity = {type: 'captured-artifact', session: '1', artifact: '302', sha256: sha('a'), bytes: 488};
  const handler = {type: 'vm-handler', finding: 'c5e529342af22aafd3d7ddbc', session: '1', artifact: '302', sha256: sha('a'), bytes: 488, handler: '0::213', start: 213, end: 247};
  let renamed = 0;
  const store = api.createStore({fetcher: server.fetcher, validateLibrary, timeout: 200, renamed: () => {renamed++;}});
  assert(await store.load());
  assert((await store.rename(identity, '  obfuscated loader ', '')).ok);
  const saved = server.library.files.find(file => file.name === api.FILE_NAME);
  assert.equal(saved.kind, 'scratchpad'); assert.equal(saved.language, 'json'); assert.equal(saved.folder_id, 1);
  assert.deepEqual(JSON.parse(saved.content).artifacts, [{session: '1', artifact: '302', sha256: sha('a'), bytes: 488, name: 'obfuscated loader'}]);
  assert.deepEqual(server.library.files.slice(0, 2).map(({updated_at_ms, ...file}) => file), originals.map(({updated_at_ms, ...file}) => file), 'Other library files are unchanged');
  assert(server.calls.every(call => ['/api/local-analyst', '/api/local-analyst/actions'].includes(call.url)), 'Only the existing Analyst routes are used');
  assert(renamed > 0);

  // Round trip through the analyst store shape: a fresh store reads it back.
  const reopened = api.createStore({fetcher: server.fetcher, validateLibrary});
  assert(await reopened.load()); assert.equal(reopened.nameOf(identity), 'obfuscated loader');

  // Another writer renames the same item after this editor opened: no silent
  // overwrite, and nothing is posted until the researcher confirms again.
  const other = api.createStore({fetcher: server.fetcher, validateLibrary});
  assert(await other.load()); assert((await other.rename(identity, 'stage-two loader', 'obfuscated loader')).ok);
  let posts = server.calls.filter(call => call.method === 'POST').length;
  const conflict = await store.rename(identity, 'my loader', 'obfuscated loader');
  assert.equal(conflict.ok, false); assert.equal(conflict.conflict, true); assert.equal(conflict.current, 'stage-two loader');
  assert.equal(server.calls.filter(call => call.method === 'POST').length, posts, 'A changed name is never overwritten silently');
  assert((await store.rename(identity, 'my loader', conflict.current)).ok, 'Confirming against the newer name writes it');

  // A newer generation with unrelated changes is reread, so those changes survive.
  assert((await other.rename(handler, 'push_const', '')).ok);
  server.library.files.push({id: 99, folder_id: 1, name: 'Added elsewhere', kind: 'scratchpad', language: 'text', content: 'kept', content_bytes: 4, created_at_ms: 1000, updated_at_ms: 1000});
  server.library.generation++;
  const kept = await store.rename(identity, 'final loader', 'my loader'); assert(kept.ok, kept.message);
  assert(server.library.files.some(file => file.id === 99), 'A file added by another writer is preserved');
  assert.equal(store.nameOf(handler), 'push_const', 'A name added by another writer is preserved');

  // A stale generation between read and write is refused by the store and is
  // not retried automatically.
  server.mode = 'conflict'; posts = server.calls.filter(call => call.method === 'POST').length;
  const stale = await store.rename(identity, 'stale loader', 'final loader');
  assert.equal(stale.ok, false); assert.match(stale.message, /Not saved/);
  assert.equal(server.calls.filter(call => call.method === 'POST').length, posts + 1, 'Exactly one refused POST, no automatic retry');
  assert.equal(JSON.parse(server.library.files.find(file => file.name === api.FILE_NAME).content).artifacts[0].name, 'final loader');
  server.mode = 'ready';

  // A committed write whose receipt is lost stays unconfirmed; the next attempt
  // rereads first and finds it saved without writing twice.
  server.mode = 'lost-receipt';
  const lost = await store.rename(identity, 'committed loader', 'final loader');
  assert.equal(lost.ok, false); assert.match(lost.message, /could not be confirmed/);
  server.mode = 'ready'; posts = server.calls.filter(call => call.method === 'POST').length;
  const confirmed = await store.rename(identity, 'committed loader', 'final loader');
  assert(confirmed.ok && confirmed.unchanged); assert.equal(server.calls.filter(call => call.method === 'POST').length, posts);

  // Clear by empty name removes only that entry.
  assert((await store.rename(identity, '', 'committed loader')).ok);
  assert.equal(store.nameOf(identity), null); assert.equal(store.nameOf(handler), 'push_const');
  assert.deepEqual(JSON.parse(server.library.files.find(file => file.name === api.FILE_NAME).content).artifacts, []);

  // Refusals before any POST: invalid names, a full library, a malformed or
  // duplicated names document, and an over-limit names document.
  posts = server.calls.filter(call => call.method === 'POST').length;
  assert.match((await store.rename(identity, 'x'.repeat(81), '')).message, /at most 80/);
  const keep = server.library;
  server.library = libraryOf(emptyLibrary, Array.from({length: 64}, (_, index) => ({name: `Existing ${index}`, content: 'x'})));
  assert.match((await store.rename(identity, 'full', '')).message, /library is full/);
  server.library = libraryOf(emptyLibrary, [{name: api.FILE_NAME, language: 'json', content: '{"broken":'}]);
  assert.match((await store.rename(identity, 'x', '')).message, /malformed/);
  assert.equal(server.library.files[0].content, '{"broken":', 'A malformed names document is never overwritten');
  assert.equal(store.nameOf(handler), null, 'Malformed documents show no names');
  const fullDoc = api.empty(), program = {finding: handler.finding, session: '1', artifact: '302', sha256: sha('a'), bytes: 488, handlers: []};
  fullDoc.vm_programs.push(program);
  for (let index = 0; index < api.LIMITS.names; index++) program.handlers.push({handler: `${index}::${index * 8}`, start: index * 8, end: index * 8 + 4, name: 'n'});
  server.library = libraryOf(emptyLibrary, [{name: api.FILE_NAME, language: 'json', content: JSON.stringify(fullDoc)}]);
  assert.match((await store.rename(identity, 'one more', '')).message, /at most 500 names/);
  assert.equal(server.calls.filter(call => call.method === 'POST').length, posts, 'Every refusal happens before a POST');
  server.library = keep;

  // Analyst admits newer generations; older or equal ones are ignored.
  const observed = api.createStore({fetcher: server.fetcher, validateLibrary});
  assert(await observed.load());
  const newer = copy(server.library); newer.generation += 5;
  const doc = api.apply(api.empty(), identity, 'from analyst');
  newer.files = newer.files.map(file => file.name === api.FILE_NAME ? {...file, content: JSON.stringify(doc), content_bytes: Buffer.byteLength(JSON.stringify(doc))} : file);
  assert(observed.observe(newer)); assert.equal(observed.nameOf(identity), 'from analyst');
  assert.equal(observed.observe(copy(server.library)), false);

  // A stalled read releases the store at its deadline.
  let release; server.hold = new Promise(resolve => {release = resolve;});
  const slow = api.createStore({fetcher: server.fetcher, validateLibrary, timeout: 20});
  assert.equal(await slow.load(), false); assert.equal(slow.model.busy, false); assert.equal(slow.model.status, 'unavailable');
  release(); server.hold = null;
  console.log('PASS evidence names store: Analyst scratchpad round trip, unrelated files preserved, per-name conflict, stale generation refused once, lost receipt confirmed by reread, clear, refusals before POST, Analyst observation, deadline (not rendered QA)');
}

// Minimal DOM for the mounted controller. innerHTML is a trap: names must only
// ever reach the document as text.
function fakeDocument() {
  const document = {activeElement: null, created: [], readyState: 'loading', listeners: new Map(), hasFocus: () => true};
  class Node {
    constructor(tag) {
      this.tagName = tag.toUpperCase(); this.children = []; this.parentElement = null; this.dataset = {}; this.attributes = {}; this.listeners = new Map();
      this.hidden = false; this.disabled = false; this.readOnly = false; this.value = ''; this.text = ''; this.className = ''; document.created.push(this);
    }
    set innerHTML(_) {throw new Error('Names must never be parsed as HTML.');}
    set textContent(value) {this.text = String(value); this.children = [];}
    get textContent() {return this.text + this.children.map(child => child.textContent).join('');}
    get isConnected() {for (let node = this; node; node = node.parentElement) if (node === document.body) return true; return false;}
    append(...nodes) {for (const node of nodes) {node.remove?.(); node.parentElement = this; this.children.push(node);}}
    remove() {if (this.parentElement) this.parentElement.children = this.parentElement.children.filter(child => child !== this); this.parentElement = null;}
    setAttribute(key, value) {this.attributes[key] = String(value);}
    getAttribute(key) {return this.attributes[key] ?? null;}
    addEventListener(type, fn) {this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);}
    async fire(type, init = {}) {
      const event = {type, target: this, defaultPrevented: false, propagationStopped: false, preventDefault() {this.defaultPrevented = true;}, stopPropagation() {this.propagationStopped = true;}, ...init};
      for (let node = this; node && !event.propagationStopped; node = node.parentElement) for (const fn of node.listeners.get(type) ?? []) await fn(event);
      return event;
    }
    contains(node) {return node === this || this.children.some(child => child.contains?.(node));}
    get classList() {return {add: name => {this.className = `${this.className} ${name}`.trim();}, remove: name => {this.className = this.className.split(/\s+/).filter(value => value !== name).join(' ');}};}
    replaceChildren(...nodes) {this.text = ''; for (const child of this.children) child.parentElement = null; this.children = []; this.append(...nodes);}
    insertBefore(node, reference) {node.remove(); node.parentElement = this; const at = reference ? this.children.indexOf(reference) : -1; if (at < 0) this.children.push(node); else this.children.splice(at, 0, node);}
    get lastElementChild() {return this.children.at(-1) ?? null;}
    querySelectorAll(selector) {const found = []; const visit = node => {for (const child of node.children) {if (child.matches(selector)) found.push(child); visit(child);}}; visit(this); return found;}
    closest(selector) {for (let node = this; node; node = node.parentElement) if (selector.split(',').some(part => node.matches(part.trim()))) return node; return null;}
    get offsetTop() {return 0;} get offsetHeight() {return 20;}
    querySelector(selector) {const found = []; const visit = node => {for (const child of node.children) {if (child.matches(selector)) found.push(child); visit(child);}}; visit(this); return found[0] ?? null;}
    matches(selector) {
      const attribute = /^\[([a-z-]+)\]$/.exec(selector);
      if (attribute) return Object.hasOwn(this.attributes, attribute[1]);
      const [tag, ...classes] = selector.split('.');
      if (tag.startsWith('#')) return this.id === tag.slice(1);
      return (!tag || this.tagName === tag.toUpperCase()) && classes.every(name => this.className.split(/\s+/).includes(name));
    }
    focus() {document.activeElement = this;}
    select() {}
    scrollIntoView() {}
  }
  document.body = new Node('body'); document.createElement = tag => new Node(tag);
  document.addEventListener = (type, fn) => document.listeners.set(type, [...(document.listeners.get(type) ?? []), fn]);
  document.fire = type => {for (const fn of document.listeners.get(type) ?? []) fn({type});};
  return document;
}

export async function checkNamesController(root) {
  const document = fakeDocument();
  const window = {listeners: new Map(), addEventListener(type, fn) {this.listeners.set(type, fn);}};
  const timers = [];
  const {api, emptyLibrary, validateLibrary} = await namesModels(root, {document, addEventListener: window.addEventListener.bind(window), location: {protocol: 'http:'},
    setTimeout: (fn, ms) => {timers.push(fn); return timers.length;}});
  const flush = async () => {for (let round = 0; round < 5; round++) {await settle(); while (timers.length) timers.shift()();}};
  const server = storeServer(libraryOf(emptyLibrary));
  const records = [artifactOf('302'), artifactOf('303', {digit: 'b'})];
  let changes = 0, opened = [];
  const controller = api.mount({fetcher: server.fetcher, validateLibrary, onChange: () => {changes++;},
    kinds: {artifact: {records: () => records, identity: api.artifactIdentity, unique: artifact => artifact.artifact_id}},
    catalog: () => records.map(record => ({kind: 'Source', identity: api.artifactIdentity(record), detail: record.url, open: () => opened.push(record.artifact_id)}))});
  assert.equal(api.controller(), controller);
  assert(await controller.load());
  const host = document.createElement('div'); const button = document.createElement('button'); button.id = 'source-rename';
  document.body.append(button, host); button.focus();
  const target = record => ({identity: controller.identityFor('artifact', record), label: record.url, host, restore: () => button, isCurrent: () => true});

  // F2/Rename opens the inline editor with the current name selected.
  assert(controller.begin(target(records[0])));
  const input = () => host.querySelector('input'), form = () => host.querySelector('form');
  assert.equal(document.activeElement, input()); assert.equal(input().value, ''); assert.equal(input().maxLength, 80);
  // Hostile text is stored and shown as text only.
  const hostile = '<img src=x onerror="globalThis.__rebInjected=1">';
  input().value = hostile;
  await form().fire('submit'); await flush();
  assert.equal(controller.nameOf(controller.identityFor('artifact', records[0])), hostile);
  assert.equal(host.children.length, 0, 'Enter saves and closes the editor'); assert.equal(document.activeElement, button, 'Focus returns to the invoker');
  assert(!document.created.some(node => node.tagName === 'IMG'), 'No element is created from a name');
  assert.equal(controller.nameFor('artifact', records[1]), null, 'Another artifact with the same URL has no name');

  // Escape cancels without writing and stops the key from reaching the view.
  const posts = () => server.calls.filter(call => call.method === 'POST').length;
  let before = posts();
  controller.begin(target(records[0])); assert.equal(input().value, hostile);
  input().value = 'discarded';
  const escape = await input().fire('keydown', {key: 'Escape'});
  assert(escape.defaultPrevented && escape.propagationStopped); assert.equal(host.children.length, 0); assert.equal(posts(), before);
  assert.equal(document.activeElement, button);

  // Leaving the editor cancels it; a failed save keeps the draft and explains.
  controller.begin(target(records[0])); input().value = 'blurred'; button.focus(); await form().fire('focusout'); await flush();
  assert.equal(host.children.length, 0); assert.equal(posts(), before);
  controller.begin(target(records[0])); input().value = 'x'.repeat(81);
  await form().fire('submit'); await flush();
  assert.equal(host.children.length, 1, 'An invalid name keeps the editor open');
  assert.match(form().children.at(-1).textContent, /at most 80/);
  assert.equal(posts(), before);

  // An empty name clears.
  input().value = '   '; await form().fire('submit'); await flush();
  assert.equal(controller.nameOf(controller.identityFor('artifact', records[0])), null);
  assert.equal(posts(), before + 1);
  assert(changes > 0, 'Every saved change re-renders the surfaces');

  // A target that is no longer exact refuses without a request.
  before = server.calls.length;
  controller.begin({...target(records[0]), isCurrent: () => false}); input().value = 'late';
  await form().fire('submit'); await flush();
  assert.equal(server.calls.length, before); assert.match(form().children.at(-1).textContent, /no longer retained/);
  controller.close(false);

  // file: previews never write.
  const offline = api.mount({fetcher: async () => {throw new Error('no network');}, validateLibrary, protocol: 'file:'});
  assert.equal(await offline.load(), false);
  console.log('PASS mounted names editor: Enter saves, Escape and blur cancel, focus returns, invalid names keep the draft, empty clears, stale targets refuse, hostile names stay text, file: never writes (DOM fixture; not rendered QA)');

}

// The palette may load before or after this module. Each case uses a fresh
// module context, as each page load does.
export async function checkNamesPalette(root) {
  const setup = async () => {
    const document = fakeDocument(), listeners = new Map(), timers = [];
    const models = await namesModels(root, {document, addEventListener: (type, fn) => listeners.set(type, fn), location: {protocol: 'http:'},
      setTimeout: fn => {timers.push(fn); return timers.length;}});
    const flush = async () => {for (let round = 0; round < 5; round++) {await settle(); while (timers.length) timers.shift()();}};
    return {...models, document, listeners, flush};
  };
  const records = [artifactOf('302'), artifactOf('303', {digit: 'b'})], opened = [], providers = [];
  const palette = {addProvider: provider => providers.push(provider), open() {}};
  const {api, emptyLibrary, validateLibrary, global, document, listeners, flush} = await setup();
  const server = storeServer(libraryOf(emptyLibrary));
  const kinds = {artifact: {records: () => records, identity: api.artifactIdentity, unique: artifact => artifact.artifact_id}};
  const catalog = () => records.map(record => ({kind: 'Source', identity: api.artifactIdentity(record), detail: `${record.url} · artifact ${record.artifact_id}`,
    open: () => opened.push(record.artifact_id)}));
  const names = api.mount({fetcher: server.fetcher, validateLibrary, kinds, catalog});
  assert.equal(names.registerPalette(), false, 'Without a palette, registration is a no-op');
  global.RebCommandPalette = palette;
  document.fire('DOMContentLoaded'); listeners.get('load')?.();
  assert.equal(providers.length, 1, 'A palette loaded after the module receives the provider exactly once');
  const provider = providers[0];
  assert.deepEqual(Object.keys(provider).sort(), ['group', 'id', 'search']);
  assert.equal(provider.id, 'evidence-names'); assert.equal(provider.group, 'Names'); assert.equal(typeof provider.search, 'function');
  assert(await names.load());
  assert.equal(provider.search('loader').length, 0, 'Nothing is named yet');
  const host = document.createElement('div'); document.body.append(host);
  names.begin({identity: names.identityFor('artifact', records[1]), label: records[1].url, host, restore: () => null});
  host.querySelector('input').value = 'stage loader';
  await host.querySelector('form').fire('submit'); await flush();
  const results = provider.search('STAGE');
  assert.equal(results.length, 1);
  assert.deepEqual(Object.keys(results[0]).sort(), ['detail', 'run', 'title']);
  assert.equal(results[0].title, 'stage loader'); assert.match(results[0].detail, /^Source · .*artifact 303$/);
  results[0].run(); assert.deepEqual(opened, ['303'], 'Running a result opens that exact item');
  assert.equal(provider.search('artifact 303').length, 1, 'The raw detail also finds a named item');
  assert.equal(provider.search('').length, 1, 'An empty query lists named items');
  records.push(artifactOf('303', {session: '2', digit: 'b'}));
  assert.equal(names.nameFor('artifact', records[1]), null, 'A now-ambiguous item loses its name');

  const first = await setup(), early = [];
  first.global.RebCommandPalette = {addProvider: provider => early.push(provider), open() {}};
  const mounted = first.api.mount({fetcher: server.fetcher, validateLibrary: first.validateLibrary});
  assert.equal(early.length, 1, 'A palette loaded first receives the provider at mount');
  first.document.fire('DOMContentLoaded'); first.listeners.get('load')?.(); mounted.registerPalette();
  assert.equal(early.length, 1, 'Registration is never repeated');
  const pulled = await setup();
  const lazy = pulled.api.mount({fetcher: server.fetcher, validateLibrary: pulled.validateLibrary});
  assert.equal(pulled.api.paletteProvider().id, 'evidence-names', 'A palette can pull the provider instead');
  pulled.global.RebCommandPalette = {addProvider: () => assert.fail('A pulled provider is not pushed again'), open() {}};
  pulled.document.fire('DOMContentLoaded'); pulled.listeners.get('load')?.(); assert.equal(lazy.registerPalette(), true);
  console.log('PASS Names palette provider: {id, group, search(query) -> [{title, detail, run}]}, registered exactly once before or after the palette or pulled lazily, no-op without it, exact items only (not rendered QA)');
}

// The shipped app wiring: Traffic rows from traffic_view.js and the names
// section of app.js (palette openers and F2 routing) with the real module.
export async function checkNamesApp(root) {
  const read = path => readFile(join(root, path), 'utf8');
  const app = await read('apps/research-ui/app.js');
  const start = app.indexOf('      // Researcher names (evidence_names.js). Each kind');
  const end = app.indexOf('\n      renderRequests();\n      renderInspector();', start);
  assert(start > 0 && end > start, 'Missing the app names section');
  const document = fakeDocument(), timers = [], calls = [];
  const flush = async () => {for (let round = 0; round < 5; round++) {await settle(); while (timers.length) timers.shift()();}};
  const node = (tag, id) => {const value = document.createElement(tag); if (id) value.id = id; document.body.append(value); return value;};
  const ids = Object.fromEntries(['request-rename', 'source-rename'].map(id => [id, node('button', id)]));
  for (const id of ['request-name-host', 'source-name-host']) ids[id] = node('div', id);
  const vmDetail = node('div', 'vm-detail'), symbolList = node('div', 'vm-symbol-list');
  let screen = 'traffic', modal = false;
  document.querySelector = selector => selector === '.screen:not([hidden])' ? {id: `screen-${screen}`} : selector === 'dialog:modal' ? (modal ? {} : null)
    : document.body.querySelector(selector);
  document.querySelectorAll = selector => selector === '#vm-symbol-list [data-vm-symbol-key]' ? symbolList.children : [];
  const keydown = [];
  const baseAdd = document.addEventListener;
  document.addEventListener = (type, fn, options) => {if (type === 'keydown') keydown.push(fn); else baseAdd(type, fn, options);};
  const server = storeServer(null);
  const workspace = workspaceOf(), finding = {findingId: 'analysis:c5e529342af22aafd3d7ddbc:artifact:302', sourceArtifactId: '302'};
  const state = {requests: [requestOf('demo-row'), requestOf('live-row', {origin: 'live', sequence: '9', request: '90'}), requestOf('other-row', {sequence: '7', request: '82'})],
    selectedRequestId: 'demo-row', trafficDetailOpen: true, artifacts: [artifactOf('302'), artifactOf('303', {digit: 'b'})], selectedArtifactId: '302',
    vmFindings: [finding], selectedVmFindingId: finding.findingId, selectedVmHandlerKey: '0::213', vmOpcodeWorkspace: {workspaces: [workspace]}};
  const stubs = `
    const state = __state, elements = {vmDetail: __vmDetail};
    const record = (name, ...args) => __calls.push([name, ...args.map(value => typeof value === 'object' ? JSON.parse(JSON.stringify(value)) : value)]);
    function renderRequests() {} function updateSelectionSummary() {} function renderSourceTree() {} function renderSourceTabs() {}
    function textElement(tag, className, value) {const element = document.createElement(tag); if (className) element.className = className; element.textContent = String(value); return element;}
    function selectedSource() {return state.artifacts.find(item => item.artifact_id === state.selectedArtifactId) ?? null;}
    function sourceDisplayName(source) {return 'loader.js · artifact ' + source.artifact_id;}
    function capturedSources() {return state.artifacts;}
    function selectRequest(id) {record('selectRequest', id); state.selectedRequestId = id;}
    function focusRequestRow(id) {record('focusRequestRow', id);}
    function showScreen(name) {record('showScreen', name);}
    function openInvestigation(target) {record('openInvestigation', target); return true;}
    function investigationNotice(message, status) {record('notice', status);}
    function renderVmLab() {record('renderVmLab');}
    function investigationBeforeSelection() {record('retire');}
    ${app.slice(start, end)}`;
  const {api, validateLibrary} = await namesModels(root, {document, location: {protocol: 'http:'}, addEventListener() {},
    setTimeout: fn => {timers.push(fn); return timers.length;}, __state: state, __vmDetail: vmDetail, __calls: calls,
    fetch: (...args) => server.fetcher(...args)}, stubs.replace('RebEvidenceNames.mount({', 'RebEvidenceNames.mount({fetcher: (...args) => fetch(...args),'), ', names: evidenceNames');
  const empty = (await namesModels(root)).emptyLibrary;
  server.library = libraryOf(empty);
  assert(validateLibrary(server.library));
  const names = api.controller();
  assert(await names.load());
  const press = (init = {}) => {const event = {key: 'F2', altKey: false, ctrlKey: false, metaKey: false, shiftKey: false, repeat: false, defaultPrevented: false,
    target: document.body, preventDefault() {this.defaultPrevented = true;}, ...init}; for (const fn of keydown) fn(event); return event.defaultPrevented;};
  const save = async (host, value) => {host.querySelector('input').value = value; await host.querySelector('form').fire('submit'); await flush();};

  // F2 on a Traffic row selects it like a click, then edits beside the header.
  const row = node('button'); row.className = 'request-row'; row.dataset.requestId = 'live-row';
  row.click = () => {calls.push(['row-click']); state.selectedRequestId = 'live-row';};
  assert.equal(press({target: row}), true);
  assert.deepEqual(calls.splice(0), [['row-click']]);
  assert.equal(ids['request-name-host'].children.length, 1);
  await save(ids['request-name-host'], 'session token mint');
  assert.equal(names.nameFor('request', state.requests[1]), 'session token mint');
  assert.equal(names.nameFor('request', state.requests[2]), null, 'The other row with the same URL keeps no name');
  for (const ignored of [{ctrlKey: true}, {metaKey: true}, {shiftKey: true}, {altKey: true}, {repeat: true}, {key: 'F3'},
    {target: Object.assign(document.createElement('input'), {})}]) assert.equal(press(ignored), false, JSON.stringify(Object.keys(ignored)));
  modal = true; assert.equal(press(), false, 'A modal dialog keeps the key'); modal = false;
  state.trafficDetailOpen = false; assert.equal(press(), false, 'A closed inspector has no rename target'); state.trafficDetailOpen = true;

  // Demo rows, sources and handlers.
  state.selectedRequestId = 'demo-row'; assert(press()); await save(ids['request-name-host'], 'demo mint');
  screen = 'sources';
  const folder = node('button'); folder.className = 'source-tree-row'; folder.click = () => assert.fail('A folder row is never opened by F2');
  assert.equal(press({target: folder}), false, 'F2 on a folder row renames nothing');
  assert.equal(ids['source-name-host'].children.length, 0);
  assert(press()); await save(ids['source-name-host'], 'obfuscated loader');
  assert.equal(names.nameFor('artifact', state.artifacts[0]), 'obfuscated loader');
  screen = 'vm';
  const host = node('div', 'vm-handler-name-host'); vmDetail.append(host);
  assert(press()); await save(host, 'push_const');
  const [first] = workspace.handlers;
  assert.equal(names.nameFor('handler', {key: '0::213', range: {start: first.source.byte_offset, end: first.source.byte_offset + first.source.byte_size}}, workspace), 'push_const');

  // The palette opens each exact item through the UI's own selection paths.
  const provider = api.paletteProvider();
  const run = query => {const results = provider.search(query); assert.equal(results.length, 1, query); calls.splice(0); results[0].run(); return copy(calls.splice(0));};
  assert.deepEqual(run('session token'), [['openInvestigation', {kind: 'request', identity: {type: 'captured-request', session: '1', process: '10', sequence: '9', request: '90'},
    relation: 'Opened by its researcher name. The name is your interpretation; the evidence is the exact retained record.'}]]);
  assert.deepEqual(run('demo mint'), [['showScreen', 'traffic'], ['selectRequest', 'demo-row'], ['focusRequestRow', 'demo-row']]);
  assert.deepEqual(run('obfuscated')[0].slice(0, 2), ['openInvestigation', {kind: 'artifact', identity: {type: 'captured-artifact', session: '1', artifact: '302', sha256: sha('a'), bytes: 488},
    relation: 'Opened by its researcher name. The name is your interpretation; the evidence is the exact retained record.'}]);
  const symbol = document.createElement('button'); symbol.dataset.vmSymbolKey = '0::213'; symbol.click = () => calls.push(['symbol-click', '0::213']);
  symbolList.append(symbol); state.selectedVmFindingId = null;
  assert.deepEqual(run('push_const'), [['showScreen', 'vm'], ['renderVmLab'], ['retire'], ['symbol-click', '0::213']]);
  // Replaced evidence: the name stays saved but is not shown or opened.
  state.requests = state.requests.map(request => request.id === 'demo-row' ? requestOf('demo-row', {sequence: '60'}) : request);
  assert.equal(provider.search('demo mint').length, 0, 'A replaced request is not offered by its old name');
  state.artifacts = [artifactOf('302', {digit: 'c'}), state.artifacts[1]];
  assert.equal(provider.search('obfuscated').length, 0, 'Changed source bytes are not offered by name');
  assert.equal(names.nameFor('handler', {key: '0::213', range: {start: 213, end: 247}}, workspace), null, 'A handler of changed source bytes loses its name');
  console.log('PASS app names wiring: F2 on Traffic, Sources and VM with modifier/text-field/modal guards, palette opens live requests via navigation, demo rows like a click, sources by exact artifact and handlers via the Symbol Tree; replaced evidence is never matched (production app.js section)');

  // Production Traffic rows: the name leads, captured path and host remain,
  // and a hostile name is only text. Search also covers names.
  const traffic = await read('apps/research-ui/traffic_view.js');
  const rows = runInNewContext(traffic + ';({renderTrafficRows, trafficSearchRequests})', {document, URL, matchMedia: () => ({matches: true})});
  const container = document.createElement('div'); document.body.append(container);
  const hostile = '<img src=x onerror="globalThis.__rebInjected=1">';
  const requests = [{...requestOf('a', {path: 'https://collector.example.test/mint'}), status: 200, type: 'xhr', time: 1},
    {...requestOf('b', {path: 'https://collector.example.test/mint'}), status: 200, type: 'xhr', time: 1}];
  const nameOf = request => request.id === 'a' ? hostile : null;
  rows.renderTrafficRows(container, requests, {selectedId: 'a', newIds: new Set(), onSelect() {}, onKey() {}, nameOf});
  const [named, plain] = container.children;
  const cell = named.querySelector('.request-name');
  assert.deepEqual(cell.children.map(child => child.className), ['researcher-name', 'request-resource', 'request-host']);
  assert.deepEqual(cell.children.map(child => child.textContent), [hostile, '/mint', 'collector.example.test']);
  assert.match(named.getAttribute('aria-label'), /^<img .*\(researcher name\)\. Demo evidence request: POST https:\/\/collector\.example\.test\/mint/);
  assert.deepEqual(plain.querySelector('.request-name').children.map(child => child.className), ['request-resource', 'request-host']);
  assert(!document.created.some(value => value.tagName === 'IMG'));
  assert.deepEqual([...rows.trafficSearchRequests(requests, 'onerror', nameOf).matches.keys()], ['a']);
  assert.deepEqual([...rows.trafficSearchRequests(requests, 'mint', nameOf).matches.keys()], ['a', 'b']);
  rows.renderTrafficRows(container, requests, {selectedId: 'a', newIds: new Set(), onSelect() {}, onKey() {}, nameOf: () => null});
  assert.equal(container.children[0], named, 'Renaming reuses the row element, preserving focus');
  assert.deepEqual(named.querySelector('.request-name').children.map(child => child.className), ['request-resource', 'request-host']);
  console.log('PASS production Traffic rows: name first with the captured path and host kept, hostile names as text, name search, row reuse on rename (DOM fixture; not rendered QA)');
}

export async function checkEvidenceNames(root) {
  await checkNamesCore(root);
  await checkNamesStore(root);
  await checkNamesController(root);
  await checkNamesPalette(root);
  await checkNamesApp(root);
  await checkNamesWiring(root);
}

// The app wiring: assets, the shared Analyst observation and exact openers.
export async function checkNamesWiring(root) {
  const read = path => readFile(join(root, path), 'utf8');
  for (const path of ['apps/origin-trace-backend/src/app.rs', 'apps/research-ui/macos/OriginTraceApp.swift', 'scripts/build-research-app.sh', 'apps/research-ui/index.html'])
    assert((await read(path)).includes('evidence_names.js'), path);
  const html = await read('apps/research-ui/index.html');
  const order = ['investigation_navigation.js', 'investigation_notebook.js', 'evidence_names.js', 'app.js'].map(name => html.indexOf(`src="${name}"`));
  assert(order.every((value, index) => value > 0 && (index === 0 || value > order[index - 1])), 'Names load after their identity helpers and before app.js');
  for (const id of ['request-rename', 'request-name-host', 'selected-name', 'source-rename', 'source-name-host']) assert(html.includes(`id="${id}"`), id);
  const app = await read('apps/research-ui/app.js'), module = await read('apps/research-ui/evidence_names.js'), traffic = await read('apps/research-ui/traffic_view.js');
  assert(!/innerHTML|insertAdjacentHTML|outerHTML\s*=/.test(module), 'The names module never parses HTML');
  assert.match(app, /RebEvidenceNames\?\.observeLibrary\(body\)/, 'Analyst admits refresh names');
  assert.match(traffic, /trafficNode\('span', 'researcher-name', researcherName\)/, 'Traffic rows insert names as text');
  console.log('PASS names wiring: packaged and served asset lists, script order, surface controls, Analyst observation, text-only insertion');
}

// Explicit real-store check against the built backend: names survive a process
// restart through the existing local Analyst route, and a stale write is refused.
export async function checkEvidenceNamesPersistence(root, binary) {
  const directory = await mkdtemp(join(tmpdir(), 'reb-names-store-'));
  const endpoint = join(directory, 'endpoint'), path = join(directory, 'library.json');
  let child, url, errors = '';
  const start = async () => {
    child = spawn(binary, ['--port', '0', '--store', join(directory, 'events'), '--trace-store', join(directory, 'trace'), '--signal-store', join(directory, 'signals'),
      '--artifacts', join(directory, 'artifacts'), '--api-collection', join(directory, 'collection'), '--local-analyst', path, '--endpoint-file', endpoint], {cwd: root, stdio: ['ignore', 'ignore', 'pipe']});
    child.stderr.on('data', value => {errors = (errors + String(value)).slice(-4096);});
    let spawnError; child.once('error', error => {spawnError = error;});
    for (let index = 0; index < 400; index++) {
      if (spawnError) throw spawnError;
      if (child.exitCode !== null) throw new Error(`Backend exited: ${errors}`);
      try {url = (await readFile(endpoint, 'utf8')).trim(); if ((await fetch(url + '/api/local-analyst')).ok) return;} catch {}
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    throw new Error('Names backend startup deadline exceeded.');
  };
  const stop = async () => {
    if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
    const exited = new Promise(resolve => child.once('exit', resolve));
    child.kill('SIGTERM'); const timer = setTimeout(() => child.kill('SIGKILL'), 1000);
    await exited; clearTimeout(timer);
  };
  try {
    const {api, validateLibrary} = await namesModels(root); await start();
    const connect = () => api.createStore({fetcher: (route, options) => fetch(url + route, options), validateLibrary});
    const identity = {type: 'vm-handler', finding: 'c5e529342af22aafd3d7ddbc', session: '1', artifact: '302', sha256: sha('a'), bytes: 488, handler: '0::213', start: 213, end: 247};
    const store = connect(); assert(await store.load());
    assert((await store.rename(identity, 'push_const', '')).ok);
    const persisted = JSON.parse(await readFile(path, 'utf8'));
    assert.equal(persisted.files[0].name, api.FILE_NAME); assert.equal((await stat(path)).mode & 0o777, 0o600);
    await stop(); await rm(endpoint, {force: true}); await start();
    const reopened = connect(); assert(await reopened.load()); assert.equal(reopened.nameOf(identity), 'push_const');
    const stale = await fetch(url + '/api/local-analyst/actions', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: 'replace_local_analyst_workspace', expected_generation: 0, folders: persisted.folders, files: []})});
    assert.equal(stale.status, 409);
    assert.equal(JSON.parse(await readFile(path, 'utf8')).files[0].content, persisted.files[0].content);
    console.log('PASS actual Rust names save through /api/local-analyst, user-only file, process restart and reload, stale generation refused');
  } finally {await stop(); await rm(directory, {recursive: true, force: true});}
}

const root = new URL('..', import.meta.url).pathname;
if (process.argv[2] === '--persistence') {
  assert(process.argv[3], 'Pass the built origin-trace-backend executable.');
  await checkEvidenceNamesPersistence(process.argv[4] || root, process.argv[3]);
} else if (import.meta.url === `file://${process.argv[1]}`) await checkEvidenceNames(process.argv[2] || root);
