/* Researcher names beside exact retained evidence. A name is interpretation,
 * never evidence: it is kept in one non-executable JSON scratchpad in the local
 * Analyst library and never replaces, hides or edits a captured value. Lookups
 * use exact identities only; a label, URL or file name never selects an item.
 * Contract: protocol/evidence-names-v1.md. */
(function () {
  'use strict';
  const KIND = 'reb-evidence-names', SUFFIX = '.reb-names.json', FILE_NAME = 'Evidence names.reb-names.json';
  // One Analyst file holds at most 32 KiB, so the byte bound usually binds
  // before the count bound. Both refuse explicitly; nothing is truncated.
  const LIMITS = Object.freeze({names: 500, characters: 80, bytes: 32768, programs: 64});
  const encoder = new TextEncoder();
  // Plain single-line text. Direction overrides and invisible marks are refused
  // because a name sits beside raw identifiers and must not reorder or mimic them.
  const FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/u;
  const FIELDS = Object.freeze({
    'captured-request': ['origin', 'session', 'process', 'sequence', 'request'],
    'captured-artifact': ['session', 'artifact', 'sha256', 'bytes'],
    'vm-handler': ['finding', 'session', 'artifact', 'sha256', 'bytes', 'handler', 'start', 'end']
  });
  const PROGRAM = ['finding', 'session', 'artifact', 'sha256', 'bytes'];
  const HANDLER = ['handler', 'start', 'end'];
  const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
  const decimal = (value, max = 18446744073709551615n) => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= max;
  const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  const offset = value => Number.isSafeInteger(value) && value >= 0;
  const wellFormed = value => typeof value.isWellFormed === 'function' ? value.isWellFormed()
    : !/[\ud800-\udfff]/.test(value.replace(/[\ud800-\udbff][\udc00-\udfff]/g, ''));
  const empty = () => ({document_kind: KIND, contract_version: 1, scope: 'local-analyst-library', requests: [], artifacts: [], vm_programs: []});

  function validName(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 4 * LIMITS.characters && value.trim() === value &&
      [...value].length <= LIMITS.characters && !FORBIDDEN.test(value) && wellFormed(value);
  }
  // Input normalization: surrounding whitespace is dropped and an empty
  // result clears the name. Nothing else is rewritten.
  function normalizeName(input) {
    const value = String(input ?? '').trim();
    if (!value) return {name: ''};
    if ([...value].length > LIMITS.characters) return {error: `Names allow at most ${LIMITS.characters} characters.`};
    if (FORBIDDEN.test(value) || !wellFormed(value)) return {error: 'Names are plain single-line text without control, invisible or direction-override characters.'};
    return {name: value};
  }
  function validIdentity(identity) {
    const fields = FIELDS[identity?.type];
    if (!fields || !exact(identity, ['type', ...fields]) || !decimal(identity.session)) return false;
    if (identity.type === 'captured-request') return ['live', 'demo'].includes(identity.origin) &&
      decimal(identity.process, 4294967295n) && decimal(identity.sequence) && decimal(identity.request);
    if (!decimal(identity.artifact) || !hash(identity.sha256) || !offset(identity.bytes)) return false;
    return identity.type === 'captured-artifact' || typeof identity.finding === 'string' && /^[0-9a-f]{24}$/.test(identity.finding) &&
      typeof identity.handler === 'string' && /^[A-Za-z0-9:]{1,96}$/.test(identity.handler) &&
      offset(identity.start) && offset(identity.end) && identity.end > identity.start;
  }
  // The canonical key is the ordered identity tuple. Two items share a key only
  // when every identity field is equal; a shared label or URL never does.
  function keyOf(identity) {
    return validIdentity(identity) ? JSON.stringify([identity.type, ...FIELDS[identity.type].map(field => identity[field])]) : null;
  }
  const pick = (value, fields) => Object.fromEntries(fields.map(field => [field, value[field]]));
  const requestOf = entry => ({type: 'captured-request', ...pick(entry, FIELDS['captured-request'])});
  const artifactOf = entry => ({type: 'captured-artifact', ...pick(entry, FIELDS['captured-artifact'])});
  const handlerOf = (program, entry) => ({type: 'vm-handler', ...pick(program, PROGRAM), ...pick(entry, HANDLER)});

  // Identities are the investigation navigation's own fields. Requests add the
  // capture origin: they carry no content hash, so deterministic demo
  // identifiers must never name a live request with the same numbers.
  function requestIdentity(request, root) {
    if (!request || !['live', 'demo'].includes(request.origin) || !root) return null;
    const event = investigationEventIdentity(root), id = investigationId(root.request_id);
    const identity = event && id && id !== '0' ? {type: 'captured-request', origin: request.origin,
      session: event.session, process: event.process, sequence: event.sequence, request: id} : null;
    return validIdentity(identity) ? identity : null;
  }
  function artifactIdentity(artifact) {
    const identity = investigationArtifactIdentity(artifact);
    return identity && validIdentity(identity) ? identity : null;
  }
  // A handler is named within one exact program: the workspace finding, its
  // retained source artifact (session, ID, SHA-256, size), the listing key and
  // the handler's source byte range.
  function handlerIdentity({workspace, artifact, row}) {
    const source = investigationArtifactIdentity(artifact);
    if (!source || investigationId(workspace?.interpreter_artifact_id) !== source.artifact ||
        workspace.source_artifact_sha256 !== source.sha256 || !row?.range) return null;
    const identity = {type: 'vm-handler', finding: workspace.finding_id, session: source.session, artifact: source.artifact,
      sha256: source.sha256, bytes: source.bytes, handler: row.key, start: row.range.start, end: row.range.end};
    return validIdentity(identity) ? identity : null;
  }

  function validate(doc) {
    if (!exact(doc, ['document_kind', 'contract_version', 'scope', 'requests', 'artifacts', 'vm_programs']) ||
        doc.document_kind !== KIND || doc.contract_version !== 1 || doc.scope !== 'local-analyst-library' ||
        ![doc.requests, doc.artifacts, doc.vm_programs].every(Array.isArray) || doc.vm_programs.length > LIMITS.programs) return false;
    const keys = new Set(), programs = new Set();
    const admit = (identity, name) => {
      const key = keyOf(identity);
      if (!key || keys.has(key) || !validName(name)) return false;
      keys.add(key); return keys.size <= LIMITS.names;
    };
    for (const entry of doc.requests) if (!exact(entry, [...FIELDS['captured-request'], 'name']) || !admit(requestOf(entry), entry.name)) return false;
    for (const entry of doc.artifacts) if (!exact(entry, [...FIELDS['captured-artifact'], 'name']) || !admit(artifactOf(entry), entry.name)) return false;
    for (const program of doc.vm_programs) {
      if (!exact(program, [...PROGRAM, 'handlers']) || !Array.isArray(program.handlers) || !program.handlers.length) return false;
      const key = JSON.stringify(PROGRAM.map(field => program[field]));
      if (programs.has(key)) return false;
      programs.add(key);
      for (const entry of program.handlers) if (!exact(entry, [...HANDLER, 'name']) || !admit(handlerOf(program, entry), entry.name)) return false;
    }
    return encoder.encode(JSON.stringify(doc)).length <= LIMITS.bytes;
  }
  function count(doc) {
    return doc.requests.length + doc.artifacts.length + doc.vm_programs.reduce((sum, program) => sum + program.handlers.length, 0);
  }
  function boundsMessage(doc) {
    if (count(doc) > LIMITS.names) return `The names document holds at most ${LIMITS.names} names. Clear a name first; nothing was saved.`;
    if (doc.vm_programs.length > LIMITS.programs) return `Names cover at most ${LIMITS.programs} VM programs. Clear one first; nothing was saved.`;
    return `The names document is limited to ${LIMITS.bytes / 1024} KiB, the Analyst file limit. Clear or shorten a name first; nothing was saved.`;
  }
  function index(doc) {
    const names = new Map();
    if (!doc) return names;
    for (const entry of doc.requests) names.set(keyOf(requestOf(entry)), entry.name);
    for (const entry of doc.artifacts) names.set(keyOf(artifactOf(entry)), entry.name);
    for (const program of doc.vm_programs) for (const entry of program.handlers) names.set(keyOf(handlerOf(program, entry)), entry.name);
    return names;
  }
  // Set, replace or clear exactly one identity. Other names keep their order.
  function apply(doc, identity, name) {
    const next = structuredClone(doc), key = keyOf(identity);
    if (!key) throw new TypeError('An exact evidence identity is required.');
    const update = (list, identityOf, entry) => {
      const at = list.findIndex(value => keyOf(identityOf(value)) === key);
      if (at >= 0 && name) list[at].name = name;
      else if (at >= 0) list.splice(at, 1);
      else if (name) list.push({...entry, name});
    };
    if (identity.type === 'captured-request') update(next.requests, requestOf, pick(identity, FIELDS['captured-request']));
    else if (identity.type === 'captured-artifact') update(next.artifacts, artifactOf, pick(identity, FIELDS['captured-artifact']));
    else {
      const programKey = JSON.stringify(PROGRAM.map(field => identity[field]));
      let program = next.vm_programs.find(value => JSON.stringify(PROGRAM.map(field => value[field])) === programKey);
      if (!program && name) {program = {...pick(identity, PROGRAM), handlers: []}; next.vm_programs.push(program);}
      if (program) update(program.handlers, entry => handlerOf(program, entry), pick(identity, HANDLER));
      next.vm_programs = next.vm_programs.filter(value => value.handlers.length);
    }
    return next;
  }
  const strictParse = (source, maximum) => RebInvestigationNotebook.strictParse(source, maximum);
  function readDocument(file) {
    if (file?.kind !== 'scratchpad' || file.language !== 'json') return null;
    try {const doc = strictParse(file.content, LIMITS.bytes * 4); return validate(doc) ? doc : null;} catch {return null;}
  }
  // A suffix only makes a malformed document discoverable; ordinary JSON files
  // are never adopted by name alone. Several candidates are ambiguous.
  function locate(library) {
    const files = (library?.files ?? []).filter(file => file.kind === 'scratchpad' && file.language === 'json' &&
      (file.name.endsWith(SUFFIX) || readDocument(file)));
    if (!files.length) return {status: 'ready', file: null, document: empty()};
    if (files.length > 1) return {status: 'ambiguous', file: null, document: null,
      message: `Several names documents (${SUFFIX}) exist in Analyst. Keep exactly one; no names are shown or saved until then.`};
    const document = readDocument(files[0]);
    return document ? {status: 'ready', file: files[0], document}
      : {status: 'malformed', file: files[0], document: null,
        message: `${files[0].name} is malformed or uses an unsupported version. It stays an unchanged, inert Analyst scratchpad; no names are shown or saved.`};
  }
  const projection = file => Object.fromEntries(['id', 'folder_id', 'name', 'kind', 'language', 'content'].map(key => [key, file[key]]));
  const folderProjection = folders => folders.map(folder => ({id: folder.id, name: folder.name, parent_id: folder.parent_id})).sort((a, b) => a.id - b.id);

  function createStore({fetcher = fetch, validateLibrary, timeout = 10000, changed = () => {}, renamed = () => {}}) {
    const model = {library: null, file: null, document: null, status: 'idle', message: '', busy: false};
    let names = new Map(), signature = 'null', active = null;
    function adopt(library) {
      const found = locate(library);
      Object.assign(model, {library, file: found.file, document: found.document, status: found.status, message: found.message ?? ''});
      names = index(found.document);
      const next = JSON.stringify([...names]);
      if (next !== signature) {signature = next; renamed();}
    }
    async function guarded(task) {
      const controller = new AbortController(); active = controller;
      let timer, abort;
      const deadline = new Promise((_, reject) => {
        abort = () => reject(new Error('The operation was cancelled.'));
        controller.signal.addEventListener('abort', abort, {once: true});
        timer = setTimeout(() => {reject(new Error('The local library did not answer in time.')); controller.abort();}, timeout);
      });
      try {return await Promise.race([task(controller.signal), deadline]);}
      finally {clearTimeout(timer); controller.signal.removeEventListener('abort', abort); if (active === controller) active = null;}
    }
    async function documentOf(response, signal) {
      const bytes = await evidencePackageReadBytes(response, 1024 * 1024, signal);
      if (!response.ok) throw new Error(response.status === 409 ? 'Another window changed the local library first.' : `Local storage returned HTTP ${response.status}.`);
      const value = strictParse(new TextDecoder('utf-8', {fatal: true}).decode(bytes), 1024 * 1024);
      if (!validateLibrary(value)) throw new Error('The local library response is malformed.');
      return value;
    }
    const read = signal => fetcher('/api/local-analyst', {cache: 'no-store', signal}).then(response => documentOf(response, signal));
    async function load() {
      if (model.busy) return false;
      model.busy = true; if (!model.library) model.status = 'loading'; changed();
      try {adopt(await guarded(read)); return true;}
      catch (error) {
        // Keep the last understandable names when a later read fails.
        if (!model.library) model.status = 'unavailable';
        model.message = `Names could not be read. ${error.message}`; return false;
      } finally {model.busy = false; changed();}
    }
    // Every write starts from a fresh read and replaces one library generation.
    // A name edited elsewhere since the editor opened is never overwritten
    // silently, and a stale generation is refused by the store (HTTP 409).
    async function rename(identity, input, base = '') {
      const key = keyOf(identity);
      if (!key) return {ok: false, message: 'This item has no exact retained identity to name.'};
      const normalized = normalizeName(input);
      if (normalized.error) return {ok: false, message: normalized.error};
      if (model.busy) return {ok: false, message: 'Another names operation is still running. Try again in a moment.'};
      model.busy = true; changed();
      let posted = false;
      try {
        const library = await guarded(read); adopt(library);
        if (model.status !== 'ready') return {ok: false, message: model.message};
        const current = names.get(key) ?? '';
        if (current === normalized.name) return {ok: true, name: current, unchanged: true};
        if (current !== base) return {ok: false, conflict: true, current, message: current
          ? `The saved name changed to “${current}” elsewhere. Press Enter again to replace it, or Escape to keep it.`
          : 'The saved name was cleared elsewhere. Press Enter again to save yours, or Escape to keep it cleared.'};
        const candidate = apply(model.document, identity, normalized.name);
        if (!validate(candidate)) return {ok: false, message: boundsMessage(candidate)};
        const content = JSON.stringify(candidate), old = model.file;
        const files = library.files.filter(file => file.id !== old?.id).map(projection);
        if (old) files.push({...projection(old), content});
        else {
          if (library.folders.some(folder => folder.parent_id === 1 && folder.name.toLocaleLowerCase() === FILE_NAME.toLocaleLowerCase()))
            return {ok: false, message: `An Analyst folder is named ${FILE_NAME}. Rename it before saving names.`};
          const id = Math.max(0, ...library.files.map(file => file.id)) + 1;
          if (!Number.isSafeInteger(id)) return {ok: false, message: 'The local file identifier limit was reached.'};
          files.push({id, folder_id: 1, name: FILE_NAME, kind: 'scratchpad', language: 'json', content});
        }
        if (files.length > 64 || files.reduce((sum, file) => sum + encoder.encode(file.content).length, 0) > 512 * 1024)
          return {ok: false, message: 'The shared Analyst library is full. Existing files were preserved; nothing was saved.'};
        const request = {action: 'replace_local_analyst_workspace', expected_generation: library.generation, folders: library.folders, files};
        posted = true;
        const receipt = await guarded(async signal => documentOf(await fetcher('/api/local-analyst/actions', {method: 'POST', cache: 'no-store', signal,
          headers: {'Content-Type': 'application/json'}, body: JSON.stringify(request)}), signal));
        if (![library.generation, library.generation + 1].includes(receipt.generation) ||
            JSON.stringify(folderProjection(receipt.folders)) !== JSON.stringify(folderProjection(library.folders)) || receipt.files.length !== files.length ||
            files.some(expected => !receipt.files.some(actual => JSON.stringify(projection(actual)) === JSON.stringify(expected))))
          throw new Error('The save receipt does not match the submitted library.');
        adopt(receipt);
        return {ok: true, name: normalized.name};
      } catch (error) {
        if (!posted) return {ok: false, message: `Names could not be read. ${error.message}`};
        return {ok: false, message: /changed the local library first/.test(error.message)
          ? `Not saved. ${error.message} Press Enter to try again; the library is reread first.`
          : `The save could not be confirmed. ${error.message} Press Enter to check: the library is reread first and nothing is written twice.`};
      } finally {model.busy = false; changed();}
    }
    // The Analyst editor admits newer library generations; names follow them
    // without a request. An older or equal generation is ignored.
    function observe(library) {
      if (model.busy || !validateLibrary(library) || model.library && library.generation <= model.library.generation) return false;
      adopt(library); changed(); return true;
    }
    const nameOf = identity => {const key = keyOf(identity); return key ? names.get(key) ?? null : null;};
    const has = type => [...names.keys()].some(key => key.startsWith(`["${type}"`));
    const cancel = () => active?.abort();
    return {model, load, rename, observe, nameOf, has, cancel, entries: () => [...names]};
  }

  // Resolve names for a set of retained records. A record whose identity is
  // missing, or shared with another record, gets no name and cannot be renamed.
  // `unique` adds the caller's own selector key (row or artifact ID), because a
  // view that selects by that key cannot open one of two records sharing it.
  function resolver(records, identityOf, nameOf, unique = null) {
    const counts = new Map(), selectors = new Map();
    const bump = (map, key) => map.set(key, (map.get(key) ?? 0) + 1);
    for (const record of records) {
      const key = keyOf(identityOf(record));
      if (key) bump(counts, key);
      if (unique) bump(selectors, unique(record));
    }
    const identity = record => {
      const value = identityOf(record), key = keyOf(value);
      return key && counts.get(key) === 1 && (!unique || selectors.get(unique(record)) === 1) ? value : null;
    };
    return {identity, name: record => {const exact = identity(record); return exact ? nameOf(exact) : null;}};
  }

  const KIND_LABELS = {'captured-request': 'request', 'captured-artifact': 'source', 'vm-handler': 'handler'};
  let mounted = null;
  // kinds: {request|artifact|handler: {records(scope), identity(record, scope),
  // unique?(record), version?(scope)}} are the caller's retained records, its
  // exact identity functions and the inputs those functions read.
  function mount({fetcher = fetch, validateLibrary, protocol = location.protocol, onChange = () => {}, kinds = {}, catalog = () => [], timeout}) {
    const supported = ['http:', 'https:', 'reb:'].includes(protocol);
    const store = createStore({fetcher, validateLibrary, timeout, renamed: () => {resolvers = new WeakMap(); onChange();}});
    let editor = null, resolvers = new WeakMap();
    // Resolvers are cached per retained record list (or VM workspace) until the
    // list, the caller's version inputs or the saved names change.
    function resolve(kind, scope) {
      const adapter = kinds[kind];
      if (!adapter) return null;
      const owner = scope ?? adapter.records();
      if (!owner || typeof owner !== 'object') return null;
      const version = adapter.version?.(scope) ?? [], length = scope === undefined ? owner.length : -1;
      const cached = resolvers.get(owner);
      if (cached && cached.length === length && cached.version.length === version.length &&
          cached.version.every((value, index) => value === version[index])) return cached.resolver;
      const records = scope === undefined ? owner : adapter.records(scope) ?? [];
      const value = resolver(records, record => adapter.identity(record, scope), store.nameOf, adapter.unique);
      resolvers.set(owner, {length, version, resolver: value});
      return value;
    }
    const identityFor = (kind, record, scope) => record ? resolve(kind, scope)?.identity(record) ?? null : null;
    const nameFor = (kind, record, scope) => record ? resolve(kind, scope)?.name(record) ?? null : null;
    const element = (tag, className, text) => {const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node;};
    function close(restore = true) {
      const current = editor;
      if (!current) return;
      editor = null; current.form.remove();
      if (restore) current.target.restore?.()?.focus({preventScroll: true});
    }
    // target: {identity, label, host, restore(), isCurrent()}. One inline editor
    // exists at a time; it never runs or fetches anything on its own.
    function begin(target) {
      close(false);
      if (!target?.host || !keyOf(target.identity)) return false;
      const noun = KIND_LABELS[target.identity.type];
      const form = element('form', 'evidence-name-editor'); form.setAttribute('aria-label', `Rename ${noun}`); form.noValidate = true;
      const field = element('label', 'evidence-name-field');
      const input = element('input'); input.type = 'text'; input.maxLength = LIMITS.characters; input.autocomplete = 'off'; input.spellcheck = false;
      input.placeholder = 'Researcher name'; input.setAttribute('aria-label', `Researcher name for ${target.label}`);
      field.append(element('span', '', 'Name'), input);
      const hint = element('span', 'evidence-name-hint', 'Enter saves · Esc cancels · empty clears');
      const status = element('p', 'evidence-name-status'); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
      form.append(field, hint, status);
      const current = {target, form, input, status, base: store.nameOf(target.identity) ?? '', saving: false};
      editor = current;
      input.value = current.base;
      const say = (message, kind = 'error') => {status.textContent = message; status.dataset.kind = kind;};
      if (!supported) say('Open the local app or browser development UI to save names.');
      else if (['malformed', 'ambiguous'].includes(store.model.status)) say(store.model.message);
      input.addEventListener('keydown', event => {
        if (event.key === 'Escape') {event.preventDefault(); event.stopPropagation(); if (editor === current) close(true);}
        else if (event.key === 'Enter') event.stopPropagation();
      });
      form.addEventListener('submit', async event => {
        event.preventDefault();
        if (current.saving || editor !== current) return;
        if (!supported) {say('Open the local app or browser development UI to save names.'); return;}
        if (target.isCurrent && !target.isCurrent()) {say('This exact item is no longer retained or is now ambiguous. Nothing was saved.'); return;}
        current.saving = true; input.readOnly = true; say('Saving to the local Analyst library…', 'pending');
        const result = await store.rename(target.identity, input.value, current.base);
        current.saving = false; input.readOnly = false;
        if (editor !== current) return;
        // A re-render may have replaced the editor's host while it saved; focus
        // then sits on the body. Focus the user moved elsewhere stays there.
        const owned = form.contains(document.activeElement) || !document.activeElement || document.activeElement === document.body;
        if (result.ok) {close(owned); return;}
        if (result.conflict) current.base = result.current;
        say(result.message);
        if (owned && form.isConnected !== false) input.focus({preventScroll: true});
      });
      // Leaving the editor cancels it. Switching applications does not.
      form.addEventListener('focusout', () => setTimeout(() => {
        if (editor !== current || current.saving || typeof document.hasFocus === 'function' && !document.hasFocus()) return;
        if (!form.contains(document.activeElement)) close(false);
      }, 0));
      target.host.append(form);
      input.focus({preventScroll: true}); input.select();
      form.scrollIntoView?.({block: 'nearest'});
      return true;
    }
    // Palette entries reopen exactly the current retained item through the
    // caller's normal selection function; absent items are not listed.
    const provider = Object.freeze({id: 'evidence-names', group: 'Names', search(query) {
      const needle = String(query ?? '').trim().toLocaleLowerCase();
      const results = [];
      for (const item of catalog()) {
        const name = store.nameOf(item.identity);
        if (!name || needle && !name.toLocaleLowerCase().includes(needle) && !String(item.detail ?? '').toLocaleLowerCase().includes(needle)) continue;
        results.push({title: name, detail: `${item.kind} · ${item.detail}`, rank: needle && name.toLocaleLowerCase().startsWith(needle) ? 0 : 1, run: () => item.open()});
      }
      return results.sort((a, b) => a.rank - b.rank || a.title.localeCompare(b.title)).slice(0, 50).map(({title, detail, run}) => ({title, detail, run}));
    }});
    let registered = false;
    function register() {
      const palette = globalThis.RebCommandPalette;
      if (registered || typeof palette?.addProvider !== 'function') return registered;
      palette.addProvider(provider); registered = true; return true;
    }
    if (!register() && typeof document.addEventListener === 'function') {
      // The palette may load after this module. Try again once the document is
      // parsed and once more after load; without a palette this stays a no-op.
      if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', register, {once: true});
      globalThis.addEventListener?.('load', register, {once: true});
    }
    globalThis.addEventListener?.('pagehide', () => {close(false); store.cancel();});
    const controller = {
      model: store.model, load: () => supported ? store.load() : Promise.resolve(false), observe: store.observe,
      nameOf: store.nameOf, has: store.has, identityFor, nameFor, begin, close, editing: () => editor?.target.identity ?? null,
      // Handing the provider to a palette transfers registration to it.
      paletteProvider: () => {registered = true; return provider;}, registerPalette: register
    };
    mounted = controller;
    return controller;
  }

  // Renderers reach the mounted controller through these module functions, so a
  // view rendered before mounting (or without it) simply shows no names.
  globalThis.RebEvidenceNames = Object.freeze({KIND, SUFFIX, FILE_NAME, LIMITS, empty, validName, normalizeName, validIdentity, keyOf,
    requestIdentity, artifactIdentity, handlerIdentity, validate, index, apply, readDocument, locate, createStore, resolver, mount,
    controller: () => mounted,
    nameFor: (kind, record, scope) => mounted?.nameFor(kind, record, scope) ?? null,
    identityFor: (kind, record, scope) => mounted?.identityFor(kind, record, scope) ?? null,
    observeLibrary: library => mounted?.observe(library) ?? false,
    paletteProvider: () => mounted?.paletteProvider() ?? null});
}());
