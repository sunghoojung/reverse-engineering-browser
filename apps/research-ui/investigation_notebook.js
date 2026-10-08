/* Explicit, library-wide research notes. This module never runs a script, imports
 * captured bytes, or restores a browser profile, capture setting or permission. */
(function () {
  'use strict';
  const KIND = 'reb-investigation-notebook', FILE_MAX = 32768, PIN_MAX = 64;
  const encoder = new TextEncoder();
  const exact = (value, fields) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
  const integer = (value, min = 0) => Number.isSafeInteger(value) && value >= min;
  const utf8Text = (value, max) => typeof value === 'string' && value.length <= max && encoder.encode(value).length <= max &&
    new TextDecoder('utf-8', {fatal: true}).decode(encoder.encode(value)) === value;
  const text = (value, max, empty = true) => utf8Text(value, max) && (empty || value.trim().length > 0) &&
    !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/u.test(value);
  const decimal = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n;
  const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  const empty = () => ({document_kind: KIND, contract_version: 1, scope: 'local-analyst-library', next_pin_id: 1, pins: []});

  // Reject duplicate (including escaped) object members before JSON.parse. All
  // notebook/library input is bounded before this nonrecursive-depth scan.
  function strictParse(source, maximum = FILE_MAX) {
    // JSON permits DEL inside strings. Validate notebook text separately so
    // unrelated Analyst scratchpads keep their existing content contract.
    if (!utf8Text(source, maximum)) throw new Error('The local document is invalid UTF-8 text or exceeds its byte limit.');
    let at = 0, nodes = 0;
    const whitespace = () => {while (/\s/.test(source[at] ?? '') && at < source.length) at++;};
    const string = () => {
      const start = at++;
      while (at < source.length) {
        if (source[at] === '\\') {at += 2; continue;}
        if (source[at++] === '"') return JSON.parse(source.slice(start, at));
      }
      throw new Error('The local document contains an incomplete string.');
    };
    function value(depth) {
      whitespace();
      if (++nodes > 25000 || depth > 16) throw new Error('The local document exceeds its structure limit.');
      if (source[at] === '"') {string(); return;}
      if (source[at] === '{') {
        at++; whitespace(); const keys = new Set();
        if (source[at] === '}') {at++; return;}
        for (;;) {
          whitespace(); if (source[at] !== '"') throw new Error('The local document has an invalid object.');
          const key = string(); if (keys.has(key)) throw new Error('The local document has duplicate object members.'); keys.add(key);
          whitespace(); if (source[at++] !== ':') throw new Error('The local document has an invalid member.');
          value(depth + 1); whitespace();
          if (source[at] === '}') {at++; return;}
          if (source[at++] !== ',') throw new Error('The local document has an incomplete object.');
        }
      }
      if (source[at] === '[') {
        at++; whitespace(); if (source[at] === ']') {at++; return;}
        for (;;) {value(depth + 1); whitespace(); if (source[at] === ']') {at++; return;} if (source[at++] !== ',') throw new Error('The local document has an incomplete array.');}
      }
      const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(source.slice(at));
      if (!match) throw new Error('The local document is malformed.'); at += match[0].length;
    }
    value(0); whitespace(); if (at !== source.length) throw new Error('The local document has trailing content.');
    return JSON.parse(source);
  }
  function validReference(ref) {
    if (!ref || !decimal(ref.session)) return false;
    if (ref.type === 'captured-artifact') return exact(ref, ['type', 'session', 'artifact', 'sha256', 'bytes', 'range']) &&
      decimal(ref.artifact) && hash(ref.sha256) && integer(ref.bytes) && (ref.range === null ||
        exact(ref.range, ['start', 'end']) && integer(ref.range.start) && integer(ref.range.end) && ref.range.end > ref.range.start && ref.range.end <= ref.bytes);
    return ref.type === 'captured-event' && exact(ref, ['type', 'session', 'process', 'sequence', 'fingerprint']) &&
      decimal(ref.process) && BigInt(ref.process) <= 4294967295n && decimal(ref.sequence) && hash(ref.fingerprint);
  }
  function validate(doc) {
    if (!exact(doc, ['document_kind', 'contract_version', 'scope', 'next_pin_id', 'pins']) ||
        doc.document_kind !== KIND || doc.contract_version !== 1 || doc.scope !== 'local-analyst-library' ||
        !integer(doc.next_pin_id, 1) || !Array.isArray(doc.pins) || doc.pins.length > PIN_MAX) return false;
    const ids = new Set();
    for (const pin of doc.pins) {
      if (!exact(pin, ['id', 'name', 'note', 'reference']) || !integer(pin.id, 1) || pin.id >= doc.next_pin_id || ids.has(pin.id) ||
          !text(pin.name, 80, false) || pin.name.trim() !== pin.name || !text(pin.note, 2048) || !validReference(pin.reference)) return false;
      ids.add(pin.id);
    }
    return encoder.encode(JSON.stringify(doc)).length <= FILE_MAX;
  }
  function readNotebook(file) {
    if (file?.kind !== 'scratchpad' || file.language !== 'json') return null;
    try {const doc = strictParse(file.content); return validate(doc) ? doc : null;} catch {return null;}
  }
  function candidates(library) {
    return (library?.files ?? []).filter(file => file.kind === 'scratchpad' && file.language === 'json' &&
      (file.name.endsWith('.reb-notebook.json') || readNotebook(file)));
  }
  const eventFields = new Set(['protocol_version', 'session_id', 'sequence_number', 'monotonic_time_ns', 'navigation_id', 'frame_id',
    'artifact_id', 'parent_event_id', 'request_id', 'browser_context_id_high', 'browser_context_id_low', 'encoded_data_length',
    'decoded_body_length', 'process_id', 'thread_id', 'initiator_request_id', 'initiator_process_id', 'resource_type', 'flags',
    'tab_id', 'status_code', 'error_code', 'category', 'type', 'payload_size', 'payload_encoding', 'payload', 'payload_truncated']);
  function eventCanonical(event) {
    // Unknown extensions are not silently dropped from a saved fingerprint.
    if (!event || ![2, 3].includes(event.protocol_version) || event.type === 'gap' || !isBrokerEvent(event) ||
        !decimal(event.session_id) || !decimal(event.sequence_number) || !integer(event.process_id, 1) ||
        Object.keys(event).some(key => !eventFields.has(key))) throw new Error('This observation has no supported complete notebook identity.');
    const entries = Object.keys(event).sort().map(key => [key, event[key]]);
    if (entries.some(([, v]) => !['string', 'number', 'boolean'].includes(typeof v))) throw new Error('Observation metadata is unsupported.');
    const canonical = JSON.stringify(Object.fromEntries(entries));
    if (encoder.encode(canonical).length > 4096) throw new Error('Observation metadata exceeds its fingerprint bound.');
    return canonical;
  }
  function eventMatches(ref, context) {
    return (context.events ?? []).slice(-5000).filter(event => String(event.session_id) === ref.session &&
      String(event.process_id) === ref.process && String(event.sequence_number) === ref.sequence);
  }
  async function digest(canonical) {
    if (!globalThis.crypto?.subtle) throw new Error('Native observation pins require local SHA-256 support.');
    const value = await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(`REB\0notebook-event\0v1\0${canonical}`));
    return [...new Uint8Array(value)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  async function eventReference(event, getContext) {
    const canonical = eventCanonical(event);
    const ref = {type: 'captured-event', session: event.session_id, process: String(event.process_id), sequence: event.sequence_number, fingerprint: ''};
    const matches = eventMatches(ref, getContext());
    if (matches.length !== 1 || eventCanonical(matches[0]) !== canonical) throw new Error('The selected observation is missing, changed or ambiguous.');
    ref.fingerprint = await digest(canonical);
    const current = eventMatches(ref, getContext());
    if (current.length !== 1 || eventCanonical(current[0]) !== canonical) throw new Error('The observation changed while its fingerprint was being checked.');
    return ref;
  }
  function artifactReference(artifact, range = null) {
    const identity = investigationArtifactIdentity(artifact);
    const ref = identity && {...identity, range: range ? {start: range.start, end: range.end} : null};
    if (!validReference(ref)) throw new Error('A complete captured artifact identity is required.');
    return ref;
  }
  async function resolve(ref, getContext) {
    if (!validReference(ref)) return {status: 'invalid', message: 'The saved reference is malformed.'};
    if (ref.type === 'captured-artifact') {
      const artifacts = (getContext().artifacts ?? []).slice(0, 5000);
      const scoped = artifacts.filter(value => String(value.session_id) === ref.session && String(value.artifact_id) === ref.artifact);
      if (!scoped.length) return {status: 'missing', message: 'This exact source is outside the retained window. Nothing was refetched.'};
      if (scoped.length !== 1 || artifacts.filter(value => String(value.artifact_id) === ref.artifact).length !== 1)
        return {status: 'ambiguous', message: 'The artifact ID is reused. Sources cannot safely distinguish these records.'};
      if (scoped[0].sha256 !== ref.sha256 || scoped[0].byte_size !== ref.bytes)
        return {status: 'changed', message: 'This source descriptor changed. The saved hash and size do not match.'};
      if (!['javascript', 'wasm', 'source_map', 'response_body'].includes(scoped[0].kind) || ref.range && scoped[0].kind !== 'javascript')
        return {status: 'unavailable', message: 'This captured source has no supported original view.'};
      return {status: 'ready', message: 'Exact retained descriptor. Original bytes are verified by Sources when required.'};
    }
    const matches = eventMatches(ref, getContext());
    if (!matches.length) return {status: 'missing', message: 'This observation is outside the retained window. Nothing was recaptured.'};
    if (matches.length !== 1) return {status: 'ambiguous', message: 'More than one observation has this exact scoped identity.'};
    try {
      const canonical = eventCanonical(matches[0]), actual = await digest(canonical);
      const current = eventMatches(ref, getContext());
      if (current.length !== 1) return {status: current.length ? 'ambiguous' : 'missing', message: 'The retained observation changed during verification.'};
      if (eventCanonical(current[0]) !== canonical || actual !== ref.fingerprint) return {status: 'changed', message: 'The retained observation differs from the saved fingerprint.'};
      return {status: 'ready', token: canonical, message: 'Exact retained record and fingerprint. This does not authenticate its producer or establish causality.'};
    } catch {return {status: 'unavailable', message: 'The observation cannot be safely fingerprinted in this workspace.'};}
  }
  function stillMatches(ref, result, getContext) {
    if (result?.status !== 'ready') return false;
    try {
      if (ref.type === 'captured-event') {
        const matches = eventMatches(ref, getContext());
        return matches.length === 1 && eventCanonical(matches[0]) === result.token;
      }
      const artifacts = (getContext().artifacts ?? []).slice(0, 5000);
      const matches = artifacts.filter(value => String(value.artifact_id) === ref.artifact);
      return matches.length === 1 && String(matches[0].session_id) === ref.session && matches[0].sha256 === ref.sha256 && matches[0].byte_size === ref.bytes;
    } catch {return false;}
  }
  const folderProjection = folders => folders.map(folder => ({id: folder.id, name: folder.name, parent_id: folder.parent_id})).sort((a, b) => a.id - b.id);
  const describe = ref => ref.type === 'captured-artifact' ? `Session ${ref.session} · artifact ${ref.artifact}${ref.range ? ` · bytes ${ref.range.start}–${ref.range.end}` : ''}`
    : `Session ${ref.session} · process ${ref.process} · event ${ref.sequence}`;
  const projection = file => Object.fromEntries(['id', 'folder_id', 'name', 'kind', 'language', 'content'].map(key => [key, file[key]]));

  function createStore({fetcher = fetch, validateLibrary, changed = () => {}, timeout = 10000}) {
    const model = {library: null, busy: false, uncertain: false, notice: '', operation: 0};
    let active = null;
    function cancel() {
      if (!active) return;
      const operation = active; active = null; model.operation++; model.busy = false;
      if (operation.write) model.uncertain = true;
      model.notice = operation.write ? 'Save outcome is unknown. Reload the saved library before another write; cancellation cannot undo a committed save.' : 'Loading cancelled. Saved files are unchanged.';
      operation.controller.abort(); changed();
    }
    async function run(write, task) {
      if (model.busy || write && model.uncertain) return null;
      const owner = {id: ++model.operation, write, controller: new AbortController()}; active = owner; model.busy = true;
      model.notice = write ? 'Saving one local library generation…' : 'Loading the local Analyst library…'; changed();
      let timer, abort;
      const deadline = new Promise((_, reject) => {
        abort = () => reject(new Error('Operation cancelled.'));
        owner.controller.signal.addEventListener('abort', abort, {once: true});
        timer = setTimeout(() => {reject(new Error('The local operation timed out.')); owner.controller.abort();}, timeout);
      });
      try {
        const value = await Promise.race([task(owner.controller.signal), deadline]);
        if (active !== owner) return null;
        model.library = value; model.uncertain = false;
        model.notice = write ? 'Saved in the local Analyst library.' : 'Local library loaded. Saved references are checked only when opened.';
        return value;
      } catch (error) {
        if (active !== owner) return null;
        if (write) model.uncertain = true;
        model.notice = write ? `Save could not be confirmed. Reload before writing again. ${error.message}` : `Library unavailable. ${error.message}`;
        return null;
      } finally {
        clearTimeout(timer); owner.controller.signal.removeEventListener('abort', abort);
        if (active === owner) {active = null; model.busy = false; changed();}
      }
    }
    async function responseDocument(response, signal) {
      const bytes = await evidencePackageReadBytes(response, 1024 * 1024, signal);
      if (!response.ok) throw new Error(response.status === 409 ? 'Another window changed this library.' : `Local storage returned HTTP ${response.status}.`);
      const value = strictParse(new TextDecoder('utf-8', {fatal: true}).decode(bytes), 1024 * 1024);
      if (!validateLibrary(value)) throw new Error('The local library response is malformed.');
      return value;
    }
    const load = () => run(false, async signal => responseDocument(await fetcher('/api/local-analyst', {cache: 'no-store', signal}), signal));
    const save = (file, remove = false) => {
      const library = model.library;
      if (!library || model.uncertain || model.busy) return Promise.resolve(null);
      const old = library.files.find(value => value.id === file.id);
      if (old && (!readNotebook(old) || old.kind !== 'scratchpad' || old.language !== 'json')) {
        model.notice = 'This file is not a valid notebook. It was not overwritten.'; changed(); return Promise.resolve(null);
      }
      if (!remove && (!readNotebook(file) || !text(file.name, 128, false) || file.name.includes('/') || /[\n\r\t]/.test(file.name))) {
        model.notice = 'The notebook is invalid or exceeds its bounds.'; changed(); return Promise.resolve(null);
      }
      const files = library.files.filter(value => value.id !== file.id).map(projection);
      if (!remove) files.push(projection(file));
      if (files.length > 64 || files.reduce((sum, value) => sum + encoder.encode(value.content).length, 0) > 512 * 1024) {
        model.notice = 'The shared Analyst library is full. Existing files were preserved.'; changed(); return Promise.resolve(null);
      }
      const request = {action: 'replace_local_analyst_workspace', expected_generation: library.generation, folders: library.folders, files};
      return run(true, async signal => {
        const response = await fetcher('/api/local-analyst/actions', {method: 'POST', cache: 'no-store', signal,
          headers: {'Content-Type': 'application/json'}, body: JSON.stringify(request)});
        const value = await responseDocument(response, signal);
        if (![library.generation, library.generation + 1].includes(value.generation) ||
            JSON.stringify(folderProjection(value.folders)) !== JSON.stringify(folderProjection(library.folders)) || value.files.length !== files.length ||
            files.some(expected => !value.files.some(actual => JSON.stringify(projection(actual)) === JSON.stringify(expected))))
          throw new Error('The save receipt does not match the submitted library.');
        return value;
      });
    };
    return {model, load, save, cancel};
  }

  function mount({button, getContext, getSelection, openReference, validateLibrary, fetcher = fetch, protocol = location.protocol}) {
    const element = (tag, className, label) => {const node = document.createElement(tag); if (className) node.className = className; if (label !== undefined) node.textContent = label; return node;};
    const action = (id, label) => {const node = element('button', 'secondary-button', label); node.type = 'button'; node.id = `notebook-${id}`; return node;};
    const field = (label, node) => {const wrap = element('label', 'notebook-field'); wrap.append(element('span', '', label), node); return wrap;};
    const dialog = element('dialog', 'investigation-notebook'); dialog.id = 'investigation-notebook'; dialog.setAttribute('aria-labelledby', 'notebook-title');
    const heading = element('h2', '', 'Investigation notebook'); heading.id = 'notebook-title';
    const close = action('close', 'Close'), header = element('header', 'notebook-header'); header.append(heading, close);
    const scope = element('p', 'notebook-scope', 'Library-wide local notes, shared across this app’s sessions. Saves a non-executable JSON scratchpad in Analyst. Pins store identifiers and fingerprints, not captured content or permissions. Names and notes may contain private information; nothing is uploaded.');
    const notice = element('p', 'notebook-notice'); notice.id = 'notebook-notice'; notice.setAttribute('role', 'status'); notice.setAttribute('aria-live', 'polite');
    const controls = element('div', 'notebook-controls');
    const select = element('select'); select.id = 'notebook-select';
    const refresh = action('refresh', 'Reload library'), cancel = action('cancel', 'Cancel operation');
    controls.append(field('Saved notebook', select), refresh, cancel);
    const createForm = element('form', 'notebook-create');
    const newName = element('input'); newName.id = 'notebook-new-name'; newName.maxLength = 80; newName.autocomplete = 'off';
    const create = action('create', 'Create notebook'); create.type = 'submit'; createForm.append(field('New notebook name', newName), create);
    const split = element('div', 'notebook-split');
    const left = element('section', 'notebook-left'); left.setAttribute('aria-label', 'Saved evidence pins');
    const tools = element('div', 'notebook-actions'); const add = action('add', 'Pin selected evidence'); const removeBook = action('delete-book', 'Delete notebook'); tools.append(add, removeBook);
    const list = element('div', 'notebook-list'); list.id = 'notebook-list'; list.setAttribute('aria-label', 'Saved pins');
    left.append(tools, list);
    const editor = element('form', 'notebook-editor'); editor.id = 'notebook-editor';
    const label = element('input'); label.id = 'notebook-pin-name'; label.maxLength = 80; label.autocomplete = 'off';
    const note = element('textarea'); note.id = 'notebook-pin-note'; note.maxLength = 2048; note.rows = 7;
    const reference = element('p', 'notebook-reference'); reference.id = 'notebook-reference';
    const assurance = element('p', 'notebook-assurance'); assurance.id = 'notebook-assurance'; assurance.setAttribute('role', 'status');
    const editTools = element('div', 'notebook-actions');
    const save = action('save', 'Save pin'); save.type = 'submit';
    const discard = action('discard', 'Cancel edits'), open = action('open', 'Open exact evidence'), remove = action('delete-pin', 'Delete pin');
    editTools.append(save, discard, open, remove);
    editor.append(field('Pin name', label), field('Research note (your interpretation)', note), reference, assurance, editTools);
    split.append(left, editor); dialog.append(header, scope, controls, createForm, notice, split); document.body.append(dialog);
    let fileId = null, doc = null, selectedId = null, draft = null, baseContent = null, baseCreated = null;
    let dirty = false, stale = false, revision = 0, verifying = false, deleteKind = null, localNotice = '', opener = button;
    let previousBusy = false, busyTrigger = null, interactionRevision = 0;
    const supported = ['http:', 'https:', 'reb:'].includes(protocol);
    const store = createStore({fetcher, validateLibrary, changed: render});
    const currentFile = () => store.model.library?.files.find(file => file.id === fileId) ?? null;
    const currentPin = () => doc?.pins.find(pin => pin.id === selectedId) ?? null;
    function say(message) {localNotice = message; render();}
    function change() {revision++; verifying = false; deleteKind = null;}
    function choosePin(id) {
      if (dirty) {say('Save or cancel the current pin edits before selecting another pin.'); return false;}
      change(); selectedId = id; const pin = currentPin(); draft = pin ? structuredClone(pin) : null;
      label.value = pin?.name ?? ''; note.value = pin?.note ?? ''; assurance.textContent = ''; render(); return true;
    }
    function adopt(id) {
      fileId = id; const file = currentFile(); doc = readNotebook(file); baseContent = file?.content ?? null; baseCreated = file?.created_at_ms ?? null;
      dirty = false; stale = false; draft = null; selectedId = null; label.value = ''; note.value = ''; assurance.textContent = ''; change();
      if (file && !doc) localNotice = 'This notebook is malformed or uses an unsupported version. It remains an unchanged, inert Analyst scratchpad.';
      else localNotice = '';
    }
    function render() {
      const busy = store.model.busy || verifying, activeBefore = document.activeElement;
      if (busy && !previousBusy) busyTrigger = activeBefore;
      const files = candidates(store.model.library);
      const selectionSignature = JSON.stringify([files.map(file => [file.id, file.name]), fileId]);
      if (select.dataset.signature !== selectionSignature) {
        select.dataset.signature = selectionSignature; select.replaceChildren();
        const placeholder = element('option', '', files.length ? 'Choose a notebook' : 'No saved notebooks'); placeholder.value = ''; select.append(placeholder);
        for (const file of files) {const option = element('option', '', file.name); option.value = String(file.id); select.append(option);}
        select.value = fileId === null ? '' : String(fileId);
      }
      notice.textContent = !supported ? 'Open the local app or browser development UI to use the saved notebook.' : localNotice || store.model.notice;
      notice.dataset.kind = stale || store.model.uncertain ? 'warning' : 'normal';
      cancel.hidden = !busy; cancel.disabled = !busy;
      for (const node of [select, refresh, newName, create]) node.disabled = !supported || busy;
      create.disabled ||= !store.model.library || store.model.uncertain;
      add.disabled = !doc || busy || dirty || stale || store.model.uncertain || doc.pins.length >= PIN_MAX;
      removeBook.disabled = !doc || busy || dirty || stale || store.model.uncertain;
      removeBook.textContent = deleteKind === 'book' ? 'Confirm notebook delete' : 'Delete notebook';
      const listSignature = JSON.stringify([doc?.pins, selectedId, busy]);
      if (list.dataset.signature !== listSignature) {
        list.dataset.signature = listSignature; const scroll = list.scrollTop, focusId = list.contains(document.activeElement) ? document.activeElement.dataset.pinId : null;
        list.replaceChildren();
        if (!doc?.pins.length) list.append(element('p', 'notebook-empty', doc ? 'No pins yet. Select a captured source or native observation, then choose Pin selected evidence.' : 'Create or choose a notebook to keep evidence-linked notes.'));
        for (const pin of doc?.pins ?? []) {
          const row = action(`pin-${pin.id}`, ''); row.classList.add('notebook-pin'); row.dataset.pinId = String(pin.id); row.disabled = busy;
          row.setAttribute('aria-current', String(pin.id === selectedId)); row.append(element('strong', '', pin.name), element('span', '', describe(pin.reference)));
          row.addEventListener('click', () => choosePin(pin.id)); list.append(row);
        }
        list.scrollTop = scroll;
        if (focusId) list.querySelector(`[data-pin-id="${focusId}"]`)?.focus({preventScroll: true});
      }
      for (const node of [label, note]) node.disabled = !draft || busy;
      reference.textContent = draft ? `${describe(draft.reference)}. The pin does not preserve a request association or prove causality.` : 'Choose a pin to inspect or edit its note.';
      save.disabled = !draft || !dirty || busy || stale || store.model.uncertain;
      discard.disabled = !draft || busy && !verifying;
      open.disabled = !draft || dirty || busy || stale;
      remove.disabled = !currentPin() || dirty || busy || stale || store.model.uncertain;
      remove.textContent = deleteKind === 'pin' ? 'Confirm pin delete' : 'Delete pin';
      if (dialog.open && busy && (activeBefore?.disabled || !dialog.contains(activeBefore))) cancel.focus();
      if (dialog.open && !busy && previousBusy && activeBefore === cancel) {
        const target = [busyTrigger, open, close].find(node => node && !node.disabled && !node.hidden && dialog.contains(node));
        target?.focus({preventScroll: true});
      }
      previousBusy = busy;
    }
    async function reload() {
      if (dirty) {say('Cancel pin edits before reloading the saved library. Your draft is still here.'); return;}
      change(); const owner = revision; localNotice = '';
      const loaded = await store.load(); if (!loaded || revision !== owner) return;
      const files = candidates(loaded); adopt(files.some(file => file.id === fileId) ? fileId : null); render(); return revision;
    }
    async function show() {
      opener = document.activeElement ?? button; change(); const interaction = interactionRevision; dialog.showModal(); render();
      if (!supported) {close.focus(); return;}
      if (dirty) {say('Your unsaved pin draft is preserved. Save or cancel its edits to reload.'); label.focus(); return;}
      const settled = await reload(); if (settled === revision && interaction === interactionRevision && dialog.open) (candidates(store.model.library).length ? select : newName).focus();
    }
    function hide() {
      change(); store.cancel(); dialog.close(); opener?.focus({preventScroll: true});
    }
    async function persist(candidate, message, removeFile = false) {
      const owner = revision; localNotice = '';
      const result = await store.save(candidate, removeFile);
      if (!result || revision !== owner) {render(); return false;}
      const pinId = selectedId; adopt(removeFile ? null : candidate.id); if (!removeFile && doc?.pins.some(pin => pin.id === pinId)) choosePin(pinId);
      say(message); return true;
    }
    createForm.addEventListener('submit', async event => {
      event.preventDefault(); if (store.model.busy || dirty || !store.model.library) {if (dirty) say('Save or cancel pin edits before creating another notebook.'); return;}
      const title = newName.value.trim(), name = `${title}.reb-notebook.json`;
      if (!text(title, 80, false) || /[\/\n\r\t]/.test(title)) {say('Use a notebook name of at most 80 UTF-8 bytes, without slashes or control characters.'); return;}
      const library = store.model.library;
      if (library.files.some(file => file.folder_id === 1 && file.name.toLocaleLowerCase() === name.toLocaleLowerCase()) || library.folders.some(folder => folder.parent_id === 1 && folder.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {say('That name already exists in the Analyst root folder. Choose another name.'); return;}
      const id = Math.max(0, ...library.files.map(file => file.id)) + 1;
      if (!integer(id, 1)) {say('The local file identifier limit was reached.'); return;}
      change(); const interaction = interactionRevision; if (await persist({id, folder_id: 1, name, kind: 'scratchpad', language: 'json', content: JSON.stringify(empty())}, 'Notebook created as a non-executable Analyst scratchpad.')) {newName.value = ''; if (interaction === interactionRevision) add.focus();}
    });
    select.addEventListener('change', () => {
      if (dirty) {select.value = String(fileId ?? ''); say('Save or cancel pin edits before changing notebooks.'); return;}
      adopt(select.value ? Number(select.value) : null); render();
    });
    refresh.addEventListener('click', reload);
    button.addEventListener('click', show); close.addEventListener('click', hide);
    dialog.addEventListener('cancel', event => {event.preventDefault(); hide();});
    dialog.addEventListener('keydown', event => {interactionRevision++; event.stopPropagation();});
    dialog.addEventListener('pointerdown', () => {interactionRevision++;});
    cancel.addEventListener('click', () => {change(); store.cancel(); localNotice = ''; render(); close.focus({preventScroll: true});});
    for (const control of [label, note]) control.addEventListener('input', () => {if (!draft) return; change(); dirty = true; draft.name = label.value; draft.note = note.value; assurance.textContent = ''; render();});
    discard.addEventListener('click', () => {change(); dirty = false; draft = null; choosePin(selectedId); localNotice = ''; render();});
    add.addEventListener('click', async () => {
      if (add.disabled) return; change(); const owner = revision, interaction = interactionRevision; verifying = true; localNotice = 'Checking the exact selected evidence…'; render();
      try {
        const selection = getSelection();
        if (!selection) throw new Error('Select a captured source or a native observation first. Live scripts and correlated debugger requests cannot be pinned.');
        const ref = selection.kind === 'artifact' ? artifactReference(selection.artifact, selection.range) : await eventReference(selection.event, getContext);
        const status = await resolve(ref, getContext);
        if (revision !== owner) return;
        if (!stillMatches(ref, status, getContext)) throw new Error(status.status === 'ready' ? 'The selected evidence changed before it could be pinned.' : status.message);
        selectedId = null; draft = {id: doc.next_pin_id, name: ref.type === 'captured-artifact' ? `Artifact ${ref.artifact}` : `Event ${ref.sequence}`, note: '', reference: ref};
        label.value = draft.name; note.value = ''; dirty = true; localNotice = 'Name this pin and add your interpretation. Save pin explicitly stores the reference and note.';
      } catch (error) {if (revision === owner) localNotice = error.message;}
      finally {if (revision === owner) {verifying = false; render(); if (interaction === interactionRevision && draft && dirty && selectedId === null) {label.focus(); label.select();}}}
    });
    editor.addEventListener('submit', async event => {
      event.preventDefault(); if (save.disabled) return;
      const file = currentFile();
      if (!file || file.content !== baseContent || file.created_at_ms !== baseCreated) {stale = true; say('The saved notebook owner changed. Cancel edits and reload before saving.'); return;}
      const pin = {...structuredClone(draft), name: label.value.trim(), note: note.value};
      const candidate = structuredClone(doc); const existing = candidate.pins.findIndex(value => value.id === pin.id);
      if (existing < 0) {candidate.pins.push(pin); candidate.next_pin_id++;} else candidate.pins[existing] = pin;
      if (!validate(candidate)) {say('Pin names allow 80 UTF-8 bytes, notes 2 KiB, and notebooks 64 pins / 32 KiB. Nothing was saved.'); return;}
      change(); const owner = revision, interaction = interactionRevision;
      if (existing < 0) {
        verifying = true; localNotice = 'Rechecking the new pin before saving…'; render();
        try {
          const status = await resolve(pin.reference, getContext);
          if (revision !== owner) return;
          if (!stillMatches(pin.reference, status, getContext)) {say(status.status === 'ready' ? 'The new pin’s evidence changed before saving.' : status.message); return;}
        } catch {
          if (revision === owner) localNotice = 'New pin verification failed. Your draft is preserved; review the retained evidence and retry.';
          return;
        } finally {if (revision === owner) {verifying = false; render();}}
      }
      selectedId = pin.id;
      if (await persist({...projection(file), content: JSON.stringify(candidate)}, 'Pin and note saved locally.') && interaction === interactionRevision) open.focus();
    });
    open.addEventListener('click', async () => {
      if (open.disabled) return; change(); const owner = revision, ref = structuredClone(draft.reference); verifying = true; assurance.textContent = 'Checking exact retained evidence…'; render();
      let result;
      try {result = await resolve(ref, getContext);}
      catch {result = {status: 'unavailable', message: 'This saved reference could not be checked. Nothing was opened; retry after reviewing retained evidence.'};}
      finally {if (revision === owner) {verifying = false; render();}}
      if (revision !== owner || !dialog.open) return;
      assurance.textContent = result.message; assurance.dataset.status = result.status; render();
      if (result.status !== 'ready') return;
      // Recheck synchronously after the async digest result reaches this owner.
      if (!stillMatches(ref, result, getContext)) {assurance.textContent = 'The exact observation changed before opening. Nothing was substituted.'; assurance.dataset.status = 'changed'; return;}
      // The receiving adapter rechecks the same identity before changing a view.
      if (openReference(ref, result.token)) hide(); else {assurance.textContent = 'The evidence changed or its exact receiving view is unavailable. Nothing was substituted.'; assurance.dataset.status = 'unavailable';}
    });
    remove.addEventListener('click', async () => {
      if (remove.disabled) return;
      if (deleteKind !== 'pin') {deleteKind = 'pin'; say('Choose Confirm pin delete to remove this saved reference and note. Captured evidence stays unchanged.'); return;}
      change(); const candidate = {...doc, pins: doc.pins.filter(pin => pin.id !== selectedId)};
      await persist({...projection(currentFile()), content: JSON.stringify(candidate)}, 'Pin deleted. Captured evidence is unchanged.');
    });
    removeBook.addEventListener('click', async () => {
      if (removeBook.disabled) return;
      if (deleteKind !== 'book') {deleteKind = 'book'; say('Choose Confirm notebook delete to remove this notebook scratchpad. Other Analyst files and captured evidence stay unchanged.'); return;}
      change(); await persist(projection(currentFile()), 'Notebook deleted. Other Analyst files are unchanged.', true);
    });
    window.addEventListener('pagehide', () => {change(); store.cancel();});
    render();
    return {show, close: hide, model: store.model, dialog};
  }
  globalThis.RebInvestigationNotebook = Object.freeze({empty, validate, validReference, strictParse, readNotebook, candidates,
    eventCanonical, eventReference, artifactReference, resolve, stillMatches, describe, createStore, mount});
}());
