/* Sources debugger sidebar (docs/product/native-debugger-v1.md). Phase 1 is
 * native observation that never pauses: threads, watch rules and observation
 * records come from get_native_debugger, and positions from get_request_stack.
 * Sections come from one registry, RebDebuggerSidebar.addSection, so a later
 * change adds its own sections without rewriting these. Only rows in view are
 * mounted, a closed sidebar runs no timers and makes no requests, and every
 * captured value reaches the DOM as text. */
// A read waits at least `poll`, and four times as long as the last read took,
// so a large store is never read back to back.
const DEBUGGER_SIDEBAR = Object.freeze({poll: 2000, slowest: 30000, deadline: 10000, retry: 2000, page: 128, rows: 4096, stacks: 32,
  threadRow: 40, groupRow: 26, observationRow: 44, overscan: 6, listHeight: 240});

const DEBUGGER_OBSERVATION_KINDS = Object.freeze({
  request_watch_match: {label: 'Request', filter: 'Requests'},
  listener_dispatch: {label: 'Listener', filter: 'Listeners'},
  timer_observation: {label: 'Timer', filter: 'Timers'},
  csp_violation: {label: 'CSP', filter: 'CSP'},
  exception_observation: {label: 'Exception', filter: 'Exceptions'},
  dom_mutation: {label: 'DOM', filter: 'DOM'}
});
const DEBUGGER_WORKER_KINDS = Object.freeze({dedicated_worker: 'Dedicated worker', shared_worker: 'Shared worker',
  service_worker: 'Service worker'});
const DEBUGGER_STACK_STATES = Object.freeze({captured: 'stack captured', no_script: 'no script on the stack',
  unsupported_thread: 'stack not recorded on this thread', not_retained_artifact_unavailable: 'stack not retained (Artifact off)',
  not_retained_budget: 'stack not retained (budget)'});
const DEBUGGER_ID = /^(0|[1-9][0-9]{0,19})$/;

// The registry is ready before the sidebar mounts: index.html loads this file
// second, so any later script can add sections whenever it evaluates.
const debuggerSidebarSections = new Map();
let debuggerSidebarController = null;

function debuggerSidebarSection(section) {
  if (!section || typeof section !== 'object') throw new TypeError('A debugger sidebar section is an object');
  const {id, title, order, render, summary = null, release = null, collapsed = false, native = null} = section;
  if (typeof id !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(id)) throw new TypeError('Section id must be 1 to 32 lowercase letters, digits or dashes');
  if (typeof title !== 'string' || !title.trim() || title.length > 64) throw new TypeError('Section title must be 1 to 64 characters');
  if (!Number.isFinite(order)) throw new TypeError('Section order must be a finite number');
  if (typeof render !== 'function') throw new TypeError('Section render must be a function');
  if (summary !== null && typeof summary !== 'function') throw new TypeError('Section summary must be a function');
  if (release !== null && typeof release !== 'function') throw new TypeError('Section release must be a function');
  if (typeof collapsed !== 'boolean') throw new TypeError('Section collapsed must be true or false');
  // `pausing`: the section presents the pausing debugger get_native_debugger
  // reports, the only place the paused-state vocabulary belongs.
  if (native !== null && native !== 'pausing') throw new TypeError('Section native must be pausing when given');
  return Object.freeze({id, title, order, render, summary, release, collapsed, native});
}

globalThis.RebDebuggerSidebar = Object.freeze({
  // Adds a section, or replaces the one with the same id; returns its removal.
  addSection(section) {
    const entry = debuggerSidebarSection(section);
    debuggerSidebarSections.set(entry.id, entry);
    debuggerSidebarController?.sectionsChanged();
    return () => {
      if (debuggerSidebarSections.get(entry.id) !== entry) return;
      debuggerSidebarSections.delete(entry.id);
      debuggerSidebarController?.sectionsChanged();
    };
  },
  open: () => debuggerSidebarController?.setOpen(true),
  close: () => debuggerSidebarController?.setOpen(false),
  isOpen: () => Boolean(debuggerSidebarController?.isOpen()),
  // The Sources tree scope, while the sidebar is open and a thread allows one.
  sourceScope: () => debuggerSidebarController?.sourceScope() ?? null
});

function debuggerNode(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function debuggerButton(text, className, onClick) {
  const button = debuggerNode('button', className, text);
  button.type = 'button';
  button.addEventListener('click', onClick);
  return button;
}

function debuggerTime(ns) {
  try {
    const micros = BigInt(ns) / 1000n;
    return `${(micros / 1000000n).toString()}.${(micros % 1000000n).toString().padStart(6, '0')} s`;
  } catch {
    return 'time not recorded';
  }
}

function debuggerRecordKey(record) {
  return `${record.session_id}:${record.process_id}:${record.sequence_number}`;
}

function debuggerCategory(type) {
  return type === 'request_watch_match' ? 'network' : 'runtime';
}

// What happened, in the words of the record's decoded detail.
function debuggerObservationText(record) {
  const detail = record.detail ?? {};
  switch (record.type) {
    case 'request_watch_match':
      return `Request rule ${Number(detail.rule) + 1} matched${detail.method_matched ? ', method too' : ''}`;
    case 'listener_dispatch':
      return `${detail.event_type} listener on ${detail.target}${detail.listener ? '' : ' (object or native listener)'}`;
    case 'timer_observation':
      return `${detail.kind === 'interval' ? 'setInterval' : 'setTimeout'} ${detail.phase}, timer ${detail.timer_id}` +
        `${detail.delay_ms ? `, ${detail.delay_ms} ms` : ''}${detail.string_callback ? ', string callback' : ''}`;
    case 'csp_violation':
      return `${detail.directive} ${detail.disposition === 'enforce' ? 'blocked' : 'reported'} ${detail.blocked_host || '(host not recorded)'}`;
    case 'exception_observation':
      return {uncaught: 'Uncaught exception', caught: 'Caught exception', unhandled_rejection: 'Unhandled rejection'}[detail.kind] ?? 'Exception';
    case 'dom_mutation':
      return detail.kind === 'attribute' ? `Attribute ${detail.attribute} changed on element ${Number(detail.node_slot) + 1}`
        : detail.kind === 'subtree' ? `Subtree changed under element ${Number(detail.node_slot) + 1}`
          : `Element ${Number(detail.node_slot) + 1} or a child removed`;
    default:
      return record.type;
  }
}

// The record's own frame: a listener, a timer callback or a throw site.
function debuggerSite(record) {
  const detail = record.detail ?? {};
  return detail.listener ?? detail.callback ?? detail.site ?? null;
}

function debuggerValidObservation(record) {
  return Boolean(record && Object.hasOwn(DEBUGGER_OBSERVATION_KINDS, record.type) &&
    ['session_id', 'frame_id', 'sequence_number', 'parent_event_id', 'request_id', 'monotonic_time_ns'].every(field => DEBUGGER_ID.test(String(record[field]))) &&
    Number.isSafeInteger(record.process_id) && record.stack && typeof record.stack === 'object' && record.detail && typeof record.detail === 'object');
}

// The shape this sidebar reads; anything else is malformed and not used.
function debuggerDocumentProblem(answer) {
  if (!answer || typeof answer !== 'object') return 'the answer is not an object';
  if (answer.contract_version !== 1) return 'an unknown contract version';
  if (!['unsupported', 'available'].includes(answer.availability)) return 'an unknown availability';
  const threads = answer.threads;
  if (!threads || !Array.isArray(threads.frames) || !Array.isArray(threads.workers) || !Array.isArray(threads.observed)) return 'the thread listing is missing';
  if (!answer.watch || !['none', 'armed', 'busy'].includes(answer.watch.state)) return 'the watch state is missing';
  if (!Array.isArray(answer.observations) || !Number.isSafeInteger(answer.observations_malformed)) return 'the observations are missing';
  if (!answer.observations_query || !Array.isArray(answer.observation_budget_gaps)) return 'the observation read is missing';
  return null;
}

/* A fixed-row listbox that mounts only the rows in view. Items are
 * {key, height, header?, ...}; headers are not options. The list keeps focus
 * itself and names the active row with aria-activedescendant, so a row
 * scrolled away never takes focus with it. */
function createDebuggerList({id, label, onActive = null, onChoose, render}) {
  const element = debuggerNode('div', 'debugger-list');
  element.id = id;
  element.tabIndex = 0;
  element.setAttribute('role', 'listbox');
  element.setAttribute('aria-label', label);
  const space = debuggerNode('div', 'debugger-list-space');
  element.append(space);
  let items = [], tops = [0], options = [], active = null, selected = null, signature = '', frame = 0;
  const rowId = key => `${id}-row-${String(key).replace(/[^A-Za-z0-9_-]/g, '-')}`;
  const indexOf = key => items.findIndex(item => item.key === key);

  function paint() {
    frame = 0;
    const height = element.clientHeight || DEBUGGER_SIDEBAR.listHeight;
    const top = element.scrollTop;
    let first = 0;
    while (first < items.length && tops[first + 1] <= top) first += 1;
    let last = first;
    while (last < items.length && tops[last] < top + height) last += 1;
    const start = Math.max(0, first - DEBUGGER_SIDEBAR.overscan), end = Math.min(items.length, last + DEBUGGER_SIDEBAR.overscan);
    const wanted = new Set();
    for (let index = start; index < end; index += 1) wanted.add(index);
    // The active row stays mounted so aria-activedescendant always names a node.
    const activeIndex = active === null ? -1 : indexOf(active);
    if (activeIndex >= 0) wanted.add(activeIndex);
    const rows = [...wanted].sort((left, right) => left - right).map(index => {
      const item = items[index];
      const row = debuggerNode('div', item.header ? 'debugger-list-group' : 'debugger-list-row');
      row.style.top = `${tops[index]}px`;
      row.style.height = `${item.height}px`;
      if (item.header) {
        row.setAttribute('role', 'presentation');
      } else {
        row.id = rowId(item.key);
        row.setAttribute('role', 'option');
        row.setAttribute('aria-selected', String(item.key === selected));
        row.setAttribute('aria-posinset', String(options.indexOf(item) + 1));
        row.setAttribute('aria-setsize', String(options.length));
        row.dataset.key = item.key;
        if (item.key === active) row.dataset.active = 'true';
      }
      render(row, item);
      return row;
    });
    space.replaceChildren(...rows);
    if (active !== null && activeIndex >= 0) element.setAttribute('aria-activedescendant', rowId(active));
    else element.removeAttribute('aria-activedescendant');
  }
  const schedule = () => {
    if (frame) return;
    frame = typeof requestAnimationFrame === 'function' ? requestAnimationFrame(paint) || -1 : -1;
    if (frame === -1) paint();
  };

  function reveal(key) {
    const index = indexOf(key);
    if (index < 0) return;
    const height = element.clientHeight || DEBUGGER_SIDEBAR.listHeight;
    if (tops[index] < element.scrollTop) element.scrollTop = tops[index];
    else if (tops[index + 1] > element.scrollTop + height) element.scrollTop = tops[index + 1] - height;
  }
  function move(next) {
    if (!options.length) return;
    const item = options[Math.max(0, Math.min(options.length - 1, next))];
    active = item.key;
    reveal(item.key);
    paint();
    onActive?.(item);
  }
  element.addEventListener('keydown', event => {
    if (event.altKey || event.metaKey || event.ctrlKey) return;
    const at = options.findIndex(item => item.key === active);
    const page = Math.max(1, Math.floor((element.clientHeight || DEBUGGER_SIDEBAR.listHeight) * items.length / Math.max(1, tops.at(-1))));
    const moves = {ArrowDown: at + 1, ArrowUp: at < 0 ? 0 : at - 1, Home: 0, End: options.length - 1, PageDown: at + page, PageUp: at - page};
    if (Object.hasOwn(moves, event.key)) { event.preventDefault(); move(moves[event.key]); return; }
    if ((event.key === 'Enter' || event.key === ' ') && at >= 0) { event.preventDefault(); onChoose(options[at], event.key); }
  });
  element.addEventListener('click', event => {
    const row = event.target.closest?.('.debugger-list-row');
    if (!row) return;
    const item = options.find(option => option.key === row.dataset.key);
    if (!item) return;
    active = item.key;
    paint();
    element.focus({preventScroll: true});
    onActive?.(item);
    onChoose(item, 'click');
  });
  element.addEventListener('dblclick', event => {
    const row = event.target.closest?.('.debugger-list-row');
    const item = row && options.find(option => option.key === row.dataset.key);
    if (item) onChoose(item, 'dblclick');
  });
  element.addEventListener('scroll', schedule, {passive: true});

  return {
    element,
    // Same keys in the same order repaint only the selection marks.
    set(next, {selectedKey = selected, anchor = true} = {}) {
      const nextSignature = next.map(item => `${item.key}/${item.version ?? ''}`).join('|');
      const changed = nextSignature !== signature;
      // Rows that arrive above the view do not move it.
      const height = element.clientHeight || DEBUGGER_SIDEBAR.listHeight;
      let kept = null;
      if (changed && anchor && element.scrollTop > 0 && items.length) {
        let first = 0;
        while (first < items.length - 1 && tops[first + 1] <= element.scrollTop) first += 1;
        kept = {key: items[first].key, offset: element.scrollTop - tops[first]};
      }
      selected = selectedKey;
      if (changed) {
        items = next;
        signature = nextSignature;
        options = items.filter(item => !item.header);
        tops = [0];
        for (const item of items) tops.push(tops.at(-1) + item.height);
        space.style.height = `${tops.at(-1)}px`;
        if (active !== null && indexOf(active) < 0) active = null;
        if (kept) {
          const at = indexOf(kept.key);
          if (at >= 0) element.scrollTop = Math.min(tops[at] + kept.offset, Math.max(0, tops.at(-1) - height));
        }
      }
      if (active === null && selected !== null && indexOf(selected) >= 0) active = selected;
      paint();
    },
    focus() { element.focus({preventScroll: true}); },
    release() { if (frame > 0 && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(frame); frame = 0; space.replaceChildren(); items = []; options = []; tops = [0]; signature = ''; active = null; }
  };
}

/* Threads: Console documents, workers whose requests the renderer recorded,
 * and the native frames observation records came from. It needs only the
 * get_native_debugger document, so it stands on its own wherever it mounts. */
function debuggerThreads(answer, {frameOrigin = () => null, consoleTarget = null} = {}) {
  const threads = answer?.threads ?? {frames: [], workers: [], observed: []};
  const armed = answer?.watch?.state === 'armed' ? answer.watch.armed?.target_id ?? null : null;
  const documents = threads.frames.map(target => ({
    key: `D:${target.target_id}`, kind: 'document', target_id: String(target.target_id), group: 'Console documents',
    title: target.frame === 'top' ? 'Top frame' : target.out_of_process === true ? 'Out-of-process frame' : 'Child frame',
    origin: target.origin || '(no origin)',
    frame: `${target.frame} · document ${target.target_id}`,
    process: target.frame === 'top' ? 'process not listed'
      : target.out_of_process === true ? 'own renderer (site isolation)' : target.out_of_process === false ? 'top renderer' : 'process undetermined',
    state: String(target.target_id) === armed ? 'watch armed' : String(target.target_id) === consoleTarget ? 'Console connected' : 'listed'
  }));
  const workers = threads.workers.map(worker => ({
    key: `W:${worker.session_id}:${worker.process_id}:${worker.context_id}`, kind: 'worker', group: 'Workers',
    session_id: worker.session_id, process_id: worker.process_id, context_id: worker.context_id,
    title: DEBUGGER_WORKER_KINDS[worker.kind] ?? 'Worker', origin: 'origin not recorded', missing: true,
    frame: `context ${worker.context_id}`, process: `process ${worker.process_id}`, last: worker.last_sequence,
    state: `${worker.requests} ${worker.requests === 1 ? 'request' : 'requests'}`
  }));
  const observed = threads.observed.map(frame => ({
    key: `F:${frame.session_id}:${frame.process_id}:${frame.frame_id}`, kind: 'observed', group: 'Observed frames',
    session_id: frame.session_id, process_id: frame.process_id, frame_id: frame.frame_id,
    title: 'Observed frame', origin: frameOrigin(frame.session_id, frame.frame_id), last: frame.last_sequence,
    frame: `frame ${frame.frame_id} · session ${frame.session_id}`, process: `process ${frame.process_id}`,
    state: `${frame.records} ${frame.records === 1 ? 'record' : 'records'}`
  })).map(frame => frame.origin ? frame : {...frame, origin: 'no retained document', missing: true});
  return [documents, observed, workers];
}

function createDebuggerThreadsView({id = 'debugger-threads', onSelect}) {
  const root = debuggerNode('div', 'debugger-threads');
  const list = createDebuggerList({id, label: 'Threads', onChoose: item => onSelect(item), render(row, item) {
    if (item.header) {
      row.append(debuggerNode('span', 'debugger-list-group-name', item.title), debuggerNode('b', 'debugger-list-count', item.count));
      return;
    }
    row.dataset.kind = item.kind;
    const head = debuggerNode('div', 'debugger-row-head');
    const origin = debuggerNode('span', 'debugger-row-main', item.origin);
    if (item.missing) origin.dataset.missing = 'true';
    head.append(debuggerNode('span', 'debugger-chip', item.title), origin, debuggerNode('span', 'debugger-row-state', item.state));
    const meta = debuggerNode('div', 'debugger-row-meta', `${item.frame} · ${item.process}`);
    row.title = [item.title, item.origin, item.frame, item.process, item.state, item.last ? `last record #${item.last}` : ''].filter(Boolean).join(' · ');
    row.append(head, meta);
  }});
  const empty = debuggerNode('p', 'debugger-note');
  root.append(list.element, empty);
  return {
    element: root,
    render(groups, selectedKey) {
      const items = [];
      for (const group of groups) {
        if (!group.length) continue;
        items.push({key: `group:${group[0].group}`, header: true, title: group[0].group, count: group.length, height: DEBUGGER_SIDEBAR.groupRow});
        for (const thread of group) items.push({...thread, height: DEBUGGER_SIDEBAR.threadRow, version: `${thread.state}|${thread.origin}|${thread.last ?? ''}`});
      }
      list.element.hidden = !items.length;
      empty.hidden = Boolean(items.length);
      empty.textContent = 'No threads listed. Connect the Console to a live capture to list its documents; workers and frames appear once the renderer records their requests or observations.';
      list.set(items, {selectedKey});
    },
    release() { list.release(); }
  };
}

function createDebuggerSidebar({root, toggle, screen, hooks}) {
  root.replaceChildren();
  const head = debuggerNode('header', 'debugger-sidebar-head');
  const title = debuggerNode('h2', 'debugger-sidebar-title', 'Debugger');
  title.id = 'debugger-sidebar-title';
  const mode = debuggerNode('span', 'debugger-sidebar-mode', 'Observes, never pauses');
  mode.title = 'Native observation records only. Nothing here pauses, steps or reads a value.';
  // A narrow toolbar keeps the toggle in the More menu; focus goes to More then.
  const focusToggle = () => (toggle.closest('details:not([open])')?.querySelector('summary') ?? toggle).focus({preventScroll: true});
  const close = debuggerButton('×', 'debugger-sidebar-close', () => { setOpen(false); focusToggle(); });
  close.setAttribute('aria-label', 'Close debugger');
  close.title = 'Close debugger (Esc)';
  head.append(title, mode, close);
  const status = debuggerNode('p', 'debugger-sidebar-status');
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  const body = debuggerNode('div', 'debugger-sidebar-sections');
  root.append(head, status, body);
  root.setAttribute('aria-labelledby', title.id);

  let open = false, timer = 0, reading = null, generation = 0, interval = DEBUGGER_SIDEBAR.poll;
  const mounted = new Map();
  const view = {
    status: 'loading', document: null, error: null, updatedAt: null, thread: null, kind: null,
    // `refused` counts rows of these pages that failed this view's own checks.
    observations: {key: null, head: [], older: [], refused: 0, olderRefused: 0, firstBefore: null, next: null, loadingOlder: false, olderError: null},
    refresh: () => read(),
    selectThread(thread) {
      view.thread = thread && view.thread?.key === thread.key ? null : thread;
      hooks.refreshTree?.();
      read();
    },
    setKind(kind) {
      view.kind = Object.hasOwn(DEBUGGER_OBSERVATION_KINDS, kind) ? kind : null;
      read();
    },
    older: () => readOlder(),
    hooks
  };

  const visible = () => open && !screen.hidden && hooks.available();
  function query(extra = {}) {
    const parameters = new URLSearchParams({limit: String(DEBUGGER_SIDEBAR.page)});
    if (view.kind) parameters.set('type', view.kind);
    if (view.thread?.kind === 'observed') {
      parameters.set('session_id', view.thread.session_id);
      parameters.set('process_id', String(view.thread.process_id));
      parameters.set('frame_id', view.thread.frame_id);
    }
    for (const [key, value] of Object.entries(extra)) parameters.set(key, value);
    return parameters;
  }
  const observationKey = () => `${view.kind ?? 'all'}|${view.thread?.kind === 'observed' ? view.thread.key : 'all'}`;

  async function fetchDocument(parameters) {
    const response = await hooks.fetch(`/api/native-debugger?${parameters}`, {cache: 'no-store', signal: AbortSignal.timeout(DEBUGGER_SIDEBAR.deadline)});
    const value = await response.json().catch(() => null);
    if (!response.ok) throw new Error(typeof value?.error === 'string' ? value.error : `the backend returned HTTP ${response.status}`);
    const problem = debuggerDocumentProblem(value);
    if (problem) { const error = new Error(problem); error.malformed = true; throw error; }
    return value;
  }

  // Newer records first; an older page is kept only while no record can be
  // missing between it and the newest page.
  function applyHead(answer) {
    const observations = view.observations, key = observationKey();
    if (observations.key !== key) Object.assign(observations, {key, older: [], olderRefused: 0, firstBefore: null, next: null, olderError: null});
    observations.head = answer.observations.filter(debuggerValidObservation);
    observations.refused = answer.observations.length - observations.head.length;
    const headNext = answer.observations_query.next_before ?? null;
    if (observations.older.length && (headNext === null || BigInt(headNext) > BigInt(observations.firstBefore))) {
      Object.assign(observations, {older: [], olderRefused: 0, firstBefore: null, next: null});
    }
    if (!observations.older.length) observations.next = headNext;
  }

  async function read() {
    clearTimeout(timer);
    timer = 0;
    if (!visible()) {
      if (open && !hooks.available()) { view.status = 'unavailable'; render(); }
      return;
    }
    const mine = ++generation, started = Date.now();
    reading = fetchDocument(query());
    try {
      const answer = await reading;
      if (mine !== generation) return;
      view.document = answer;
      view.status = 'ready';
      view.error = null;
      view.updatedAt = new Date();
      applyHead(answer);
    } catch (error) {
      if (mine !== generation) return;
      view.status = error?.malformed ? 'malformed' : 'disconnected';
      view.error = error?.name === 'TimeoutError' ? 'the backend did not answer within 10 seconds' : String(error?.message ?? error);
    } finally {
      if (mine === generation) {
        reading = null;
        interval = Math.min(DEBUGGER_SIDEBAR.slowest, Math.max(DEBUGGER_SIDEBAR.poll, 4 * (Date.now() - started)));
        render();
        if (visible()) timer = setTimeout(read, interval);
      }
    }
  }

  async function readOlder() {
    const observations = view.observations, key = observations.key;
    if (observations.loadingOlder || observations.next === null || !visible()) return;
    const before = observations.next;
    observations.loadingOlder = true;
    render();
    try {
      const answer = await fetchDocument(query({before}));
      if (observations.key !== key) return;
      const valid = answer.observations.filter(debuggerValidObservation);
      observations.older.push(...valid);
      observations.olderRefused += answer.observations.length - valid.length;
      observations.firstBefore ??= before;
      observations.next = answer.observations_query.next_before ?? null;
      observations.olderError = null;
    } catch (error) {
      observations.olderError = String(error?.message ?? error);
    } finally {
      observations.loadingOlder = false;
      render();
    }
  }

  function renderStatus() {
    const when = view.updatedAt ? view.updatedAt.toLocaleTimeString() : null;
    const text = {
      loading: 'Reading the native debugger state…',
      unavailable: 'No backend serves this window, so the debugger state cannot be read.',
      ready: `Updated ${when}. Read every ${Math.round(interval / 1000)} seconds while open.`,
      disconnected: when ? `Disconnected: ${view.error}. Showing what was read at ${when}; reading again.` : `Cannot read the native debugger state: ${view.error}. Reading again.`,
      malformed: when ? `The last answer was malformed (${view.error}) and was not used. Showing what was read at ${when}.` : `The answer was malformed (${view.error}) and was not used.`
    }[view.status];
    status.textContent = text;
    status.dataset.kind = view.status;
    root.dataset.state = view.status;
  }

  function sections() {
    return [...debuggerSidebarSections.values()].sort((left, right) => left.order - right.order || (left.id < right.id ? -1 : 1));
  }
  function release(entry) {
    try { entry.section.release?.(entry.body); } catch (error) { console.error('Debugger sidebar section release failed', error); }
  }
  // Mounts every registered section in order; only expanded ones render.
  function render() {
    if (!open) return;
    renderStatus();
    const wanted = sections();
    for (const [id, entry] of mounted) {
      if (!wanted.some(section => section.id === id && section === entry.section)) { release(entry); entry.details.remove(); mounted.delete(id); }
    }
    wanted.forEach((section, index) => {
      let entry = mounted.get(section.id);
      if (!entry) {
        const details = debuggerNode('details', 'debug-pane debugger-section');
        details.dataset.debuggerSection = section.id;
        if (section.native) details.dataset.debuggerNative = section.native;
        details.open = !section.collapsed;
        const summary = debuggerNode('summary');
        const name = debuggerNode('span', 'debugger-section-title', section.title);
        const count = debuggerNode('span', 'debugger-section-count');
        summary.append(name, count);
        const sectionBody = debuggerNode('div', 'debug-pane-body debugger-section-body');
        details.append(summary, sectionBody);
        entry = {section, details, body: sectionBody, count};
        details.addEventListener('toggle', () => { if (details.open) paintSection(entry); else release(entry); });
        mounted.set(section.id, entry);
      }
      if (body.children[index] !== entry.details) body.insertBefore(entry.details, body.children[index] ?? null);
      paintSection(entry);
    });
  }
  function paintSection(entry) {
    entry.details.dataset.stale = String(view.status !== 'ready' && view.document !== null);
    try {
      entry.count.textContent = entry.section.summary ? String(entry.section.summary(view) ?? '') : '';
      if (entry.details.open) entry.section.render(entry.body, view);
    } catch (error) {
      console.error('Debugger sidebar section failed', error);
      entry.body.replaceChildren(debuggerNode('p', 'debugger-note debugger-note-error', `This section failed to render: ${error?.message ?? error}`));
    }
  }

  function setOpen(value) {
    if (open === value) return;
    open = value;
    root.hidden = !open;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-pressed', String(open));
    if (open) {
      hooks.closeDetails();
      hooks.syncLayout(true);
      view.status = view.document ? view.status : 'loading';
      render();
      read();
    } else {
      generation += 1;
      clearTimeout(timer);
      timer = 0;
      for (const entry of mounted.values()) release(entry);
      hooks.syncLayout(false);
    }
    hooks.refreshTree?.();
  }

  toggle.addEventListener('click', () => {
    setOpen(!open);
    if (open) body.querySelector('summary')?.focus({preventScroll: true});
  });
  root.addEventListener('keydown', event => {
    if (event.key !== 'Escape' || event.defaultPrevented) return;
    event.preventDefault();
    if (hooks.overlays()) setOpen(false);
    focusToggle();
  });
  // Leaving Sources stops the reads; coming back resumes them.
  if (typeof MutationObserver === 'function') {
    new MutationObserver(() => { if (visible() && !reading && !timer) read(); }).observe(screen, {attributes: true, attributeFilter: ['hidden']});
  }

  return {
    view,
    setOpen,
    isOpen: () => open,
    sectionsChanged: () => render(),
    sourceScope() {
      const thread = view.thread;
      if (!open || thread?.kind !== 'observed') return null;
      return {key: thread.key, label: `Frame ${thread.frame_id} of session ${thread.session_id}, selected in Debugger Threads: only its files are listed.`,
        empty: `No retained source carries frame ${thread.frame_id} of session ${thread.session_id}.`,
        includes: source => String(source.session_id) === String(thread.session_id) && String(source.frame_id) === String(thread.frame_id)};
    }
  };
}

function debuggerNote(text, kind = '') {
  const note = debuggerNode('p', 'debugger-note', text);
  if (kind) note.dataset.kind = kind;
  return note;
}

// Replaces a container's children only when what they say changed, so a
// poll never moves a focused control.
function debuggerReplace(container, nodes) {
  const signature = nodes.map(node => `${node.tagName}:${node.dataset?.kind ?? ''}:${node.textContent}`).join('\n');
  if (container.dataset.signature === signature) return;
  container.dataset.signature = signature;
  container.replaceChildren(...nodes);
}

// Shown in place of a section's content until a document has been read.
function debuggerUnread(view) {
  if (view.document) return null;
  return debuggerNote({loading: 'Reading…', unavailable: 'Not available in this window.',
    disconnected: 'Not read: the backend did not answer.', malformed: 'Not read: the answer was malformed.'}[view.status] ?? 'Reading…',
  view.status === 'loading' ? '' : 'warning');
}

function debuggerGapNote(view) {
  const gaps = view.hooks.sequenceGaps?.();
  return typeof gaps === 'bigint' && gaps > 0n
    ? debuggerNote(`${gaps} sequence-gap IDs in the retained window: records may be missing, so a missing row is unknown rather than absent.`, 'gap')
    : null;
}

// Threads section: the Threads view plus what the selection scopes.
function debuggerThreadsSection() {
  let threadsView = null;
  return {
    id: 'threads', title: 'Threads', order: 10,
    summary: view => view.document ? String(view.document.threads.frames.length + view.document.threads.workers.length + view.document.threads.observed.length) : '',
    render(body, view) {
      const unread = debuggerUnread(view);
      if (unread) { threadsView?.release(); threadsView = null; body.replaceChildren(unread); return; }
      if (!threadsView || !body.contains(threadsView.element)) {
        threadsView = createDebuggerThreadsView({onSelect: thread => view.selectThread(thread)});
        body.replaceChildren(threadsView.element, debuggerNode('div', 'debugger-thread-notes'));
      }
      const live = view.hooks.consoleLive?.() ?? null;
      threadsView.render(debuggerThreads(view.document, {frameOrigin: view.hooks.frameOrigin, consoleTarget: live?.target_id ?? null}), view.thread?.key ?? null);
      const notes = [];
      const thread = view.thread;
      if (thread?.kind === 'observed') {
        const scope = debuggerNode('p', 'debugger-note debugger-scope');
        scope.append(`Scoped to frame ${thread.frame_id}: Observations and the Sources tree show only this frame's records and files. `,
          debuggerButton('Show all', 'debugger-link', () => view.selectThread(thread)));
        notes.push(scope);
      } else if (thread?.kind === 'document') {
        notes.push(debuggerNote(`Document ${thread.target_id}: Watch rules say whether they are armed here. A Console document carries no native frame ID, so Observations and the Sources tree are not scoped; select its observed frame for that.`));
      } else if (thread?.kind === 'worker') {
        notes.push(debuggerNote('Workers record no observations: rules match only a document\'s main thread. Compiled worker scripts carry frame 0, so the Sources tree is not scoped.'));
      }
      notes.push(debuggerNote(`Console listing: ${view.document.threads.console}. Workers come from the newest 2,048 request records and observed frames from the newest 2,048 observation records.`));
      const gap = debuggerGapNote(view);
      if (gap) notes.push(gap);
      debuggerReplace(body.querySelector(':scope > .debugger-thread-notes'), notes);
    },
    release() { threadsView?.release(); threadsView = null; }
  };
}

function debuggerRulesText(rules) {
  const rows = [];
  const requests = Array.isArray(rules?.requests) ? rules.requests : [];
  rows.push(['Requests', requests.length ? requests.map(rule => `${rule.method ?? 'any method'} · URL contains “${rule.url_contains}”`) : ['off']]);
  rows.push(['Listeners', Array.isArray(rules?.events) && rules.events.length ? [rules.events.join(', ')] : ['off']]);
  rows.push(['Timers', [rules?.timers ? 'scheduled and fired' : 'off']]);
  rows.push(['CSP violations', [rules?.csp ? 'on' : 'off']]);
  rows.push(['Exceptions', [{uncaught: 'uncaught and unhandled rejections', all: 'caught and uncaught'}[rules?.exceptions] ?? 'off']]);
  const dom = Array.isArray(rules?.dom) ? rules.dom : [];
  rows.push(['DOM mutations', dom.length ? dom.map((node, index) => `element ${index + 1} (handle ${node.handle}): ${['attributes', 'subtree', 'removal'].filter(field => node[field]).join(', ') || 'nothing'}`) : ['off']]);
  return rows;
}

function debuggerParseRules(form, carried) {
  const encoder = new TextEncoder();
  const requests = [];
  for (const line of form.requests.value.split('\n').map(text => text.trim()).filter(Boolean)) {
    const match = /^([A-Z]{1,16})\s+(.+)$/.exec(line);
    const rule = match ? {method: match[1], url_contains: match[2]} : {url_contains: line};
    const bytes = encoder.encode(rule.url_contains).length;
    if (bytes < 1 || bytes > 256) return {error: 'Each request rule is 1 to 256 bytes of URL text, after an optional uppercase method.'};
    requests.push(rule);
  }
  if (requests.length > 8) return {error: 'At most 8 request rules.'};
  const events = [...new Set(form.events.value.split(/[\s,]+/).filter(Boolean))];
  if (events.length > 16 || events.some(name => name.length > 27 || !/^[!-~]+$/.test(name))) {
    return {error: 'At most 16 event types, each 1 to 27 printable ASCII characters.'};
  }
  const rules = {requests, events, timers: form.timers.checked, csp: form.csp.checked, exceptions: form.exceptions.value, dom: carried};
  if (!requests.length && !events.length && !rules.timers && !rules.csp && rules.exceptions === 'off' && !carried.length) {
    return {error: 'Add at least one rule, or use Clear rules to disarm.'};
  }
  return {rules};
}

// Watch rules: what the renderer confirmed, and arming through the Console's
// own live connection to the document the researcher selected and confirmed.
function debuggerWatchSection() {
  let form = null, sending = false, result = '', draftFor = null;
  function build(view) {
    const element = debuggerNode('form', 'debugger-watch-form');
    element.noValidate = true;
    const field = (label, control, hint) => {
      const wrap = debuggerNode('label', 'debugger-field');
      wrap.append(debuggerNode('span', 'debugger-field-label', label), control);
      if (hint) wrap.append(debuggerNode('span', 'debugger-field-hint', hint));
      return wrap;
    };
    const requests = debuggerNode('textarea', 'debugger-input');
    requests.rows = 2; requests.maxLength = 2200; requests.spellcheck = false; requests.placeholder = 'POST /api/login';
    const events = debuggerNode('input', 'debugger-input');
    events.type = 'text'; events.maxLength = 460; events.spellcheck = false; events.autocomplete = 'off'; events.placeholder = 'click, submit';
    const check = text => { const label = debuggerNode('label', 'debugger-check'); const box = debuggerNode('input'); box.type = 'checkbox'; label.append(box, ` ${text}`); return {label, box}; };
    const timers = check('Timers'), csp = check('CSP violations');
    const exceptions = debuggerNode('select', 'debugger-select');
    for (const [value, text] of [['off', 'Off'], ['uncaught', 'Uncaught'], ['all', 'Caught and uncaught']]) {
      const option = debuggerNode('option', '', text); option.value = value; exceptions.append(option);
    }
    const switches = debuggerNode('div', 'debugger-watch-switches');
    switches.append(timers.label, csp.label, field('Exceptions', exceptions));
    const dom = debuggerNode('p', 'debugger-note');
    const arm = debuggerNode('button', 'secondary-button debugger-arm');
    arm.type = 'submit';
    const clear = debuggerButton('Clear rules', 'secondary-button', () => send(view, null));
    const actions = debuggerNode('div', 'debugger-watch-actions');
    actions.append(arm, clear);
    const output = debuggerNode('p', 'debugger-note debugger-watch-result');
    output.setAttribute('role', 'status');
    element.append(field('Requests', requests, 'One per line: an optional method, then text the URL contains.'),
      field('Event listeners', events, 'Event types, separated by commas.'), switches, dom, actions, output);
    element.addEventListener('submit', event => { event.preventDefault(); send(view, 'arm'); });
    form = {element, requests, events, timers: timers.box, csp: csp.box, exceptions, dom, arm, clear, output};
  }
  function fill(rules) {
    form.requests.value = (rules?.requests ?? []).map(rule => rule.method ? `${rule.method} ${rule.url_contains}` : rule.url_contains).join('\n');
    form.events.value = (rules?.events ?? []).join(', ');
    form.timers.checked = Boolean(rules?.timers);
    form.csp.checked = Boolean(rules?.csp);
    form.exceptions.value = ['uncaught', 'all'].includes(rules?.exceptions) ? rules.exceptions : 'off';
  }
  async function send(view, action) {
    const live = view.hooks.consoleLive?.();
    if (sending || !live) return;
    const armed = view.document?.watch?.armed;
    const carried = armed && armed.session_id === live.session_id && armed.target_id === live.target_id && Array.isArray(armed.rules?.dom) ? armed.rules.dom : [];
    let rules = null;
    if (action === 'arm') {
      const parsed = debuggerParseRules(form, carried);
      if (parsed.error) { result = parsed.error; view.refresh(); return; }
      rules = parsed.rules;
    }
    sending = true;
    result = action === 'arm' ? `Arming on document ${live.target_id}…` : `Clearing the rules of document ${live.target_id}…`;
    view.refresh();
    try {
      const reply = await view.hooks.watch(rules);
      result = !reply ? 'No confirmed answer. The rules may have changed; nothing was retried.'
        : reply.status === 'ok' ? (action === 'arm' ? `Armed on document ${live.target_id}. The renderer confirmed the set below.` : `Cleared on document ${live.target_id}.`)
          : `Refused: ${reply.text || reply.status}. A refused set leaves nothing armed.`;
    } catch (error) {
      result = `Not confirmed: ${error?.message ?? error}. Nothing was retried.`;
    } finally {
      sending = false;
      view.refresh();
    }
  }
  return {
    id: 'watch-rules', title: 'Watch rules', order: 20,
    summary: view => view.document?.watch?.state ?? '',
    render(body, view) {
      const unread = debuggerUnread(view);
      if (unread) { body.replaceChildren(unread); form = null; return; }
      let armedBox = body.querySelector(':scope > .debugger-watch-state');
      if (!armedBox) { armedBox = debuggerNode('div', 'debugger-watch-state'); body.replaceChildren(armedBox); }
      const watch = view.document.watch, armed = watch.state === 'armed' ? watch.armed : null;
      const nodes = [];
      if (watch.state === 'busy') nodes.push(debuggerNote('A Console action holds the session, so the armed set is read again shortly.', 'warning'));
      else if (!armed) nodes.push(debuggerNote('No rules armed. Nothing is observed until a set is armed on one live document.'));
      else {
        nodes.push(debuggerNote(`Armed on Console document ${armed.target_id} (Console session ${armed.session_id}). Navigation, a new capture, Clear rules or a Console Stop disarms them.`));
        const thread = view.thread;
        if (thread?.kind === 'document' && thread.target_id !== armed.target_id) nodes.push(debuggerNote(`The selected document ${thread.target_id} has no rules; they are armed on document ${armed.target_id}.`, 'warning'));
        const list = debuggerNode('dl', 'debugger-rules');
        for (const [label, values] of debuggerRulesText(armed.rules)) {
          list.append(debuggerNode('dt', '', label));
          for (const value of values) list.append(debuggerNode('dd', value === 'off' ? 'debugger-off' : '', value));
        }
        nodes.push(list);
      }
      const live = view.hooks.consoleLive?.() ?? null;
      if (!live) {
        form?.element.remove();
        form = null;
        nodes.push(debuggerNote('To arm or clear rules, connect the Console to a live capture document: select it, confirm that commands can change it, then Connect. The rules arm through that connection\'s watch command; this sidebar never selects or confirms a document.'));
        debuggerReplace(armedBox, nodes);
        return;
      }
      debuggerReplace(armedBox, nodes);
      if (!form) { build(view); body.append(form.element); }
      const sameDocument = armed && armed.session_id === live.session_id && armed.target_id === live.target_id;
      const key = `${live.session_id}:${live.target_id}:${JSON.stringify(sameDocument ? armed.rules : null)}`;
      if (draftFor !== key && !form.element.contains(document.activeElement)) { fill(sameDocument ? armed.rules : null); draftFor = key; }
      const carried = sameDocument && Array.isArray(armed.rules?.dom) ? armed.rules.dom.length : 0;
      form.dom.textContent = carried
        ? `Arming here keeps the ${carried} DOM ${carried === 1 ? 'rule' : 'rules'} armed from the Console. Arming replaces the whole set; a refused set leaves nothing armed.`
        : 'DOM mutation rules need an element handle from the Console watch command. Arming replaces the whole set; a refused set leaves nothing armed.';
      form.arm.textContent = sending ? 'Working…' : `Arm on document ${live.target_id}`;
      form.arm.title = `Arms these rules on Console document ${live.target_id}${live.label ? ` (${live.label})` : ''} through the live Console connection. Nothing pauses and no value is read.`;
      form.arm.disabled = sending;
      form.clear.disabled = sending || !sameDocument;
      form.output.textContent = result;
      form.output.hidden = !result;
    },
    release() { form = null; draftFor = null; }
  };
}

// Observations: the newest records per kind, with their identities. A row
// opens its script position in Sources or its request in Traffic.
function debuggerObservationsSection() {
  let list = null, controls = null, detail = null, selected = null, detailTimer = 0, notice = null;
  const stacks = new Map();
  // Read once per record; a failed read is tried again only after a pause.
  function resolution(view, record) {
    const key = debuggerRecordKey(record);
    let entry = stacks.get(key);
    const retry = entry?.retryAt && Date.now() >= entry.retryAt;
    if ((!entry || retry) && view.hooks.available()) {
      stacks.delete(key);
      entry = {status: 'loading'};
      stacks.set(key, entry);
      while (stacks.size > DEBUGGER_SIDEBAR.stacks) stacks.delete(stacks.keys().next().value);
      const parameters = new URLSearchParams({session_id: record.session_id, process_id: String(record.process_id), observation_sequence: record.sequence_number});
      entry.promise = view.hooks.fetch(`/api/request-stack?${parameters}`, {cache: 'no-store', signal: AbortSignal.timeout(DEBUGGER_SIDEBAR.deadline)})
        .then(async response => {
          const body = await response.json().catch(() => null);
          if (!response.ok) throw new Error(body?.error ?? `HTTP ${response.status}`);
          const ready = body?.status === 'recorded' && body.request?.sequence_number === record.sequence_number;
          Object.assign(entry, ready ? {status: 'ready', document: body} : {status: 'error', error: {
            outside_scan: 'This record is outside the scanned range of the event store, so it is unknown rather than missing.',
            not_recorded: 'The event store no longer holds this record.', malformed: 'The stored record is malformed.'
          }[body?.status] ?? 'The stored record no longer matches this row.'});
        })
        .catch(error => Object.assign(entry, {status: 'error', retryAt: Date.now() + DEBUGGER_SIDEBAR.retry,
          error: error?.name === 'TimeoutError' ? 'the backend did not answer within 10 seconds' : String(error?.message ?? error)}))
        .finally(() => { if (selected?.key === key) paintDetail(view); });
    }
    return entry ?? {status: 'error', error: 'No backend serves this window.'};
  }
  function frameText(frame) {
    return typeof requestStackFrameText === 'function' ? requestStackFrameText(frame) : `script ${frame.script_id} @ ${frame.position}`;
  }
  // The position a row opens: its own frame, else the innermost resolved one.
  function target(entry) {
    if (entry?.status !== 'ready') return null;
    const site = entry.document.observation?.site;
    if (site?.resolution?.status === 'resolved') return site;
    return (entry.document.frames ?? []).find(frame => frame.resolution?.status === 'resolved' && frame.resolution.artifact_id) ?? null;
  }
  function choose(view, item, how) {
    if (!item) return;
    if (selected?.key !== item.key) notice = null;
    selected = item;
    paintDetail(view);
    if (how === 'Enter' || how === 'dblclick') openPrimary(view, item.record);
  }
  function say(view, record, text) {
    notice = {key: debuggerRecordKey(record), text};
    paintDetail(view);
  }
  // Waits for the position when it is still resolving; a newer choice wins.
  function openPrimary(view, record) {
    if (record.type === 'request_watch_match' && record.request_id !== '0') { openRequest(view, record); return; }
    const entry = resolution(view, record), key = debuggerRecordKey(record);
    Promise.resolve(entry.promise).then(() => {
      if (selected?.key !== key) return;
      const frame = target(entry);
      if (frame) view.hooks.openSource(frame.resolution);
      else say(view, record, 'This record has no retained script position to open.');
    });
  }
  function openRequest(view, record) {
    const problem = view.hooks.openRequest(record);
    if (problem) say(view, record, problem);
  }
  function paintDetail(view) {
    if (!detail) return;
    if (!selected) { detail.hidden = true; detail.replaceChildren(); delete detail.dataset.signature; return; }
    const record = selected.record, entry = resolution(view, record);
    // Repainting only on a change keeps focus on its buttons between polls.
    const signature = `${selected.key}|${entry.status}|${notice?.key === selected.key ? notice.text : ''}`;
    if (detail.dataset.signature === signature && !detail.hidden) return;
    detail.dataset.signature = signature;
    detail.hidden = false;
    const heading = debuggerNode('div', 'debugger-detail-head');
    heading.append(debuggerNode('strong', '', debuggerObservationText(record)), debuggerButton('×', 'debugger-detail-close', () => { selected = null; notice = null; paintDetail(view); list?.set(rows(view), {selectedKey: null}); list?.focus(); }));
    heading.lastChild.setAttribute('aria-label', 'Close record details');
    const fields = debuggerNode('dl', 'debugger-fields');
    const add = (label, value) => { fields.append(debuggerNode('dt', '', label), debuggerNode('dd', '', value)); };
    add('Operation', record.type);
    add('Category', debuggerCategory(record.type));
    add('Time', `${debuggerTime(record.monotonic_time_ns)} (monotonic)`);
    add('Source', `renderer process ${record.process_id}, frame ${record.frame_id}`);
    add('Identity', `session ${record.session_id} · process ${record.process_id} · sequence ${record.sequence_number}`);
    if (record.parent_event_id !== '0') add('Parent', `sequence ${record.parent_event_id}`);
    if (record.request_id !== '0') add('Request', `request ${record.request_id}`);
    add('Stack', `${DEBUGGER_STACK_STATES[record.stack.state] ?? record.stack.state}${record.stack.total_depth ? `, ${record.stack.total_depth} frames` : ''}`);
    const nodes = [heading, fields];
    const actions = debuggerNode('div', 'debugger-detail-actions');
    if (record.type === 'request_watch_match' && record.request_id !== '0') actions.append(debuggerButton('Open request in Traffic', 'secondary-button', () => openRequest(view, record)));
    const frame = target(entry);
    if (notice?.key === selected.key) nodes.push(debuggerNote(notice.text, 'warning'));
    if (entry.status === 'loading') nodes.push(debuggerNote('Resolving positions from retained sources…'));
    else if (entry.status === 'error') nodes.push(debuggerNote(`Positions unavailable: ${entry.error}`, 'warning'));
    else {
      const site = entry.document.observation?.site;
      if (debuggerSite(record) && site && site.resolution?.status !== 'resolved') nodes.push(debuggerNote(`Its own frame (script ${site.script_id}) did not resolve: ${String(site.resolution?.reason ?? 'unresolved').replace(/_/g, ' ')}.`, 'warning'));
      if (frame) actions.prepend(debuggerButton(`Open ${frameText(frame)}`, 'secondary-button debugger-open-source', () => view.hooks.openSource(frame.resolution)));
      const frames = entry.document.frames ?? [];
      if (frames.length) {
        const stack = debuggerNode('ol', 'debugger-stack');
        stack.setAttribute('aria-label', 'Stack when the record was made, innermost first');
        for (const item of frames.slice(0, 64)) {
          const row = debuggerNode('li', 'debugger-stack-frame');
          if (item.resolution?.status === 'resolved' && item.resolution.artifact_id) row.append(debuggerButton(frameText(item), 'debugger-link', () => view.hooks.openSource(item.resolution)));
          else row.textContent = frameText(item);
          stack.append(row);
        }
        if (frames.length > 64) stack.append(debuggerNode('li', 'debugger-stack-frame debugger-off', `${frames.length - 64} more frames; the request Initiator tab lists them all.`));
        nodes.push(stack);
      }
    }
    if (actions.children.length) nodes.splice(2, 0, actions);
    detail.replaceChildren(...nodes);
  }
  function rows(view) {
    const observations = view.observations, seen = new Set(), items = [];
    for (const record of [...observations.head, ...observations.older]) {
      const key = debuggerRecordKey(record);
      if (seen.has(key) || items.length >= DEBUGGER_SIDEBAR.rows) continue;
      seen.add(key);
      items.push({key, record, height: DEBUGGER_SIDEBAR.observationRow});
    }
    return items;
  }
  function build(view) {
    const root = debuggerNode('div', 'debugger-observations');
    const kinds = debuggerNode('div', 'debugger-kinds');
    kinds.setAttribute('role', 'group');
    kinds.setAttribute('aria-label', 'Observation kind');
    for (const [kind, text] of [[null, 'All'], ...Object.entries(DEBUGGER_OBSERVATION_KINDS).map(([kind, value]) => [kind, value.filter])]) {
      const pill = debuggerButton(text, 'debugger-kind', () => { selected = null; view.setKind(kind); });
      pill.dataset.kind = kind ?? 'all';
      kinds.append(pill);
    }
    const notes = debuggerNode('div', 'debugger-observation-notes');
    list = createDebuggerList({id: 'debugger-observations', label: 'Observation records, newest first',
      onActive: item => { clearTimeout(detailTimer); detailTimer = setTimeout(() => choose(view, item, 'active'), 120); },
      onChoose: (item, how) => { clearTimeout(detailTimer); choose(view, item, how); },
      render(row, item) {
        const record = item.record;
        row.dataset.kind = record.type;
        const head = debuggerNode('div', 'debugger-row-head');
        head.append(debuggerNode('span', 'debugger-chip', DEBUGGER_OBSERVATION_KINDS[record.type].label), debuggerNode('span', 'debugger-row-main', debuggerObservationText(record)));
        const meta = debuggerNode('div', 'debugger-row-meta',
          `${debuggerTime(record.monotonic_time_ns)} · ${debuggerCategory(record.type)} · P${record.process_id} F${record.frame_id} #${record.sequence_number}${record.request_id !== '0' ? ` · R${record.request_id}` : ''}`);
        row.title = `${debuggerObservationText(record)} · ${record.type} · session ${record.session_id} · process ${record.process_id} · frame ${record.frame_id} · sequence ${record.sequence_number}`;
        row.append(head, meta);
      }});
    const more = debuggerButton('Show older records', 'secondary-button debugger-older', () => view.older());
    detail = debuggerNode('div', 'debugger-detail');
    detail.hidden = true;
    root.append(kinds, notes, list.element, more, detail);
    controls = {root, kinds, notes, more};
  }
  return {
    id: 'observations', title: 'Observations', order: 30,
    summary: view => view.document ? String(rows(view).length) : '',
    render(body, view) {
      const unread = debuggerUnread(view);
      if (unread) { list?.release(); list = null; controls = null; detail = null; body.replaceChildren(unread); return; }
      if (!controls || !body.contains(controls.root)) { build(view); body.replaceChildren(controls.root); }
      for (const pill of controls.kinds.children) pill.setAttribute('aria-pressed', String((pill.dataset.kind === 'all' ? null : pill.dataset.kind) === view.kind));
      const items = rows(view), answer = view.document, observations = view.observations;
      const notes = [];
      const scope = view.thread?.kind === 'observed' ? ` in frame ${view.thread.frame_id}` : '';
      const kind = view.kind ? DEBUGGER_OBSERVATION_KINDS[view.kind].filter.toLowerCase() : 'records of every kind';
      if (observations.key !== `${view.kind ?? 'all'}|${view.thread?.kind === 'observed' ? view.thread.key : 'all'}`) notes.push(debuggerNote('Reading…'));
      else if (!items.length) notes.push(debuggerNote(view.kind || scope ? `No ${kind}${scope} in the event store's newest records.` : 'No observation records. Arm rules on a live document to record them; nothing pauses.'));
      else notes.push(debuggerNote(`Newest ${items.length.toLocaleString('en-US')} ${kind}${scope}${items.length >= DEBUGGER_SIDEBAR.rows ? ', the most this list keeps; get_events pages the rest' : ''}. Enter opens a row's position in Sources, or its request in Traffic.`));
      const malformed = answer.observations_malformed + observations.refused + observations.olderRefused;
      if (malformed > 0) notes.push(debuggerNote(`${malformed} ${malformed === 1 ? 'record' : 'records'} in the newest read ${malformed === 1 ? 'was' : 'were'} malformed and ${malformed === 1 ? 'is' : 'are'} not shown.`, 'warning'));
      for (const gap of answer.observation_budget_gaps.slice(0, 2)) {
        notes.push(debuggerNote(`Renderer ${gap.process_id} reached 1,024 observation records in frame ${gap.frame_id} (gap #${gap.sequence_number}); its later records were refused until the next capture.`, 'gap'));
      }
      const gap = debuggerGapNote(view);
      if (gap) notes.push(gap);
      if (observations.olderError) notes.push(debuggerNote(`Older records were not read: ${observations.olderError}`, 'warning'));
      debuggerReplace(controls.notes, notes);
      list.element.hidden = !items.length;
      list.set(items, {selectedKey: selected?.key ?? null});
      controls.more.hidden = observations.next === null || items.length >= DEBUGGER_SIDEBAR.rows;
      controls.more.disabled = observations.loadingOlder;
      controls.more.textContent = observations.loadingOlder ? 'Reading older records…' : 'Show older records';
      if (selected) {
        const current = items.find(item => item.key === selected.key);
        if (current) selected = current;
      }
      paintDetail(view);
    },
    release() { clearTimeout(detailTimer); list?.release(); list = null; controls = null; detail = null; selected = null; notice = null; }
  };
}

// Pausing: one state, from the availability get_native_debugger reports. The
// pausing debugger adds its own sections here; none are imitated.
function debuggerPausingSection() {
  return {
    id: 'pausing', title: 'Pausing', order: 40,
    summary: view => view.document?.availability ?? '',
    render(body, view) {
      const unread = debuggerUnread(view);
      if (unread) { body.replaceChildren(unread); return; }
      const answer = view.document, available = answer.availability === 'available';
      const state = debuggerNode('p', 'debugger-note debugger-pausing-state');
      state.dataset.debuggerNative = 'availability';
      state.dataset.availability = answer.availability;
      state.append(debuggerNode('strong', '', available ? 'Available. ' : 'Unsupported. '), available
        ? 'A Brave build serves the pausing debugger, but its controls are not part of this sidebar yet, so nothing here can pause the page.'
        : `No Brave build serves the pausing debugger (${answer.reason}), so breakpoints, scopes, a paused call stack and stepping are unavailable. Nothing is attached and no page is paused.`);
      const fields = debuggerNode('dl', 'debugger-fields');
      for (const [label, value] of [
        ['Policy', answer.policy === 'approved' ? 'approved in SAFETY.md' : 'proposed, pending maintainer approval'],
        ['Experiment', `${answer.experiment_flag}, off by default`],
        ['Pause lease', `at most ${Math.round(answer.lease_limit_ms / 1000)} seconds`],
        ['Detectable', answer.detectable ? 'yes, a page can detect an active debugger' : 'no']
      ]) fields.append(debuggerNode('dt', '', label), debuggerNode('dd', '', value));
      body.replaceChildren(state, fields);
    }
  };
}

for (const section of [debuggerThreadsSection(), debuggerWatchSection(), debuggerObservationsSection(), debuggerPausingSection()]) {
  globalThis.RebDebuggerSidebar.addSection(section);
}

// Wiring to the Sources workspace. Every app function is looked up when it
// is needed, so this file also loads where the workspace is absent.
(() => {
  const root = document.querySelector('#debugger-sidebar'), toggle = document.querySelector('#source-debugger-toggle');
  const screen = document.querySelector('#screen-sources'), details = document.querySelector('#source-sidebar');
  if (!root || !toggle || !screen || !details) return;
  const appState = () => typeof state === 'object' && state ? state : null;
  let origins = {artifacts: null, map: new Map()};
  const hooks = {
    available: () => location.protocol !== 'file:',
    fetch: (input, init) => fetch(input, init),
    overlays: () => getComputedStyle(root).position === 'absolute',
    closeDetails() {
      const app = appState();
      if (app?.sourceSidebarOpen && typeof renderSourceSidebar === 'function') { app.sourceSidebarOpen = false; renderSourceSidebar(); }
    },
    syncLayout(open) { screen.dataset.sidebarOpen = String(open || !details.hidden); },
    refreshTree() { if (typeof renderSourceTree === 'function') renderSourceTree(); },
    // A frame's origin from its retained document artifact, matched by exact session and frame.
    frameOrigin(session, frame) {
      const artifacts = appState()?.artifacts;
      if (!Array.isArray(artifacts) || typeof sourceTreeDocumentArtifact !== 'function' || typeof sourceTreeUrl !== 'function') return null;
      if (origins.artifacts !== artifacts) {
        origins = {artifacts, map: new Map()};
        for (const artifact of artifacts) {
          const key = `${artifact.session_id}:${artifact.frame_id}`;
          if (origins.map.has(key) || !sourceTreeDocumentArtifact(artifact)) continue;
          const url = sourceTreeUrl(artifact.url);
          if (url.identity[0] === 'url') origins.map.set(key, url.origin);
        }
      }
      return origins.map.get(`${session}:${frame}`) ?? null;
    },
    // The Initiator tab's own path, so both open a resolved frame alike.
    openSource(resolution) {
      if (typeof openResolvedFrame !== 'function' || !resolution?.artifact_id) return;
      if (hooks.overlays()) debuggerSidebarController?.setOpen(false);
      openResolvedFrame(resolution);
    },
    // The renderer request's Traffic row, named by the request index's own row identity.
    openRequest(record) {
      const app = appState(), id = `S${record.session_id}:R${record.process_id}:${record.request_id}`;
      const rows = (app?.requests ?? []).filter(request => request.id === id);
      if (rows.length !== 1 || typeof showScreen !== 'function' || typeof selectRequest !== 'function') {
        return `Request ${record.request_id} of renderer ${record.process_id} is not among the Traffic rows loaded now. Its stack is shown here.`;
      }
      showScreen('traffic');
      if (!document.querySelector('#console-experiment-traffic')?.hidden) document.querySelector('#console-traffic-back')?.click();
      selectRequest(id);
      app.inspectorTab = 'initiator';
      if (typeof renderInspector === 'function') renderInspector();
      return null;
    },
    consoleLive: () => globalThis.RebNativeConsole?.liveDocument?.() ?? null,
    watch: rules => globalThis.RebNativeConsole?.watch?.(rules) ?? Promise.resolve(null),
    sequenceGaps: () => typeof shownSequenceGaps === 'function' ? shownSequenceGaps() : null
  };
  debuggerSidebarController = createDebuggerSidebar({root, toggle, screen, hooks});
})();
