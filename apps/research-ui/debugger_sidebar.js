/* Sources debugger sidebar (docs/product/native-debugger-v1.md). Phase 1 is
 * native observation that never pauses: threads, watch rules and observation
 * records come from get_native_debugger, and positions from get_request_stack.
 * Sections come from one registry, RebDebuggerSidebar.addSection, so a later
 * change adds its own sections without rewriting these. Only rows in view are
 * mounted, a closed sidebar runs no timers and makes no requests, and every
 * captured value reaches the DOM as text. */
// A read waits at least `poll`, and four times as long as the last read took,
// so a large store is never read back to back; a refresh() a section asks
// for waits at least `refreshGap` after the last read started. The stored-
// evidence window's first read may wait for its bundled backend to start
// (up to 15 seconds) and then scan 64 MiB, so it gets `storedDeadline`.
const DEBUGGER_SIDEBAR = Object.freeze({poll: 2000, slowest: 30000, deadline: 10000, storedDeadline: 45000, refreshGap: 1000, retry: 2000,
  page: 128, rows: 4096, stacks: 32, bridge: 2, threadRow: 40, groupRow: 26, observationRow: 44, overscan: 6, listHeight: 240});

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
// The phase 1 ids, reserved once this file has registered them.
const debuggerSidebarReserved = new Set();
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
    if (debuggerSidebarReserved.has(entry.id)) throw new TypeError(`Section id ${entry.id} is a built-in section and cannot be replaced`);
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
    // The second click of a double-click is the dblclick's, not a new choice.
    if (!row || event.detail > 1) return;
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
      // Rows that arrive above the view do not move it, and with a row
      // selected they do not push the view down either.
      const height = element.clientHeight || DEBUGGER_SIDEBAR.listHeight;
      let kept = null;
      if (changed && anchor && (element.scrollTop > 0 || selectedKey !== null) && items.length) {
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

function debuggerThreadFields(thread) {
  return [['Kind', thread.title], ['Origin', thread.origin], ['Frame', thread.frame], ['Process', thread.process],
    ['State', thread.state], ...(thread.last ? [['Last record', `#${thread.last}`]] : [])];
}

function createDebuggerThreadsView({id = 'debugger-threads', onSelect}) {
  const root = debuggerNode('div', 'debugger-threads');
  // A click or a key chooses a thread; a double-click is not a third toggle.
  const list = createDebuggerList({id, label: 'Threads', onChoose: (item, how) => { if (how !== 'dblclick') onSelect(item); }, render(row, item) {
    if (item.header) {
      row.append(debuggerNode('span', 'debugger-list-group-name', item.title), debuggerNode('b', 'debugger-list-count', item.count));
      return;
    }
    row.dataset.kind = item.kind;
    // The origin has the first line to itself; the selected thread's
    // details below the list repeat every field in full.
    const head = debuggerNode('div', 'debugger-row-head');
    const origin = debuggerNode('span', 'debugger-row-main', item.origin);
    if (item.missing) origin.dataset.missing = 'true';
    head.append(origin, debuggerNode('span', 'debugger-row-state', item.state));
    const foot = debuggerNode('div', 'debugger-row-foot');
    foot.append(debuggerNode('span', 'debugger-chip', item.title), debuggerNode('span', 'debugger-row-meta', `${item.frame} · ${item.process}`));
    row.title = debuggerThreadFields(item).map(([label, value]) => `${label}: ${value}`).join(' · ');
    row.append(head, foot);
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

/* The controller. In a live window it reads get_native_debugger while open
 * and visible; the stored-evidence window (reb://) answers the same reads
 * from its store through the bundled backend, so it reads once and on
 * request; a window with no backend reads nothing. One read is in flight at
 * a time: a newer one, closing, leaving Sources or a replaced store aborts it. */
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
  // Only the state is announced; the time of the last read changes every poll.
  const status = debuggerNode('p', 'debugger-sidebar-status');
  const announced = debuggerNode('span', 'debugger-status-state');
  announced.setAttribute('role', 'status');
  announced.setAttribute('aria-live', 'polite');
  const when = debuggerNode('span', 'debugger-status-time');
  const again = debuggerButton('Read again', 'debugger-link debugger-status-again', () => read());
  status.append(announced, ' ', when, ' ', again);
  const body = debuggerNode('div', 'debugger-sidebar-sections');
  root.append(head, status, body);
  root.setAttribute('aria-labelledby', title.id);

  let open = false, timer = 0, generation = 0, interval = DEBUGGER_SIDEBAR.poll, controller = null;
  // `renderTurn` lasts from a render until the next task, so a refresh() a
  // section queues from render (even as a promise) is ignored.
  let rendering = false, renderTurn = false, renderTurns = 0, lastStarted = 0, refreshQueued = false, stops = 0, readsStarted = 0;
  const mounted = new Map();
  const blankObservations = () => ({key: null, head: [], refused: 0, query: null, list: null, loadingOlder: false, olderError: null, olderController: null});
  const view = {
    // `readSerial` numbers the read whose answer `document` is; readsStarted()
    // counts reads begun, so an action can tell which reads followed it.
    status: 'loading', document: null, error: null, updatedAt: null, readSerial: 0, thread: null, kind: null,
    readsStarted: () => readsStarted,
    observations: blankObservations(),
    // Asks for a read soon. From a render, or the promises it queued, it does
    // nothing: a render follows a read. While a read is in flight it runs one
    // more read after that one; otherwise it reads once `refreshGap` has
    // passed since the last read started. So no section reads back to back.
    refresh() {
      if (rendering || renderTurn || !open) return;
      if (controller) { refreshQueued = true; return; }
      const wait = lastStarted + DEBUGGER_SIDEBAR.refreshGap - Date.now();
      if (wait <= 0) { read(); return; }
      clearTimeout(timer);
      timer = setTimeout(read, wait);
    },
    // Paints the sections again from what was last read, without a read.
    repaint: () => render(),
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
    showNewest() { dropList(); render(); read(); },
    // Once the researcher has a place (a selected row, or the list scrolled
    // from its top), the newest page becomes a kept list that later reads add
    // to; back at the top with nothing selected, the list follows the newest
    // page again; followNewest returns whether the rows changed, and with
    // `any` (a pane drawn again, with no place in it) drops any kept list.
    holdObservations() {
      const observations = view.observations;
      if (observations.list || !observations.query || observations.key !== observationKey()) return;
      observations.list = {records: [...observations.head], top: BigInt(observations.query.store_end), bottom: observations.query.next_before ?? null,
        refused: 0, pinned: null, dropped: 0, query: observations.query, followed: true};
    },
    followNewest(any = false) {
      const list = view.observations.list;
      if (!list || (!any && (!list.followed || list.pinned || list.dropped))) return false;
      // dropList also cancels a Show older read that would continue this list.
      dropList();
      return true;
    },
    // A read for the sidebar's own Watch action: now, or right after the read
    // in flight, never only at the next poll. Not for registered sections.
    readAfterAction() {
      if (!open) return;
      if (controller) refreshQueued = true;
      else read();
    },
    // The other sections registered as presenting the pausing debugger.
    nativeSections: () => sections().filter(section => section.native === 'pausing' && section.id !== 'pausing').map(section => ({id: section.id, title: section.title})),
    hooks
  };

  const windowMode = () => hooks.mode();
  const visible = () => open && !screen.hidden && windowMode() !== 'none';
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

  // WebKit rejects a timed-out fetch with AbortError, so the deadline itself
  // says whether the limit was reached.
  async function fetchDocument(parameters, signal) {
    const limit = windowMode() === 'stored' ? DEBUGGER_SIDEBAR.storedDeadline : DEBUGGER_SIDEBAR.deadline;
    const deadline = AbortSignal.timeout(limit);
    let response;
    try {
      response = await hooks.fetch(`/api/native-debugger?${parameters}`,
        {cache: 'no-store', signal: typeof AbortSignal.any === 'function' ? AbortSignal.any([signal, deadline]) : signal});
    } catch (error) {
      if (deadline.aborted && !signal.aborted) throw new Error(`the backend did not answer within ${limit / 1000} seconds`);
      throw error;
    }
    const value = await response.json().catch(() => null);
    if (!response.ok) throw new Error(typeof value?.error === 'string' ? value.error : `the backend returned HTTP ${response.status}`);
    const problem = debuggerDocumentProblem(value);
    if (problem) { const error = new Error(problem); error.malformed = true; throw error; }
    return value;
  }
  const cursor = page => BigInt(page.next_before ?? 0);
  const valid = answer => answer.observations.filter(debuggerValidObservation);
  function dropList() {
    const observations = view.observations;
    observations.olderController?.abort();
    Object.assign(observations, {list: null, loadingOlder: false, olderError: null, olderController: null});
  }

  /* Without a kept list the rows are the newest page. A kept list (older
   * pages loaded, or the researcher's place held) stays: each read adds the
   * records written since, reading the span between the newest page and the
   * list (at most DEBUGGER_SIDEBAR.bridge more pages). A longer span leaves
   * the list as it is and names the bytes it lacks. Past DEBUGGER_SIDEBAR.rows
   * the oldest rows are dropped, and the list says how many. Nothing changes
   * until every read has answered, so a failed read leaves rows and notes as
   * they were. */
  async function applyHead(answer, signal) {
    const observations = view.observations, key = observationKey(), page = answer.observations_query;
    // A shorter store was cleared or replaced: its older pages, and any read
    // of them still running, belong to the evidence before it.
    const replaced = observations.query && BigInt(page.store_end) < BigInt(observations.query.store_end);
    if (observations.key !== key || replaced) { dropList(); Object.assign(observations, {key, head: [], refused: 0, query: null}); }
    const head = valid(answer), list = observations.list;
    let bridged = null;
    if (list && !list.pinned) {
      const added = [...head];
      let start = cursor(page), malformed = 0;
      for (let reads = 0; start > list.top && reads < DEBUGGER_SIDEBAR.bridge; reads += 1) {
        const more = await fetchDocument(query({before: String(start)}), signal);
        if (observations.key !== key || observations.list !== list) return;
        const records = valid(more);
        malformed += more.observations_malformed + more.observations.length - records.length;
        added.push(...records);
        start = cursor(more.observations_query);
      }
      bridged = {malformed, records: start <= list.top ? debuggerUnique([...added, ...list.records]) : null};
    }
    if (observations.key !== key || observations.list !== list) return;
    Object.assign(observations, {head, refused: answer.observations.length - head.length, query: page});
    if (!list) return;
    if (list.pinned) { list.pinned.to = BigInt(page.store_end); return; }
    list.refused += bridged.malformed;
    if (!bridged.records) { list.pinned = {from: list.top, to: BigInt(page.store_end)}; return; }
    const kept = bridged.records.slice(0, DEBUGGER_SIDEBAR.rows);
    if (kept.length < bridged.records.length) {
      list.dropped += bridged.records.length - kept.length;
      list.bottom = null;
    }
    list.records = kept;
    list.top = BigInt(page.store_end);
  }

  // Renders only after its answer: a section's refresh() can never re-enter
  // it synchronously. A window without a backend is stated by setOpen.
  async function read() {
    clearTimeout(timer);
    timer = 0;
    const kind = windowMode();
    if (!open || screen.hidden || kind === 'none') return;
    controller?.abort();
    const own = new AbortController();
    controller = own;
    const mine = ++generation, started = Date.now(), serial = ++readsStarted;
    lastStarted = started;
    try {
      const answer = await fetchDocument(query(), own.signal);
      if (mine !== generation) return;
      await applyHead(answer, own.signal);
      if (mine !== generation) return;
      view.document = answer;
      view.status = 'ready';
      view.error = null;
      view.updatedAt = new Date();
      view.readSerial = serial;
    } catch (error) {
      if (mine !== generation) return;
      view.status = error?.malformed ? 'malformed' : 'disconnected';
      view.error = String(error?.message ?? error);
    } finally {
      if (mine === generation) {
        controller = null;
        interval = Math.min(DEBUGGER_SIDEBAR.slowest, Math.max(DEBUGGER_SIDEBAR.poll, 4 * (Date.now() - started)));
        render();
        // The stored-evidence window holds a fixed store: no poll there, only
        // a refresh a section asked for while this read ran.
        const queued = refreshQueued;
        refreshQueued = false;
        if ((kind === 'live' || queued) && visible()) timer = setTimeout(read, queued ? DEBUGGER_SIDEBAR.refreshGap : interval);
      }
    }
  }

  async function readOlder() {
    const observations = view.observations, key = observations.key, list = observations.list;
    const before = list ? list.bottom : observations.query?.next_before ?? null;
    if (observations.loadingOlder || before === null || !visible()) return;
    // Asking for older pages keeps the rows: without a kept list, a copy of
    // the newest page becomes one now, so a read that answers meanwhile
    // bridges into it and the older page continues exactly these rows.
    const base = list ?? {records: [...observations.head], top: BigInt(observations.query.store_end), bottom: before, refused: 0, pinned: null, dropped: 0,
      query: observations.query};
    base.followed = false;
    observations.list = base;
    const own = new AbortController();
    observations.olderController = own;
    observations.loadingOlder = true;
    render();
    try {
      const answer = await fetchDocument(query({before: String(before)}), own.signal);
      if (observations.key !== key || observations.olderController !== own) return;
      // A list dropped or replaced while this read ran, or one that dropped
      // its oldest rows, is not continued by this page.
      if (observations.list !== base || base.bottom !== before) return;
      const records = valid(answer);
      const target = base;
      target.records = debuggerUnique([...target.records, ...records]);
      target.refused += answer.observations_malformed + answer.observations.length - records.length;
      target.bottom = answer.observations_query.next_before ?? null;
      target.query = answer.observations_query;
      observations.list = target;
      observations.olderError = null;
    } catch (error) {
      if (observations.olderController !== own) return;
      observations.olderError = String(error?.message ?? error);
    } finally {
      if (observations.olderController === own) {
        observations.loadingOlder = false;
        observations.olderController = null;
        render();
      }
    }
  }

  function renderStatus() {
    const kind = windowMode(), stored = kind === 'stored';
    const time = view.updatedAt ? view.updatedAt.toLocaleTimeString() : null;
    const text = {
      loading: stored ? 'Reading the stored evidence…' : 'Reading the native debugger state…',
      unavailable: 'No backend serves this window, so the debugger state cannot be read.',
      ready: stored ? 'Stored evidence: read once, since nothing captures in this window.' : 'Live: read while open.',
      disconnected: stored ? `The stored-evidence backend did not answer: ${view.error}.`
        : time ? `Disconnected: ${view.error}. Showing what was read before; reading again.` : `Cannot read the native debugger state: ${view.error}. Reading again.`,
      malformed: `The last answer was malformed (${view.error}) and was not used.${time ? ' Showing what was read before.' : ''}`
    }[view.status];
    if (announced.textContent !== text) announced.textContent = text;
    // Outside the live region: the time, and the interval, which follows how long reads take.
    when.textContent = time ? kind === 'live' ? `Read at ${time}, every ${Math.round(interval / 1000)} seconds.` : `Read at ${time}.` : '';
    when.hidden = !time;
    again.hidden = !stored || view.status === 'loading';
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
    if (!open || rendering) return;
    rendering = true;
    try {
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
    } finally {
      rendering = false;
    }
    // Each render starts the turn again, so it ends after the last one.
    renderTurn = true;
    const turn = ++renderTurns;
    setTimeout(() => { if (turn === renderTurns) renderTurn = false; }, 0);
  }
  // A section's count and body fail apart: a throwing summary leaves the body.
  function paintSection(entry) {
    entry.details.dataset.stale = String(view.status !== 'ready' && view.document !== null);
    try {
      entry.count.textContent = entry.section.summary ? String(entry.section.summary(view) ?? '') : '';
    } catch (error) {
      console.error('Debugger sidebar section summary failed', error);
      entry.count.textContent = '';
    }
    if (!entry.details.open) return;
    try {
      entry.section.render(entry.body, view);
    } catch (error) {
      console.error('Debugger sidebar section failed', error);
      entry.body.replaceChildren(debuggerNode('p', 'debugger-note debugger-note-error', `This section failed to render: ${error?.message ?? error}`));
    }
  }

  function stop() {
    generation += 1;
    stops += 1;
    clearTimeout(timer);
    timer = 0;
    refreshQueued = false;
    controller?.abort();
    controller = null;
    view.observations.olderController?.abort();
    view.observations.olderController = null;
    view.observations.loadingOlder = false;
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
      view.status = windowMode() === 'none' ? 'unavailable' : view.document ? view.status : 'loading';
      render();
      read();
    } else {
      stop();
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
  // Leaving Sources aborts the read and stops polling; coming back resumes it.
  // The stored-evidence window, whose store does not change, reads again only
  // when leaving aborted its first read.
  if (typeof MutationObserver === 'function') {
    new MutationObserver(() => {
      if (screen.hidden) stop();
      else if (open && !timer && !controller && (windowMode() === 'live' || !view.document)) read();
    }).observe(screen, {attributes: true, attributeFilter: ['hidden']});
  }

  return {
    view,
    setOpen,
    isOpen: () => open,
    // Counts closes and departures from Sources, so work begun before one can tell.
    stops: () => stops,
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

// Records newest first, each once.
function debuggerUnique(records) {
  const seen = new Set();
  return records.filter(record => {
    const key = debuggerRecordKey(record);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function debuggerBytes(value) {
  const bytes = Number(value);
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KiB`;
  return `${bytes} ${bytes === 1 ? 'byte' : 'bytes'}`;
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
      const groups = debuggerThreads(view.document, {frameOrigin: view.hooks.frameOrigin, consoleTarget: live?.target_id ?? null});
      threadsView.render(groups, view.thread?.key ?? null);
      const notes = [];
      // The selected thread's fields in full, as text the keyboard reaches.
      const thread = view.thread ? groups.flat().find(item => item.key === view.thread.key) ?? view.thread : null;
      if (thread) {
        const fields = debuggerNode('dl', 'debugger-fields debugger-thread-detail');
        fields.setAttribute('aria-label', 'Selected thread');
        for (const [label, value] of debuggerThreadFields(thread)) fields.append(debuggerNode('dt', '', label), debuggerNode('dd', '', value));
        notes.push(fields);
      }
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
      notes.push(debuggerNote(`Console listing: ${view.document.threads.console}. Workers come from the newest 2,048 request records, and observed frames from the observation records among the newest 2,048 records that are observations or gaps of any kind, each within the newest 64 MiB of the store.`));
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
// There is one form, drawn for one Console document; it is drawn again when
// the Console holds another, and it sends nothing if that changed since.
function debuggerWatchSection() {
  // The last outcome names its document, so it outlives a form drawn again.
  // An arm or clear outcome lasts only while the state read after it agrees.
  let form = null, outcome = null;
  // `after` is the count of reads begun when the outcome came; only a read
  // begun later can confirm or end it.
  const say = (text, kind = 'notice', target = null, after = 0) => { outcome = {text, kind, target, after}; };
  const sameDocument = (left, right) => Boolean(left && right) && left.session_id === right.session_id && left.target_id === right.target_id;
  function build(view, live) {
    const element = debuggerNode('form', 'debugger-watch-form');
    element.noValidate = true;
    element.dataset.target = live.target_id;
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
    const actions = debuggerNode('div', 'debugger-watch-actions');
    const output = debuggerNode('p', 'debugger-note debugger-watch-result');
    output.setAttribute('role', 'status');
    const own = {element, document: {session_id: live.session_id, target_id: live.target_id, label: live.label ?? ''},
      requests, events, timers: timers.box, csp: csp.box, exceptions, dom, arm, output, sending: false, draftFor: null};
    own.clear = debuggerButton('Clear rules', 'secondary-button', () => send(view, own, null));
    actions.append(arm, own.clear);
    element.append(field('Requests', requests, 'One per line: an optional method, then text the URL contains.'),
      field('Event listeners', events, 'Event types, separated by commas.'), switches, dom, actions, output);
    element.addEventListener('submit', event => { event.preventDefault(); send(view, own, 'arm'); });
    return own;
  }
  function fill(own, rules) {
    own.requests.value = (rules?.requests ?? []).map(rule => rule.method ? `${rule.method} ${rule.url_contains}` : rule.url_contains).join('\n');
    own.events.value = (rules?.events ?? []).join(', ');
    own.timers.checked = Boolean(rules?.timers);
    own.csp.checked = Boolean(rules?.csp);
    own.exceptions.value = ['uncaught', 'all'].includes(rules?.exceptions) ? rules.exceptions : 'off';
  }
  // Rules come from the form that was submitted, and go only to the document
  // that form names, which must still be the Console's live document.
  async function send(view, own, action) {
    if (own.sending) return;
    const live = view.hooks.consoleLive?.() ?? null;
    if (!sameDocument(live, own.document)) {
      say(live
        ? `Not sent: the Console now holds document ${live.target_id}, not document ${own.document.target_id} this form was drawn for. Nothing was armed.`
        : `Not sent: the Console is no longer connected to document ${own.document.target_id}. Nothing was armed.`);
      view.repaint();
      return;
    }
    const armed = view.document?.watch?.armed;
    const carried = sameDocument(armed, live) && Array.isArray(armed.rules?.dom) ? armed.rules.dom : [];
    let rules = null;
    if (action === 'arm') {
      const parsed = debuggerParseRules(own, carried);
      if (parsed.error) { say(parsed.error); view.repaint(); return; }
      rules = parsed.rules;
    }
    own.sending = true;
    say(action === 'arm' ? `Arming on document ${live.target_id}…` : `Clearing the rules of document ${live.target_id}…`);
    view.repaint();
    try {
      const reply = await view.hooks.watch(rules);
      if (!reply) say(`No confirmed answer from document ${live.target_id}. The rules may have changed; nothing was retried.`);
      else if (reply.status !== 'ok') say(`Refused by document ${live.target_id}: ${reply.text || reply.status}. A refused set leaves nothing armed.`);
      else if (action === 'arm') say(`Armed on document ${live.target_id}. The renderer confirmed the set below.`, 'armed', live.target_id, view.readsStarted());
      else say(`Cleared on document ${live.target_id}.`, 'cleared', live.target_id, view.readsStarted());
    } catch (error) {
      say(`Not confirmed by document ${live.target_id}: ${error?.message ?? error}. Nothing was retried.`);
    } finally {
      own.sending = false;
      // A read of the confirmed set starts now; the outcome shows meanwhile.
      view.readAfterAction();
      view.repaint();
    }
  }
  function drop() {
    form?.element.remove();
    form = null;
  }
  return {
    id: 'watch-rules', title: 'Watch rules', order: 20,
    summary: view => view.document?.watch?.state ?? '',
    render(body, view) {
      const unread = debuggerUnread(view);
      if (unread) { drop(); body.replaceChildren(unread); return; }
      let armedBox = body.querySelector(':scope > .debugger-watch-state');
      if (!armedBox) { drop(); armedBox = debuggerNode('div', 'debugger-watch-state'); body.replaceChildren(armedBox); }
      const watch = view.document.watch, armed = watch.state === 'armed' ? watch.armed : null;
      // A read that started after the outcome and disagrees with it ends it:
      // "Armed on document 22" never stands above "No rules armed".
      if (outcome && view.readSerial > outcome.after && view.status === 'ready' && watch.state !== 'busy') {
        const armedThere = armed?.target_id === outcome.target;
        if ((outcome.kind === 'armed' && !armedThere) || (outcome.kind === 'cleared' && armedThere)) outcome = null;
      }
      // Until a read after the arm answers, the confirmed set is not below yet.
      const text = outcome?.kind === 'armed' && !(view.readSerial > outcome.after)
        ? `Armed on document ${outcome.target}. Reading the set the renderer confirmed…` : outcome?.text ?? '';
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
        drop();
        if (text) nodes.push(debuggerNote(text, 'warning'));
        nodes.push(debuggerNote('To arm or clear rules, connect the Console to a live capture document: select it, confirm that commands can change it, then Connect. The rules arm through that connection\'s watch command; this sidebar never selects or confirms a document.'));
        debuggerReplace(armedBox, nodes);
        return;
      }
      debuggerReplace(armedBox, nodes);
      // The Console holds another document: that document gets a form of its own.
      if (form && (!sameDocument(form.document, live) || !body.contains(form.element))) drop();
      if (!form) { form = build(view, live); body.append(form.element); }
      const same = sameDocument(armed, live);
      const key = JSON.stringify(same ? armed.rules : null);
      // A draft being typed is never overwritten by a poll.
      const focused = document.activeElement;
      if (form.draftFor !== key && !(focused && form.element.contains(focused))) { fill(form, same ? armed.rules : null); form.draftFor = key; }
      const carried = same && Array.isArray(armed.rules?.dom) ? armed.rules.dom.length : 0;
      form.dom.textContent = carried
        ? `Arming here keeps the ${carried} DOM ${carried === 1 ? 'rule' : 'rules'} armed from the Console. Arming replaces the whole set; a refused set leaves nothing armed.`
        : 'DOM mutation rules need an element handle from the Console watch command. Arming replaces the whole set; a refused set leaves nothing armed.';
      form.arm.textContent = form.sending ? 'Working…' : `Arm on document ${form.document.target_id}`;
      form.arm.title = `Arms these rules on Console document ${form.document.target_id}${form.document.label ? ` (${form.document.label})` : ''} through the live Console connection. Nothing pauses and no value is read.`;
      form.arm.disabled = form.sending;
      form.clear.disabled = form.sending || !same;
      if (form.output.textContent !== text) form.output.textContent = text;
      form.output.hidden = !text;
    },
    release() { drop(); }
  };
}

// Observations: the newest records per kind, with their identities. A row
// opens its script position in Sources or its request in Traffic. The notes
// say how much of the store the rows come from: an empty list says that no
// record exists only when the whole store was read.
function debuggerObservationsSection() {
  // `shown` is what the list holds now; `revealKey` names the record whose
  // details come into view, again once its positions resolve; `opening` is the
  // one Traffic lookup in flight.
  let list = null, controls = null, detail = null, selected = null, detailTimer = 0, notice = null, revealKey = null, shown = [], opening = null;
  const stacks = new Map();
  // Read once per record; a failed read is tried again only after a pause.
  function resolution(view, record) {
    const key = debuggerRecordKey(record);
    let entry = stacks.get(key);
    const retry = entry?.retryAt && Date.now() >= entry.retryAt;
    if ((!entry || retry) && view.hooks.mode() !== 'none') {
      stacks.delete(key);
      entry = {status: 'loading'};
      stacks.set(key, entry);
      while (stacks.size > DEBUGGER_SIDEBAR.stacks) stacks.delete(stacks.keys().next().value);
      const parameters = new URLSearchParams({session_id: record.session_id, process_id: String(record.process_id), observation_sequence: record.sequence_number});
      const deadline = AbortSignal.timeout(DEBUGGER_SIDEBAR.deadline);
      entry.promise = view.hooks.fetch(`/api/request-stack?${parameters}`, {cache: 'no-store', signal: deadline})
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
          error: deadline.aborted ? 'the backend did not answer within 10 seconds' : String(error?.message ?? error)}))
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
  // A row the researcher chose is marked at once and brings its details into view.
  function choose(view, item, how) {
    if (!item) return;
    if (selected?.key !== item.key) notice = null;
    if (opening && opening.key !== item.key) cancelOpening();
    selected = item;
    revealKey = item.key;
    list?.set(shown, {selectedKey: item.key});
    holdPlace(view);
    paintDetail(view);
    if (how === 'Enter' || how === 'dblclick') openPrimary(view, item.record);
  }
  // A selection or a scrolled list keeps the rows; at the top with nothing
  // selected they follow the newest page.
  function holdPlace(view) {
    if (!list) return;
    if (selected || list.element.scrollTop > 0) view.holdObservations();
    else if (view.followNewest()) view.repaint();
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
  function cancelOpening() {
    opening?.controller.abort();
    opening = null;
  }
  // One lookup at a time: a newer click, choosing another record, the kind
  // filter, Show newest, closing the sidebar or leaving Sources cancels it,
  // and its link says it is working.
  function openRequest(view, record) {
    const key = debuggerRecordKey(record);
    opening?.controller.abort();
    const controller = new AbortController();
    opening = {key, controller};
    paintDetail(view);
    Promise.resolve(view.hooks.openRequest(record, controller.signal))
      .then(problem => { if (problem && !controller.signal.aborted && selected?.key === key) say(view, record, problem); },
        error => { if (!controller.signal.aborted && selected?.key === key) say(view, record, `The request was not opened: ${error?.message ?? error}.`); })
      .finally(() => { if (opening?.controller === controller) { opening = null; paintDetail(view); } });
  }
  function paintDetail(view) {
    if (!detail) return;
    if (!selected) { detail.hidden = true; detail.replaceChildren(); delete detail.dataset.signature; revealKey = null; return; }
    const record = selected.record, entry = resolution(view, record);
    const listed = shown.some(item => item.key === selected.key);
    // Repainting only on a change keeps focus on its buttons between polls.
    const signature = `${selected.key}|${entry.status}|${notice?.key === selected.key ? notice.text : ''}|${opening?.key === selected.key}|${listed}`;
    if (detail.dataset.signature !== signature || detail.hidden) {
      detail.dataset.signature = signature;
      detail.hidden = false;
      detail.replaceChildren(...detailNodes(view, record, entry, listed));
    }
    // Into view when chosen, and again once its positions resolve and its
    // actions appear; the actions row first when the detail is taller.
    if (revealKey === selected.key) {
      if (entry.status !== 'loading') revealKey = null;
      if (typeof detail.scrollIntoView === 'function') detail.scrollIntoView({block: 'nearest'});
      const actions = detail.querySelector('.debugger-detail-actions');
      if (actions && typeof actions.scrollIntoView === 'function') actions.scrollIntoView({block: 'nearest'});
    }
  }
  function detailNodes(view, record, entry, listed) {
    const heading = debuggerNode('div', 'debugger-detail-head');
    heading.append(debuggerNode('strong', '', debuggerObservationText(record)), debuggerButton('×', 'debugger-detail-close', () => {
      selected = null; notice = null; opening?.controller.abort(); paintDetail(view); list?.set(shown, {selectedKey: null}); holdPlace(view); list?.focus();
    }));
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
    if (!listed) nodes.push(debuggerNote('This record is no longer in the list above; its details stay until another row is chosen.', 'warning'));
    const actions = debuggerNode('div', 'debugger-detail-actions');
    if (record.type === 'request_watch_match' && record.request_id !== '0') {
      const busy = opening?.key === debuggerRecordKey(record);
      const link = debuggerButton(busy ? 'Opening request in Traffic…' : 'Open request in Traffic', 'secondary-button debugger-open-request', () => openRequest(view, record));
      if (busy) link.setAttribute('aria-busy', 'true');
      actions.append(link);
    }
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
    return nodes;
  }
  // The loaded pages when older ones were read, else the newest page.
  function rows(view) {
    const observations = view.observations;
    return (observations.list?.records ?? observations.head).slice(0, DEBUGGER_SIDEBAR.rows)
      .map(record => ({key: debuggerRecordKey(record), record, height: DEBUGGER_SIDEBAR.observationRow}));
  }
  // How much of the store the rows were read from.
  function coverage(view, count, kind, scope) {
    const observations = view.observations, query = observations.query, loaded = observations.list;
    const end = BigInt(query.store_end);
    const top = loaded ? loaded.top : end;
    const bottom = loaded ? loaded.bottom : query.next_before;
    const whole = bottom === null && !loaded?.pinned && !loaded?.dropped && (loaded ? true : query.scope === 'store');
    const read = top - (bottom === null ? 0n : BigInt(bottom));
    const where = whole ? 'the whole event store'
      : loaded?.dropped ? `the newest records of the event store's ${debuggerBytes(end)}`
        : loaded?.pinned ? `${debuggerBytes(read)} of the event store's ${debuggerBytes(end)}, below the newest ${debuggerBytes(end - top)}`
          : `the newest ${debuggerBytes(read)} of the event store's ${debuggerBytes(end)}`;
    const why = !whole && (loaded?.query ?? query).budget_exhausted ? ', where the last read stopped at its 64 MiB budget' : '';
    if (!count) {
      if (whole) return view.kind || scope ? `No ${kind}${scope} in ${where}.` : 'No observation records in the event store. Arm rules on a live document to record them; nothing pauses.';
      return `No ${kind}${scope} in ${where}${why}. Older bytes were not read, so older records may exist: Show older records reads them.`;
    }
    const capped = count >= DEBUGGER_SIDEBAR.rows ? `, the most this list keeps; get_events pages the rest` : '';
    return `${count.toLocaleString('en-US')} ${kind}${scope}, newest first, from ${where}${why}${capped}. Enter opens a row's position in Sources, or its request in Traffic.`;
  }
  function build(view) {
    // A pane drawn again (reopened or expanded) starts at its top with no
    // selection, so it holds no place: no rows are kept from before.
    if (!selected) view.followNewest(true);
    const root = debuggerNode('div', 'debugger-observations');
    const kinds = debuggerNode('div', 'debugger-kinds');
    kinds.setAttribute('role', 'group');
    kinds.setAttribute('aria-label', 'Observation kind');
    for (const [kind, text] of [[null, 'All'], ...Object.entries(DEBUGGER_OBSERVATION_KINDS).map(([kind, value]) => [kind, value.filter])]) {
      const pill = debuggerButton(text, 'debugger-kind', () => { selected = null; cancelOpening(); view.setKind(kind); });
      pill.dataset.kind = kind ?? 'all';
      kinds.append(pill);
    }
    const notes = debuggerNode('div', 'debugger-observation-notes');
    // A list kept at older pages says what was written since and offers the newest.
    const pinned = debuggerNode('div', 'debugger-observation-pinned');
    const pinnedText = debuggerNote('', 'warning');
    pinned.append(pinnedText, debuggerButton('Show newest', 'secondary-button debugger-show-newest', () => {
      selected = null;
      cancelOpening();
      if (list) list.element.scrollTop = 0;
      view.showNewest();
    }));
    pinned.hidden = true;
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
    list.element.addEventListener('scroll', () => holdPlace(view), {passive: true});
    const more = debuggerButton('Show older records', 'secondary-button debugger-older', () => view.older());
    detail = debuggerNode('div', 'debugger-detail');
    detail.hidden = true;
    root.append(kinds, notes, pinned, list.element, more, detail);
    controls = {root, kinds, notes, pinned, pinnedText, more};
  }
  return {
    id: 'observations', title: 'Observations', order: 30,
    summary: view => view.document ? String(rows(view).length) : '',
    render(body, view) {
      const unread = debuggerUnread(view);
      if (unread) { list?.release(); list = null; controls = null; detail = null; body.replaceChildren(unread); return; }
      if (!controls || !body.contains(controls.root)) { build(view); body.replaceChildren(controls.root); }
      for (const pill of controls.kinds.children) pill.setAttribute('aria-pressed', String((pill.dataset.kind === 'all' ? null : pill.dataset.kind) === view.kind));
      const answer = view.document, observations = view.observations, loaded = observations.list;
      const current = Boolean(observations.query) && observations.key === `${view.kind ?? 'all'}|${view.thread?.kind === 'observed' ? view.thread.key : 'all'}`;
      // Until the new filter is read, the rows read before stay, named as what they are.
      const items = observations.query ? rows(view) : [];
      const notes = [];
      const scope = view.thread?.kind === 'observed' ? ` in frame ${view.thread.frame_id}` : '';
      const kind = view.kind ? DEBUGGER_OBSERVATION_KINDS[view.kind].filter.toLowerCase() : 'records';
      if (current) notes.push(debuggerNote(coverage(view, items.length, kind, scope)));
      else if (!observations.query || view.status === 'ready' || view.status === 'loading') notes.push(debuggerNote('Reading…'));
      else {
        const before = observations.query.type ? DEBUGGER_OBSERVATION_KINDS[observations.query.type].filter.toLowerCase() : 'records';
        const where = observations.query.thread ? ` in frame ${observations.query.thread.frame_id}` : '';
        notes.push(debuggerNote(`The ${kind}${scope} were not read. The rows below are the ${before}${where} read before.`, 'warning'));
      }
      const malformed = answer.observations_malformed + observations.refused + (loaded?.refused ?? 0);
      if (malformed > 0) notes.push(debuggerNote(`${malformed} ${malformed === 1 ? 'record' : 'records'} in these reads ${malformed === 1 ? 'was' : 'were'} malformed and ${malformed === 1 ? 'is' : 'are'} not shown.`, 'warning'));
      for (const gap of answer.observation_budget_gaps.slice(0, 2)) {
        notes.push(debuggerNote(`Renderer ${gap.process_id} reached 1,024 observation records in frame ${gap.frame_id} (gap #${gap.sequence_number}); its later records were refused until the next capture.`, 'gap'));
      }
      const gap = debuggerGapNote(view);
      if (gap) notes.push(gap);
      if (observations.olderError) notes.push(debuggerNote(`Older records were not read: ${observations.olderError}`, 'warning'));
      if (current && loaded?.dropped) {
        notes.push(debuggerNote(`The list keeps at most ${DEBUGGER_SIDEBAR.rows.toLocaleString('en-US')} records, so ${loaded.dropped.toLocaleString('en-US')} older ${loaded.dropped === 1 ? 'row was' : 'rows were'} dropped as newer ones arrived; get_events pages them.`, 'warning'));
      }
      debuggerReplace(controls.notes, notes);
      const pin = current ? loaded?.pinned : null;
      controls.pinned.hidden = !pin;
      if (pin) {
        const text = `Kept where you were: the ${debuggerBytes(pin.to - pin.from)} written since (bytes ${pin.from} to ${pin.to}) are more than ${DEBUGGER_SIDEBAR.bridge} reads and are not in this list.`;
        if (controls.pinnedText.textContent !== text) controls.pinnedText.textContent = text;
      }
      list.element.hidden = !items.length;
      shown = items;
      list.set(items, {selectedKey: selected?.key ?? null});
      const end = loaded ? loaded.bottom : observations.query?.next_before ?? null;
      controls.more.hidden = !current || end === null || items.length >= DEBUGGER_SIDEBAR.rows;
      controls.more.disabled = observations.loadingOlder;
      controls.more.textContent = observations.loadingOlder ? 'Reading older records…' : 'Show older records';
      if (selected) {
        const kept = items.find(item => item.key === selected.key);
        if (kept) selected = kept;
      }
      // A selection or scroll carried into these rows (a Threads scope, say) holds them.
      if (current && (selected || list.element.scrollTop > 0)) view.holdObservations();
      paintDetail(view);
    },
    release() {
      clearTimeout(detailTimer); opening?.controller.abort(); opening = null;
      list?.release(); list = null; controls = null; detail = null; selected = null; notice = null; shown = []; revealKey = null;
    }
  };
}

// Pausing: one state, from the availability get_native_debugger reports. A
// section registered with native: 'pausing' either replaces this one (id
// pausing) or follows it, and then this statement names it; none is imitated.
function debuggerPausingSection() {
  return {
    id: 'pausing', title: 'Pausing', order: 40,
    summary: view => view.document?.availability ?? '',
    render(body, view) {
      const unread = debuggerUnread(view);
      if (unread) { delete body.dataset.signature; body.replaceChildren(unread); return; }
      const answer = view.document, available = answer.availability === 'available';
      const others = view.nativeSections();
      const titles = others.map(section => section.title);
      const names = titles.length > 1 ? `${titles.slice(0, -1).join(', ')} and ${titles.at(-1)}` : titles.join('');
      const where = others.length === 1 ? `the ${names} section` : `the ${names} sections`;
      const state = debuggerNode('p', 'debugger-note debugger-pausing-state');
      state.dataset.debuggerNative = 'availability';
      state.dataset.availability = answer.availability;
      state.append(debuggerNode('strong', '', available ? 'Available. ' : 'Unsupported. '), available
        ? others.length ? `A Brave build serves the pausing debugger. Its controls are in ${where}.`
          : 'A Brave build serves the pausing debugger, but its controls are not part of this sidebar yet, so nothing here can pause the page.'
        : `No Brave build serves the pausing debugger (${answer.reason}), so breakpoints, scopes, a paused call stack and stepping are unavailable. Nothing is attached and no page is paused.${others.length ? ` The controls in ${where} stay disabled.` : ''}`);
      const fields = debuggerNode('dl', 'debugger-fields');
      for (const [label, value] of [
        ['Policy', answer.policy === 'approved' ? 'approved in SAFETY.md' : 'proposed, pending maintainer approval'],
        ['Experiment', `${answer.experiment_flag}, off by default`],
        ['Pause lease', `at most ${Math.round(answer.lease_limit_ms / 1000)} seconds`],
        ['Detectable', answer.detectable ? 'yes, a page can detect an active debugger' : 'no']
      ]) fields.append(debuggerNode('dt', '', label), debuggerNode('dd', '', value));
      debuggerReplace(body, [state, fields]);
    }
  };
}

for (const section of [debuggerThreadsSection(), debuggerWatchSection(), debuggerObservationsSection(), debuggerPausingSection()]) {
  globalThis.RebDebuggerSidebar.addSection(section);
  debuggerSidebarReserved.add(section.id);
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
    // A live window polls its backend; the stored-evidence window (reb://)
    // answers from its fixed store; any other window has no backend.
    mode: () => location.protocol === 'http:' || location.protocol === 'https:' ? 'live' : location.protocol === 'reb:' ? 'stored' : 'none',
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
    // The renderer request's Traffic row, named by the request index's own row
    // identity, selected the way a click on that row selects it. A row outside
    // the block Traffic holds is located in the request index first. Nothing
    // switches screens once `signal` is aborted, the sidebar is closed or
    // Sources is no longer showing.
    async openRequest(record, signal) {
      const app = appState(), id = `S${record.session_id}:R${record.process_id}:${record.request_id}`;
      const name = `Request ${record.request_id} of renderer ${record.process_id}`;
      // Leaving Sources and coming back counts as moving on, as closing does.
      const stopped = debuggerSidebarController?.stops() ?? 0;
      const moved = () => signal?.aborted || !debuggerSidebarController?.isOpen() || screen.hidden || debuggerSidebarController.stops() !== stopped;
      if (!app || typeof selectTrafficRow !== 'function' || typeof showScreen !== 'function') return `${name} cannot be opened: Traffic is not available here.`;
      let located = null;
      if (!app.trafficIndex?.row?.(id) && !(app.requests ?? []).some(request => request.id === id)) {
        if (!app.trafficIndex || typeof loadTrafficRequest !== 'function' || typeof trafficIndexRequest !== 'function') {
          return `${name} is not among the Traffic rows loaded now, and no request index can locate it. Its stack is shown here.`;
        }
        const ask = async parameters => {
          const deadline = AbortSignal.timeout(DEBUGGER_SIDEBAR.deadline);
          let response;
          try {
            response = await hooks.fetch(`/api/requests?${new URLSearchParams({sort: 'capture', order: 'asc', limit: '1', ...parameters})}`,
              {cache: 'no-store', signal: signal && typeof AbortSignal.any === 'function' ? AbortSignal.any([signal, deadline]) : deadline});
          } catch (error) {
            if (deadline.aborted && !signal?.aborted) throw new Error('the request index did not answer within 10 seconds');
            throw error;
          }
          const page = await response.json().catch(() => null);
          if (!response.ok || page?.format !== 'reb-request-index-v1' || !Array.isArray(page.requests)) throw new Error(`the request index answered HTTP ${response.status}`);
          return page;
        };
        try {
          const position = (await ask({offset: '0', locate: id})).located?.[id];
          if (moved()) return null;
          if (!Number.isSafeInteger(position)) return `${name} is not in the request index. Its stack is shown here.`;
          const row = (await ask({offset: String(position)})).requests[0];
          if (moved()) return null;
          if (row?.id !== id) return `${name} moved in the request index while it was located. Nothing was selected.`;
          located = trafficIndexRequest(row, app.sessionMode === 'demo' ? 'demo' : 'live');
        } catch (error) {
          if (moved()) return null;
          return `${name} was not located: ${error?.message ?? error}.`;
        }
      }
      if (moved()) return null;
      if (hooks.overlays()) debuggerSidebarController?.setOpen(false);
      showScreen('traffic');
      if (typeof setConsoleTrafficView === 'function') setConsoleTrafficView(false);
      app.inspectorTab = 'initiator';
      // Traffic's own selection; it reads the row's records when the newest window lacks them.
      if (located && !app.trafficIndex.row(id)) loadTrafficRequest(located, true);
      else selectTrafficRow(id);
      if (typeof renderInspector === 'function') renderInspector();
      return null;
    },
    consoleLive: () => globalThis.RebNativeConsole?.liveDocument?.() ?? null,
    watch: rules => globalThis.RebNativeConsole?.watch?.(rules) ?? Promise.resolve(null),
    sequenceGaps: () => typeof shownSequenceGaps === 'function' ? shownSequenceGaps() : null
  };
  debuggerSidebarController = createDebuggerSidebar({root, toggle, screen, hooks});
})();
