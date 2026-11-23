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
  page: 128, rows: 4096, stacks: 32, bridge: 2, threadRow: 28, groupRow: 24, observationRow: 44, overscan: 6, listHeight: 240});

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
  not_retained_budget: 'stack not retained (older build budget)'});
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
  // Opens on one observation record (session_id, process_id, sequence_number,
  // type and frame_id): its kind is listed and its row selected once a read
  // holds it. Traffic's watched requests link here.
  showObservation: record => Boolean(debuggerSidebarController?.reveal(record)),
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

// A loss or gap count in the locale grouping the status bar and its chips use.
function debuggerCount(value) {
  return globalThis.RebEvidenceChips?.formatCount(value) ?? String(value);
}

// The recorded monotonic time, exact to the microsecond.
function debuggerTime(ns) {
  try {
    const micros = BigInt(ns) / 1000n;
    return `${(micros / 1000000n).toString()}.${(micros % 1000000n).toString().padStart(6, '0')} s`;
  } catch {
    return 'time not recorded';
  }
}

// The first record time of a record's session (get_native_debugger's
// time_origins), or null while the event index has not folded that session.
function debuggerOrigin(answer, record) {
  const origins = Array.isArray(answer?.time_origins) ? answer.time_origins : [];
  return origins.find(origin => origin?.session_id === record.session_id)?.monotonic_time_ns ?? null;
}

// A monotonic time as minutes and seconds since `origin`, its session's first
// record; the exact value stays in the row's tooltip and details. Without an
// origin the exact value is all there is.
function debuggerRelativeTime(ns, origin) {
  try {
    if (origin === null || origin === undefined) return debuggerTime(ns);
    const delta = BigInt(ns) - BigInt(origin), sign = delta < 0n ? '-' : '+';
    const ms = (delta < 0n ? -delta : delta) / 1000000n;
    const pad = (value, width) => value.toString().padStart(width, '0');
    const [hours, minutes, seconds] = [ms / 3600000n, ms / 60000n % 60n, ms / 1000n % 60n];
    const clock = hours ? `${hours}:${pad(minutes, 2)}` : `${minutes}`;
    return `${sign}${clock}:${pad(seconds, 2)}.${pad(ms % 1000n, 3)}`;
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
 * scrolled away never takes focus with it. Its frame shades the edge that
 * has more rows past it. It stops on a whole row, not wherever its CSS cap
 * lands: the row edge nearest the cap, or its end, so no row shows sliced and
 * a list the cap would cut by a few pixels shows whole. A group heading is
 * never its last row. */
function createDebuggerList({id, label, onActive = null, onChoose, render}) {
  const box = debuggerNode('div', 'debugger-list-frame');
  const element = debuggerNode('div', 'debugger-list');
  box.append(element);
  element.id = id;
  element.tabIndex = 0;
  element.setAttribute('role', 'listbox');
  element.setAttribute('aria-label', label);
  const space = debuggerNode('div', 'debugger-list-space');
  element.append(space);
  let items = [], tops = [0], options = [], active = null, selected = null, signature = '', frame = 0, unfit = true;
  const rowId = key => `${id}-row-${String(key).replace(/[^A-Za-z0-9_-]/g, '-')}`;
  const indexOf = key => items.findIndex(item => item.key === key);

  function fit() {
    unfit = false;
    element.style.maxHeight = '';
    const cap = typeof getComputedStyle === 'function' ? Number.parseFloat(getComputedStyle(element).maxHeight) : Number.NaN;
    const total = tops.at(-1);
    if (!Number.isFinite(cap) || total <= cap) return;
    let stop = total;
    items.forEach((item, index) => {
      if (!item.header && Math.abs(tops[index + 1] - cap) < Math.abs(stop - cap)) stop = tops[index + 1];
    });
    element.style.maxHeight = `${stop}px`;
  }
  // The cap follows the window's height.
  const refit = () => { unfit = true; schedule(); };
  if (typeof addEventListener === 'function') addEventListener('resize', refit);

  function paint() {
    frame = 0;
    if (unfit && element.isConnected) fit();
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
    const above = top > 0.5, below = tops.at(-1) - top - height > 0.5;
    box.dataset.more = above && below ? 'both' : above ? 'above' : below ? 'below' : 'none';
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
    box,
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
        unfit = true;
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
    scrollTo(key) { reveal(key); paint(); },
    // The painted row of `key`, or null while it is outside the window.
    row(key) { return [...space.children].find(row => row.dataset.key === key) ?? null; },
    release() {
      if (frame > 0 && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(frame);
      if (typeof removeEventListener === 'function') removeEventListener('resize', refit);
      frame = 0; space.replaceChildren(); items = []; options = []; tops = [0]; signature = ''; active = null;
    }
  };
}

/* Threads: Console documents, workers whose requests the renderer recorded,
 * and the native frames observation records came from. It needs only the
 * get_native_debugger document, so it stands on its own wherever it mounts.
 * A row reads as one line: what the thread is (`label`), its identifiers
 * (`ids`) and its activity or state (`badge`); `tag` names a document's frame
 * kind. Every field is in full in the row's tooltip and the selected details. */
function debuggerThreads(answer, {frameOrigin = () => null, consoleTarget = null} = {}) {
  const threads = answer?.threads ?? {frames: [], workers: [], observed: []};
  const armed = answer?.watch?.state === 'armed' ? answer.watch.armed?.target_id ?? null : null;
  const count = (value, one, many) => `${Number(value).toLocaleString('en-US')} ${value === 1 ? one : many}`;
  const documents = threads.frames.map(target => {
    const id = String(target.target_id), oop = target.out_of_process === true;
    const state = id === armed ? 'watch armed' : id === consoleTarget ? 'Console connected' : 'listed';
    return {key: `D:${id}`, kind: 'document', target_id: id, group: 'Console documents',
      title: target.frame === 'top' ? 'Top frame' : oop ? 'Out-of-process frame' : 'Child frame',
      origin: target.origin || '(no origin)', label: target.origin || '(no origin)', missing: !target.origin,
      tag: target.frame === 'top' ? 'top' : oop ? 'OOPIF' : 'child', ids: `doc ${id}`,
      badge: id === armed ? 'armed' : id === consoleTarget ? 'Console' : '', tone: id === armed ? 'ok' : 'accent',
      frame: `${target.frame} · document ${id}`,
      process: target.frame === 'top' ? 'process not listed'
        : oop ? 'own renderer (site isolation)' : target.out_of_process === false ? 'top renderer' : 'process undetermined',
      state};
  });
  const workers = threads.workers.map(worker => ({
    key: `W:${worker.session_id}:${worker.process_id}:${worker.context_id}`, kind: 'worker', group: 'Workers',
    session_id: worker.session_id, process_id: worker.process_id, context_id: worker.context_id,
    title: DEBUGGER_WORKER_KINDS[worker.kind] ?? 'Worker', origin: 'origin not recorded',
    label: DEBUGGER_WORKER_KINDS[worker.kind] ?? 'Worker', ids: `ctx ${worker.context_id} P${worker.process_id}`,
    badge: `${Number(worker.requests).toLocaleString('en-US')} req`,
    frame: `context ${worker.context_id}`, process: `process ${worker.process_id}`, last: worker.last_sequence,
    state: count(worker.requests, 'request', 'requests')
  }));
  const observed = threads.observed.map(frame => {
    const origin = frameOrigin(frame.session_id, frame.frame_id);
    return {key: `F:${frame.session_id}:${frame.process_id}:${frame.frame_id}`, kind: 'observed', group: 'Observed frames',
      session_id: frame.session_id, process_id: frame.process_id, frame_id: frame.frame_id, kinds: frame.kinds ?? null,
      title: 'Observed frame', origin: origin ?? 'no retained document', missing: !origin, last: frame.last_sequence,
      label: origin ?? `frame ${frame.frame_id}`, ids: origin ? `F${frame.frame_id} P${frame.process_id}` : `P${frame.process_id}`,
      badge: Number(frame.records).toLocaleString('en-US'),
      frame: `frame ${frame.frame_id} · session ${frame.session_id}`, process: `process ${frame.process_id}`,
      state: count(frame.records, 'record', 'records')};
  });
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
      row.append(debuggerNode('span', 'debugger-list-group-name', item.title), debuggerNode('span', 'debugger-list-count', item.count));
      return;
    }
    row.dataset.kind = item.kind;
    if (item.tag) row.append(debuggerNode('span', 'debugger-thread-tag', item.tag));
    const label = debuggerNode('span', 'debugger-row-main', item.label);
    if (item.missing) label.dataset.missing = 'true';
    const badge = debuggerNode('span', 'debugger-thread-badge', item.badge);
    if (item.badge && item.kind === 'document') badge.dataset.tone = item.tone;
    row.append(label, debuggerNode('span', 'debugger-thread-ids', item.ids), badge);
    row.title = debuggerThreadFields(item).map(([label, value]) => `${label}: ${value}`).join('\n');
  }});
  const empty = debuggerNode('p', 'debugger-note debugger-empty');
  root.append(list.box, empty);
  return {
    element: root,
    render(groups, selectedKey) {
      const items = [];
      for (const group of groups) {
        if (!group.length) continue;
        items.push({key: `group:${group[0].group}`, header: true, title: group[0].group, count: group.length.toLocaleString('en-US'), height: DEBUGGER_SIDEBAR.groupRow});
        for (const thread of group) items.push({...thread, height: DEBUGGER_SIDEBAR.threadRow, version: `${thread.state}|${thread.label}|${thread.badge}|${thread.last ?? ''}`});
      }
      list.box.hidden = !items.length;
      empty.hidden = Boolean(items.length);
      empty.textContent = 'No threads yet. Frames and workers appear as they record; documents once the Console connects.';
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
  // A dot and a word for the state, then the time of the last read. Only the
  // state is announced; the time changes every poll, and the interval, which
  // follows how long reads take, is in the tooltip.
  const status = debuggerNode('div', 'debugger-sidebar-status');
  const dot = debuggerNode('span', 'debugger-status-dot');
  dot.setAttribute('aria-hidden', 'true');
  const announced = debuggerNode('span', 'debugger-status-state');
  announced.setAttribute('role', 'status');
  announced.setAttribute('aria-live', 'polite');
  const when = debuggerNode('span', 'debugger-status-time');
  const again = debuggerButton('Read again', 'debugger-link debugger-status-again', () => read());
  status.append(dot, announced, when, again);
  const body = debuggerNode('div', 'debugger-sidebar-sections');
  root.append(head, status, body);
  root.setAttribute('aria-labelledby', title.id);

  let open = false, timer = 0, generation = 0, interval = DEBUGGER_SIDEBAR.poll, controller = null;
  // `renderTurn` lasts from a render until the next task, so a refresh() a
  // section queues from render (even as a promise) is ignored.
  let rendering = false, renderTurn = false, renderTurns = 0, lastStarted = 0, refreshQueued = false, stops = 0, readsStarted = 0;
  const mounted = new Map();
  const blankObservations = () => ({key: null, head: [], refused: 0, query: null, list: null, loadingOlder: false, olderError: null, olderController: null, olderCreated: null});
  const view = {
    // `readSerial` numbers the read whose answer `document` is; readsStarted()
    // counts reads begun, so an action can tell which reads followed it.
    status: 'loading', document: null, error: null, updatedAt: null, readSerial: 0, thread: null, kind: null, reveal: null,
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
      view.reveal = null;
      view.thread = thread && view.thread?.key === thread.key ? null : thread;
      hooks.refreshTree?.();
      read();
    },
    setKind(kind) {
      view.reveal = null;
      view.kind = Object.hasOwn(DEBUGGER_OBSERVATION_KINDS, kind) ? kind : null;
      read();
    },
    older: () => readOlder(),
    showNewest() { view.reveal = null; dropList(); render(); read(); },
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
      if (!open || rendering) return;
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
    Object.assign(observations, {list: null, loadingOlder: false, olderError: null, olderController: null, olderCreated: null});
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
    if (replaced) view.reveal = null;
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

  // A Show older read that added no page leaves a list it made only for
  // itself as it found it: none, so the rows follow the newest page again.
  function revertOlder() {
    const observations = view.observations, base = observations.olderCreated;
    observations.olderCreated = null;
    if (base && observations.list === base && !base.pinned) observations.list = null;
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
    observations.olderCreated = list ? null : base;
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
      revertOlder();
      observations.olderError = String(error?.message ?? error);
    } finally {
      if (observations.olderController === own) {
        observations.olderCreated = null;
        observations.loadingOlder = false;
        observations.olderController = null;
        render();
      }
    }
  }

  function renderStatus() {
    const kind = windowMode(), stored = kind === 'stored';
    const time = view.updatedAt ? view.updatedAt.toLocaleTimeString() : null;
    const every = `every ${Math.round(interval / 1000)} seconds`;
    const text = {
      loading: stored ? 'Reading stored evidence…' : 'Reading…',
      unavailable: 'No backend serves this window',
      ready: stored ? 'Stored evidence' : 'Live',
      disconnected: stored ? `Not answered: ${view.error}` : time ? `Disconnected: ${view.error}` : `Cannot read: ${view.error}`,
      malformed: `Malformed answer: ${view.error}`
    }[view.status];
    if (announced.textContent !== text) announced.textContent = text;
    when.textContent = !time ? '' : view.status === 'ready' ? time : `last read ${time}`;
    when.hidden = !time;
    status.title = {
      loading: stored ? 'The bundled backend can take 15 seconds to start.' : '',
      unavailable: 'This window has no backend, so the debugger state cannot be read.',
      ready: stored ? `Read once at ${time}: nothing captures in this window.` : `Read at ${time}. Reads ${every} while open.`,
      disconnected: stored ? 'Read again asks the stored-evidence backend again.'
        : `${time ? `Showing what was read at ${time}. ` : ''}Reading again ${every}.`,
      malformed: `The answer was not used.${time ? ` Showing what was read at ${time}.` : ''}`
    }[view.status];
    again.hidden = !stored || view.status === 'loading';
    status.dataset.kind = view.status;
    status.dataset.mode = kind;
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
    // Closing or leaving Sources is moving on: a pending showObservation ends.
    view.reveal = null;
    clearTimeout(timer);
    timer = 0;
    refreshQueued = false;
    controller?.abort();
    controller = null;
    revertOlder();
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
    // An observed-frame scope that excludes the record is cleared; any other
    // thread scope does not filter Observations, so it stays.
    reveal(record) {
      if (!record || !Object.hasOwn(DEBUGGER_OBSERVATION_KINDS, record.type)) return false;
      const thread = view.thread;
      if (thread?.kind === 'observed' && !(thread.session_id === record.session_id &&
          String(thread.process_id) === String(record.process_id) && thread.frame_id === record.frame_id)) view.thread = null;
      view.kind = record.type;
      // Where focus was when asked: the record takes focus only if it is still there.
      view.reveal = {key: debuggerRecordKey(record), record, after: readsStarted, focus: document.activeElement};
      hooks.refreshTree?.();
      if (open) read(); else setOpen(true);
      return true;
    },
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

// A short flag for a state the researcher must see (malformed records, gaps,
// a partial read): its words say what happened, `detail` says the rest in
// the tooltip, and an assistive reader hears both.
function debuggerFlag(text, detail = '', kind = 'warning') {
  const flag = debuggerNode('span', 'debugger-flag', text);
  flag.dataset.kind = kind;
  if (detail) {
    flag.title = detail;
    flag.append(debuggerNode('span', 'debugger-visually-hidden', `. ${detail}`));
  }
  return flag;
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

function debuggerGapFlag(view) {
  const gaps = view.hooks.sequenceGaps?.();
  return typeof gaps === 'bigint' && gaps > 0n
    ? debuggerFlag(`${debuggerCount(gaps)} sequence ${gaps === 1n ? 'gap' : 'gaps'}`,
      `${debuggerCount(gaps)} sequence-gap IDs in the retained window: records may be missing, so a missing row is unknown rather than absent.`, 'gap')
    : null;
}

// Threads section: the Threads view, the selected thread in full, and one
// line for the Console's state and what the event index covered.
function debuggerThreadsSection() {
  let threadsView = null;
  return {
    id: 'threads', title: 'Threads', order: 10,
    summary: view => view.document ? (view.document.threads.frames.length + view.document.threads.workers.length + view.document.threads.observed.length).toLocaleString('en-US') : '',
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
      // What the selection scopes, in one line.
      if (thread?.kind === 'observed') {
        const scope = debuggerNode('p', 'debugger-note debugger-scope');
        scope.append(`Observations and Sources show frame ${thread.frame_id} only. `,
          debuggerButton('Show all', 'debugger-link', () => view.selectThread(thread)));
        notes.push(scope);
      } else if (thread?.kind === 'document') {
        notes.push(debuggerNote('Nothing is scoped: a Console document carries no native frame ID. Select its observed frame instead.'));
      } else if (thread?.kind === 'worker') {
        notes.push(debuggerNote('Nothing is scoped: workers record no observations, and their scripts carry frame 0.'));
      }
      const foot = debuggerNode('p', 'debugger-thread-foot');
      foot.append(debuggerNode('span', '', `Console ${view.document.threads.console}`));
      const coverage = view.document.threads.coverage;
      if (coverage && coverage.scope !== 'store') {
        foot.append(debuggerFlag(`Indexed ${debuggerBytes(coverage.scan_end)} of ${debuggerBytes(coverage.store_end)}`,
          'Workers and observed frames cover the event store\'s indexed part while its index catches up.', 'gap'));
      }
      notes.push(foot);
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

// The rules that are on, one row each, then one row naming those that are
// off, so an armed set reads at a glance. A kept scope holds no DOM rules.
function debuggerRulesList(rules, {dom = true} = {}) {
  const list = debuggerNode('dl', 'debugger-rules');
  const off = [];
  for (const [label, values] of debuggerRulesText(rules)) {
    if (!dom && label === 'DOM mutations') continue;
    if (values.length === 1 && values[0] === 'off') { off.push(label); continue; }
    list.append(debuggerNode('dt', '', label));
    for (const value of values) list.append(debuggerNode('dd', '', value));
  }
  if (off.length) list.append(debuggerNode('dt', 'debugger-off', 'Off'), debuggerNode('dd', 'debugger-off', off.join(', ')));
  return list;
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
  if (requests.length > 32) return {error: 'At most 32 request rules.'};
  const events = [...new Set(form.events.value.split(/[\s,]+/).filter(Boolean))];
  if (events.length > 64 || events.some(name => name.length > 27 || !/^[!-~]+$/.test(name))) {
    return {error: 'At most 64 event types, each 1 to 27 printable ASCII characters.'};
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
    // The label and a short hint share one line above the control.
    const field = (label, control, hint) => {
      const wrap = debuggerNode('label', 'debugger-field');
      const head = debuggerNode('span', 'debugger-field-head');
      head.append(debuggerNode('span', 'debugger-field-label', label));
      if (hint) head.append(debuggerNode('span', 'debugger-field-hint', hint));
      wrap.append(head, control);
      return wrap;
    };
    const requests = debuggerNode('textarea', 'debugger-input');
    requests.rows = 2; requests.maxLength = 8800; requests.spellcheck = false; requests.placeholder = 'POST /api/login';
    const events = debuggerNode('input', 'debugger-input');
    events.type = 'text'; events.maxLength = 1860; events.spellcheck = false; events.autocomplete = 'off'; events.placeholder = 'click, submit';
    const check = text => { const label = debuggerNode('label', 'debugger-check'); const box = debuggerNode('input'); box.type = 'checkbox'; label.append(box, debuggerNode('span', '', text)); return {label, box}; };
    const timers = check('Timers'), csp = check('CSP violations');
    const exceptions = debuggerNode('select', 'debugger-select');
    for (const [value, text] of [['off', 'Off'], ['uncaught', 'Uncaught'], ['all', 'Caught and uncaught']]) {
      const option = debuggerNode('option', '', text); option.value = value; exceptions.append(option);
    }
    const exceptionsField = debuggerNode('label', 'debugger-check debugger-exceptions');
    exceptionsField.append(debuggerNode('span', '', 'Exceptions'), exceptions);
    const switches = debuggerNode('div', 'debugger-watch-switches');
    switches.append(timers.label, csp.label, exceptionsField);
    const dom = debuggerNode('p', 'debugger-note');
    // Keeping hands the rules to the browser, which arms every later document
    // of this document's exact origin and frame kind before its own scripts.
    const keep = debuggerNode('label', 'debugger-keep');
    const keepBox = debuggerNode('input');
    keepBox.type = 'checkbox';
    const keepText = debuggerNode('span', 'debugger-keep-text');
    keep.append(keepBox, keepText, debuggerNode('span', 'debugger-field-hint',
      'Armed before their own scripts, in any tab, until Clear rules or a Console Stop. DOM rules stay here.'));
    // What a rule cannot see, said where it is armed: a wait for it would time
    // out with nothing missing (protocol/native-debugger-observation-v1.md).
    const limits = debuggerNode('p', 'debugger-note debugger-watch-limits',
      'Main thread of armed documents only, never workers or other documents. Navigation clears these rules; kept rules arm later documents from their first script, not ones already open.');
    const arm = debuggerNode('button', 'secondary-button debugger-arm');
    arm.type = 'submit';
    const actions = debuggerNode('div', 'debugger-watch-actions');
    const output = debuggerNode('p', 'debugger-note debugger-watch-result');
    output.setAttribute('role', 'status');
    const own = {element, document: {session_id: live.session_id, target_id: live.target_id, label: live.label ?? ''},
      requests, events, timers: timers.box, csp: csp.box, exceptions, dom, keep: keepBox, keepText, arm, output, sending: false, draftFor: null};
    own.clear = debuggerButton('Clear rules', 'secondary-button', () => send(view, own, null));
    own.clear.title = 'Disarms this document\'s rules and forgets any kept ones.';
    actions.append(arm, own.clear);
    element.append(field('Requests', requests, 'one per line, method optional'),
      field('Listeners', events, 'event types, comma-separated'), switches, dom, keep, limits, actions, output);
    element.addEventListener('submit', event => { event.preventDefault(); send(view, own, 'arm'); });
    return own;
  }
  function fill(own, rules, kept) {
    own.keep.checked = Boolean(kept);
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
    const keep = action === 'arm' && own.keep.checked;
    own.sending = true;
    say(action === 'arm' ? `Arming on document ${live.target_id}…` : `Clearing the rules of document ${live.target_id}…`);
    view.repaint();
    try {
      const reply = await view.hooks.watch(rules, keep);
      // The browser names what it keeps; an older one leaves kept out.
      const kept = !keep ? '' : reply?.kept
        ? ` Kept for every later ${reply.kept.origin} ${reply.kept.frame === 'top' ? 'top-frame' : 'child-frame'} document.`
        : reply && 'kept' in reply ? ' Nothing is kept: only DOM rules were armed.' : ' This browser does not keep rules for later documents; nothing is kept.';
      if (!reply) say(`No confirmed answer from document ${live.target_id}. The rules may have changed; nothing was retried.`);
      else if (reply.status !== 'ok') say(`Refused by document ${live.target_id}: ${reply.text || reply.status}. A refused set leaves nothing armed.`);
      else if (action === 'arm') say(`Armed on document ${live.target_id}. The renderer confirmed the set below.${kept}`, 'armed', live.target_id, view.readsStarted());
      else say(`Cleared on document ${live.target_id}. Nothing is kept for later documents.`, 'cleared', live.target_id, view.readsStarted());
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
      const kept = watch.state === 'busy' ? null : watch.kept ?? null;
      // A read that started after the outcome and disagrees with it ends it:
      // "Armed on document 22" never stands above "No rules armed".
      if (outcome && view.readSerial > outcome.after && view.status === 'ready' && watch.state !== 'busy') {
        const armedThere = armed?.target_id === outcome.target;
        if ((outcome.kind === 'armed' && !armedThere) || (outcome.kind === 'cleared' && armedThere)) outcome = null;
      }
      // Until a read begun after the outcome answers, and while the Console
      // holds the session, the set below is not the one the outcome names.
      const pending = Boolean(outcome) && !(view.readSerial > outcome.after);
      const text = outcome?.kind === 'armed' && (pending || watch.state === 'busy')
        ? `Armed on document ${outcome.target}. Reading the set the renderer confirmed…`
        : outcome?.kind === 'cleared' && pending ? `Cleared on document ${outcome.target}. Reading the set that is left…` : outcome?.text ?? '';
      const live = view.hooks.consoleLive?.() ?? null;
      const nodes = [];
      // A heading line for each armed set: what holds it, then what it cannot see.
      const heading = (title, limit, detail) => {
        const line = debuggerNode('p', 'debugger-watch-head');
        line.append(debuggerNode('strong', '', title), ' ', debuggerNode('span', 'debugger-watch-limit', limit));
        line.title = detail;
        return line;
      };
      if (watch.state === 'busy') nodes.push(debuggerNote('A Console action holds the session; reading the armed set again shortly.', 'warning'));
      else if (!armed && !kept) {
        // One line and, without a live connection, the way to get one.
        const empty = debuggerNode('div', 'debugger-empty-row');
        empty.append(debuggerNode('span', 'debugger-empty-text', 'No rules armed'));
        if (!live && view.hooks.canOpenConsole?.()) {
          const open = debuggerButton('Open Console', 'secondary-button debugger-open-console', () => view.hooks.openConsole());
          open.title = 'Rules arm through the Console\'s live connection: choose Live capture there, select a document, confirm, then Connect.';
          empty.append(open);
        }
        nodes.push(empty);
      } else {
        if (armed) {
          nodes.push(heading(`Armed on Console document ${armed.target_id}`, kept?.target_id === armed.target_id ? 'main thread only · kept' : 'main thread only · navigation clears',
            `Console session ${armed.session_id}. Only its main thread is observed. Navigation, a new capture, Clear rules or a Console Stop disarms them.`));
          const thread = view.thread;
          if (thread?.kind === 'document' && thread.target_id !== armed.target_id) nodes.push(debuggerNote(`Selected document ${thread.target_id} has no rules; they are on document ${armed.target_id}.`, 'warning'));
          nodes.push(debuggerRulesList(armed.rules));
        } else {
          nodes.push(debuggerNote('No Console document holds rules of its own now.'));
        }
        if (kept) {
          const frame = kept.frame === 'top' ? 'top-frame' : 'child-frame';
          nodes.push(heading(`Kept for every later ${kept.origin} ${frame} document`, `from document ${kept.target_id}`,
            'Each one is armed before its own scripts run, in any tab; documents already open are not. Clear rules or a Console Stop forgets it.'));
          // The kept rules are the armed set without DOM rules; list them only
          // when no armed set above shows them.
          if (!armed || armed.target_id !== kept.target_id) nodes.push(debuggerRulesList(kept.rules, {dom: false}));
        }
        if (!live && view.hooks.canOpenConsole?.()) {
          const open = debuggerButton('Open Console to change', 'debugger-link debugger-open-console', () => view.hooks.openConsole());
          open.title = 'Rules change through the Console\'s live connection to the document.';
          nodes.push(open);
        }
      }
      if (!live) {
        drop();
        if (text) nodes.push(debuggerNote(text, 'warning'));
        debuggerReplace(armedBox, nodes);
        return;
      }
      debuggerReplace(armedBox, nodes);
      // The Console holds another document: that document gets a form of its own.
      if (form && (!sameDocument(form.document, live) || !body.contains(form.element))) drop();
      if (!form) { form = build(view, live); body.append(form.element); }
      const same = sameDocument(armed, live);
      const keptHere = same && kept?.target_id === armed.target_id;
      const key = JSON.stringify(same ? [armed.rules, keptHere] : null);
      // A draft being typed is never overwritten by a poll.
      const focused = document.activeElement;
      if (form.draftFor !== key && !(focused && form.element.contains(focused))) { fill(form, same ? armed.rules : null, keptHere); form.draftFor = key; }
      // The browser keeps the origin and frame kind of the document itself.
      const listed = view.document.threads?.frames?.find(frame => String(frame.target_id) === String(live.target_id));
      const keptOrigin = listed?.origin ? `${listed.origin} ${listed.frame === 'top' ? 'top-frame' : 'child-frame'}` : 'same-origin, same-kind';
      const keepText = `Keep for every later ${keptOrigin} document`;
      if (form.keepText.textContent !== keepText) form.keepText.textContent = keepText;
      form.keep.disabled = form.sending;
      const carried = same && Array.isArray(armed.rules?.dom) ? armed.rules.dom.length : 0;
      form.dom.textContent = carried
        ? `Keeps the ${carried} DOM ${carried === 1 ? 'rule' : 'rules'} the Console armed here.`
        : 'DOM rules come from the Console\'s watch command.';
      form.arm.textContent = form.sending ? 'Working…' : `Arm on document ${form.document.target_id}`;
      form.arm.title = `Arms these rules on Console document ${form.document.target_id}${form.document.label ? ` (${form.document.label})` : ''} through the live Console connection, replacing the whole set; a refused set leaves nothing armed. Nothing pauses and no value is read.`;
      form.arm.disabled = form.sending;
      // Clear also forgets the kept scope, even after its document navigated.
      form.clear.disabled = form.sending || !(same || kept);
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
    // Any other choice is the researcher moving on from a pending showObservation.
    if (how !== 'reveal') view.reveal = null;
    // A key that leaves the chosen row active (an arrow past the last row,
    // Home on the first) chooses nothing new and leaves the pane where it is.
    if (how === 'active' && selected?.key === item.key) return;
    if (selected?.key !== item.key) notice = null;
    if (opening && opening.key !== item.key) cancelOpening();
    selected = item;
    // A revealed row keeps its list, which takes focus, in view instead.
    revealKey = how === 'reveal' ? null : item.key;
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
    const origin = debuggerOrigin(view.document, record);
    add('Time', origin === null ? `${debuggerTime(record.monotonic_time_ns)} (monotonic)`
      : `${debuggerRelativeTime(record.monotonic_time_ns, origin)} into session ${record.session_id} · ${debuggerTime(record.monotonic_time_ns)} (monotonic)`);
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
  // How much of the store the rows were read from. Only what the researcher
  // must know is said: that nothing was found where nothing exists, how much
  // was read when that is unknown, and why a read stopped short.
  function coverage(view, count, kind, scope, counted) {
    const observations = view.observations, query = observations.query, loaded = observations.list;
    const end = BigInt(query.store_end);
    const top = loaded ? loaded.top : end;
    const bottom = loaded ? loaded.bottom : query.next_before;
    const whole = bottom === null && !loaded?.pinned && !loaded?.dropped && (loaded ? true : query.scope === 'store');
    const read = top - (bottom === null ? 0n : BigInt(bottom));
    const where = loaded?.dropped ? `the newest records of ${debuggerBytes(end)}`
      : loaded?.pinned ? `${debuggerBytes(read)} of ${debuggerBytes(end)}, below the newest ${debuggerBytes(end - top)}`
        : `the newest ${debuggerBytes(read)} of ${debuggerBytes(end)}`;
    const budget = !whole && (loaded?.query ?? query).budget_exhausted;
    const why = budget ? ', where the read stopped at its 64 MiB budget' : '';
    if (!count) {
      if (whole) {
        return {note: view.kind || scope ? `No ${kind}${scope} in the event store.`
          : `No observation records in the event store.${view.hooks.mode() === 'live' ? ' Arm watch rules to record them.' : ''}`};
      }
      return {note: `No ${kind}${scope} in ${where}${why}. Older ones may exist.`};
    }
    // With the index's counts, the count and Show older records already say
    // that more exist; without them, or when a read ran out of budget, the
    // part read is named.
    if (whole || (counted && !budget)) return {};
    return {flag: debuggerFlag(`Read ${where}`, `${count.toLocaleString('en-US')} ${kind}${scope} from ${where} of the event store${why}. Show older records reads further.`, 'gap')};
  }
  // Records per kind from the event index: every observed frame's, or the
  // selected frame's. Null when the backend gives no counts; `partial` while
  // the index is still catching up with the store.
  function counts(view) {
    const threads = view.document?.threads, observed = threads?.observed ?? [];
    if (!threads || observed.some(frame => !frame.kinds || typeof frame.kinds !== 'object')) return null;
    const thread = view.thread?.kind === 'observed' ? view.thread : null;
    const frames = thread ? observed.filter(frame => frame.session_id === thread.session_id && String(frame.process_id) === String(thread.process_id) && frame.frame_id === thread.frame_id) : observed;
    const totals = {all: 0, partial: threads.coverage ? threads.coverage.scope !== 'store' : false};
    for (const frame of frames) {
      for (const [type, records] of Object.entries(frame.kinds)) {
        if (!Object.hasOwn(DEBUGGER_OBSERVATION_KINDS, type) || !Number.isSafeInteger(records)) continue;
        totals[type] = (totals[type] ?? 0) + records;
        totals.all += records;
      }
    }
    return totals;
  }
  const countText = (totals, kind) => totals ? `${(totals[kind ?? 'all'] ?? 0).toLocaleString('en-US')}${totals.partial ? '+' : ''}` : null;
  function build(view) {
    // A pane drawn again (reopened or expanded) starts at its top with no
    // selection, so it holds no place: no rows are kept from before.
    if (!selected) view.followNewest(true);
    const root = debuggerNode('div', 'debugger-observations');
    // One line of controls: the kind, the frame scope, and the read state.
    const bar = debuggerNode('div', 'debugger-observation-bar');
    const kinds = debuggerNode('select', 'debugger-select debugger-kind-select');
    kinds.setAttribute('aria-label', 'Observation kind');
    for (const [kind, text] of [[null, 'All kinds'], ...Object.entries(DEBUGGER_OBSERVATION_KINDS).map(([kind, value]) => [kind, value.filter])]) {
      const option = debuggerNode('option', '', text);
      option.value = kind ?? 'all';
      option.dataset.label = text;
      kinds.append(option);
    }
    kinds.addEventListener('change', () => { selected = null; cancelOpening(); view.setKind(kinds.value === 'all' ? null : kinds.value); });
    const scope = debuggerButton('', 'debugger-scope-chip', () => { if (view.thread?.kind === 'observed') view.selectThread(view.thread); });
    scope.hidden = true;
    const reading = debuggerNode('span', 'debugger-observation-state');
    bar.append(kinds, scope, reading);
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
        const enter = debuggerNode('kbd', 'debugger-row-enter', '↵ Open');
        enter.setAttribute('aria-hidden', 'true');
        head.append(debuggerNode('span', 'debugger-chip', DEBUGGER_OBSERVATION_KINDS[record.type].label), debuggerNode('span', 'debugger-row-main', debuggerObservationText(record)), enter);
        // Time and category, then the correlation identifiers, quieter and apart.
        const meta = debuggerNode('div', 'debugger-row-meta');
        const ids = `P${record.process_id} F${record.frame_id} #${record.sequence_number}${record.request_id !== '0' ? ` R${record.request_id}` : ''}`;
        meta.append(debuggerNode('span', 'debugger-row-time', debuggerRelativeTime(record.monotonic_time_ns, debuggerOrigin(view.document, record))),
          debuggerNode('span', 'debugger-row-category', debuggerCategory(record.type)), debuggerNode('span', 'debugger-row-ids', ` ${ids} `));
        row.title = `${debuggerObservationText(record)}\n${record.type} · ${debuggerCategory(record.type)}\nsession ${record.session_id} · process ${record.process_id} · frame ${record.frame_id} · sequence ${record.sequence_number}` +
          `${record.request_id !== '0' ? ` · request ${record.request_id}` : ''}\n${debuggerTime(record.monotonic_time_ns)} monotonic\nEnter opens its position in Sources${record.type === 'request_watch_match' ? ', or its request in Traffic' : ''}.`;
        row.append(head, meta);
      }});
    list.element.addEventListener('scroll', () => holdPlace(view), {passive: true});
    const more = debuggerButton('Show older records', 'debugger-link debugger-older', () => view.older());
    detail = debuggerNode('div', 'debugger-detail');
    detail.hidden = true;
    root.append(bar, notes, pinned, list.box, more, detail);
    controls = {root, kinds, scope, reading, notes, pinned, pinnedText, more};
  }
  return {
    id: 'observations', title: 'Observations', order: 30,
    summary: view => view.document ? countText(counts(view), view.kind) ?? rows(view).length.toLocaleString('en-US') : '',
    render(body, view) {
      const unread = debuggerUnread(view);
      if (unread) { list?.release(); list = null; controls = null; detail = null; body.replaceChildren(unread); return; }
      if (!controls || !body.contains(controls.root)) { build(view); body.replaceChildren(controls.root); }
      const answer = view.document, observations = view.observations, loaded = observations.list;
      const totals = counts(view);
      // The kind menu names each kind's records in scope; a poll changes only what changed.
      const wantedKind = view.kind ?? 'all';
      for (const option of controls.kinds.options) {
        const count = countText(totals, option.value === 'all' ? null : option.value);
        const text = count === null ? option.dataset.label : `${option.dataset.label} · ${count}`;
        if (option.textContent !== text) option.textContent = text;
        if (option.selected !== (option.value === wantedKind)) option.selected = option.value === wantedKind;
      }
      const frame = view.thread?.kind === 'observed' ? view.thread : null;
      controls.scope.hidden = !frame;
      if (frame) {
        const text = `Frame ${frame.frame_id} ×`;
        if (controls.scope.textContent !== text) controls.scope.textContent = text;
        controls.scope.setAttribute('aria-label', `Scoped to frame ${frame.frame_id} of session ${frame.session_id}. Show every frame`);
        controls.scope.title = `Only frame ${frame.frame_id}'s records are listed. Click to list every frame.`;
      }
      const current = Boolean(observations.query) && observations.key === `${view.kind ?? 'all'}|${view.thread?.kind === 'observed' ? view.thread.key : 'all'}`;
      // Until the new filter is read, the rows read before stay, named as what they are.
      const items = observations.query ? rows(view) : [];
      const readingText = !current && (!observations.query || view.status === 'ready' || view.status === 'loading') ? 'Reading…' : '';
      if (controls.reading.textContent !== readingText) controls.reading.textContent = readingText;
      // A record asked for by showObservation is chosen once a read made after
      // the ask holds it, older pages included; until then the list says so.
      const wanted = view.reveal;
      const asked = Boolean(wanted) && current && view.status === 'ready' && view.readSerial > wanted.after;
      const revealing = asked ? items.find(item => item.key === wanted.key) ?? null : null;
      if (revealing) view.reveal = null;
      const notes = [], flags = [];
      const scope = frame ? ` in frame ${frame.frame_id}` : '';
      const kind = view.kind ? DEBUGGER_OBSERVATION_KINDS[view.kind].filter.toLowerCase() : 'records';
      if (current) {
        const said = coverage(view, items.length, kind, scope, totals !== null);
        if (said.note) notes.push(debuggerNote(said.note, said.note.endsWith('may exist.') ? 'gap' : ''));
        if (said.flag) flags.push(said.flag);
      } else if (observations.query && view.status !== 'ready' && view.status !== 'loading') {
        const before = observations.query.type ? DEBUGGER_OBSERVATION_KINDS[observations.query.type].filter.toLowerCase() : 'records';
        const where = observations.query.thread ? ` in frame ${observations.query.thread.frame_id}` : '';
        notes.push(debuggerNote(`The ${kind}${scope} were not read. The rows below are the ${before}${where} read before.`, 'warning'));
      }
      if (asked && !revealing) {
        notes.push(debuggerNote(`Observation #${wanted.record.sequence_number} of renderer ${wanted.record.process_id} is not among these ${kind}. Show older records reads older ones, and it is chosen once read.`, 'warning'));
      }
      // Never hidden silently: each of these is a flag above the list.
      const malformed = answer.observations_malformed + observations.refused + (loaded?.refused ?? 0);
      if (malformed > 0) {
        flags.push(debuggerFlag(`${debuggerCount(malformed)} malformed, not shown`,
          `${debuggerCount(malformed)} ${malformed === 1 ? 'record' : 'records'} in these reads ${malformed === 1 ? 'was' : 'were'} malformed and ${malformed === 1 ? 'is' : 'are'} not shown.`));
      }
      for (const gap of answer.observation_budget_gaps.slice(0, 2)) {
        flags.push(debuggerFlag(`Renderer ${gap.process_id} capped (older build)`,
          `Renderer ${gap.process_id}, from an earlier build, reached its ${debuggerCount(1024)} observation records in frame ${gap.frame_id} (gap #${gap.sequence_number}); its later records were refused until the next capture.`, 'gap'));
      }
      if (answer.observation_budget_gaps.length > 2) {
        flags.push(debuggerFlag(`${debuggerCount(answer.observation_budget_gaps.length - 2)} more capped`, `Further renderers from earlier builds that reached their ${debuggerCount(1024)} observation records.`, 'gap'));
      }
      const gap = debuggerGapFlag(view);
      if (gap) flags.push(gap);
      if (observations.olderError) flags.push(debuggerFlag(`Older records not read: ${observations.olderError}`));
      if (current && loaded?.dropped) {
        flags.push(debuggerFlag(`${debuggerCount(loaded.dropped)} older ${loaded.dropped === 1 ? 'row' : 'rows'} dropped`,
          `The list keeps at most ${debuggerCount(DEBUGGER_SIDEBAR.rows)} records, so ${debuggerCount(loaded.dropped)} older ${loaded.dropped === 1 ? 'row was' : 'rows were'} dropped as newer ones arrived; get_events pages them.`));
      }
      if (flags.length) {
        const row = debuggerNode('div', 'debugger-flags');
        row.append(...flags);
        notes.unshift(row);
      }
      debuggerReplace(controls.notes, notes);
      controls.notes.hidden = !notes.length;
      const pin = current ? loaded?.pinned : null;
      controls.pinned.hidden = !pin;
      if (pin) {
        const text = `${debuggerBytes(pin.to - pin.from)} of newer records are not in this list.`;
        if (controls.pinnedText.textContent !== text) controls.pinnedText.textContent = text;
        controls.pinnedText.title = `Kept where you were: the ${debuggerBytes(pin.to - pin.from)} written since (bytes ${pin.from} to ${pin.to}) are more than ${DEBUGGER_SIDEBAR.bridge} reads.`;
      }
      list.box.hidden = !items.length;
      shown = items;
      list.set(items, {selectedKey: selected?.key ?? null});
      if (revealing) {
        // The chosen row in its list, then the list, which takes focus, at the
        // top of the pane; its details follow below it. Once they render, the
        // row itself is brought whole into view where the pane is short.
        list.scrollTo(revealing.key);
        choose(view, revealing, 'reveal');
        if (typeof list.element.scrollIntoView === 'function') list.element.scrollIntoView({block: 'start'});
        const row = list.row(revealing.key);
        if (row && typeof row.scrollIntoView === 'function') row.scrollIntoView({block: 'nearest'});
        // A control the researcher picked meanwhile (a file, Find, the Watch
        // form) keeps focus; the record is still chosen and in view.
        const active = document.activeElement;
        if (!active || active === document.body || active === wanted.focus) list.focus();
      }
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
        ? others.length ? `A Brave build serves the pausing debugger; its controls are in ${where}.`
          : 'A Brave build serves the pausing debugger, but this sidebar has no controls for it yet.'
        : `No Brave build serves the pausing debugger, so nothing is attached or paused.${others.length ? ` The controls in ${where} stay disabled.` : ''}`);
      const fields = debuggerNode('dl', 'debugger-fields');
      for (const [label, value] of [
        ...(available ? [] : [['Reason', answer.reason]]),
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
          if (!response.ok || page?.format !== 'reb-request-index-v2' || !Array.isArray(page.requests)) throw new Error(`the request index answered HTTP ${response.status}`);
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
    // Watch rules arm only through the Console's connection; this opens it there.
    canOpenConsole: () => typeof globalThis.RebNativeConsole?.open === 'function',
    openConsole() {
      if (hooks.overlays()) debuggerSidebarController?.setOpen(false);
      globalThis.RebNativeConsole?.open?.();
    },
    watch: (rules, keep) => globalThis.RebNativeConsole?.watch?.(rules, keep) ?? Promise.resolve(null),
    sequenceGaps: () => typeof shownSequenceGaps === 'function' ? shownSequenceGaps() : null
  };
  debuggerSidebarController = createDebuggerSidebar({root, toggle, screen, hooks});
})();
