/* Paused-state sections of the Sources debugger sidebar
 * (protocol/native-debugger-pause-v1.md). They register themselves with
 * RebDebuggerSidebar.addSection, so this file adds Breakpoints, Call stack,
 * Scope, Watch, the step controls and the lease without touching the phase 1
 * sections. Every value the page can see reaches the DOM as text, is bounded
 * by the backend, and is dropped when the pause ends: nothing here is stored,
 * exported or added to evidence. */
const DEBUGGER_PAUSE = Object.freeze({
  order: 50, watchLimit: 16, expressionBytes: 8192, propertyPage: 64, deadline: 10000, frameRows: 64
});

const DEBUGGER_PAUSE_REASONS = Object.freeze({
  breakpoint: 'breakpoint', exception: 'exception', step: 'step', pause: 'pause',
  debugger_statement: 'the page’s own debugger statement'
});
// The kinds an inspector session can serve. XHR, event listener, DOM and CSP
// breakpoints are Blink's DOMDebugger domain, which it does not dispatch;
// native debugger observation v1 records all four without pausing.
const DEBUGGER_PAUSE_KINDS = Object.freeze({
  line: 'Line', conditional: 'Conditional', logpoint: 'Logpoint'
});
const DEBUGGER_PAUSE_UNSUPPORTED = Object.freeze({
  browser_debugger_unsupported: 'No browser serves the pausing debugger. Nothing is attached and no page is paused.',
  peer_unavailable: 'The debugger peer did not answer. Nothing is attached and no page is paused.'
});

function pauseNode(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  // Always text: a value read from a page is never markup here.
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function pauseButton(text, className, onClick, disabled = false) {
  const button = pauseNode('button', className, text);
  button.type = 'button';
  button.disabled = disabled;
  button.addEventListener('click', onClick);
  return button;
}

function pauseRow(label, value) {
  const row = pauseNode('div', 'debugger-pause-row');
  row.append(pauseNode('span', 'debugger-pause-label', label),
    pauseNode('span', 'debugger-pause-value', value));
  return row;
}

function pauseDocument(answer) {
  return answer && typeof answer === 'object' ? answer : null;
}

/* Nothing in these sections may be operated unless the last read is good and
 * a browser serves the debugger. The sidebar's contract is stricter than
 * "looks inert": every control is a form control with `disabled` set, so one
 * gate decides it for all of them. */
function pauseLive(view) {
  return view?.status === 'ready' && pauseDocument(view?.document)?.availability === 'available';
}

// Before the first read, or in a window with no backend, every section says
// why it has nothing rather than looking like an empty debugger.
const DEBUGGER_PAUSE_UNREAD = Object.freeze({
  loading: 'Reading the debugger state.',
  disconnected: 'The backend is not answering, so the pausing debugger cannot be read.',
  malformed: 'The last answer could not be read, so nothing here is shown.',
  unavailable: 'This window has no backend, so the pausing debugger cannot be read.'
});

function pauseUnsupported(view) {
  const answer = pauseDocument(view?.document);
  if (!answer || answer.availability === 'available') return null;
  return pauseNode('p', 'debugger-pause-unsupported',
    DEBUGGER_PAUSE_UNSUPPORTED[answer.reason] ?? 'The pausing debugger is unsupported.');
}

function pauseUnread(view) {
  const answer = pauseDocument(view?.document);
  if (answer) return null;
  return pauseNode('p', 'debugger-pause-unread',
    DEBUGGER_PAUSE_UNREAD[view?.status] ?? 'The debugger state has not been read yet.');
}

/* The one place that decides whether an action can be sent. Without an
 * authorized document, or without the pause and lease the action needs,
 * nothing is sent and the control is disabled instead. */
function pauseCommand(answer, action, extra = {}) {
  const selected = answer?.document;
  if (!selected) return null;
  const body = {action, target_id: selected.target_id, ...extra};
  if (['resume', 'step_over', 'step_into', 'step_out', 'release_lease', 'evaluate_on_frame', 'get_properties'].includes(action)) {
    const lease = answer?.lease;
    if (!lease || lease.state !== 'active') return null;
    body.lease_id = lease.lease_id;
  }
  return body;
}

function pauseLeaseText(lease) {
  if (!lease) return 'no lease';
  if (lease.state === 'expired') return 'expired; the browser resumed the page';
  if (lease.state === 'released') return 'released; the page is running';
  const seconds = Math.max(0, Math.round(Number(lease.expires_in_ms ?? 0) / 1000));
  return `active, ${seconds} s left before the browser resumes the page`;
}

function pauseBreakpointText(breakpoint) {
  const kind = DEBUGGER_PAUSE_KINDS[breakpoint.kind] ?? breakpoint.kind;
  return `${kind} · script ${breakpoint.script_id} line ${breakpoint.line}:${breakpoint.column}`;
}

function pauseFrameText(frame) {
  const name = String(frame.function_name ?? '').trim();
  return `${name || '(anonymous)'} · script ${frame.script_id} line ${frame.line}:${frame.column}`;
}

/* Local, ephemeral state: watch expressions the researcher typed and the
 * property pages read while this pause lasts. A new lease clears both, so a
 * value from one pause can never be shown as if it belonged to the next. */
function createPauseState() {
  return {lease: null, watches: [], watchResults: new Map(), expanded: new Map(), notice: '', busy: false,
    allFrames: false};
}

function pauseSync(state, answer) {
  const lease = answer?.lease?.state === 'active' ? answer.lease.lease_id : null;
  if (state.lease !== lease) {
    state.lease = lease;
    state.watchResults = new Map();
    state.expanded = new Map();
    state.allFrames = false;
  }
}

function createDebuggerPause(hooks = {}) {
  const fetcher = hooks.fetch ?? ((...args) => globalThis.fetch(...args));
  const state = createPauseState();
  let repaint = () => {};

  async function send(body) {
    if (!body) return null;
    state.busy = true;
    state.notice = '';
    try {
      const response = await fetcher('/api/native-debugger/actions', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
        signal: typeof AbortSignal?.timeout === 'function' ? AbortSignal.timeout(DEBUGGER_PAUSE.deadline) : undefined
      });
      const value = await response.json().catch(() => null);
      if (!response.ok) {
        state.notice = typeof value?.error === 'string' ? value.error : `the backend returned HTTP ${response.status}`;
        return null;
      }
      if (value?.status && value.status !== 'ok' && value.status !== 'evaluation_error') {
        state.notice = `${body.action}: ${String(value.status).replace(/_/g, ' ')}; nothing else changed`;
      }
      return value;
    } catch (error) {
      state.notice = `${body.action}: ${String(error?.message ?? error)}; whether it ran is unknown and it is not retried`;
      return null;
    } finally {
      state.busy = false;
      repaint();
    }
  }

  async function runWatch(answer, index) {
    const expression = state.watches[index];
    const command = pauseCommand(answer, 'evaluate_on_frame', {call_frame_index: 0, expression});
    if (!command) return;
    const value = await send(command);
    if (!value?.value) return;
    state.watchResults.set(expression, value.value);
    // send repainted before this result was stored, so paint it again.
    repaint();
  }

  async function expand(answer, objectId, offset) {
    const command = pauseCommand(answer, 'get_properties', {object_id: objectId, offset});
    if (!command) return;
    const value = await send(command);
    if (!value?.properties) return;
    const previous = offset === 0 ? [] : (state.expanded.get(objectId)?.items ?? []);
    state.expanded.set(objectId, {
      items: [...previous, ...value.properties.items],
      next: value.properties.next_offset ?? null,
      total: value.properties.total
    });
    repaint();
  }

  function notice(body) {
    if (state.notice) body.append(pauseNode('p', 'debugger-pause-notice', state.notice));
  }

  // Availability, the detectable label, the document, quiet mode, the lease
  // and the step controls.
  function renderPause(body, view) {
    const answer = pauseDocument(view?.document);
    pauseSync(state, answer);
    body.replaceChildren();
    const unread = pauseUnread(view);
    if (unread) { body.append(unread); return; }
    if (answer.availability !== 'available') {
      body.append(pauseNode('p', 'debugger-pause-unsupported',
        DEBUGGER_PAUSE_UNSUPPORTED[answer.reason] ?? 'The pausing debugger is unsupported.'));
      return;
    }
    // The words the state itself carries, so the interface and an HTTP or
    // MCP client say the same thing about a page that can tell either way.
    const label = pauseNode('p', 'debugger-pause-active',
      answer.active_indication ?? 'Debugger attached to no document');
    label.dataset.active = answer.document ? 'yes' : 'no';
    body.append(label);
    if (answer.document) {
      body.append(pauseRow('Document',
        `target ${answer.document.target_id}, ${answer.document.frame === 'child' ? 'a same-process iframe' : 'the top frame'}`));
    } else if (answer.last_clear) {
      body.append(pauseRow('Last authorization', `cleared: ${answer.last_clear}`));
    }
    body.append(pauseRow('Page debugger statements',
      answer.quiet_mode === true ? 'ignored (quiet mode); only breakpoints you set pause'
        : answer.quiet_mode === false ? 'pause the page' : 'not reported'));
    body.append(pauseRow('Pause on exceptions', String(answer.exceptions ?? 'none')));
    body.append(pauseRow('Lease', pauseLeaseText(answer.lease)));
    body.append(pauseRow('State', answer.paused
      ? `paused at a ${DEBUGGER_PAUSE_REASONS[answer.pause?.reason] ?? 'pause'}`
      : 'running'));

    const controls = pauseNode('div', 'debugger-pause-controls');
    const frozen = !pauseLive(view) || state.busy;
    const paused = Boolean(answer.paused);
    for (const [text, action] of [['Resume', 'resume'], ['Step over', 'step_over'], ['Step into', 'step_into'],
      ['Step out', 'step_out'], ['Release lease', 'release_lease']]) {
      const command = pauseCommand(answer, action);
      controls.append(pauseButton(text, 'debugger-pause-control',
        () => { void send(command); }, frozen || !paused || !command));
    }
    const pauseNow = pauseCommand(answer, 'pause', {confirm_pause: true});
    controls.append(pauseButton('Pause', 'debugger-pause-control',
      () => { void send(pauseNow); }, frozen || paused || !pauseNow));
    body.append(controls);
    notice(body);
  }

  function renderBreakpoints(body, view) {
    const answer = pauseDocument(view?.document);
    pauseSync(state, answer);
    body.replaceChildren();
    const unread = pauseUnread(view) ?? pauseUnsupported(view);
    if (unread) { body.append(unread); return; }
    const frozen = !pauseLive(view) || state.busy;
    const breakpoints = Array.isArray(answer?.breakpoints) ? answer.breakpoints : [];
    if (!breakpoints.length) {
      body.append(pauseNode('p', 'debugger-pause-empty', 'No breakpoint is set on this document.'));
      return;
    }
    const list = pauseNode('ul', 'debugger-pause-list');
    for (const breakpoint of breakpoints) {
      const row = pauseNode('li', 'debugger-pause-breakpoint');
      row.append(pauseNode('span', 'debugger-pause-value', pauseBreakpointText(breakpoint)));
      const state_text = [breakpoint.resolved ? 'bound' : 'not bound yet',
        `${breakpoint.hits} ${Number(breakpoint.hits) === 1 ? 'hit' : 'hits'}`];
      if (breakpoint.logpoint) state_text.push('never pauses');
      row.append(pauseNode('span', 'debugger-pause-state', state_text.join(' · ')));
      const command = pauseCommand(answer, 'remove_breakpoint', {breakpoint_id: breakpoint.breakpoint_id});
      row.append(pauseButton('Remove', 'debugger-pause-remove',
        () => { void send(command); }, frozen || !command));
      list.append(row);
    }
    body.append(list);
    notice(body);
  }

  function renderCallStack(body, view) {
    const answer = pauseDocument(view?.document);
    pauseSync(state, answer);
    body.replaceChildren();
    const unread = pauseUnread(view) ?? pauseUnsupported(view);
    if (unread) { body.append(unread); return; }
    const frozen = !pauseLive(view) || state.busy;
    const pause = answer?.paused ? answer.pause : null;
    if (!pause) {
      body.append(pauseNode('p', 'debugger-pause-empty', 'The page is not paused, so there is no call stack.'));
      return;
    }
    // A 1,024 frame stack is in the contract, so only the rows a reader can
    // use are mounted until they ask for the rest.
    const frames = pause.frames ?? [];
    const shown = state.allFrames ? frames : frames.slice(0, DEBUGGER_PAUSE.frameRows);
    const list = pauseNode('ol', 'debugger-pause-list');
    for (const frame of shown) {
      const row = pauseNode('li', 'debugger-pause-frame', pauseFrameText(frame));
      row.dataset.index = String(frame.index);
      list.append(row);
    }
    body.append(list);
    if (shown.length < frames.length) {
      body.append(pauseButton(`Show all ${frames.length} frames`, 'debugger-pause-more',
        () => { state.allFrames = true; repaint(); }, frozen));
    }
    const counts = [`${pause.frames_recorded} recorded`];
    if (pause.async_frames) counts.push(`${pause.async_frames} async`);
    if (pause.frames_truncated) counts.push('deeper than the 1,024 frame bound');
    body.append(pauseNode('p', 'debugger-pause-state', counts.join(' · ')));
    notice(body);
  }

  function renderScope(body, view) {
    const answer = pauseDocument(view?.document);
    pauseSync(state, answer);
    body.replaceChildren();
    const unread = pauseUnread(view) ?? pauseUnsupported(view);
    if (unread) { body.append(unread); return; }
    const frozen = !pauseLive(view) || state.busy;
    const frame = answer?.paused ? answer.pause?.frames?.[0] : null;
    if (!frame) {
      body.append(pauseNode('p', 'debugger-pause-empty', 'The page is not paused, so there are no scopes.'));
      return;
    }
    for (const scope of frame.scopes ?? []) {
      const block = pauseNode('div', 'debugger-pause-scope');
      const title = [scope.type, scope.name].filter(Boolean).join(' · ');
      const page = state.expanded.get(scope.object_id);
      block.append(pauseButton(`${page ? '▼' : '▶'} ${title}`, 'debugger-pause-scope-title',
        () => {
          if (page) state.expanded.delete(scope.object_id);
          else void expand(answer, scope.object_id, 0);
          repaint();
        }, frozen));
      if (page) {
        const list = pauseNode('ul', 'debugger-pause-list');
        for (const item of page.items) {
          const row = pauseNode('li', 'debugger-pause-property');
          row.append(pauseNode('span', 'debugger-pause-name', item.name),
            pauseNode('span', 'debugger-pause-value',
              item.truncated ? `${item.text} (cut)` : item.text));
          list.append(row);
        }
        block.append(list);
        if (page.next !== null) {
          block.append(pauseButton(`Show more of ${page.total}`, 'debugger-pause-more',
            () => { void expand(answer, scope.object_id, Number(page.next)); }, frozen));
        }
      }
      body.append(block);
    }
    notice(body);
  }

  function renderWatch(body, view) {
    const answer = pauseDocument(view?.document);
    pauseSync(state, answer);
    body.replaceChildren();
    const unread = pauseUnread(view) ?? pauseUnsupported(view);
    if (unread) { body.append(unread); return; }
    const frozen = !pauseLive(view) || state.busy;
    const field = pauseNode('input', 'debugger-pause-watch-input');
    field.type = 'text';
    field.placeholder = 'Expression on the innermost paused frame';
    field.maxLength = DEBUGGER_PAUSE.expressionBytes;
    field.disabled = frozen;
    const add = pauseButton('Watch', 'debugger-pause-watch-add', () => {
      const expression = String(field.value ?? '').trim();
      if (!expression || state.watches.length >= DEBUGGER_PAUSE.watchLimit ||
        state.watches.includes(expression)) return;
      state.watches.push(expression);
      field.value = '';
      void runWatch(answer, state.watches.length - 1);
      repaint();
    }, frozen);
    const form = pauseNode('div', 'debugger-pause-watch-form');
    form.append(field, add);
    body.append(form);
    if (!state.watches.length) {
      body.append(pauseNode('p', 'debugger-pause-empty', 'No watch expression. A result is read while the page is paused and kept only until it resumes.'));
      notice(body);
      return;
    }
    const list = pauseNode('ul', 'debugger-pause-list');
    state.watches.forEach((expression, index) => {
      const row = pauseNode('li', 'debugger-pause-watch');
      row.append(pauseNode('span', 'debugger-pause-name', expression));
      const result = state.watchResults.get(expression);
      row.append(pauseNode('span', result?.threw ? 'debugger-pause-threw' : 'debugger-pause-value',
        result ? (result.truncated ? `${result.text} (cut)` : result.text)
          : answer?.paused ? 'not read yet' : 'the page is running'));
      row.append(pauseButton('Read', 'debugger-pause-read',
        () => { void runWatch(answer, index); },
        frozen || !answer?.paused ||
        !pauseCommand(answer, 'evaluate_on_frame', {call_frame_index: 0, expression})));
      row.append(pauseButton('Remove', 'debugger-pause-remove', () => {
        state.watches.splice(index, 1);
        state.watchResults.delete(expression);
        repaint();
      }, frozen));
      list.append(row);
    });
    body.append(list);
    notice(body);
  }

  /* The sidebar repaints on its own poll. An action a researcher just took
   * has to show at once, so each section remembers the body and view it was
   * last given and paints that again, in place. Nothing re-enters the
   * registry: replacing a section there would unmount it and lose the scope
   * the researcher had just opened. */
  const painted = new Map();
  function section(id, title, order, render, extra = {}) {
    const paint = (body, view) => {
      painted.set(id, {body, view});
      render(body, view);
    };
    // `native: 'pausing'` is what lets these sections use the paused-state
    // words at all, and what the sidebar's own Pausing statement names.
    return {id, title, order, native: 'pausing', render: paint,
      release: () => { painted.delete(id); }, ...extra};
  }

  const sections = [
    section('pause', 'Pause', DEBUGGER_PAUSE.order, renderPause,
      {summary: view => pauseDocument(view?.document)?.paused ? 'paused' : ''}),
    section('breakpoints', 'Breakpoints', DEBUGGER_PAUSE.order + 1, renderBreakpoints,
      {summary: view => String(pauseDocument(view?.document)?.breakpoints?.length ?? 0)}),
    section('call-stack', 'Call stack', DEBUGGER_PAUSE.order + 2, renderCallStack,
      {summary: view => String(pauseDocument(view?.document)?.pause?.frames_recorded ?? 0)}),
    section('scope', 'Scope', DEBUGGER_PAUSE.order + 3, renderScope),
    section('watch', 'Watch', DEBUGGER_PAUSE.order + 4, renderWatch,
      {summary: () => String(state.watches.length)})
  ];
  const byId = new Map(sections.map(entry => [entry.id, entry]));
  repaint = () => {
    for (const [id, {body, view}] of [...painted]) byId.get(id)?.render(body, view);
  };

  return {
    sections,
    state,
    setRepaint(fn) { repaint = typeof fn === 'function' ? fn : () => {}; }
  };
}

// The sidebar owns the registry; without it these sections simply do not
// exist, and nothing here polls, fetches or holds a timer on its own.
function registerDebuggerPause(registry = globalThis.RebDebuggerSidebar) {
  if (!registry?.addSection) return null;
  const panel = createDebuggerPause();
  const removals = panel.sections.map(section => registry.addSection(section));
  return {panel, remove: () => { for (const remove of removals) remove(); }};
}

globalThis.RebDebuggerPause = Object.freeze({create: createDebuggerPause, register: registerDebuggerPause});
registerDebuggerPause();
