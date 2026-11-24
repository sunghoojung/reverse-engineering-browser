// Live session panel: the start choices, the startup wait and a failed or
// ended session, drawn inside the workspace instead of a modal alert. Native
// owns the decision (macos/SessionPanel.swift): it says what to show, accepts
// a choice only while that decision is open, validates it and then starts,
// retries or stays offline. This page only draws the state and asks. Every
// value from native, saved site labels and URLs included, is inserted as text.
(() => {
  'use strict';
  const root = document.getElementById('session-panel');
  if (!root) return;
  const bridge = () => globalThis.webkit?.messageHandlers?.rebSession ?? null;

  const MODE_TEXT = {
    content: 'Retains request paths, queries and bodies, every response body whole with media and fonts, request and response headers, cookies, and Canvas images.',
    metadata: 'Keeps request hosts and each request body’s length, type and SHA-256, without headers, cookies or Canvas images.',
  };
  const ARTIFACT_NOTE = 'Artifacts keep raw source URLs locally; only an explicitly exported redacted copy is altered.';
  // A Content session keeps every body whole, so the only bound on what it
  // stores is the receiver's free-disk reserve
  // (services/artifact-receiver/README.md#disk-reserve). The panel names no
  // environment variable; the README names the one that sets another reserve.
  const DISK_NOTE = 'Content stays on this Mac with the session and has no size limit. Capture keeps 4 GiB of disk free by default and names each body it could not store.';

  // The page's own selection while the decision is open: the capture mode.
  // It starts from what native offers and is sent with Start; native
  // validates it again. Sessions started here always use the isolated profile.
  const view = {state: null, mode: 'content', busy: false, confirmClear: false, notice: null};

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function button(className, text, onClick, focusKey) {
    const node = element('button', className, text);
    node.type = 'button';
    if (focusKey) node.dataset.focusKey = focusKey;
    node.addEventListener('click', () => { if (!node.disabled && !view.busy) onClick(); });
    return node;
  }

  const ICONS = {
    start: 'M4 4h12v12H4zM8 8l5 2-5 2z',
    error: 'M10 3 2.5 16h15zM10 8v4M10 14v.5',
    ended: 'M4 4h12v12H4zM8 8h4v4H8z',
  };
  function icon(name, className) {
    const holder = element('span', className);
    holder.setAttribute('aria-hidden', 'true');
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 20 20');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', ICONS[name]);
    svg.append(path);
    holder.append(svg);
    return holder;
  }

  function modeTitle(id) {
    return view.state?.modes?.find(mode => mode.id === id)?.title ?? (id === 'metadata' ? 'Metadata only' : 'Content (default)');
  }

  function plural(count, word) { return `${count} ${word}${count === 1 ? '' : 's'}`; }

  async function ask(op, body = {}) {
    const handler = bridge();
    if (!handler) throw new Error('The native app is not connected.');
    if (!listening) listen();
    return handler.postMessage({op, ...body});
  }

  // A choice the native side refused, or a bridge that stopped answering,
  // stays on screen with the decision; native republishes what is current.
  async function choose(op, body = {}) {
    if (view.busy) return;
    // Every start names all session options, as native requires.
    if (op === 'start') body = {...body, options: {...session.options}};
    view.busy = true;
    view.notice = null;
    render();
    try {
      const reply = await ask(op, body);
      if (reply && reply.panel) receive(reply, {keepNotice: true});
    } catch (error) {
      // Native refusals are whole sentences; a lost bridge says it did not answer.
      const reason = String(error?.message || error || '').trim() || 'Origin Trace did not answer.';
      view.notice = {kind: 'error', text: `${/[.!?]$/.test(reason) ? reason : `${reason}.`} New Live Session… in the Origin Trace menu offers the choices again.`};
    } finally {
      view.busy = false;
      render();
    }
  }

  function header(name, title, tone) {
    const node = element('header', 'session-panel-head');
    if (tone) node.dataset.tone = tone;
    node.append(name === 'busy' ? element('span', 'session-panel-spinner') : icon(name, 'session-panel-icon'));
    const heading = element('h2', 'session-panel-title', title);
    heading.id = 'session-panel-title';
    node.append(heading);
    return node;
  }

  function noticeNode() {
    if (!view.notice) return null;
    const note = element('p', `session-panel-notice${view.notice.kind === 'error' ? ' session-panel-notice-error' : ''}`, view.notice.text);
    note.setAttribute('role', view.notice.kind === 'error' ? 'alert' : 'status');
    return note;
  }

  // The session options beyond mode and limits (LiveSessionOptions in
  // macos/LiveSessionOptions.swift): the browser profile and the native
  // switches that were otherwise only environment variables. Native sends
  // each value with its default; the page sends every one back with Start.
  const FRESH_PROFILE = {key: 'fresh_profile', name: 'Fresh profile',
    detail: 'Start signed out, with a new, empty profile that only this session uses. It stays in the session folder.'};
  const DIGESTS = {key: 'invocation_digests', name: 'Record settled-value digests',
    detail: 'SHA-256 digests of the string and byte results of tracked calls. They can confirm a known value, so they are sensitive capture.'};
  // `needs` names an option this one depends on; `content` marks one only a
  // Content session uses.
  const ADVANCED = [
    {key: 'request_stacks', name: 'Request stacks', detail: 'Record the JavaScript stack that started each request.'},
    {key: 'promise_stacks', name: 'Promise stacks', needs: 'request_stacks',
      detail: 'Also record where each promise a request awaited was created. Slower; turns on request stacks.'},
    {key: 'wasm_dispatch', name: 'Wasm dispatch sampling',
      detail: 'Sample br_table and call_indirect targets. Wasm then compiles with Liftoff only, so Wasm-heavy pages run slower.'},
    {key: 'wasm_every_record', name: 'Every Wasm record', needs: 'wasm_dispatch',
      detail: 'Keep every br_table, call_indirect and execution record instead of up to 1024 a second. A hot loop can write millions; turns on Wasm dispatch sampling.'},
    {key: 'ignore_debugger_statements', name: 'Ignore debugger statements',
      detail: 'Pages cannot pause the browser with a debugger statement.'},
    {key: 'document_start', name: 'Allow document-start Console scripts',
      detail: 'A live Console may arm a script that runs before page scripts, after you confirm it there.'},
    {key: 'canvas_images', name: 'Canvas images', content: true,
      detail: 'Keep the pixels a page reads back from a canvas.'},
    {key: 'browser_internal', name: 'Browser-internal traffic',
      detail: 'Record requests of browser pages such as brave://settings and DevTools. Otherwise they are counted, not recorded.'},
    {key: 'extension_traffic', name: 'Extension traffic',
      detail: 'Record requests of extension workers. Otherwise they are counted, not recorded.'},
  ];
  // The page's selection of those options while the start decision is open,
  // and whether Advanced options is expanded.
  const session = {options: null, advanced: false};

  function optionsFrom(options) {
    const keys = [FRESH_PROFILE.key, DIGESTS.key, ...ADVANCED.map(option => option.key)];
    return Object.fromEntries(keys.map(key => [key, (options?.[key]?.value ?? options?.[key]?.default) === true]));
  }

  function optionDefault(key) { return view.state?.options?.[key]?.default === true; }

  function optionCheck(option) {
    const row = element('label', 'session-panel-check');
    const box = element('input');
    box.type = 'checkbox';
    box.id = `session-panel-option-${option.key.replaceAll('_', '-')}`;
    box.dataset.focusKey = `option:${option.key}`;
    box.checked = session.options?.[option.key] === true;
    box.addEventListener('change', () => {
      session.options[option.key] = box.checked;
      // A dependent option turns on what it needs, and loses it with that.
      if (option.needs && box.checked) session.options[option.needs] = true;
      for (const dependent of ADVANCED) {
        if (dependent.needs === option.key && !box.checked) session.options[dependent.key] = false;
      }
      render();
    });
    const text = element('span', 'session-panel-mode-text');
    text.append(element('span', 'session-panel-mode-name', option.name), element('span', 'session-panel-mode-detail', option.detail));
    row.append(box, text);
    return row;
  }

  // Native names the persistent research profile's folder; it is drawn as
  // text.
  function profileGroup(state) {
    const group = element('fieldset', 'session-panel-profile');
    group.append(element('legend', 'session-panel-label', 'Browser profile'), optionCheck(FRESH_PROFILE));
    const folder = typeof state.researchProfile === 'string' && state.researchProfile ? state.researchProfile : null;
    const note = element('p', 'session-panel-text session-panel-note');
    if (session.options?.[FRESH_PROFILE.key]) {
      note.textContent = 'The research profile is left as it is for later sessions.';
    } else {
      note.append('Sessions share the research profile, so sign-ins and site data carry over. Each session’s evidence still stays in its own folder.');
      if (folder) {
        const path = element('span', 'session-panel-path', folder);
        path.title = folder;
        note.append(' ', path);
      }
    }
    group.append(note);
    return group;
  }

  function advancedGroup() {
    const group = element('section', 'session-panel-advanced');
    const shown = ADVANCED.filter(option => !option.content || view.mode === 'content');
    const changed = shown.filter(option => session.options?.[option.key] !== optionDefault(option.key)).length;
    const toggle = button('session-panel-disclosure', '', () => { session.advanced = !session.advanced; render(); }, 'advanced');
    toggle.id = 'session-panel-advanced';
    toggle.setAttribute('aria-expanded', String(session.advanced));
    toggle.setAttribute('aria-controls', 'session-panel-advanced-options');
    toggle.append(element('span', 'session-panel-disclosure-mark'), element('span', 'session-panel-label', 'Advanced options'));
    if (changed) toggle.append(element('span', 'session-panel-disclosure-count', `${changed} changed`));
    group.append(toggle);
    if (session.advanced) {
      const list = element('div', 'session-panel-advanced-options');
      list.id = 'session-panel-advanced-options';
      list.append(...shown.map(optionCheck));
      group.append(list);
    }
    return group;
  }

  function modeGroup() {
    const group = element('fieldset', 'session-panel-modes');
    group.append(element('legend', 'session-panel-label', 'Capture mode'));
    // Native says why the mode is preselected when the environment decided it.
    if (typeof view.state?.modeNote === 'string' && view.state.modeNote) {
      const note = element('p', 'session-panel-text session-panel-mode-note', view.state.modeNote);
      note.id = 'session-panel-mode-note';
      group.setAttribute('aria-describedby', note.id);
      group.append(note);
    }
    for (const id of ['content', 'metadata']) {
      const option = element('label', 'session-panel-mode');
      option.dataset.mode = id;
      const input = element('input');
      input.type = 'radio';
      input.name = 'session-panel-mode';
      input.value = id;
      input.id = `session-panel-mode-${id}`;
      input.dataset.focusKey = `mode:${id}`;
      input.checked = view.mode === id;
      input.addEventListener('change', () => {
        if (!input.checked) return;
        view.mode = id;
        render();
      });
      const text = element('span', 'session-panel-mode-text');
      text.append(element('span', 'session-panel-mode-name', modeTitle(id)), element('span', 'session-panel-mode-detail', MODE_TEXT[id]));
      option.append(input, text);
      if (view.mode === id) option.dataset.selected = 'true';
      group.append(option);
    }
    return group;
  }

  // Start sends the mode, and choose adds the session options; a Content
  // session keeps every body whole, so there is no size to send.
  function start() {
    if (view.busy) return;
    choose('start', {mode: view.mode});
  }

  // The saved invocation sites the capture about to start arms, read by
  // native from the same file Sources writes.
  function sitesSection(sites) {
    const section = element('section', 'session-panel-sites');
    section.setAttribute('aria-labelledby', 'session-panel-sites-title');
    const items = Array.isArray(sites?.items) ? sites.items : [];
    let title, detail;
    if (sites?.state === 'saved' && items.length) {
      title = `Tracking ${plural(items.length, 'function')}`;
      detail = 'This capture arms these functions in pages it loads; a page already open cannot gain tracking. '
        + (view.mode === 'content'
          ? 'Content mode can also record digests of their results, chosen below.'
          : 'Metadata mode records no settled-value digests.')
        + ' A Brave without invocation capture starts without them and says so.';
    } else if (sites?.state === 'unreadable') {
      title = 'Saved functions unreadable';
      detail = 'The saved invocation site file is not a valid site file, so this capture tracks nothing. Clear it to start again.';
    } else {
      title = 'Tracking no functions';
      detail = 'Choose Track calls in Sources during the capture to save a function. The capture tracks its calls from then on in pages that compile it, and so does every later capture.';
    }
    const heading = element('h3', 'session-panel-label', title);
    heading.id = 'session-panel-sites-title';
    section.append(heading, element('p', 'session-panel-text', detail));
    if (sites?.state === 'saved' && items.length && view.mode === 'content') section.append(optionCheck(DIGESTS));
    if (sites?.notice) {
      const note = element('p', 'session-panel-notice session-panel-notice-error', sites.notice);
      note.setAttribute('role', 'alert');
      section.append(note);
    }
    if (items.length) {
      const list = element('ul', 'session-panel-site-list');
      items.forEach((site, index) => {
        const row = element('li', 'session-panel-site');
        const text = element('span', 'session-panel-site-text');
        const name = element('span', 'session-panel-site-name', String(site?.label ?? 'Unlabeled function'));
        name.title = name.textContent;
        // An isolated left-to-right run inside the right-to-left box keeps the
        // URL's own order while the ellipsis replaces its start.
        const url = element('span', 'session-panel-site-url');
        const urlText = element('bdi', '', site?.sourceURL ? String(site.sourceURL) : 'Source URL not recorded');
        urlText.dir = 'ltr';
        url.append(urlText);
        if (site?.sourceURL) url.title = String(site.sourceURL);
        text.append(name, url);
        const remove = button('session-panel-button session-panel-button-small', 'Remove',
          () => choose('removeSite', {index, generation: sites.generation}), `remove:${index}`);
        remove.setAttribute('aria-label', `Remove ${name.textContent}`);
        row.append(text, remove);
        list.append(row);
      });
      section.append(list);
    }
    if (items.length || sites?.state === 'unreadable') {
      const clear = button('session-panel-button session-panel-button-small', view.confirmClear ? 'Confirm Clear All' : 'Clear All', () => {
        if (!view.confirmClear) { view.confirmClear = true; render(); return; }
        view.confirmClear = false;
        choose('clearSites', {generation: sites.generation});
      }, 'clear');
      clear.id = 'session-panel-clear';
      if (view.confirmClear) clear.dataset.tone = 'danger';
      section.append(clear);
    }
    return section;
  }

  function actions(primary, secondary) {
    const footer = element('footer', 'session-panel-actions');
    const notice = noticeNode();
    if (notice) footer.append(notice);
    const row = element('div', 'session-panel-action-row');
    row.append(secondary, primary);
    footer.append(row);
    return footer;
  }

  function chooseContent(state) {
    const body = element('div', 'session-panel-body');
    body.append(element('p', 'session-panel-lede', 'Choose the evidence boundary for this session. You can start another session later from the Origin Trace menu.'),
      modeGroup(), ...(view.mode === 'content' ? [element('p', 'session-panel-text session-panel-note', DISK_NOTE)] : []),
      element('p', 'session-panel-text session-panel-note', ARTIFACT_NOTE), sitesSection(state.sites));
    body.append(profileGroup(state), advancedGroup());
    const offline = button('session-panel-button', 'Continue Offline', () => choose('offline'), 'offline');
    offline.id = 'session-panel-offline';
    const startButton = button('session-panel-button session-panel-button-primary', 'Start Session', start, 'start');
    startButton.id = 'session-panel-start';
    return [header('start', 'Start a live research session'), body, actions(startButton, offline)];
  }

  function startingContent(state) {
    const body = element('div', 'session-panel-body');
    const status = element('p', 'session-panel-text', `Capture mode: ${modeTitle(state.mode)}. Origin Trace opens the live workspace when the broker, receiver and Brave Browser Development are ready, within a minute.`);
    status.setAttribute('role', 'status');
    body.append(status);
    return [header('busy', 'Starting a live session'), body];
  }

  function failedContent(state) {
    const failure = state.failure ?? {};
    const body = element('div', 'session-panel-body');
    const message = element('p', 'session-panel-failure', String(failure.message ?? 'The live session stopped.'));
    message.id = 'session-panel-failure';
    body.append(message);
    body.append(element('p', 'session-panel-text', `Retry starts a new session with the same capture mode: ${modeTitle(state.mode)}.`));
    if (failure.afterStartup) {
      body.append(element('p', 'session-panel-text', 'Continue Offline replaces this ended workspace, which can no longer load or save anything, with the offline workspace. Its evidence stays in its session folder.'));
    }
    const offline = button('session-panel-button', 'Continue Offline', () => choose('offline'), 'offline');
    offline.id = 'session-panel-offline';
    const retry = button('session-panel-button session-panel-button-primary', 'Retry', () => choose('retry'), 'retry');
    retry.id = 'session-panel-retry';
    return [header('error', String(failure.title ?? 'Live session unavailable'), 'error'), body, actions(retry, offline)];
  }

  // A session that ended after it started, with its folder known: open its
  // evidence for review, or start again with the same choices.
  function endedContent(state) {
    const failure = state.failure ?? {};
    const normal = failure.endedNormally === true;
    const body = element('div', 'session-panel-body');
    const message = element('p', 'session-panel-failure', String(failure.message ?? 'The live session ended.'));
    message.id = 'session-panel-failure';
    if (normal) message.dataset.tone = 'ended';
    body.append(message, element('p', 'session-panel-text', 'Review Session opens its evidence in the offline workspace, in place of this ended workspace, which can no longer load or save anything. Start Again starts a new session with the same choices.'));
    const again = button('session-panel-button', 'Start Again', () => choose('retry'), 'retry');
    again.id = 'session-panel-retry';
    const review = button('session-panel-button session-panel-button-primary', 'Review Session', () => choose('review'), 'review');
    review.id = 'session-panel-review';
    return [header(normal ? 'ended' : 'error', String(failure.title ?? 'Live session ended'), normal ? null : 'error'), body, actions(review, again)];
  }

  // A decision arriving takes focus to its default control, as an alert's
  // default button would. A redraw of the same state keeps the control the
  // researcher used; while a request is in flight focus waits on the panel.
  const DEFAULT_FOCUS = {choose: 'start', failed: 'retry'};
  let shown = 'hidden';
  let focusKey = null;

  function render() {
    const state = view.state;
    const panel = state?.panel ?? 'hidden';
    const active = document.activeElement ?? null;
    const inside = Boolean(active) && root.contains(active);
    if (panel === 'hidden') {
      root.hidden = true;
      root.replaceChildren();
      delete root.dataset.state;
      shown = panel;
      focusKey = null;
      // Focus returns to the workspace, not to a control that no longer exists.
      if (inside) document.querySelector('.primary-nav .nav-button[aria-current="page"]')?.focus();
      return;
    }
    const arrived = shown !== panel;
    if (arrived) focusKey = null;
    else if (inside && active !== root && active.dataset?.focusKey) focusKey = active.dataset.focusKey;
    // A redraw of the same state keeps where the researcher scrolled to.
    const scrolled = arrived ? 0 : root.querySelector('.session-panel-body')?.scrollTop ?? 0;
    const builders = {choose: chooseContent, starting: startingContent,
      failed: state => state.failure?.reviewable === true ? endedContent(state) : failedContent(state)};
    root.replaceChildren(...(builders[panel] ?? startingContent)(state));
    if (scrolled) root.querySelector('.session-panel-body').scrollTop = scrolled;
    root.dataset.state = panel;
    root.setAttribute('aria-busy', String(view.busy || panel === 'starting'));
    for (const control of root.querySelectorAll('button, input')) control.disabled = view.busy;
    root.hidden = false;
    shown = panel;
    const decision = Boolean(DEFAULT_FOCUS[panel]);
    if (view.busy || !decision) {
      if (inside || (arrived && decision)) root.focus();
      return;
    }
    if (!arrived && !inside) return;
    let target = focusKey ? root.querySelector(`[data-focus-key="${focusKey}"]`) : null;
    if (!target && focusKey?.startsWith('remove:')) {
      target = root.querySelector('[data-focus-key^="remove:"]') ?? root.querySelector('[data-focus-key="clear"]');
    }
    const defaultKey = panel === 'failed' && state.failure?.reviewable === true ? 'review' : DEFAULT_FOCUS[panel];
    (target ?? root.querySelector(`[data-focus-key="${defaultKey}"]`) ?? root).focus();
  }

  function receive(state, {keepNotice = false} = {}) {
    if (!state || typeof state !== 'object') return;
    const previous = view.state?.panel;
    if (state.panel === 'choose' && previous !== 'choose') {
      view.mode = state.mode === 'metadata' ? 'metadata' : 'content';
      view.confirmClear = false;
      session.options = optionsFrom(state.options);
      session.advanced = false;
    }
    if (!keepNotice && state.panel !== previous) view.notice = null;
    view.state = state;
    render();
  }

  root.tabIndex = -1;
  globalThis.__rebSessionPanel = state => receive(state);
  // Native's states come only as the answers to one request the page keeps
  // waiting (macos/NativePageOutbox.swift), in order with the replies: a
  // script native ran in the page would take the activation of a click it
  // landed in. The wait starts with the document, and again with a request
  // after a refusal ended it.
  // Names this document to native, which refuses a request from one it saw leave.
  const page = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  let listening = false;
  async function listen() {
    listening = true;
    try {
      for (;;) {
        const answer = await bridge().postMessage({op: 'events', page});
        if (!Array.isArray(answer?.events)) return;
        for (const state of answer.events) {
          try { globalThis.__rebSessionPanel(state); } catch (error) { reportError(error); }
        }
      }
    } catch {
      // Refused: the document is leaving or is not the application's.
    } finally {
      listening = false;
    }
  }
  if (bridge()) {
    listen();
    // Native also publishes once the document finishes loading; this covers a
    // reload the page itself started.
    window.addEventListener('load', () => { ask('state').then(receive, () => {}); });
  }
})();
