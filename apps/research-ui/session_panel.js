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
    content: 'Retains request paths, queries and bodies and response bodies up to 16 MiB each, request and response headers, cookies, and Canvas images.',
    metadata: 'Keeps request hosts and each request body’s length, type and SHA-256, without headers, cookies or Canvas images.',
  };
  const ARTIFACT_NOTE = 'Artifacts keep raw source URLs locally; only an explicitly exported redacted copy is altered.';

  // A Content session's limits, in the order the panel lists them. Native
  // sends each value with its bounds and default (ContentLimits in
  // macos/LiveSessionCoordinator.swift); the keys are the agent options'.
  const LIMITS = [
    {key: 'request_content_budget_mib', id: 'session-panel-request-budget', name: 'Request content budget',
      detail: 'How much of the request bodies and full URLs this session keeps, counting identical content once. Past it, later ones are listed but not kept.'},
    {key: 'response_body_budget_mib', id: 'session-panel-response-budget', name: 'Response body budget',
      detail: 'How much of the response bodies this session keeps, counting identical bodies once. Past it, later bodies are listed but not kept.'},
  ];
  const MEDIA = {key: 'response_media', id: 'session-panel-media', name: 'Capture media and fonts',
    detail: 'Also keep the images, audio, video and fonts that pages load. They count against the response body budget.'};
  const LIMITS_NOTE = 'Both budgets stay on this Mac with the session and can use that much disk. They apply to the session you start here.';

  // The page's own selection while the decision is open: the capture mode
  // and, for Content, its limits as typed. It starts from what native offers
  // and is sent with Start; native validates it again. Sessions started here
  // always use the isolated profile.
  const view = {state: null, mode: 'content', limits: null, invalid: null, busy: false, confirmClear: false, notice: null};

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
  const mib = value => `${Number(value).toLocaleString('en-US')} MiB`;

  // The typed text of each budget and the media choice, from native's values.
  function limitsFrom(limits) {
    const text = key => String(limits?.[key]?.value ?? limits?.[key]?.default ?? '');
    return {[LIMITS[0].key]: text(LIMITS[0].key), [LIMITS[1].key]: text(LIMITS[1].key),
      [MEDIA.key]: limits?.[MEDIA.key]?.value === true};
  }

  // The rule native applies, so a value it would refuse is named here before
  // anything is sent: a whole number of MiB within the stated bounds.
  function budgetProblem(limit) {
    const bounds = view.state?.limits?.[limit.key];
    const text = String(view.limits?.[limit.key] ?? '').trim();
    const value = /^[0-9]+$/.test(text) ? Number(text) : NaN;
    if (!bounds || (Number.isSafeInteger(value) && value >= bounds.min && value <= bounds.max)) return null;
    return `${limit.name} must be a whole number from ${bounds.min} to ${bounds.max} MiB.`;
  }

  // A sentence naming the limits a session runs with, for the starting and
  // failed states.
  function limitsSentence(limits) {
    if (!limits) return '';
    const value = key => limits[key]?.value;
    return `Request content budget ${mib(value(LIMITS[0].key))}, response body budget ${mib(value(LIMITS[1].key))}, `
      + `media and fonts ${value(MEDIA.key) === true ? 'kept' : 'skipped'}.`;
  }

  async function ask(op, body = {}) {
    const handler = bridge();
    if (!handler) throw new Error('The native app is not connected.');
    return handler.postMessage({op, ...body});
  }

  // A choice the native side refused, or a bridge that stopped answering,
  // stays on screen with the decision; native republishes what is current.
  async function choose(op, body = {}) {
    if (view.busy) return;
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

  function modeGroup() {
    const group = element('fieldset', 'session-panel-modes');
    group.append(element('legend', 'session-panel-label', 'Capture mode'));
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

  // A Content session's budgets and media choice, shown only when Content is
  // chosen: a Metadata session keeps no content, so it is given none of them.
  function limitsGroup() {
    const group = element('fieldset', 'session-panel-limits');
    group.append(element('legend', 'session-panel-label', 'Content limits'));
    for (const limit of LIMITS) {
      const bounds = view.state?.limits?.[limit.key] ?? {};
      const row = element('div', 'session-panel-limit');
      const label = element('label', 'session-panel-limit-name', limit.name);
      label.setAttribute('for', limit.id);
      const field = element('span', 'session-panel-limit-field');
      const input = element('input', 'session-panel-limit-input');
      input.type = 'text';
      input.inputMode = 'numeric';
      input.autocomplete = 'off';
      input.spellcheck = false;
      input.maxLength = 6;
      input.id = limit.id;
      input.dataset.focusKey = `limit:${limit.key}`;
      input.value = view.limits?.[limit.key] ?? '';
      const detailId = `${limit.id}-detail`;
      const errorId = `${limit.id}-error`;
      const problem = view.invalid === limit.key ? budgetProblem(limit) : null;
      input.setAttribute('aria-describedby', problem ? `${errorId} ${detailId}` : detailId);
      if (problem) input.setAttribute('aria-invalid', 'true');
      input.addEventListener('input', () => {
        view.limits[limit.key] = input.value;
        // A fixed value takes its error away at once, without a redraw that
        // would move the caret.
        if (view.invalid === limit.key && !budgetProblem(limit)) {
          view.invalid = null;
          input.removeAttribute('aria-invalid');
          input.setAttribute('aria-describedby', detailId);
          row.querySelector('.session-panel-limit-error')?.remove();
        }
      });
      // Return in a budget starts, as it does on Start Session.
      input.addEventListener('keydown', event => {
        if (event.key === 'Enter' && !event.isComposing) { event.preventDefault(); start(); }
      });
      field.append(input, element('span', 'session-panel-limit-unit', 'MiB'));
      const detail = element('span', 'session-panel-limit-detail',
        `${limit.detail} ${Number(bounds.min ?? 1).toLocaleString('en-US')} to ${mib(bounds.max ?? 0)}; default ${mib(bounds.default ?? 0)}.`);
      detail.id = detailId;
      row.append(label, field, detail);
      if (problem) {
        const error = element('span', 'session-panel-limit-error', problem);
        error.id = errorId;
        error.setAttribute('role', 'alert');
        row.append(error);
      }
      group.append(row);
    }
    const media = element('label', 'session-panel-media');
    const box = element('input');
    box.type = 'checkbox';
    box.id = MEDIA.id;
    box.dataset.focusKey = `limit:${MEDIA.key}`;
    box.checked = view.limits?.[MEDIA.key] === true;
    box.addEventListener('change', () => { view.limits[MEDIA.key] = box.checked; });
    const text = element('span', 'session-panel-mode-text');
    text.append(element('span', 'session-panel-mode-name', MEDIA.name), element('span', 'session-panel-mode-detail', MEDIA.detail));
    media.append(box, text);
    group.append(media, element('p', 'session-panel-text session-panel-note', LIMITS_NOTE));
    return group;
  }

  // Start sends the mode, and for Content the limits as whole numbers. A
  // budget native would refuse is named at its field and nothing is sent.
  function start() {
    if (view.busy) return;
    if (view.mode !== 'content') { choose('start', {mode: view.mode}); return; }
    const wrong = LIMITS.find(limit => budgetProblem(limit));
    if (wrong) {
      view.invalid = wrong.key;
      render();
      root.querySelector(`#${wrong.id}`)?.focus();
      return;
    }
    view.invalid = null;
    choose('start', {mode: 'content',
      [LIMITS[0].key]: Number(view.limits[LIMITS[0].key].trim()), [LIMITS[1].key]: Number(view.limits[LIMITS[1].key].trim()),
      [MEDIA.key]: view.limits[MEDIA.key] === true});
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
          ? 'Content mode also records settled-value digests of their string and byte results (sensitive capture); set REB_NATIVE_JS_INVOCATION_DIGESTS=0 to opt out.'
          : 'Metadata mode records no settled-value digests.')
        + ' A Brave without invocation capture starts without them and says so.';
    } else if (sites?.state === 'unreadable') {
      title = 'Saved functions unreadable';
      detail = 'The saved invocation site file is not a valid site file, so this capture tracks nothing. Clear it to start again.';
    } else {
      title = 'Tracking no functions';
      detail = 'Choose Track calls in Sources during a capture to save a function. The next capture you start tracks its calls.';
    }
    const heading = element('h3', 'session-panel-label', title);
    heading.id = 'session-panel-sites-title';
    section.append(heading, element('p', 'session-panel-text', detail));
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
      modeGroup(), ...(view.mode === 'content' && state.limits ? [limitsGroup()] : []),
      element('p', 'session-panel-text session-panel-note', ARTIFACT_NOTE), sitesSection(state.sites));
    const offline = button('session-panel-button', 'Continue Offline', () => choose('offline'), 'offline');
    offline.id = 'session-panel-offline';
    const startButton = button('session-panel-button session-panel-button-primary', 'Start Session', start, 'start');
    startButton.id = 'session-panel-start';
    return [header('start', 'Start a live research session'), body, actions(startButton, offline)];
  }

  function startingContent(state) {
    const body = element('div', 'session-panel-body');
    const status = element('p', 'session-panel-text', `Capture mode: ${modeTitle(state.mode)}. ${limitsSentence(state.limits)}${state.limits ? ' ' : ''}Origin Trace opens the live workspace when the broker, receiver and Brave Browser Development are ready, within a minute.`);
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
    body.append(element('p', 'session-panel-text', `Retry starts a new session with the same capture mode: ${modeTitle(state.mode)}.${state.limits ? ` Same limits: ${limitsSentence(state.limits).replace(/^./, letter => letter.toLowerCase())}` : ''}`));
    if (failure.afterStartup) {
      body.append(element('p', 'session-panel-text', 'Continue Offline replaces this ended workspace, which can no longer load or save anything, with the offline workspace. Its evidence stays in its session folder.'));
    }
    const offline = button('session-panel-button', 'Continue Offline', () => choose('offline'), 'offline');
    offline.id = 'session-panel-offline';
    const retry = button('session-panel-button session-panel-button-primary', 'Retry', () => choose('retry'), 'retry');
    retry.id = 'session-panel-retry';
    return [header('error', String(failure.title ?? 'Live session unavailable'), 'error'), body, actions(retry, offline)];
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
    const builders = {choose: chooseContent, starting: startingContent, failed: failedContent};
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
    (target ?? root.querySelector(`[data-focus-key="${DEFAULT_FOCUS[panel]}"]`) ?? root).focus();
  }

  function receive(state, {keepNotice = false} = {}) {
    if (!state || typeof state !== 'object') return;
    const previous = view.state?.panel;
    if (state.panel === 'choose' && previous !== 'choose') {
      view.mode = state.mode === 'metadata' ? 'metadata' : 'content';
      view.limits = limitsFrom(state.limits);
      view.invalid = null;
      view.confirmClear = false;
    }
    if (!keepNotice && state.panel !== previous) view.notice = null;
    view.state = state;
    render();
  }

  root.tabIndex = -1;
  globalThis.__rebSessionPanel = state => receive(state);
  // Native also publishes once the document finishes loading; this covers a
  // reload the page itself started.
  if (bridge()) window.addEventListener('load', () => { ask('state').then(receive, () => {}); });
})();
