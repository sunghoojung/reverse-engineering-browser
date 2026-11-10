/* In-app agent dock. The native side owns provider calls, the Keychain, the
 * `reb-api mcp` child and the Claude and Grok CLIs; this file owns only the
 * visible conversation. With a key or a ChatGPT subscription the LangGraph
 * graph runs here; with a Claude or Grok subscription the CLI's own loop runs
 * natively and sends the same rows.
 * Captured values and model output are inserted as text, never as markup. Nothing
 * here runs while the dock is closed: no timers, no polling, no listeners on
 * the workspace. */
(function () {
  'use strict';

  // One tool result is at most the projection's 128 KiB inline limit, so 6 MiB
  // keeps about 46 full-size results in the web view, or a far longer chat.
  // Older rows leave the view with a visible label and stay in the local file.
  const WEB_BUDGET_BYTES = 6 * 1024 * 1024;
  // Below this every row stays mounted, which is cheaper than measuring them.
  const WINDOW_THRESHOLD = 80;
  const OVERSCAN_PIXELS = 900;
  // A focused row this close to the window stays mounted with the rows between.
  // Farther away, focus moves to the log instead, so one focused row (a
  // request waiting for a decision) never keeps the whole log mounted.
  const FOCUS_KEEP_ROWS = 40;
  const ESTIMATED_ROW_HEIGHT = 84;
  // A pin holds what a selection realistically is: a function, a request body.
  // A pin matches the projection's inline limit; a turn holds a few of them.
  const PIN_BYTES = 128 * 1024;
  const PIN_TOTAL_BYTES = 512 * 1024;
  const CITE_KEYS = new Set(['session', 'process', 'sequence', 'artifact', 'offset']);

  const encoder = new TextEncoder();
  const utf8Bytes = text => encoder.encode(String(text ?? '')).length;
  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10240 ? 1 : 0)} KiB`;
    return `${(bytes / 1048576).toFixed(1)} MiB`;
  }

  /* ---- Pure models: exercised directly by tools/check-agent-panel.mjs ---- */

  // Tokens the model was asked to emit. Any other shape stays ordinary text.
  function parseCitation(body) {
    const fields = {};
    for (const part of String(body).trim().split(/\s+/)) {
      const match = /^([a-z]+)=([0-9]{1,20})$/.exec(part);
      if (!match || !CITE_KEYS.has(match[1]) || Object.hasOwn(fields, match[1])) return null;
      fields[match[1]] = match[2];
    }
    if (!fields.session) return null;
    if (fields.artifact) return Object.hasOwn(fields, 'process') || Object.hasOwn(fields, 'sequence') ? null : fields;
    return fields.process && fields.sequence && !fields.offset ? fields : null;
  }
  const citeKey = fields => ['session', 'process', 'sequence', 'artifact', 'offset'].map(key => fields[key] ?? '').join(':');
  function citeLabel(fields) {
    if (fields.artifact) return `S${fields.session} · A${fields.artifact}${fields.offset === undefined ? '' : ` · +${fields.offset}`}`;
    return `S${fields.session} · P${fields.process} · E${fields.sequence}`;
  }

  // Inline tokens: **bold**, `code`, *em* and [cite ...]. Nothing else is special.
  function parseInline(text) {
    const tokens = [];
    const pattern = /`([^`\n]{1,4096})`|\*\*([^*\n]{1,4096})\*\*|(?<![*\w])\*([^*\n]{1,4096})\*(?![*\w])|\[cite\s+([^\]\n]{1,200})\]/g;
    let last = 0;
    for (const match of String(text).matchAll(pattern)) {
      const citation = match[4] !== undefined ? parseCitation(match[4]) : undefined;
      if (citation === null) continue;
      if (match.index > last) tokens.push({type: 'text', text: text.slice(last, match.index)});
      if (match[1] !== undefined) tokens.push({type: 'code', text: match[1]});
      else if (match[2] !== undefined) tokens.push({type: 'strong', text: match[2]});
      else if (match[3] !== undefined) tokens.push({type: 'em', text: match[3]});
      else tokens.push({type: 'cite', fields: citation, raw: match[0]});
      last = match.index + match[0].length;
    }
    if (last < text.length) tokens.push({type: 'text', text: text.slice(last)});
    return tokens;
  }

  // The safe subset: paragraphs, headings, lists and fenced code. Raw HTML is
  // not a block type, so `<script>` reaches the DOM only as literal text.
  function parseMarkdown(source) {
    const blocks = [];
    const lines = String(source ?? '').split('\n');
    let paragraph = [], list = null, code = null;
    const flushParagraph = () => {
      if (paragraph.length) blocks.push({type: 'paragraph', inline: parseInline(paragraph.join(' '))});
      paragraph = [];
    };
    const flushList = () => { if (list) blocks.push(list); list = null; };
    for (const line of lines) {
      if (code) {
        if (/^\s*```\s*$/.test(line)) { blocks.push({type: 'code', lang: code.lang, text: code.lines.join('\n')}); code = null; }
        else code.lines.push(line);
        continue;
      }
      const fence = /^\s*```\s*([\w.+#-]{0,32})\s*$/.exec(line);
      if (fence) { flushParagraph(); flushList(); code = {lang: fence[1], lines: []}; continue; }
      if (!line.trim()) { flushParagraph(); flushList(); continue; }
      const heading = /^(#{1,4})\s+(.+?)\s*#*\s*$/.exec(line);
      if (heading) { flushParagraph(); flushList(); blocks.push({type: 'heading', level: heading[1].length, inline: parseInline(heading[2])}); continue; }
      const item = /^\s*(?:([-*+])|(\d{1,9})\.)\s+(.+)$/.exec(line);
      if (item) {
        flushParagraph();
        const ordered = Boolean(item[2]);
        if (!list || list.ordered !== ordered) { flushList(); list = {type: 'list', ordered, items: []}; }
        list.items.push(parseInline(item[3]));
        continue;
      }
      flushList();
      paragraph.push(line.trim());
    }
    if (code) blocks.push({type: 'code', lang: code.lang, text: code.lines.join('\n'), open: true});
    flushParagraph(); flushList();
    return blocks;
  }

  function clipPin(text, limit = PIN_BYTES) {
    const totalBytes = utf8Bytes(text);
    if (totalBytes <= limit) return {text, totalBytes, truncated: false};
    let low = 0, high = text.length;
    while (low < high) {
      const middle = Math.ceil((low + high) / 2);
      if (utf8Bytes(text.slice(0, middle)) <= limit) low = middle; else high = middle - 1;
    }
    return {text: text.slice(0, low), totalBytes, truncated: true};
  }

  function rowBytes(row) {
    // JavaScript strings are UTF-16, so this counts what the view actually holds.
    const strings = [row.text, row.result, row.arguments, row.context];
    return strings.reduce((total, value) => total + 2 * (value?.length ?? 0), 256);
  }

  function createTranscriptModel(budget = WEB_BUDGET_BYTES) {
    let rows = [], bytes = 0, droppedRows = 0, droppedBytes = 0;
    const size = new Map();
    const measure = row => {
      const next = rowBytes(row);
      bytes += next - (size.get(row.id) ?? 0);
      size.set(row.id, next);
    };
    const enforce = keep => {
      while (bytes > budget && rows.length > 1) {
        const index = rows.findIndex(row => row.id !== keep);
        if (index < 0) break;
        const [removed] = rows.splice(index, 1);
        bytes -= size.get(removed.id) ?? 0;
        droppedBytes += size.get(removed.id) ?? 0;
        size.delete(removed.id);
        droppedRows += 1;
      }
    };
    return {
      rows: () => rows,
      get: id => rows.find(row => row.id === id),
      add(row) { rows.push(row); measure(row); enforce(row.id); return row; },
      prepend(older) {
        rows = [...older, ...rows];
        older.forEach(measure);
        // A loaded page is a deliberate request, so it may use spare budget only.
        enforce(rows.at(-1)?.id);
      },
      update(id, patch) {
        const row = rows.find(candidate => candidate.id === id);
        if (!row) return null;
        Object.assign(row, patch);
        measure(row);
        enforce(row.id);
        return row;
      },
      appendText(id, delta) {
        const row = rows.find(candidate => candidate.id === id);
        if (!row) return null;
        row.text += delta;
        measure(row);
        enforce(row.id);
        return row;
      },
      clear() { rows = []; size.clear(); bytes = 0; droppedRows = 0; droppedBytes = 0; },
      stats: () => ({bytes, droppedRows, droppedBytes, count: rows.length, budget}),
    };
  }

  // Only exact, retained identities become links. A model cannot create one by
  // naming an identifier the store does not have.
  async function verifyCitation(fields, {artifacts, events, fetchArtifact, fetchEvents}) {
    if (fields.artifact) {
      let match = artifacts.filter(item => String(item.session_id) === fields.session && String(item.artifact_id) === fields.artifact);
      if (!match.length) match = (await fetchArtifact(fields.session, fields.artifact).catch(() => []));
      if (match.length !== 1) return {status: 'unverified', reason: match.length ? 'ambiguous' : 'not found'};
      const artifact = match[0];
      if (fields.offset !== undefined && !(Number.isSafeInteger(Number(fields.offset)) && Number(fields.offset) <= artifact.byte_size)) {
        return {status: 'unverified', reason: 'offset out of range'};
      }
      return {status: 'verified', kind: 'artifact', artifact};
    }
    const matches = list => list.filter(event => String(event.session_id) === fields.session &&
      String(event.process_id) === fields.process && String(event.sequence_number) === fields.sequence);
    let match = matches(events);
    if (!match.length) match = matches(await fetchEvents(fields.session, fields.process).catch(() => []));
    if (match.length !== 1) return {status: 'unverified', reason: match.length ? 'ambiguous' : 'not retained'};
    return {status: 'verified', kind: 'event', event: match[0]};
  }

  globalThis.RebAgentModel = {parseMarkdown, parseInline, parseCitation, clipPin, createTranscriptModel, verifyCitation, formatBytes,
    WEB_BUDGET_BYTES, PIN_BYTES, PIN_TOTAL_BYTES};

  /* ---- View ---- */

  const dock = document.getElementById('agent-dock');
  const toggle = document.getElementById('agent-toggle');
  const workspace = document.getElementById('workspace');
  if (!dock || !toggle || !workspace) return;

  // Read at use so the native capability is never cached across a reload.
  // randomUUID needs a secure context; the offline reb:// page is not one.
  const rowId = prefix => `${prefix}-${crypto.randomUUID?.() ?? Math.random().toString(36).slice(2)}`;
  const nativeBridge = () => globalThis.webkit?.messageHandlers?.rebAgent ?? null;
  const call = (op, fields = {}) => nativeBridge().postMessage({op, ...fields});
  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const button = (className, text, onClick, label) => {
    const node = element('button', className, text);
    node.type = 'button';
    if (label) node.setAttribute('aria-label', label);
    node.addEventListener('click', onClick);
    return node;
  };

  const PROVIDERS = [['claude', 'Claude'], ['chatgpt', 'ChatGPT'], ['grok', 'Grok']];
  const view = {
    open: false, native: false, status: null, surfaceError: '', provider: 'claude', models: {}, model: {},
    auth: {claude: 'key', chatgpt: 'key', grok: 'subscription'}, subs: {}, checking: {}, signingIn: false,
    phase: 'off', running: false, sessionKey: null, consenting: false, effects: false, turning: false, follow: true,
    usage: null, olderBefore: null, olderAvailable: false, pins: [], selectionKey: '', copied: null, setupNotice: '',
  };
  const transcript = createTranscriptModel();
  const citeChecks = new Map();
  const heights = new Map();
  let framePending = false, frameTranscript = false, lastWindow = '', approvalFocus = null;
  // The mounted rows by id, with what each was drawn from (rowSignature).
  const mountedRows = new Map();
  try {
    const remembered = localStorage.getItem('origin-trace.agent.provider');
    if (PROVIDERS.some(([id]) => id === remembered)) view.provider = remembered;
    const auth = JSON.parse(localStorage.getItem('origin-trace.agent.auth') ?? '{}');
    for (const [id] of PROVIDERS) if (auth?.[id] === 'key' || auth?.[id] === 'subscription') view.auth[id] = auth[id];
  } catch { /* Preferences are optional. */ }

  // Icons are fixed markup from this file. Captured and model text never
  // reaches innerHTML; it is always a text node.
  const ICONS = {
    agent: '<path d="M4 4h12v9H9l-4 3v-3H4zM7 8h6"/>',
    compose: '<path d="M9 4.5H5.5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1V11"/><path d="m13.6 3.9 2.5 2.5-6 6H7.6V9.9z"/>',
    more: '<path d="M5 10h.01M10 10h.01M15 10h.01" stroke-width="2.6"/>',
    close: '<path d="m5.5 5.5 9 9M14.5 5.5l-9 9"/>',
    chevron: '<path d="m6.5 8 3.5 3.5L13.5 8"/>',
    caret: '<path d="m8 6 4 4-4 4"/>',
    send: '<path d="M10 15.5v-11M5.5 9 10 4.5 14.5 9"/>',
    stop: '<rect x="6" y="6" width="8" height="8" rx="1.5" fill="currentColor" stroke="none"/>',
    check: '<path d="m5 10.5 3.2 3.2L15 7"/>',
    error: '<circle cx="10" cy="10" r="6.5"/><path d="M10 6.8v3.8M10 13.3h.01"/>',
    denied: '<circle cx="10" cy="10" r="6.5"/><path d="m5.6 14.4 8.8-8.8"/>',
    shield: '<path d="M10 3.2 4.8 5.1v4.3c0 3.3 2.2 5.9 5.2 7.2 3-1.3 5.2-3.9 5.2-7.2V5.1z"/>',
  };
  function icon(name, extra = '') {
    const node = element('span', `agent-icon${extra ? ` ${extra}` : ''}`);
    node.setAttribute('aria-hidden', 'true');
    node.innerHTML = `<svg viewBox="0 0 20 20">${ICONS[name]}</svg>`;
    return node;
  }
  function iconButton(id, name, label, onClick) {
    const node = button('agent-icon-button', '', onClick, label);
    if (id) node.id = id;
    node.title = label;
    node.append(icon(name));
    return node;
  }

  dock.replaceChildren();
  // One quiet row: the title, what is running, and three icon buttons.
  const head = element('header', 'agent-head');
  const headTitle = element('h2', 'agent-title', 'Agent');
  const chip = element('span', 'agent-status');
  chip.id = 'agent-status';
  chip.setAttribute('role', 'status');
  const chipText = element('span', 'agent-status-text');
  chip.append(element('span', 'agent-status-dot'), chipText);
  const newButton = iconButton('agent-new', 'compose', 'New conversation', () => restartConversation());
  const moreButton = iconButton('agent-more', 'more', 'More', () => toggleMenu());
  moreButton.setAttribute('aria-haspopup', 'menu');
  moreButton.setAttribute('aria-expanded', 'false');
  moreButton.setAttribute('aria-controls', 'agent-menu');
  const close = iconButton('agent-close', 'close', 'Close agent panel', () => setOpen(false));
  close.title = 'Close (⌘ / Ctrl + Shift + A)';
  head.append(headTitle, chip, element('span', 'agent-spacer'), newButton, moreButton, close);

  const menu = element('div', 'agent-menu');
  menu.id = 'agent-menu';
  menu.hidden = true;
  menu.setAttribute('role', 'menu');
  menu.setAttribute('aria-label', 'Agent');
  const menuMeta = element('div', 'agent-menu-meta');
  menuMeta.setAttribute('role', 'presentation');
  const menuItem = (id, text, onClick) => {
    const node = button('agent-menu-item', text, onClick);
    node.id = id;
    node.tabIndex = -1;
    node.setAttribute('role', 'menuitem');
    return node;
  };
  const menuInfo = menuItem('agent-menu-info', 'What leaves this Mac', () => openSheet('info'));
  const menuModel = menuItem('agent-menu-model', 'Change provider or model', () => { closeMenu(false); openPicker(modelButton); });
  const menuClear = menuItem('agent-menu-clear', 'Clear transcript…', () => openSheet('clear'));
  const menuSeparator = element('div', 'agent-menu-separator');
  menuSeparator.setAttribute('role', 'separator');
  const menuOff = menuItem('agent-turn-off', 'Turn off', () => { closeMenu(false); turnOff().then(() => focusDefault()); });
  menuOff.classList.add('agent-menu-danger');
  menu.append(menuMeta, menuInfo, menuModel, menuClear, menuSeparator, menuOff);

  // Info and the clear confirmation open here, over the top of the body.
  const sheet = element('div', 'agent-sheet');
  sheet.id = 'agent-sheet';
  sheet.hidden = true;
  sheet.tabIndex = -1;
  sheet.setAttribute('aria-labelledby', 'agent-sheet-title');

  const body = element('div', 'agent-body');
  const surface = element('div', 'agent-surface');
  surface.id = 'agent-surface';
  // Holds focus while the status loads, then hands it to the first real control.
  surface.tabIndex = -1;
  const log = element('div', 'agent-log');
  log.id = 'agent-log';
  log.tabIndex = 0;
  log.setAttribute('role', 'log');
  log.setAttribute('aria-label', 'Agent conversation');
  const spacerTop = element('div'), rowsHost = element('div', 'agent-rows'), spacerBottom = element('div');
  log.append(spacerTop, rowsHost, spacerBottom);
  body.append(surface, log);

  // One card: attached context, the question, and a bar with the model and Send.
  const composer = element('div', 'agent-composer');
  composer.id = 'agent-composer';
  const composerCard = element('div', 'agent-composer-card');
  const chips = element('div', 'agent-chips');
  chips.id = 'agent-chips';
  const input = element('textarea', 'agent-input');
  input.id = 'agent-input';
  input.rows = 1;
  input.placeholder = 'Ask about this session';
  input.setAttribute('aria-label', 'Message the agent');
  input.setAttribute('aria-describedby', 'agent-input-hint');
  const inputHint = element('span', '', 'Return sends. Shift+Return adds a line.');
  inputHint.id = 'agent-input-hint';
  inputHint.hidden = true;
  const bar = element('div', 'agent-composer-bar');
  const modelButton = button('agent-model-button', '', () => togglePicker(modelButton));
  modelButton.id = 'agent-model';
  modelButton.setAttribute('aria-haspopup', 'menu');
  modelButton.setAttribute('aria-expanded', 'false');
  modelButton.setAttribute('aria-controls', 'agent-picker');
  const modelLabel = element('span', 'agent-model-label');
  modelButton.append(modelLabel, icon('chevron', 'agent-model-chevron'));
  const send = button('agent-send-button', '', onSend, 'Send');
  send.id = 'agent-send';
  bar.append(modelButton, element('span', 'agent-spacer'), send);
  composerCard.append(chips, input, bar);
  composer.append(composerCard, inputHint);

  const picker = element('div', 'agent-picker');
  picker.id = 'agent-picker';
  picker.hidden = true;
  picker.setAttribute('role', 'menu');
  picker.setAttribute('aria-label', 'Provider and model');
  dock.append(head, menu, sheet, body, composer, picker);

  function bridgeFailure(error) {
    return String(error?.message ?? error ?? 'The agent could not complete that.').replace(/^Error:\s*/, '');
  }

  const providerInfo = (id = view.provider) => view.status?.providers?.find(item => item.id === id);
  // A provider without a key path (Grok) is always on its subscription.
  const authFor = (id = view.provider) => providerInfo(id)?.supportsKey === false ? 'subscription' : view.auth[id] ?? 'key';
  const loopFor = (id = view.provider, auth = authFor(id)) => auth === 'subscription' && id !== 'chatgpt' ? 'cli' : 'langgraph';
  const modelKey = (id = view.provider) => `${id}:${authFor(id)}`;
  const modesOf = provider => provider?.supportsKey === false ? ['subscription'] : ['key', 'subscription'];
  const CLI_NAMES = {claude: 'Claude CLI', grok: 'Grok CLI'};
  const CLI_LOGIN = {claude: 'Run claude auth login in Terminal, then check again.', grok: 'Run grok login in Terminal, then check again.'};
  const subscriptionOf = id => view.subs[id] ?? providerInfo(id)?.subscription ?? {};
  // A loopback stand-in replaces only the graph's provider endpoint. A CLI
  // still talks to its own vendor, so its disclosure never says "stand-in".
  const standInApplies = (id = view.provider, auth = authFor(id)) => Boolean(view.status?.standIn) && loopFor(id, auth) === 'langgraph';

  // What a provider and payment need before the agent can turn on.
  function credential(id = view.provider, auth = authFor(id)) {
    const provider = providerInfo(id);
    if (!provider) return {ready: false, text: ''};
    if (auth === 'key') {
      return provider.hasKey ? {ready: true, text: standInApplies(id, auth) ? 'Local stand-in provider' : 'Key in your Keychain'}
        : {ready: false, text: `No ${provider.label} key yet`, action: 'addKey'};
    }
    const sub = subscriptionOf(id);
    if (id === 'chatgpt') {
      if (view.signingIn || sub.waiting) return {ready: false, text: 'Finish signing in to ChatGPT in your browser.', action: 'cancelSignIn'};
      if (sub.signedIn) return {ready: true, text: sub.standIn ? 'Stand-in ChatGPT sign-in' : 'ChatGPT, token sharing allowed'};
      return {ready: false, text: sub.reason ?? 'Sign in with ChatGPT to use your plan.', action: 'signIn'};
    }
    if (view.checking[id]) return {ready: false, text: `Checking the ${CLI_NAMES[id]}…`};
    if (sub.available === false) return {ready: false, text: sub.reason ?? `The ${CLI_NAMES[id]} is not installed.`, action: 'check'};
    if (sub.signedIn === true) {
      const plan = sub.plan ? `${String(sub.plan).replace(/^./, letter => letter.toUpperCase())} plan` : 'Signed in';
      return {ready: true, text: `${plan}, through your ${CLI_NAMES[id]}`};
    }
    if (sub.signedIn === false) return {ready: false, text: sub.reason ? `${sub.reason} ${CLI_LOGIN[id]}` : CLI_LOGIN[id], action: 'check'};
    return {ready: false, text: `Select it to check your ${CLI_NAMES[id]} sign-in.`, action: 'check'};
  }

  // A few words for a provider card or a picker row; credential().text is the full line.
  function credentialBadge(id, auth = authFor(id)) {
    const state = credential(id, auth);
    const sub = subscriptionOf(id);
    if (state.ready) {
      if (auth === 'key') return {tone: 'ready', text: standInApplies(id, auth) ? 'Stand-in' : 'Key saved'};
      return {tone: 'ready', text: id === 'chatgpt' ? 'Signed in' : planText(id) || 'Signed in'};
    }
    if (auth === 'subscription' && view.checking[id]) return {tone: 'busy', text: 'Checking'};
    if (state.action === 'addKey') return {tone: 'todo', text: 'Add key'};
    if (state.action === 'signIn') return {tone: 'todo', text: 'Sign in'};
    if (state.action === 'cancelSignIn') return {tone: 'busy', text: 'Signing in'};
    if (sub.available === false) return {tone: 'todo', text: 'Not installed'};
    if (sub.signedIn === false) return {tone: 'todo', text: 'Signed out'};
    return {tone: 'idle', text: 'Not checked'};
  }

  const titleCase = word => String(word).replace(/^./, letter => letter.toUpperCase());
  const planText = id => (subscriptionOf(id).plan ? `${titleCase(subscriptionOf(id).plan)} plan` : '');
  // Model ids as a person reads them: claude-opus-5-5 is Claude Opus 5.5 and
  // gpt-6-astra is GPT-6 Astra. Anything else stays as the provider named it.
  function modelName(model, id = view.provider) {
    const raw = String(model ?? '');
    if (!raw || raw === 'default') return '';
    const claude = /^claude-([a-z]+)-(\d+)-(\d+)(?:-\d{8})?$/.exec(raw);
    if (claude) return `Claude ${titleCase(claude[1])} ${claude[2]}.${claude[3]}`;
    const gpt = /^gpt-(\d[\w.]*)((?:-[a-z0-9]+)*)$/i.exec(raw);
    if (gpt) return `GPT-${gpt[1]}${gpt[2].split('-').filter(Boolean).map(part => ` ${titleCase(part)}`).join('')}`;
    if (/^grok-[\w.-]+$/i.test(raw)) return raw.split('-').map(titleCase).join(' ');
    if (/^[a-z]+$/.test(raw)) return `${providerInfo(id)?.label ?? ''} ${titleCase(raw)}`.trim();
    return raw;
  }
  function modeLabel(id, auth) {
    if (auth === 'key') return standInApplies(id, auth) ? 'Stand-in' : 'API key';
    if (id === 'chatgpt') return subscriptionOf(id).standIn ? 'Stand-in sign-in' : 'ChatGPT plan';
    return planText(id) || 'Subscription';
  }
  function selectedModel(id = view.provider, auth = authFor(id)) {
    const provider = providerInfo(id);
    const fallback = auth === 'subscription' ? provider?.subscriptionModel ?? provider?.defaultModel : provider?.defaultModel;
    return view.model[`${id}:${auth}`] ?? fallback ?? view.models[`${id}:${auth}`]?.[0] ?? '';
  }
  const modelsFor = (id, auth) => (view.models[`${id}:${auth}`] ?? [selectedModel(id, auth)]).filter(Boolean);
  // What is running, or what turning on would start.
  function activeChoice() {
    const engine = view.status?.engine;
    if (view.phase !== 'off' && engine?.provider) {
      return {provider: engine.provider, auth: engine.auth ?? authFor(engine.provider), model: engine.model ?? ''};
    }
    return {provider: view.provider, auth: authFor(), model: selectedModel()};
  }
  function choiceLabel(choice = activeChoice()) {
    const name = modelName(choice.model, choice.provider) || providerInfo(choice.provider)?.label || 'Agent';
    return `${name} · ${modeLabel(choice.provider, choice.auth)}`;
  }
  const count = (value, noun) => `${value.toLocaleString('en-US')} ${noun}${value === 1 ? '' : 's'}`;
  // Tool and token counts live here, in the menu and the chip's tooltip.
  function statusDetail() {
    const choice = activeChoice(), engine = view.status?.engine;
    const parts = [providerInfo(choice.provider)?.label, choice.model || 'default model', modeLabel(choice.provider, choice.auth)];
    if (view.phase !== 'off') parts.push(count(engine?.tools?.length ?? 0, 'tool'), engine?.effects ? 'actions ask each time' : 'read only');
    if (view.usage) parts.push(`last turn ${count(view.usage.input, 'token')} in, ${count(view.usage.output, 'token')} out`);
    return parts.filter(Boolean).join(' · ');
  }

  function disclosureText() {
    const provider = providerInfo();
    const vendor = provider?.vendor ?? 'the provider';
    const structural = 'Tool results are structural: they can include URLs, hosts, identifiers and counts. Source, bytecode, disassembly and request bodies stay on this Mac unless you pin them.';
    if (standInApplies()) return `Your question, excerpts you pin and every tool result go to a local stand-in provider on this machine. ${structural}`;
    if (authFor() === 'key') return `Your question, excerpts you pin and every tool result go to ${vendor}. ${structural}`;
    if (view.provider === 'chatgpt') {
      return `Your question, excerpts you pin and every tool result go to ${vendor} under your ChatGPT plan, through token sharing. ${structural}`;
    }
    const kept = view.provider === 'grok' ? ' Grok keeps its own record of the session in ~/.grok/sessions on this Mac.' : '';
    return `Your question, excerpts you pin and every tool result go to ${vendor} under your plan, through the ${CLI_NAMES[view.provider]} installed and signed in on this Mac. This is your own local use of your own CLI login, which stays with the CLI. The CLI runs its own agent loop with only the reb-api tools; every action still needs Allow once.${kept} ${structural}`;
  }

  // One line for the setup state. The full disclosure is the consent step and Info.
  function shortDisclosure() {
    const vendor = providerInfo()?.vendor ?? 'the provider';
    if (standInApplies()) return 'Local stand-in provider. Nothing leaves this Mac.';
    if (authFor() === 'key') return `Once on, your question, pins and tool results go to ${vendor}.`;
    if (view.provider === 'chatgpt') return `Once on, your question, pins and tool results go to ${vendor} under your ChatGPT plan.`;
    return `Once on, your question, pins and tool results go to ${vendor} through your ${CLI_NAMES[view.provider]}.`;
  }

  const focusedIn = node => { const active = document.activeElement; return Boolean(active && active !== document.body && node.contains(active)); };
  // Rebuilt regions find the control that had focus again by its key.
  function restoreFocus(container, key) {
    if (key === undefined || key === null) return false;
    const target = [...container.querySelectorAll('[data-focus-key]')].find(node => node.dataset.focusKey === key);
    target?.focus();
    return Boolean(target);
  }
  const focusKeyIn = node => (focusedIn(node) ? document.activeElement.dataset?.focusKey ?? '' : undefined);

  function dockState() {
    if (!view.native || view.status?.available === false) return 'unavailable';
    if (!view.status) return 'loading';
    if (view.consenting) return 'consent';
    if (view.turning) return 'starting';
    if (view.phase === 'off') return 'off';
    if (view.phase === 'stopped') return 'stopped';
    return view.running ? 'running' : 'ready';
  }

  function renderHead() {
    const state = dockState();
    dock.dataset.state = state;
    const usable = state !== 'unavailable' && state !== 'loading';
    chip.hidden = !usable;
    const tone = {starting: 'busy', running: 'busy', ready: 'ready', stopped: 'error'}[state] ?? 'off';
    chip.dataset.tone = tone;
    chipText.textContent = state === 'starting' ? 'Starting…' : state === 'stopped' ? 'Disconnected' : tone === 'off' ? 'Off' : choiceLabel();
    // The pulsing dot shows a running turn; the tooltip says it in words.
    chip.title = usable ? `${state === 'running' ? 'Working. ' : ''}${statusDetail()}` : '';
    newButton.hidden = moreButton.hidden = !usable;
    newButton.disabled = view.phase === 'off' || view.running || view.turning || !transcript.rows().length;
  }

  /* ---- Menus and popovers. Arrow keys move, Escape closes, Tab leaves. ---- */

  const menuItems = container => [...container.querySelectorAll('[role^="menuitem"]')].filter(node => !node.hidden && !node.disabled);
  function menuKeys(container, close) {
    container.addEventListener('keydown', event => {
      const items = menuItems(container);
      const at = items.indexOf(document.activeElement);
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        const step = event.key === 'ArrowDown' ? 1 : -1;
        items[at < 0 ? (step > 0 ? 0 : items.length - 1) : (at + step + items.length) % items.length]?.focus();
      } else if (event.key === 'Home' || event.key === 'End') {
        event.preventDefault();
        items[event.key === 'Home' ? 0 : items.length - 1]?.focus();
      } else if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        close(true);
      } else if (event.key === 'Tab') close(true);
    });
  }

  let outsideWatched = false;
  function onOutside(event) {
    const target = event.target;
    if (!menu.hidden && !menu.contains(target) && !moreButton.contains(target)) closeMenu(false);
    if (!picker.hidden && !picker.contains(target) && !pickerAnchor?.contains(target)) closePicker(false);
    if (sheetKind && !sheet.contains(target) && !menu.contains(target) && !moreButton.contains(target)) closeSheet(false);
  }
  // A pointer listener exists only while something is open.
  function watchOutside() {
    const want = view.open && (!menu.hidden || !picker.hidden || Boolean(sheetKind));
    if (want === outsideWatched) return;
    outsideWatched = want;
    document[want ? 'addEventListener' : 'removeEventListener']('pointerdown', onOutside, true);
  }

  function openMenu() {
    closePicker(false);
    closeSheet(false);
    menu.hidden = false;
    moreButton.setAttribute('aria-expanded', 'true');
    renderMenu();
    menuItems(menu)[0]?.focus();
    watchOutside();
  }
  function closeMenu(focus = true) {
    if (menu.hidden) return;
    menu.hidden = true;
    moreButton.setAttribute('aria-expanded', 'false');
    if (focus) moreButton.focus();
    watchOutside();
  }
  const toggleMenu = () => (menu.hidden ? openMenu() : closeMenu());
  menuKeys(menu, closeMenu);

  function renderMenu() {
    if (menu.hidden) return;
    const on = view.phase !== 'off';
    menuMeta.textContent = statusDetail();
    menuModel.hidden = menuClear.hidden = menuOff.hidden = menuSeparator.hidden = !on;
    menuModel.disabled = menuClear.disabled = view.running || view.turning;
    menuOff.disabled = view.turning;
  }

  let sheetKind = null, sheetKey = '';
  function openSheet(kind) {
    closeMenu(false);
    closePicker(false);
    sheetKind = kind;
    sheetKey = '';
    sheet.hidden = false;
    sheet.setAttribute('role', kind === 'clear' ? 'alertdialog' : 'dialog');
    renderSheet();
    (sheet.querySelector('[data-autofocus]') ?? sheet).focus();
    watchOutside();
  }
  function closeSheet(focus = true) {
    if (!sheetKind) return;
    sheetKind = null;
    sheetKey = '';
    sheet.hidden = true;
    sheet.replaceChildren();
    if (focus) moreButton.focus();
    watchOutside();
  }
  sheet.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    event.preventDefault();
    event.stopPropagation();
    closeSheet();
  });

  function renderSheet() {
    if (!sheetKind) return;
    const key = JSON.stringify([sheetKind, view.provider, view.auth, view.phase, view.status?.providers, view.status?.engine, view.subs, view.usage, view.running, view.turning]);
    if (key === sheetKey) return;
    sheetKey = key;
    const focusKey = focusKeyIn(sheet);
    sheet.replaceChildren(...(sheetKind === 'clear' ? clearSheet() : infoSheet()));
    restoreFocus(sheet, focusKey);
  }

  function sheetHead(title) {
    const top = element('div', 'agent-sheet-head');
    const heading = element('h3', 'agent-sheet-title', title);
    heading.id = 'agent-sheet-title';
    const shut = iconButton('', 'close', 'Close', () => closeSheet());
    shut.dataset.focusKey = 'close';
    shut.dataset.autofocus = 'true';
    top.append(heading, shut);
    return top;
  }

  function infoSheet() {
    const row = (key, value) => {
      const line = element('div', 'agent-sheet-row');
      line.append(element('span', 'agent-sheet-key', key), element('span', 'agent-sheet-value', value));
      return line;
    };
    const provider = providerInfo();
    const auth = authFor();
    const rows = element('div', 'agent-sheet-rows');
    rows.append(row('Provider', standInApplies() ? `${provider?.label ?? ''}, local stand-in` : provider?.vendor ?? 'Unknown'));
    if (auth === 'key') rows.append(row('Key', provider?.hasKey ? 'Stored in Keychain' : 'Not set'));
    else if (view.provider === 'chatgpt') rows.append(row('Account', subscriptionOf('chatgpt').signedIn ? 'ChatGPT token in Keychain' : 'Not signed in'));
    else rows.append(row('Account', `Your ${CLI_NAMES[view.provider]} login, kept by the CLI`));
    rows.append(row('Loop', loopFor() === 'cli' ? `The ${CLI_NAMES[view.provider]}'s own loop` : 'LangGraph in this window'));
    rows.append(row('Tools', view.status?.engine?.effects ? 'Read and actions (ask each time)' : 'Read only'));
    if (view.phase !== 'off') rows.append(row('Listed', count(view.status?.engine?.tools?.length ?? 0, 'tool')));
    if (view.usage) rows.append(row('Last turn', `${count(view.usage.input, 'token')} in, ${count(view.usage.output, 'token')} out`));
    rows.append(row('Transcript', 'Local, user-only, not part of the evidence'));
    const nodes = [sheetHead('What leaves this Mac'), element('p', 'agent-sheet-text', disclosureText()), rows];
    const actions = element('div', 'agent-sheet-actions');
    if (auth === 'key' && provider?.hasKey && !standInApplies()) {
      const remove = button('agent-button', `Remove ${provider.label} key`, removeKey);
      remove.dataset.focusKey = 'remove-key';
      actions.append(remove);
    }
    if (auth === 'subscription' && view.provider === 'chatgpt' && subscriptionOf('chatgpt').signedIn && !subscriptionOf('chatgpt').standIn) {
      const out = button('agent-button', 'Sign out of ChatGPT', signOut);
      out.dataset.focusKey = 'sign-out';
      actions.append(out);
    }
    if (actions.childElementCount) nodes.push(actions);
    return nodes;
  }

  function clearSheet() {
    const actions = element('div', 'agent-sheet-actions');
    const cancel = button('agent-button', 'Cancel', () => closeSheet());
    cancel.dataset.focusKey = 'cancel';
    const confirm = button('agent-button agent-button-danger', 'Clear transcript', async () => {
      closeSheet(false);
      await restartConversation({clear: true});
      focusDefault();
    });
    confirm.id = 'agent-clear-confirm';
    confirm.disabled = view.running || view.turning;
    actions.append(cancel, confirm);
    const nodes = [sheetHead('Clear this transcript?'),
      element('p', 'agent-sheet-text', 'This deletes the local record of this session\'s conversation and starts a new one. The model starts fresh; the evidence is not changed.'), actions];
    nodes[0].querySelector('button').removeAttribute('data-autofocus');
    cancel.dataset.autofocus = 'true';
    return nodes;
  }

  /* ---- Centered states: setup, consent, empty and messages ---- */

  function surfaceState() {
    if (!view.native) return {kind: 'message', title: 'Available in the macOS app', text: 'The agent runs in the native app, which holds your key and the local tool server. Open this workspace in Origin Trace.'};
    if (!view.status) return {kind: 'loading'};
    if (view.status.available === false) {
      return view.status.reason === 'offline-workspace'
        ? {kind: 'message', title: 'Needs a live or opened session', text: 'The agent reads evidence through a session\'s local API. This offline workspace has none. Start a live capture to use it.'}
        : {kind: 'message', title: 'Tool server missing', text: 'This build has no OriginTraceAPI helper. Rebuild the app with make app-build.'};
    }
    if (view.consenting) return {kind: 'consent'};
    if (view.phase === 'off') return {kind: 'setup'};
    if (transcript.rows().length) return null;
    if (view.phase === 'stopped') return {kind: 'message', tone: 'error', title: 'Disconnected', text: view.surfaceError || 'The local tool server stopped. Ask again to restart it.'};
    return {kind: 'empty'};
  }

  let surfaceKey = '';
  function renderSurface() {
    const state = surfaceState();
    surface.hidden = !state;
    log.hidden = Boolean(state);
    if (!state) { if (surfaceKey) { surfaceKey = ''; surface.replaceChildren(); } return; }
    // Everything a state is drawn from, so a selection change in the
    // workspace never rebuilds the controls under the pointer or the focus.
    const key = JSON.stringify([state, view.provider, view.auth, view.status?.standIn, view.status?.providers, view.subs, view.checking,
      view.signingIn, view.model, view.models[modelKey()], view.setupNotice, view.turning, view.olderAvailable]);
    if (key === surfaceKey) return;
    surfaceKey = key;
    const focusKey = focusKeyIn(surface);
    // Focus the panel placed itself moves on to the next decision; focus the
    // researcher placed stays on the same control.
    const placed = document.activeElement === surface || (autoFocused && document.activeElement === autoFocused);
    const builders = {setup: setupSurface, consent: consentSurface, empty: emptySurface, loading: loadingSurface, message: messageSurface};
    surface.replaceChildren(builders[state.kind](state));
    if (placed || (!restoreFocus(surface, focusKey) && focusKey !== undefined)) focusDefault();
  }

  function welcome(className, name, title, text) {
    const node = element('div', `agent-center ${className}`);
    node.append(icon(name, 'agent-center-icon'), element('h3', 'agent-center-title', title));
    if (text) node.append(element('p', 'agent-center-text', text));
    return node;
  }

  function loadingSurface() {
    const node = element('div', 'agent-center agent-loading');
    node.append(element('span', 'agent-spinner'), element('span', 'agent-center-text', 'Loading'));
    return node;
  }

  function messageSurface(state) {
    const node = welcome('agent-message', state.tone === 'error' ? 'error' : 'agent', state.title, state.text);
    if (state.tone) node.dataset.tone = state.tone;
    return node;
  }

  function badgeNode({tone, text}) {
    const node = element('span', 'agent-badge');
    node.dataset.tone = tone;
    node.append(tone === 'busy' ? element('span', 'agent-spinner') : element('span', 'agent-badge-dot'), element('span', '', text));
    return node;
  }

  // Off: each provider with what it needs, then one way to turn on.
  function setupSurface() {
    const node = welcome('agent-setup', 'agent', 'The agent is off', 'Turn it on for this session to ask about the evidence. Nothing is sent until you do.');
    const list = element('div', 'agent-providers');
    list.setAttribute('role', 'group');
    list.setAttribute('aria-label', 'Provider');
    for (const provider of view.status?.providers ?? []) list.append(providerCard(provider));
    node.append(list);
    if (view.setupNotice) {
      const note = element('p', `agent-setup-note${view.setupNotice.kind === 'error' ? ' agent-setup-error' : ''}`, view.setupNotice.text);
      note.setAttribute('role', view.setupNotice.kind === 'error' ? 'alert' : 'status');
      node.append(note);
    }
    const turnOn = button('agent-button agent-button-primary agent-turn-on', 'Turn on for this session', requestConsent);
    turnOn.id = 'agent-turn-on';
    turnOn.dataset.focusKey = 'turn-on';
    turnOn.disabled = !credential().ready || view.turning;
    turnOn.setAttribute('aria-describedby', 'agent-account-text');
    node.append(turnOn, element('p', 'agent-leaves', shortDisclosure()));
    return node;
  }

  function providerCard(provider) {
    const id = provider.id, selected = id === view.provider, auth = authFor(id), state = credential(id, auth);
    const card = element('div', `agent-provider${selected ? ' agent-provider-selected' : ''}`);
    const pick = button('agent-provider-pick', '', () => chooseProvider(id));
    pick.dataset.provider = id;
    pick.dataset.focusKey = `provider:${id}`;
    pick.setAttribute('aria-pressed', String(selected));
    const badge = credentialBadge(id, auth);
    pick.append(element('span', 'agent-provider-name', provider.label), badgeNode(badge.tone === 'ready' ? {tone: 'ready', text: 'Ready'} : badge));
    const status = element('p', 'agent-provider-status', state.text);
    card.append(pick, status);
    // The rest of the card selects it too; only its own controls do something else.
    card.addEventListener('click', event => { if (!event.target.closest('button')) chooseProvider(id); });
    if (!selected) return card;
    card.id = 'agent-account';
    status.id = 'agent-account-text';
    const controls = element('div', 'agent-provider-controls');
    if (modesOf(provider).length > 1) {
      const segment = element('div', 'agent-segment');
      segment.setAttribute('role', 'group');
      segment.setAttribute('aria-label', 'Pay with');
      for (const mode of modesOf(provider)) {
        const node = button('agent-segment-button', mode === 'key' ? 'API key' : 'Subscription', () => chooseAuth(mode));
        node.dataset.auth = mode;
        node.dataset.focusKey = `auth:${mode}`;
        node.setAttribute('aria-pressed', String(mode === auth));
        segment.append(node);
      }
      controls.append(segment);
    } else {
      // One way to pay is stated, not offered as a choice.
      controls.append(element('span', 'agent-mode-only', 'Subscription only'));
    }
    controls.append(element('span', 'agent-spacer'));
    const labels = {addKey: `Add ${provider.label} key`, signIn: 'Sign in', cancelSignIn: 'Cancel', check: 'Check again'};
    if (labels[state.action]) {
      const action = button('agent-button', labels[state.action], () => accountActions[state.action]());
      action.id = 'agent-account-action';
      action.dataset.action = state.action;
      action.dataset.focusKey = 'account-action';
      controls.append(action);
    } else if (state.ready) {
      const choose = button('agent-model-button', '', () => togglePicker(choose, {modelsOnly: true}));
      choose.id = 'agent-setup-model';
      choose.dataset.focusKey = 'setup-model';
      choose.setAttribute('aria-haspopup', 'menu');
      choose.setAttribute('aria-expanded', 'false');
      const name = modelName(selectedModel(), id) || 'Default';
      choose.setAttribute('aria-label', `Model: ${name}`);
      choose.title = selectedModel() || 'The default model';
      choose.append(element('span', 'agent-model-label', name), icon('chevron', 'agent-model-chevron'));
      controls.append(choose);
    }
    card.append(controls);
    return card;
  }

  function consentSurface() {
    const node = welcome('agent-consent', 'shield', 'Before you turn this on');
    node.append(element('p', 'agent-consent-target', choiceLabel()));
    node.append(element('p', 'agent-consent-text', disclosureText()));
    const effectsLabel = element('label', 'agent-check');
    const effects = element('input');
    effects.type = 'checkbox';
    effects.id = 'agent-effects';
    effects.dataset.focusKey = 'effects';
    effects.checked = view.effects;
    effects.addEventListener('change', () => { view.effects = effects.checked; });
    effectsLabel.append(effects, element('span', '', 'Let the agent request actions. Each one needs Allow once.'));
    const actions = element('div', 'agent-consent-actions');
    const cancel = button('agent-button', 'Cancel', () => { view.consenting = false; render(); focusDefault(); });
    cancel.dataset.focusKey = 'cancel';
    const accept = button('agent-button agent-button-primary', 'Turn on for this session', confirmConsent);
    accept.id = 'agent-consent-accept';
    accept.dataset.focusKey = 'accept';
    actions.append(cancel, accept);
    node.append(effectsLabel, actions);
    return node;
  }

  const SUGGESTIONS = ['Summarize this session', 'What scripts ran first?', 'Which hosts did it contact?', 'Explain the selected row'];
  // A suggestion fills the composer; the researcher still sends it.
  function useSuggestion(text) {
    input.value = text;
    input.dispatchEvent(new Event('input'));
    input.focus();
    input.setSelectionRange?.(text.length, text.length);
  }

  function emptySurface() {
    const node = welcome('agent-empty', 'agent', 'Ask about this session', 'Select a request, script or VM row to attach it. Pin what the model should read.');
    const list = element('div', 'agent-suggestions');
    for (const text of SUGGESTIONS) {
      const suggestion = button('agent-suggestion', text, () => useSuggestion(text));
      suggestion.dataset.focusKey = `suggest:${text}`;
      list.append(suggestion);
    }
    node.append(list);
    if (view.olderAvailable) {
      const older = button('agent-button agent-older-button', 'Show earlier rows', loadOlder);
      older.dataset.focusKey = 'older';
      node.append(older);
    }
    return node;
  }

  /* ---- Provider and model picker ---- */

  let pickerAnchor = null, pickerKey = '', pickerModelsOnly = false;
  function openPicker(anchor, {modelsOnly = false} = {}) {
    if (!view.status?.providers?.length || !anchor) return;
    closeMenu(false);
    closeSheet(false);
    pickerAnchor = anchor;
    pickerModelsOnly = modelsOnly;
    pickerKey = '';
    picker.hidden = false;
    anchor.setAttribute('aria-expanded', 'true');
    renderPicker();
    (picker.querySelector('[data-model][aria-checked="true"]') ?? picker.querySelector('[aria-checked="true"]') ?? menuItems(picker)[0])?.focus();
    watchOutside();
  }
  function closePicker(focus = true) {
    if (picker.hidden) return;
    picker.hidden = true;
    pickerKey = '';
    const anchor = pickerAnchor;
    pickerAnchor = null;
    anchor?.setAttribute('aria-expanded', 'false');
    if (focus) { if (anchor?.isConnected) anchor.focus(); else focusDefault(); }
    watchOutside();
  }
  const togglePicker = (anchor, options) => (picker.hidden ? openPicker(anchor, options) : closePicker());
  menuKeys(picker, closePicker);

  // On: the current choice is checked, and any other one turns the agent
  // off and asks again, as switching it off by hand does.
  const isCurrent = (id, mode) => { const choice = activeChoice(); return choice.provider === id && choice.auth === mode; };

  function pickerItem(className, checked, onPick) {
    const node = element('button', `agent-picker-item ${className}`);
    node.type = 'button';
    node.tabIndex = -1;
    node.setAttribute('role', 'menuitemradio');
    node.setAttribute('aria-checked', String(checked));
    node.append(icon('check', 'agent-picker-check'));
    node.addEventListener('click', onPick);
    return node;
  }

  function renderPicker() {
    if (picker.hidden) return;
    const on = view.phase !== 'off';
    const key = JSON.stringify([pickerModelsOnly, on, activeChoice(), view.status?.providers, view.subs, view.checking, view.models, view.model, view.signingIn, view.running]);
    if (key !== pickerKey) {
      pickerKey = key;
      const focusKey = focusKeyIn(picker);
      picker.replaceChildren();
      if (on) {
        const note = element('p', 'agent-picker-note', 'Choosing another turns the agent off and asks again.');
        note.setAttribute('role', 'presentation');
        picker.append(note);
      }
      const choice = activeChoice();
      for (const provider of view.status?.providers ?? []) {
        if (pickerModelsOnly && provider.id !== choice.provider) continue;
        const group = element('div', 'agent-picker-group');
        group.setAttribute('role', 'group');
        group.setAttribute('aria-label', provider.label);
        const heading = element('div', 'agent-picker-heading', provider.label);
        heading.setAttribute('role', 'presentation');
        group.append(heading);
        for (const mode of modesOf(provider)) {
          if (pickerModelsOnly && mode !== choice.auth) continue;
          const current = isCurrent(provider.id, mode);
          if (!pickerModelsOnly) {
            const item = pickerItem('agent-picker-mode', current, () => pickMode(provider.id, mode));
            item.dataset.pick = `${provider.id}:${mode}`;
            item.dataset.focusKey = `pick:${provider.id}:${mode}`;
            item.disabled = on && view.running;
            item.append(element('span', 'agent-picker-label', mode === 'key' ? 'API key' : 'Subscription'), badgeNode(credentialBadge(provider.id, mode)));
            group.append(item);
          }
          if (!current || !credential(provider.id, mode).ready) continue;
          for (const model of modelsFor(provider.id, mode)) {
            const item = pickerItem('agent-picker-model', model === choice.model, () => pickModel(model));
            item.dataset.model = model;
            item.dataset.focusKey = `model:${model}`;
            item.disabled = on && view.running;
            const name = modelName(model, provider.id);
            item.append(element('span', 'agent-picker-label', name || 'Default model'), element('span', 'agent-picker-id', model));
            group.append(item);
          }
        }
        picker.append(group);
      }
      restoreFocus(picker, focusKey);
    }
    positionPicker();
  }

  // Inside the dock, on whichever side of its button has more room.
  function positionPicker() {
    if (picker.hidden || !pickerAnchor?.isConnected) return;
    const host = dock.getBoundingClientRect(), anchor = pickerAnchor.getBoundingClientRect();
    const margin = 8, width = Math.min(300, host.width - 2 * margin);
    picker.style.width = `${width}px`;
    picker.style.left = `${Math.max(margin, Math.min(anchor.left - host.left, host.width - width - margin))}px`;
    const above = anchor.top - host.top - margin - 6, below = host.bottom - anchor.bottom - margin - 6;
    if (above > below) {
      picker.style.top = '';
      picker.style.bottom = `${host.bottom - anchor.top + 6}px`;
      picker.style.maxHeight = `${Math.max(120, above)}px`;
    } else {
      picker.style.bottom = '';
      picker.style.top = `${anchor.bottom - host.top + 6}px`;
      picker.style.maxHeight = `${Math.max(120, below)}px`;
    }
  }

  function pickMode(id, mode) {
    if (view.phase !== 'off') { if (!isCurrent(id, mode)) switchTo(id, mode); return; }
    setChoice(id, mode);
  }

  function pickModel(model) {
    if (view.phase !== 'off') {
      const choice = activeChoice();
      if (model === choice.model) closePicker();
      else switchTo(choice.provider, choice.auth, model);
      return;
    }
    view.model[modelKey()] = model;
    closePicker();
    render();
  }

  function renderComposer() {
    const on = view.phase !== 'off';
    composer.hidden = !view.native || !view.status || view.status.available === false || view.consenting || !on;
    const label = choiceLabel();
    modelLabel.textContent = label;
    modelButton.setAttribute('aria-label', `Provider and model: ${label}`);
    modelButton.title = statusDetail();
    modelButton.disabled = view.turning;
    const mode = view.running ? 'stop' : 'send';
    if (send.dataset.mode !== mode) {
      send.dataset.mode = mode;
      send.replaceChildren(icon(mode));
      send.setAttribute('aria-label', view.running ? 'Stop' : 'Send');
      send.title = view.running ? 'Stop' : 'Send (Return)';
    }
    send.classList.toggle('agent-send-stop', view.running);
    send.disabled = !on || (!view.running && !input.value.trim());
    // A stopped tool server restarts on the next question.
    input.disabled = !on;
    renderChips();
  }

  function currentSelection() {
    try {
      const screen = investigationScreen();
      if (screen === 'sources') {
        const source = selectedSource();
        const identity = investigationArtifactIdentity(source);
        if (identity) return {key: `a:${identity.session}:${identity.artifact}`, label: sourceDisplayName(source), kind: 'script',
          identifiers: `session=${identity.session} artifact=${identity.artifact} byte_size=${identity.bytes} sha256=${identity.sha256}`};
      }
      if (screen === 'traffic' || screen === 'backtrace') {
        const request = state.requests.find(item => item.id === state.selectedRequestId);
        const identity = investigationRequestIdentity(request);
        if (identity) return {key: `r:${identity.session}:${identity.process}:${identity.sequence}`,
          label: `${request.method ?? 'Request'} ${request.path ?? ''}`.trim(), kind: 'request',
          identifiers: `session=${identity.session} process=${identity.process} sequence=${identity.sequence} request_id=${identity.request}`};
      }
    } catch { /* A screen without a selection has no chip. */ }
    return null;
  }

  let chipsKey = '';
  function renderChips() {
    const selection = currentSelection();
    view.selection = selection;
    const canPin = view.phase !== 'off' && view.phase !== 'stopped';
    const pinnable = Boolean(selection || pinnableText());
    // Workspace activity re-renders on every selection change; the chips are
    // rebuilt only when what they show changes, so focus stays on them.
    const key = JSON.stringify([selection, canPin, pinnable, view.pins.map(entry => [entry.label, entry.bytes, entry.truncated])]);
    if (key === chipsKey) return;
    chipsKey = key;
    const focusKey = focusKeyIn(chips);
    chips.replaceChildren();
    if (selection) {
      const chip = element('span', 'agent-chip');
      chip.title = selection.identifiers;
      chip.append(element('span', 'agent-chip-kind', selection.kind), element('span', 'agent-chip-label', selection.label || selection.key));
      chips.append(chip);
    }
    if (pinnable) {
      const pin = button('agent-pin', 'Pin', onPin, 'Pin the selection or excerpt into this turn');
      pin.id = 'agent-pin';
      pin.dataset.focusKey = 'pin';
      pin.disabled = !canPin;
      chips.append(pin);
    }
    view.pins.forEach((entry, index) => {
      const chip = element('span', 'agent-chip agent-chip-pinned');
      chip.append(element('span', 'agent-chip-kind', 'pinned'), element('span', 'agent-chip-label',
        `${entry.label} · ${formatBytes(entry.bytes)}${entry.truncated ? ' (cut)' : ''}`));
      chip.title = entry.truncated ? `First ${formatBytes(entry.bytes)} of ${formatBytes(entry.totalBytes)}; the rest is not sent.` : entry.label;
      const remove = button('agent-chip-remove', '', () => { view.pins.splice(view.pins.indexOf(entry), 1); renderComposer(); input.focus(); }, `Remove pin ${entry.label}`);
      remove.dataset.focusKey = `remove:${index}`;
      remove.append(icon('close'));
      chip.append(remove);
      chips.append(chip);
    });
    chips.hidden = !chips.childElementCount;
    restoreFocus(chips, focusKey);
  }

  function pinnableText() {
    const selected = getSelection?.();
    const text = selected?.toString().trim() ?? '';
    if (!text) return '';
    const anchor = selected.anchorNode?.nodeType === 1 ? selected.anchorNode : selected.anchorNode?.parentElement;
    return anchor?.closest?.('.main') ? text : '';
  }

  async function onPin() {
    const total = () => view.pins.reduce((sum, item) => sum + item.bytes, 0);
    let text = pinnableText(), label = view.selection?.label || 'Selection';
    if (text) label = `Selection in ${label}`;
    else {
      const source = view.selection?.kind === 'script' ? selectedSource() : null;
      if (!source?.artifact_id) { appendNotice('Select text in the workspace to pin it.'); return; }
      const response = await fetch(`/api/artifacts/${encodeURIComponent(source.artifact_id)}/content?limit=${PIN_BYTES}`, {cache: 'no-store'}).catch(() => null);
      if (!response?.ok) { appendNotice('That artifact could not be read for pinning.'); return; }
      text = new TextDecoder('utf-8', {fatal: false}).decode(await response.arrayBuffer());
      label = `First bytes of ${label}`;
    }
    const clipped = clipPin(text);
    const bytes = utf8Bytes(clipped.text);
    if (total() + bytes > PIN_TOTAL_BYTES) { appendNotice(`This turn already has ${formatBytes(total())} pinned. Remove a pin first.`); return; }
    view.pins.push({label: label.slice(0, 120), text: clipped.text, bytes, totalBytes: clipped.totalBytes, truncated: clipped.truncated});
    renderComposer();
    input.focus();
  }

  // While the agent is off there is no conversation to add a row to: the
  // setup state shows the line instead, beside the provider it is about.
  function appendNotice(text, kind = 'info') {
    if (view.phase === 'off' && !runtime) {
      view.setupNotice = {text, kind};
      render();
      return;
    }
    transcript.add({id: rowId('n'), role: 'notice', text, kind});
    if (view.follow) log.scrollTop = 0;
    render();
    scheduleTranscript();
  }

  function renderInlineTokens(parent, tokens) {
    for (const token of tokens) {
      if (token.type === 'text') parent.append(document.createTextNode(token.text));
      else if (token.type === 'code') parent.append(element('code', 'agent-inline-code', token.text));
      else if (token.type === 'strong') parent.append(element('strong', '', token.text));
      else if (token.type === 'em') parent.append(element('em', '', token.text));
      else parent.append(citationNode(token));
    }
  }

  function citationNode(token) {
    const key = citeKey(token.fields);
    const known = citeChecks.get(key);
    if (known?.status === 'verified') {
      const link = button('agent-cite', citeLabel(token.fields), () => openCitation(token.fields, known), `Open evidence ${citeLabel(token.fields)}`);
      link.title = 'Verified against this session\'s evidence';
      return link;
    }
    // A pending or unverified citation updates in place when its check ends, so
    // a check finishing never rebuilds the rows under the pointer.
    const placeholder = citationPlaceholder(token, key, known);
    placeholder.dataset.citeKey = key;
    placeholder.dataset.citeFields = JSON.stringify(token.fields);
    placeholder.dataset.citeRaw = token.raw;
    return placeholder;
  }

  function citationPlaceholder(token, key, known) {
    if (!known) { citeChecks.set(key, {status: 'checking'}); verify(token.fields, key); }
    const plain = element('span', 'agent-cite-plain');
    plain.textContent = token.raw;
    if (known?.status === 'unverified') {
      plain.title = `Not verified: ${known.reason}. This identifier was not found in the evidence.`;
      const note = element('span', 'agent-cite-note', 'not verified');
      const wrap = element('span');
      wrap.append(plain, note);
      return wrap;
    }
    return plain;
  }

  async function verify(fields, key) {
    const result = await verifyCitation(fields, {
      artifacts: state.artifacts ?? [], events: state.events ?? [],
      fetchArtifact: async (session, artifact) => {
        const response = await fetch(`/api/artifacts?session_id=${session}&artifact_id=${artifact}&limit=2`, {cache: 'no-store'});
        return response.ok ? (await response.json()).artifacts ?? [] : [];
      },
      fetchEvents: async (session, process) => {
        const response = await fetch(`/api/events?session_id=${session}&process_id=${process}&limit=5000`, {cache: 'no-store'});
        return response.ok ? (await response.json()).events ?? [] : [];
      },
    }).catch(() => ({status: 'unverified', reason: 'could not be checked'}));
    citeChecks.set(key, result);
    for (const node of rowsHost.querySelectorAll('[data-cite-key]')) {
      if (node.dataset.citeKey !== key) continue;
      node.replaceWith(citationNode({type: 'cite', fields: JSON.parse(node.dataset.citeFields), raw: node.dataset.citeRaw}));
    }
  }

  function openCitation(fields, known) {
    const notice = 'Opened from a model citation. The identifier is exact; the claim around it is the model\'s.';
    if (known.kind === 'artifact') {
      const identity = investigationArtifactIdentity(known.artifact);
      const range = fields.offset !== undefined && known.artifact.kind === 'javascript'
        ? {start: Number(fields.offset), end: Math.min(known.artifact.byte_size, Number(fields.offset) + 1)} : undefined;
      if (known.artifact.kind === 'request_body') {
        const owner = state.requests.find(item => item.requestBodyArtifactId === known.artifact.artifact_id);
        if (owner) { openInvestigation({kind: 'request', identity: investigationRequestIdentity(owner), relation: notice}); return; }
      }
      openInvestigation({kind: 'artifact', identity, range, relation: notice});
      return;
    }
    const identity = investigationEventIdentity(known.event);
    const request = state.requests.find(item => investigationSame(investigationEventIdentity(requestTraceRoot(item)), identity));
    if (request) { openInvestigation({kind: 'request', identity: investigationRequestIdentity(request), relation: notice}); return; }
    if (fingerprintEventsFromEvents([known.event]).length) {
      state.selectedSignalEventKey = signalEventKey(known.event);
      showScreen('signals');
      renderFingerprintActivity();
      investigationNotice(notice);
      return;
    }
    if (/^(wasm|vm|native_guest|guest)/i.test(String(known.event.type ?? known.event.category ?? ''))) {
      showScreen('vm');
      investigationNotice(`${notice} This event opens the VM workspace; exact VM rows are selected there.`);
      return;
    }
    showScreen('evidence');
    evidenceWorkspace.openEvent(`${fields.session}:${fields.process}:${fields.sequence}`);
    investigationNotice(notice);
  }

  // One element per block, so a streamed reply can keep the blocks it already drew (mountRow).
  function renderBlock(parent, block) {
    if (block.type === 'paragraph') { const node = element('p', 'agent-para'); renderInlineTokens(node, block.inline); parent.append(node); }
    else if (block.type === 'heading') { const node = element('p', 'agent-para agent-heading'); renderInlineTokens(node, block.inline); parent.append(node); }
    else if (block.type === 'list') {
      const list = element(block.ordered ? 'ol' : 'ul', 'agent-list');
      for (const item of block.items) { const li = element('li'); renderInlineTokens(li, item); list.append(li); }
      parent.append(list);
    } else parent.append(codeBlock(block));
  }

  // Fenced code and tool JSON take the shared code view's lexer and colors
  // (code_view.js). Every token is a text node, so model output stays inert.
  function fenceSyntax(lang) {
    const name = String(lang ?? '').toLowerCase();
    if (/^(?:js|javascript|jsx|mjs|cjs)$/.test(name)) return codeViewSyntax('javascript');
    if (name === 'json') return codeViewSyntax('json');
    if (name === 'css') return {kind: 'plain', mime_type: 'text/css'};
    if (/^(?:html|xml|svg)$/.test(name)) return {kind: 'plain', mime_type: 'text/html'};
    return codeViewSyntax('text');
  }

  function codeText(className, text, syntax) {
    return codeViewColor(element('pre', className), text, syntax);
  }

  function toolText(text) {
    return codeText('agent-tool-pre', text, codeViewSyntax(/^\s*[[{]/.test(text) ? 'json' : 'text'));
  }

  function codeBlock(block) {
    const wrap = element('div', 'agent-code');
    const header = element('div', 'agent-code-head');
    header.append(element('span', 'agent-code-lang', block.lang || 'text'));
    const copy = button('agent-code-copy', 'Copy', async () => {
      await navigator.clipboard.writeText(block.text).catch(() => {});
      copy.textContent = 'Copied';
      copy.classList.add('copied');
    }, 'Copy code');
    header.append(copy);
    const pre = codeText('agent-code-body', block.text, fenceSyntax(block.lang));
    wrap.append(header, pre);
    return wrap;
  }

  function renderRow(row) {
    const node = element('div', `agent-row agent-row-${row.role}`);
    node.dataset.rowId = row.id;
    if (row.role === 'user') {
      node.append(element('div', 'agent-user-bubble', row.text));
      if (row.pins?.length) {
        const pins = element('div', 'agent-row-pins');
        for (const pin of row.pins) pins.append(element('span', 'agent-chip agent-chip-pinned', `pinned · ${pin.label} · ${formatBytes(pin.bytes)}${pin.truncated ? ' (cut)' : ''}`));
        node.append(pins);
      }
    } else if (row.role === 'tool') {
      node.append(toolRow(row));
    } else if (row.role === 'approval') {
      node.append(approvalRow(row));
    } else if (row.role !== 'assistant') {
      node.classList.toggle('agent-row-error', row.kind === 'error');
      const box = element('div', 'agent-notice');
      if (row.kind === 'error') box.append(icon('error', 'agent-notice-icon'));
      box.append(element('span', 'agent-notice-text', row.text));
      node.append(box);
    }
    // An assistant row's blocks are drawn by mountRow, which keeps them across streamed deltas.
    return node;
  }

  const domId = (prefix, value) => `${prefix}-${String(value).replace(/[^\w-]/g, '_').slice(0, 80)}`;
  const TOOL_STATES = {running: 'Running', done: 'Done', error: 'Failed', denied: 'Denied', refused: 'Refused'};

  // One line per call: state, tool, arguments and result size. The full
  // arguments and result stay one click or key press away and are drawn only
  // while open, so a long log keeps no hidden result nodes.
  function toolRow(row) {
    const wrap = element('div', `agent-tool agent-tool-${row.state}`);
    const detailId = domId('agent-tool', row.id);
    const summary = element('button', 'agent-tool-summary');
    summary.type = 'button';
    summary.dataset.focusKey = 'summary';
    summary.setAttribute('aria-expanded', String(Boolean(row.openTool)));
    summary.setAttribute('aria-controls', detailId);
    const mark = row.state === 'running' ? element('span', 'agent-tool-mark agent-spinner')
      : icon({done: 'check', error: 'error'}[row.state] ?? 'denied', 'agent-tool-mark');
    summary.append(mark, element('span', 'agent-tool-name', row.name));
    const args = compactArguments(row.arguments);
    if (args) summary.append(element('span', 'agent-tool-args', args));
    const size = row.resultBytes ? formatBytes(row.resultBytes) : '';
    const state = row.state === 'done' ? size || 'Done' : row.state === 'error' && size ? `Failed · ${size}` : TOOL_STATES[row.state] ?? row.state;
    summary.append(element('span', `agent-tool-state agent-tool-state-${row.state}`, state), icon('caret', 'agent-tool-caret'));
    summary.title = `${TOOL_STATES[row.state] ?? row.state}. ${row.openTool ? 'Hide' : 'Show'} the arguments and the result sent to the provider.`;
    summary.addEventListener('click', () => {
      row.openTool = !row.openTool;
      summary.setAttribute('aria-expanded', String(row.openTool));
      summary.title = `${TOOL_STATES[row.state] ?? row.state}. ${row.openTool ? 'Hide' : 'Show'} the arguments and the result sent to the provider.`;
      if (row.openTool) wrap.append(toolDetail(row, detailId));
      else wrap.querySelector('.agent-tool-detail')?.remove();
      // This node already shows the new state, so the next frame keeps it
      // (and the focus on it) instead of drawing the row again.
      const kept = mountedRows.get(row.id);
      if (kept) kept.signature = rowSignature(row);
      heights.delete(row.id);
      scheduleTranscript(true);
    });
    wrap.append(summary);
    if (row.openTool) wrap.append(toolDetail(row, detailId));
    return wrap;
  }

  function toolDetail(row, id) {
    const area = element('div', 'agent-tool-detail');
    area.id = id;
    area.append(element('div', 'agent-tool-label', 'Arguments'), toolText(row.arguments || '{}'));
    area.append(element('div', 'agent-tool-label', `Result sent to the provider${row.resultBytes ? ` · ${formatBytes(row.resultBytes)}` : ''}`));
    const result = toolText(row.result ?? (row.state === 'running' ? 'Running' : 'No result'));
    // The block is bounded and scrolls; it takes focus so keys can scroll it.
    result.tabIndex = 0;
    result.setAttribute('role', 'region');
    result.setAttribute('aria-label', `Result of ${row.name}`);
    area.append(result);
    return area;
  }

  function compactArguments(raw) {
    if (!raw) return '';
    try {
      const value = JSON.parse(raw);
      return Object.entries(value).map(([key, item]) => `${key}=${typeof item === 'string' ? item : JSON.stringify(item)}`).join(' ').slice(0, 160);
    } catch { return ''; }
  }

  function approvalRow(row) {
    const card = element('div', `agent-approval agent-approval-${row.state}`);
    const titleId = domId('agent-approval', row.callId);
    card.setAttribute('role', 'group');
    card.setAttribute('aria-labelledby', titleId);
    const top = element('div', 'agent-approval-head');
    const title = element('div', 'agent-approval-title', `Allow ${row.name}?`);
    title.id = titleId;
    top.append(icon('shield', 'agent-approval-icon'), title);
    card.append(top);
    if (row.state === 'pending') {
      card.tabIndex = -1;
      card.dataset.focusKey = 'card';
      card.append(element('p', 'agent-approval-text', 'The agent asks to run this action once. Read-only calls run without asking.'));
    }
    card.append(toolText(row.arguments || '{}'));
    if (row.state === 'pending') {
      const actions = element('div', 'agent-approval-actions');
      const deny = button('agent-button', 'Deny', () => decide(row, false));
      deny.dataset.focusKey = 'deny';
      const allow = button('agent-button agent-button-approve', 'Allow once', () => decide(row, true));
      allow.dataset.approve = row.callId;
      allow.dataset.focusKey = 'allow';
      actions.append(deny, allow);
      card.append(actions);
    } else {
      const decided = element('div', 'agent-approval-state');
      decided.append(icon(row.state === 'allowed' ? 'check' : 'denied'), element('span', '', row.state === 'allowed' ? 'Allowed once' : 'Denied'));
      card.append(decided);
    }
    return card;
  }

  async function decide(row, allow) {
    transcript.update(row.id, {state: allow ? 'allowed' : 'denied'});
    scheduleTranscript(true);
    if (!runtime?.decide(row.callId, allow)) appendNotice('This request is no longer waiting for a decision.', 'error');
  }

  function scheduleRender() { if (!view.open || framePending) return; framePending = true; requestAnimationFrame(() => { framePending = false; render(); }); }
  function scheduleTranscript(force = false) {
    if (!view.open) return;
    frameTranscript = true;
    if (force) lastWindow = '';
    scheduleRender();
  }

  // Mounts only the rows near the viewport once the log is long, keeps a
  // focused row mounted, and reuses nothing else so detached rows can be freed.
  function renderTranscript() {
    const rows = transcript.rows();
    const stats = transcript.stats();
    const headNote = (stats.droppedRows || view.olderAvailable) ? olderBanner(stats) : null;
    if (!rows.length) { lastWindow = ''; mountedRows.clear(); rowsHost.replaceChildren(); spacerTop.style.height = spacerBottom.style.height = '0'; return; }
    const windowed = rows.length > WINDOW_THRESHOLD;
    const viewport = log.clientHeight || 600;
    const estimates = rows.map(row => heights.get(row.id) ?? ESTIMATED_ROW_HEIGHT);
    let total = 0;
    const offsets = estimates.map(height => { const at = total; total += height; return at; });
    let first = 0, last = rows.length - 1;
    if (windowed) {
      const top = view.follow ? Math.max(0, total - viewport) : log.scrollTop;
      first = offsets.findIndex((offset, index) => offset + estimates[index] >= top - OVERSCAN_PIXELS);
      if (first < 0) first = 0;
      const bottom = top + viewport + OVERSCAN_PIXELS;
      last = offsets.findIndex(offset => offset > bottom);
      last = last < 0 ? rows.length - 1 : last;
      const focused = document.activeElement?.closest?.('.agent-row')?.dataset.rowId;
      if (focused) {
        const index = rows.findIndex(row => row.id === focused);
        // A focused row that left the byte budget is gone too; its focus goes to the log.
        if (index >= 0 && index >= first - FOCUS_KEEP_ROWS && index <= last + FOCUS_KEEP_ROWS) { first = Math.min(first, index); last = Math.max(last, index); }
        else log.focus({preventScroll: true});
      }
    }
    const key = `${first}:${last}:${rows.length}:${rows.slice(first, last + 1).map(row => row.text?.length ?? 0).join(',')}:${stats.droppedRows}:${view.olderAvailable}`;
    if (key !== lastWindow) {
      lastWindow = key;
      const nodes = headNote ? [headNote] : [];
      const shown = new Set();
      for (let index = first; index <= last; index += 1) {
        nodes.push(mountRow(rows[index]));
        shown.add(rows[index].id);
      }
      for (const id of mountedRows.keys()) if (!shown.has(id)) mountedRows.delete(id);
      // Nodes already in place stay attached; only new or changed rows go in.
      const wanted = new Set(nodes);
      for (const child of [...rowsHost.children]) if (!wanted.has(child)) child.remove();
      let at = rowsHost.firstChild;
      for (const node of nodes) {
        if (node === at) at = at.nextSibling;
        else rowsHost.insertBefore(node, at);
      }
      // A row redrawn while it held focus gives it to the same control, or to
      // the composer when that control is gone (a decided approval).
      for (const {node, key: focusKey} of refocus.splice(0)) {
        if (!restoreFocus(node, focusKey)) (input.disabled ? log : input).focus({preventScroll: true});
      }
    }
    refocus.length = 0;
    // A new approval takes focus unless the researcher is working elsewhere.
    if (approvalFocus) {
      const card = [...rowsHost.querySelectorAll('[data-row-id]')].find(node => node.dataset.rowId === approvalFocus)?.querySelector('.agent-approval');
      const active = document.activeElement;
      if (card && (!active || active === document.body || dock.contains(active))) card.focus();
      if (card) approvalFocus = null;
    }
    spacerTop.style.height = windowed ? `${offsets[first]}px` : '0';
    spacerBottom.style.height = windowed ? `${Math.max(0, total - offsets[last] - estimates[last])}px` : '0';
    for (const node of rowsHost.querySelectorAll('.agent-row')) {
      const height = node.getBoundingClientRect().height;
      if (height) heights.set(node.dataset.rowId, height);
    }
    // Code blocks and wrapped text can settle after this frame; follow once more.
    if (view.follow) { log.scrollTop = log.scrollHeight; requestAnimationFrame(() => { if (view.follow) log.scrollTop = log.scrollHeight; }); }
  }

  // Everything renderRow draws from. A row whose signature is unchanged keeps
  // its node, so a streamed delta rebuilds only its own row: rebuilding every
  // mounted row took about 100 ms a frame with 20 colored code blocks in view.
  // Citation checks update mounted nodes in place (verify).
  function rowSignature(row) {
    return JSON.stringify([row.role, row.kind, row.text, row.name, row.arguments, row.state, row.result ?? null, row.resultBytes,
      Boolean(row.openTool), row.callId, row.pins?.map(pin => [pin.label, pin.bytes, pin.truncated]) ?? null]);
  }

  const refocus = [];
  function mountRow(row) {
    const signature = rowSignature(row), kept = mountedRows.get(row.id);
    if (kept?.signature === signature) return kept.node;
    if (row.role !== 'assistant') {
      const node = renderRow(row);
      const focusKey = kept ? focusKeyIn(kept.node) : undefined;
      if (focusKey !== undefined) refocus.push({node, key: focusKey});
      mountedRows.set(row.id, {signature, node});
      return node;
    }
    // A streamed reply keeps its unchanged leading blocks and redraws from the
    // first changed one: redrawing ten finished code blocks on every delta
    // took about 60 ms a frame.
    const node = kept?.blocks ? kept.node : renderRow(row);
    const blocks = parseMarkdown(row.text), keys = blocks.map(block => JSON.stringify(block)), before = kept?.blocks ?? [];
    let same = 0;
    while (same < keys.length && keys[same] === before[same]) same += 1;
    while (node.children.length > same) node.lastElementChild.remove();
    for (const block of blocks.slice(same)) renderBlock(node, block);
    mountedRows.set(row.id, {signature, node, blocks: keys});
    return node;
  }

  function olderBanner(stats) {
    const banner = element('div', 'agent-row agent-older');
    const text = stats.droppedRows ? `${stats.droppedRows} earlier row${stats.droppedRows === 1 ? '' : 's'} left this view to stay under ${formatBytes(stats.budget)}.` : 'Earlier rows are in the local transcript.';
    banner.append(element('span', '', text), view.olderAvailable || stats.droppedRows
      ? button('agent-button agent-button-small', 'Load earlier', loadOlder) : element('span'));
    return banner;
  }

  async function loadOlder() {
    const response = await call('transcript', {before: view.olderBefore ?? undefined}).catch(() => null);
    if (!response) return;
    const empty = !transcript.rows().length;
    ingestRows(response.rows ?? []);
    // After a new conversation the model has none of these rows; say so as turning on does.
    if (empty && response.rows?.length) transcript.add({id: rowId('n'), role: 'notice', text: 'Earlier rows from this session. They are shown here and not resent to the model.'});
    view.olderBefore = response.before;
    view.olderAvailable = response.before !== null && response.before !== undefined;
    scheduleTranscript(true);
  }

  // Rows from the file are shown, never resent: the model's history is native.
  function ingestRows(rows) {
    const merged = [];
    for (const row of rows) {
      if (row.role === 'assistant') {
        const previous = merged.at(-1);
        if (previous?.role === 'assistant' && previous.id === row.rowId) previous.text += row.delta;
        else merged.push({id: row.rowId || rowId('a'), role: 'assistant', text: row.delta ?? '', restored: true});
      } else if (row.role === 'user') merged.push({id: rowId('u'), role: 'user', text: row.text ?? '', pins: row.pins, restored: true});
      else if (row.role === 'tool') merged.push({...row, id: row.id || rowId('t'), restored: true});
      else merged.push({id: rowId('n'), role: 'notice', text: row.text ?? '', kind: row.kind, restored: true});
    }
    transcript.prepend(merged);
  }

  function render() {
    renderHead();
    renderMenu();
    renderSheet();
    renderSurface();
    renderComposer();
    renderPicker();
    if (frameTranscript) { frameTranscript = false; renderTranscript(); }
  }

  log.addEventListener('scroll', () => {
    const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 32;
    view.follow = atBottom;
    if (transcript.rows().length > WINDOW_THRESHOLD) scheduleTranscript();
  });
  input.addEventListener('input', () => {
    input.style.height = 'auto';
    input.style.height = `${Math.min(input.scrollHeight, 168)}px`;
    send.disabled = view.phase === 'off' || (!view.running && !input.value.trim());
  });
  input.addEventListener('keydown', event => {
    // Return sends; while a turn runs it does nothing, so a stray Return never stops it.
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); if (!view.running) onSend(); }
  });

  function selectionContext() {
    return view.selection ? `kind=${view.selection.kind} ${view.selection.identifiers}` : '';
  }

  async function sessionKey() {
    const response = await fetch('/api/session/context', {cache: 'no-store'});
    if (!response.ok) throw new Error('The session identity could not be read.');
    const instance = (await response.json()).instance_id;
    if (typeof instance !== 'string' || !instance) throw new Error('The session identity could not be read.');
    return instance;
  }

  async function refreshStatus() {
    try {
      view.status = await call('status');
      syncEngine(view.status.engine);
      view.surfaceError = '';
      if (view.status.available) {
        if (authFor() === 'subscription' && loopFor() === 'cli' && subscriptionOf(view.provider).signedIn === undefined) checkSubscription();
        if (credential().ready) refreshModels();
      }
    } catch (error) {
      view.status = {available: false, reason: 'offline-workspace'};
      view.surfaceError = bridgeFailure(error);
    }
    scheduleRender();
  }

  async function refreshModels() {
    const provider = view.provider, auth = authFor(provider), key = modelKey(provider);
    if (view.models[key]) return;
    try {
      const result = await call('models', {provider, auth});
      view.models[key] = result.models;
      if (!view.model[key]) view.model[key] = result.models.includes(result.defaultModel) ? result.defaultModel : result.models[0];
      scheduleRender();
    } catch { /* The default model remains selectable. */ }
  }

  // A CLI is asked whether it is signed in only when its subscription is chosen.
  async function checkSubscription(id = view.provider) {
    if (view.checking[id]) return;
    view.checking[id] = true;
    scheduleRender();
    try {
      view.subs[id] = await call('subscriptionStatus', {provider: id});
    } catch (error) {
      view.subs[id] = {signedIn: false, reason: bridgeFailure(error)};
    } finally {
      view.checking[id] = false;
    }
    if (id === view.provider && credential(id).ready) refreshModels();
    scheduleRender();
  }

  // The running state belongs to the graph in this page, not to native status.
  function syncEngine(engine) {
    if (!engine) return;
    view.phase = engine.phase;
    if (engine.phase !== 'off' && engine.provider) view.provider = engine.provider;
    if (engine.phase !== 'off' && engine.provider && engine.auth) view.auth[engine.provider] = engine.auth;
  }

  // The LangGraph bundle loads the first time the agent is turned on in this
  // document, so a closed or never-used dock parses none of it.
  // One bundle per provider, so a session parses only its own SDK.
  const runtimeModules = {};
  let runtime = null, fetchListener = null;
  function loadRuntime(provider) {
    const loaded = globalThis.RebAgentRuntimes?.[provider];
    if (loaded) return Promise.resolve(loaded);
    runtimeModules[provider] ??= new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = `agent_runtime_${provider}.js`;
      script.onload = () => globalThis.RebAgentRuntimes?.[provider] ? resolve(globalThis.RebAgentRuntimes[provider]) : reject(new Error('The agent runtime did not load.'));
      script.onerror = () => { delete runtimeModules[provider]; script.remove(); reject(new Error('This build does not include the agent runtime.')); };
      document.head.append(script);
    });
    return runtimeModules[provider];
  }

  // What the graph shows is also what the local transcript keeps.
  function persist(row) { call('transcriptAppend', {row}).catch(() => {}); }
  function handleRuntimeEvent(event) {
    if (event.type === 'tool' && event.state !== 'running') {
      persist({role: 'tool', id: event.id, turnId: event.turnId, name: event.name, arguments: event.arguments, state: event.state,
        result: event.result, isError: event.isError, resultBytes: event.resultBytes});
    } else if (event.type === 'assistantDone') persist({role: 'assistant', rowId: event.rowId, turnId: event.turnId, delta: event.text});
    else if (event.type === 'notice') persist({role: 'notice', text: event.text});
    else if (event.type === 'error') persist({role: 'notice', text: event.message, kind: 'error'});
    else if (event.type === 'turnEnd') {
      view.running = false;
      call('turn', {running: false}).catch(() => {});
      render();
    }
    handleEvent(event);
  }

  // The CLI loops run natively; this keeps the panel's runtime interface.
  // Rows arrive through __rebAgentEvent marked `cli`.
  function createCliRuntime() {
    const waiting = new Set();
    let running = false;
    return {
      get running() { return running; },
      send({turnId, text, context, pins}) {
        running = true;
        return call('cliSend', {turnId, text, context, pins}).catch(error => {
          receiveCli({type: 'error', turnId, message: bridgeFailure(error), cli: true});
          receiveCli({type: 'turnEnd', turnId, stopped: false, cli: true});
        });
      },
      observe(event) {
        if (event.type === 'approval') waiting.add(event.callId);
        if (event.type === 'turnEnd') { waiting.clear(); running = false; }
      },
      decide(callId, allow) {
        if (!waiting.delete(callId)) return false;
        call('cliDecide', {callId, allow}).catch(() => {});
        return true;
      },
      cancel() { call('cliCancel').catch(() => {}); },
      dispose() { waiting.clear(); running = false; },
    };
  }

  function receiveCli(event) {
    runtime?.observe?.(event);
    handleRuntimeEvent(event);
  }

  // The provider and payment turning on would use. A CLI is asked whether it
  // is signed in only when its subscription is chosen.
  function setChoice(id, mode) {
    if (view.phase !== 'off') return;
    if (view.provider !== id) {
      view.provider = id;
      view.setupNotice = '';
      try { localStorage.setItem('origin-trace.agent.provider', id); } catch { /* Optional. */ }
    }
    if (mode && providerInfo(id)?.supportsKey !== false && view.auth[id] !== mode) {
      view.auth[id] = mode;
      view.setupNotice = '';
      try { localStorage.setItem('origin-trace.agent.auth', JSON.stringify(view.auth)); } catch { /* Optional. */ }
    }
    if (authFor(id) === 'subscription' && loopFor(id) === 'cli' && subscriptionOf(id).signedIn === undefined) checkSubscription(id);
    if (credential(id).ready) refreshModels();
    render();
  }
  const chooseProvider = id => setChoice(id);
  const chooseAuth = mode => setChoice(view.provider, mode);

  const accountActions = {
    signIn: async () => {
      view.signingIn = true;
      render();
      try {
        view.subs.chatgpt = await call('subscriptionSignIn', {provider: 'chatgpt'});
        await refreshStatus();
        delete view.subs.chatgpt;
        refreshModels();
      } catch (error) {
        appendNotice(bridgeFailure(error), 'error');
      } finally {
        view.signingIn = false;
        render();
      }
    },
    cancelSignIn: () => { call('subscriptionCancel', {provider: 'chatgpt'}).catch(() => {}); },
    check: () => checkSubscription(),
  };

  async function signOut() {
    try {
      const result = await call('subscriptionSignOut', {provider: 'chatgpt'});
      if (result?.notice) appendNotice(result.notice);
      delete view.subs.chatgpt;
      await refreshStatus();
    } catch (error) { appendNotice(bridgeFailure(error), 'error'); }
  }

  async function addKey() {
    try {
      await call('setKey', {provider: view.provider});
      await refreshStatus();
      await refreshModels();
    } catch (error) { appendNotice(bridgeFailure(error), 'error'); }
    focusDefault();
  }

  async function removeKey() {
    // The native app shows the confirmation; the web view has no dialog surface.
    try { await call('clearKey', {provider: view.provider}); await refreshStatus(); }
    catch (error) { appendNotice(bridgeFailure(error), 'error'); }
  }

  // Turning on always passes the disclosure for the selected provider and payment.
  function requestConsent() {
    if (view.phase !== 'off' || view.turning || !view.status?.available) return;
    const state = credential();
    if (!state.ready) { view.setupNotice = {text: state.text || 'This provider is not ready yet.', kind: 'error'}; render(); return; }
    view.setupNotice = '';
    view.consenting = true;
    render();
    document.getElementById('agent-consent-accept')?.focus();
  }

  // Enables native for one session and builds the loop that drives it.
  async function startAgent({provider, auth, model, effects, key}) {
    view.sessionKey = key;
    const result = await call('enable', {provider, auth, model, effects, sessionKey: key});
    if ((result.engine?.loop ?? loopFor(provider, auth)) === 'cli') {
      runtime = createCliRuntime();
    } else {
      let api;
      try { api = await loadRuntime(provider); }
      catch (error) { view.status = await call('disable'); syncEngine(view.status.engine); throw error; }
      runtime = api.createAgentRuntime({
        bridge: {call, onFetchEvent: listener => { fetchListener = listener; }},
        provider, model: result.engine?.model ?? model, tools: result.tools ?? [], emit: handleRuntimeEvent,
      });
    }
    view.status = result;
    syncEngine(result.engine);
  }

  async function confirmConsent() {
    view.consenting = false;
    view.turning = true;
    view.setupNotice = '';
    render();
    try {
      const key = await sessionKey();
      await startAgent({provider: view.provider, auth: authFor(), model: view.model[modelKey()] ?? '', effects: view.effects, key});
      const page = await call('transcript', {});
      view.olderBefore = page.before ?? null;
      view.olderAvailable = view.olderBefore !== null;
      const restored = page.rows ?? [];
      transcript.clear();
      if (restored.length) {
        ingestRows(restored);
        transcript.add({id: rowId('n'), role: 'notice', text: 'Earlier rows from this session. They are shown here and not resent to the model.'});
      }
      await call('panel', {visible: true});
    } catch (error) {
      appendNotice(bridgeFailure(error), 'error');
    } finally {
      view.turning = false;
      scheduleTranscript(true);
      render();
      focusDefault();
    }
  }

  // A new conversation is the same session, provider, model and permission
  // the researcher already agreed to, started again with an empty history.
  // Earlier rows stay in the local transcript unless it is cleared.
  async function restartConversation({clear = false} = {}) {
    if (view.phase === 'off' || view.running || view.turning) return;
    const engine = view.status?.engine ?? {};
    const choice = {provider: engine.provider ?? view.provider, auth: engine.auth ?? authFor(), model: engine.model ?? '', effects: Boolean(engine.effects)};
    const had = transcript.rows().length > 0 || view.olderAvailable;
    view.turning = true;
    render();
    try {
      const key = await sessionKey();
      if (key !== view.sessionKey) {
        // Consent was for that session; a different one asks again.
        view.turning = false;
        await turnOff();
        appendNotice('The capture session changed. Turn the agent on again for this one.');
        return;
      }
      if (clear) await call('clearTranscript');
      runtime?.dispose();
      runtime = null;
      fetchListener = null;
      await startAgent({...choice, key});
      transcript.clear();
      heights.clear();
      citeChecks.clear();
      lastWindow = '';
      view.pins = [];
      view.usage = null;
      view.olderBefore = null;
      view.olderAvailable = !clear && had;
      await call('panel', {visible: true});
    } catch (error) {
      appendNotice(bridgeFailure(error), 'error');
    } finally {
      view.turning = false;
      scheduleTranscript(true);
      render();
    }
  }

  // Choosing another provider, payment or model while on is the same as
  // switching off by hand, choosing, and turning on again behind the disclosure.
  async function switchTo(id, mode, model) {
    if (view.running || view.turning) return;
    closePicker(false);
    await turnOff();
    setChoice(id, mode);
    if (model) view.model[modelKey(id)] = model;
    if (credential().ready) requestConsent();
    focusDefault();
  }

  async function turnOff() {
    runtime?.dispose();
    runtime = null;
    fetchListener = null;
    view.running = false;
    try { const result = await call('disable'); view.status = result; syncEngine(result.engine); }
    catch (error) { appendNotice(bridgeFailure(error), 'error'); }
    view.consenting = false;
    view.pins = [];
    view.olderAvailable = false;
    transcript.clear();
    heights.clear();
    citeChecks.clear();
    lastWindow = '';
    closeMenu(false);
    closePicker(false);
    closeSheet(false);
    render();
    scheduleTranscript(true);
  }

  // Where focus goes when a state appears: the composer when on, otherwise the
  // next decision in the centered state.
  let autoFocused = null;
  function focusDefault() {
    if (!view.open) return;
    const turnOn = document.getElementById('agent-turn-on');
    const target = !composer.hidden && !input.disabled ? input
      : document.getElementById('agent-consent-accept')
      ?? (turnOn && !turnOn.disabled ? turnOn : null)
      ?? document.getElementById('agent-account-action')
      ?? surface.querySelector('[data-provider][aria-pressed="true"]')
      ?? surface.querySelector('button')
      ?? close;
    target.focus();
    autoFocused = target;
  }

  async function onSend() {
    if (view.running) { runtime?.cancel(); return; }
    const text = input.value.trim();
    if (!text || view.phase === 'off' || !runtime) return;
    const turnId = rowId('turn');
    const pins = view.pins.map(item => ({label: item.label, text: item.text, truncated: item.truncated, totalBytes: item.totalBytes}));
    const context = selectionContext();
    // Composer text and pins as the panel limits them, with room for encoding.
    if (utf8Bytes(text) + utf8Bytes(context) + pins.reduce((total, pin) => total + utf8Bytes(pin.text), 0) > 1024 * 1024) {
      appendNotice('This turn is larger than 1 MiB. Remove a pin or shorten the question.', 'error');
      return;
    }
    try {
      const pinRows = view.pins.map(item => ({label: item.label, bytes: item.bytes, truncated: item.truncated}));
      view.running = true;
      call('turn', {running: true}).catch(() => {});
      runtime.send({turnId, text, context, pins});
      persist({role: 'user', turnId, text, context, pins: pinRows});
      transcript.add({id: `u-${turnId}`, role: 'user', text, pins: pinRows});
      input.value = '';
      input.style.height = 'auto';
      view.pins = [];
      view.follow = true;
      view.usage = null;
      scheduleTranscript(true);
      render();
    } catch (error) {
      view.running = false;
      appendNotice(bridgeFailure(error), 'error');
    }
  }

  function handleEvent(event) {
    if (event.type === 'fetchChunk' || event.type === 'fetchEnd' || event.type === 'fetchError') { fetchListener?.(event); return; }
    if (event.type === 'assistantDone') return;
    if (event.type === 'status') {
      if (view.status) view.status.engine = event;
      syncEngine(event);
      render();
      return;
    }
    if (event.type === 'text') {
      if (!transcript.get(event.rowId)) transcript.add({id: event.rowId, role: 'assistant', text: ''});
      transcript.appendText(event.rowId, event.delta);
      heights.delete(event.rowId);
      scheduleTranscript();
      return;
    }
    if (event.type === 'tool') {
      const patch = {state: event.state, name: event.name, arguments: event.arguments,
        ...(event.result !== undefined ? {result: event.result, resultBytes: event.resultBytes, isError: event.isError} : {})};
      if (transcript.get(event.id)) transcript.update(event.id, patch);
      else transcript.add({id: event.id, role: 'tool', ...patch});
      scheduleTranscript(true);
      return;
    }
    if (event.type === 'approval') {
      transcript.add({id: `approval-${event.callId}`, role: 'approval', callId: event.callId, name: event.name, arguments: event.arguments, state: 'pending'});
      approvalFocus = `approval-${event.callId}`;
      view.follow = true;
      scheduleTranscript(true);
      return;
    }
    if (event.type === 'notice') { appendNotice(event.text); return; }
    if (event.type === 'error') { appendNotice(event.message, 'error'); return; }
    if (event.type === 'toolServer') { view.surfaceError = event.reason; appendNotice(event.reason, 'error'); return; }
    if (event.type === 'turnEnd') {
      if (event.inputTokens) view.usage = {input: event.inputTokens, output: event.outputTokens};
      scheduleTranscript();
    }
  }
  globalThis.__rebAgentEvent = event => (event?.cli ? receiveCli(event) : handleEvent(event));

  // WebKit keeps a nested grid's auto rows from the old width when only an
  // ancestor track changes, so a Sources toolbar that wraps after the dock (or
  // its divider) narrows it would overlap the code. Measured in the packaged app.
  const sourcesEditor = document.querySelector('.sources-editor');
  let sourcesEditorWidth = 0;
  const recomputeEditorRows = () => {
    if (!sourcesEditor) return;
    sourcesEditor.style.gridTemplateRows = '35px auto minmax(0, 1fr) 28px';
    void sourcesEditor.offsetHeight;
    sourcesEditor.style.removeProperty('grid-template-rows');
  };
  const editorWidthWatch = new ResizeObserver(entries => {
    const width = Math.round(entries.at(-1)?.contentRect.width ?? 0);
    if (!width || width === sourcesEditorWidth) return;
    sourcesEditorWidth = width;
    recomputeEditorRows();
  });

  // Listeners live only while the dock is open.
  const workspaceActivity = () => { if (!framePending) scheduleRender(); };
  // One right-side dock at a time: opening this one closes Cross-references
  // through its own toggle, and Cross-references opening closes this one.
  const xrefsToggle = document.getElementById('xrefs-toggle');
  const otherDock = new MutationObserver(() => { if (workspace.dataset.xrefsOpen === 'true') setOpen(false, {focus: false}); });
  function setOpen(open, {focus = true} = {}) {
    if (view.open === open) return;
    if (open && workspace.dataset.xrefsOpen === 'true') xrefsToggle?.click();
    view.open = open;
    dock.hidden = !open;
    if (open) workspace.dataset.agentDock = 'open'; else delete workspace.dataset.agentDock;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-pressed', String(open));
    if (open) {
      if (sourcesEditor) { sourcesEditorWidth = 0; editorWidthWatch.observe(sourcesEditor); }
      otherDock.observe(workspace, {attributes: true, attributeFilter: ['data-xrefs-open']});
      workspace.addEventListener('pointerup', workspaceActivity);
      workspace.addEventListener('keyup', workspaceActivity);
      document.addEventListener('selectionchange', workspaceActivity);
      view.native = Boolean(nativeBridge());
      if (view.native) { call('panel', {visible: true}).catch(() => {}); refreshStatus(); }
      frameTranscript = true;
      render();
      if (!composer.hidden && !input.disabled) input.focus(); else if (view.status) focusDefault(); else surface.focus();
    } else {
      closeMenu(false);
      closePicker(false);
      closeSheet(false);
      editorWidthWatch.disconnect();
      otherDock.disconnect();
      requestAnimationFrame(recomputeEditorRows);
      workspace.removeEventListener('pointerup', workspaceActivity);
      workspace.removeEventListener('keyup', workspaceActivity);
      document.removeEventListener('selectionchange', workspaceActivity);
      if (view.native) call('panel', {visible: false}).catch(() => {});
      if (focus) toggle.focus();
    }
    window.dispatchEvent(new Event('resize'));
  }

  toggle.addEventListener('click', () => setOpen(!view.open));
  document.addEventListener('keydown', event => {
    if (!(event.metaKey || event.ctrlKey) || !event.shiftKey || event.altKey || event.repeat) return;
    if (event.code === 'KeyA') { event.preventDefault(); setOpen(!view.open); }
  });
  render();
})();
