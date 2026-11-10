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
    usage: null, olderBefore: null, olderAvailable: false, pins: [], selectionKey: '', copied: null,
  };
  const transcript = createTranscriptModel();
  const citeChecks = new Map();
  const heights = new Map();
  let framePending = false, frameTranscript = false, lastWindow = '';
  // The mounted rows by id, with what each was drawn from (rowSignature).
  const mountedRows = new Map();
  try {
    const remembered = localStorage.getItem('origin-trace.agent.provider');
    if (PROVIDERS.some(([id]) => id === remembered)) view.provider = remembered;
    const auth = JSON.parse(localStorage.getItem('origin-trace.agent.auth') ?? '{}');
    for (const [id] of PROVIDERS) if (auth?.[id] === 'key' || auth?.[id] === 'subscription') view.auth[id] = auth[id];
  } catch { /* Preferences are optional. */ }

  dock.replaceChildren();
  const head = element('header', 'agent-head');
  const headTitle = element('strong', 'agent-title', 'Agent');
  const headStats = element('span', 'agent-stats');
  headStats.id = 'agent-stats';
  const info = element('details', 'agent-info');
  const infoSummary = element('summary', '', 'Info');
  infoSummary.setAttribute('aria-label', 'What the agent sends and its keys');
  const infoBody = element('div', 'agent-popover');
  info.append(infoSummary, infoBody);
  const switchLabel = element('label', 'agent-switch');
  const switchInput = element('input');
  switchInput.type = 'checkbox';
  switchInput.id = 'agent-switch';
  switchInput.setAttribute('role', 'switch');
  switchInput.setAttribute('aria-label', 'Turn the agent on');
  switchLabel.append(switchInput, element('span', 'agent-switch-track'), element('span', 'agent-switch-text', 'Off'));
  const close = button('agent-close', '', () => setOpen(false), 'Close agent panel');
  close.id = 'agent-close';
  close.title = 'Close (⌘ / Ctrl + Shift + A)';
  close.innerHTML = '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="m5 5 10 10M15 5 5 15"/></svg>';
  head.append(headTitle, headStats, info, switchLabel, close);

  const body = element('div', 'agent-body');
  const surface = element('div', 'agent-surface');
  surface.id = 'agent-surface';
  const log = element('div', 'agent-log');
  log.id = 'agent-log';
  log.tabIndex = 0;
  log.setAttribute('role', 'log');
  log.setAttribute('aria-label', 'Agent conversation');
  const spacerTop = element('div'), rowsHost = element('div', 'agent-rows'), spacerBottom = element('div');
  log.append(spacerTop, rowsHost, spacerBottom);
  body.append(surface, log);

  const composer = element('div', 'agent-composer');
  composer.id = 'agent-composer';
  const chips = element('div', 'agent-chips');
  chips.id = 'agent-chips';
  const input = element('textarea', 'agent-input');
  input.id = 'agent-input';
  input.rows = 1;
  input.placeholder = 'Ask about this session';
  input.setAttribute('aria-label', 'Message the agent');
  const controls = element('div', 'agent-controls');
  const providerGroup = element('div', 'agent-segment');
  providerGroup.setAttribute('role', 'group');
  providerGroup.setAttribute('aria-label', 'Provider');
  const providerButtons = {};
  for (const kind of PROVIDERS) {
    providerButtons[kind[0]] = button('agent-segment-button', kind[1], () => chooseProvider(kind[0]));
    providerButtons[kind[0]].dataset.provider = kind[0];
    providerGroup.append(providerButtons[kind[0]]);
  }
  const modelSelect = element('select', 'agent-model');
  modelSelect.id = 'agent-model';
  modelSelect.setAttribute('aria-label', 'Model');
  modelSelect.addEventListener('change', () => { view.model[modelKey()] = modelSelect.value; });
  const send = button('agent-send', 'Send', onSend);
  send.id = 'agent-send';
  controls.append(providerGroup, modelSelect, element('span', 'agent-spacer'), send);
  // How this provider is paid for: the researcher's own key, or their own
  // subscription, with what that needs next.
  const account = element('div', 'agent-account');
  account.id = 'agent-account';
  const authGroup = element('div', 'agent-segment');
  authGroup.setAttribute('role', 'group');
  authGroup.setAttribute('aria-label', 'Pay with');
  const authButtons = {
    key: button('agent-segment-button', 'API key', () => chooseAuth('key')),
    subscription: button('agent-segment-button', 'Subscription', () => chooseAuth('subscription')),
  };
  for (const [mode, node] of Object.entries(authButtons)) { node.dataset.auth = mode; authGroup.append(node); }
  const accountText = element('span', 'agent-account-text');
  accountText.id = 'agent-account-text';
  const keyButton = button('agent-key', 'Add key', addKey);
  keyButton.id = 'agent-key';
  const accountAction = button('agent-key', '', () => accountActions[accountAction.dataset.action]?.());
  accountAction.id = 'agent-account-action';
  account.append(authGroup, accountText, keyButton, accountAction);
  const hint = element('p', 'agent-hint');
  hint.id = 'agent-hint';
  composer.append(chips, input, controls, account, hint);
  dock.append(head, body, composer);

  function bridgeFailure(error) {
    return String(error?.message ?? error ?? 'The agent could not complete that.').replace(/^Error:\s*/, '');
  }

  const providerInfo = (id = view.provider) => view.status?.providers?.find(item => item.id === id);
  // A provider without a key path (Grok) is always on its subscription.
  const authFor = (id = view.provider) => providerInfo(id)?.supportsKey === false ? 'subscription' : view.auth[id] ?? 'key';
  const loopFor = (id = view.provider, auth = authFor(id)) => auth === 'subscription' && id !== 'chatgpt' ? 'cli' : 'langgraph';
  const modelKey = (id = view.provider) => `${id}:${authFor(id)}`;
  const CLI_NAMES = {claude: 'Claude CLI', grok: 'Grok CLI'};
  const CLI_LOGIN = {claude: 'Run claude auth login in Terminal, then check again.', grok: 'Run grok login in Terminal, then check again.'};
  const subscriptionOf = id => view.subs[id] ?? providerInfo(id)?.subscription ?? {};
  // A loopback stand-in replaces only the graph's provider endpoint. A CLI
  // still talks to its own vendor, so its disclosure never says "stand-in".
  const standInApplies = (id = view.provider) => Boolean(view.status?.standIn) && loopFor(id) === 'langgraph';

  // What the selected provider and payment need before the agent can turn on.
  function credential(id = view.provider) {
    const provider = providerInfo(id);
    if (!provider) return {ready: false, text: ''};
    if (authFor(id) === 'key') {
      return provider.hasKey ? {ready: true, text: standInApplies(id) ? 'Local stand-in provider' : 'Key in your Keychain'}
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
    return {ready: false, text: `Checks the ${CLI_NAMES[id]} on this Mac.`, action: 'check'};
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

  function renderHead() {
    const on = view.phase !== 'off';
    switchInput.checked = on;
    switchInput.setAttribute('aria-checked', String(on));
    switchLabel.querySelector('.agent-switch-text').textContent = view.turning ? 'Starting' : on ? 'On' : 'Off';
    const tools = view.status?.engine?.tools?.length ?? 0;
    const provider = providerInfo();
    const engine = view.status?.engine;
    const parts = [];
    if (on && view.phase !== 'stopped') parts.push(`${provider?.label ?? ''} · ${tools} tools`);
    const working = engine?.loop === 'cli' ? engine?.cliRunning : engine?.childRunning;
    if (view.phase === 'stopped') parts.push('Disconnected');
    else if (on && !working && !view.running && view.phase === 'ready') parts.push('Idle');
    if (view.running) parts.push('Working');
    headStats.textContent = parts.join(' · ');
  }

  function renderInfo() {
    infoBody.replaceChildren();
    const row = (key, value) => {
      const line = element('div', 'agent-popover-row');
      line.append(element('span', 'agent-popover-key', key), element('span', 'agent-popover-value', value));
      return line;
    };
    const provider = providerInfo();
    const auth = authFor();
    infoBody.append(element('p', 'agent-popover-note', disclosureText()));
    infoBody.append(row('Provider', standInApplies() ? `${provider?.label ?? ''}, local stand-in` : provider?.vendor ?? 'Unknown'));
    if (auth === 'key') infoBody.append(row('Key', provider?.hasKey ? 'Stored in Keychain' : 'Not set'));
    else if (view.provider === 'chatgpt') infoBody.append(row('Account', subscriptionOf('chatgpt').signedIn ? 'ChatGPT token in Keychain' : 'Not signed in'));
    else infoBody.append(row('Account', `Your ${CLI_NAMES[view.provider]} login, kept by the CLI`));
    infoBody.append(row('Loop', loopFor() === 'cli' ? `The ${CLI_NAMES[view.provider]}'s own loop` : 'LangGraph in this window'));
    infoBody.append(row('Tools', view.status?.engine?.effects ? 'Read and actions (ask each time)' : 'Read only'));
    infoBody.append(row('Transcript', 'Local, user-only, not part of the evidence'));
    if (auth === 'key' && provider?.hasKey && !standInApplies()) {
      infoBody.append(button('agent-text-button', `Remove ${provider.label} key`, removeKey));
    }
    if (auth === 'subscription' && view.provider === 'chatgpt' && subscriptionOf('chatgpt').signedIn && !subscriptionOf('chatgpt').standIn) {
      infoBody.append(button('agent-text-button', 'Sign out of ChatGPT', signOut));
    }
  }

  function renderSurface() {
    const message = surfaceState();
    surface.replaceChildren();
    surface.hidden = !message;
    log.hidden = Boolean(message);
    if (!message) return;
    if (message.title) surface.append(element('strong', 'agent-surface-title', message.title));
    if (message.text) surface.append(element('p', 'agent-surface-text', message.text));
    if (message.node) surface.append(message.node);
  }

  function surfaceState() {
    if (!view.native) return {title: 'Available in the macOS app', text: 'The agent runs in the native app, which holds your key and the local tool server. Open this workspace in Origin Trace.'};
    if (!view.status) return {title: 'Loading', text: ''};
    if (view.status.available === false) {
      return view.status.reason === 'offline-workspace'
        ? {title: 'Needs a live or opened session', text: 'The agent reads evidence through a session\'s local API. This offline workspace has none. Start a live capture to use it.'}
        : {title: 'Tool server missing', text: 'This build has no OriginTraceAPI helper. Rebuild the app with make app-build.'};
    }
    if (view.consenting) return consentSurface();
    if (view.phase === 'off' && !transcript.rows().length) {
      return {title: 'The agent is off', text: 'Turn it on for this session to ask about the evidence. Nothing is sent until you do.'};
    }
    if (view.phase === 'stopped' && !transcript.rows().length) {
      return {title: 'Disconnected', text: view.surfaceError || 'The local tool server stopped. Ask again to restart it.'};
    }
    if (view.phase !== 'off' && !transcript.rows().length) {
      return {title: 'Ask about this session', text: 'Select a request, script or VM row to attach it. Pin what the model should read.'};
    }
    return null;
  }

  function consentSurface() {
    const node = element('div', 'agent-consent');
    node.append(element('p', 'agent-consent-text', disclosureText()));
    const effectsLabel = element('label', 'agent-check');
    const effects = element('input');
    effects.type = 'checkbox';
    effects.id = 'agent-effects';
    effects.checked = view.effects;
    effects.addEventListener('change', () => { view.effects = effects.checked; });
    effectsLabel.append(effects, element('span', '', 'Let the agent request actions. Each one needs Allow once.'));
    const actions = element('div', 'agent-consent-actions');
    const accept = button('agent-send', 'Turn on for this session', confirmConsent);
    accept.id = 'agent-consent-accept';
    actions.append(button('agent-text-button', 'Cancel', () => { view.consenting = false; render(); }), accept);
    node.append(effectsLabel, actions);
    return {title: 'Before you turn this on', node};
  }

  function renderAccount(on) {
    const provider = providerInfo();
    const auth = authFor();
    account.hidden = !provider;
    if (!provider) return;
    authButtons.key.hidden = provider.supportsKey === false;
    for (const [mode, node] of Object.entries(authButtons)) {
      node.setAttribute('aria-pressed', String(mode === auth));
      node.disabled = on;
    }
    const state = credential();
    accountText.textContent = state.text;
    accountText.title = state.text;
    accountText.classList.toggle('agent-account-ready', Boolean(state.ready));
    keyButton.hidden = on || state.action !== 'addKey';
    keyButton.textContent = `Add ${provider.label} key`;
    const labels = {signIn: 'Sign in', cancelSignIn: 'Cancel', check: 'Check again'};
    accountAction.hidden = on || !labels[state.action];
    accountAction.dataset.action = state.action ?? '';
    accountAction.textContent = labels[state.action] ?? '';
  }

  function renderComposer() {
    const on = view.phase !== 'off';
    const provider = providerInfo();
    composer.hidden = !view.native || view.status?.available === false || view.consenting;
    for (const [id, node] of Object.entries(providerButtons)) {
      node.setAttribute('aria-pressed', String(id === view.provider));
      node.disabled = on;
    }
    renderAccount(on);
    const fallback = authFor() === 'subscription' ? provider?.subscriptionModel ?? provider?.defaultModel : provider?.defaultModel;
    const list = view.models[modelKey()] ?? [fallback ?? ''];
    const selected = view.model[modelKey()] ?? fallback ?? list[0] ?? '';
    if (modelSelect.dataset.options !== list.join('|')) {
      modelSelect.replaceChildren(...list.filter(Boolean).map(id => { const option = element('option', '', id); option.value = id; return option; }));
      modelSelect.dataset.options = list.join('|');
    }
    modelSelect.value = selected;
    modelSelect.disabled = on;
    send.textContent = view.running ? 'Stop' : 'Send';
    send.classList.toggle('agent-send-stop', view.running);
    send.disabled = !on || (!view.running && !input.value.trim());
    // A stopped tool server restarts on the next question.
    input.disabled = !on;
    input.placeholder = on ? 'Ask about this session' : 'Turn the agent on to ask';
    const pinNote = view.pins.length ? `${view.pins.length} pin${view.pins.length === 1 ? '' : 's'} attached. ` : '';
    const via = loopFor() === 'cli' ? ` through the ${CLI_NAMES[view.provider]}` : '';
    hint.textContent = standInApplies()
      ? `${pinNote}Local stand-in provider. Nothing leaves this Mac.`
      : `↵ send · ⇧↵ new line · ${pinNote}question, pins and tool results go to ${provider?.vendor ?? 'the provider'}${via}`;
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

  function renderChips() {
    chips.replaceChildren();
    const selection = currentSelection();
    view.selection = selection;
    if (selection) {
      const chip = element('span', 'agent-chip');
      chip.title = selection.identifiers;
      chip.append(element('span', 'agent-chip-kind', selection.kind), element('span', 'agent-chip-label', selection.label || selection.key));
      chips.append(chip);
    }
    const canPin = view.phase !== 'off' && view.phase !== 'stopped';
    if (selection || pinnableText()) {
      const pin = button('agent-pin', 'Pin', onPin, 'Pin the selection or excerpt into this turn');
      pin.id = 'agent-pin';
      pin.disabled = !canPin;
      chips.append(pin);
    }
    for (const entry of view.pins) {
      const chip = element('span', 'agent-chip agent-chip-pinned');
      chip.append(element('span', 'agent-chip-kind', 'pinned'), element('span', 'agent-chip-label',
        `${entry.label} · ${formatBytes(entry.bytes)}${entry.truncated ? ' (cut)' : ''}`));
      chip.title = entry.truncated ? `First ${formatBytes(entry.bytes)} of ${formatBytes(entry.totalBytes)}; the rest is not sent.` : entry.label;
      chip.append(button('agent-chip-remove', '×', () => { view.pins.splice(view.pins.indexOf(entry), 1); renderComposer(); }, `Remove pin ${entry.label}`));
      chips.append(chip);
    }
    chips.hidden = !chips.childElementCount;
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

  function appendNotice(text, kind = 'info') {
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
      node.append(element('div', 'agent-user-text', row.text));
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
      node.textContent = row.text;
    }
    // An assistant row's blocks are drawn by mountRow, which keeps them across streamed deltas.
    return node;
  }

  function toolRow(row) {
    const detail = element('details', 'agent-tool');
    if (row.openTool) detail.open = true;
    detail.addEventListener('toggle', () => {
      // Restoring an open row above queues a toggle too. Acting on it would
      // append a second result and rebuild every frame, so a click in the log
      // would land on a replaced node. Only a change from the saved state counts.
      if (detail.open === Boolean(row.openTool)) return;
      row.openTool = detail.open;
      if (detail.open) detail.append(toolDetail(row));
      else detail.querySelector('.agent-tool-detail')?.remove();
      // Rows were measured closed. Force a fresh window on the next frame.
      heights.delete(row.id);
      scheduleTranscript(true);
    });
    const summary = element('summary', 'agent-tool-summary');
    summary.append(element('span', 'agent-tool-name', row.name));
    const args = compactArguments(row.arguments);
    if (args) summary.append(element('span', 'agent-tool-args', args));
    const size = row.resultBytes ? formatBytes(row.resultBytes) : '';
    const state = {running: 'Running', done: size || 'Done', error: `Failed${size ? ` · ${size}` : ''}`, denied: 'Denied', refused: 'Refused'}[row.state] ?? row.state;
    const status = element('span', `agent-tool-state agent-tool-state-${row.state}`, state);
    summary.append(status);
    detail.append(summary);
    if (detail.open) detail.append(toolDetail(row));
    return detail;
  }

  function toolDetail(row) {
    const area = element('div', 'agent-tool-detail');
    area.append(element('div', 'agent-tool-label', 'Arguments'), toolText(row.arguments || '{}'));
    area.append(element('div', 'agent-tool-label', `Result sent to the provider${row.resultBytes ? ` · ${formatBytes(row.resultBytes)}` : ''}`));
    area.append(toolText(row.result ?? (row.state === 'running' ? 'Running' : 'No result')));
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
    const card = element('div', 'agent-approval');
    card.append(element('div', 'agent-approval-title', `Allow ${row.name}?`));
    card.append(toolText(row.arguments || '{}'));
    if (row.state === 'pending') {
      const actions = element('div', 'agent-approval-actions');
      const deny = button('agent-text-button', 'Deny', () => decide(row, false));
      const allow = button('agent-send', 'Allow once', () => decide(row, true));
      allow.dataset.approve = row.callId;
      actions.append(deny, allow);
      card.append(actions);
    } else {
      card.append(element('div', 'agent-approval-state', row.state === 'allowed' ? 'Allowed once' : 'Denied'));
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
        if (index >= 0) { first = Math.min(first, index); last = Math.max(last, index); }
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

  function mountRow(row) {
    const signature = rowSignature(row), kept = mountedRows.get(row.id);
    if (kept?.signature === signature) return kept.node;
    if (row.role !== 'assistant') {
      const node = renderRow(row);
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
      ? button('agent-text-button', 'Load earlier', loadOlder) : element('span'));
    return banner;
  }

  async function loadOlder() {
    const response = await call('transcript', {before: view.olderBefore ?? undefined}).catch(() => null);
    if (!response) return;
    ingestRows(response.rows ?? []);
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
    renderInfo();
    renderSurface();
    renderComposer();
    if (frameTranscript) { frameTranscript = false; renderTranscript(); }
  }

  log.addEventListener('scroll', () => {
    const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 32;
    view.follow = atBottom;
    if (transcript.rows().length > WINDOW_THRESHOLD) scheduleTranscript();
  });
  input.addEventListener('input', () => {
    input.style.height = 'auto';
    input.style.height = `${Math.min(input.scrollHeight, 180)}px`;
    send.disabled = view.phase === 'off' || (!view.running && !input.value.trim());
  });
  input.addEventListener('keydown', event => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); onSend(); }
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

  function chooseProvider(id) {
    if (view.phase !== 'off') return;
    view.provider = id;
    try { localStorage.setItem('origin-trace.agent.provider', id); } catch { /* Optional. */ }
    if (authFor(id) === 'subscription' && loopFor(id) === 'cli' && subscriptionOf(id).signedIn === undefined) checkSubscription(id);
    if (credential(id).ready) refreshModels();
    render();
  }

  function chooseAuth(mode) {
    if (view.phase !== 'off' || providerInfo()?.supportsKey === false) return;
    view.auth[view.provider] = mode;
    try { localStorage.setItem('origin-trace.agent.auth', JSON.stringify(view.auth)); } catch { /* Optional. */ }
    if (mode === 'subscription' && loopFor() === 'cli' && subscriptionOf(view.provider).signedIn === undefined) checkSubscription();
    if (credential().ready) refreshModels();
    render();
  }

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
    keyButton.focus();
  }

  async function removeKey() {
    // The native app shows the confirmation; the web view has no dialog surface.
    try { await call('clearKey', {provider: view.provider}); await refreshStatus(); }
    catch (error) { appendNotice(bridgeFailure(error), 'error'); }
  }

  switchInput.addEventListener('change', async () => {
    if (switchInput.checked) {
      switchInput.checked = false;
      if (view.phase !== 'off' || view.turning) return;
      if (!view.status?.available) return;
      const state = credential();
      if (!state.ready) { appendNotice(state.text || 'This provider is not ready yet.', 'error'); return; }
      view.consenting = true;
      render();
      document.getElementById('agent-consent-accept')?.focus();
    } else {
      await turnOff();
    }
  });

  async function confirmConsent() {
    view.consenting = false;
    view.turning = true;
    render();
    try {
      const key = await sessionKey();
      view.sessionKey = key;
      const auth = authFor();
      const result = await call('enable', {provider: view.provider, auth, model: view.model[modelKey()] ?? '', effects: view.effects, sessionKey: key});
      if ((result.engine?.loop ?? loopFor()) === 'cli') {
        runtime = createCliRuntime();
      } else {
        let api;
        try { api = await loadRuntime(view.provider); }
        catch (error) { view.status = await call('disable'); syncEngine(view.status.engine); throw error; }
        runtime = api.createAgentRuntime({
          bridge: {call, onFetchEvent: listener => { fetchListener = listener; }},
          provider: view.provider, model: result.engine?.model ?? view.model[modelKey()], tools: result.tools ?? [], emit: handleRuntimeEvent,
        });
      }
      view.status = result;
      syncEngine(result.engine);
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
    }
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
    transcript.clear();
    heights.clear();
    citeChecks.clear();
    lastWindow = '';
    render();
    scheduleTranscript(true);
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
      (input.disabled ? switchInput : input).focus();
    } else {
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
