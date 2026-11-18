/* Session flow graph (protocol/flow-graph-v2.md): every recorded stack of one
 * session as one graph of functions, read top to bottom like a disassembler's
 * CFG. Realms are full-width bands stacked in call order. A card lists the
 * calls its function made, one row each, the way a disassembly block lists its
 * instructions; its header is tinted by its kind (JavaScript, Wasm, eval, a
 * request), and edges are coloured by what they are: a call, an await or task,
 * a crossing (a frame, JavaScript and Wasm, a call into eval) or a request. A
 * call into a same-process iframe, a posted task into one, a JavaScript to
 * Wasm call and a call into eval code also say so on their row. A chosen
 * request or card lights the stacks through it, read from the backend on
 * demand, and its lineage can be drawn alone, left to right. The drawing is
 * one canvas; reading, folding, sizing and layout run in flow_graph_worker.js
 * as a Web Worker. Captured names and URLs are painted as glyphs or inserted
 * as text. flow_graph_model.js holds the model, fold and cards. */
/* The CSS custom property stem of each kind: --flow-<stem> is its hue and
 * --flow-<stem>-ink its text colour. */
const FLOW_GRAPH_KIND_TOKENS = Object.freeze({javascript: 'js', eval: 'eval', wasm: 'wasm', request: 'request', navigation: 'navigation', cookie_write: 'cookie', chain: 'chain'});
const FLOW_GRAPH_EDGE_FAMILIES = Object.freeze(['call', 'async', 'cross', 'sink', 'omitted']);
/* Realm bands cycle --flow-realm-0 to -5. */
const FLOW_GRAPH_REALM_HUES = 6;
const FLOW_GRAPH_LIMITS = 'Observed stacks only. A call that never reached a recorded request, navigation, task or cookie write is not drawn.';
/* At and above this zoom a card shows its rows; below it, its name is painted
 * at screen size over a sketch of the rows; below the sketch zoom only boxes
 * remain, and below the band zoom each realm is one block with its counts and
 * the calls between realms bundled, so the whole session fits one view. */
const FLOW_GRAPH_TEXT_ZOOM = 0.85;
const FLOW_GRAPH_SKETCH_ZOOM = 0.2;
const FLOW_GRAPH_BAND_ZOOM = 0.045;
/* The first view fits the whole graph when its rows stay legible; a taller
 * or wider one opens at reading size at its top, never as an unreadable
 * overview: the minimap and Fit are the overview. Below this zoom it starts
 * at the busiest entry of the first band instead of the whole width. */
const FLOW_GRAPH_START_ZOOM = 0.92;
/* The minimap shows only on a canvas at least this wide: on a narrower one
 * it would cover the cards it maps (M still shows it). */
const FLOW_GRAPH_MINIMAP_MIN_W = 820;
/* Stack answers kept per generation: stepping back and forth between cards
 * asks the backend once per card. */
const FLOW_GRAPH_PATH_CACHE = 256;
/* Rows of a Details list drawn at once; the list scrolls over all of them. */
const FLOW_GRAPH_LIST_ROW = 24;

/** Why a realm keeps the layered layout (a graphLayoutClient reason, or
 * one_card, not_served or pending from the pipeline), or '' when it needs
 * none. */
function flowGraphLayoutReason(reason) {
  const {LIMITS} = graphLayoutClient;
  switch (reason?.code) {
    case 'too_large': return 'over Triskel\u2019s size limit';
    case 'request_budget': return reason.limit === 'graphs' ? `past the ${LIMITS.graphs} realms one layout request holds` : `past the ${LIMITS.nodes.toLocaleString()} cards one layout request holds`;
    case 'wider': return `Triskel would draw it ${reason.ratio.toFixed(1)}\u00d7 wider`;
    case 'taller': return `Triskel would draw it ${reason.ratio.toFixed(1)}\u00d7 taller`;
    case 'mismatch': return 'Triskel\u2019s answer did not match the realm';
    case 'failed': return `Triskel ${reason.status}${reason.detail ? `: ${reason.detail}` : ''}`;
    case 'status': return `the layout route returned ${reason.status}`;
    case 'route_failed': return 'the layout route was unavailable';
    case 'not_served': return 'the layout route is not served here';
    case 'pending': return 'waiting for Triskel';
    default: return '';
  }
}

/** Parses a colour token (#rgb, #rrggbb, rgb() or rgba()) into a canvas
 * colour at `alpha`, for shadows, which take no global alpha of their own. */
function flowGraphAlpha(color, alpha) {
  const text = String(color ?? '').trim();
  let r, g, b;
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})([0-9a-f]{2})?$/i.exec(text);
  if (hex) {
    const digits = hex[1].length === 3 ? [...hex[1]].map(digit => digit + digit).join('') : hex[1];
    [r, g, b] = [0, 2, 4].map(at => parseInt(digits.slice(at, at + 2), 16));
  } else {
    const rgb = /^rgba?\(\s*([\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i.exec(text);
    if (!rgb) return text || 'transparent';
    [r, g, b] = rgb.slice(1, 4).map(Number);
  }
  return `rgba(${r}, ${g}, ${b}, ${Math.max(0, Math.min(1, alpha))})`;
}

/** Yields the page's thread between slices of work. A message is never
 * clamped the way a timer is, so a large graph lands at full speed. */
function flowGraphPause() {
  return new Promise(resolve => {
    const channel = new MessageChannel();
    channel.port1.onmessage = () => { channel.port1.close(); resolve(); };
    channel.port2.postMessage(null);
  });
}

/** The Graph pane's pipeline (flow_graph_worker.js) in a Web Worker, or on
 * this thread where none starts; `receive` hears every message it sends. A
 * worker that fails is replaced by the pipeline on this thread, which holds
 * no graph yet, so `receive` hears {type: 'restarted'} and loads again. */
function createFlowGraphPipelineClient(receive) {
  let worker = null, local = null;
  const runLocal = () => { local ??= createFlowGraphPipeline(message => queueMicrotask(() => receive(message))); };
  try {
    worker = new Worker('flow_graph_worker.js');
    worker.onmessage = event => receive(event.data);
    worker.onerror = event => { event.preventDefault?.(); worker?.terminate(); worker = null; runLocal(); receive({type: 'restarted'}); };
  } catch {
    worker = null; runLocal();
  }
  return {send(message) { if (worker) worker.postMessage(message); else local.handle(message); }};
}

/**
 * The flow graph view: the Graph pane of the Flow workspace.
 * `open(node)` reveals a resolved function in Sources; `available()` says
 * whether this shell serves the route. `onSelect(info | null, {requested})`
 * hears every change of the selected card or row, clears included, with its
 * cause; `onFollow(info)`, when given, takes Enter or a double-click on a Wasm
 * card instead of Sources; `hostKeys(event)` says which keys the host owns,
 * which the canvas then leaves to it. The README's Flow graph section
 * documents `info` and the returned methods.
 */
function createFlowGraphPanel({host, open = () => {}, available = () => true, onSelect = null, onFollow = null, hostKeys = () => false}) {
  const make = (tag, className = '', text = '') => { const element = document.createElement(tag); if (className) element.className = className; if (text) element.textContent = text; return element; };
  const button = (label, action, aria, className = 'flow-graph-tool') => { const element = make('button', className, label); element.type = 'button'; element.setAttribute('aria-label', aria ?? label); element.addEventListener('click', action); return element; };
  host.classList.add('flow-graph');
  host.hidden = true;
  const body = make('div', 'flow-graph-body');
  const stage = make('div', 'flow-graph-stage');
  const canvas = make('canvas', 'flow-graph-canvas');
  canvas.tabIndex = 0; canvas.setAttribute('role', 'application');
  canvas.setAttribute('aria-label', 'Flow graph of every recorded stack');
  const help = make('p', 'flow-graph-help', 'Arrow keys move between functions. J and K step through the selected function\u2019s calls; Enter follows the call or opens the function (in Sources, or for a Wasm function in the pane beside the graph when there is one); Backspace goes back. Space expands a chain, U goes to a caller, O opens in Sources, S copies the call site, the context menu key or Shift F10 opens actions, I shows details, F centers, C and L copy the name and location, V draws the lit stack\u2019s lineage alone, left to right, M shows or hides the minimap, slash finds, Escape clears the selection or closes details, plus and minus zoom, 0 fits, Shift and arrows pan. A card with more calls than it shows pages through them on its last row; J and K page with the selection.');
  help.id = `flow-graph-help-${Math.random().toString(36).slice(2, 8)}`; help.hidden = true;
  canvas.setAttribute('aria-describedby', help.id);

  // Heading and tools float over the top of the canvas.
  const heading = make('div', 'flow-graph-heading');
  const title = make('strong', 'flow-graph-title', 'Flow graph');
  const stats = make('span', 'flow-graph-stats', '');
  const evidence = make('span', 'flow-graph-evidence', '');
  heading.append(title, stats, evidence);
  const tools = make('div', 'flow-graph-tools');
  const filterLabel = make('label', 'flow-graph-filter');
  const filter = make('input'); filter.type = 'search'; filter.maxLength = 256; filter.placeholder = 'Find function or host'; filter.setAttribute('aria-label', 'Find in the flow graph'); filter.autocomplete = 'off'; filter.spellcheck = false;
  filterLabel.append(filter);
  const matchLabel = make('span', 'flow-graph-matches', ''); matchLabel.setAttribute('aria-live', 'polite');
  const find = make('div', 'flow-graph-find'); find.hidden = true;
  find.append(button('\u25b2', () => stepMatch(-1), 'Previous match'), matchLabel, button('\u25bc', () => stepMatch(1), 'Next match'));
  // Folded or every frame: one radio group, one tab stop, arrows switch.
  const segment = make('div', 'flow-graph-segment'); segment.setAttribute('role', 'radiogroup'); segment.setAttribute('aria-label', 'Pass-through frames');
  const renderCollapse = value => {
    for (const [item, on] of [[folded, value], [every, !value]]) {
      item.setAttribute('aria-checked', String(on));
      item.setAttribute('aria-pressed', String(on));
      item.tabIndex = on ? 0 : -1;
    }
  };
  const setCollapse = (value, focus = false) => {
    renderCollapse(value);
    if (focus) (value ? folded : every).focus();
    if (collapse === value) return;
    collapse = value;
    rebuild();
  };
  const folded = button('Folded', () => setCollapse(true), 'Fold pass-through frames into chains', 'flow-graph-segment-item');
  const every = button('Every frame', () => setCollapse(false), 'Draw every frame', 'flow-graph-segment-item');
  folded.title = 'Fold frames that only pass one call through, inside one realm, into a chain card';
  for (const item of [folded, every]) item.setAttribute('role', 'radio');
  segment.addEventListener('keydown', event => { if (['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) { event.preventDefault(); setCollapse(!collapse, true); } });
  segment.append(folded, every);
  renderCollapse(true);
  const zoomBar = make('div', 'flow-graph-zoom-bar');
  const zoomLabel = make('span', 'flow-graph-zoom', '100%');
  zoomBar.append(button('−', () => zoomAt(0.8), 'Zoom out'), zoomLabel, button('+', () => zoomAt(1.25), 'Zoom in'), button('Fit', fit, 'Fit graph to view'));
  // Lineage draws only the lit stack's cards, left to right, in place of the
  // session; the session is one press away.
  const lineageButton = button('Lineage', () => setLineage(!lineageOn), 'Draw only the lit stack\u2019s lineage, left to right', 'flow-graph-tool flow-graph-lineage-toggle');
  lineageButton.setAttribute('aria-pressed', 'false'); lineageButton.disabled = true;
  lineageButton.title = 'Draw only the cards the lit stack walks, causes left of what they led to (V)';
  const refresh = button('Refresh', () => load(true), 'Reload the flow graph');
  tools.append(filterLabel, find, segment, lineageButton, zoomBar, refresh);
  // The banner holds what stays true until dealt with (a failed refresh);
  // passing feedback (a copy) uses the toast, so it never hides a warning.
  const banner = make('div', 'flow-graph-banner'); banner.setAttribute('role', 'status'); banner.hidden = true;
  const bannerText = make('span', '', ''), bannerRetry = make('button', 'secondary-button', 'Retry'); bannerRetry.type = 'button'; bannerRetry.hidden = true;
  bannerRetry.addEventListener('click', () => load(true));
  banner.append(bannerText, bannerRetry);
  const toast = make('div', 'flow-graph-toast'); toast.setAttribute('role', 'status'); toast.hidden = true;
  const stateBox = make('div', 'flow-graph-state'); stateBox.setAttribute('role', 'status'); stateBox.setAttribute('aria-live', 'polite');
  const stateTitle = make('strong', '', ''), stateText = make('p', '', ''), retry = make('button', 'secondary-button', 'Retry'); retry.type = 'button'; retry.hidden = true;
  retry.addEventListener('click', () => load(true));
  stateBox.append(stateTitle, stateText, retry);
  const minimap = make('canvas', 'flow-graph-minimap'); minimap.setAttribute('aria-hidden', 'true');
  const tooltip = make('div', 'flow-graph-tooltip'); tooltip.setAttribute('role', 'tooltip'); tooltip.hidden = true;
  const menu = make('div', 'flow-graph-menu'); menu.setAttribute('role', 'menu'); menu.setAttribute('aria-label', 'Card actions'); menu.hidden = true;
  // Heading and tools come first in tab order; they float over the canvas.
  stage.append(heading, tools, canvas, help, banner, toast, minimap, tooltip, menu, stateBox);
  const inspector = make('aside', 'flow-graph-inspector'); inspector.setAttribute('aria-label', 'Flow graph details'); inspector.hidden = true;
  body.append(stage, inspector);

  // Status bar: the selection, the evidence behind the graph, the key.
  const status = make('div', 'flow-graph-status');
  // The selection line: what is selected gives way, its count never does.
  const selectionText = make('span', 'flow-graph-selection', ''); selectionText.setAttribute('aria-live', 'polite');
  const selectionWhat = make('span', 'flow-graph-selection-what', ''), selectionCount = make('span', 'flow-graph-selection-count', '');
  selectionText.append(selectionWhat, selectionCount);
  function setSelectionText(what = '', count = '') {
    selectionWhat.textContent = what; selectionCount.textContent = count;
    selectionText.title = [what, count].filter(Boolean).join(' · ');
    selectionText.toggleAttribute('data-empty', !what && !count);
  }
  setSelectionText();
  const summary = make('span', 'flow-graph-summary', '');
  const engineLabel = make('span', 'flow-graph-engine', '');
  const limits = make('span', 'flow-graph-limits', FLOW_GRAPH_LIMITS);
  const legend = make('div', 'flow-graph-legend'); legend.id = `flow-graph-legend-${Math.random().toString(36).slice(2, 8)}`;
  const requestAgain = button('Request stack', () => { if (requestKey) lightRequest(requestKey); canvas.focus({preventScroll: true}); }, 'Light the stack of the chosen request again', 'flow-graph-tool flow-graph-request-again');
  requestAgain.hidden = true;
  const keyToggle = button('Key', () => setKey(!status.hasAttribute('data-key-open')), 'Show the key', 'flow-graph-tool flow-graph-key-toggle');
  keyToggle.setAttribute('aria-expanded', 'false'); keyToggle.setAttribute('aria-controls', legend.id);
  const setKey = isOpen => { status.toggleAttribute('data-key-open', isOpen); keyToggle.setAttribute('aria-expanded', String(isOpen)); };
  status.addEventListener('keydown', event => { if (event.key === 'Escape' && status.hasAttribute('data-key-open')) { event.stopPropagation(); setKey(false); keyToggle.focus(); } });
  status.addEventListener('focusout', event => { if (event.relatedTarget && !status.contains(event.relatedTarget)) setKey(false); });
  // WebKit does not focus a clicked button, so focus alone never closes the
  // key there: any press outside it, or Escape anywhere in the view, does.
  host.ownerDocument?.addEventListener?.('pointerdown', event => { if (status.hasAttribute('data-key-open') && !legend.contains(event.target) && event.target !== keyToggle) setKey(false); }, true);
  host.addEventListener('keydown', event => { if (event.key === 'Escape' && status.hasAttribute('data-key-open')) { event.stopPropagation(); setKey(false); } }, true);
  const keyRow = (mark, label) => { const item = make('span', 'flow-graph-key'); item.append(mark, make('span', '', label)); legend.append(item); };
  const keyTag = (text, tone, kind) => { const tag = make('b', 'flow-graph-key-tag', text); if (tone) tag.dataset.tone = tone; if (kind) tag.dataset.kind = kind; return tag; };
  legend.append(make('h4', '', 'Edges'));
  for (const [family, label] of [['call', 'call'], ['async', 'await or posted task'], ['cross', 'crosses a frame, JS ↔ Wasm or into eval'], ['sink', 'request, navigation or cookie write'], ['omitted', 'frames omitted']]) keyRow(make('i', `flow-graph-key-line flow-graph-key-${family}`), label);
  keyRow(make('i', 'flow-graph-key-line flow-graph-key-glow'), 'the lit stack glows; edges off it fade');
  legend.append(make('h4', '', 'Rows'));
  keyRow(keyTag('call', 'call'), 'a mnemonic in its edge\u2019s colour');
  keyRow(keyTag('setTimeout', 'async'), 'an await or a posted task');
  keyRow(keyTag('; → frame', 'cross'), 'what a call crosses, after its callee');
  keyRow(keyTag('request', 'sink'), 'a request, navigation or cookie write it made');
  legend.append(make('h4', '', 'Cards'));
  // The kinds in one wrapped row: each tints its card's header and names
  // its pill.
  const kinds = make('div', 'flow-graph-key-kinds');
  for (const kind of ['javascript', 'eval', 'wasm', 'request', 'chain']) { const item = make('span', 'flow-graph-key-kind'); item.append(keyTag(FLOW_GRAPH_KIND_TAGS[kind].toUpperCase(), null, kind), make('span', '', FLOW_GRAPH_KIND_LABELS[kind])); kinds.append(item); }
  kinds.append(make('span', 'flow-graph-key-kinds-note', 'each tints its card\u2019s header'));
  legend.append(kinds);
  keyRow(keyTag('18', 'badge'), 'distinct stacks that passed through the card');
  keyRow(make('i', 'flow-graph-key-mark'), 'dashed: an unresolved frame');
  keyRow(make('i', 'flow-graph-key-stub'), 'a dashed stub above: earlier async callers not recorded');
  keyRow(make('i', 'flow-graph-key-sample'), 'a dashed ring around it: the function a timeline sample is in');
  legend.append(make('h4', '', 'Realms'));
  keyRow(make('i', 'flow-graph-key-band'), 'a band each, stacked in call order: a realm that calls or posts into another sits above it');
  legend.append(make('h4', '', 'Keys'));
  for (const [keys, label] of [['\u2190\u2191\u2192\u2193', 'move between cards'], ['J K', 'step through calls'], ['\u21a9', 'follow the call, or open'], ['\u232b', 'go back'], ['U', 'go to the caller'], ['O  S', 'open in Sources, copy call site'],
    ['I  F  M', 'details, center, minimap'], ['C  L', 'copy name, location'], ['V', 'lineage of the lit stack'], ['/', 'find'], ['0  +  \u2212', 'fit and zoom']]) keyRow(keyTag(keys, 'call'), label);
  const keyLimits = make('p', '', FLOW_GRAPH_LIMITS); legend.append(keyLimits);
  const detailsToggle = button('Details', () => setDetails(!detailsOpen), 'Show details', 'flow-graph-tool flow-graph-details-toggle');
  detailsToggle.setAttribute('aria-pressed', 'false');
  status.append(selectionText, requestAgain, summary, engineLabel, limits, keyToggle, legend, detailsToggle);
  // The rename editor's own slot: Details is rebuilt on every refresh.
  const nameHost = make('div', 'flow-graph-name-host');
  stage.append(nameHost);
  host.append(body, status);

  const ctx = canvas.getContext?.('2d');
  const miniCtx = minimap.getContext?.('2d');
  const tokenNames = {bg: '--graph-canvas', card: '--flow-card', cardLine: '--flow-card-line', cardRule: '--flow-card-rule', shadow: '--flow-card-shadow',
    badgeFill: '--flow-badge-fill', badge: '--flow-badge', tagFill: '--flow-tag-fill', rowFill: '--flow-row-fill', box: '--flow-box', mini: '--flow-minimap',
    text: '--text', muted: '--muted', faint: '--faint', accent: '--accent', soft: '--accent-soft', mono: '--mono', sans: '--sans',
    site: '--flow-site', note: '--flow-note', mark: '--flow-mark', viewport: '--flow-viewport', researcher: '--researcher-name'};
  const alphaNames = {head: '--flow-tint-head', tag: '--flow-tint-tag', tagLine: '--flow-tint-tag-line', row: '--flow-tint-row', band: '--flow-tint-band', bandLine: '--flow-tint-band-line', border: '--flow-tint-border'};
  let tokens = {kind: {}, ink: {}, edge: {}, rowInk: {}, realm: [], alpha: {}};
  // Without a 2D context (an offline DOM) cards take the default advances.
  let measure = FLOW_GRAPH_MEASURE;
  const pillWidths = new Map();
  const readTokens = () => {
    const style = getComputedStyle(host);
    const read = name => style.getPropertyValue(name).trim();
    const next = {kind: {}, ink: {}, edge: {}, rowInk: {}, alpha: {}};
    for (const [key, name] of Object.entries(tokenNames)) next[key] = read(name);
    // A kind's hue tints its card; its ink is the text in that colour.
    for (const [kind, stem] of Object.entries(FLOW_GRAPH_KIND_TOKENS)) { next.kind[kind] = read(`--flow-${stem}`); next.ink[kind] = read(`--flow-${stem}-ink`); }
    for (const family of FLOW_GRAPH_EDGE_FAMILIES) { next.edge[family] = read(`--flow-edge-${family}`); next.rowInk[family] = read(`--flow-ink-${family}`); }
    next.realm = Array.from({length: FLOW_GRAPH_REALM_HUES}, (_, index) => read(`--flow-realm-${index}`));
    for (const [key, name] of Object.entries(alphaNames)) next.alpha[key] = Number.parseFloat(read(name));
    tokens = next; tokensRead = true; miniKey = ''; miniHighlightKey = ''; labelSides = null; pillWidths.clear();
    cards?.forEach(item => { item.fit = null; });
    if (ctx) {
      // Monospace: one advance per font sizes every card. The pipeline sizes
      // cards where no canvas measures, so the pills go to it as numbers.
      const advance = font => { ctx.font = font; return ctx.measureText('0000000000').width / 10; };
      measure = {row: advance(`11.5px ${tokens.mono}`), head: advance(`600 12.5px ${tokens.mono}`), badge: advance(`10.5px ${tokens.mono}`), pill: FLOW_GRAPH_MEASURE.pill,
        pills: Object.fromEntries(Object.values(FLOW_GRAPH_KIND_TAGS).map(tag => [tag, pillWidth(tag)]))};
    }
  };
  /** The kind pill's text width: small capitals, letter-spaced. */
  function pillWidth(tag) {
    if (!pillWidths.has(tag)) { setPillFont(); pillWidths.set(tag, ctx.measureText(tag.toUpperCase()).width); clearLetterSpacing(); }
    return pillWidths.get(tag);
  }
  const setPillFont = () => { ctx.font = `600 9.5px ${tokens.sans}`; if ('letterSpacing' in ctx) ctx.letterSpacing = '0.6px'; };
  const clearLetterSpacing = () => { if ('letterSpacing' in ctx) ctx.letterSpacing = '0px'; };
  if (typeof MutationObserver === 'function') new MutationObserver(() => { readTokens(); requestDraw(); }).observe(document.documentElement, {attributes: true, attributeFilter: ['data-theme']});
  globalThis.matchMedia?.('(prefers-color-scheme: dark)')?.addEventListener?.('change', () => { readTokens(); requestDraw(); });

  // Reading, folding, sizing and layout run in the pipeline's worker, or on
  // this thread where none starts; all it sends comes to receive().
  const pipeline = createFlowGraphPipelineClient(message => receive(message));
  let session = null, requested = null, status_ = 'idle', error = '', model = null, display = null, cards = null, layout = null;
  // The session's layout, and while Lineage is on the lineage drawn in its
  // place (`lineage` is the layout the pipeline laid out for the lit stack).
  let sessionLayout = null, lineage = null, lineageOn = false;
  let collapse = true, expanded = new Set(), selected = -1, selectedRow = -1, highlight = null, highlightLabel = '', matches = [], matchSet = new Set(), matchIndex = -1, requestKey = null, shownRequest = '', visible = false;
  // The workspace's timeline mark: a Wasm function (and row) a sample points
  // to, apart from the selection. The selection last reported to onSelect.
  let mark = null, markTarget = null, reported = '', keyIndex = null, labelSides = null;
  // Who is changing the selection while a call runs, as onSelect reports it:
  // null is the researcher ('pick'); 'host' a public setter or show() acting
  // for the host; 'replay' the graph putting back what it had after a
  // refresh or a new layout; 'silent' a setter whose return value answers.
  let cause = null;
  const as = (next, run) => { const was = cause; cause = next; try { return run(); } finally { cause = was; } };
  // What to select once the next layout lands, asked for while there was
  // none or it was being replaced, each with the cause that asked: a `key`
  // the host asked for, the lit `request`, the `card` (and row) the graph
  // had. The first of them that is in the new graph wins, in that order.
  let intent = null;
  const expect = (kind, wanted) => { intent = {...intent, [kind]: wanted}; };
  // Jobs the pipeline answers. A load, a refold, a lineage and a Find each
  // carry the id of the request that started them; an answer to an older
  // one is dropped. A load's document arrives in slices into `incoming`, and
  // a fold waits in `packedFold` for its layout. Landing a fold awaits its
  // unpacking, so what follows it waits in `landing`.
  let jobs = 0, loadJob = 0, foldJob = 0, shownFold = 0, lineageJob = 0, findJob = 0, incoming = null, packedFold = null, landing = Promise.resolve();
  // The cause each fold job reports its selection change with.
  const reasons = new Map();
  // A fold asked for while a refresh read applies to the graph on screen;
  // the refreshed graph is folded again with it once it lands.
  let foldedDuringLoad = false;
  // The minimap shows on a wide canvas unless M hid it, and on a narrow one
  // only when M showed it: null follows the width.
  let layingOut = false, highlightFromRequest = false, detailsOpen = false, minimapPref = null;
  // A stack answer being read for the selection or the request; the lit set
  // and the fold the drawn lineage was laid out for.
  let stacksPending = false, lineageFor = null;
  // A read in flight; the stack count the host gave on the last show() and
  // when the last read started, so an empty graph asks again only for more.
  let reading = false, hostStacks = null, loadedStacks = null, tokensRead = false;
  // The first row each paged card shows, by card key.
  const pages = new Map();
  // This generation's stack answers, by query, and the latest asked for.
  const stackAnswers = new Map();
  let stackToken = 0;
  // Cards visited by following calls, for Backspace.
  const history = [];
  // What the pointer is over: a card and its row or pager half (-1 back, 1
  // on), an edge, or in the overview a realm's band.
  const noHover = () => ({node: -1, row: -1, edge: -1, pager: 0, band: -1});
  let hover = noHover(), edgeBounds = null, edgeFlat = [], overview = null;
  let view = {x: 0, y: 0, z: 1}, cssW = 0, cssH = 0, dpr = 1, frame = 0, needsStart = false, miniKey = '', miniBase = null, miniHighlightKey = '', miniLit = null, miniFit = null;
  const ROUTE = flowGraphLayout.ROUTE;

  const requestDraw = () => { if (visible && !frame) frame = requestAnimationFrame(() => { frame = 0; draw(); }); };
  /** The heading and the tools share the top of the stage. When the
   * heading's whole text and the tools do not fit side by side, as when Find
   * widens, the tools move under the heading rather than cut it. */
  function syncToolsWidth() {
    const toolsW = Math.ceil(tools.offsetWidth || 0);
    host.style.setProperty('--flow-tools-w', `${toolsW}px`);
    let want = 0;
    for (const part of heading.children) if (part.textContent) want += part.scrollWidth + (want ? 12 : 0);
    // The heading's left inset, the tools' right one and the gap between.
    host.toggleAttribute('data-tools-below', 18 + want + 48 + toolsW + 12 > stage.clientWidth);
  }
  function resize() {
    if (!visible) return;
    const shown = selected >= 0 && onScreen(selected);
    ({cssW, cssH, dpr} = graphFitCanvas(canvas, stage));
    miniKey = ''; miniHighlightKey = '';
    syncToolsWidth();
    if (needsStart && layout && cssW > 1) { needsStart = false; start(); return; }
    // A rail opening beside the stage never hides the card it was opened
    // for: the view pans, at the same zoom, until the card's right edge is in
    // view or its left edge would leave.
    if (shown) {
      const box = nodeBox(selected), area = freeArea(), margin = 24;
      const left = (box.x - view.x) * view.z - area.left - margin, over = (box.x + box.w - view.x) * view.z + margin - area.right;
      if (over > 0 && left > 0) view.x += Math.min(over, left) / view.z;
    }
    requestDraw();
  }
  if (typeof ResizeObserver === 'function') {
    new ResizeObserver(resize).observe(stage);
    // Find opening widens the tools; the heading gives way at once.
    new ResizeObserver(syncToolsWidth).observe(tools);
  }
  window.addEventListener('resize', resize);

  function setState(kind, headingText = '', message = '', canRetry = false, retryLabel = 'Retry') {
    status_ = kind;
    stateBox.hidden = kind === 'ready';
    stateBox.dataset.kind = kind;
    stateTitle.textContent = headingText; stateText.textContent = message; retry.hidden = !canRetry; retry.textContent = retryLabel;
    host.dataset.state = kind;
  }
  let flashTimer = 0;
  /** Passing feedback, in its own toast: a warning in the banner stays. */
  function flash(text, kind = 'info') {
    toast.hidden = false; toast.dataset.kind = kind; toast.textContent = text;
    clearTimeout(flashTimer); flashTimer = setTimeout(() => { toast.hidden = true; }, 1800);
  }
  function setBanner(kind, text) {
    banner.hidden = !kind; banner.dataset.kind = kind ?? ''; bannerText.textContent = text ?? ''; bannerRetry.hidden = kind !== 'error';
  }
  function setDetails(isOpen) {
    if (isOpen) setKey(false);
    detailsOpen = isOpen;
    inspector.hidden = !isOpen; host.toggleAttribute('data-details', isOpen);
    detailsToggle.setAttribute('aria-pressed', String(isOpen));
    detailsToggle.setAttribute('aria-label', isOpen ? 'Hide details' : 'Show details');
    if (isOpen) renderInspector();
    // A Details sheet over the bottom of a narrow canvas must not hide the
    // card it describes.
    if (isOpen && selected >= 0 && layout) requestAnimationFrame(() => { if (detailsOpen && selected >= 0) ensureVisible(selected); });
  }

  const sessionKey = () => session ? String(session) : null;
  function load(force = false) {
    if (!available()) {
      setState('unavailable', 'Flow graph needs the live backend', 'This stored-evidence window has no flow graph route. Open the session in the live workspace or with make ui.');
      return;
    }
    if (!session) { setState('empty', 'No capture session', 'Capture requests in a live session, then return here to see every recorded stack as one graph.'); return; }
    // A read already running for this session is left to finish.
    if (reading && requested === sessionKey()) return;
    if (!force && requested === sessionKey() && model) return;
    requested = sessionKey();
    loadedStacks = hostStacks;
    reading = true;
    if (!model) setState('loading', 'Building the flow graph…', 'Folding every recorded stack of this session.');
    else setBanner('loading', 'Refreshing the flow graph…');
    refresh.disabled = true;
    // Expanded chains are named by their function, since a new generation
    // numbers its nodes anew.
    const keepExpanded = model ? [...expanded].map(id => flowGraphNodeKey(model.nodes[Number(id)])) : [];
    loadJob = foldJob = ++jobs; incoming = null; packedFold = null; foldedDuringLoad = false;
    reasons.set(loadJob, 'replay');
    pipeline.send({op: 'load', id: loadJob, session: requested, measure, collapse, expanded: keepExpanded, triskel: available()});
  }

  /** Folds the model again (a chain expanded or folded, every frame drawn or
   * not); the pipeline lays out again only the bands that changed. A
   * selection change it makes is reported with `why` unless an intent it
   * applies has its own cause. */
  function rebuild({cause: why = 'pick'} = {}) {
    if (!model) return;
    if (reading) foldedDuringLoad = true;
    // Once the refreshed document is here the pipeline holds its graph, and
    // this fold waits for it.
    if (incoming) return;
    foldJob = ++jobs; packedFold = null; layingOut = true;
    reasons.set(foldJob, why);
    if (layout) setBanner('loading', 'Laying out the realms that changed…');
    pipeline.send({op: 'refold', id: foldJob, generation: model.doc.generation, collapse, expanded: [...expanded], measure});
  }

  /** Every message the pipeline sends. */
  function receive(message) {
    const {id, type} = message;
    if (type === 'restarted') { reading = false; if (session) load(true); return; }
    if (type === 'error') { landing = landing.then(() => failed(message)); return; }
    if (id === loadJob && reading) {
      if (type === 'progress') { renderProgress(message); return; }
      if (type === 'doc') {
        incoming = {head: message.head, nodes: [], edges: [], expanded: []};
        if (!model) setState('loading', 'Laying out…', `${message.head.node_count.toLocaleString()} functions and sinks in ${message.head.contexts.length.toLocaleString()} ${message.head.contexts.length === 1 ? 'realm' : 'realms'}.`);
        return;
      }
      if (type === 'nodes') { if (incoming) for (const node of message.items) incoming.nodes.push(node); return; }
      if (type === 'edges') { if (incoming) for (const edge of message.items) incoming.edges.push(edge); return; }
      if (type === 'expanded') { if (incoming) incoming.expanded = message.expanded; return; }
    }
    // A refresh's fold lands even when a fold of the graph on screen was
    // asked for while it read.
    if (id === foldJob || (id === loadJob && incoming)) {
      if (type === 'fold') { packedFold = message.packed; return; }
      if (type === 'layout') {
        const packed = packedFold;
        packedFold = null;
        landing = landing.then(() => (message.swap ? swapIn(id, message.layout) : land(id, packed, message.layout))).catch(problem => failed({id, error: problem?.message}));
        return;
      }
      if (type === 'engine') { landing = landing.then(() => { if (id === shownFold && sessionLayout) { sessionLayout.engine = message.engine; renderEngine(); if (detailsOpen && selected < 0) renderInspector(); } }); return; }
    }
    if (type === 'lineage' && id === lineageJob) { landing = landing.then(() => landLineage(message)); return; }
    if (type === 'find' && id === findJob) landing = landing.then(() => landFind(message));
  }
  function renderProgress(message) {
    let text;
    if (message.stage === 'folding') {
      const done = Number(message.coverage?.folded_bytes ?? 0), end = Number(message.coverage?.store_end ?? 0);
      text = `Folding every recorded stack of this session${end ? `: ${Math.min(99, Math.floor(done / end * 100))}% of the store read` : ''}.`;
    } else text = `Reading the graph: ${message.read.toLocaleString()} of ${message.total.toLocaleString()} functions and sinks.`;
    if (!model) setState('loading', 'Building the flow graph…', text); else setBanner('loading', `Refreshing the flow graph. ${text}`);
  }
  function failed({id, error: text}) {
    if (id === lineageJob) { lineageJob = 0; flash(`The lineage could not be laid out. ${text ?? ''}`.trim(), 'error'); return; }
    if (id === findJob) { flash(`Find failed. ${text ?? ''}`.trim(), 'error'); return; }
    if (id !== loadJob && id !== foldJob) return;
    const refreshing = id === loadJob && reading;
    reading = false; refresh.disabled = false; layingOut = false; incoming = null;
    error = text ?? 'The flow graph could not be loaded.';
    if (model) setBanner('error', `${refreshing ? 'Refresh failed' : 'Layout failed'}. Showing the previous graph. ${error}`);
    else setState('error', refreshing ? 'Could not build the flow graph' : 'Could not lay out the flow graph', error, true);
  }

  /** A fold and its layout, drawn together: the drawn display, cards and
   * layout change only when both are ready, so a card is never drawn at
   * another card's position. A load lands its new model with them. */
  async function land(id, packed, nextLayout) {
    let nextModel = model;
    const fresh = id === loadJob && incoming;
    if (fresh) { nextModel = flowGraphModel({...incoming.head, nodes: incoming.nodes, edges: incoming.edges}); nextModel.session = requested; }
    const nextDisplay = await flowGraphUnpack(nextModel, packed, {pause: flowGraphPause});
    if (fresh ? id !== loadJob : id !== foldJob) return;
    const why = reasons.get(id) ?? 'pick';
    reasons.delete(id);
    if (fresh) {
      foldJob = id;
      const refold = foldedDuringLoad && model ? [...expanded].map(index => flowGraphNodeKey(model.nodes[Number(index)])) : null;
      foldedDuringLoad = false;
      // A refresh keeps the lit request or the selection, the expanded
      // chains and the view wherever the same functions are still there.
      if (highlightFromRequest && !intent?.request) expect('request', {reveal: false, cause: 'replay'});
      else if (selected >= 0 && display && !intent?.card) expect('card', {key: cardKey(selected), row: selectedRow, cause: 'replay'});
      const first = !model;
      model = nextModel; expanded = new Set(incoming.expanded); incoming = null; reading = false; refresh.disabled = false;
      selected = -1; selectedRow = -1; highlight = null; highlightLabel = ''; stackAnswers.clear(); stackToken += 1;
      setBanner(null);
      apply(nextDisplay, nextLayout, {first, why, id});
      if (refold) { expanded = new Set(refold.map(modelIndexOfKey).filter(index => index >= 0).map(String)); rebuild({cause: 'replay'}); }
    } else {
      setBanner(null);
      apply(nextDisplay, nextLayout, {first: false, why, id});
    }
  }
  function apply(nextDisplay, nextLayout, {first, why, id}) {
    layingOut = false; shownFold = id;
    const keep = selected >= 0 ? display?.nodes[selected]?.members?.[0] : null;
    // A refold keeps the selected card where it was on screen: an expanded
    // chain's members start where the chain card was.
    const anchor = keep !== null && keep !== undefined && layout && Number.isFinite(layout.x[selected]) ? screenOf(selected) : null;
    if (!nextDisplay.nodes.length) {
      display = nextDisplay; cards = []; layout = null; sessionLayout = null; lineage = null; keyIndex = null; markTarget = null; overview = null;
      selected = -1; selectedRow = -1; highlight = null; highlightFromRequest = false; setSelectionText(); requestAgain.hidden = true;
      notify(why);
      const records = model.doc.stacks?.records ?? {}, walked = Object.values(model.doc.stacks?.not_walked ?? {}).reduce((sum, value) => sum + value, 0);
      const stacks = FLOW_GRAPH_STACK_RECORDS.reduce((sum, type) => sum + (records[type] ?? 0), 0);
      setState('empty', 'No recorded stacks in this session', stacks > walked
        ? 'Stack records were found, but none could be decoded into frames. Details lists why.'
        : walked
          ? 'Every recorded request in this session started with no script on the stack: the parser, a preload, or a deferred start.'
          : 'Request stacks are recorded when the session runs with request stacks on (the packaged app does when Network and Artifact capture are on). Refresh once the page has made requests.', true, 'Refresh');
      renderSummary(); renderInspector(); renderLineageButton();
      return;
    }
    display = nextDisplay; cards = new Array(display.nodes.length); sessionLayout = nextLayout; lineage = null; layout = sessionLayout;
    keyIndex = null; labelSides = null; invalidateGeometry(); hover = noHover();
    findMark();
    selected = keep === null || keep === undefined ? -1 : display.displayOf[keep] ?? -1;
    selectedRow = -1;
    if (highlight?.answer) highlight = {...flowGraphHighlight(display, highlight.answer), answer: highlight.answer};
    renderSummary(); applyFilter(); renderInspector(); renderSelection(); renderLineageButton();
    setState('ready');
    const wanted = intent;
    intent = null;
    if (first) { needsStart = cssW <= 1; start(); }
    else if (anchor && selected >= 0) keepOnScreen(selected, anchor);
    else if (selected >= 0 && !wanted) ensureVisible(selected); else requestDraw();
    if (!applyIntent(wanted)) notify(why);
    if (lineageOn) requestLineage();
  }
  /** A layout with more realms laid out by Triskel, for the fold on screen.
   * The selected card, else the one nearest the middle of the view, stays
   * where it is on screen. */
  function swapIn(id, nextLayout) {
    if (id !== shownFold || !display || nextLayout.x.length !== display.nodes.length) return;
    const anchorIndex = lineageOn ? -1 : selected >= 0 && onScreen(selected) ? selected : middleCard();
    const anchor = anchorIndex >= 0 ? screenOf(anchorIndex) : null;
    sessionLayout = nextLayout;
    if (!lineageOn) {
      layout = sessionLayout; labelSides = null; invalidateGeometry();
      if (anchor) keepOnScreen(anchorIndex, anchor); else requestDraw();
    }
    renderEngine();
    if (detailsOpen && selected < 0) renderInspector();
  }

  /** Applies `wanted`, the intent a layout found: the first kind that is in
   * this graph, reported with its own cause. Says whether one applied. */
  function applyIntent(wanted) {
    if (wanted?.key && indexOfKey(wanted.key.key) >= 0) {
      as(wanted.key.cause, () => selectKey(wanted.key.key, wanted.key.reveal));
      return true;
    }
    if (wanted?.request && requestKey) {
      as(wanted.request.cause, () => lightRequest(requestKey, {reveal: wanted.request.reveal}));
      return true;
    }
    const index = wanted?.card ? indexOfKey(wanted.card.key) : -1;
    if (index < 0) return false;
    const row = wanted.card.row < card(index).rows.length ? wanted.card.row : -1;
    as(wanted.card.cause, () => selectCard(index, {reveal: false, row}));
    return true;
  }

  function renderSummary() {
    const doc = model?.doc;
    if (!doc) { stats.textContent = ''; stats.title = ''; evidence.textContent = ''; summary.textContent = ''; return; }
    let functions = 0;
    for (const node of doc.nodes) if (!FLOW_GRAPH_SINKS.has(node.kind)) functions += 1;
    const sinks = doc.nodes.length - functions, distinct = doc.stacks.distinct;
    const parts = [`${distinct.toLocaleString()} distinct ${distinct === 1 ? 'stack' : 'stacks'}`, `${functions.toLocaleString()} ${functions === 1 ? 'function' : 'functions'}`,
      `${sinks.toLocaleString()} ${sinks === 1 ? 'sink' : 'sinks'}`, `${model.contexts.length} ${model.contexts.length === 1 ? 'realm' : 'realms'}`];
    if (display?.groups) parts.push(`${display.groups.toLocaleString()} ${display.groups === 1 ? 'chain' : 'chains'} folded`);
    // The heading names the count that matters; the rest is in its tooltip
    // and the key.
    stats.textContent = `${distinct.toLocaleString()} ${distinct === 1 ? 'stack' : 'stacks'}`;
    stats.title = parts.join(' · ');
    evidence.textContent = 'observed';
    evidence.title = 'Every record and artifact of the session was folded.';
    syncToolsWidth();
    const {frame, language, dynamic} = flowGraphCrossings(display);
    const crossings = [[frame, 'frame'], [language, 'JS ↔ Wasm'], [dynamic, 'into eval']].filter(([count]) => count).map(([count, label]) => `${count.toLocaleString()} ${label}`);
    summary.textContent = `${(doc.stacks?.occurrences ?? 0).toLocaleString()} stack records · ${crossings.length ? `crossings: ${crossings.join(', ')}` : 'no crossings'}`;
    const notes = [];
    if (doc.coverage?.malformed_records) notes.push(`${doc.coverage.malformed_records.toLocaleString()} malformed ${doc.coverage.malformed_records === 1 ? 'record was' : 'records were'} not folded.`);
    if (doc.coverage?.index_damage) notes.push(`The event index refused store line ${doc.coverage.index_damage}, which no fold reads.`);
    if (model.dropped) notes.push(`${model.dropped.toLocaleString()} malformed edges are not drawn.`);
    renderEngine();
    // The status bar names only what this graph is missing; what no graph
    // shows is in the key.
    limits.textContent = notes.join(' ');
    limits.title = notes.join(' ');
    keyLimits.textContent = `${parts.join(' · ')}. ${FLOW_GRAPH_LIMITS}${doc.not_shown?.length ? ` Stacks cannot show ${doc.not_shown.join('; ')}.` : ''}`;
  }

  /** Which engine laid out the realms, and why a realm kept the layered one. */
  function renderEngine() {
    const engine = layout?.engine, realms = sessionLayout?.engine?.realms ?? [];
    if (!engine) { engineLabel.textContent = ''; engineLabel.title = ''; return; }
    if (lineageOn && lineage) {
      engineLabel.textContent = 'Lineage · layered'; engineLabel.dataset.engine = 'layered';
      engineLabel.title = 'Only the cards the lit stack walks, laid out left to right with the layered layout. Lineage (V) returns to the session.';
      return;
    }
    const sized = realms.filter(item => item.reason?.code !== 'one_card'), triskel = sized.filter(item => item.engine === 'triskel').length;
    const waiting = sized.filter(item => item.reason?.code === 'pending').length, failure = sessionLayout.engine.failure;
    engineLabel.textContent = (triskel ? `Triskel layout${triskel < sized.length ? ` · ${triskel} of ${sized.length} realms` : ''}` : failure ? 'Layered layout · Triskel unavailable' : 'Layered layout')
      + (waiting ? ` · ${waiting} waiting` : '');
    engineLabel.dataset.engine = triskel ? 'triskel' : 'layered';
    engineLabel.title = [triskel || waiting ? `Triskel ${sessionLayout.engine.revision ? sessionLayout.engine.revision.slice(0, 7) : ''} lays out each realm that fits its limits, in the background; a realm it would draw far wider than the stacked layered layout keeps that one.`.replace('  ', ' ') : 'Laid out in the app with the layered layout.',
      // Realms of one origin are told apart by their realm, the detail's first part.
      ...realms.filter(item => flowGraphLayoutReason(item.reason)).map(item => {
        const label = model?.contexts[item.key]?.label;
        return `${[label?.title ?? 'Realm', label?.detail?.split(' · ')[0]].filter(Boolean).join(', ')}: layered, ${flowGraphLayoutReason(item.reason)}.`;
      }), failure ?? ''].filter(Boolean).join('\n');
  }

  // Geometry ---------------------------------------------------------------
  const nodeBox = index => ({x: layout.x[index], y: layout.y[index], w: layout.w[index], h: layout.h[index]});
  const visibleBox = (x, y, w, h) => x < view.x + cssW / view.z && x + w > view.x && y < view.y + cssH / view.z && y + h > view.y;
  /** The top of a card's row slot: its rows in view, then the pager. */
  const slotTop = (box, slot) => box.y + FLOW_GRAPH_CARD.head + FLOW_GRAPH_CARD.location + FLOW_GRAPH_CARD.gap + slot * FLOW_GRAPH_CARD.row;
  /** The first row a card shows, and the top of one of its rows. */
  const firstRow = index => (card(index).paged ? pages.get(cardKey(index)) ?? 0 : 0);
  const rowTop = (index, box, row) => slotTop(box, row - firstRow(index));
  /** Pages a card so `row` shows; says whether its page changed. */
  function showRow(index, row) {
    const item = card(index), page = FLOW_GRAPH_CARD.page;
    if (!item.paged || row < 0) return false;
    const first = firstRow(index);
    if (row >= first && row < first + page) return false;
    setPage(index, Math.floor(row / page) * page);
    return true;
  }
  function setPage(index, first) {
    const total = card(index).rows.length, page = FLOW_GRAPH_CARD.page;
    pages.set(cardKey(index), Math.max(0, Math.min(first, Math.floor((total - 1) / page) * page)));
    requestDraw();
  }
  const screenOf = index => ({x: (layout.x[index] - view.x) * view.z, y: (layout.y[index] - view.y) * view.z});
  const onScreen = index => Number.isFinite(layout?.x[index]) && visibleBox(layout.x[index], layout.y[index], layout.w[index], layout.h[index]);
  /** Moves the view so card `index` is at screen point `at`. */
  function keepOnScreen(index, at) {
    view.x = layout.x[index] - at.x / view.z; view.y = layout.y[index] - at.y / view.z;
    requestDraw();
  }
  /** The card nearest the middle of the view, or -1. */
  function middleCard() {
    const cx = view.x + cssW / view.z / 2, cy = view.y + cssH / view.z / 2;
    let best = -1, distance = Infinity;
    for (let index = 0; index < display.nodes.length; index += 1) {
      if (!onScreen(index)) continue;
      const d = Math.hypot(layout.x[index] + layout.w[index] / 2 - cx, layout.y[index] + layout.h[index] / 2 - cy);
      if (d < distance) { distance = d; best = index; }
    }
    return best;
  }
  /** Drops what was measured from the layout on screen. */
  function invalidateGeometry() {
    edgeBounds = null; edgeFlat = []; edgeOrder = null; overview = null; miniKey = ''; miniHighlightKey = '';
  }
  function boundsOfEdges() {
    if (edgeBounds) return edgeBounds;
    const count = display.edges.length, bounds = new Float32Array(count * 4), P = layout.routes, S = layout.routeStart;
    for (let e = 0; e < count; e += 1) {
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      for (let i = S[e]; i < S[e + 1]; i += 1) { const x = P[2 * i], y = P[2 * i + 1]; if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; }
      const at = e * 4;
      bounds[at] = x0; bounds[at + 1] = y0; bounds[at + 2] = x1; bounds[at + 3] = y1;
    }
    return (edgeBounds = bounds);
  }
  // A lineage reads left to right: its curves leave and arrive sideways.
  const sideways = () => layout?.direction === 'right';
  /** Points along a route, curves flattened, for hit tests. */
  function flatRoute(e) {
    if (edgeFlat[e]) return edgeFlat[e];
    const P = layout.routes, T = layout.routeTypes, S = layout.routeStart, out = [], across = sideways();
    for (let i = S[e]; i < S[e + 1]; i += 1) {
      const x = P[2 * i], y = P[2 * i + 1];
      if (i > S[e] && T[i] === ROUTE.CURVE) {
        const px = P[2 * i - 2], py = P[2 * i - 1];
        if (across) { const mid = (px + x) / 2; out.push(mid, py, mid, y, x, y); } else { const mid = (py + y) / 2; out.push(px, mid, x, mid, x, y); }
      }
      else out.push(x, y);
    }
    return (edgeFlat[e] = out);
  }
  /** The canvas path of an edge's route: curves with vertical tangents
   * between layers (sideways in a lineage), straight runs past waypoints,
   * rounded corners. */
  function tracePath(e) {
    const P = layout.routes, T = layout.routeTypes, S = layout.routeStart, start = S[e], end = S[e + 1], across = sideways();
    for (let i = start; i < end; i += 1) {
      const x = P[2 * i], y = P[2 * i + 1];
      if (i === start) { ctx.moveTo(x, y); continue; }
      const px = P[2 * i - 2], py = P[2 * i - 1];
      if (T[i] === ROUTE.CURVE) {
        // Down, across at mid-gap and down again, corners rounded: the same
        // shape Triskel's waypoints take; across, down and across sideways.
        if (across) {
          if (Math.abs(y - py) < 0.5) { ctx.lineTo(x, y); continue; }
          const mid = (px + x) / 2, radius = Math.max(0.1, Math.min(12, Math.abs(y - py) / 2, Math.abs(x - px) / 4));
          ctx.arcTo(mid, py, mid, y, radius); ctx.arcTo(mid, y, x, y, radius); ctx.lineTo(x, y);
          continue;
        }
        if (Math.abs(x - px) < 0.5) { ctx.lineTo(x, y); continue; }
        const mid = (py + y) / 2, radius = Math.max(0.1, Math.min(12, Math.abs(x - px) / 2, Math.abs(y - py) / 4));
        ctx.arcTo(px, mid, x, mid, radius); ctx.arcTo(x, mid, x, y, radius); ctx.lineTo(x, y);
      }
      else if (T[i] === ROUTE.CORNER && i + 1 < end) {
        const nx = P[2 * i + 2], ny = P[2 * i + 3];
        const radius = Math.max(0.1, Math.min(10, Math.hypot(x - px, y - py) / 2, Math.hypot(nx - x, ny - y) / 2));
        ctx.arcTo(x, y, nx, ny, radius);
      } else ctx.lineTo(x, y);
    }
  }
  /** The direction an edge arrives in, for its arrowhead. */
  function arrival(e) {
    const P = layout.routes, T = layout.routeTypes, end = layout.routeStart[e + 1] - 1;
    const x = P[2 * end], y = P[2 * end + 1], px = P[2 * end - 2], py = P[2 * end - 1];
    if (T[end] === ROUTE.CURVE) return sideways() ? {x, y, dx: Math.sign(x - px) || 1, dy: 0} : {x, y, dx: 0, dy: Math.sign(y - py) || 1};
    const length = Math.hypot(x - px, y - py) || 1;
    return {x, y, dx: (x - px) / length, dy: (y - py) / length};
  }
  // Drawing ----------------------------------------------------------------
  /** 2: rows; 1: a sketch of them; 0: boxes; -1: a block per realm. */
  const lodNow = () => view.z >= FLOW_GRAPH_TEXT_ZOOM ? 2 : view.z >= FLOW_GRAPH_SKETCH_ZOOM ? 1 : view.z >= FLOW_GRAPH_BAND_ZOOM ? 0 : -1;
  const realmHue = key => tokens.realm[((Number(key) || 0) % FLOW_GRAPH_REALM_HUES + FLOW_GRAPH_REALM_HUES) % FLOW_GRAPH_REALM_HUES] ?? tokens.faint;
  /** A card is drawn undimmed when the lit stack walks it, Find matched it
   * or it is the selection. */
  const dimmed = index => Boolean(highlight) && index !== selected && !highlight.nodes.has(index) && !matchSet.has(index);
  // The cards and edges the last frame drew, which hit tests look through.
  const shownCards = [], shownEdges = [];
  function draw() {
    if (!ctx || !visible) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.fillStyle = tokens.bg; ctx.fillRect(0, 0, cssW, cssH);
    shownCards.length = 0; shownEdges.length = 0;
    if (!layout || !display || layout.x.length !== display.nodes.length) return;
    host.toggleAttribute('data-minimap-off', !miniShown());
    clampView();
    ctx.setTransform(dpr * view.z, 0, 0, dpr * view.z, -view.x * view.z * dpr, -view.y * view.z * dpr);
    const lod = lodNow();
    if (lod < 0) drawOverview();
    else {
      drawBands();
      drawEdges();
      // A realm's name sits under the cards at its home corner; pinned under
      // the heading it is drawn at screen size, where no card is under it.
      if (lod === 2) drawBandLabels();
      for (let index = 0; index < display.nodes.length; index += 1) if (visibleBox(layout.x[index] - 8, layout.y[index] - 26, layout.w[index] + 16, layout.h[index] + 34)) shownCards.push(index);
      // A soft lift under each card while few are in view; a dense view skips it.
      const lift = lod === 2 && shownCards.length <= 160;
      for (const index of shownCards) drawCard(index, nodeBox(index), lod, lift);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      if (lod === 1) drawScreenTitles();
      if (lod === 2) drawPinnedLabels(); else drawScreenBandLabels();
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const percent = view.z * 100;
    zoomLabel.textContent = `${percent >= 10 ? Math.round(percent) : percent.toFixed(percent >= 1 ? 1 : 2)}%`;
    drawMinimap();
  }

  /** Each realm is a full-width band with a faint tint of its own. */
  function drawBands() {
    layout.lanes.forEach(lane => {
      if (!visibleBox(lane.x, lane.y, lane.w, lane.h)) return;
      const hue = realmHue(lane.key);
      ctx.beginPath(); graphRoundedRect(ctx, lane.x, lane.y, lane.w, lane.h, 14);
      ctx.globalAlpha = tokens.alpha.band; ctx.fillStyle = hue; ctx.fill();
      ctx.globalAlpha = tokens.alpha.bandLine; ctx.strokeStyle = hue; ctx.lineWidth = 1 / view.z; ctx.stroke();
      ctx.globalAlpha = 1;
    });
  }

  /** Per band of the drawn layout: its cards and the distinct requests they
   * made, and the calls between bands bundled per pair of bands, heaviest
   * first. A bundle to the band below runs straight down; one further down
   * runs in the right gutter, and one back up in the left gutter, a track
   * each. */
  function bandOverview() {
    if (overview?.layout === layout) return overview;
    const lanes = layout.lanes, at = new Map(lanes.map((lane, index) => [lane.key, index]));
    const counts = lanes.map(() => ({cards: 0, requests: new Set()}));
    display.nodes.forEach((node, v) => {
      const lane = counts[at.get(node.context)];
      if (!lane || !Number.isFinite(layout.x[v])) return;
      lane.cards += 1;
      if (node.kind === 'request') lane.requests.add(node.members[0]);
      for (const row of display.sinkRows[v]) if (row.sink.kind === 'request') lane.requests.add(row.sink.members[0]);
    });
    const pairs = new Map();
    display.edges.forEach((edge, e) => {
      if (layout.routeStart[e] === layout.routeStart[e + 1]) return;
      const a = at.get(display.nodes[edge.from].context), b = at.get(display.nodes[edge.to].context);
      if (a === b || a === undefined || b === undefined) return;
      const key = a * lanes.length + b, item = pairs.get(key) ?? {from: a, to: b, edges: 0, count: 0};
      item.edges += 1; item.count += edge.count;
      pairs.set(key, item);
    });
    const bundles = [...pairs.values()].sort((x, y) => y.count - x.count), straight = new Uint32Array(lanes.length);
    let right = 0, left = 0;
    for (const bundle of bundles) {
      if (sideways() || bundle.to === bundle.from + 1) straight[bundle.from] += 1;
      else if (bundle.to > bundle.from) right += 1; else left += 1;
    }
    return (overview = {layout, lanes: counts.map(count => ({cards: count.cards, requests: count.requests.size})), bundles, straight, right, left,
      max: bundles.reduce((most, bundle) => Math.max(most, bundle.count), 1)});
  }
  /** Screen pixels from the bands to a gutter's first track, and between
   * two tracks: six, closer when there are many, so every track fits in 96. */
  const GUTTER = 16, trackGap = tracks => Math.min(6, 96 / Math.max(1, tracks));
  /** Screen room the overview's gutters take on each side of the bands. */
  function overviewGutters() {
    if (!layout || !display || sideways()) return {left: 0, right: 0};
    const data = bandOverview();
    return {left: data.left ? GUTTER + data.left * trackGap(data.left) : 0, right: data.right ? GUTTER + data.right * trackGap(data.right) : 0};
  }
  /** Below the box zoom the session is one block per realm, with its name
   * and counts, and the calls between realms bundled. */
  function drawOverview() {
    const data = bandOverview(), lanes = layout.lanes, hair = 1 / view.z, across = sideways();
    lanes.forEach((lane, index) => {
      const hue = realmHue(lane.key);
      ctx.beginPath(); graphRoundedRect(ctx, lane.x, lane.y, lane.w, lane.h, Math.min(10 * hair, lane.w / 2, lane.h / 2));
      ctx.globalAlpha = Math.min(1, tokens.alpha.band * 3); ctx.fillStyle = hue; ctx.fill();
      ctx.globalAlpha = Math.min(1, tokens.alpha.bandLine + 0.25); ctx.strokeStyle = hue; ctx.lineWidth = (hover.band === index ? 2.5 : 1.2) * hair; ctx.stroke();
      ctx.globalAlpha = 1;
    });
    let right = -Infinity, left = Infinity;
    for (const lane of lanes) { right = Math.max(right, lane.x + lane.w); left = Math.min(left, lane.x); }
    const spread = new Uint32Array(lanes.length), log = Math.log(data.max + 1), color = tokens.edge.cross;
    let rightTrack = 0, leftTrack = 0;
    ctx.lineCap = 'round'; ctx.lineJoin = 'round'; ctx.strokeStyle = color; ctx.fillStyle = color;
    for (const bundle of data.bundles) {
      const a = lanes[bundle.from], b = lanes[bundle.to], width = (1.2 + 3 * Math.log(bundle.count + 1) / log) * hair;
      let tip;
      ctx.beginPath();
      if (across) {
        // A lineage's realms are columns in call order.
        const forward = b.x > a.x, x0 = forward ? a.x + a.w : a.x, x1 = forward ? b.x : b.x + b.w, y0 = a.y + a.h / 2, y1 = b.y + b.h / 2, mid = (x0 + x1) / 2;
        ctx.moveTo(x0, y0); ctx.bezierCurveTo(mid, y0, mid, y1, x1, y1);
        tip = {x: x1, y: y1, dx: forward ? 1 : -1, dy: 0};
      } else if (bundle.to === bundle.from + 1) {
        const x = a.x + a.w * (spread[bundle.from] + 1) / (data.straight[bundle.from] + 1);
        spread[bundle.from] += 1;
        ctx.moveTo(x, a.y + a.h); ctx.lineTo(x, b.y);
        tip = {x, y: b.y, dx: 0, dy: 1};
      } else {
        const down = bundle.to > bundle.from, track = down ? rightTrack++ : leftTrack++, gap = trackGap(down ? data.right : data.left);
        const gx = down ? right + (GUTTER + track * gap) * hair : left - (GUTTER + track * gap) * hair, y0 = a.y + a.h * (down ? 0.6 : 0.4), y1 = b.y + b.h * (down ? 0.4 : 0.6), side = down ? a.x + a.w : a.x, into = down ? b.x + b.w : b.x;
        ctx.moveTo(side, y0); ctx.lineTo(gx, y0); ctx.lineTo(gx, y1); ctx.lineTo(into, y1);
        tip = {x: into, y: y1, dx: down ? -1 : 1, dy: 0};
      }
      ctx.globalAlpha = 0.7; ctx.lineWidth = width; ctx.stroke();
      const size = (7 + width * view.z) * hair, half = size * 0.5;
      ctx.beginPath(); ctx.moveTo(tip.x, tip.y); ctx.lineTo(tip.x - tip.dx * size - tip.dy * half, tip.y - tip.dy * size + tip.dx * half); ctx.lineTo(tip.x - tip.dx * size + tip.dy * half, tip.y - tip.dy * size - tip.dx * half); ctx.closePath(); ctx.fill();
    }
    ctx.globalAlpha = 1;
    // Names and counts at screen size, kept under the heading: inside a block
    // wide enough to hold them, else beside the bands past the gutters, top
    // to bottom, each within its block's height. A label that has no room
    // left there is the band's hover.
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.textBaseline = 'alphabetic';
    const inset = topInset(), gutters = overviewGutters();
    const outRight = (right - view.x) * view.z + gutters.right + 14, outLeft = (left - view.x) * view.z - gutters.left - 14;
    const outside = !across && cssW - outRight >= 160 ? 'right' : !across && outLeft >= 160 ? 'left' : null;
    let below = inset;
    lanes.forEach((lane, index) => {
      const x = (lane.x - view.x) * view.z, y = (lane.y - view.y) * view.z, w = lane.w * view.z, h = lane.h * view.z;
      if (y > cssH || y + h < inset) return;
      const counts = data.lanes[index], within = w >= 140 && h >= 16;
      // Realms of one origin are told apart by their realm, the detail's first part.
      const label = model.contexts[lane.key]?.label;
      const line = [label?.detail?.split(' · ')[0], `${counts.cards.toLocaleString()} ${counts.cards === 1 ? 'card' : 'cards'}`, `${counts.requests.toLocaleString()} ${counts.requests === 1 ? 'request' : 'requests'}`].filter(Boolean).join(' · ');
      let start, room, top, two;
      if (within) {
        if (x > cssW || x + w < 0) return;
        start = Math.max(x + 10, 8); room = Math.min(x + w, cssW) - start - 10;
        top = Math.min(Math.max(y + 6, inset), y + h - 16); two = h >= 38 && y + h - top >= 36;
      } else {
        if (!outside) return;
        two = true;
        top = Math.max(y + h / 2 - 16, below, inset);
        if (top > y + h || top + 34 > cssH) return;
        room = outside === 'right' ? cssW - outRight - 12 : outLeft - 12;
        start = outside === 'right' ? outRight : outLeft - room;
        below = top + 36;
      }
      ctx.font = `600 12px ${tokens.sans}`;
      const name = fitText(label?.title ?? 'Realm', room - 14);
      ctx.fillStyle = realmHue(lane.key); ctx.beginPath(); ctx.arc(start + 4, top + 8, 3.5, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = tokens.text; ctx.fillText(name, start + 14, top + 12);
      if (!two) return;
      ctx.font = `11px ${tokens.sans}`; ctx.fillStyle = tokens.muted;
      ctx.fillText(fitText(line, room - 14), start + 14, top + 28);
    });
  }

  /** The band label: realm name and its process, frame and realm IDs, in the
   * top corner of the band that no edge crosses (the right one when both are
   * clear), so it never sits on the spine. Sizes are screen pixels at zoom 1. */
  const LABEL = Object.freeze({inset: 18, top: 14, height: 24});
  function bandLabelText(lane) {
    const context = model.contexts[lane.key]?.label;
    return {title: context?.title ?? 'Realm', detail: context?.detail ?? ''};
  }
  function bandLabelWidth(lane) {
    const {title, detail} = bandLabelText(lane);
    ctx.font = `600 12.5px ${tokens.sans}`; const titleW = ctx.measureText(title).width;
    ctx.font = `11px ${tokens.sans}`; const detailW = detail ? ctx.measureText(detail).width + 10 : 0;
    return 16 + titleW + detailW + 4;
  }
  /** Which top corner each band's label takes: the right one unless more
   * routes cross it than the left. Bands are looked up by each route's
   * extent, so this is one pass over the edges. */
  function chooseLabelSides() {
    labelSides = new Map();
    if (!ctx) return;
    const strips = layout.lanes.map(lane => ({lane, y0: lane.y + LABEL.top - 2, y1: lane.y + LABEL.top + LABEL.height + 2, width: Math.min(bandLabelWidth(lane), lane.w - LABEL.inset * 2), right: 0, left: 0}))
      .sort((a, b) => a.y0 - b.y0);
    const bounds = boundsOfEdges();
    // Every strip is as tall as the next, so sorted by top they are sorted by bottom too.
    const crosses = (e, x0, x1, strip) => {
      const points = flatRoute(e);
      for (let i = 2; i < points.length; i += 2) {
        const ax = Math.min(points[i - 2], points[i]), bx = Math.max(points[i - 2], points[i]), ay = Math.min(points[i - 1], points[i + 1]), by = Math.max(points[i - 1], points[i + 1]);
        if (bx >= x0 && ax <= x1 && by >= strip.y0 && ay <= strip.y1) return true;
      }
      return false;
    };
    for (let e = 0; e < display.edges.length; e += 1) {
      const at = e * 4, top = bounds[at + 1], bottom = bounds[at + 3];
      if (!(bottom >= top)) continue;
      let low = 0, high = strips.length;
      while (low < high) { const mid = (low + high) >> 1; if (strips[mid].y1 < top) low = mid + 1; else high = mid; }
      for (let s = low; s < strips.length && strips[s].y0 <= bottom; s += 1) {
        const strip = strips[s], lane = strip.lane, rx1 = lane.x + lane.w - LABEL.inset, rx0 = rx1 - strip.width, lx0 = lane.x + LABEL.inset, lx1 = lx0 + strip.width;
        if (bounds[at + 2] >= rx0 && bounds[at] <= rx1 && crosses(e, rx0, rx1, strip)) strip.right += 1;
        if (bounds[at + 2] >= lx0 && bounds[at] <= lx1 && crosses(e, lx0, lx1, strip)) strip.left += 1;
      }
    }
    for (const strip of strips) labelSides.set(strip.lane.key, strip.right && strip.left < strip.right ? 'left' : 'right');
  }
  /** Where a band's label is pinned on screen, under the heading, while its
   * home corner is scrolled above it, sliding up with the band's end; null
   * while it is at home. */
  function pinnedTop(lane, inset) {
    const home = (lane.y + LABEL.top - view.y) * view.z, want = inset - 4;
    if (home >= want - 0.5) return null;
    return Math.min(want, (lane.y + lane.h - view.y) * view.z - LABEL.height - 10);
  }
  /** Labels at their home corner, in graph space, under the cards. */
  function drawBandLabels() {
    if (!labelSides) chooseLabelSides();
    const inset = topInset(), mini = miniRect();
    layout.lanes.forEach(lane => {
      if (!visibleBox(lane.x, lane.y, lane.w, lane.h) || pinnedTop(lane, inset) !== null) return;
      const top = lane.y + LABEL.top, width = Math.min(bandLabelWidth(lane), lane.w - LABEL.inset * 2);
      // A label level with the minimap stops short of it.
      const screenTop = (top - view.y) * view.z, miniLeft = mini && screenTop + LABEL.height * view.z > mini.top ? mini.left - 8 : cssW;
      const viewLeft = Math.max(lane.x, view.x), viewRight = Math.min(lane.x + lane.w, view.x + miniLeft / view.z);
      const left = labelSides.get(lane.key) === 'left' ? viewLeft + LABEL.inset : Math.max(lane.x + LABEL.inset, viewRight - LABEL.inset - width);
      paintLabel(lane, left, top, width);
    });
  }
  /** A label pinned under the heading is drawn in screen space at one size,
   * so zooming in never makes it cover more than a row. It never covers a
   * card: while one is under it, the band's hue alone names the realm. */
  function drawPinnedLabels() {
    if (!labelSides) chooseLabelSides();
    const inset = topInset(), mini = miniRect();
    layout.lanes.forEach(lane => {
      if (!visibleBox(lane.x, lane.y, lane.w, lane.h)) return;
      const top = pinnedTop(lane, inset);
      if (top === null) return;
      const miniLeft = mini && top + LABEL.height > mini.top ? mini.left - 8 : cssW;
      const x0 = Math.max(0, (lane.x - view.x) * view.z), x1 = Math.min(miniLeft, (lane.x + lane.w - view.x) * view.z);
      const width = Math.min(bandLabelWidth(lane), x1 - x0 - LABEL.inset * 2);
      if (width < 40) return;
      const left = labelSides.get(lane.key) === 'left' ? x0 + LABEL.inset : x1 - LABEL.inset - width;
      // The plate's box, in graph space, against the cards drawn this frame.
      const gx0 = view.x + (left - 8) / view.z, gx1 = view.x + (left + width + 8) / view.z, gy0 = view.y + top / view.z, gy1 = view.y + (top + LABEL.height) / view.z;
      if (shownCards.some(index => layout.x[index] < gx1 && layout.x[index] + layout.w[index] > gx0 && layout.y[index] < gy1 && layout.y[index] + layout.h[index] > gy0)) return;
      paintLabel(lane, left, top, width);
    });
  }
  function paintLabel(lane, left, top, width) {
    const {title, detail} = bandLabelText(lane), hue = realmHue(lane.key);
    ctx.textBaseline = 'alphabetic';
    // A plate keeps an edge passing under the name from striking it out.
    ctx.globalAlpha = 0.9; ctx.fillStyle = tokens.bg; ctx.beginPath(); graphRoundedRect(ctx, left - 8, top, width + 16, LABEL.height, 6); ctx.fill(); ctx.globalAlpha = 1;
    ctx.fillStyle = hue; ctx.beginPath(); ctx.arc(left + 4, top + LABEL.height / 2, 4, 0, Math.PI * 2); ctx.fill();
    ctx.font = `600 12.5px ${tokens.sans}`; ctx.fillStyle = tokens.text;
    const titleText = fitText(title, width - 16), titleW = ctx.measureText(titleText).width;
    ctx.fillText(titleText, left + 14, top + 16.5);
    if (detail && width - 16 - titleW > 40) { ctx.font = `11px ${tokens.sans}`; ctx.fillStyle = tokens.muted; ctx.fillText(fitText(detail, width - 26 - titleW), left + 24 + titleW, top + 16.5); }
  }
  /** Zoomed out, each band keeps its realm's name at screen size, on a
   * plate, since its top pad is too small to hold it. */
  function drawScreenBandLabels() {
    ctx.textBaseline = 'alphabetic'; ctx.font = `600 11px ${tokens.sans}`;
    const inset = topInset();
    layout.lanes.forEach(lane => {
      const x = (lane.x - view.x) * view.z, y = (lane.y - view.y) * view.z, w = lane.w * view.z, h = lane.h * view.z;
      if (x > cssW || x + w < 0 || y > cssH || y + h < 0 || w < 24 || h < 18) return;
      const left = Math.max(x + 6, 6), base = Math.min(Math.max(y + 14, inset + 8), y + h - 4);
      const text = fitText(model.contexts[lane.key]?.label.title ?? 'Realm', Math.min(x + w, cssW) - left - 22), width = ctx.measureText(text).width;
      ctx.globalAlpha = 0.88; ctx.fillStyle = tokens.bg; ctx.beginPath(); graphRoundedRect(ctx, left - 2, base - 12, width + 20, 16, 4); ctx.fill(); ctx.globalAlpha = 1;
      ctx.fillStyle = realmHue(lane.key); ctx.beginPath(); ctx.arc(left + 5, base - 4, 3, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = tokens.muted; ctx.fillText(text, left + 13, base);
    });
  }

  function fitText(text, room) {
    if (!text || room <= 0) return '';
    if (ctx.measureText(text).width <= room) return text;
    let low = 0, high = text.length;
    while (low < high) { const mid = (low + high + 1) >> 1; if (ctx.measureText(`${text.slice(0, mid)}…`).width <= room) low = mid; else high = mid - 1; }
    return low ? `${text.slice(0, low)}…` : '';
  }

  const edgeColor = edge => tokens.edge[flowGraphEdgeFamily(edge)] ?? tokens.edge.call;
  /** Edges off the lit stack first, then on it, per display and highlight;
   * the hovered and chosen edges are drawn last, over both. */
  let edgeOrder = null;
  function drawOrder() {
    if (edgeOrder?.display === display && edgeOrder.highlight === highlight) return edgeOrder.order;
    const count = display.edges.length, order = new Int32Array(count);
    let at = 0;
    if (highlight) for (let e = 0; e < count; e += 1) if (!highlight.edges.has(e)) order[at++] = e;
    for (let e = 0; e < count; e += 1) if (!highlight || highlight.edges.has(e)) order[at++] = e;
    edgeOrder = {display, highlight, order};
    return order;
  }
  /** The edge of a card's row, or -1. */
  const rowEdge = (index, row) => (index >= 0 && row >= 0 ? card(index).rows[row]?.edge ?? -1 : -1);
  function drawEdges() {
    const bounds = boundsOfEdges(), order = drawOrder(), chosen = rowEdge(selected, selectedRow), pointed = rowEdge(hover.node, hover.row);
    // The lit stack glows: a heavier stroke and a soft shadow of its colour.
    // A huge lit set skips the shadow, which costs a blur per edge.
    const style = {casing: view.z >= 0.3, log: Math.log(display.maxCount + 1), glows: Boolean(highlight) && view.z >= 0.25 && highlight.edges.size <= 600};
    ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    for (let i = 0; i < order.length; i += 1) {
      const index = order[i];
      if (index !== hover.edge && index !== pointed && index !== chosen) drawEdge(index, false, bounds, style);
    }
    if (chosen >= 0) drawEdge(chosen, true, bounds, style);
    if (pointed >= 0 && pointed !== chosen) drawEdge(pointed, true, bounds, style);
    if (hover.edge >= 0 && hover.edge !== chosen && hover.edge !== pointed) drawEdge(hover.edge, true, bounds, style);
    ctx.globalAlpha = 1;
  }
  function drawEdge(index, strong, bounds, {casing, log, glows}) {
    const at = index * 4;
    if (!visibleBox(bounds[at] - 6, bounds[at + 1] - 6, bounds[at + 2] - bounds[at] + 12, bounds[at + 3] - bounds[at + 1] + 12)) return;
    shownEdges.push(index);
    const edge = display.edges[index], dim = Boolean(highlight), on = !dim || strong || highlight.edges.has(index), color = edgeColor(edge), family = flowGraphEdgeFamily(edge);
    // Zoomed out to boxes, plain calls recede to hairlines so crossings
    // and tasks carry the picture; dimmed edges stay traceable.
    const boxes = view.z < FLOW_GRAPH_SKETCH_ZOOM && family !== 'cross' && family !== 'async' && !strong;
    const glow = dim && on;
    const weight = boxes ? 1 / view.z : (1.4 + 1.6 * Math.log(edge.count + 1) / log + (strong ? 1.2 : 0) + (glow ? 1 : 0)) * Math.max(1, 0.7 / view.z);
    ctx.globalAlpha = (on ? 1 : family === 'cross' ? 0.4 : 0.26) * (boxes ? 0.6 : 1);
    ctx.beginPath(); tracePath(index);
    if (casing) { ctx.strokeStyle = tokens.bg; ctx.lineWidth = weight + 3.4; ctx.setLineDash([]); ctx.stroke(); }
    if (glow && glows) { ctx.shadowColor = flowGraphAlpha(color, 0.6); ctx.shadowBlur = 9 * dpr; }
    ctx.strokeStyle = color; ctx.lineWidth = weight;
    if (edge.kind === 'omitted') ctx.setLineDash([1.5, 4.5]);
    ctx.stroke();
    if (edge.kind === 'omitted') ctx.setLineDash([]);
    if (glow && glows) { ctx.shadowBlur = 0; ctx.shadowColor = 'transparent'; }
    if (view.z >= 0.25) arrowHead(index, color, Math.max(6.5, 4 + weight * 1.5));
  }
  function arrowHead(index, color, size) {
    const {x, y, dx, dy} = arrival(index), nx = -dy, ny = dx, half = size * 0.48;
    ctx.beginPath(); ctx.moveTo(x, y); ctx.lineTo(x - dx * size + nx * half, y - dy * size + ny * half); ctx.lineTo(x - dx * size - nx * half, y - dy * size - ny * half); ctx.closePath();
    if (view.z >= 0.3) { ctx.strokeStyle = tokens.bg; ctx.lineWidth = 2; ctx.stroke(); }
    ctx.fillStyle = color; ctx.fill();
  }

  /** What card `index` says, built when it is first drawn or asked about. */
  const card = index => (cards[index] ??= flowGraphCard(model, display, index, measure));
  /** The family a row's mnemonic is coloured by: its edge's, or a sink's. */
  const rowFamily = item => item?.family ?? (item?.sink ? 'sink' : 'call');
  /** A row band: the surface, a tint of `hue` and a bar on the left. */
  function rowBand(x, top, w, hue, strength) {
    const C = FLOW_GRAPH_CARD;
    ctx.globalAlpha = 1; ctx.fillStyle = tokens.rowFill; ctx.fillRect(x + 1, top, w - 2, C.row);
    ctx.globalAlpha = tokens.alpha.row * strength; ctx.fillStyle = hue; ctx.fillRect(x + 1, top, w - 2, C.row);
    ctx.globalAlpha = strength; ctx.fillRect(x + 1, top, 2, C.row); ctx.globalAlpha = 1;
  }
  function drawCard(index, box, lod, lift) {
    const node = display.nodes[index], item = card(index), picked = index === selected, C = FLOW_GRAPH_CARD;
    const matched = matchSet.has(index), hue = tokens.kind[node.kind] ?? tokens.faint, ink = tokens.ink[node.kind] ?? tokens.muted;
    // Off the lit stack, a card keeps its place and fill; its tint, outline
    // and colours fade, and its text turns muted (still 4.5:1).
    const dim = dimmed(index), marked = markTarget?.index === index;
    const {x, y, w, h} = box, r = C.radius, hair = 1 / view.z;
    ctx.globalAlpha = 1;
    if (node.kind === 'chain') {
      // A folded chain reads as a stack of cards behind it, down and right.
      ctx.fillStyle = tokens.card; ctx.strokeStyle = hue; ctx.lineWidth = hair;
      for (const offset of [6, 3]) { ctx.beginPath(); graphRoundedRect(ctx, x + offset, y + offset, w, h, r); ctx.fill(); ctx.globalAlpha = dim ? 0.25 : tokens.alpha.border; ctx.stroke(); ctx.globalAlpha = 1; }
    }
    if (node.chain_cut && lod > 0) {
      // Earlier async callers were not recorded: a stub with no edge.
      ctx.strokeStyle = tokens.faint; ctx.lineWidth = 1.4 / Math.max(view.z, 0.5); ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(x + 16, y - 20); ctx.lineTo(x + 16, y); ctx.stroke(); ctx.setLineDash([]);
    }
    if (picked && lod > 0) {
      // Selected: a soft ring and a glow in the card's colour.
      ctx.globalAlpha = 0.2; ctx.fillStyle = hue; ctx.beginPath(); graphRoundedRect(ctx, x - 4, y - 4, w + 8, h + 8, r + 4); ctx.fill(); ctx.globalAlpha = 1;
      ctx.shadowColor = flowGraphAlpha(hue, 0.35); ctx.shadowBlur = 30 * dpr;
    } else if (lift && !dim) { ctx.shadowColor = tokens.shadow; ctx.shadowBlur = 14 * dpr; ctx.shadowOffsetY = 5 * dpr * view.z; }
    // A dimmed card's fill fades toward its band, so it recedes while its
    // muted text keeps its contrast; no edge runs under a card.
    ctx.globalAlpha = dim ? 0.5 : 1; ctx.fillStyle = tokens.card; ctx.beginPath(); graphRoundedRect(ctx, x, y, w, h, r); ctx.fill(); ctx.globalAlpha = 1;
    ctx.shadowBlur = 0; ctx.shadowOffsetY = 0; ctx.shadowColor = 'transparent';
    if (lod === 0) {
      // Boxes: filled with the kind's colour, like the minimap.
      ctx.globalAlpha = dim ? 0.18 : 0.5; ctx.fillStyle = hue; ctx.fill(); ctx.globalAlpha = 1;
      if (picked || marked) { ctx.strokeStyle = picked ? hue : tokens.mark; ctx.lineWidth = 2 / view.z; ctx.stroke(); }
      return;
    }
    // Header strip, tinted by the kind, ruled off from the body.
    ctx.save(); ctx.beginPath(); graphRoundedRect(ctx, x, y, w, h, r); ctx.clip();
    ctx.globalAlpha = tokens.alpha.head * (dim ? 0.35 : 1); ctx.fillStyle = hue; ctx.fillRect(x, y, w, C.head);
    ctx.globalAlpha = dim ? 0.15 : 0.38; ctx.fillRect(x, y + C.head - hair, w, hair);
    ctx.restore(); ctx.globalAlpha = 1;
    // Outline: the kind's colour, heavier when selected; dashed for an
    // unresolved frame or a match of Find.
    ctx.beginPath(); graphRoundedRect(ctx, x, y, w, h, r);
    ctx.strokeStyle = matched && !picked ? tokens.accent : hue;
    ctx.globalAlpha = picked || matched ? 1 : dim ? 0.3 : highlight ? 0.85 : tokens.alpha.border;
    ctx.lineWidth = (picked ? 2 : matched ? 1.5 : 1) / view.z;
    if ((node.status !== 'resolved' && !picked) || (matched && !picked)) ctx.setLineDash(matched && !picked ? [5 / view.z, 3 / view.z] : [4, 3]);
    ctx.stroke(); ctx.setLineDash([]); ctx.globalAlpha = 1;
    if (marked) {
      // A timeline sample's function: a dashed ring outside the card.
      ctx.strokeStyle = tokens.mark; ctx.lineWidth = 2 / view.z; ctx.setLineDash([6 / view.z, 4 / view.z]);
      ctx.beginPath(); graphRoundedRect(ctx, x - 6, y - 6, w + 12, h + 12, r + 6); ctx.stroke(); ctx.setLineDash([]);
    }
    const first = firstRow(index), shown = item.paged ? Math.min(C.page, item.rows.length - first) : item.rows.length;
    if (lod === 1) {
      // A sketch of the rows, coloured by what each row does; the name is
      // painted at screen size later.
      ctx.globalAlpha = dim ? 0.35 : 0.8;
      for (let slot = -1; slot < shown + (item.paged ? 1 : 0); slot += 1) {
        const entry = slot >= 0 && slot < shown ? item.rows[first + slot] : null;
        ctx.fillStyle = entry ? tokens.rowInk[rowFamily(entry)] ?? tokens.cardLine : tokens.cardLine;
        const top = slot < 0 ? y + C.head + 7 : slotTop(box, slot === shown ? C.page : slot) + 7;
        const width = slot < 0 ? item.location.length * measure.badge : entry ? item.siteW + item.opW + 22 + entry.target.length * measure.row : w / 2;
        ctx.fillRect(slot === shown ? x + w / 4 : x + C.pad, top, Math.min(w - C.pad * 2, width), 5);
      }
      ctx.globalAlpha = 1;
      return;
    }
    ctx.save(); ctx.beginPath(); ctx.rect(x, y, w, h); ctx.clip();
    ctx.textBaseline = 'alphabetic';
    // Header: name, then the stack badge, then the kind pill.
    const pillX = x + w - C.pad - item.pillW, badgeX = pillX - 6 - item.badgeW;
    ctx.fillStyle = tokens.tagFill; ctx.beginPath(); graphRoundedRect(ctx, pillX, y + 8, item.pillW, 16, 4); ctx.fill();
    if (tokens.alpha.tag > 0) { ctx.globalAlpha = tokens.alpha.tag * (dim ? 0.4 : 1); ctx.fillStyle = hue; ctx.fill(); }
    if (tokens.alpha.tagLine > 0) { ctx.globalAlpha = tokens.alpha.tagLine * (dim ? 0.4 : 1); ctx.strokeStyle = hue; ctx.lineWidth = hair; ctx.stroke(); }
    ctx.globalAlpha = 1;
    setPillFont(); ctx.fillStyle = dim ? tokens.muted : ink; ctx.textAlign = 'center';
    ctx.fillText(item.tag.toUpperCase(), pillX + item.pillW / 2, y + 19.5); ctx.textAlign = 'left'; clearLetterSpacing();
    ctx.fillStyle = tokens.badgeFill; ctx.strokeStyle = tokens.badge; ctx.lineWidth = hair; ctx.beginPath(); graphRoundedRect(ctx, badgeX, y + 8, item.badgeW, 16, 4); ctx.fill(); ctx.stroke();
    ctx.font = `10.5px ${tokens.mono}`; ctx.fillStyle = tokens.muted; ctx.fillText(item.badge, badgeX + 5, y + 19.5);
    if (item.fit?.w !== w) item.fit = fitCard(item, w);
    const fit = item.fit;
    ctx.font = `600 12.5px ${tokens.mono}`; ctx.fillStyle = node.status === 'resolved' && !dim ? tokens.text : tokens.muted;
    ctx.fillText(fit.title, x + C.pad, y + 21);
    ctx.font = `11px ${tokens.mono}`; ctx.fillStyle = tokens.site;
    ctx.fillText(fit.location, x + C.pad, y + C.head + 15);
    // A researcher name follows the location in its own italic colour, in the
    // room the card already has, so naming never moves the layout.
    const analyst = flowGraphAnalystName(node);
    if (analyst) {
      const used = ctx.measureText(fit.location).width + 10, room = w - C.pad * 2 - used;
      ctx.font = `italic 500 11px ${tokens.sans}`;
      if (room > 36) { ctx.fillStyle = dim ? tokens.muted : tokens.researcher || tokens.accent; ctx.fillText(fitText(analyst, room), x + C.pad + used, y + C.head + 15); }
    }
    // Rows: site, mnemonic, callee, then the note and the count.
    ctx.font = `11.5px ${tokens.mono}`;
    const opX = x + C.pad + (item.siteW ? item.siteW + 12 : 0), targetX = x + fit.targetX;
    for (let slot = 0; slot < shown; slot += 1) {
      const row = first + slot, top = slotTop(box, slot), base = top + 13.5, entry = item.rows[row];
      const isHover = hover.node === index && hover.row === row, isPicked = picked && selectedRow === row, isMarked = marked && markTarget.row === row;
      if (isPicked) rowBand(x, top, w, hue, 1); else if (isMarked) rowBand(x, top, w, tokens.mark, 1); else if (isHover) rowBand(x, top, w, hue, 0.55);
      const family = rowFamily(entry), tone = dim ? tokens.muted : tokens.rowInk[family] ?? tokens.muted;
      if (highlight && !dim && !isHover && !isPicked && entry.members?.some(member => highlight.originalEdges.has(member))) { ctx.fillStyle = tokens.edge[family] ?? hue; ctx.fillRect(x + 4, top + 4, 2, C.row - 8); }
      ctx.fillStyle = tokens.site; ctx.fillText(entry.site, x + C.pad, base);
      const edge = entry.edge >= 0 ? display.edges[entry.edge] : null;
      ctx.fillStyle = tone; ctx.fillText(entry.op, opX, base);
      const text = fitRow(fit, item, row);
      ctx.fillStyle = dim || (edge && display.nodes[edge.to]?.status !== 'resolved') ? tokens.muted : tokens.text; ctx.fillText(text.target, targetX, base);
      if (text.note) { ctx.fillStyle = family === 'call' || dim ? tokens.note : tone; ctx.fillText(text.note, x + text.noteX, base); }
      if (entry.count) { ctx.fillStyle = tokens.muted; ctx.fillText(entry.count, x + text.countX, base); }
    }
    if (item.paged) drawPager(index, item, box, first, hue, dim);
    ctx.restore();
    ctx.globalAlpha = 1;
  }
  /** A paged card's last row: back on its left half, on on its right, and
   * which of its rows show. Every row is reachable here, by J and K, and in
   * Details. */
  function drawPager(index, item, box, first, hue, dim) {
    const C = FLOW_GRAPH_CARD, top = slotTop(box, C.page), base = top + 13.5, {x, w} = box, half = w / 2, total = item.rows.length;
    const back = first > 0, on = first + C.page < total;
    if (hover.node === index && hover.pager && (hover.pager < 0 ? back : on)) rowBand(hover.pager < 0 ? x : x + half - 1, top, half + 1, hue, 0.55);
    ctx.fillStyle = tokens.cardRule; ctx.fillRect(x + C.pad, top, w - C.pad * 2, 1 / view.z);
    ctx.font = `600 12.5px ${tokens.mono}`;
    ctx.fillStyle = back && !dim ? tokens.text : tokens.faint; ctx.fillText('‹', x + C.pad, base);
    ctx.textAlign = 'right'; ctx.fillStyle = on && !dim ? tokens.text : tokens.faint; ctx.fillText('›', x + w - C.pad, base);
    ctx.textAlign = 'center'; ctx.font = `10.5px ${tokens.mono}`; ctx.fillStyle = tokens.muted;
    ctx.fillText(flowGraphPagerText(first, total), x + half, base); ctx.textAlign = 'left';
  }

  /** A card's header text cut to its width, once per card and font; its
   * rows are cut as their page is first drawn. Positions are from the card's
   * left edge. */
  function fitCard(item, w) {
    const C = FLOW_GRAPH_CARD;
    const targetX = C.pad + (item.siteW ? item.siteW + 12 : 0) + (item.opW ? item.opW + 10 : 0);
    ctx.font = `600 12.5px ${tokens.mono}`;
    const title = fitText(item.title, w - C.pad - item.pillW - 6 - item.badgeW - C.pad - 8);
    ctx.font = `11px ${tokens.mono}`;
    const location = fitText(item.location, w - C.pad * 2);
    return {w, title, location, rows: [], targetX};
  }
  /** Row `row` of a card cut to its room, in the row font. */
  function fitRow(fit, item, row) {
    if (fit.rows[row]) return fit.rows[row];
    const C = FLOW_GRAPH_CARD, entry = item.rows[row], {w, targetX} = fit;
    const countW = entry.count ? ctx.measureText(entry.count).width + 10 : 0, room = w - C.pad - countW - targetX;
    const target = fitText(entry.target, room), used = ctx.measureText(target).width + 10;
    const note = entry.note && room - used > 30 ? fitText(`; ${entry.note}`, room - used) : '';
    return (fit.rows[row] = {target, note, noteX: targetX + used, countX: w - C.pad - countW + 10});
  }

  /** Between the sketch and text zooms, each card keeps a legible name. */
  function drawScreenTitles() {
    ctx.font = `600 10.5px ${tokens.mono}`; ctx.textBaseline = 'middle';
    for (const index of shownCards) {
      const box = nodeBox(index), sx = (box.x - view.x) * view.z, sy = (box.y - view.y) * view.z, sw = box.w * view.z;
      if (sw < 28) continue;
      const node = display.nodes[index];
      ctx.fillStyle = node.status === 'resolved' && !dimmed(index) ? tokens.text : tokens.muted;
      // A name may run a little past a narrow card, into the gap beside it.
      ctx.fillText(fitText(card(index).title, sw - 10 + Math.min(24, 26 * view.z)), sx + 6, sy + Math.max(8, FLOW_GRAPH_CARD.head * view.z / 2));
    }
    ctx.textBaseline = 'alphabetic';
  }

  // Minimap ----------------------------------------------------------------
  const miniShown = () => minimapPref ?? cssW >= FLOW_GRAPH_MINIMAP_MIN_W;
  /** The minimap's box on the stage, while it shows. */
  const miniRect = () => (miniShown() && !host.hasAttribute('data-all-in-view') && minimap.offsetWidth
    ? {left: minimap.offsetLeft ?? cssW, top: minimap.offsetTop ?? cssH, w: minimap.offsetWidth, h: minimap.offsetHeight} : null);
  /** A canvas the size of the minimap's backing store. */
  function miniLayer(previous) {
    const layer = previous ?? document.createElement('canvas');
    layer.width = minimap.width; layer.height = minimap.height;
    return layer;
  }
  /** Strokes each route of `edges` (indexes, all when null) as its points,
   * one path per edge family. */
  function miniRoutes(g, edges, scale, ox, oy) {
    const P = layout.routes, S = layout.routeStart, paths = new Map();
    const add = e => {
      if (S[e] === S[e + 1]) return;
      const family = flowGraphEdgeFamily(display.edges[e]);
      if (!paths.has(family)) paths.set(family, []);
      paths.get(family).push(e);
    };
    if (edges) for (const e of edges) add(e); else for (let e = 0; e < display.edges.length; e += 1) add(e);
    paths.forEach((list, family) => {
      g.strokeStyle = tokens.edge[family] ?? tokens.edge.call; g.beginPath();
      for (const e of list) for (let i = S[e]; i < S[e + 1]; i += 1) { const px = ox + P[2 * i] * scale, py = oy + P[2 * i + 1] * scale; if (i === S[e]) g.moveTo(px, py); else g.lineTo(px, py); }
      g.stroke();
    });
  }
  function miniCards(g, indexes, scale, ox, oy) {
    for (const index of indexes) {
      if (!Number.isFinite(layout.x[index])) continue;
      g.fillStyle = tokens.kind[display.nodes[index].kind] ?? tokens.faint;
      g.fillRect(ox + layout.x[index] * scale, oy + layout.y[index] * scale, Math.max(1.5, layout.w[index] * scale), Math.max(1.5, layout.h[index] * scale));
    }
  }
  function drawMinimap() {
    // The minimap is for a graph larger than the view.
    const inView = view.x <= 0 && view.y <= 0 && view.x + cssW / view.z >= layout.width && view.y + cssH / view.z >= layout.height;
    host.toggleAttribute('data-all-in-view', inView);
    if (!miniCtx || !miniShown() || inView) return;
    // The minimap takes the graph's shape: a tall graph gets a tall column,
    // like a disassembler's overview, a wide one a short strip.
    const shape = layout.width / Math.max(1, layout.height), maxW = Math.max(72, Math.min(170, cssW * 0.16)), maxH = Math.max(80, Math.min(440, cssH * 0.55, cssH - topInset() - 40));
    const wantW = Math.round(Math.max(72, Math.min(maxW, maxH * shape))), wantH = Math.round(Math.max(60, Math.min(maxH, wantW / shape)));
    if (minimap.style.width !== `${wantW}px`) minimap.style.width = `${wantW}px`;
    if (minimap.style.height !== `${wantH}px`) minimap.style.height = `${wantH}px`;
    const mw = minimap.clientWidth || wantW, mh = minimap.clientHeight || wantH;
    if (!mw || !mh) return;
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    if (minimap.width !== Math.round(mw * ratio) || minimap.height !== Math.round(mh * ratio)) { minimap.width = Math.round(mw * ratio); minimap.height = Math.round(mh * ratio); miniKey = ''; }
    const scale = Math.min((mw - 12) / layout.width, (mh - 12) / layout.height), ox = (mw - layout.width * scale) / 2, oy = (mh - layout.height * scale) / 2;
    miniFit = {scale, ox, oy};
    // The base (bands, routes, cards) changes with the layout, the theme and
    // the size; what the lit stack, Find and the mark show is a layer over
    // it; the selection and the view box are drawn each frame.
    const key = `${mw}x${mh}@${ratio}`;
    if (key !== miniKey || miniBase?.layout !== layout || miniBase?.tokens !== tokens) {
      miniKey = key; miniHighlightKey = '';
      const canvasLayer = miniLayer(miniBase?.canvas), g = canvasLayer.getContext?.('2d');
      if (!g) return;
      miniBase = {canvas: canvasLayer, layout, tokens};
      g.setTransform(ratio, 0, 0, ratio, 0, 0); g.clearRect(0, 0, mw, mh);
      layout.lanes.forEach(lane => {
        const hue = realmHue(lane.key);
        g.globalAlpha = Math.min(1, tokens.alpha.band * 2); g.fillStyle = hue; g.fillRect(ox + lane.x * scale, oy + lane.y * scale, lane.w * scale, lane.h * scale);
        g.globalAlpha = Math.min(1, tokens.alpha.bandLine + 0.1); g.strokeStyle = hue; g.lineWidth = 1; g.strokeRect(ox + lane.x * scale, oy + lane.y * scale, lane.w * scale, lane.h * scale);
      });
      g.globalAlpha = 0.5; g.lineWidth = 1;
      miniRoutes(g, null, scale, ox, oy);
      miniCards(g, display.nodes.keys(), scale, ox, oy);
      g.globalAlpha = 1;
    }
    const lit = highlight || matches.length || markTarget;
    if (lit && (miniHighlightKey !== key || miniLit?.highlight !== highlight || miniLit?.matchSet !== matchSet || miniLit?.markTarget !== markTarget || miniLit?.base !== miniBase)) {
      miniHighlightKey = key;
      const canvasLayer = miniLayer(miniLit?.canvas), g = canvasLayer.getContext?.('2d');
      miniLit = {canvas: canvasLayer, highlight, matchSet, markTarget, base: miniBase};
      if (g) {
        g.setTransform(ratio, 0, 0, ratio, 0, 0); g.clearRect(0, 0, mw, mh);
        if (highlight) {
          // Off the lit stack everything recedes under a veil.
          g.globalAlpha = 0.62; g.fillStyle = tokens.bg; g.fillRect(0, 0, mw, mh);
          g.globalAlpha = 0.95; g.lineWidth = 1.6; miniRoutes(g, highlight.edges, scale, ox, oy);
          g.globalAlpha = 0.85; miniCards(g, highlight.nodes, scale, ox, oy);
        }
        g.globalAlpha = 1; g.lineWidth = 1.2;
        const ring = (index, color) => {
          if (!Number.isFinite(layout.x[index])) return;
          g.strokeStyle = color; g.strokeRect(ox + layout.x[index] * scale - 1, oy + layout.y[index] * scale - 1, Math.max(1.5, layout.w[index] * scale) + 2, Math.max(1.5, layout.h[index] * scale) + 2);
        };
        for (const index of matches) ring(index, tokens.accent);
        if (markTarget) ring(markTarget.index, tokens.mark);
      }
    }
    miniCtx.setTransform(1, 0, 0, 1, 0, 0); miniCtx.clearRect(0, 0, minimap.width, minimap.height); miniCtx.drawImage(miniBase.canvas, 0, 0);
    if (lit && miniLit) miniCtx.drawImage(miniLit.canvas, 0, 0);
    miniCtx.setTransform(ratio, 0, 0, ratio, 0, 0);
    if (selected >= 0 && Number.isFinite(layout.x[selected])) {
      miniCtx.globalAlpha = 1; miniCtx.strokeStyle = tokens.kind[display.nodes[selected].kind] ?? tokens.accent; miniCtx.lineWidth = 1.6;
      miniCtx.strokeRect(ox + layout.x[selected] * scale - 1.5, oy + layout.y[selected] * scale - 1.5, Math.max(1.5, layout.w[selected] * scale) + 3, Math.max(1.5, layout.h[selected] * scale) + 3);
    }
    // The view box, clipped to the graph so a view wider or taller than the
    // graph still shows as a box.
    const x0 = Math.max(ox - 3, ox + view.x * scale), y0 = Math.max(oy - 3, oy + view.y * scale);
    const x1 = Math.min(ox + layout.width * scale + 3, ox + (view.x + cssW / view.z) * scale), y1 = Math.min(oy + layout.height * scale + 3, oy + (view.y + cssH / view.z) * scale);
    const vx = Math.min(x0, x1 - 4), vy = Math.min(y0, y1 - 4), vw = Math.max(4, x1 - x0), vh = Math.max(4, y1 - y0);
    miniCtx.fillStyle = tokens.viewport; miniCtx.globalAlpha = 0.08; miniCtx.fillRect(vx, vy, vw, vh); miniCtx.globalAlpha = 1;
    miniCtx.strokeStyle = tokens.viewport; miniCtx.lineWidth = 1.5; miniCtx.strokeRect(vx + 0.75, vy + 0.75, Math.max(2, vw - 1.5), Math.max(2, vh - 1.5));
  }
  const miniPointer = {down: false};
  const miniJump = event => {
    if (!miniFit || !layout) return;
    const rect = minimap.getBoundingClientRect(), gx = (event.clientX - rect.left - miniFit.ox) / miniFit.scale, gy = (event.clientY - rect.top - miniFit.oy) / miniFit.scale;
    view.x = gx - cssW / view.z / 2; view.y = gy - cssH / view.z / 2; requestDraw();
  };
  minimap.addEventListener('pointerdown', event => { miniPointer.down = true; minimap.setPointerCapture?.(event.pointerId); miniJump(event); event.preventDefault(); });
  minimap.addEventListener('pointermove', event => { if (miniPointer.down) miniJump(event); });
  minimap.addEventListener('pointerup', () => { miniPointer.down = false; canvas.focus({preventScroll: true}); });

  // View -------------------------------------------------------------------
  /** Screen room the floating heading and tools take at the top. */
  const topInset = () => Math.max(56, (tools.offsetTop ?? 0) + (tools.offsetHeight ?? 0), (heading.offsetTop ?? 0) + (heading.offsetHeight ?? 0)) + 12;
  /** The zoom and position that show the whole graph under the heading,
   * centred: as small as that takes, since below the box zoom the session
   * is drawn as one block per realm, with room for the overview's gutters. */
  function fitted(cap = 1) {
    const inset = topInset(), room = Math.max(40, cssH - inset - 16);
    let side = {left: 0, right: 0}, z = Math.min(cap, (cssW - 32) / layout.width, room / layout.height);
    if (z < FLOW_GRAPH_BAND_ZOOM) { side = overviewGutters(); z = Math.min(cap, Math.max(16, cssW - 32 - side.left - side.right) / layout.width, room / layout.height); }
    return {z, x: (layout.width - (cssW - side.left - side.right) / z) / 2 - side.left / z, y: (layout.height - room / z) / 2 - inset / z};
  }
  /** The least zoom: the shared floor, or below it what fits the graph. */
  const zoomFloor = () => Math.min(GRAPH_ZOOM.min, layout && cssW > 1 ? fitted().z * 0.8 : GRAPH_ZOOM.min);
  /** Keeps the graph in view: no more than a margin of blank canvas past
   * its edges when it is larger than the view, and wholly inside it when it
   * is smaller. */
  function clampView() {
    if (!layout || cssW <= 1) return;
    const z = view.z, margin = 80, side = lodNow() < 0 ? overviewGutters() : {left: 0, right: 0}, inset = topInset();
    const clamp = (value, a, b) => Math.min(Math.max(value, Math.min(a, b)), Math.max(a, b));
    view.x = clamp(view.x, -(margin + side.left) / z, layout.width - (cssW - margin - side.right) / z);
    view.y = clamp(view.y, -inset / z, layout.height - (cssH - margin) / z);
  }
  /** The part of the stage a card can be shown in: under the heading, above
   * a Details sheet, and clear of the minimap. */
  function freeArea() {
    // In a narrow panel Details is a drawer over the right of the canvas.
    const drawer = detailsOpen && globalThis.getComputedStyle?.(inspector)?.position === 'absolute' ? inspector.offsetWidth ?? 0 : 0;
    const box = miniRect(), mini = box ? {w: box.w + 14, h: box.h + 14} : null;
    return {top: topInset(), bottom: cssH - 8, left: 8, right: cssW - drawer - 8, mini: drawer ? null : mini};
  }
  /** First view: the whole graph when its rows stay legible; else reading
   * size at the top of the first band, the full width in view when it fits,
   * so a tall session reads from its top down like a CFG. A card the left
   * edge would cut is shown whole. */
  function start() {
    if (!layout || cssW <= 1) { needsStart = true; return; }
    const whole = fitted();
    if (whole.z >= FLOW_GRAPH_TEXT_ZOOM) { view = whole; requestDraw(); return; }
    const room = Math.max(120, cssW - 32 - (miniShown() ? Math.max(72, Math.min(170, cssW * 0.16)) + 14 : 0)), first = layout.lanes[0];
    view.z = Math.min(1, room / layout.width);
    if (view.z >= FLOW_GRAPH_START_ZOOM) view.x = layout.width / 2 - (16 + room / 2) / view.z;
    else {
      view.z = FLOW_GRAPH_START_ZOOM;
      let best = -1;
      display.nodes.forEach((node, index) => {
        if (node.context !== first?.key || layout.layer[index] !== 0 || !Number.isFinite(layout.x[index])) return;
        if (best < 0 || (node.hits ?? 0) > (display.nodes[best].hits ?? 0)) best = index;
      });
      const at = best >= 0 ? layout.x[best] + layout.w[best] / 2 : layout.width / 2;
      view.x = Math.max(-16, Math.min(at - (16 + room / 2) / view.z, layout.width - cssW / view.z));
    }
    view.y = (first ? first.y : 0) - (topInset() + 4) / view.z;
    const edge = view.x + 8 / view.z, bottom = view.y + cssH / view.z;
    let left = Infinity;
    for (let index = 0; index < display.nodes.length; index += 1) {
      const x = layout.x[index];
      if (x < edge && x + layout.w[index] > edge && layout.y[index] < bottom && layout.y[index] + layout.h[index] > view.y) left = Math.min(left, x);
    }
    if (left < Infinity) view.x = left - 16 / view.z;
    requestDraw();
  }
  function fit() {
    if (!layout || cssW <= 1) return;
    view = fitted(1.2); requestDraw();
  }
  function zoomAt(factor, cx = cssW / 2, cy = cssH / 2) {
    const z = Math.min(GRAPH_ZOOM.max, Math.max(zoomFloor(), view.z * factor)), gx = view.x + cx / view.z, gy = view.y + cy / view.z;
    view = {x: gx - cx / z, y: gy - cy / z, z};
    hideTooltip();
    requestDraw();
  }
  function centerOn(index) {
    if (!Number.isFinite(layout?.x[index])) return;
    const box = nodeBox(index), area = freeArea();
    if (view.z < FLOW_GRAPH_TEXT_ZOOM) view.z = 0.95;
    const midX = (area.left + area.right - (area.mini ? area.mini.w : 0)) / 2, midY = (area.top + area.bottom) / 2;
    view.x = box.x + box.w / 2 - midX / view.z; view.y = box.y + Math.min(box.h, (area.bottom - area.top) / view.z * 0.6) / 2 - midY / view.z; requestDraw();
  }
  function ensureVisible(index) {
    if (!Number.isFinite(layout?.x[index])) return;
    const box = nodeBox(index), area = freeArea(), margin = 24;
    const sx = (box.x - view.x) * view.z, sy = (box.y - view.y) * view.z, sw = box.w * view.z, sh = Math.min(box.h, 120) * view.z;
    const underMini = area.mini && sx + sw > cssW - area.mini.w && sy + sh > area.bottom - area.mini.h;
    if (sx - margin < area.left || sy - margin < area.top || sx + sw + margin > area.right || sy + sh + margin > area.bottom || underMini || view.z < FLOW_GRAPH_SKETCH_ZOOM) centerOn(index);
    else requestDraw();
  }
  function showRealm(key) {
    const members = display ? display.nodes.map((node, index) => (node.context === key && Number.isFinite(layout.x[index]) ? index : -1)).filter(index => index >= 0) : [];
    if (members.length) { showCards(members); canvas.focus({preventScroll: true}); }
  }
  /** Fits a set of cards when they fit at a legible zoom and says so; else
   * shows the top of the set at reading size and returns false, so a caller
   * can centre the card that matters instead. */
  function showCards(indexes) {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const index of indexes) {
      if (!Number.isFinite(layout.x[index])) continue;
      const box = nodeBox(index); x0 = Math.min(x0, box.x); y0 = Math.min(y0, box.y); x1 = Math.max(x1, box.x + box.w); y1 = Math.max(y1, box.y + box.h);
    }
    if (x0 === Infinity) return false;
    const area = freeArea(), roomW = area.right - area.left - 32 - (area.mini ? area.mini.w : 0), roomH = area.bottom - area.top - 24;
    const z = Math.min(1, roomW / (x1 - x0 + 40), roomH / (y1 - y0 + 40));
    if (z >= 0.66) { view.z = z; view.x = (x0 + x1) / 2 - (area.left + roomW / 2 + 16) / z; view.y = (y0 + y1) / 2 - (area.top + roomH / 2 + 12) / z; requestDraw(); return true; }
    view.z = FLOW_GRAPH_START_ZOOM; view.x = (x0 + x1) / 2 - (area.left + roomW / 2 + 16) / view.z; view.y = y0 - (area.top + 24) / view.z;
    requestDraw();
    return false;
  }

  // Selection and the lit stack ---------------------------------------------
  /** The query of a renderer request's stacks. */
  const requestQuery = key => ({process_id: String(key.process), request_id: String(key.request)});
  /** The stacks that match `query`, from the backend (flow-graph-paths-v1):
   * its first page carries the cards and edges of every matching stack, which
   * is all the lit set needs. Answers are kept per generation. A graph that
   * moved on is read again, and the answer is asked for again then. */
  async function stackAnswer(query) {
    const key = new URLSearchParams(query).toString(), cached = stackAnswers.get(key);
    if (cached) { stackAnswers.delete(key); stackAnswers.set(key, cached); return cached; }
    const asked = model;
    const response = await fetch(`/api/flow-graph/paths?${new URLSearchParams({session_id: asked.session, generation: asked.doc.generation, ...query, limit: '1'})}`, {cache: 'no-store'});
    if (response.status === 409) { if (asked === model) load(true); throw Object.assign(Error('The graph changed; reading it again.'), {stale: true}); }
    if (!response.ok) {
      let detail = '';
      try { const body = await response.json(); detail = typeof body?.error === 'string' ? body.error : body?.error?.message ?? ''; } catch {}
      throw Error(detail || `The stacks route returned ${response.status}.`);
    }
    const answer = await response.json();
    if (answer?.schema !== 'flow-graph-paths-v1' || !Array.isArray(answer.nodes) || !Array.isArray(answer.edges)) throw Error('The stacks route returned an invalid answer.');
    if (asked !== model) throw Object.assign(Error('The graph changed while its stacks were read.'), {stale: true});
    stackAnswers.set(key, answer);
    if (stackAnswers.size > FLOW_GRAPH_PATH_CACHE) stackAnswers.delete(stackAnswers.keys().next().value);
    return answer;
  }
  /** Lights what `answer` walks; none clears the lit stack. */
  function applyAnswer(answer, label) {
    highlight = answer?.total ? {...flowGraphHighlight(display, answer), answer} : null;
    highlightLabel = highlight ? label : '';
    renderSelection(); requestDraw();
  }
  /** Lights the stacks through card `index`. The lit set before it stays
   * until they arrive. Resolves to the answer, or null when another
   * selection, a clear or a new graph came first. */
  async function lightStacks(index) {
    const node = display.nodes[index], token = ++stackToken;
    stacksPending = true;
    try {
      const answer = await stackAnswer({node: String(node.members[0])});
      if (token !== stackToken) return null;
      stacksPending = false;
      applyAnswer(answer, `${answer.total.toLocaleString()} ${answer.total === 1 ? 'stack passes' : 'stacks pass'} through ${flowGraphNodeName(node)}`);
      return answer;
    } catch (problem) {
      if (token === stackToken) { stacksPending = false; renderSelection(); if (!problem.stale) flash(`Could not read the stacks through this card. ${problem.message}`, 'error'); }
      return null;
    }
  }
  const stackCount = count => `${count.toLocaleString()} ${count === 1 ? 'stack' : 'stacks'}`;
  function renderSelection() {
    renderLineageButton();
    // A chosen request whose stack another selection replaced can be lit
    // again, unless it is known to have none.
    const known = requestKey ? stackAnswers.get(new URLSearchParams(requestQuery(requestKey)).toString()) : null;
    requestAgain.hidden = !(requestKey && !highlightFromRequest && (!known || known.total));
    if (selected < 0 || !display?.nodes[selected]) { if (!requestKey) setSelectionText(); return; }
    const node = display.nodes[selected], item = card(selected), row = selectedRow >= 0 ? item.rows[selectedRow] : null;
    const parts = [flowGraphNodeName(node)];
    if (row) parts.push(`${row.op} ${row.target}${row.note ? ` (${row.note})` : ''}`);
    else parts.push(item.location ?? flowGraphNodeDetail(node));
    parts.push(model.contexts[node.context]?.label.title ?? '');
    setSelectionText(parts.filter(Boolean).join(' · '), stacksPending ? 'reading its stacks…' : highlight ? stackCount(highlight.paths) : '');
  }
  function selectCard(index, {reveal = true, focusPaths = true, row = -1} = {}) {
    if (!display || index < 0 || index >= display.nodes.length) return;
    // A card outside the drawn lineage is shown in the session.
    if (lineageOn && !Number.isFinite(layout?.x[index])) leaveLineage();
    selected = index; selectedRow = row;
    if (row >= 0) showRow(index, row);
    // In the lineage every card drawn is on the lit stack, so a selection
    // there keeps it; Draw its lineage lights another.
    if (focusPaths && !lineageOn) { highlightFromRequest = false; lightStacks(index); }
    renderSelection(); renderInspector();
    if (reveal) ensureVisible(index); else requestDraw();
    notify();
  }
  function clearSelection() {
    selected = -1; selectedRow = -1; highlight = null; highlightLabel = ''; highlightFromRequest = false; setSelectionText();
    stackToken += 1; stacksPending = false;
    if (lineageOn) setLineage(false);
    renderSelection(); renderInspector(); requestDraw();
    notify();
  }

  // Lineage --------------------------------------------------------------------
  /** Draws the cards the lit stack walks alone, left to right, in place of
   * the session; off, the session returns with the selection in view. */
  function setLineage(on) {
    if (on === lineageOn) return;
    if (on && !highlight) { flash('Select a card or a request first: Lineage draws the stacks it lights'); return; }
    lineageOn = on;
    host.toggleAttribute('data-lineage', on);
    if (on) requestLineage();
    else {
      leaveLineage();
      if (selected >= 0) centerOn(selected); else start();
    }
    renderLineageButton(); renderEngine();
  }
  /** The session's layout in place of the lineage, the view left as is. */
  function leaveLineage() {
    lineageOn = false; lineageJob = 0; lineage = null; lineageFor = null;
    host.toggleAttribute('data-lineage', false);
    if (sessionLayout && layout !== sessionLayout) { layout = sessionLayout; labelSides = null; invalidateGeometry(); hover = noHover(); }
    renderLineageButton(); renderEngine();
  }
  function renderLineageButton() {
    lineageButton.setAttribute('aria-pressed', String(lineageOn));
    lineageButton.disabled = !lineageOn && !highlight;
  }
  /** Asks the pipeline to lay out the lit stack's cards and edges. */
  function requestLineage() {
    if (!lineageOn || !highlight || !display) return;
    lineageJob = ++jobs; lineageFor = highlight;
    pipeline.send({op: 'lineage', id: lineageJob, nodes: [...highlight.nodes].sort((a, b) => a - b), edges: [...highlight.edges].sort((a, b) => a - b)});
  }
  function landLineage({id, fold, layout: next}) {
    // A lineage of another fold is asked for again when that fold lands.
    if (id !== lineageJob || !lineageOn || fold !== shownFold || !display || next.x.length !== display.nodes.length) return;
    lineage = next; layout = lineage; labelSides = null; invalidateGeometry(); hover = noHover();
    renderEngine();
    const nodes = [...lineageFor.nodes];
    if (!showCards(nodes) && selected >= 0) { centerOn(selected); slideWithin(nodes); }
  }
  /** Moves the view the least that keeps it within the cards' bounds where
   * they are wider or taller than the free area, so the selected card it was
   * centred on stays in view while no side of the view is left empty. */
  function slideWithin(indexes) {
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const index of indexes) {
      if (!Number.isFinite(layout.x[index])) continue;
      const box = nodeBox(index); x0 = Math.min(x0, box.x); y0 = Math.min(y0, box.y); x1 = Math.max(x1, box.x + box.w); y1 = Math.max(y1, box.y + box.h);
    }
    if (x0 === Infinity) return;
    const area = freeArea(), pad = 24 / view.z;
    const left = view.x + area.left / view.z, right = view.x + (area.right - (area.mini ? area.mini.w : 0)) / view.z;
    const top = view.y + area.top / view.z, bottom = view.y + area.bottom / view.z;
    const slide = (from, to, low, high) => (to - from >= high - low + 2 * pad ? 0 : from < low - pad ? low - pad - from : to > high + pad ? high + pad - to : 0);
    view.x += slide(left, right, x0, x1);
    view.y += slide(top, bottom, y0, y1);
    requestDraw();
  }
  /** Lights the stacks through a card and draws their lineage. */
  async function drawLineageOf(index) {
    highlightFromRequest = false;
    selectCard(index, {reveal: false, focusPaths: false});
    if (!(await lightStacks(index))) return;
    if (lineageOn) requestLineage(); else setLineage(true);
  }

  /** Drops what only drawing needs while the view is hidden: the backing
   * stores, the minimap, the cards' text and the route and label caches.
   * Showing the view again sizes and fills them anew. */
  function releaseDrawing() {
    if (frame) { cancelAnimationFrame(frame); frame = 0; }
    canvas.width = 0; canvas.height = 0;
    minimap.width = 0; minimap.height = 0;
    miniBase = null; miniLit = null; miniKey = ''; miniHighlightKey = '';
    edgeFlat = []; edgeBounds = null; labelSides = null; edgeOrder = null;
    if (cards) cards = new Array(cards.length);
  }

  // Workspace API ---------------------------------------------------------------
  /** What a host is told about a card and its chosen row. A chain card is
   * keyed by its first member, and `select(key)` with any member's key finds
   * the chain. Realm facts come from the node's context. */
  function selectionInfo(index, rowIndex = -1) {
    const node = display?.nodes[index];
    if (!node || !model) return null;
    const context = model.contexts[node.context], first = model.nodes[node.members[0]], item = rowIndex >= 0 ? card(index).rows[rowIndex] : null;
    return {key: flowGraphNodeKey(node.kind === 'chain' ? first : node), kind: node.kind, name: flowGraphNodeName(node), location: flowGraphNodeLocation(node) || null,
      process_id: context?.process_id ?? null, execution_context_id: context?.execution_context_id ?? null, url: node.url ?? null, artifact_id: node.artifact_id ?? null,
      function_index: node.function_index ?? null, row: item ? {index: rowIndex, site: item.site, op: item.op, target: item.target} : null,
      request: highlightFromRequest && requestKey ? {process: requestKey.process, request: requestKey.request} : null,
      callers: cardNeighbours(index, true), callees: cardNeighbours(index, false)};
  }
  /** Every card on a drawn edge into (`incoming`) or out of a card, most
   * stacks first. */
  function cardNeighbours(index, incoming) {
    const seen = new Map();
    for (const e of (incoming ? display.ins : display.outs)[index]) {
      const edge = display.edges[e], other = incoming ? edge.from : edge.to;
      if (other === index) continue;
      const key = cardKey(other);
      const entry = seen.get(key) ?? {key, name: flowGraphNodeName(display.nodes[other]), kind: display.nodes[other].kind, note: edge.kind, count: 0};
      entry.count += edge.count ?? 1;
      seen.set(key, entry);
    }
    return [...seen.values()].sort((a, b) => b.count - a.count);
  }
  /** The key a host knows a card by: its first member's, for a chain. */
  const cardKey = index => flowGraphNodeKey(model.nodes[display.nodes[index].members[0]]);
  /** The selection as onSelect describes it, or null. */
  const currentInfo = () => (selected >= 0 ? selectionInfo(selected, selectedRow) : null);
  /** Tells the host when the selected card, row or lit request changed,
   * with `how` as its cause; 'silent' records it without telling. */
  function notify(how = cause ?? 'pick') {
    const request = highlightFromRequest && requestKey ? [requestKey.process, requestKey.request] : null;
    const signature = selected >= 0 ? JSON.stringify([cardKey(selected), selectedRow, request]) : '';
    if (signature === reported) return;
    reported = signature;
    if (how === 'silent' || typeof onSelect !== 'function') return;
    try { onSelect(currentInfo(), {cause: how}); } catch (problem) { console.error(problem); }
  }
  /** The model node with flowGraphNodeKey `key`, or -1. Its fixed fields
   * are compared before any key is built, so a lookup in a large graph
   * allocates almost nothing. */
  function modelIndexOfKey(key) {
    const parts = String(key).split('|');
    if (!model || parts.length < 8) return -1;
    const [kind, context] = parts, line = parts.at(-2), column = parts.at(-1);
    for (let v = 0; v < model.nodes.length; v += 1) {
      const node = model.nodes[v];
      if (node.kind !== kind || String(node.context) !== context || String(node.line ?? '') !== line || String(node.column ?? '') !== column) continue;
      if (flowGraphNodeKey(node) === key) return v;
    }
    return -1;
  }
  /** The card holding the model node with key `key`, or -1. */
  function indexOfKey(key) {
    if (!display || !model) return -1;
    keyIndex ??= new Map();
    const text = String(key);
    if (!keyIndex.has(text)) { const v = modelIndexOfKey(text); keyIndex.set(text, v >= 0 ? display.displayOf[v] : -1); }
    return keyIndex.get(text);
  }
  /** Selects the card that holds `key`; returns its info, or null. Before
   * the graph is drawn the key waits for it, and is applied then for the
   * host even when the call was silent, since it could not answer. */
  function selectKey(key, reveal) {
    if (key === null || key === undefined) return null;
    if (!layout || layingOut) { expect('key', {key: String(key), reveal, cause: 'host'}); return null; }
    const index = indexOfKey(key);
    if (index < 0) return null;
    selectCard(index, {reveal: false});
    if (reveal) centerOn(index);
    return currentInfo();
  }
  /** The card (and row) a timeline sample's {artifact_id, function_index,
   * offset} names: a Wasm function of that module and index, and its row
   * whose call site is at that module offset, when one is. */
  function findMark() {
    markTarget = null;
    if (!mark || !display) return;
    for (let index = 0; index < display.nodes.length && !markTarget; index += 1) {
      const node = display.nodes[index];
      const hit = node.members.findIndex(member => { const item = model.nodes[member]; return item?.kind === 'wasm' && String(item.artifact_id ?? '') === mark.artifact_id && Number(item.function_index) === mark.function_index; });
      if (hit < 0) continue;
      const rows = card(index).rows;
      let row = -1;
      if (node.kind === 'chain') row = hit < rows.length ? hit : -1;
      else if (mark.offset !== null) row = rows.findIndex(item => (item.members ?? []).some(edge => (model.edges[edge]?.sites ?? []).some(site => site.module_offset !== undefined && Number(site.module_offset) === mark.offset)));
      markTarget = {index, row};
      if (row >= 0) showRow(index, row);
    }
  }
  /** The request show() names, lit for the host once the graph is drawn;
   * none clears a stack it lit. */
  function showRequest(request) {
    if (!request) {
      if (intent?.request) expect('request', null);
      if (highlightFromRequest) clearSelection();
    } else if (layout && !layingOut) lightRequest(request);
    else expect('request', {reveal: true, cause: 'host'});
  }
  /** highlightRequest(request): resolves to the info of the card that made
   * the request once its stack is lit; null when it has no stack (the
   * selection clears) or the graph is not drawn yet (it is lit then). */
  function hostLightRequest(request, reveal) {
    if (!layout || layingOut) {
      requestKey = request;
      if (request) expect('request', {reveal, cause: 'host'});
      return Promise.resolve(null);
    }
    return lightRequest(request, {reveal}).then(lit => (lit ? currentInfo() : null));
  }
  function setMark(next) {
    mark = next && typeof next === 'object' && next.artifact_id !== undefined && next.artifact_id !== null && Number.isFinite(Number(next.function_index))
      ? {artifact_id: String(next.artifact_id), function_index: Number(next.function_index), offset: next.offset === undefined || next.offset === null || !Number.isFinite(Number(next.offset)) ? null : Number(next.offset)} : null;
    findMark(); requestDraw();
    return Boolean(markTarget);
  }
  function toggleChain(index) {
    const node = display?.nodes[index];
    if (!node) return;
    if (node.kind === 'chain') expanded.add(node.key);
    else {
      // A member of an expanded chain folds it again.
      const key = display.foldKey.get(node.members[0]);
      if (!key) return;
      expanded.delete(key);
    }
    // The selected card stays where it is on screen: an expanded chain's
    // first member takes the chain card's place.
    selected = index; rebuild();
  }
  /** Lights the stack of a renderer request {process, request}, read from
   * the backend, and selects the row that made it. Resolves to whether the
   * request has a stack here; the cause it was asked with reports it. */
  async function lightRequest(key, {reveal = true} = {}) {
    requestKey = key;
    if (!model || !display || !key) return false;
    const how = cause, token = ++stackToken;
    stacksPending = true; renderSelection();
    let answer;
    try { answer = await stackAnswer(requestQuery(key)); } catch (problem) {
      if (token === stackToken) { stacksPending = false; renderSelection(); if (!problem.stale) flash(`Could not read the request’s stack. ${problem.message}`, 'error'); }
      return false;
    }
    if (token !== stackToken || requestKey !== key || !display) return false;
    stacksPending = false;
    return as(how, () => showRequestStack(key, answer, reveal));
  }
  function showRequestStack(key, answer, reveal) {
    if (!answer.total) {
      // The previous request's stack must not stay lit for this one.
      clearSelection();
      requestKey = key; requestAgain.hidden = true;
      setSelectionText('The selected request has no recorded stack in this graph.');
      return false;
    }
    applyAnswer(answer, 'Stack of the selected request');
    highlightFromRequest = true;
    // The request is a row of the function that made it, or its own card
    // when nothing recorded calls it.
    const sinks = new Set(answer.nodes.filter(node => FLOW_GRAPH_SINKS.has(model.nodes[node]?.kind)));
    let target = null;
    for (const index of [...highlight.nodes].sort((a, b) => a - b)) {
      const row = card(index).rows.findIndex(item => item.sink && sinks.has(item.sink.members[0]));
      if (row >= 0) { target = {index, row}; break; }
    }
    if (!target) { const own = [...sinks].map(node => display.displayOf[node]).find(index => index >= 0); if (own !== undefined) target = {index: own, row: -1}; }
    if (target) selectCard(target.index, {focusPaths: false, row: target.row, reveal: false});
    // A new request draws its own lineage while Lineage is on; else the
    // whole stack is shown when it fits legibly, or its top.
    if (lineageOn) requestLineage();
    else if (reveal && !showCards([...highlight.nodes]) && target) centerOn(target.index);
    const caller = target ? display.nodes[target.index] : null, sink = target && target.row >= 0 ? card(target.index).rows[target.row] : null;
    setSelectionText([`Selected request${sink ? ` ${sink.target}` : ''}`, caller ? `← ${flowGraphNodeName(caller)} ${card(target.index).location}` : '', caller ? model.contexts[caller.context]?.label.title : ''].filter(Boolean).join(' · '),
      `${stackCount(highlight.paths)} · ${highlight.nodes.size.toLocaleString()} ${highlight.nodes.size === 1 ? 'card' : 'cards'}`);
    requestAgain.hidden = true;
    return true;
  }
  const canOpen = node => Boolean(node?.artifact_id && node.status === 'resolved' && !FLOW_GRAPH_SINKS.has(node.kind));
  function activate(index) {
    const node = display?.nodes[index];
    if (!node) return;
    if (node.kind === 'chain') toggleChain(index);
    // A Wasm function follows into the host's pane when it has one.
    else if (node.kind === 'wasm' && typeof onFollow === 'function') { try { onFollow(selectionInfo(index, index === selected ? selectedRow : -1)); } catch (problem) { console.error(problem); } }
    else if (canOpen(node)) open(node);
  }
  /** Follows a row's call to the card it reaches; Backspace comes back. */
  function follow(index, row) {
    const entry = card(index).rows[row], edge = display.edges[entry?.edge];
    if (!edge) { if (entry?.sink) setDetails(true); return; }
    if (edge.to === index) return;
    remember();
    selectCard(edge.to);
  }
  function remember() {
    if (selected >= 0) history.push({key: cardKey(selected), row: selectedRow, view: {...view}});
  }
  function back() {
    const entry = history.pop();
    if (!entry) { flash('Nothing to go back to'); return; }
    const index = indexOfKey(entry.key);
    if (index < 0) { back(); return; }
    view = {...entry.view}; selectCard(index, {reveal: false, row: entry.row});
  }
  /** Goes to the caller that reached this card most often. */
  function toCaller(index) {
    let best = -1;
    for (const e of display.ins[index]) if (display.edges[e].from !== index && (best < 0 || display.edges[e].count > display.edges[best].count)) best = e;
    if (best < 0) { flash('No recorded caller'); return; }
    remember();
    const caller = display.edges[best].from;
    selectCard(caller, {row: card(caller).rows.findIndex(row => row.edge === best)});
  }
  /** J and K step through the selected card's calls, paging with them. */
  function stepRow(direction) {
    if (selected < 0) return;
    const count = card(selected).rows.length;
    if (!count) return;
    const next = selectedRow < 0 ? (direction > 0 ? firstRow(selected) : Math.min(count, firstRow(selected) + FLOW_GRAPH_CARD.page) - 1) : Math.max(0, Math.min(count - 1, selectedRow + direction));
    if (next === selectedRow) return;
    selectCard(selected, {reveal: false, focusPaths: false, row: next});
  }
  function copy(text, what) {
    if (!text) return;
    const clipboard = globalThis.navigator?.clipboard;
    if (!clipboard?.writeText) { flash(`Copy is not available here. ${what}: ${text}`, 'error'); return; }
    clipboard.writeText(text).then(() => flash(`Copied ${what.toLowerCase()}`), () => flash(`Could not copy the ${what.toLowerCase()}`, 'error'));
  }

  // Find ---------------------------------------------------------------------
  /** Find runs in the pipeline over every card's names, file, host, folded
   * members and requests; its answer applies to the fold it was made for. */
  function applyFilter() {
    const needle = filter.value.trim();
    find.hidden = !needle;
    if (!needle || !display?.nodes.length) { findJob = 0; landMatches([]); return; }
    findJob = ++jobs;
    matchLabel.textContent = 'finding…';
    pipeline.send({op: 'find', id: findJob, needle});
  }
  function landFind({fold, matches: found}) {
    // A Find of another fold runs again when the fold on screen lands.
    if (fold === shownFold) landMatches(Array.from(found));
  }
  function landMatches(list) {
    matches = list; matchSet = new Set(list); matchIndex = -1;
    renderMatches(); requestDraw();
  }
  function renderMatches() {
    matchLabel.textContent = !matches.length ? 'no matches' : matchIndex < 0 ? `${matches.length.toLocaleString()} ${matches.length === 1 ? 'match' : 'matches'}` : `${(matchIndex + 1).toLocaleString()} of ${matches.length.toLocaleString()}`;
  }
  function stepMatch(direction) {
    if (!matches.length) return;
    matchIndex = (matchIndex + direction + matches.length) % matches.length;
    renderMatches();
    // A match is shown at reading size, and the other matches stay undimmed.
    selectCard(matches[matchIndex], {reveal: false}); centerOn(matches[matchIndex]);
  }
  let filterTimer = 0;
  filter.addEventListener('input', () => { clearTimeout(filterTimer); filterTimer = setTimeout(applyFilter, 120); });
  filter.addEventListener('keydown', event => {
    if (event.key === 'Enter' && matches.length) { event.preventDefault(); stepMatch(event.shiftKey ? -1 : 1); }
    else if (event.key === 'Escape' && filter.value) { event.stopPropagation(); filter.value = ''; applyFilter(); }
  });

  // Details -------------------------------------------------------------------
  // A rename redraws the cards and Details; the layout does not change.
  globalThis.RebWasmFunctionNames?.subscribe(() => { if (model) { requestDraw(); renderInspector(); } });
  /** Every item of a Details list, however many: a short list is built
   * whole, a long one only the rows scrolled into view. A row is one line,
   * cut with an ellipsis, its whole text in its title. */
  function longList(items, renderRow, label) {
    const ROW = FLOW_GRAPH_LIST_ROW, shown = 12;
    const scroller = make('div', 'flow-inspector-scroll'), list = make('ul', 'flow-inspector-list flow-inspector-rows');
    list.setAttribute('aria-label', label);
    scroller.append(list);
    const build = index => { const item = renderRow(items[index], index); item.dataset.index = String(index); item.title ||= item.textContent; return item; };
    if (items.length <= shown) { items.forEach((item, index) => list.append(build(index))); return scroller; }
    scroller.dataset.virtual = 'true';
    scroller.style.height = `${shown * ROW}px`; list.style.height = `${items.length * ROW}px`;
    let first = -1, pending = 0;
    const paint = () => {
      pending = 0;
      const top = Math.max(0, Math.floor(scroller.scrollTop / ROW) - 4), end = Math.min(items.length, top + shown + 8);
      if (top === first) return;
      first = top;
      // The row that had focus keeps it when it is still in view.
      const focused = list.contains(document.activeElement) ? document.activeElement.closest('li')?.dataset.index : null;
      const rows = [];
      for (let index = top; index < end; index += 1) {
        const item = build(index);
        item.style.top = `${index * ROW}px`; item.setAttribute('aria-posinset', String(index + 1)); item.setAttribute('aria-setsize', String(items.length));
        rows.push(item);
      }
      list.replaceChildren(...rows);
      if (focused !== null && focused !== undefined) list.querySelector(`li[data-index="${focused}"] button`)?.focus({preventScroll: true});
    };
    scroller.addEventListener('scroll', () => { if (!pending) pending = requestAnimationFrame(paint); }, {passive: true});
    paint();
    return scroller;
  }
  /** A Details row: a card link (or a plain name) and what is known of it. */
  function detailRow(name, meta, onPick = null, className = 'flow-inspector-sink') {
    const item = make('li');
    if (onPick) { const link = make('button', 'flow-inspector-link', name); link.type = 'button'; link.addEventListener('click', onPick); item.append(link); }
    else item.append(make('span', className, name));
    if (meta) item.append(make('span', 'flow-inspector-meta', meta));
    item.title = meta ? `${name} · ${meta}` : name;
    return item;
  }
  function renderInspector() {
    host.toggleAttribute('data-selected', selected >= 0);
    // F2 on the graph renames the selected Wasm function.
    const chosen = selected >= 0 ? display?.nodes[selected] : null;
    // After a save Details is redrawn, so focus returns to its new Rename
    // button, or the canvas when Details is closed.
    if (chosen?.kind === 'wasm' && chosen.sha256) globalThis.RebWasmFunctionNames?.mark(host, chosen.sha256, chosen.function_index, `${flowGraphNodeName(chosen)} · func ${chosen.function_index}`, nameHost,
      () => inspector.querySelector('[data-wasm-rename]') ?? canvas);
    else globalThis.RebWasmFunctionNames?.unmark(host);
    // Details is built only while it is open; opening it builds it.
    if (!detailsOpen) return;
    inspector.replaceChildren();
    if (!model) return;
    const close = button('Close', () => { setDetails(false); canvas.focus({preventScroll: true}); }, 'Hide details', 'flow-graph-tool flow-graph-inspector-close');
    inspector.append(close);
    if (selected < 0 || !display?.nodes[selected]) { renderOverview(); return; }
    const node = display.nodes[selected], context = model.contexts[node.context];
    const titleRow = make('div', 'flow-inspector-head');
    const tag = make('span', 'flow-kind-tag', FLOW_GRAPH_KIND_LABELS[node.kind] ?? node.kind); tag.dataset.kind = node.kind;
    titleRow.append(make('h3', 'flow-inspector-title', flowGraphNodeName(node)), tag);
    inspector.append(titleRow);
    const facts = make('dl', 'flow-inspector-facts');
    const fact = (label, value) => { if (value === undefined || value === null || value === '') return; facts.append(make('dt', '', label), make('dd', '', String(value))); };
    if (node.kind === 'chain') {
      fact('Folded', `${node.members.length.toLocaleString()} pass-through functions in one realm`);
      fact('Realm', `${context?.label.title ?? ''}\n${context?.label.detail ?? ''}`);
      inspector.append(facts);
      inspector.append(longList(node.members, (member, index) => detailRow(`${index + 1}. ${flowGraphNodeName(model.nodes[member])}`, flowGraphNodeDetail(model.nodes[member])), 'Folded functions'));
      const expand = make('button', 'secondary-button', 'Expand chain'); expand.type = 'button'; expand.addEventListener('click', () => { toggleChain(selected); canvas.focus({preventScroll: true}); });
      inspector.append(expand);
      return;
    }
    const foldable = display.foldKey.get(node.members[0]);
    if (!FLOW_GRAPH_SINKS.has(node.kind)) {
      fact('Location', node.url ?? null);
      if (node.line) fact('Line', `${node.line}:${node.column}${node.kind === 'eval' ? ` in VM${node.script_id}` : ''}`);
    }
    fact('Realm', `${context?.label.title ?? ''}\n${context?.label.detail ?? ''}`);
    if (node.kind === 'wasm') fact('Function index', node.function_index);
    const analyst = flowGraphAnalystName(node);
    if (analyst) { const value = make('dd'); value.append(globalThis.RebWasmFunctionNames.nameNode(analyst)); facts.append(make('dt', '', 'Researcher name'), value); }
    if (node.script_id !== undefined) fact('Script ID', node.kind === 'eval' ? `${node.script_id} (eval or new Function)` : node.script_id);
    fact('Records', `${node.hits.toLocaleString()} ${FLOW_GRAPH_SINKS.has(node.kind) ? (node.hits === 1 ? 'occurrence' : 'occurrences') : `stack ${node.hits === 1 ? 'record passes' : 'records pass'} through it`}`);
    fact('Distinct stacks', card(selected).stacks.toLocaleString());
    if (node.entries) fact('Task entry', `${node.entries.toLocaleString()} ${node.entries === 1 ? 'time' : 'times'}`);
    if (node.leaves) fact('Innermost', `${node.leaves.toLocaleString()} ${node.leaves === 1 ? 'time' : 'times'}`);
    if (node.schedules) fact('Scheduled', Object.entries(node.schedules).map(([task, count]) => `${REQUEST_STACK_TASKS[task] ?? task} ×${count.toLocaleString()}`).join(', '));
    if (node.chain_ends) fact('Chain starts', flowGraphChainEnds(node));
    if (node.status !== 'resolved') fact('Unresolved', FLOW_GRAPH_REASONS[node.reason] ?? node.reason);
    inspector.append(facts);
    if (node.chain_cut) inspector.append(make('p', 'flow-inspector-note', 'Earlier async callers were not recorded: a scheduling stack in its task chain was not retained, or a microtask hop names no recorded task.'));
    const actions = make('div', 'flow-inspector-actions');
    if (canOpen(node)) {
      const openButton = make('button', 'secondary-button', 'Open in Sources'); openButton.type = 'button';
      openButton.addEventListener('click', () => open(node)); actions.append(openButton);
    }
    if (node.kind === 'wasm' && node.sha256 && globalThis.RebWasmFunctionNames) {
      const rename = make('button', 'secondary-button', analyst ? 'Rename' : 'Name function'); rename.type = 'button'; rename.dataset.wasmRename = 'true';
      rename.title = 'Rename this Wasm function (F2)';
      rename.addEventListener('click', () => globalThis.RebWasmFunctionNames.beginFrom(host));
      actions.append(rename);
    }
    if (foldable) {
      const fold = make('button', 'secondary-button', 'Fold chain'); fold.type = 'button';
      fold.addEventListener('click', () => { toggleChain(selected); canvas.focus({preventScroll: true}); }); actions.append(fold);
    }
    if (actions.children.length) inspector.append(actions);
    const linked = incoming => (incoming ? display.ins : display.outs)[selected].map(index => display.edges[index]).filter(edge => edge.from !== edge.to);
    for (const [label, incoming] of [['Called by', true], ['Calls', false]]) {
      const items = linked(incoming).sort((a, b) => b.count - a.count);
      if (!items.length) continue;
      inspector.append(make('h4', 'flow-inspector-heading', `${label} · ${items.length.toLocaleString()}`));
      inspector.append(longList(items, edge => {
        const other = incoming ? edge.from : edge.to, sites = flowGraphEdgeSites(model, edge);
        const meta = [edge.kind === 'task' ? REQUEST_STACK_TASKS[edge.task] ?? edge.task : edge.kind, ...edge.crosses.map(cross => ({frame: 'frame boundary', language: 'JS ↔ Wasm', dynamic: 'into eval'})[cross]),
          ...(sites.length ? [`at ${sites.join(', ')}`] : []), `×${edge.count.toLocaleString()}`];
        return detailRow(flowGraphNodeName(display.nodes[other]), meta.join(' · '), () => { selectCard(other); canvas.focus({preventScroll: true}); });
      }, label));
    }
    const made = display.sinkRows?.[selected] ?? [];
    if (made.length) {
      inspector.append(make('h4', 'flow-inspector-heading', `Requests, navigations and cookie writes · ${made.length.toLocaleString()}`));
      inspector.append(longList([...made].sort((a, b) => b.count - a.count), row => {
        const sites = flowGraphEdgeSites(model, row);
        return detailRow(flowGraphNodeName(row.sink), [FLOW_GRAPH_KIND_LABELS[row.sink.kind] ?? row.sink.kind, ...(sites.length ? [`at ${sites.join(', ')}`] : []), `×${row.count.toLocaleString()}`].join(' · '));
      }, 'Requests, navigations and cookie writes'));
    }
  }

  function renderOverview() {
    const doc = model.doc;
    inspector.append(make('h3', 'flow-inspector-title', 'Realms'));
    const list = make('ul', 'flow-inspector-realms');
    model.contexts.forEach(context => {
      const item = make('li');
      const counts = Object.entries(context.counts ?? {}).map(([kind, count]) => `${count.toLocaleString()} ${FLOW_GRAPH_KIND_TAGS[kind] ?? kind}`).join(' · ');
      // A realm jumps to its cluster.
      const name = make('button', 'flow-inspector-link flow-inspector-realm', context.label.title); name.type = 'button';
      name.addEventListener('click', () => showRealm(context.index));
      const engine = sessionLayout?.engine?.realms?.find(entry => entry.key === context.index);
      const laidBy = engine?.engine === 'triskel' ? 'laid out by Triskel' : flowGraphLayoutReason(engine?.reason) ? `layered layout: ${flowGraphLayoutReason(engine.reason)}` : '';
      item.append(name, make('span', '', context.label.detail), make('span', 'flow-inspector-meta', counts));
      if (laidBy) item.append(make('span', 'flow-inspector-meta', laidBy));
      list.append(item);
    });
    inspector.append(list);
    const {frame, language, dynamic} = flowGraphCrossings(display);
    if (frame || language || dynamic) inspector.append(make('p', 'flow-inspector-note', `Crossings: ${frame.toLocaleString()} frame, ${language.toLocaleString()} JS ↔ Wasm, ${dynamic.toLocaleString()} into eval.`));
    const decoded = doc.stacks?.decoded ?? 0, distinct = doc.stacks?.distinct ?? 0;
    inspector.append(make('p', 'flow-inspector-note', `${(doc.stacks?.occurrences ?? 0).toLocaleString()} stack records, ${distinct.toLocaleString()} distinct, ${decoded.toLocaleString()} with retained frames.`));
    const unresolved = Object.entries(doc.stacks?.unresolved ?? {});
    if (unresolved.length) inspector.append(make('p', 'flow-inspector-note', `Not decoded: ${unresolved.map(([reason, count]) => `${count.toLocaleString()} ${reason.replaceAll('_', ' ')}`).join(', ')}.`));
    const notWalked = Object.entries(doc.stacks?.not_walked ?? {});
    if (notWalked.length) inspector.append(make('p', 'flow-inspector-note', `No script on the stack: ${notWalked.map(([reason, count]) => `${count.toLocaleString()} ${reason.replaceAll('_', ' ')}`).join(', ')}.`));
    inspector.append(make('h4', 'flow-inspector-heading', 'Not shown'));
    const missing = make('ul', 'flow-inspector-list'); (doc.not_shown ?? []).forEach(item => missing.append(make('li', '', item))); inspector.append(missing);
    inspector.append(make('p', 'flow-inspector-hint', 'Select a card to light every stack through it, and Lineage (V) to draw them alone. Choose a request above to light its own stack.'));
  }

  // Tooltip -------------------------------------------------------------------
  function hideTooltip() { tooltip.hidden = true; }
  /** The first sites of a list, and how many more there are. */
  const someSites = sites => `${sites.slice(0, 6).join(', ')}${sites.length > 6 ? ` and ${(sites.length - 6).toLocaleString()} more` : ''}`;
  function buildTooltip() {
    const facts = [];
    let heading = '', kind = '';
    if (hover.band >= 0) {
      const lane = layout.lanes[hover.band], context = model.contexts[lane.key]?.label, counts = bandOverview().lanes[hover.band];
      heading = context?.title ?? 'Realm'; kind = '';
      facts.push(['realm', context?.detail ?? '', '']);
      facts.push(['cards', counts.cards.toLocaleString(), 'count']);
      facts.push(['requests', counts.requests.toLocaleString(), 'count']);
      facts.push(['', 'click to show its cards', '']);
    } else if (hover.pager) return false;
    else if (hover.node >= 0 && hover.row < 0) {
      const node = display.nodes[hover.node], context = model.contexts[node.context]?.label;
      heading = flowGraphNodeName(node); kind = node.kind;
      facts.push(['kind', FLOW_GRAPH_KIND_LABELS[node.kind] ?? node.kind, 'kind']);
      const location = flowGraphNodeLocation(node);
      if (location && !FLOW_GRAPH_SINKS.has(node.kind)) facts.push(['at', location, 'location']);
      facts.push(['realm', `${context?.title ?? ''} · ${context?.detail ?? ''}`, '']);
      facts.push(['stacks', `${card(hover.node).stacks.toLocaleString()} distinct`, 'count']);
      facts.push(['records', `${(node.hits ?? 0).toLocaleString()}`, 'count']);
      if (card(hover.node).paged) facts.push(['calls', `${card(hover.node).rows.length.toLocaleString()}, paged on its last row`, 'count']);
      if (node.entries) facts.push(['task entry', node.entries.toLocaleString(), 'count']);
      if (node.status !== 'resolved') facts.push(['unresolved', FLOW_GRAPH_REASONS[node.reason] ?? node.reason ?? '', '']);
      if (node.chain_cut) facts.push(['callers', 'earlier async callers not recorded', '']);
      if (node.chain_ends) facts.push(['chain starts', flowGraphChainEnds(node), '']);
    } else if (hover.row >= 0 && card(hover.node).rows[hover.row]?.sink) {
      const row = card(hover.node).rows[hover.row], sink = row.sink, context = model.contexts[sink.context]?.label;
      heading = flowGraphNodeName(sink); kind = sink.kind;
      facts.push(['kind', FLOW_GRAPH_KIND_LABELS[sink.kind] ?? sink.kind, 'kind']);
      facts.push(['from', flowGraphNodeName(display.nodes[hover.node]), '']);
      if (row.site) facts.push(['site', someSites(flowGraphEdgeSites(model, {members: row.members})), 'location']);
      facts.push(['realm', context?.title ?? '', '']);
      facts.push(['seen', `${(sink.hits ?? 0).toLocaleString()} in this session, ${row.count ? row.count.slice(1) : '1'} from here`, 'count']);
    } else {
      const edgeIndex = hover.row >= 0 ? card(hover.node).rows[hover.row]?.edge : hover.edge, edge = display.edges[edgeIndex];
      if (!edge) { hideTooltip(); return false; }
      heading = `${edge.kind === 'task' ? REQUEST_STACK_TASKS[edge.task] ?? edge.task : edge.kind}`; kind = flowGraphEdgeFamily(edge);
      facts.push(['from', flowGraphNodeName(display.nodes[edge.from]), '']);
      facts.push(['to', flowGraphNodeName(display.nodes[edge.to]), '']);
      const note = flowGraphEdgeNote(model, display, edge);
      if (note) facts.push(['crosses', note, 'cross']);
      const sites = flowGraphEdgeSites(model, edge);
      if (sites.length) facts.push(['site', someSites(sites), 'location']);
      facts.push(['walked', `${edge.count.toLocaleString()} ${edge.count === 1 ? 'time' : 'times'}`, '']);
    }
    tooltip.replaceChildren();
    const head = make('strong', 'flow-graph-tooltip-title', heading); head.dataset.kind = kind; tooltip.append(head);
    const list = make('dl');
    for (const [label, value, tone] of facts) { const dd = make('dd', '', value); if (tone) dd.dataset.tone = tone; list.append(make('dt', '', label), dd); }
    tooltip.append(list);
    tooltip.hidden = false;
    return true;
  }
  /** Beside the card, at the row, so it never covers what it describes or
   * the callee about to be followed; at the pointer for an edge or a band. */
  function placeTooltip(px, py) {
    const tw = tooltip.offsetWidth || 240, th = tooltip.offsetHeight || 100;
    let left = px + 16, top = py + 18;
    if (hover.node >= 0) {
      const box = nodeBox(hover.node), right = (box.x + box.w - view.x) * view.z + 12, leftSide = (box.x - view.x) * view.z - 12 - tw;
      left = right + tw <= cssW - 8 ? right : leftSide >= 8 ? leftSide : left;
      top = ((hover.row >= 0 ? rowTop(hover.node, box, hover.row) : box.y) - view.y) * view.z - 4;
    }
    left = Math.max(8, Math.min(left, cssW - tw - 8)); top = Math.max(8, Math.min(top, cssH - th - 8));
    tooltip.style.left = `${left}px`; tooltip.style.top = `${top}px`;
  }

  // Context menu --------------------------------------------------------------
  let menuItems = [];
  function closeMenu(refocus = true) {
    if (menu.hidden) return;
    menu.hidden = true; menuItems = [];
    if (refocus) canvas.focus({preventScroll: true});
  }
  /** A call site as a researcher pastes it: file:line:column, or the module
   * and its offset. */
  function callSite(index, row) {
    const node = display.nodes[index], item = card(index).rows[row], site = item?.site?.replace(/\+\d+$/, '');
    if (!site) return '';
    const file = flowGraphNodeFile(node);
    return site.startsWith('+0x') ? `${file} ${site}`.trim() : `${file}:${site}`;
  }
  const hasCaller = index => display.ins[index].some(e => display.edges[e].from !== index);
  function openMenu(index, px, py, row = -1) {
    if (!display?.nodes[index]) return;
    if (selected !== index || selectedRow !== row) selectCard(index, {reveal: false, row, focusPaths: selected !== index});
    hideTooltip();
    const node = display.nodes[index], foldable = node.kind === 'chain' || display.foldKey.get(node.members[0]), item = row >= 0 ? card(index).rows[row] : null;
    // Each entry is [label, shortcut, enabled, action]; null is a rule.
    const entries = [];
    if (item) {
      if (item.edge >= 0) entries.push(['Follow call', '↩', true, () => follow(index, row)]);
      entries.push(['Copy call site', 'S', Boolean(callSite(index, row)), () => copy(callSite(index, row), 'Call site')], null);
    }
    entries.push(['Open in Sources', item ? 'O' : '↩', canOpen(node), () => open(node)]);
    if (foldable) entries.push([node.kind === 'chain' ? 'Expand chain' : 'Fold chain', 'Space', true, () => toggleChain(index)]);
    entries.push(null,
      ['Go to caller', 'U', hasCaller(index), () => toCaller(index)],
      ['Center on card', 'F', true, () => centerOn(index)],
      ['Draw its lineage', 'V', true, () => drawLineageOf(index)],
      ['Show details', 'I', true, () => setDetails(true)],
      null,
      ['Copy name', 'C', true, () => copy(flowGraphNodeName(node), 'Name')],
      ['Copy location', 'L', Boolean(flowGraphNodeLocation(node)), () => copy(flowGraphNodeLocation(node), 'Location')]);
    menu.replaceChildren(); menuItems = [];
    for (const entry of entries) {
      if (!entry) { const rule = make('div', 'flow-graph-menu-rule'); rule.setAttribute('role', 'separator'); menu.append(rule); continue; }
      const [label, shortcut, enabled, action] = entry;
      const menuItem = make('button', 'flow-graph-menu-item'); menuItem.type = 'button'; menuItem.setAttribute('role', 'menuitem'); menuItem.tabIndex = -1; menuItem.disabled = !enabled;
      menuItem.append(make('span', '', label), make('kbd', '', shortcut));
      menuItem.addEventListener('click', () => { closeMenu(); action(); });
      menu.append(menuItem);
      if (enabled) menuItems.push({item: menuItem, shortcut, action});
    }
    menu.hidden = false;
    const mw = menu.offsetWidth || 220, mh = menu.offsetHeight || 220;
    menu.style.left = `${Math.max(6, Math.min(px, cssW - mw - 6))}px`; menu.style.top = `${Math.max(6, Math.min(py, cssH - mh - 6))}px`;
    menuItems[0]?.item.focus({preventScroll: true});
  }
  menu.addEventListener('keydown', event => {
    const at = menuItems.findIndex(entry => entry.item === document.activeElement);
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); const next = (at + (event.key === 'ArrowDown' ? 1 : -1) + menuItems.length) % menuItems.length; menuItems[next]?.item.focus(); }
    else if (event.key === 'Home' || event.key === 'End') { event.preventDefault(); menuItems[event.key === 'Home' ? 0 : menuItems.length - 1]?.item.focus(); }
    else if (event.key === 'Escape' || event.key === 'Tab') { event.preventDefault(); event.stopPropagation(); closeMenu(); }
    else if (event.key.length === 1 && !event.metaKey && !event.ctrlKey) {
      const entry = menuItems.find(item => item.shortcut.toLowerCase() === event.key.toLowerCase());
      if (entry) { event.preventDefault(); closeMenu(); entry.action(); }
    }
  });
  menu.addEventListener('focusout', event => { if (!menu.contains(event.relatedTarget)) closeMenu(false); });

  // Input ----------------------------------------------------------------------
  const toGraph = (px, py) => [view.x + px / view.z, view.y + py / view.z];
  /** What is under a point: in the overview a band; else a card of the last
   * frame (its row, or its pager's half), else an edge of the last frame. */
  function hitTest(px, py) {
    const miss = noHover();
    if (!layout || !display) return miss;
    const [gx, gy] = toGraph(px, py), lod = lodNow();
    if (lod < 0) {
      const band = layout.lanes.findIndex(lane => gx >= lane.x && gx <= lane.x + lane.w && gy >= lane.y && gy <= lane.y + lane.h);
      return {...miss, band};
    }
    for (let i = shownCards.length - 1; i >= 0; i -= 1) {
      const index = shownCards[i], box = nodeBox(index);
      if (!(gx >= box.x && gx <= box.x + box.w && gy >= box.y && gy <= box.y + box.h)) continue;
      const item = card(index), slot = Math.floor((gy - slotTop(box, 0)) / FLOW_GRAPH_CARD.row);
      if (lod < 2 || slot < 0) return {...miss, node: index};
      if (item.paged && slot === FLOW_GRAPH_CARD.page) return {...miss, node: index, pager: gx < box.x + box.w / 2 ? -1 : 1};
      const row = firstRow(index) + slot, entry = slot < FLOW_GRAPH_CARD.page ? item.rows[row] : null;
      return {...miss, node: index, row: entry && (entry.edge >= 0 || entry.sink) ? row : -1};
    }
    if (view.z < 0.25) return miss;
    const bounds = boundsOfEdges(), tolerance = 5 / view.z;
    let best = -1, bestDistance = tolerance;
    for (const e of shownEdges) {
      const at = e * 4;
      if (gx < bounds[at] - tolerance || gx > bounds[at + 2] + tolerance || gy < bounds[at + 1] - tolerance || gy > bounds[at + 3] + tolerance) continue;
      const points = flatRoute(e);
      for (let i = 2; i < points.length; i += 2) {
        const ax = points[i - 2], ay = points[i - 1], bx = points[i], by = points[i + 1], dx = bx - ax, dy = by - ay, length = dx * dx + dy * dy;
        const t = length ? Math.max(0, Math.min(1, ((gx - ax) * dx + (gy - ay) * dy) / length)) : 0;
        const distance = Math.hypot(gx - ax - t * dx, gy - ay - t * dy);
        if (distance < bestDistance) { bestDistance = distance; best = e; }
      }
    }
    return {...miss, edge: best};
  }
  /** Whether the pointer is over something a press acts on. */
  const pressable = hit => hit.band >= 0 || hit.row >= 0 || hit.edge >= 0
    || (hit.pager !== 0 && (hit.pager < 0 ? firstRow(hit.node) > 0 : firstRow(hit.node) + FLOW_GRAPH_CARD.page < card(hit.node).rows.length));
  const pointer = {down: false, x: 0, y: 0, moved: false};
  const local = event => { const rect = canvas.getBoundingClientRect(); return [event.clientX - rect.left, event.clientY - rect.top]; };
  canvas.addEventListener('pointerdown', event => {
    if (event.button === 2) return;
    pointer.down = true; pointer.x = event.clientX; pointer.y = event.clientY; pointer.moved = false;
    canvas.setPointerCapture?.(event.pointerId); canvas.focus({preventScroll: true}); hideTooltip(); closeMenu(false);
  });
  canvas.addEventListener('pointermove', event => {
    if (!layout) return;
    if (pointer.down) {
      if (Math.abs(event.clientX - pointer.x) + Math.abs(event.clientY - pointer.y) > 2) pointer.moved = true;
      view.x -= (event.clientX - pointer.x) / view.z; view.y -= (event.clientY - pointer.y) / view.z; pointer.x = event.clientX; pointer.y = event.clientY; requestDraw();
      return;
    }
    const [px, py] = local(event), next = hitTest(px, py);
    const changed = next.node !== hover.node || next.row !== hover.row || next.edge !== hover.edge || next.pager !== hover.pager || next.band !== hover.band;
    hover = next;
    canvas.style.cursor = pressable(next) ? 'pointer' : '';
    if (next.node < 0 && next.edge < 0 && next.band < 0) hideTooltip();
    else if (menu.hidden && (changed || tooltip.hidden)) { if (buildTooltip()) placeTooltip(px, py); else hideTooltip(); }
    else if (menu.hidden && next.node < 0) placeTooltip(px, py);
    if (changed) requestDraw();
  });
  canvas.addEventListener('pointerleave', () => { if (pointer.down) return; hover = noHover(); hideTooltip(); requestDraw(); });
  canvas.addEventListener('pointerup', event => {
    if (!pointer.down) return;
    pointer.down = false;
    if (pointer.moved || !layout) return;
    const [px, py] = local(event), hit = hitTest(px, py);
    if (hit.band >= 0) { showRealm(layout.lanes[hit.band].key); return; }
    if (hit.pager) { setPage(hit.node, firstRow(hit.node) + hit.pager * FLOW_GRAPH_CARD.page); return; }
    if (hit.node >= 0) { selectCard(hit.node, {reveal: false, row: hit.row}); return; }
    if (hit.edge >= 0) { const edge = display.edges[hit.edge]; selectCard(edge.from, {reveal: false, row: card(edge.from).rows.findIndex(row => row.edge === hit.edge)}); return; }
    clearSelection();
  });
  canvas.addEventListener('dblclick', event => {
    const [px, py] = local(event), hit = hitTest(px, py);
    if (hit.node < 0 || hit.pager) return;
    if (hit.row >= 0) follow(hit.node, hit.row); else activate(hit.node);
  });
  canvas.addEventListener('contextmenu', event => {
    const [px, py] = local(event), hit = hitTest(px, py);
    if (hit.node < 0) return;
    event.preventDefault();
    openMenu(hit.node, px, py, hit.row);
  });
  canvas.addEventListener('wheel', event => {
    if (!layout) return;
    event.preventDefault(); hideTooltip(); closeMenu(false);
    if (event.ctrlKey || event.metaKey) { const [px, py] = local(event); zoomAt(Math.exp(-event.deltaY * 0.01), px, py); }
    else { view.x += event.deltaX / view.z; view.y += event.deltaY / view.z; requestDraw(); }
  }, {passive: false});
  /** The drawn card at the top left, which the first arrow key selects. */
  function topLeftCard() {
    let first = -1;
    for (let index = 0; index < display.nodes.length; index += 1) {
      if (!Number.isFinite(layout.x[index])) continue;
      if (first < 0 || layout.y[index] < layout.y[first] || (layout.y[index] === layout.y[first] && layout.x[index] < layout.x[first])) first = index;
    }
    return first;
  }
  function move(dx, dy) {
    if (!display?.nodes.length) return;
    if (selected < 0 || !Number.isFinite(layout.x[selected])) { const first = topLeftCard(); if (first >= 0) selectCard(first); return; }
    const from = nodeBox(selected), cx = from.x + from.w / 2, cy = from.y + from.h / 2;
    let best = -1, bestScore = Infinity;
    for (let index = 0; index < display.nodes.length; index += 1) {
      if (index === selected || !Number.isFinite(layout.x[index])) continue;
      const ddx = layout.x[index] + layout.w[index] / 2 - cx, ddy = layout.y[index] + layout.h[index] / 2 - cy;
      const along = dx ? ddx * dx : ddy * dy, across = dx ? Math.abs(ddy) : Math.abs(ddx);
      if (along <= 1) continue;
      const score = along + across * 2.5;
      if (score < bestScore) { bestScore = score; best = index; }
    }
    if (best >= 0) selectCard(best);
  }
  const ARROWS = Object.freeze({ArrowDown: [0, 1], ArrowUp: [0, -1], ArrowLeft: [-1, 0], ArrowRight: [1, 0]});
  function pan(dx, dy) {
    view = {...view, x: view.x + dx * 80 / view.z, y: view.y + dy * 80 / view.z};
    requestDraw();
  }
  /** Enter: follow the chosen call, as in a disassembler; on the card itself,
   * open the function or expand the chain. */
  function followOrActivate() {
    if (selectedRow >= 0 && card(selected).rows[selectedRow]?.edge >= 0) follow(selected, selectedRow);
    else activate(selected);
  }
  function openMenuAtSelection() {
    if (!Number.isFinite(layout.x[selected])) return;
    const box = nodeBox(selected), rowY = selectedRow >= 0 ? rowTop(selected, box, selectedRow) + FLOW_GRAPH_CARD.row : box.y + 24;
    openMenu(selected, (box.x + Math.min(box.w, 140) - view.x) * view.z, (rowY - view.y) * view.z, selectedRow);
  }
  function focusFind() {
    filter.focus();
    filter.select();
  }
  function toggleMinimap() {
    minimapPref = !miniShown();
    host.toggleAttribute('data-minimap-off', !minimapPref);
    requestDraw();
  }
  function clearOrClose() {
    if (selected >= 0 || highlight) clearSelection();
    else setDetails(false);
  }
  /** What a key does on the canvas, or null when it does nothing here and
   * goes on to the host. Letters are the same with Shift; Command, Control
   * and Option belong to the app, except Option+Left. */
  function keyAction(event) {
    const key = event.key, chosen = selected >= 0;
    if (key === 'ArrowLeft' && event.altKey) return back;
    if (key === 'ContextMenu' || (key === 'F10' && event.shiftKey)) return chosen ? openMenuAtSelection : null;
    if (event.metaKey || event.ctrlKey || event.altKey) return null;
    if (ARROWS[key]) return event.shiftKey ? () => pan(...ARROWS[key]) : () => move(...ARROWS[key]);
    switch (key.length === 1 ? key.toLowerCase() : key) {
      case 'Backspace': return back;
      case 'Escape': return chosen || highlight || detailsOpen ? clearOrClose : null;
      case '+': case '=': return () => zoomAt(1.25);
      case '-': case '_': return () => zoomAt(0.8);
      case '0': return fit;
      case '/': return focusFind;
      case 'i': return () => setDetails(!detailsOpen);
      case 'm': return toggleMinimap;
      case 'v': return highlight || lineageOn ? () => setLineage(!lineageOn) : null;
      case ' ': return chosen ? () => toggleChain(selected) : null;
      case 'Enter': return chosen ? followOrActivate : null;
      case 'j': return chosen ? () => stepRow(1) : null;
      case 'k': return chosen ? () => stepRow(-1) : null;
      case 'u': return chosen ? () => toCaller(selected) : null;
      case 'f': return chosen ? () => centerOn(selected) : null;
      case 'o': return chosen && canOpen(display.nodes[selected]) ? () => open(display.nodes[selected]) : null;
      case 's': return chosen && selectedRow >= 0 ? () => copy(callSite(selected, selectedRow), 'Call site') : null;
      case 'c': return chosen ? () => copy(flowGraphNodeName(display.nodes[selected]), 'Name') : null;
      case 'l': return chosen ? () => copy(flowGraphNodeLocation(display.nodes[selected]), 'Location') : null;
      default: return null;
    }
  }
  canvas.addEventListener('keydown', event => {
    // The host's chords are its own, checked before any of the canvas's.
    if (!layout || hostKeys(event)) return;
    hideTooltip();
    // An open key closes before Escape does anything else.
    if (event.key === 'Escape' && status.hasAttribute('data-key-open')) {
      setKey(false);
      event.preventDefault();
      event.stopPropagation();
      return;
    }
    const action = keyAction(event);
    if (!action) return;
    event.preventDefault();
    event.stopPropagation();
    action();
  });

  return {
    /** Shows the view for one session; loads it the first time or when the session changes. */
    show({session: next, request = null, stacks = null}) {
      const wasVisible = visible;
      visible = true; host.hidden = false;
      // Tokens change only with the theme, which the observers above follow.
      if (!tokensRead) readTokens();
      const changed = String(next ?? '') !== String(session ?? ''), first = session === null;
      session = next ?? null;
      if (changed) {
        // What was read for the last session is not this one's.
        pipeline.send({op: 'abort'});
        loadJob = foldJob = shownFold = ++jobs; incoming = null; packedFold = null; reading = false; requested = null; layingOut = false; foldedDuringLoad = false;
        model = null; display = null; cards = null; layout = null; sessionLayout = null; lineage = null; lineageOn = false; lineageFor = null; overview = null;
        selected = -1; selectedRow = -1; highlight = null; highlightFromRequest = false; keyIndex = null; markTarget = null;
        stackAnswers.clear(); stackToken += 1; stacksPending = false; pages.clear(); history.length = 0;
        host.toggleAttribute('data-lineage', false); renderLineageButton(); setBanner(null); refresh.disabled = false;
        // The previous session's function is no longer selected: F2 must not
        // rename it.
        globalThis.RebWasmFunctionNames?.unmark(host);
        status_ = 'idle';
        // A key asked for before the first session waits for it; what was
        // asked for in another session does not carry over, and this
        // session's request is lit afresh.
        if (!first) intent = null;
        shownRequest = '';
        as('host', notify);
      }
      // Evidence polls re-render Flow; only a newly chosen request moves
      // the highlight, so a card the researcher picked stays lit.
      const requestText = request ? `${request.process}:${request.request}` : '';
      const newRequest = requestText !== shownRequest;
      shownRequest = requestText;
      requestKey = request;
      // The stage's size is the ResizeObserver's, except as the view appears.
      if (!wasVisible) resize();
      // Polls call show() often. An empty or failed graph asks again only
      // when the view reopens or the host has seen more stacks (Refresh and
      // Retry ask at once), and a read already running is left to finish.
      hostStacks = stacks;
      const settled = status_ === 'empty' || status_ === 'error';
      const more = stacks !== null && loadedStacks !== null && stacks > loadedStacks;
      if (settled && (!wasVisible || more)) load(true);
      else if (!model && !settled) load();
      if (newRequest) as('host', () => showRequest(request));
    },
    /** Hides the view. A read or layout in flight runs on in the pipeline
     * and lands while hidden, so showing the view again draws at once. */
    hide() {
      visible = false; host.hidden = true;
      hideTooltip(); closeMenu(false);
      releaseDrawing();
    },
    focus() { canvas.focus({preventScroll: true}); },
    // The setters act for the host: a change they make is never a pick. By
    // default they are silent, and their return value is the answer.
    /** Selects (and by default centres) the card that holds `key`, a
     * flowGraphNodeKey(); returns its info, or null when it is not in the
     * graph or the graph is not drawn yet. */
    select: (key, {reveal = true, silent = true} = {}) => as(silent ? 'silent' : 'host', () => selectKey(key, reveal)),
    /** Lights the stack of a renderer request {process, request}; resolves
     * to the info of the card that made it, or null. */
    highlightRequest: (request, {reveal = true, silent = true} = {}) => as(silent ? 'silent' : 'host', () => hostLightRequest(request, reveal)),
    /** Marks the Wasm card (and row) a timeline sample points to, apart from
     * the selection; null clears it. Says whether a card took the mark. */
    setMark: next => as('silent', () => setMark(next)),
    /** The selection as onSelect last described it, or null. */
    selection: currentInfo,
    /** Re-measures the stage after the host resized it. */
    resize: () => resize()
  };
}
