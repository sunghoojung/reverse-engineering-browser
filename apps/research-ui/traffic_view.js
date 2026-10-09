/* Body views consume explicit capture states. Missing bytes are never inferred from a URL. */
const TRAFFIC_BODY_LIMIT = 128 * 1024;
const TRAFFIC_TREE_LIMIT = 1000;
const TRAFFIC_PREVIEW_DEPTH = 24;
// Rebuild a presentation-only tree. Never attach the captured tree to a live document.
const TRAFFIC_PREVIEW_TAGS = new Set(('a abbr article aside b bdi bdo blockquote br button caption code col colgroup dd del details div dl dt em fieldset figcaption figure footer h1 h2 h3 h4 h5 h6 header hr i input label legend li main mark nav ol option p pre s section select small span strong sub summary sup table tbody td textarea th thead time tr u ul').split(' '));
const TRAFFIC_PREVIEW_STYLES = ('color background-color font-family font-size font-style font-weight line-height text-align text-decoration white-space overflow-wrap word-break display margin margin-top margin-right margin-bottom margin-left padding padding-top padding-right padding-bottom padding-left border border-color border-style border-width border-radius width max-width min-width height max-height min-height').split(' ');

function trafficHtmlPreview(text) {
  const template = document.createElement('template');
  template.innerHTML = text;
  const output = document.createElement('div');
  let count = 0;
  let limited = false;
  function copy(source, target, depth) {
    if (++count > TRAFFIC_TREE_LIMIT || depth > TRAFFIC_PREVIEW_DEPTH) { limited = true; return; }
    if (source.nodeType === Node.TEXT_NODE) { target.append(document.createTextNode(source.textContent)); return; }
    if (source.nodeType !== Node.ELEMENT_NODE || source.namespaceURI !== 'http://www.w3.org/1999/xhtml') return;
    const tag = source.localName;
    if (tag === 'img') {
      target.append(trafficNode('span', '', `[Image omitted${source.getAttribute('alt') ? ': ' + source.getAttribute('alt') : ''}]`));
      return;
    }
    // Forms keep their static layout, but no submission or captured actions survive.
    if (tag !== 'form' && !TRAFFIC_PREVIEW_TAGS.has(tag)) return;
    const node = document.createElement(tag === 'form' ? 'div' : tag);
    for (const attribute of ['title', 'lang', 'dir', 'value']) {
      const value = source.getAttribute(attribute);
      if (value !== null && value.length <= 1024) node.setAttribute(attribute, value);
    }
    for (const attribute of ['colspan', 'rowspan']) {
      const value = source.getAttribute(attribute);
      if (/^[1-9][0-9]?$/.test(value ?? '') && Number(value) <= 64) node.setAttribute(attribute, value);
    }
    if (['button', 'input', 'select', 'textarea', 'option', 'fieldset'].includes(tag)) node.setAttribute('disabled', '');
    // Simple presentation values and numeric colors only: no URLs, escapes,
    // custom properties, positioning, animation, or external stylesheets.
    for (const property of TRAFFIC_PREVIEW_STYLES) {
      const value = source.style.getPropertyValue(property);
      const simple = /^[a-zA-Z0-9\s#%.,/-]+$/.test(value);
      const color = ['color', 'background-color', 'border-color'].includes(property) && /^(?:rgba?|hsla?)\([0-9\s%.,/+-]+\)$/.test(value);
      const bounded = [...value.matchAll(/\d+(?:\.\d+)?/g)].every(match => Number(match[0]) <= 4096);
      if (value.length <= 256 && bounded && (simple || color)) node.style.setProperty(property, value);
    }
    target.append(node);
    for (const child of source.childNodes) {
      if (count >= TRAFFIC_TREE_LIMIT) { limited = true; break; }
      copy(child, node, depth + 1);
    }
  }
  for (const child of template.content.childNodes) {
    if (count >= TRAFFIC_TREE_LIMIT) { limited = true; break; }
    copy(child, output, 0);
  }
  const policy = "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'";
  return {
    limited,
    // Retained elements can paint through borders or backgrounds without text.
    empty: !output.textContent.trim() && output.childElementCount === 0,
    document: '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="' + policy + '">' +
      '<style>html{color-scheme:light}body{margin:16px;background:#fff;color:#202124;font:14px/1.5 system-ui,sans-serif;overflow-wrap:anywhere}' +
      '*{box-sizing:border-box;max-width:100%}pre{white-space:pre-wrap}table{border-collapse:collapse}td,th{padding:4px 8px;border:1px solid #ddd}' +
      'a{color:#185abc;text-decoration:underline}input,button,select,textarea{pointer-events:none}</style></head><body>' + output.innerHTML + '</body></html>'
  };
}
function trafficTargetParts(request) {
  const target = String(request?.path ?? '').trim();
  if (request?.hostOnly) return {name: target || 'Unknown host', host: 'Host-only metadata'};
  try {
    const url = new URL(target);
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) throw new TypeError('Not a network URL');
    return {name: `${url.pathname || '/'}${url.search}`, host: url.host};
  } catch {
    return {name: target || 'Unidentified request', host: ''};
  }
}

const TRAFFIC_TYPE_LABELS = Object.freeze({xhr: 'Fetch/XHR', doc: 'Document', css: 'CSS', js: 'Script',
  font: 'Font', img: 'Image', media: 'Media', socket: 'WebSocket', wasm: 'Wasm', other: 'Other'});
function trafficTypeLabel(type) {
  return Object.hasOwn(TRAFFIC_TYPE_LABELS, type) ? TRAFFIC_TYPE_LABELS[type] : 'Other';
}

// Keep table labels compact; filters and tooltips retain the full type names.
const TRAFFIC_TABLE_TYPE_LABELS = Object.freeze({xhr: 'XHR/F', doc: 'Doc', css: 'CSS', js: 'JS',
  font: 'Font', img: 'Img', media: 'Media', socket: 'WS', wasm: 'Wasm'});
function trafficTableTypeLabel(type) {
  return Object.hasOwn(TRAFFIC_TABLE_TYPE_LABELS, type) ? TRAFFIC_TABLE_TYPE_LABELS[type] : 'Other';
}

function trafficTimeLabel(time) {
  if (typeof time !== 'number' || !Number.isFinite(time)) return time === 'pending' ? '—' : String(time ?? '—');
  if (time < 1) return `${time.toFixed(2)} ms`;
  if (time < 100) return `${time.toFixed(1)} ms`;
  if (time < 1000) return `${Math.round(time)} ms`;
  return `${(time / 1000).toFixed(2)} s`;
}

// The broker retains 5,000 events. A separately paged ledger never mounts more
// than 500 rows; filters and sorting still inspect the whole retained window.
const TRAFFIC_ROW_LIMIT = 500;
const TRAFFIC_RETAINED_LIMIT = 5000;
function trafficTimeValue(request) {
  if (typeof request.time === 'number' && Number.isFinite(request.time)) return request.time;
  const milliseconds = /^(\d+(?:\.\d+)?) ms$/.exec(String(request.time));
  return milliseconds && Number.isFinite(Number(milliseconds[1])) ? Number(milliseconds[1]) : null;
}
function trafficSortedRequests(requests, key = 'capture', direction = 1) {
  if (key === 'capture') return requests;
  const value = request => key === 'name' ? trafficTargetParts(request).name
    : key === 'time' ? trafficTimeValue(request)
      : key === 'status' ? /^\d+$/.test(String(request.status)) ? Number(request.status) : null
        : key === 'type' ? trafficTypeLabel(request.type) : request.method;
  // Precompute URL/type keys once; stable ties retain evidence order.
  return requests.map((request, index) => ({request, index, value: value(request)})).sort((a, b) => {
    if (a.value === null || b.value === null) return a.value === b.value ? a.index - b.index : a.value === null ? 1 : -1;
    const comparison = typeof a.value === 'number' ? a.value - b.value : String(a.value).localeCompare(String(b.value));
    return comparison * direction || a.index - b.index;
  }).map(entry => entry.request);
}

function trafficWindow(requests, start, anchor = null) {
  const found = anchor === null ? -1 : requests.findIndex(request => request.id === anchor);
  const offset = Math.max(0, Math.min(found < 0 ? start : found, Math.max(0, requests.length - TRAFFIC_ROW_LIMIT)));
  return {start: offset, rows: requests.slice(offset, offset + TRAFFIC_ROW_LIMIT)};
}

function renderTrafficRows(container, requests, {selectedId, newIds, matches, onSelect, onKey}) {
  requests = requests.slice(0, TRAFFIC_ROW_LIMIT);
  const previousRows = new Map([...container.querySelectorAll('.request-row')].map(row => [row.dataset.requestId, row]));
  const focused = document.activeElement;
  const focusedId = container.contains(focused) ? focused.dataset.requestId : null;
  const scrollTop = container.scrollTop;
  const anchor = [...previousRows.values()].find(row => row.offsetTop + row.offsetHeight > scrollTop);
  const anchorOffset = anchor ? anchor.offsetTop - scrollTop : 0;
  const selectedVisible = requests.some(request => request.id === selectedId);
  const rows = requests.map((request, index) => {
    const match = matches?.get(request.id);
    let row = previousRows.get(String(request.id));
    if (!row) {
      row = trafficNode('button', 'request-row'); row.type = 'button';
      row.setAttribute('role', 'option'); row.dataset.requestId = request.id;
      row.addEventListener('click', () => onSelect(row.dataset.requestId));
      row.addEventListener('keydown', onKey);
      row.addEventListener('animationend', () => row.classList.remove('is-new'));
      row.addEventListener('animationcancel', () => row.classList.remove('is-new'));
      if (newIds.has(request.id) && (typeof matchMedia !== 'function' || !matchMedia('(prefers-reduced-motion: reduce)').matches)) row.classList.add('is-new');
    }
    const key = JSON.stringify([request.path, request.method, request.status, request.time,
      request.type, request.origin, request.hostOnly, request.failed, request.targetKind, request.operation, match?.label]);
    // Reuse the row itself on lifecycle changes, preserving focus and its single
    // arrival animation. Unchanged rows do not rebuild captured text children.
    if (row.dataset.renderKey !== key) {
      row.dataset.renderKey = key;
      row.dataset.origin = request.origin;
      row.dataset.targetKind = request.targetKind ?? 'unknown';
      row.dataset.pending = String(request.status === 'pending' && !request.failed);
      const target = trafficTargetParts(request);
      const name = trafficNode('span', 'request-name');
      name.title = `${trafficOriginLabel(request)} · ${request.method} ${request.path} · network · ${request.operation ?? 'sample'} · request ${request.id}${request.hostOnly ? ' · URL path and query not captured' : ''}`;
      name.append(trafficNode('span', 'request-resource', target.name),
        trafficNode('span', 'request-host', `${target.host}${match ? ' · ' + match.label : ''}`));
      const numericStatus = Number(request.status);
      const status = trafficNode('span', request.failed || numericStatus >= 400 ? 'status-error'
        : numericStatus >= 200 ? 'status-ok' : 'status-neutral', request.failed ? 'Failed' : request.status === 'pending' ? 'Pending' : String(request.status));
      status.title = request.failed ? 'Request failed. Inspect the retained response state for details.'
        : request.status === 'pending' ? 'No terminal lifecycle event has been captured.' : `HTTP status ${request.status}`;
      const type = trafficNode('span', 'request-type', trafficTableTypeLabel(request.type));
      type.title = trafficTypeLabel(request.type);
      row.replaceChildren(name, status, type,
        trafficNode('span', 'request-method', request.method), trafficNode('span', 'request-time', trafficTimeLabel(request.time)));
      row.setAttribute('aria-label', `${trafficOriginLabel(request)} ${request.hostOnly ? 'host-only metadata' : 'request'}: ${request.method} ${request.path}, ${status.textContent}, ${trafficTimeLabel(request.time)}, ${request.operation ?? 'network'}, request ${request.id}${match ? ', match in ' + match.label : ''}`);
    }
    row.setAttribute('aria-selected', String(request.id === selectedId));
    row.tabIndex = request.id === selectedId || !selectedVisible && index === 0 ? 0 : -1;
    return row;
  });
  rows.forEach((row, index) => {
    const current = container.children[index];
    if (current !== row) container.insertBefore(row, current ?? null);
  });
  while (container.children.length > rows.length) container.lastElementChild.remove();
  const restored = anchor && rows.find(row => row.dataset.requestId === anchor.dataset.requestId);
  container.scrollTop = restored ? restored.offsetTop - anchorOffset : scrollTop;
  if (focusedId && document.activeElement !== focused) (rows.find(row => row.dataset.requestId === focusedId) ?? rows[0] ?? container).focus({preventScroll: true});
  container.tabIndex = rows.length ? -1 : 0;
}

const sampleExchanges = {
  '78': {
    request: {state: 'empty', headers: [['accept', 'application/json']]},
    response: {state: 'available', mime: 'application/json', headers: [['content-type', 'application/json']],
      text: JSON.stringify({profile: {id: 'demo-user-42', preferences: {language: 'en-US', currency: 'USD'}}, features: ['saved-cart', 'express-checkout']})}
  },
  '79': {request: {state: 'empty', headers: [['accept', 'text/javascript']]}, response: {state: 'empty', reason: '304 Not Modified has no response body.', headers: [['etag', '"demo-cart-v3"']]}},
  '80': {
    request: {state: 'empty', headers: [['accept', 'application/json'], ['accept-language', 'en-US']]},
    response: {state: 'available', mime: 'application/json', headers: [['content-type', 'application/json; charset=utf-8'], ['cache-control', 'max-age=300']],
      text: JSON.stringify({version: 3, collection: {canvas: true, audio: true, webgl: false}, sampling: {rate: 0.25, interval: 5000}, endpoints: ['/events', '/sessions'], policy: {mode: 'metadata', excluded: ['cookies', 'authorization']}, publicConfigId: 'demo_' + 'a7f309bd'.repeat(36)})}
  },
  '81': {
    request: {state: 'available', mime: 'application/json', headers: [['content-type', 'application/json'], ['accept', 'application/json']],
      text: JSON.stringify({cart: {items: [{sku: 'A14', qty: 1}], coupon: null}, device: {locale: 'en-US', fingerprint: 'N2Y0YTFjZj'}})},
    response: {state: 'available', mime: 'application/json', headers: [['content-type', 'application/json'], ['location', '/cart/demo-8e11']],
      text: JSON.stringify({id: 'demo-8e11', status: 'created', items: [{sku: 'A14', qty: 1, price: {amount: 2499, currency: 'USD'}}], total: {amount: 2499, currency: 'USD'}, messages: []})}
  }
};

function trafficExchange(request) {
  if (request?.origin === 'sample' && Object.hasOwn(sampleExchanges, request.id)) return sampleExchanges[request.id];
  if (request?.exchange) return request.exchange;
  const responseEmpty = request && (request.method === 'HEAD' || [204, 205, 304].includes(Number(request.status)));
  return {
    request: {state: 'missing'},
    response: responseEmpty ? {state: 'empty', reason: 'This HTTP response has no body.'} : {state: 'missing'}
  };
}

// Bound transient case folding to 8 million UTF-16 units per search. Search the
// newest scoped records first and report omitted records instead of false negatives.
const TRAFFIC_SEARCH_LIMIT = 8 * 1024 * 1024;
function trafficSearchRequests(requests, needle, includeContent) {
  const matches = new Map();
  let remaining = TRAFFIC_SEARCH_LIMIT;
  let inspected = 0;
  let omitted = 0;
  for (let index = requests.length - 1; index >= 0; index -= 1) {
    const request = requests[index];
    if (!needle || `${request.method} ${request.path} ${request.status}`.toLowerCase().includes(needle)) {
      matches.set(request.id, {label: 'URL / method / status'});
    }
    if (!needle || !includeContent) continue;
    const exchange = trafficExchange(request);
    const records = ['Request', 'Response'].map(side => {
      const record = exchange[side.toLowerCase()];
      const bytes = record?.bytes instanceof Uint8Array;
      const mime = (record?.mime ?? '').split(';')[0].trim().toLowerCase();
      const body = record?.state === 'available' && (!bytes || /^text\/|json|javascript|xml/.test(mime));
      return {side, record, bytes, body};
    });
    // Preflight before decoding bytes or joining headers, including records we
    // omit. The search budget bounds work as well as temporary string storage.
    const size = records.reduce((total, {record, bytes, body}) => total +
      (record?.headers ?? []).reduce((sum, [name, value]) => sum + name.length + value.length + 1, 0) +
      (body ? bytes ? Math.min(record.bytes.length, TRAFFIC_BODY_LIMIT) : (record.text ?? '').length : 0), 0);
    if (size > remaining) { omitted += 1; continue; }
    remaining -= size;
    inspected += 1;
    if (matches.has(request.id)) continue;
    const fields = [];
    for (const {side, record, bytes, body} of records) {
      for (const [name, value] of record?.headers ?? []) {
        fields.push({side, mode: 'headers', label: `${side} header`, text: `${name} ${value}`});
      }
      if (!body) continue;
      const text = bytes ? new TextDecoder().decode(record.bytes.subarray(0, TRAFFIC_BODY_LIMIT)) : record.text ?? '';
      fields.push({side, mode: 'raw', label: `${side} body`, text});
    }
    const field = fields.find(candidate => candidate.text.toLowerCase().includes(needle));
    if (field) matches.set(request.id, {side: field.side, mode: field.mode, label: field.label});
  }
  return {matches, inspected, omitted};
}

// Format lexical tokens so large numbers, duplicate keys, and escape sequences survive.
function trafficPrettyJson(text) {
  const tokens = text.match(/"(?:\\.|[^"\\])*"|[^\s{}\[\],:]+|[{}\[\],:]/g) || [];
  let depth = 0;
  let output = '';
  const newline = () => '\n' + '  '.repeat(depth);
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token === '{' || token === '[') {
      if (++depth > 24) return {text, limited: true};
      output += token;
      if (tokens[index + 1] !== '}' && tokens[index + 1] !== ']') output += newline();
    } else if (token === '}' || token === ']') {
      depth = Math.max(0, depth - 1);
      if (tokens[index - 1] !== '{' && tokens[index - 1] !== '[') output += newline();
      output += token;
    } else if (token === ',') output += ',' + newline();
    else if (token === ':') output += ': ';
    else output += token;
    if (output.length > TRAFFIC_BODY_LIMIT * 4) return {text, limited: true};
  }
  return {text: output, limited: false, compact: tokens.join('')};
}

function trafficBodyModel(record, side) {
  const messages = {
    missing: `${side} body was not captured.`,
    empty: `No ${side.toLowerCase()} body.`,
    redacted: `${side} body was redacted.`,
    loading: `Loading ${side.toLowerCase()} body…`,
    error: `${side} body could not be loaded.`
  };
  if (!record || record.state !== 'available') {
    return {message: record?.reason || messages[record?.state] || messages.missing};
  }
  const bytes = record.bytes instanceof Uint8Array ? record.bytes : new TextEncoder().encode(record.text ?? '');
  const bounded = bytes.subarray(0, TRAFFIC_BODY_LIMIT);
  const truncated = bytes.length > bounded.length || record.truncated === true;
  const mime = (record.mime || 'text/plain').split(';')[0].trim().toLowerCase();
  const binary = record.bytes instanceof Uint8Array && !/^text\/|json|javascript|xml/.test(mime);
  const text = binary ? Array.from({length: Math.ceil(bounded.length / 16)}, (_, row) => {
    const chunk = bounded.subarray(row * 16, row * 16 + 16);
    return `${(row * 16).toString(16).padStart(8, '0')}  ${Array.from(chunk, byte => byte.toString(16).padStart(2, '0')).join(' ').padEnd(47)}  ${Array.from(chunk, byte => byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '.').join('')}`;
  }).join('\n') : new TextDecoder().decode(bounded);
  let json;
  let malformed = false;
  let treeSafe = false;
  let formatted;
  if (/json/.test(mime) && !truncated) {
    try { json = JSON.parse(text); } catch { malformed = true; }
    if (!malformed) {
      formatted = trafficPrettyJson(text);
      try { treeSafe = formatted.compact === JSON.stringify(json); } catch { treeSafe = false; }
    }
  }
  return {text, json, treeSafe, formatted, binary, malformed, truncated, mime, bytes: bytes.length};
}

function trafficNode(tag, className, text) {
  const node = document.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function trafficOriginLabel(request) {
  return request?.origin === 'sample' ? 'Sample data'
    : request?.origin === 'demo' ? 'Demo evidence'
      : request?.exchange ? 'Live CDP capture'
        : request?.origin === 'live' ? 'Live metadata' : 'Local evidence';
}

function createTrafficPane(side, record, request, onDecode, onTrace, searchMatch = null, view = null) {
  const pane = trafficNode('section', 'exchange-pane');
  pane.dataset.origin = request?.origin ?? 'none';
  pane.setAttribute('aria-label', `${side} content`);
  const header = trafficNode('div', 'exchange-pane-head');
  header.append(trafficNode('strong', '', side));
  const controls = trafficNode('div', 'exchange-controls');
  controls.hidden = true;
  const tabs = trafficNode('div', 'exchange-tabs');
  tabs.setAttribute('role', 'tablist'); tabs.setAttribute('aria-label', `${side} view`);
  const bodyModel = value => view === 'headers' ? {message: 'Headers'} : trafficBodyModel(value, side);
  let model = bodyModel(record);
  const htmlResponse = side === 'Response' && record?.mime?.split(';')[0].trim().toLowerCase() === 'text/html';
  const mode = {value: searchMatch?.side === side ? searchMatch.mode : view === 'headers' ? 'headers' : view === 'response' ? 'raw' : view === 'preview' && htmlResponse ? 'preview' : 'formatted'};
  const modes = view === 'headers' ? [['headers', 'Headers']]
    : view === 'preview' ? [[htmlResponse ? 'preview' : 'formatted', 'Preview']]
      : view === 'response' ? [['raw', 'Raw'], ['formatted', 'Formatted']]
        : [['query', 'Query'], ['formatted', 'Body'], ['raw', 'Raw']];
  const tabButtons = modes.map(([value, label]) => {
    const button = trafficNode('button', 'exchange-tab', label); button.type = 'button';
    button.setAttribute('role', 'tab'); button.setAttribute('aria-selected', String(value === mode.value));
    button.tabIndex = value === mode.value ? 0 : -1;
    button.addEventListener('click', () => { mode.value = value; render(); });
    tabs.append(button); return button;
  });
  tabs.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const index = tabButtons.indexOf(event.target);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabButtons.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabButtons.length) % tabButtons.length;
    tabButtons[next].click(); tabButtons[next].focus();
  });
  header.append(tabs);
  const options = trafficNode('details', 'exchange-options');
  const optionsTitle = trafficNode('summary', '', '⋯');
  optionsTitle.setAttribute('aria-label', `${side} viewer options`);
  optionsTitle.title = `${side} viewer options`;
  const menu = trafficNode('div', 'exchange-options-menu');
  const find = trafficNode('button', 'exchange-button', 'Find'); find.type = 'button';
  find.addEventListener('click', () => { controls.hidden = !controls.hidden; options.open = false; if (!controls.hidden) search.focus(); });
  const tree = trafficNode('button', 'exchange-button', 'JSON tree'); tree.type = 'button';
  tree.setAttribute('aria-pressed', 'false');
  let treeMode = view === 'preview' && model.treeSafe;
  tree.addEventListener('click', () => { treeMode = !treeMode; tree.setAttribute('aria-pressed', String(treeMode)); renderedMode = undefined; options.open = false; mode.value = 'formatted'; render(); });
  const search = trafficNode('input', 'exchange-search');
  search.type = 'search'; search.placeholder = 'Find in body'; search.setAttribute('aria-label', `Find in ${side.toLowerCase()}`);
  if (searchMatch?.side === side) { search.value = searchMatch.query; controls.hidden = false; }
  const wrap = trafficNode('button', 'exchange-button', 'Wrap');
  wrap.type = 'button'; wrap.setAttribute('aria-pressed', 'true');
  const copy = trafficNode('button', 'exchange-button', 'Copy body'); copy.type = 'button';
  const closeSearch = trafficNode('button', 'exchange-button', 'Done'); closeSearch.type = 'button';
  closeSearch.addEventListener('click', () => { search.value = ''; controls.hidden = true; render(); optionsTitle.focus(); });
  search.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    event.preventDefault(); event.stopPropagation(); closeSearch.click();
  });
  controls.append(search, closeSearch);
  menu.append(find, tree, wrap, copy); options.append(optionsTitle, menu); header.append(options);
  const meta = trafficNode('div', 'exchange-meta'); meta.setAttribute('role', 'status');
  const content = trafficNode('div', 'exchange-content'); content.tabIndex = 0;
  content.setAttribute('aria-label', `${side} body viewer`);
  const selection = trafficNode('div', 'exchange-selection'); selection.hidden = true;
  let wrapping = true;
  let renderedMode;
  let renderedSearch;
  async function copyText(value, button) {
    const original = button.textContent;
    try { await navigator.clipboard.writeText(value); button.textContent = 'Copied'; }
    catch { button.textContent = 'Copy unavailable'; }
    setTimeout(() => { button.textContent = original; }, 1600);
  }
  tree.setAttribute('aria-pressed', String(treeMode));
  tree.disabled = !model.treeSafe;
  tree.title = model.treeSafe ? 'Explore JSON values' : 'Body preserves original literal forms; tree is unavailable.';
  copy.textContent = model.binary ? 'Copy hex' : model.truncated ? 'Copy preview' : 'Copy body';
  copy.disabled = model.text === undefined;
  copy.addEventListener('click', () => copyText(model.text, copy));
  wrap.addEventListener('click', () => {
    wrapping = !wrapping; wrap.setAttribute('aria-pressed', String(wrapping));
    content.classList.toggle('no-wrap', !wrapping);
  });
  function selectValue(path, value, row, descriptor = null) {
    content.querySelectorAll('[aria-pressed]').forEach(node => node.setAttribute('aria-pressed', String(node === row)));
    selection.hidden = false;
    const pathLabel = trafficNode('span', 'exchange-value-path', path); pathLabel.title = path;
    const valueText = typeof value === 'string' ? value : JSON.stringify(value);
    const valueCopy = trafficNode('button', 'exchange-button', 'Copy value'); valueCopy.type = 'button';
    valueCopy.addEventListener('click', () => copyText(valueText, valueCopy));
    const decode = trafficNode('button', 'exchange-button', 'Decode'); decode.type = 'button';
    decode.addEventListener('click', () => onDecode(valueText, {side, path}));
    const close = trafficNode('button', 'exchange-button', 'Close'); close.type = 'button';
    close.addEventListener('click', () => { selection.hidden = true; row.setAttribute('aria-pressed', 'false'); row.focus(); });
    const full = trafficNode('pre', 'exchange-selected-value', valueText);
    full.tabIndex = 0;
    const trace = trafficNode('button', 'exchange-button', 'Trace value'); trace.type = 'button';
    trace.disabled = side !== 'Request' || request?.urlTruncated || !descriptor || typeof value !== 'string' ||
      new TextEncoder().encode(value).length > 4096 || !descriptor.selector ||
      new TextEncoder().encode(descriptor.selector).length > 256;
    trace.title = trace.disabled ? 'Select one complete request string in a JSON field or unique query parameter (up to 4 KiB).' : 'Inspect evidence and test this value in an isolated replay';
    trace.addEventListener('click', () => onTrace({...descriptor, value, label: path, request}));
    selection.replaceChildren(pathLabel, valueCopy, decode, ...(side === 'Request' ? [trace] : []), close, full);
  }
  function render(preservePosition = false) {
    const query = search.value.toLowerCase();
    if (renderedMode === mode.value && renderedSearch === query) return;
    renderedMode = mode.value; renderedSearch = query;
    selection.hidden = true;
    const scrollTop = content.scrollTop;
    const contentFocused = content.contains(document.activeElement);
    content.replaceChildren();
    content.scrollTop = 0;
    // Finish restoration after this synchronous render, including early returns.
    if (preservePosition) queueMicrotask(() => {
      if (!pane.isConnected) return;
      content.scrollTop = scrollTop;
      if (contentFocused) content.focus({preventScroll: true});
    });
    tabButtons.forEach((button, index) => {
      const selected = modes[index][0] === mode.value;
      button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1;
    });
    copy.hidden = !['formatted', 'raw'].includes(mode.value);
    options.hidden = mode.value === 'preview';
    if (mode.value === 'preview') options.open = false;
    content.classList.toggle('showing-html-preview', mode.value === 'preview');
    search.placeholder = mode.value === 'headers' ? 'Find header' : mode.value === 'query' ? 'Find parameter' : 'Find in body';
    meta.textContent = model.message ? trafficOriginLabel(request) : `${request?.origin === 'sample' ? 'Sample · ' : request?.origin === 'demo' ? 'Demo · ' : request?.origin === 'live' ? 'Live · ' : ''}${model.mime} · ${model.bytes.toLocaleString()} bytes${model.binary ? ' · Hex view' : ''}${model.truncated ? ' · Truncated: showing first 128 KiB or retained prefix' : ''}${model.malformed ? ' · Invalid JSON: showing text' : ''}${model.formatted?.limited ? ' · Formatting limit: showing raw text' : ''}`;
    function message(text) {
      const prefix = request?.exchange ? 'Live capture: '
        : request?.origin === 'live' ? 'Live metadata only: '
          : request?.origin === 'demo' ? 'Demo evidence: ' : '';
      content.append(trafficNode('div', 'exchange-empty', `${prefix}${text}`));
    }
    if (mode.value === 'headers' || mode.value === 'query') {
      let rows = record?.headers;
      if (mode.value === 'query') {
        // The live event contract retains the host only. Do not claim its query was empty.
        try { rows = request?.origin === 'sample' || request?.exchange && !request.hostOnly
          ? [...new URL(request.path, 'https://checkout.acme.test').searchParams] : undefined; } catch { rows = undefined; }
      }
      meta.textContent = rows ? `${rows.length} ${mode.value === 'headers' ? 'headers' : 'parameters'} · ${request?.origin === 'sample' ? 'sample data' : request?.origin === 'demo' ? 'demo evidence' : request?.origin === 'live' ? 'live metadata' : 'captured'}` : 'Not captured';
      if (mode.value === 'headers' && record?.headersTruncated) meta.textContent += ' · truncated: only retained header names/values are shown';
      if (!rows) return message(`${mode.value === 'headers' ? side + ' headers were' : 'Query parameters were'} not captured.`);
      const matches = rows.filter(([key, value]) => `${key} ${value}`.toLowerCase().includes(query));
      const nameCounts = new Map();
      for (const [name] of rows) nameCounts.set(name, (nameCounts.get(name) || 0) + 1);
      for (const [key, value] of matches) {
        const row = trafficNode('button', 'exchange-leaf'); row.type = 'button'; row.setAttribute('aria-pressed', 'false');
        row.append(trafficNode('span', 'exchange-key', key), trafficNode('span', 'exchange-value', value));
        row.addEventListener('click', () => selectValue(key, value, row, mode.value === 'query' && nameCounts.get(key) === 1 ? {kind: 'query', selector: key} : null)); content.append(row);
      }
      if (!matches.length) message(query ? 'No matches.' : mode.value === 'headers' ? 'No headers.' : 'No query parameters.');
      return;
    }
    if (model.message) return message(model.message);
    if (!model.text.length) return message(`Captured ${side.toLowerCase()} body is empty (0 bytes).`);
    if (mode.value === 'preview') {
      const preview = trafficHtmlPreview(model.text);
      const warnings = [];
      if (model.truncated) warnings.push('Captured content is truncated; this preview is incomplete.');
      if (preview.limited) warnings.push('Rendering limited to 1,000 nodes and 24 levels.');
      if (preview.empty) return message([...warnings,
        warnings.length ? 'No supported HTML content was rendered from the inspected prefix.' : 'No supported HTML content to preview.',
        'Inspect Raw body for the retained source.'].join(' '));
      const notice = trafficNode('p', 'exchange-preview-notice', 'Isolated HTML preview. Scripts, links, forms, images, and external styles are disabled. Basic inline styling only.');
      if (warnings.length) notice.append(document.createTextNode(` ${warnings.join(' ')} Inspect Raw body for the retained source.`));
      const frame = trafficNode('iframe', 'exchange-html-preview');
      frame.title = 'Isolated HTML response preview';
      frame.setAttribute('sandbox', '');
      frame.referrerPolicy = 'no-referrer';
      frame.srcdoc = preview.document;
      content.append(notice, frame);
      return;
    }
    if (mode.value === 'formatted' && treeMode && model.json !== undefined) {
      let count = 0;
      let exhausted = false;
      function tree(value, key, path, depth, pointer) {
        if (++count > TRAFFIC_TREE_LIMIT || depth > 24) { exhausted = true; return null; }
        if (value !== null && typeof value === 'object') {
          const branch = trafficNode('details', 'exchange-branch'); branch.open = depth < 2 || Boolean(query);
          const entries = Object.entries(value);
          const summary = trafficNode('summary', '', `${key}  ${Array.isArray(value) ? '[' + entries.length + ' items]' : '{' + entries.length + ' fields}'}`);
          branch.append(summary);
          for (const [childKey, child] of entries) {
            if (count >= TRAFFIC_TREE_LIMIT) { exhausted = true; break; }
            const node = tree(child, childKey, `${path}[${JSON.stringify(childKey)}]`, depth + 1, `${pointer}/${childKey.replaceAll('~', '~0').replaceAll('/', '~1')}`);
            if (node) branch.append(node);
          }
          if (query && branch.children.length === 1 && !`${key} ${path}`.toLowerCase().includes(query)) return null;
          return branch;
        }
        const text = JSON.stringify(value);
        if (query && !`${path} ${text}`.toLowerCase().includes(query)) return null;
        const row = trafficNode('button', 'exchange-leaf'); row.type = 'button'; row.setAttribute('aria-pressed', 'false');
        row.append(trafficNode('span', 'exchange-key', key), trafficNode('span', `exchange-value value-${value === null ? 'null' : typeof value}`, text.length > 180 ? text.slice(0, 180) + '…' : text));
        row.addEventListener('click', () => selectValue(path, value, row, {kind: 'json', selector: pointer}));
        return row;
      }
      const root = tree(model.json, '$', '$', 0, '');
      if (root) content.append(root); else message('No matches.');
      if (exhausted) content.append(trafficNode('p', 'exchange-limit', 'Tree limited to 1,000 nodes and 24 levels. Use Raw body to inspect the retained text.'));
    } else {
      const pretty = mode.value === 'formatted' && model.json !== undefined;
      const lines = (pretty ? model.formatted.text : model.text).split('\n');
      const tokenizer = createSourceTokenizer({mime_type: model.mime, kind: 'response_body', url: ''});
      let matches = 0;
      lines.forEach((line, index) => {
        const tokens = sourceSyntaxTokens(line, tokenizer);
        if (query && !line.toLowerCase().includes(query)) return;
        if (matches++ >= 2000) return;
        const row = trafficNode('div', 'exchange-code-line');
        const number = trafficNode('span', 'exchange-line-number', String(index + 1)); number.setAttribute('aria-hidden', 'true');
        const code = trafficNode('code', '');
        tokens.forEach(token => code.append(trafficNode('span', `syntax-${token.type}`, token.text)));
        row.append(number, code); content.append(row);
      });
      if (!matches) message('No matches.');
      if (matches > 2000) content.append(trafficNode('p', 'exchange-limit', 'Showing the first 2,000 matching lines. Copy body includes the retained preview.'));
    }
  }
  search.addEventListener('input', () => render());
  pane.append(header, controls, content, selection, meta);
  let signature = trafficPaneSignature(record, request, view);
  pane.updateRecord = (nextRecord, nextRequest) => {
    const next = trafficPaneSignature(nextRecord, nextRequest, view);
    if (next === signature) return;
    signature = next; record = nextRecord; request = nextRequest;
    model = bodyModel(record);
    tree.disabled = !model.treeSafe;
    if (treeMode && !model.treeSafe) treeMode = false;
    tree.setAttribute('aria-pressed', String(treeMode));
    copy.disabled = model.text === undefined;
    copy.textContent = model.binary ? 'Copy hex' : model.truncated ? 'Copy preview' : 'Copy body';
    renderedMode = undefined;
    render(true);
  };
  render();
  return pane;
}

// Full retained values, including headers and equal-length text replacements,
// participate in invalidation. Only the selected request owns these bounded keys.
// Network projection reuses immutable decoded bytes for unchanged bodies.
// Weak identities avoid retaining a second expanded copy of every inspected body.
const trafficByteSignatures = new WeakMap();
let trafficByteIdentity = 0;
function trafficPaneSignature(record, request, view = null) {
  if (view === 'headers') return JSON.stringify([request?.origin, request?.id, record?.headers]);
  if (record?.bytes && !trafficByteSignatures.has(record.bytes)) trafficByteSignatures.set(record.bytes, ++trafficByteIdentity);
  return JSON.stringify([request?.id, request?.origin, request?.path, request?.hostOnly,
    request?.urlTruncated, record?.state, record?.reason, record?.mime, record?.truncated,
    record?.headers, record?.text, record?.bytes ? trafficByteSignatures.get(record.bytes) : null]);
}

function renderTrafficDetails(container, request, tab, onDecode, onTrace, find = null, notice = '') {
  const findTab = find?.mode === 'headers' ? 'headers' : find?.side === 'Request' ? 'payload' : 'response';
  if (findTab !== tab) find = null;
  const exchange = trafficExchange(request);
  const html = exchange.response?.mime?.split(';')[0].trim().toLowerCase() === 'text/html';
  const key = JSON.stringify([request?.origin, request?.id, tab, tab === 'preview' && html, find, notice]);
  if (container.dataset.selection !== key) {
    container.dataset.selection = key;
    container.replaceChildren();
    if (!request) {
      container.append(trafficNode('div', 'exchange-no-selection', notice || 'Select a request to inspect captured details.'));
      return;
    }
    if (tab === 'headers') {
      const general = trafficNode('section', 'traffic-general');
      general.append(trafficNode('h2', '', 'General'));
      for (const label of ['Request URL', 'Document URL', 'Request Method', 'Status', 'Source', 'Request ID', 'Browser tab', 'Capture limits']) {
        const row = trafficNode('div', 'traffic-general-row');
        row.append(trafficNode('span', '', label), trafficNode('span', 'traffic-general-value'));
        general.append(row);
      }
      container.append(general);
      for (const side of ['Response', 'Request']) {
        const pane = createTrafficPane(side, exchange[side.toLowerCase()], request, onDecode, onTrace, find, 'headers');
        pane.dataset.side = side.toLowerCase(); container.append(pane);
      }
    } else {
      const side = tab === 'payload' ? 'Request' : 'Response';
      const pane = createTrafficPane(side, exchange[side.toLowerCase()], request, onDecode, onTrace, find, tab);
      pane.dataset.side = side.toLowerCase(); container.append(pane);
    }
  }
  if (!request) return;
  container.dataset.view = tab;
  container.querySelectorAll('.exchange-pane').forEach(pane => pane.updateRecord(exchange[pane.dataset.side], request));
  if (tab === 'headers') {
    const values = [request.hostOnly ? `${request.path} (host only; path and query not captured)` : request.path,
      request.documentUrl ?? 'Not captured', request.method, request.failed ? 'Failed' : request.status, trafficOriginLabel(request), request.id,
      request.tabId && request.tabId !== '0' ? request.tabId : 'Unattributed',
      `Retained evidence only. Missing headers and bodies are not fetched.${request.urlTruncated ? ' Request URL truncated.' : ''}${request.documentUrlTruncated ? ' Document URL truncated.' : ''}${request.methodTruncated ? ' Method truncated.' : ''}`];
    container.querySelectorAll('.traffic-general-value').forEach((node, index) => {
      if (node.textContent !== String(values[index])) node.textContent = String(values[index]);
    });
  }
}

// A baseline is an exact reference into the retained window, never a body copy.
// Observed target/restart changes retire it permanently, even across A → B → A.
function createTrafficComparisonController(identityOf, sameIdentity) {
  let baseline = null, scope = null, generation = null, notice = '';
  const exact = (identity, requests) => requests.filter(value => sameIdentity(identity, identityOf(value)));
  function sync(requests, owner) {
    const nextScope = JSON.stringify([owner.mode, owner.target, owner.capture]);
    const replaced = scope !== null && (scope !== nextScope ||
      Number.isSafeInteger(generation) && Number.isSafeInteger(owner.generation) && owner.generation < generation);
    scope = nextScope; generation = owner.generation;
    if (baseline && (replaced || exact(baseline, requests).length !== 1)) {
      baseline = null;
      notice = 'Baseline expired: its exact capture is no longer uniquely retained or the capture session changed. Select it again explicitly.';
    }
    return baseline ? exact(baseline, requests)[0] : null;
  }
  return {
    sync,
    pin(request, requests, owner) {
      sync(requests, owner);
      const identity = identityOf(request);
      if (!identity || exact(identity, requests).length !== 1 || requests.filter(value => value.id === request.id).length !== 1) {
        notice = 'A unique retained capture identity is required. Sample data cannot be pinned.'; return false;
      }
      baseline = identity; notice = ''; return true;
    },
    clear() {baseline = null; notice = 'Baseline cleared.';},
    get identity() {return baseline;},
    get notice() {return notice;}
  };
}

function trafficComparisonOwner() {
  return {mode: state.sessionMode, target: state.debuggerSession?.network?.target_id ?? state.debuggerSession?.target?.id ?? null,
    capture: state.debuggerSession?.network?.capture_enabled ?? false, generation: state.debuggerSession?.generation ?? null};
}

// Lazy initialization keeps pure viewer/model fixtures independent of navigation.
let trafficComparisonController = null;
function syncTrafficComparison() {
  trafficComparisonController ??= createTrafficComparisonController(investigationRequestIdentity, investigationSame);
  return trafficComparisonController.sync(state.requests, trafficComparisonOwner());
}

function trafficComparisonLabel(request) {
  const identity = investigationRequestIdentity(request);
  if (!identity) return 'No exact captured request selected';
  const context = identity.type === 'debugger-request'
    ? `CDP target ${identity.target} · request ${identity.protocol} · start ${identity.started} ns`
    : `session ${identity.session} · process ${identity.process} · event ${identity.sequence} · request ${identity.request}`;
  return `${request.method} ${request.path} · ${context}`;
}

function renderTrafficComparison(container, request, active) {
  const baseline = syncTrafficComparison();
  if (!active) {
    if (container.rebComparison) {container.replaceChildren(); delete container.rebComparison;}
    return;
  }
  if (!container.rebComparison) {
    const toolbar = trafficNode('div', 'traffic-comparison-toolbar');
    const pin = trafficNode('button', 'secondary-button', 'Use selected as baseline'); pin.type = 'button'; pin.id = 'traffic-comparison-pin';
    const clear = trafficNode('button', 'secondary-button', 'Clear baseline'); clear.type = 'button'; clear.id = 'traffic-comparison-clear';
    toolbar.append(pin, clear);
    const status = trafficNode('p', 'traffic-comparison-notice'); status.setAttribute('role', 'status');
    const identityDisclosure = trafficNode('details', 'traffic-comparison-identities');
    const identitySummary = trafficNode('summary', '', 'Capture identities');
    const identities = trafficNode('div', ''); identityDisclosure.append(identitySummary, identities);
    const result = trafficNode('div', 'traffic-comparison-results');
    result.tabIndex = 0; result.setAttribute('aria-label', 'Captured request comparison results');
    container.append(toolbar, status, identityDisclosure, result);
    container.rebComparison = {pin, clear, status, identities, identitySummary, result, key: null, byteSnapshots: [], byteRevision: 0};
    pin.addEventListener('click', () => {
      const selected = state.requests.find(value => value.id === state.selectedRequestId);
      trafficComparisonController.pin(selected, state.requests, trafficComparisonOwner());
      renderInspector();
    });
    clear.addEventListener('click', () => {
      trafficComparisonController.clear(); renderInspector();
      container.rebComparison.pin.focus();
    });
  }
  const view = container.rebComparison;
  const selectedIdentity = investigationRequestIdentity(request);
  const selectedUnique = selectedIdentity && state.requests.filter(value => value.id === request.id).length === 1 &&
    state.requests.filter(value => investigationSame(selectedIdentity, investigationRequestIdentity(value))).length === 1;
  view.pin.disabled = !selectedUnique;
  view.clear.disabled = !baseline;
  if ((document.activeElement === view.pin && view.pin.disabled) || (document.activeElement === view.clear && view.clear.disabled)) {
    if (!view.pin.disabled) view.pin.focus();
    else {container.tabIndex = -1; container.focus();}
  }
  view.status.textContent = trafficComparisonController.notice || (!selectedUnique
    ? request ? 'The selected capture identity is unavailable or ambiguous. Choose a unique retained request.' : 'Choose a retained request from the ledger.'
    : !baseline
    ? 'Select a captured request as baseline, then choose another request from the ledger. Comparison stays local and sends no requests.'
    : investigationSame(selectedIdentity, trafficComparisonController.identity)
      ? 'Baseline selected. Choose another captured request to compare.'
      : 'Baseline → selected. Comparing retained content locally; capture limits remain visible.');
  // Match the pure model's original exchange inputs, without inspector-only
  // HTTP empty-body fallbacks becoming evidence in the invalidation key.
  const left = baseline?.exchange, right = request?.exchange;
  // Only this visible pair owns byte snapshots (four × 128 KiB maximum).
  // Compare bytes exactly so a future mutable adapter cannot leave stale rows.
  const comparable = baseline && request && selectedUnique && !investigationSame(selectedIdentity, trafficComparisonController.identity);
  const records = comparable ? [left?.request, left?.response, right?.request, right?.response] : [];
  if (!comparable) view.byteSnapshots = [];
  const byteKeys = records.map((record, index) => {
    const bytes = record?.bytes;
    if (!(bytes instanceof Uint8Array) || bytes.length > TRAFFIC_COMPARISON_LIMITS.bodyBytes) {
      view.byteSnapshots[index] = null;
      return bytes instanceof Uint8Array ? ['oversized', bytes.length] : null;
    }
    let prior = view.byteSnapshots[index];
    if (!prior || prior.bytes.length !== bytes.length || !bytes.every((byte, offset) => byte === prior.bytes[offset])) {
      prior = {bytes: bytes.slice(), revision: ++view.byteRevision}; view.byteSnapshots[index] = prior;
    }
    return prior.revision;
  });
  const key = JSON.stringify([trafficComparisonController.identity, selectedIdentity, selectedUnique, byteKeys,
    ...[baseline, request].map(value => [value?.id, value?.method, value?.path, value?.status, value?.hostOnly, value?.urlTruncated, value?.methodTruncated, value?.targetKind]),
    ...records.map(record => [trafficPaneSignature(record, null), record?.headersTruncated, record?.headers_truncated])]);
  if (view.key === key) return;
  view.key = key;
  const shortLabel = value => {
    if (!value) return 'not selected';
    let path = String(value.path ?? '');
    try {path = new URL(path).pathname;} catch {}
    const id = String(value.id ?? '');
    return `${value.method} ${path.slice(0,40)}${path.length > 40 ? '…' : ''} · ${id.length > 16 ? '…' + id.slice(-16) : id}`;
  };
  view.identitySummary.textContent = `Baseline: ${shortLabel(baseline)} → selected: ${shortLabel(request)} (full IDs)`;
  view.identities.replaceChildren();
  if (baseline) view.identities.append(trafficNode('p', '', `Baseline: ${trafficComparisonLabel(baseline)}`));
  if (request) view.identities.append(trafficNode('p', '', `Selected: ${trafficComparisonLabel(request)}`));
  const priorSections = new Map([...view.result.children].map(section => [section.dataset.label, section.open]));
  const focusedSection = [...view.result.children].find(section => section.children[0] === document.activeElement)?.dataset.label;
  view.result.replaceChildren();
  if (!comparable) {
    if (focusedSection) {
      if (!view.pin.disabled) view.pin.focus({preventScroll: true});
      else {container.tabIndex = -1; container.focus({preventScroll: true});}
    }
    return;
  }
  const report = trafficCompareRequests(baseline, request);
  for (const section of report.sections) {
    const details = trafficNode('details', 'traffic-comparison-section');
    details.dataset.label = section.label;
    details.open = priorSections.get(section.label) ?? /body/i.test(section.label);
    const summary = trafficNode('summary', '', `${section.label} · ${section.structuralStatus ? 'JSON ' : ''}${section.status}${section.omitted ? ` · ${section.omitted} omitted` : ''}`);
    details.append(summary, trafficNode('p', 'traffic-comparison-coverage', section.message));
    if (section.rawStatus) details.append(trafficNode('p', 'traffic-comparison-coverage',
      `Retained bytes: ${section.rawStatus}${section.structuralStatus ? ` · JSON structure: ${section.structuralStatus}` : ''}`));
    if (section.omitted) details.append(trafficNode('p', 'traffic-comparison-coverage', `${section.omitted} additional changes omitted from this bounded view.`));
    const rows = trafficNode('ol', 'traffic-comparison-rows');
    for (const row of section.rows) {
      const item = trafficNode('li', ''); item.dataset.kind = row.kind;
      item.append(trafficNode('code', 'traffic-comparison-path', `${row.path || '(root)'} · ${row.kind}`),
        trafficNode('div', '', `Baseline: ${row.before ?? '(absent)'}`), trafficNode('div', '', `Selected: ${row.after ?? '(absent)'}`));
      rows.append(item);
    }
    details.append(rows); view.result.append(details);
    if (focusedSection === section.label) summary.focus({preventScroll: true});
  }
}
// Local selected-record export. Redaction transforms a copy, never capture state.
function trafficCaptureDocument(request, mode = 'raw') {
  if (!request?.captureRecord) throw new TypeError('Select a retained CDP request first.');
  if (!['raw', 'redacted_copy'].includes(mode)) throw new TypeError('Unknown capture export mode.');
  const record = JSON.parse(JSON.stringify(request.captureRecord));
  if (mode === 'redacted_copy') {
    const redactUrl = value => {
      if (!value) return value;
      try {
        const url = new URL(value);
        if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) return '<redacted>';
        url.username = ''; url.password = ''; url.search = ''; url.hash = '';
        return url.href;
      } catch { return '<redacted>'; }
    };
    record.url = redactUrl(record.url);
    record.document_url = redactUrl(record.document_url);
    record.target_title = '<redacted>';
    if (record.error_text) record.error_text = '<redacted>';
    for (const site of record.initiator?.sites ?? []) {
      site.source = redactUrl(site.source);
    }
    for (const side of [record.request, record.response]) {
      side.headers = side.headers.map(([name]) => [name, '<redacted>']);
      if (side.body.state === 'available') side.body.state = 'redacted';
      side.body.text = ''; side.body.base64 = '';
      side.body.reason = 'Body content omitted from this explicitly redacted copy.';
    }
  }
  return {
    format: 'reb-traffic-capture-v1', mode,
    representation: 'Retained CDP strings/base64, not original HTTP wire bytes.',
    warning: mode === 'raw'
      ? 'Raw local capture may contain credentials and personal data. Review before sharing.'
      : 'Best-effort redacted copy. Paths, header names and other metadata may contain secrets. Review before sharing.',
    coverage: {
      scope: 'One selected record from the ephemeral CDP Traffic window; not a durable session archive.',
      headers: 'Primary CDP event headers only; extra-info headers, original casing/order and duplicate wire lines are not guaranteed.',
      storage: 'Reconnect, target change, process exit or retention eviction can discard the live record.',
      dropped: request.captureDropped ?? 0,
      limits: JSON.parse(JSON.stringify(request.captureLimits ?? {}))
    },
    record
  };
}

function installTrafficCaptureExport(host, getRequest) {
  if (!host) return {sync() {}};
  const status = host.querySelector('[data-traffic-export-status]');
  const buttons = [...host.querySelectorAll('[data-traffic-export]')];
  const nativeShell = document.documentElement.classList.contains('native-shell');
  let busy = false, selection = null, revision = 0;
  const identityOf = request => request?.captureRecord ? JSON.stringify([request.captureOwner,
    request.tabId, request.id, request.captureRecord.started_monotonic_ms, request.captureRecord.wall_time_ms]) : null;
  function sync() {
    const request = getRequest();
    const identity = identityOf(request);
    if (identity !== selection) { selection = identity; revision++; status.textContent = ''; host.open = false; }
    host.hidden = !request?.captureRecord;
    for (const button of buttons) {
      const unsupported = nativeShell && button.dataset.trafficDestination === 'download';
      button.disabled = busy || !request?.captureRecord || unsupported;
      button.title = unsupported ? 'Native file download is unavailable. Use Copy and save locally.' : '';
    }
  }
  host.addEventListener('keydown', event => {
    if (event.key === 'Escape' && host.open) {
      event.preventDefault(); event.stopPropagation(); host.open = false;
      host.querySelector('summary').focus();
    }
  });
  for (const button of buttons) button.addEventListener('click', async () => {
    if (button.disabled || busy) return;
    const request = getRequest();
    sync();
    const identity = identityOf(request), started = revision;
    const mode = button.dataset.trafficExport;
    try {
      const text = JSON.stringify(trafficCaptureDocument(request, mode), null, 2) + '\n';
      if (button.dataset.trafficDestination === 'clipboard') {
        busy = true; sync();
        await navigator.clipboard.writeText(text);
        if (selection === identity && identityOf(getRequest()) === identity && revision === started) status.textContent = mode === 'raw'
          ? 'Raw capture copied. Clipboard contains unmasked values.'
          : 'Redacted copy copied. Review for remaining secrets before sharing.';
      } else {
        const url = URL.createObjectURL(new Blob([text], {type: 'application/json'}));
        const link = document.createElement('a');
        link.href = url; link.download = mode === 'raw' ? 'selected.reb-traffic.raw.json' : 'selected.reb-traffic.redacted.json';
        link.hidden = true; document.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        status.textContent = 'Download requested. Check your browser downloads for completion.';
      }
    } catch {
      if (selection === identity && identityOf(getRequest()) === identity && revision === started) status.textContent = 'Export failed. The captured record is unchanged.';
    } finally { busy = false; sync(); }
  });
  sync();
  return {sync};
}
