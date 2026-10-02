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
    empty: !output.textContent.trim() && !output.querySelector('hr, input, textarea, select, table'),
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

function trafficTimeLabel(time) {
  if (typeof time !== 'number' || !Number.isFinite(time)) return time === 'pending' ? '—' : String(time ?? '—');
  if (time < 1) return `${time.toFixed(2)} ms`;
  if (time < 100) return `${time.toFixed(1)} ms`;
  if (time < 1000) return `${Math.round(time)} ms`;
  return `${(time / 1000).toFixed(2)} s`;
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

function createTrafficPane(side, record, request, onDecode, onTrace) {
  const pane = trafficNode('section', 'exchange-pane');
  pane.dataset.origin = request?.origin ?? 'none';
  pane.setAttribute('aria-label', `${side} content`);
  const header = trafficNode('div', 'exchange-pane-head');
  header.append(trafficNode('strong', '', side));
  const controls = trafficNode('div', 'exchange-controls');
  controls.hidden = true;
  const tabs = trafficNode('div', 'exchange-tabs');
  tabs.setAttribute('role', 'tablist'); tabs.setAttribute('aria-label', `${side} view`);
  const model = trafficBodyModel(record, side);
  const htmlResponse = side === 'Response' && record?.mime?.split(';')[0].trim().toLowerCase() === 'text/html';
  const mode = {value: 'formatted'};
  const modes = [['headers', 'Header'], ...(side === 'Request' ? [['query', 'Query']] : []), ['formatted', 'Body'], ['raw', 'Raw body'], ...(htmlResponse ? [['preview', 'Preview']] : [])];
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
  let treeMode = false;
  tree.addEventListener('click', () => { treeMode = !treeMode; tree.setAttribute('aria-pressed', String(treeMode)); renderedMode = undefined; options.open = false; mode.value = 'formatted'; render(); });
  const search = trafficNode('input', 'exchange-search');
  search.type = 'search'; search.placeholder = 'Find in body'; search.setAttribute('aria-label', `Find in ${side.toLowerCase()}`);
  const wrap = trafficNode('button', 'exchange-button', 'Wrap');
  wrap.type = 'button'; wrap.setAttribute('aria-pressed', 'true');
  const copy = trafficNode('button', 'exchange-button', 'Copy body'); copy.type = 'button';
  const closeSearch = trafficNode('button', 'exchange-button', 'Done'); closeSearch.type = 'button';
  closeSearch.addEventListener('click', () => { search.value = ''; controls.hidden = true; render(); optionsTitle.focus(); });
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
    decode.addEventListener('click', () => onDecode(valueText));
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
  function render() {
    const query = search.value.toLowerCase();
    if (renderedMode === mode.value && renderedSearch === query) return;
    renderedMode = mode.value; renderedSearch = query;
    selection.hidden = true;
    content.replaceChildren();
    content.scrollTop = 0;
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
      if (preview.empty) return message('No supported HTML content to preview. Inspect Raw body for the retained source.');
      const notice = trafficNode('p', 'exchange-preview-notice', 'Isolated HTML preview. Scripts, links, forms, images, and external styles are disabled. Basic inline styling only.');
      if (model.truncated) notice.append(document.createTextNode(' Captured content is truncated; this preview is incomplete.'));
      if (preview.limited) notice.append(document.createTextNode(' Rendering limited to 1,000 nodes and 24 levels. Inspect Raw body for the retained source.'));
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
  search.addEventListener('input', render);
  pane.append(header, controls, content, selection, meta);
  render();
  return pane;
}

function renderTrafficExchange(container, request, onDecode, onTrace) {
  const key = `${request?.origin}:${request?.id}:${request?.method}:${request?.status}:` +
    `${request?.exchange?.request?.state}:${request?.exchange?.request?.text?.length ?? request?.exchange?.request?.bytes?.length ?? 0}:` +
    `${request?.exchange?.response?.state}:${request?.exchange?.response?.mime}:${request?.exchange?.response?.truncated}:` +
    `${request?.exchange?.response?.text?.length ?? request?.exchange?.response?.bytes?.length ?? 0}`;
  if (container.dataset.selection === key) return;
  container.dataset.selection = key;
  if (!request) {
    container.dataset.side = 'none';
    container.replaceChildren(trafficNode('div', 'exchange-no-selection', 'Select a request to inspect its request and response.'));
    return;
  }
  const exchange = trafficExchange(request);
  const switcher = trafficNode('div', 'exchange-mobile-switch');
  switcher.setAttribute('role', 'group'); switcher.setAttribute('aria-label', 'Visible content pane');
  container.dataset.side = 'request';
  for (const side of ['Request', 'Response']) {
    const button = trafficNode('button', 'exchange-button', side); button.type = 'button';
    button.setAttribute('aria-pressed', String(side === 'Request'));
    button.addEventListener('click', () => {
      container.dataset.side = side.toLowerCase();
      switcher.querySelectorAll('button').forEach(node => node.setAttribute('aria-pressed', String(node === button)));
    });
    switcher.append(button);
  }
  container.replaceChildren(switcher, createTrafficPane('Request', exchange.request, request, onDecode, onTrace), createTrafficPane('Response', exchange.response, request, onDecode, onTrace));
}
