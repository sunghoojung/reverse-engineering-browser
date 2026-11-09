/* The Payload tab: the captured query string and the retained request body
 * (protocol/native-network-v2.md), parsed and as sent. Captured values are only
 * ever assigned as text; a binary body is shown as hex and never interpreted. */
const TRAFFIC_PAYLOAD_BLOCK_ROWS = 200;
const TRAFFIC_PAYLOAD_GROUP = 100;
const TRAFFIC_PAYLOAD_LEAF_UNITS = 1000;
const TRAFFIC_PAYLOAD_FIELD_BYTES = 64 * 1024;
const TRAFFIC_PAYLOAD_HEX_BYTES = 1024 * 1024;
const TRAFFIC_PAYLOAD_FIND_LIMIT = 1000;
const TRAFFIC_PAYLOAD_BINARY_TYPES = /^(?:image\/(?!svg\+xml$)|audio\/|video\/|font\/)|^application\/(?:octet-stream|wasm|zip|gzip|pdf|cbor|msgpack|x-msgpack|protobuf|x-protobuf|vnd\.google\.protobuf|grpc(?:-web)?(?:\+proto)?)$/;

// Toggles carry across requests, as in DevTools; the rest belongs to the shown body.
const trafficPayloadPrefs = {source: false, encoded: false, wrap: true};
let trafficPayloadShown = null;
let trafficPayloadLayouts = null;
const trafficPayloadLayout = () => trafficPayloadLayouts ??= createCodeLayouts({onChange: () => trafficPayloadShown?.relayout?.()});

function trafficPayloadDecode(part) {
  try {
    return decodeURIComponent(part.replaceAll('+', ' '));
  } catch {
    return null;
  }
}

function trafficPayloadPairs(text) {
  return text.split('&').filter(Boolean).map(segment => {
    const at = segment.indexOf('=');
    const name = at < 0 ? segment : segment.slice(0, at), value = at < 0 ? '' : segment.slice(at + 1);
    return {name, value, decodedName: trafficPayloadDecode(name), decodedValue: trafficPayloadDecode(value)};
  });
}

function trafficPayloadPair(pair, encoded = trafficPayloadPrefs.encoded) {
  return encoded ? {name: pair.name, value: pair.value} : {name: pair.decodedName ?? pair.name, value: pair.decodedValue ?? pair.value};
}

// The query of the captured target, never of a reconstructed URL. A retained full
// target replaces the 116-byte row prefix; the prefix's notice stays only until it does.
function trafficPayloadQuery(request, targetView = null) {
  if (!request) return null;
  if (request.hostOnly) return {pairs: null, note: 'Path and query are recorded only in content capture sessions.'};
  let target = typeof request.target === 'string' ? request.target : '';
  if (typeof request.target !== 'string') {
    try {
      target = new URL(request.path).search;
    } catch {
      target = '';
    }
  }
  const whole = request.urlTruncated && targetView?.status === 'ready' && targetView.complete;
  if (whole) target = targetView.text;
  const retained = request.fullTarget?.retention === 'retained';
  const reading = !targetView || targetView.status === 'loading';
  const unread = targetView?.status === 'missing' ? (targetView.unknown ? 'is not in the scanned range of the artifact manifest' : 'is not in the artifact manifest')
    : targetView?.status === 'refused' ? 'was not retained by the artifact receiver'
      : targetView?.status === 'error' ? `could not be read: ${targetView.error}` : 'is not readable here';
  const cut = !request.urlTruncated || whole ? ''
    : retained && reading ? `Showing the captured start of the ${request.targetLength}-byte path and query; reading the retained full target.`
      : retained ? `Showing the captured start of the ${request.targetLength}-byte path and query; the retained full target ${unread}.`
        : `Only the first part of the ${request.targetLength}-byte path and query was captured; later parameters are missing and the last one shown may be cut.`;
  const at = target.indexOf('?');
  return at < 0 ? (cut ? {pairs: null, cut} : null) : {pairs: trafficPayloadPairs(target.slice(at + 1)), raw: target.slice(at + 1), cut};
}

function trafficPayloadIndexOf(bytes, pattern, from) {
  for (let at = bytes.indexOf(pattern[0], Math.max(0, from)); at >= 0; at = bytes.indexOf(pattern[0], at + 1)) {
    if (at + pattern.length > bytes.length) return -1;
    let index = 1;
    while (index < pattern.length && bytes[at + index] === pattern[index]) index += 1;
    if (index === pattern.length) return at;
  }
  return -1;
}

function trafficPayloadPartHeaders(head) {
  const fields = {name: null, filename: null, type: null};
  for (const line of head.split('\r\n')) {
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const field = line.slice(0, colon).trim().toLowerCase(), value = line.slice(colon + 1).trim();
    if (field === 'content-type') fields.type = value;
    if (field !== 'content-disposition') continue;
    for (const match of value.matchAll(/;\s*(name|filename)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]*))/gi)) {
      fields[match[1].toLowerCase()] = match[2] === undefined ? match[3] : match[2].replace(/\\(.)/g, '$1');
    }
  }
  return fields;
}

// The record keeps only type/subtype, so the boundary is read from the first line.
function trafficPayloadMultipart(bytes) {
  const lineEnd = trafficPayloadIndexOf(bytes, [13, 10], 0);
  if (lineEnd < 3 || lineEnd > 80) return null;
  const decoder = new TextDecoder();
  const boundary = /^--([\x21-\x7e][\x20-\x7e]{0,69})$/.exec(decoder.decode(bytes.subarray(0, lineEnd)).trimEnd())?.[1];
  if (!boundary) return null;
  const delimiter = new TextEncoder().encode(`\r\n--${boundary}`);
  const parts = [];
  let at = lineEnd + 2, closed = false;
  while (at < bytes.length) {
    const headerEnd = trafficPayloadIndexOf(bytes, [13, 10, 13, 10], at - 2);
    if (headerEnd < 0) {
      parts.push({name: null, filename: null, type: null, size: 0, value: null, cut: true});
      break;
    }
    const start = headerEnd + 4, end = trafficPayloadIndexOf(bytes, delimiter, start);
    const stop = end < 0 ? bytes.length : end;
    const fields = trafficPayloadPartHeaders(decoder.decode(bytes.subarray(at, Math.max(at, headerEnd))));
    let value = null;
    if (fields.filename === null && stop - start <= TRAFFIC_PAYLOAD_FIELD_BYTES) {
      try {
        value = new TextDecoder('utf-8', {fatal: true}).decode(bytes.subarray(start, stop));
      } catch {
        value = null;
      }
    }
    parts.push({...fields, size: stop - start, value, cut: end < 0});
    if (end < 0) break;
    at = end + delimiter.length;
    if (bytes[at] === 45 && bytes[at + 1] === 45) {
      closed = true;
      break;
    }
    const next = trafficPayloadIndexOf(bytes, [13, 10], at);
    if (next < 0) break;
    at = next + 2;
  }
  return {boundary, parts, closed};
}

function trafficPayloadBinary(bytes, type, lossy) {
  if (lossy || TRAFFIC_PAYLOAD_BINARY_TYPES.test(type)) return true;
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index];
    if ((byte < 32 && byte !== 9 && byte !== 10 && byte !== 12 && byte !== 13) || byte === 127) return true;
  }
  return false;
}

function trafficPayloadModel(body, view) {
  const bytes = view.bytes ?? new TextEncoder().encode(view.text ?? '');
  const text = view.text ?? new TextDecoder().decode(bytes);
  const type = body.contentType ?? '';
  const model = {bytes, text, type, binary: trafficPayloadBinary(bytes, type, view.lossy), keys: new WeakMap(),
    artifact: view.complete === false || view.lossy ? null : view.artifact ?? null};
  if (type.startsWith('multipart/')) {
    model.parts = trafficPayloadMultipart(bytes);
    if (!model.parts) model.parsedNote = 'The multipart boundary could not be read from the first line.';
    else if (view.complete === false) for (const part of model.parts.parts) if (part.cut) part.cut = 'read';
  } else if (model.binary) {
    return model;
  } else if (type === 'application/x-www-form-urlencoded') {
    model.pairs = trafficPayloadPairs(text);
  } else if (/[/+]json$/.test(type) || /^\s*[[{]/.test(text)) {
    try {
      model.json = {value: JSON.parse(text)};
    } catch {
      // A partly read prefix is not judged; its read note says more follows.
      if (/json$/.test(type) && view.complete !== false) {
        model.parsedNote = body.state === 'captured_truncated' ? 'The retained prefix ends before the JSON does, so it is shown as sent.'
          : 'This body is not valid JSON, so it is shown as sent.';
      }
    }
  }
  model.syntax = {mime_type: model.json || /json$/.test(type) ? 'application/json' : type};
  return model;
}

function trafficPayloadSourceRows(model) {
  if (model.binary) {
    if (model.sourceRows) return model.sourceRows;
    const hex = formatWasmHex(model.bytes.subarray(0, TRAFFIC_PAYLOAD_HEX_BYTES));
    return model.sourceRows = {text: hex, rows: codeViewRows(hex), syntax: {kind: 'bytecode_buffer'}, hex: true, layout: null,
      note: model.bytes.length > TRAFFIC_PAYLOAD_HEX_BYTES ? `Hex shows the first 1 MiB of ${trafficByteCount(model.bytes.length)}.` : ''};
  }
  const layout = model.json ? trafficPayloadLayout().layout(model.artifact, model.text, model.syntax, 'json') : null;
  if (model.sourceRows && model.sourceRows.layout === layout && model.sourceRows.status === layout?.status) return model.sourceRows;
  const text = layout?.status === 'ready' ? layout.text : model.text;
  return model.sourceRows = {text, rows: codeViewRows(text), syntax: model.syntax, hex: false, layout, status: layout?.status,
    note: codeLayoutNote(layout) ?? ''};
}

// JSON tree. Containers with more than 100 children show ranges of them, so
// one expansion adds at most 100 rows and a large body needs no node cap.
function trafficPayloadKeys(model, value) {
  if (Array.isArray(value)) return null;
  let keys = model.keys.get(value);
  if (!keys) model.keys.set(value, keys = Object.keys(value));
  return keys;
}

function trafficPayloadContainer(value) {
  return value !== null && typeof value === 'object';
}

function trafficPayloadChildren(model, node) {
  const keys = trafficPayloadKeys(model, node.value);
  const count = keys ? keys.length : node.value.length;
  const start = node.group ? node.start : 0, end = node.group ? node.end : count;
  const container = node.group ? node.container : node.id;
  const children = [];
  if (end - start <= TRAFFIC_PAYLOAD_GROUP) {
    for (let index = start; index < end; index += 1) {
      const key = keys ? keys[index] : index;
      children.push({id: `${container}/${JSON.stringify(key)}`, key, value: node.value[key], depth: node.depth + 1, parent: node.id});
    }
    return children;
  }
  let step = TRAFFIC_PAYLOAD_GROUP;
  while ((end - start) / step > TRAFFIC_PAYLOAD_GROUP) step *= TRAFFIC_PAYLOAD_GROUP;
  for (let from = start; from < end; from += step) {
    const to = Math.min(end, from + step);
    children.push({id: `${container}#${from}-${to}`, group: true, start: from, end: to, container, value: node.value,
      depth: node.depth + 1, parent: node.id});
  }
  return children;
}

function trafficPayloadVisible(model, expanded) {
  const rows = [], stack = [{id: '$', key: null, value: model.json.value, depth: 0, parent: null}];
  while (stack.length) {
    const node = stack.pop();
    rows.push(node);
    if ((node.group || trafficPayloadContainer(node.value)) && expanded.has(node.id)) {
      stack.push(...trafficPayloadChildren(model, node).reverse());
    }
  }
  return rows;
}

// Expands the containers and ranges from the root down to one match.
function trafficPayloadExpand(model, expanded, steps) {
  for (const {container, index, count} of steps) {
    expanded.add(container);
    let start = 0, end = count;
    while (end - start > TRAFFIC_PAYLOAD_GROUP) {
      let step = TRAFFIC_PAYLOAD_GROUP;
      while ((end - start) / step > TRAFFIC_PAYLOAD_GROUP) step *= TRAFFIC_PAYLOAD_GROUP;
      const from = start + Math.floor((index - start) / step) * step, to = Math.min(end, from + step);
      expanded.add(`${container}#${from}-${to}`);
      start = from; end = to;
    }
  }
}

// Ids and expansion steps are built only for matches, so a miss costs one walk.
function trafficPayloadTreeSearch(model, needle) {
  const matches = [];
  const stack = [{key: null, value: model.json.value, up: null}];
  while (stack.length && matches.length < TRAFFIC_PAYLOAD_FIND_LIMIT) {
    const frame = stack.pop(), value = frame.value, container = trafficPayloadContainer(value);
    if ((typeof frame.key === 'string' && frame.key.toLowerCase().includes(needle)) ||
        (!container && String(value).toLowerCase().includes(needle))) {
      const path = [];
      for (let at = frame; at.up; at = at.up) path.unshift(at);
      let id = '$';
      const steps = path.map(at => {
        const step = {container: id, index: at.index, count: at.count};
        id = `${id}/${JSON.stringify(at.key)}`;
        return step;
      });
      matches.push({section: 'payload', id, steps});
    }
    if (!container) continue;
    const keys = trafficPayloadKeys(model, value), count = keys ? keys.length : value.length;
    for (let index = count - 1; index >= 0; index -= 1) {
      const key = keys ? keys[index] : index;
      stack.push({key, value: value[key], up: frame, index, count});
    }
  }
  return matches;
}

function trafficPayloadNodeValue(model, node) {
  if (!node.group) return node.value;
  const keys = trafficPayloadKeys(model, node.value);
  return keys ? Object.fromEntries(keys.slice(node.start, node.end).map(key => [key, node.value[key]])) : node.value.slice(node.start, node.end);
}

function trafficPayloadLeaf(model, value) {
  if (Array.isArray(value)) return [`Array(${value.length})`, 'meta'];
  if (trafficPayloadContainer(value)) {
    const count = trafficPayloadKeys(model, value).length;
    return [`{…} ${count} ${count === 1 ? 'key' : 'keys'}`, 'meta'];
  }
  if (typeof value === 'string') {
    const shown = JSON.stringify(value.slice(0, TRAFFIC_PAYLOAD_LEAF_UNITS));
    return [value.length > TRAFFIC_PAYLOAD_LEAF_UNITS ? `${shown.slice(0, -1)}…"` : shown, 'string'];
  }
  return [String(value), typeof value === 'number' ? 'number' : 'literal'];
}

// Rows render in blocks as they near the visible part of their box, so a large
// body costs only the rows a researcher reaches.
function trafficPayloadArea({className, label, role = null, count, makeRow, selectable = false, selected = -1,
  onSelect = () => {}, onKey = () => false}) {
  const box = trafficNode('div', `traffic-payload-view ${className}`);
  box.setAttribute('aria-label', label);
  if (role) box.setAttribute('role', role);
  box.tabIndex = selectable && count ? -1 : 0;
  const blocks = [], rows = [];
  let focusIndex = Math.max(0, Math.min(count - 1, selected));
  const fill = block => {
    const node = blocks[block];
    if (!node || node.dataset.filled) return;
    node.dataset.filled = 'true';
    observer?.unobserve(node);
    node.style.removeProperty('height');
    const end = Math.min(count, (block + 1) * TRAFFIC_PAYLOAD_BLOCK_ROWS);
    for (let index = block * TRAFFIC_PAYLOAD_BLOCK_ROWS; index < end; index += 1) {
      const row = makeRow(index);
      if (selectable) {
        row.dataset.index = String(index);
        row.tabIndex = index === focusIndex ? 0 : -1;
        row.setAttribute('aria-selected', String(index === selected));
      }
      node.append(rows[index] = row);
    }
  };
  const observer = typeof IntersectionObserver === 'function' ? new IntersectionObserver(entries => {
    for (const entry of entries) if (entry.isIntersecting) fill(Number(entry.target.dataset.block));
  }, {root: box, rootMargin: '600px 0px'}) : null;
  for (let block = 0; block * TRAFFIC_PAYLOAD_BLOCK_ROWS < count; block += 1) {
    const node = trafficNode('div', 'traffic-payload-block');
    node.dataset.block = String(block);
    if (role) node.setAttribute('role', role === 'table' ? 'rowgroup' : 'presentation');
    node.style.height = `${Math.min(TRAFFIC_PAYLOAD_BLOCK_ROWS, count - block * TRAFFIC_PAYLOAD_BLOCK_ROWS) * 18}px`;
    box.append(node);
    blocks.push(node);
    observer?.observe(node);
  }
  const reveal = index => {
    fill(Math.floor(index / TRAFFIC_PAYLOAD_BLOCK_ROWS));
    return rows[index] ?? null;
  };
  fill(0);
  reveal(focusIndex);
  // Keyboard moves keep the focus ring on a row the move just mounted.
  const select = (index, focus = true, keyboard = true) => {
    if (index < 0 || index >= count) return;
    const previous = rows[focusIndex];
    if (previous) {
      previous.tabIndex = -1;
      previous.setAttribute('aria-selected', 'false');
    }
    focusIndex = selected = index;
    const row = reveal(index);
    row.tabIndex = 0;
    row.setAttribute('aria-selected', 'true');
    if (focus) row.focus(keyboard ? {focusVisible: true} : undefined);
    row.scrollIntoView?.({block: 'nearest'});
    onSelect(index);
  };
  if (selectable) {
    box.addEventListener('keydown', event => {
      const index = Number(event.target.closest?.('[data-index]')?.dataset.index ?? focusIndex);
      if (onKey(event, index)) {
        event.preventDefault();
        return;
      }
      const next = {ArrowDown: index + 1, ArrowUp: index - 1, Home: 0, End: count - 1}[event.key];
      if (next === undefined) return;
      event.preventDefault();
      select(Math.max(0, Math.min(count - 1, next)));
    });
    box.addEventListener('click', event => {
      const row = event.target.closest?.('[data-index]');
      if (row && box.contains(row)) select(Number(row.dataset.index), true, false);
    });
  }
  return {box, rows, reveal, select, dispose: () => observer?.disconnect()};
}

function trafficPayloadButton(label, className = 'secondary-button') {
  const button = trafficNode('button', className, label);
  button.type = 'button';
  return button;
}

function trafficPayloadToggle(labels, active, onChange) {
  const group = trafficNode('div', 'traffic-payload-toggle');
  group.setAttribute('role', 'group');
  labels.forEach((label, index) => {
    const button = trafficPayloadButton(label);
    button.setAttribute('aria-pressed', String(index === active));
    button.addEventListener('click', () => onChange(index));
    group.append(button);
  });
  return group;
}

function trafficPayloadSection(id, title, meta) {
  const element = trafficNode('section', 'traffic-payload-section');
  element.dataset.section = id;
  const head = trafficNode('div', 'traffic-payload-head');
  const heading = trafficNode('h2', '', title);
  if (meta) heading.append(trafficNode('span', 'traffic-payload-count', meta));
  head.append(heading);
  element.append(head);
  return {element, head};
}

function trafficPayloadMatchesBy(shown, section) {
  const by = new Map();
  shown.find.matches.forEach((match, index) => {
    if (match.section !== section) return;
    const key = match.id ?? match.row;
    if (!by.has(key)) by.set(key, []);
    by.get(key).push({...match, match: index});
  });
  return by;
}

function trafficPayloadPairRow(pair, index, marks, current) {
  const shownPair = trafficPayloadPair(pair);
  const row = trafficNode('div', 'traffic-payload-pair');
  row.setAttribute('role', 'row');
  const name = trafficNode('span', 'traffic-payload-name', shownPair.name);
  const value = trafficNode('span', 'traffic-payload-value', shownPair.value);
  for (const cell of [name, value]) cell.setAttribute('role', 'cell');
  if (!trafficPayloadPrefs.encoded && (pair.decodedName === null || pair.decodedValue === null)) {
    row.classList.add('is-undecodable');
    row.title = 'Not valid percent-encoding; shown as sent.';
  }
  const match = marks.get(index);
  if (match) row.classList.add('is-match');
  if (match?.some(entry => entry.match === current)) row.classList.add('is-current');
  row.append(name, value);
  return row;
}

function trafficPayloadPairsArea(pairs, label, section, shown) {
  const marks = trafficPayloadMatchesBy(shown, section);
  const area = trafficPayloadArea({className: 'traffic-payload-pairs', label, role: 'table', count: pairs.length, selectable: true,
    selected: shown.selected?.section === section ? shown.selected.index : -1,
    makeRow: index => trafficPayloadPairRow(pairs[index], index, marks, shown.find.current),
    onSelect: index => {shown.selected = {section, index};}});
  const head = trafficNode('div', 'traffic-payload-pair traffic-payload-columns');
  head.setAttribute('role', 'row');
  for (const text of ['Name', 'Value']) {
    const cell = trafficNode('span', '', text);
    cell.setAttribute('role', 'columnheader');
    head.append(cell);
  }
  area.box.prepend(head);
  return area;
}

function trafficPayloadPartRow(part, index, marks, current) {
  const row = trafficNode('div', 'traffic-payload-part');
  row.setAttribute('role', 'listitem');
  const head = trafficNode('div', 'traffic-payload-part-head');
  head.append(trafficNode('span', 'traffic-payload-name', part.name ?? '(unnamed part)'));
  const meta = [part.filename === null ? null : `file ${part.filename || '(empty name)'}`, part.type, trafficByteCount(part.size),
    part.cut === 'read' ? 'continues past this read' : part.cut ? 'cut at the capture limit' : null].filter(Boolean).join(' · ');
  head.append(trafficNode('span', 'traffic-payload-part-meta', meta));
  row.append(head);
  if (part.value !== null) row.append(trafficNode('div', 'traffic-payload-value', part.value));
  else if (part.filename === null && part.size) row.append(trafficNode('div', 'traffic-payload-part-meta', 'Not UTF-8 text or over 64 KiB; see Source.'));
  const match = marks.get(index);
  if (match) row.classList.add('is-match');
  if (match?.some(entry => entry.match === current)) row.classList.add('is-current');
  return row;
}

function trafficPayloadLinesArea(rows, shown, status) {
  const marks = trafficPayloadMatchesBy(shown, 'payload');
  return createCodeView({text: rows.text, rows: rows.rows, syntax: rows.syntax, label: rows.hex ? 'Request payload hex' : 'Request payload source',
    className: 'traffic-payload-view traffic-payload-lines', rowClass: 'traffic-payload-line', wrap: trafficPayloadPrefs.wrap && !rows.hex,
    marks, current: shown.find.current, layout: rows.layout?.status === 'ready' && rows.layout.map ? rows.layout : null,
    onRaw: raw => {status.textContent = codeViewRawText(raw);}});
}

function trafficPayloadPartsArea(parts, shown) {
  const marks = trafficPayloadMatchesBy(shown, 'payload');
  return trafficPayloadArea({className: 'traffic-payload-parts', label: 'Multipart parts', role: 'list', count: parts.length,
    selectable: true, selected: shown.selected?.section === 'payload' ? shown.selected.index ?? -1 : -1,
    makeRow: index => trafficPayloadPartRow(parts[index], index, marks, shown.find.current),
    onSelect: index => {shown.selected = {section: 'payload', index};}});
}

function trafficPayloadTreeArea(model, shown, rerender, label = 'Request payload tree') {
  const visible = trafficPayloadVisible(model, shown.expanded);
  const marks = trafficPayloadMatchesBy(shown, 'payload');
  const selectedId = shown.selected?.section === 'payload' ? shown.selected.id : null;
  const expandable = node => node.group || trafficPayloadContainer(node.value);
  const toggle = (index, open) => {
    const node = visible[index];
    if (!expandable(node) || shown.expanded.has(node.id) === open) return false;
    if (open) shown.expanded.add(node.id);
    else shown.expanded.delete(node.id);
    shown.selected = {section: 'payload', id: node.id};
    rerender();
    return true;
  };
  const area = trafficPayloadArea({className: 'traffic-payload-tree', label, role: 'tree',
    count: visible.length, selectable: true, selected: selectedId ? visible.findIndex(node => node.id === selectedId) : -1,
    makeRow: index => {
      const node = visible[index];
      const row = trafficNode('div', 'traffic-payload-node');
      row.setAttribute('role', 'treeitem');
      row.setAttribute('aria-level', String(node.depth + 1));
      row.style.setProperty('--depth', String(node.depth));
      if (expandable(node)) row.setAttribute('aria-expanded', String(shown.expanded.has(node.id)));
      if (node.group) {
        row.append(trafficNode('span', 'traffic-payload-index', `[${node.start} … ${node.end - 1}]`));
      } else {
        if (node.key !== null) {
          row.append(trafficNode('span', typeof node.key === 'number' ? 'traffic-payload-index' : 'traffic-payload-key', String(node.key)),
            trafficNode('span', 'traffic-payload-colon', ': '));
        }
        const [text, kind] = trafficPayloadLeaf(model, node.value);
        const leaf = trafficNode('span', `traffic-payload-leaf is-${kind}`, text);
        if (kind === 'number' && Number.isInteger(node.value) && !Number.isSafeInteger(node.value)) {
          leaf.title = 'Beyond exact double precision; Source shows the digits as sent.';
        }
        row.append(leaf);
      }
      const match = marks.get(node.id);
      if (match) row.classList.add('is-match');
      if (match?.some(entry => entry.match === shown.find.current)) row.classList.add('is-current');
      return row;
    },
    onSelect: index => {shown.selected = {section: 'payload', id: visible[index].id};},
    onKey: (event, index) => {
      const node = visible[index];
      if (event.key === 'ArrowRight') {
        if (!toggle(index, true) && expandable(node) && visible[index + 1]?.depth === node.depth + 1) area.select(index + 1);
        return true;
      }
      if (event.key === 'ArrowLeft') {
        if (!toggle(index, false)) {
          const parent = visible.findIndex(candidate => candidate.id === node.parent);
          if (parent >= 0) area.select(parent);
        }
        return true;
      }
      if (event.key === 'Enter' || event.key === ' ') {
        toggle(index, !shown.expanded.has(node.id));
        return true;
      }
      return false;
    }});
  area.box.addEventListener('click', event => {
    const row = event.target.closest?.('[data-index]');
    if (row && area.box.contains(row)) toggle(Number(row.dataset.index), !shown.expanded.has(visible[Number(row.dataset.index)].id));
  });
  area.node = id => visible.find(node => node.id === id) ?? null;
  area.indexOf = id => visible.findIndex(node => node.id === id);
  return area;
}

function trafficPayloadSearchRows(items, needle, text) {
  const matches = [];
  for (let row = 0; row < items.length && matches.length < TRAFFIC_PAYLOAD_FIND_LIMIT; row += 1) {
    if (text(items[row]).toLowerCase().includes(needle)) matches.push({row});
  }
  return matches;
}

function trafficPayloadPartJson(part) {
  return {name: part.name, filename: part.filename, type: part.type, size: part.size, ...(part.value === null ? {} : {value: part.value}),
    ...(part.cut ? {cut: true} : {})};
}

function trafficPayloadQuerySection(query, shown, panel) {
  const {element, head} = trafficPayloadSection('query', 'Query String Parameters', query.pairs ? String(query.pairs.length) : '');
  const inert = {name: 'query', element, render() {}, search: () => [], reveal: () => null, copy: () => null, copyAll: () => null, dispose() {}};
  if (!query.pairs?.length) {
    element.append(trafficNode('p', 'traffic-payload-note', query.note ?? (query.pairs ? 'The query string is empty.'
      : 'The captured part of the path has no query string.')));
    return inert;
  }
  head.append(trafficPayloadToggle(['Decoded', 'Encoded'], Number(trafficPayloadPrefs.encoded), index => {
    trafficPayloadPrefs.encoded = index === 1;
    head.querySelectorAll('[aria-pressed]').forEach((button, at) => button.setAttribute('aria-pressed', String(at === index)));
    panel.refresh();
  }));
  const holder = trafficNode('div', 'traffic-payload-holder');
  element.append(holder);
  let area = null;
  return {name: 'query', element,
    render() {
      area?.dispose();
      area = trafficPayloadPairsArea(query.pairs, 'Query string parameters', 'query', shown);
      holder.replaceChildren(area.box);
    },
    search: (_raw, needle) => trafficPayloadSearchRows(query.pairs, needle, pair => {
      const shownPair = trafficPayloadPair(pair);
      return `${shownPair.name}\n${shownPair.value}`;
    }).map(match => ({...match, section: 'query'})),
    reveal(match) {
      this.render();
      return area.reveal(match.row);
    },
    copy(asJson) {
      if (shown.selected?.section !== 'query') return null;
      const pair = trafficPayloadPair(query.pairs[shown.selected.index]);
      return {text: asJson ? JSON.stringify(pair, null, 2) : pair.value, what: 'the selected parameter'};
    },
    copyAll: asJson => asJson ? {text: JSON.stringify(query.pairs.map(pair => trafficPayloadPair(pair)), null, 2),
      what: 'the query string parameters'} : {text: query.raw, what: 'the query string as captured'},
    dispose: () => area?.dispose()};
}

// Whether this body parses into a table or tree, which needs every retained byte.
function trafficPayloadParses(body, view) {
  const type = body?.contentType ?? '';
  if (type.startsWith('multipart/') || type === 'application/x-www-form-urlencoded' || /[/+]json$/.test(type)) return true;
  return !TRAFFIC_PAYLOAD_BINARY_TYPES.test(type) && !view?.lossy && /^\s*[[{]/.test(view?.text ?? '');
}

function trafficPayloadBodySection(body, view, shown, panel) {
  const {element, head} = trafficPayloadSection('payload', 'Request Payload', body?.contentType ?? '');
  element.dataset.state = body === undefined ? 'none' : body === null ? 'missing' : body.malformed ? 'malformed' : body.state;
  const note = text => {if (text) element.append(trafficNode('p', 'traffic-payload-note', text));};
  const inert = {name: 'payload', element, render() {}, search: () => [], reveal: () => null, copy: () => null, copyAll: () => null, dispose() {}};
  const model = shown.model;
  if (body === undefined) {
    note('This row has no native body record.');
    return inert;
  }
  if (!['captured', 'captured_truncated'].includes(body?.state)) {
    note(trafficBodyCapture(body));
    return inert;
  }
  if (view?.status !== 'ready') note(`${trafficBodyContent(body, view).note}${model ? ' Showing the last read copy.' : ''}`);
  if (!model) return inert;
  if (view?.status === 'ready' && view.complete === false) {
    // Ranged reads (protocol/native-network-v2.md): a prefix parses as source until every byte is read.
    note(trafficBodyContent(body, view).note);
    const more = trafficNode('button', 'secondary-button traffic-body-more', view.loadingMore ? 'Loading…' : 'Show the next 2 MiB');
    more.type = 'button';
    more.dataset.contentKey = view.key;
    // Not `disabled`, so keyboard focus stays on it while the range loads.
    more.setAttribute('aria-disabled', String(Boolean(view.loadingMore)));
    element.append(more);
  } else if (view?.status === 'ready' && view.verified === false) note('The retained digest could not be rechecked in this view.');
  const parsed = Boolean(model.json || model.pairs || model.parts);
  const sourceMode = () => !parsed || trafficPayloadPrefs.source;
  const options = trafficNode('div', 'traffic-payload-options');
  head.append(options);
  const holder = trafficNode('div', 'traffic-payload-holder');
  element.append(holder);
  let area = null;
  const controller = {name: 'payload', element,
    render({focus = false, keepScroll = false} = {}) {
      const scroll = keepScroll ? area?.box.scrollTop ?? 0 : 0;
      area?.dispose();
      const source = sourceMode(), rows = source ? trafficPayloadSourceRows(model) : null;
      options.replaceChildren();
      if (parsed) {
        options.append(trafficPayloadToggle(['Parsed', 'Source'], Number(source), index => {
          trafficPayloadPrefs.source = index === 1;
          panel.refresh();
        }));
      }
      if (rows && !rows.hex) {
        const wrap = trafficPayloadButton('Wrap');
        wrap.setAttribute('aria-pressed', String(trafficPayloadPrefs.wrap));
        wrap.addEventListener('click', () => {
          trafficPayloadPrefs.wrap = !trafficPayloadPrefs.wrap;
          wrap.setAttribute('aria-pressed', String(trafficPayloadPrefs.wrap));
          area.box.classList.toggle('is-wrapped', trafficPayloadPrefs.wrap);
        });
        options.append(wrap);
      }
      const notes = [model.parsedNote, rows?.note, rows?.hex ? 'Binary bytes are shown as hex and never interpreted.' : '',
        !source && model.parts && !model.parts.parts.length ? 'No part precedes the closing boundary.' : '']
        .filter(Boolean).map(text => trafficNode('p', 'traffic-payload-note', text));
      const raw = trafficNode('p', 'traffic-payload-note code-view-raw');
      raw.setAttribute('role', 'status');
      area = source ? trafficPayloadLinesArea(rows, shown, raw)
        : model.json ? trafficPayloadTreeArea(model, shown, () => controller.render({focus: true, keepScroll: true}))
          : model.pairs ? trafficPayloadPairsArea(model.pairs, 'Form fields', 'payload', shown)
            : trafficPayloadPartsArea(model.parts.parts, shown);
      holder.replaceChildren(...notes, area.box, ...(rows?.layout?.status === 'ready' && rows.layout.map ? [raw] : []));
      area.box.scrollTop = scroll;
      if (focus) area.box.querySelector('[tabindex="0"]')?.focus();
    },
    search(raw, needle) {
      if (sourceMode()) {
        return findSourceOccurrences(trafficPayloadSourceRows(model).rows.map(row => row.text), raw, TRAFFIC_PAYLOAD_FIND_LIMIT).matches
          .map(({line, column, length}) => ({section: 'payload', row: line, column, length}));
      }
      if (model.json) return trafficPayloadTreeSearch(model, needle);
      if (model.pairs) {
        return trafficPayloadSearchRows(model.pairs, needle, pair => Object.values(trafficPayloadPair(pair)).join('\n'))
          .map(match => ({...match, section: 'payload'}));
      }
      return trafficPayloadSearchRows(model.parts.parts, needle, part => [part.name, part.filename, part.type, part.value].join('\n'))
        .map(match => ({...match, section: 'payload'}));
    },
    reveal(match) {
      if (match.steps) trafficPayloadExpand(model, shown.expanded, match.steps);
      this.render();
      return area.reveal(match.steps ? area.indexOf(match.id) : match.row);
    },
    copy(asJson) {
      if (shown.selected?.section !== 'payload' || sourceMode()) return null;
      let value;
      if (model.json) {
        const node = area.node?.(shown.selected.id);
        if (!node) return null;
        value = trafficPayloadNodeValue(model, node);
        return {text: asJson || typeof value !== 'string' ? JSON.stringify(value, null, asJson || trafficPayloadContainer(value) ? 2 : 0) : value,
          what: 'the selected value'};
      }
      value = model.pairs ? trafficPayloadPair(model.pairs[shown.selected.index]) : trafficPayloadPartJson(model.parts.parts[shown.selected.index]);
      return {text: asJson ? JSON.stringify(value, null, 2) : value.value ?? value.filename ?? '', what: 'the selected value'};
    },
    copyAll(asJson) {
      if (!asJson) return {text: model.binary ? trafficPayloadSourceRows(model).text : model.text, what: model.binary ? 'the payload hex' : 'the payload as sent'};
      const value = model.json ? model.json.value : model.pairs ? model.pairs.map(pair => trafficPayloadPair(pair))
        : model.parts ? model.parts.parts.map(trafficPayloadPartJson) : model.binary ? undefined : model.text;
      return value === undefined ? null : {text: JSON.stringify(value, null, 2), what: 'the payload'};
    },
    dispose: () => area?.dispose()};
  return controller;
}

function trafficPayloadDetails(body) {
  const details = trafficNode('details', 'traffic-payload-details');
  details.toggleAttribute('open', trafficPayloadPrefs.details === true);
  details.addEventListener('toggle', () => {trafficPayloadPrefs.details = details.hasAttribute('open');});
  details.append(trafficNode('summary', '', 'Capture details'));
  const rows = body === undefined ? [['Capture', 'This row has no native body record.', 'prose']]
    : [['Capture', trafficBodyCapture(body), 'prose'], ...trafficBodyRows(body)];
  if (['captured', 'captured_truncated'].includes(body?.state)) {
    rows.push(['Retained', `${trafficByteCount(body.capturedLength)} of ${trafficByteCount(body.bodyLength)}`, 'value'],
      ['Artifact ID', body.artifactId, 'value']);
  }
  for (const [label, value, kind] of rows) {
    const row = trafficNode('div', 'traffic-general-row');
    const valueNode = trafficNode('span', 'traffic-general-value', String(value));
    valueNode.dataset.kind = kind;
    row.append(trafficNode('span', '', label), valueNode);
    details.append(row);
  }
  return details;
}

// Find, Copy value and Copy as JSON act on every section of the tab.
function trafficPayloadTools(panel, shown) {
  const tools = trafficNode('div', 'traffic-payload-tools');
  const find = trafficNode('input', 'traffic-payload-find');
  find.setAttribute('type', 'search');
  find.setAttribute('placeholder', 'Find in payload');
  find.setAttribute('aria-label', 'Find in payload');
  find.value = shown.find.query;
  const previous = trafficPayloadButton('↑', 'secondary-button traffic-payload-step');
  previous.setAttribute('aria-label', 'Previous match');
  previous.title = 'Previous match (Shift+Enter)';
  const next = trafficPayloadButton('↓', 'secondary-button traffic-payload-step');
  next.setAttribute('aria-label', 'Next match');
  next.title = 'Next match (Enter)';
  const count = trafficNode('span', 'traffic-payload-matches');
  count.setAttribute('aria-live', 'polite');
  const copyValue = trafficPayloadButton('Copy value'), copyJson = trafficPayloadButton('Copy as JSON');
  const status = trafficNode('span', 'traffic-payload-status');
  status.setAttribute('role', 'status');
  panel.count = () => {
    const {query, matches, current, truncated} = shown.find;
    count.textContent = !query ? '' : !matches.length ? 'No matches' : `${current + 1} of ${matches.length}${truncated ? '+' : ''}`;
    previous.disabled = next.disabled = matches.length < 2;
  };
  find.addEventListener('input', () => {
    shown.find.query = find.value;
    panel.search();
    panel.go(0);
  });
  find.addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      panel.go(event.shiftKey ? -1 : 1);
    } else if (event.key === 'Escape' && find.value) {
      event.preventDefault();
      find.value = shown.find.query = '';
      panel.search();
      panel.refresh();
    }
  });
  previous.addEventListener('click', () => panel.go(-1));
  next.addEventListener('click', () => panel.go(1));
  const copy = async asJson => {
    const result = panel.copy(asJson);
    if (!result) {
      status.textContent = 'Binary payloads have no JSON form.';
      return;
    }
    try {
      if (!globalThis.navigator?.clipboard?.writeText) throw new Error('unavailable');
      await navigator.clipboard.writeText(result.text);
      status.textContent = `Copied ${result.what}${asJson ? ' as JSON' : ''}.`;
    } catch {
      status.textContent = 'Clipboard access is unavailable.';
    }
  };
  copyValue.addEventListener('click', () => copy(false));
  copyJson.addEventListener('click', () => copy(true));
  tools.append(find, previous, next, count, copyValue, copyJson, status);
  return tools;
}

function renderTrafficPayload(container, request, view, targetView = null) {
  const body = request && (request.origin === 'live' || request.origin === 'demo') ? request.body ?? null : undefined;
  const identity = JSON.stringify([request?.origin ?? null, request?.id ?? null, body?.sessionId, body?.artifactId, body?.sequenceNumber]);
  const sameRequest = trafficPayloadShown?.identity === identity;
  if (!sameRequest) {
    trafficPayloadShown?.dispose();
    trafficPayloadShown = {identity, source: null, model: null, expanded: new Set(['$']), selected: null,
      find: {query: '', matches: [], current: -1, truncated: false}, dispose() {}};
  }
  const shown = trafficPayloadShown;
  if (!['captured', 'captured_truncated'].includes(body?.state)) shown.model = null;
  else if (view?.status === 'ready' && shown.source !== (view.bytes ?? view.text)) {
    shown.source = view.bytes ?? view.text;
    shown.model = trafficPayloadModel(body, view);
  } else if (view?.status === 'error' && !view.retryable) {
    // An integrity failure discards the last read; any other failure keeps it.
    shown.model = shown.source = null;
  }
  const key = JSON.stringify([identity, body, request?.path, request?.target, request?.urlTruncated, request?.hostOnly,
    targetView?.status ?? null, targetView?.loaded ?? null, targetView?.unknown ?? null, targetView?.error ?? targetView?.reason ?? '',
    view?.status ?? null, view?.error ?? view?.reason ?? '', view?.verified ?? null, view?.loaded ?? null,
    Boolean(view?.loadingMore), view?.moreError ?? '', Boolean(shown.model)]);
  if (container.dataset.renderKey === key) return;
  container.dataset.renderKey = key;
  shown.dispose();
  const query = trafficPayloadQuery(request, targetView);
  const panel = {
    search() {
      const raw = shown.find.query, needle = raw.toLowerCase();
      const matches = raw ? panel.sections.flatMap(section => section.search(raw, needle)) : [];
      shown.find = {query: raw, matches: matches.slice(0, TRAFFIC_PAYLOAD_FIND_LIMIT), current: matches.length ? 0 : -1,
        truncated: matches.length >= TRAFFIC_PAYLOAD_FIND_LIMIT};
    },
    refresh() {
      if (shown.find.query) {
        panel.search();
        panel.go(0);
        return;
      }
      for (const section of panel.sections) section.render();
      panel.count?.();
    },
    go(step) {
      const {matches} = shown.find;
      if (matches.length) shown.find.current = (shown.find.current + step + matches.length) % matches.length;
      const match = matches[shown.find.current];
      for (const section of panel.sections) if (section.name !== match?.section) section.render();
      const row = match ? panel.sections.find(section => section.name === match.section).reveal(match) : null;
      (row?.querySelector('.is-current') ?? row)?.scrollIntoView?.({block: 'center'});
      panel.count?.();
    },
    copy: asJson => {
      const selected = panel.sections.find(section => section.name === shown.selected?.section)?.copy(asJson);
      const fallback = panel.sections.find(section => section.name === (shown.model ? 'payload' : 'query'));
      return selected ?? fallback?.copyAll(asJson) ?? null;
    }
  };
  panel.sections = [query ? trafficPayloadQuerySection(query, shown, panel) : null, trafficPayloadBodySection(body, view, shown, panel)].filter(Boolean);
  const notices = [body?.state === 'captured_truncated' ? trafficBodyCapture(body) : '', query?.cut ?? ''].filter(Boolean);
  const nodes = [];
  if (notices.length) {
    const box = trafficNode('div', 'traffic-payload-notices');
    for (const text of notices) box.append(trafficNode('p', 'traffic-payload-notice', text));
    nodes.push(box);
  }
  if (query?.pairs?.length || shown.model) nodes.push(trafficPayloadTools(panel, shown));
  nodes.push(...panel.sections.map(section => section.element), trafficPayloadDetails(body, view));
  // Keyboard focus stays on the body when its next range replaces the button.
  const refocus = container.querySelector('.traffic-body-more') === globalThis.document?.activeElement;
  // The same request keeps its place when a new range arrives or the view redraws.
  const scrolls = sameRequest && !shown.find.query ? new Map([...container.querySelectorAll('.traffic-payload-section')].map(section =>
    [section.dataset.section, section.querySelector('.traffic-payload-view')?.scrollTop ?? 0])) : null;
  container.replaceChildren(...nodes);
  panel.refresh();
  for (const section of container.querySelectorAll('.traffic-payload-section')) {
    const view = section.querySelector('.traffic-payload-view'), top = scrolls?.get(section.dataset.section);
    if (view && top) view.scrollTop = top;
  }
  if (refocus) (container.querySelector('.traffic-body-more') ?? container.querySelector('.traffic-payload-view'))?.focus?.();
  shown.dispose = () => panel.sections.forEach(section => section.dispose());
  shown.relayout = () => {
    if (container.isConnected === false || !shown.model) return;
    const body = panel.sections.find(section => section.name === 'payload');
    if (shown.find.query) {panel.search(); panel.go(0);} else body?.render({keepScroll: true});
  };
}
