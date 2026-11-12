/* Sources navigator: frames, groups, origins and folders; only rows near the viewport are mounted. */
// The node bound is counted before folder chains collapse, so it is sized for
// the worst case of 20,000 sources: each adds at most a frame or group, an
// origin, 16 folders and its file (19 nodes), 380,001 with the root. A session
// of 20,000 scripts can therefore never lose a row to it; past it, the omission is shown.
const SOURCE_TREE_LIMITS = Object.freeze({nodes: 400000, depth: 16, url: 4096, identity: 8192, filter: 512, label: 512,
  row: 24, overscan: 64, frameDocuments: 64});

const SOURCE_TREE_GROUPS = Object.freeze([
  ['workers', 'Workers', 'worker', 'Loaded outside a frame: workers, worklets and requests no frame made'],
  ['dynamic', 'Dynamic (eval / new Function)', 'dynamic', 'Code compiled from strings at run time'],
  ['wasm', 'WebAssembly', 'wasm-group', 'Modules compiled from bytes, and guest artifacts read from them'],
  ['extensions', 'Extensions', 'extension', 'Extension pages and scripts, by extension ID'],
  ['internal', 'Browser internals', 'internal', 'Browser pages recorded by older sessions']
]);
const SOURCE_TREE_INTERNAL_SCHEMES = new Set(['chrome:', 'chrome-untrusted:', 'chrome-search:', 'brave:', 'devtools:']);
// Renderer-generated artifacts carry their execution context's URL: the frame's document.
const SOURCE_TREE_DOCUMENT_ORIGINS = new Set(['dynamic_javascript', 'webassembly_compile', 'webassembly_module', 'webassembly_instantiate']);
// Content sessions retain the HTML of a navigation as a response body with the frame's ID.
function sourceTreeDocumentArtifact(source) {
  const mime = String(source.mime_type ?? '').split(';', 1)[0].trim().toLowerCase();
  return SOURCE_TREE_DOCUMENT_ORIGINS.has(source.capture_origin) ||
    (source.kind === 'response_body' && (mime === 'text/html' || mime === 'application/xhtml+xml'));
}
const sourceTreeCollate = new Intl.Collator(undefined, {numeric: true, sensitivity: 'base'}).compare;

// Non-special schemes have a 'null' origin, so their host is read by hand.
function sourceTreeUrl(value) {
  if (!value) return {origin: '(anonymous)', identity: ['anonymous'], scheme: '', host: '', parts: [], search: ''};
  let url;
  try { url = new URL(value); } catch { return {origin: '(generated)', identity: ['generated'], scheme: '', host: '', parts: [], search: ''}; }
  const scheme = url.protocol;
  let {host, pathname: path, origin} = url;
  if (scheme === 'blob:') path = `/${path.split('/').at(-1)}`;
  else if (origin === 'null') {
    const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)([^?#]*)/i.exec(value);
    host = authority?.[1] ?? '';
    path = authority ? authority[2] : '';
    origin = host ? `${scheme}//${host}` : scheme;
  }
  const parts = path ? path.split('/') : [];
  if (path.startsWith('/')) parts.shift();
  return {origin, identity: ['url', origin], scheme, host, parts, search: url.search};
}

function sourceTreeOriginLabel(origin) {
  return origin.replace(/^https:\/\//, '');
}

function sourceTreePlace(source, url) {
  if (url.scheme === 'chrome-extension:') return 'extensions';
  if (SOURCE_TREE_INTERNAL_SCHEMES.has(url.scheme)) return 'internal';
  if (source.capture_origin === 'dynamic_javascript') return 'dynamic';
  if ((source.kind === 'wasm' && source.capture_origin !== 'network_response') || source.capture_origin === 'native_wasm_guest') return 'wasm';
  return String(source.frame_id) === '0' ? 'workers' : null;
}

function sourceTreeFileIcon(source) {
  const mime = String(source.mime_type ?? '').split(';', 1)[0].trim().toLowerCase();
  if (source.kind === 'javascript') return 'js';
  if (source.kind === 'wasm') return 'wasm';
  if (source.kind === 'source_map') return 'map';
  if (source.kind === 'wasm_guest_adapter' || mime === 'application/json' || mime.endsWith('+json')) return 'json';
  if (mime === 'text/html' || mime === 'application/xhtml+xml') return 'html';
  if (mime.includes('javascript')) return 'js';
  return 'file';
}

// helpers: isSource, identity, reference, name (plain file label).
function sourceTreeModel(collection, catalog, helpers, {consoleDocuments = null, catalogLimit = 0, hideInternal = false} = {}) {
  const nodes = new Map(), files = new Map(), byArtifact = new Map(), frames = new Map();
  const keyOf = (...parts) => JSON.stringify([collection, ...parts]);
  const rootKey = keyOf('root');
  const root = {key: rootKey, kind: 'root', icon: 'top', label: 'top', title: 'Every retained source', parent: null, depth: 0, children: [], count: 0};
  nodes.set(rootKey, root);
  const limits = {catalog: catalogLimit, omitted: 0, deep: 0, ambiguous: 0, internal: 0};
  const branch = (key, fields, parent) => {
    let node = nodes.get(key);
    if (!node) {
      node = {key, parent: parent.key, children: [], count: 0, ...fields};
      nodes.set(key, node); parent.children.push(key);
    }
    return node;
  };
  for (let index = 0; index < catalog.length; index++) {
    const raw = catalog[index];
    if (!helpers.isSource(raw)) continue;
    // Refuse an overlong path before URL parsing or identity serialization.
    if (typeof raw.url !== 'string' || raw.url.length > SOURCE_TREE_LIMITS.url) {limits.omitted++; continue;}
    const source = {...helpers.reference(raw), source_type: 'artifact'};
    const identity = helpers.identity(source);
    if (!identity || identity.length > SOURCE_TREE_LIMITS.identity) {limits.omitted++; continue;}
    const key = keyOf('source', identity);
    // Duplicate exact identities must never become two apparent choices.
    if (files.has(key)) {files.get(key).ambiguous = true; limits.ambiguous++; continue;}
    const url = sourceTreeUrl(source.url), group = sourceTreePlace(source, url);
    // Counted, reversible and shared with Traffic (protocol/native-network-v3.md).
    if (group === 'internal') {
      limits.internal++;
      if (hideInternal) continue;
    }
    const frameId = ['frame', String(source.session_id), String(source.frame_id)];
    if (frameId[2] !== '0') {
      const frame = frames.get(frameId.join(':')) ?? {first: index, documents: new Set(), documentOrigin: null, firstOrigin: null};
      frames.set(frameId.join(':'), frame);
      if (url.identity[0] === 'url') frame.firstOrigin ??= url.origin;
      if (sourceTreeDocumentArtifact(source) && url.identity[0] === 'url') {
        frame.documentOrigin ??= url.origin;
        if (frame.documents.size < SOURCE_TREE_LIMITS.frameDocuments) frame.documents.add(source.url);
      }
    }
    const container = group ? ['group', group] : frameId;
    const containerKey = keyOf(...container);
    const directories = url.parts.slice(0, -1), bounded = directories.slice(0, SOURCE_TREE_LIMITS.depth);
    const originKey = keyOf('origin', container, url.identity);
    const folderKeys = bounded.map((_, depth) => keyOf('folder', container, url.identity, bounded.slice(0, depth + 1)));
    const fresh = [containerKey, originKey, ...folderKeys].filter(value => !nodes.has(value)).length;
    if (nodes.size + fresh + 1 > SOURCE_TREE_LIMITS.nodes) {limits.omitted++; continue;}
    if (directories.length > SOURCE_TREE_LIMITS.depth) limits.deep++;
    const groupIndex = SOURCE_TREE_GROUPS.findIndex(([name]) => name === group);
    const top = group
      ? branch(containerKey, {kind: 'group', group, icon: SOURCE_TREE_GROUPS[groupIndex][2], label: SOURCE_TREE_GROUPS[groupIndex][1],
        title: SOURCE_TREE_GROUPS[groupIndex][3], rank: groupIndex, collapsed: group === 'internal'}, root)
      : branch(containerKey, {kind: 'frame', icon: 'frame', label: 'frame', frameKey: frameId.join(':'),
        session: frameId[1], frameId: frameId[2]}, root);
    const originLabel = group === 'extensions' ? url.host || '(no extension ID)' : sourceTreeOriginLabel(url.origin);
    let parent = branch(originKey, {kind: 'origin', icon: group === 'extensions' ? 'extension' : 'origin', label: originLabel,
      title: url.origin, origin: url.origin}, top);
    const ancestors = [root, top, parent];
    bounded.forEach((segment, depth) => {
      parent = branch(folderKeys[depth], {kind: 'folder', icon: 'folder', label: segment || '(empty path segment)',
        title: `${url.origin}/${bounded.slice(0, depth + 1).join('/')}`}, parent);
      ancestors.push(parent);
    });
    const node = {key, identity, kind: 'file', icon: sourceTreeFileIcon(source), label: helpers.name(source), source,
      search: url.search, parent: parent.key, children: null};
    nodes.set(key, node); files.set(key, node); parent.children.push(key);
    if (!byArtifact.has(source.artifact_id)) byArtifact.set(source.artifact_id, []);
    byArtifact.get(source.artifact_id).push(node);
    for (const ancestor of ancestors) ancestor.count++;
  }
  sourceTreeFrames(nodes, root, frames, consoleDocuments);
  sourceTreeCompact(nodes, root);
  sourceTreeArrange(nodes, root);
  return {collection, rootKey, nodes, files, byArtifact, limits};
}

// A frame is named by its Console document URL, else the origin of its first document artifact.
// With neither, the origin of its first source is marked as such, because it may not be the frame's own.
function sourceTreeFrames(nodes, root, frames, consoleDocuments) {
  const shortUrl = value => {
    try { const url = new URL(value); return sourceTreeOriginLabel(`${sourceTreeUrl(value).origin}${url.origin === 'null' ? '' : url.pathname}`); } catch { return value; }
  };
  let earliest = null;
  for (const key of root.children) {
    const node = nodes.get(key);
    if (node.kind !== 'frame') continue;
    const frame = frames.get(node.frameKey);
    const match = Array.isArray(consoleDocuments) ? consoleDocuments.find(item => typeof item?.url === 'string' && frame.documents.has(item.url)) : null;
    node.label = match ? shortUrl(match.url) : frame.documentOrigin ? sourceTreeOriginLabel(frame.documentOrigin)
      : frame.firstOrigin ? `frame · ${sourceTreeOriginLabel(frame.firstOrigin)}` : `frame ${node.frameId}`;
    node.top = Boolean(match?.main_frame);
    node.first = frame.first;
    node.documentOrigin = frame.documentOrigin;
    node.title = `${match ? match.url : frame.documentOrigin ?? `No document URL recorded${frame.firstOrigin ? `; first source from ${frame.firstOrigin}` : ''}`} · frame ${node.frameId} · session ${node.session}${node.top ? ' · top-level document' : ''}`;
    if (!earliest || node.first < earliest.first) earliest = node;
  }
  // Without a Console listing the frame seen first is listed first.
  const anyTop = root.children.some(key => nodes.get(key).top);
  for (const key of root.children) {
    const node = nodes.get(key);
    if (node.kind === 'frame') node.rank = node.top || (!anyTop && node === earliest) ? 0 : 1;
  }
}

// One-folder chains read as one row and keep the deepest key, so expansion survives a split.
function sourceTreeCompact(nodes, root) {
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    node.children = node.children.map(key => {
      let child = nodes.get(key);
      while (child.kind === 'folder' && child.children.length === 1 && nodes.get(child.children[0]).kind === 'folder') {
        const next = nodes.get(child.children[0]);
        nodes.delete(child.key);
        next.label = `${child.label}/${next.label}`;
        next.parent = child.parent;
        child = next;
      }
      if (child.children) stack.push(child);
      return child.key;
    });
  }
}

function sourceTreeArrange(nodes, root) {
  const order = {frame: 0, group: 1, origin: 2, folder: 3, file: 4};
  const compare = (left, right) => order[left.kind] - order[right.kind] || (left.rank ?? 0) - (right.rank ?? 0) ||
    sourceTreeCollate(left.label, right.label) || (left.key < right.key ? -1 : left.key > right.key ? 1 : 0);
  root.depth = 0; root.position = 1; root.size = 1;
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    const children = node.children.map(key => nodes.get(key));
    if (node.kind === 'frame') for (const child of children) child.rank = child.origin === node.documentOrigin ? 0 : 1;
    children.sort(compare);
    node.children = children.map(child => child.key);
    sourceTreeSuffixes(children);
    children.forEach((child, index) => {
      child.depth = node.depth + 1; child.position = index + 1; child.size = children.length;
      if (child.children) stack.push(child);
    });
  }
}

// Same-named siblings get a muted query, session or frame suffix; the artifact ID separates any that still match.
function sourceTreeSuffixes(children) {
  const groups = new Map();
  for (const child of children) {
    if (child.kind !== 'file' && child.kind !== 'frame') continue;
    const name = `${child.kind}\n${child.label}`;
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(child);
  }
  for (const members of groups.values()) {
    if (members.length < 2) continue;
    const sessions = new Set(members.map(member => member.session ?? member.source.session_id));
    if (members[0].kind === 'frame') {
      for (const member of members) member.suffix = sessions.size > 1 ? `session ${member.session}` : `frame ${member.frameId}`;
      continue;
    }
    const queries = new Set(members.map(member => member.search)), frames = new Set(members.map(member => member.source.frame_id));
    for (const member of members) {
      const query = member.search.length > 64 ? `${member.search.slice(0, 63)}…` : member.search;
      member.suffix = queries.size > 1 ? query || '(no query)' : sessions.size > 1 ? `session ${member.source.session_id}`
        : frames.size > 1 ? `frame ${member.source.frame_id}` : '';
    }
    const uses = new Map();
    for (const member of members) uses.set(member.suffix, (uses.get(member.suffix) ?? 0) + 1);
    for (const member of members) if (uses.get(member.suffix) > 1) member.suffix = `${member.suffix} #${member.source.artifact_id}`.trim();
  }
}

// A filter shows matches and their ancestors with its own expansion.
// `scope` keeps only files whose exact identity it accepts, with their ancestors.
function sourceTreeRows(model, collapsed, filter = '', scope = null) {
  const rows = [], index = new Map();
  let include = null, counts = null;
  if (filter || scope) {
    include = new Set(); counts = new Map();
    for (const file of model.files.values()) {
      if (scope && !scope.includes(file.source)) continue;
      file.text ??= `${file.label}\n${file.source.url}\n${file.source.artifact_id}`.toLowerCase();
      if (!file.text.includes(filter)) continue;
      for (let key = file.key; key; key = model.nodes.get(key).parent) {
        include.add(key);
        if (key !== file.key) counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }
  }
  const stack = model.nodes.get(model.rootKey).count ? [model.rootKey] : [];
  while (stack.length) {
    const node = model.nodes.get(stack.pop());
    if (include && !include.has(node.key)) continue;
    index.set(node.key, rows.length); rows.push(node);
    if (node.children && !collapsed(node)) for (let child = node.children.length - 1; child >= 0; child--) stack.push(node.children[child]);
  }
  return {rows, index, counts};
}

function createSourceTree(options) {
  const {tree, filter, expand, collapse, helpers} = options;
  const ROW = SOURCE_TREE_LIMITS.row;
  const nav = {scopes: new Map(), rows: new Map(), model: null, list: [], index: new Map(), counts: null, stale: true, generation: 0,
    refs: null, filter: '', filterCollapsed: new Set(), typeahead: {text: '', time: 0}, selected: null, notice: null, scopeKey: null};
  const canvas = document.createElement('div');
  canvas.className = 'source-tree-canvas';
  tree.append(canvas);
  const scopeOf = collection => {
    if (!nav.scopes.has(collection)) nav.scopes.set(collection, {open: new Map(), focus: null, scrollTop: 0});
    return nav.scopes.get(collection);
  };
  const scope = () => scopeOf(nav.model.collection);
  const collapsed = node => {
    if (!node.children?.length) return false;
    if (nav.filter) return nav.filterCollapsed.has(node.key);
    const open = scope().open;
    return open.has(node.key) ? !open.get(node.key) : Boolean(node.collapsed);
  };
  const canvasTop = () => canvas.offsetTop || 0;
  const viewport = () => tree.clientHeight || 40 * ROW;

  // Records are compared by reference, so an in-place catalog edit is seen.
  function catalogChanged() {
    const list = options.catalog(), refs = nav.refs;
    return !refs || refs.docs !== options.consoleDocuments() || refs.limit !== options.catalogLimit() ||
      refs.hide !== Boolean(options.hideInternal?.()) ||
      refs.items.length !== list.length || list.some((item, index) => item !== refs.items[index]);
  }

  function rebuild() {
    const collection = options.collection(), list = options.catalog(), docs = options.consoleDocuments(), limit = options.catalogLimit();
    const hide = Boolean(options.hideInternal?.());
    nav.refs = {docs, limit, hide, items: list.slice()};
    nav.model = sourceTreeModel(collection, list, helpers, {consoleDocuments: docs, catalogLimit: limit, hideInternal: hide});
    const open = scopeOf(collection).open;
    // Deleted branches cannot grow an unbounded preference history.
    for (const key of open.keys()) if (!nav.model.nodes.get(key)?.children) open.delete(key);
    for (const key of nav.filterCollapsed) if (!nav.model.nodes.has(key)) nav.filterCollapsed.delete(key);
    nav.stale = true;
  }

  function anchor() {
    const offset = tree.scrollTop - canvasTop();
    if (!(tree.scrollTop > 0) || !nav.list.length) return null;
    const index = Math.max(0, Math.min(nav.list.length - 1, Math.floor(offset / ROW)));
    return {key: nav.list[index].key, offset: offset - index * ROW};
  }

  function nearest(key, previous) {
    for (let count = 0; key && count <= SOURCE_TREE_LIMITS.depth + 4; count++) {
      if (nav.index.has(key)) return key;
      key = (nav.model.nodes.get(key) ?? previous?.nodes.get(key))?.parent;
    }
    return null;
  }

  function render(refresh = true) {
    const active = document.activeElement, hadFocus = tree.contains(active);
    const activeKey = hadFocus ? active?.dataset?.sourceTreeKey : null;
    const previous = nav.model, collection = options.collection();
    const kept = previous?.collection === collection ? anchor() : null;
    if (previous) scopeOf(previous.collection).scrollTop = tree.scrollTop;
    if (!previous || previous.collection !== collection || (refresh && catalogChanged())) rebuild();
    const model = nav.model, current = scope(), narrowed = options.scope?.() ?? null;
    if (nav.scopeKey !== (narrowed?.key ?? null)) {nav.scopeKey = narrowed?.key ?? null; nav.stale = true;}
    if (nav.stale) {
      const filterText = nav.filter.toLowerCase();
      ({rows: nav.list, index: nav.index, counts: nav.counts} = sourceTreeRows(model, collapsed, filterText, narrowed));
      nav.stale = false;
    }
    const candidates = model.byArtifact.get(options.selectedId()) ?? [];
    // Selection must agree with the authoritative raw catalog, including
    // records omitted by limits. An incomplete catalog cannot prove uniqueness.
    nav.selected = !model.limits.catalog && candidates.length === 1 && !candidates[0].ambiguous &&
      nav.index.has(candidates[0].key) && helpers.isCurrent(candidates[0].source) ? candidates[0] : null;
    current.focus = nearest(activeKey ?? current.focus, previous) ?? nav.selected?.key ?? nav.list[0]?.key ?? null;
    renderNotice(model, narrowed);
    canvas.style.setProperty('height', `${nav.list.length * ROW}px`);
    if (kept && nav.index.has(kept.key)) tree.scrollTop = canvasTop() + nav.index.get(kept.key) * ROW + kept.offset;
    else if (!previous || previous.collection !== collection) tree.scrollTop = current.scrollTop;
    tree.tabIndex = nav.list.length ? -1 : 0;
    nav.generation++;
    paint();
    if (hadFocus) {
      if (current.focus) focusRow(current.focus, Boolean(activeKey && activeKey !== current.focus));
      else tree.focus({preventScroll: true});
    }
  }

  function renderNotice(model, narrowed) {
    const notices = narrowed ? [narrowed.label] : [];
    if (model.limits.catalog) notices.push(`More than ${model.limits.catalog.toLocaleString()} sources are retained; later ones are not loaded. Selection markers are withheld until the whole catalog loads.`);
    if (model.limits.omitted) notices.push(`${model.limits.omitted} sources exceed the navigator URL, identity or node limit and are not listed.`);
    if (model.limits.ambiguous) notices.push(`${model.limits.ambiguous} duplicate source identities are not shown twice; ambiguous sources cannot be opened.`);
    if (model.limits.deep) notices.push(`${model.limits.deep} paths are shortened after ${SOURCE_TREE_LIMITS.depth} folders; file tooltips keep their full URLs.`);
    const hidden = model.limits.internal && options.hideInternal?.();
    if (hidden) notices.push(`${model.limits.internal} browser-internal ${model.limits.internal === 1 ? 'source is' : 'sources are'} hidden.`);
    if (!nav.list.length && nav.filter && model.files.size) notices.push(`No files match “${nav.filter}”.`);
    else if (!nav.list.length && narrowed && model.files.size) notices.push(narrowed.empty);
    else if (!nav.list.length && !hidden) notices.push('No source artifacts captured. Canvas images are shown in Fingerprinting.');
    const toggle = model.limits.internal ? options.internalToggle?.(model.limits.internal) : null;
    if (!notices.length && !toggle) {nav.notice?.remove(); return;}
    if (!nav.notice) {
      nav.notice = document.createElement('div'); nav.notice.className = 'source-tree-empty'; nav.notice.setAttribute('role', 'status');
    }
    const toggleFocused = Boolean(toggle) && document.activeElement === toggle;
    nav.notice.textContent = notices.join(' ');
    // Above listed rows it is a disclosure, not the empty state, so it takes no empty-state padding.
    nav.notice.className = nav.list.length ? 'source-tree-empty source-tree-disclosure' : 'source-tree-empty';
    if (toggle) nav.notice.append(toggle);
    if (toggleFocused) toggle.focus({preventScroll: true});
    // Limit disclosures stay above the rows, including when nothing is listed.
    if (tree.children[0] !== nav.notice) tree.insertBefore(nav.notice, tree.children[0] ?? null);
  }

  function paint() {
    const list = nav.list, focusIndex = nav.index.get(scope().focus);
    const visible = Math.ceil(viewport() / ROW), overscan = Math.max(SOURCE_TREE_LIMITS.overscan, visible);
    const first = Math.floor(Math.max(0, tree.scrollTop - canvasTop()) / ROW);
    const start = Math.max(0, first - overscan), end = Math.min(list.length, first + visible + overscan);
    const wanted = [];
    // The tab stop stays mounted while it is scrolled away.
    if (focusIndex !== undefined && focusIndex < start) wanted.push(focusIndex);
    for (let index = start; index < end; index++) wanted.push(index);
    if (focusIndex !== undefined && focusIndex >= end) wanted.push(focusIndex);
    const keys = new Set(wanted.map(index => list[index].key));
    for (const [key, entry] of nav.rows) if (!keys.has(key)) {entry.row.remove(); nav.rows.delete(key);}
    const rows = wanted.map(index => update(list[index], index));
    rows.forEach((row, index) => {if (canvas.children[index] !== row) canvas.insertBefore(row, canvas.children[index] ?? null);});
  }

  // Rows painted in this render are current; scrolling paints only new rows.
  function update(node, index) {
    let entry = nav.rows.get(node.key);
    if (!entry) {entry = createRow(node.key); nav.rows.set(node.key, entry);}
    if (entry.generation === nav.generation) return entry.row;
    entry.generation = nav.generation;
    const {row, twisty, icon, raw, suffix, researcher, detail} = entry;
    const file = Boolean(node.source);
    row.dataset.sourceTreeKind = node.kind;
    row.style.setProperty('--source-row', String(index));
    row.style.setProperty('--source-depth', String(Math.min(node.depth, 8)));
    row.setAttribute('aria-level', String(node.depth + 1));
    row.setAttribute('aria-posinset', String(node.position)); row.setAttribute('aria-setsize', String(node.size));
    row.tabIndex = scope().focus === node.key ? 0 : -1;
    const label = node.label.length > SOURCE_TREE_LIMITS.label ? `${node.label.slice(0, SOURCE_TREE_LIMITS.label - 1)}…` : node.label;
    if (raw.textContent !== label) raw.textContent = label;
    if (suffix.textContent !== (node.suffix ?? '')) suffix.textContent = node.suffix ?? '';
    suffix.hidden = !node.suffix;
    const name = file ? options.researcherName(node.source) : null;
    if (researcher.textContent !== (name ?? '')) researcher.textContent = name ?? '';
    researcher.hidden = !name;
    const kind = file ? options.kindLabel(node.source) : null;
    icon.className = file ? 'source-file-icon' : 'source-tree-icon';
    icon.dataset.icon = node.icon;
    icon.textContent = file ? kind?.[0] ?? '?' : '';
    icon.title = file ? kind?.[1] ?? node.source.kind : '';
    const count = nav.counts?.get(node.key) ?? node.count;
    const id = file ? String(node.source.artifact_id) : '';
    detail.textContent = file ? label.endsWith(id) ? '' : id : String(count);
    const where = file ? `${node.source.url || '(anonymous)'} · artifact ${id}` : node.title ?? label;
    row.title = name ? `${name} (researcher name) · ${where}` : where;
    const described = file ? `${kind?.[1] ?? node.source.kind}, artifact ${id}` : `${count} ${count === 1 ? 'file' : 'files'}`;
    row.setAttribute('aria-label', `${name ? `${name} (researcher name), ` : ''}${label}${node.suffix ? ` ${node.suffix}` : ''}, ${described}`);
    if (file) {
      row.dataset.artifactId = node.source.artifact_id;
      row.setAttribute('aria-selected', String(node === nav.selected));
    } else row.setAttribute('aria-expanded', String(!collapsed(node)));
    return row;
  }

  function createRow(key) {
    const row = document.createElement('button');
    row.type = 'button'; row.className = 'source-tree-row'; row.dataset.sourceTreeKey = key;
    row.setAttribute('role', 'treeitem');
    const twisty = document.createElement('span'); twisty.className = 'source-tree-twisty'; twisty.setAttribute('aria-hidden', 'true');
    const icon = document.createElement('span');
    const name = document.createElement('span'); name.className = 'source-tree-name';
    // A researcher name leads the cell; the captured label stays beside it.
    const researcher = document.createElement('span'); researcher.className = 'researcher-name'; researcher.hidden = true;
    const raw = document.createElement('span'); raw.className = 'source-tree-raw';
    const suffix = document.createElement('span'); suffix.className = 'source-tree-suffix'; suffix.hidden = true;
    name.append(researcher, raw, suffix);
    const detail = document.createElement('span'); detail.className = 'source-tree-meta';
    row.append(twisty, icon, name, detail);
    row.addEventListener('focus', () => {
      if (!nav.model?.nodes.has(key)) return;
      scope().focus = key;
      for (const [rowKey, entry] of nav.rows) entry.row.tabIndex = rowKey === key ? 0 : -1;
    });
    row.addEventListener('keydown', event => keydown(event, key));
    row.addEventListener('click', () => {
      const node = nav.model?.nodes.get(key);
      if (!node) return;
      scope().focus = key;
      if (node.children) toggle(key);
      else if (helpers.isCurrent(node.source)) options.open(node.source.artifact_id);
      else options.stale();
    });
    return {row, twisty, icon, raw, suffix, researcher, detail};
  }

  function focusRow(key, reveal = false, keyboard = false) {
    const index = nav.index.get(key);
    if (index === undefined) return;
    scope().focus = key;
    if (reveal) {
      // Scroll only the navigator, never the editor or an outer workspace.
      const top = canvasTop() + index * ROW, height = viewport();
      if (top < tree.scrollTop) tree.scrollTop = top;
      else if (top + ROW > tree.scrollTop + height) tree.scrollTop = top + ROW - height;
    }
    paint();
    const entry = nav.rows.get(key);
    for (const [rowKey, value] of nav.rows) value.row.tabIndex = rowKey === key ? 0 : -1;
    entry.row.focus(keyboard ? {preventScroll: true, focusVisible: true} : {preventScroll: true});
  }

  function toggle(key, expanded = null) {
    const node = nav.model?.nodes.get(key);
    if (!node?.children?.length) return;
    const open = expanded ?? collapsed(node);
    if (nav.filter) {if (open) nav.filterCollapsed.delete(key); else nav.filterCollapsed.add(key);}
    else scope().open.set(key, open);
    nav.stale = true;
    render(false);
  }

  function setAll(open) {
    if (!nav.model) return;
    for (const node of nav.model.nodes.values()) {
      if (!node.children || (!open && node.key === nav.model.rootKey)) continue;
      if (nav.filter) {if (open) nav.filterCollapsed.delete(node.key); else nav.filterCollapsed.add(node.key);}
      else scope().open.set(node.key, open);
    }
    nav.stale = true;
    render(false);
  }

  // Repeating one letter cycles through the rows that start with it.
  function typeahead(character, index) {
    const now = Date.now(), state = nav.typeahead, list = nav.list;
    state.text = (now - state.time > 700 ? '' : state.text).concat(character.toLowerCase()).slice(0, 64);
    state.time = now;
    const repeated = [...state.text].every(value => value === state.text[0]);
    const needle = repeated ? state.text[0] : state.text;
    const from = repeated ? index + 1 : index;
    for (let step = 0; step < list.length; step++) {
      const node = list[(from + step) % list.length];
      if (node.label.toLowerCase().startsWith(needle)) return node.key;
    }
    return null;
  }

  function keydown(event, key) {
    // Leave browser/history/OS chords and native button Enter/Space alone.
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    const printable = event.key.length === 1 && event.key !== ' ';
    if (event.shiftKey && !printable) return;
    const node = nav.model?.nodes.get(key);
    if (!node) return;
    const index = nav.index.get(key) ?? 0, list = nav.list;
    let next;
    if (event.key === 'ArrowDown') next = list[Math.min(index + 1, list.length - 1)]?.key;
    else if (event.key === 'ArrowUp') next = list[Math.max(0, index - 1)]?.key;
    else if (event.key === 'Home') next = list[0]?.key;
    else if (event.key === 'End') next = list.at(-1)?.key;
    else if (event.key === 'ArrowRight') {
      if (node.children?.length && collapsed(node)) toggle(key, true);
      else if (node.children?.length && list[index + 1]?.parent === key) next = list[index + 1].key;
    } else if (event.key === 'ArrowLeft') {
      if (node.children?.length && !collapsed(node)) toggle(key, false);
      else next = node.parent;
    } else if (event.key === 'PageDown' || event.key === 'PageUp') {
      const page = Math.max(1, Math.floor(viewport() / ROW) - 1);
      next = list[Math.max(0, Math.min(list.length - 1, index + (event.key === 'PageDown' ? page : -page)))]?.key;
    } else if (printable) next = typeahead(event.key, index);
    else return;
    event.preventDefault(); event.stopPropagation();
    if (next) focusRow(next, true, true);
  }

  tree.addEventListener('scroll', () => {if (nav.model) paint();});
  if (typeof ResizeObserver === 'function') new ResizeObserver(() => {if (nav.model) paint();}).observe(tree);
  filter?.addEventListener('input', () => {
    nav.filter = filter.value.trim().slice(0, SOURCE_TREE_LIMITS.filter);
    nav.filterCollapsed.clear(); nav.stale = true; tree.scrollTop = 0;
    if (nav.model) render(false);
  });
  filter?.addEventListener('keydown', event => {
    if (event.key === 'Escape' && filter.value) {event.preventDefault(); filter.value = ''; filter.dispatchEvent(new Event('input'));}
    else if (event.key === 'ArrowDown' && nav.model && scope().focus) {event.preventDefault(); focusRow(scope().focus, true, true);}
  });
  expand?.addEventListener('click', () => setAll(true));
  collapse?.addEventListener('click', () => setAll(false));

  return {render, toggle, focus: focusRow, keydown, expandAll: () => setAll(true), collapseAll: () => setAll(false), state: () => nav};
}
