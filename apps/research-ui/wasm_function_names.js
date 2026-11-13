/* Researcher names for Wasm functions wherever a function appears: Sources
 * Inspect, the Graph function list and title, Flow graph cards, Initiator
 * frames and cross-references. A name is keyed by the module's SHA-256 and
 * the function index in the full index space (imports included), so it
 * follows identical module bytes across sessions. It is shown beside the
 * captured identity (`func N`, import, export and name-section names) and
 * never replaces it. Names are stored by evidence_names.js; this module only
 * reads them, renders them as text and starts its inline editor.
 * Contract: protocol/wasm-function-names-v1.md. */
(function () {
  'use strict';
  const names = () => globalThis.RebEvidenceNames;
  const listeners = new Set();
  // Rows whose function_index is the row's own function. Body rows (locals,
  // instructions) carry their function too but are not its header.
  const HEADER_KINDS = new Set(['function', 'import', 'declaration', 'start']);
  const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  const index = value => Number.isInteger(value) && value >= 0 && value <= 4294967295;

  function nameOf(sha256, functionIndex) {
    return hash(sha256) && index(functionIndex) ? names()?.wasmFunctionName?.(sha256, functionIndex) ?? null : null;
  }
  function nameNode(name, className = '') {
    const node = document.createElement('span');
    node.className = `researcher-name${className ? ` ${className}` : ''}`;
    node.textContent = name ?? '';
    node.hidden = !name;
    if (name) node.title = `${name} (researcher name)`;
    return node;
  }
  function setName(node, name) {
    node.textContent = name ?? '';
    node.hidden = !name;
    node.title = name ? `${name} (researcher name)` : '';
  }
  function subscribe(listener) {listeners.add(listener); return () => listeners.delete(listener);}

  // Where a marked element's editor opens, when not the Sources toolbar.
  const editorHosts = new WeakMap();
  // Marks an element as standing for one function, so F2 inside it renames
  // that function. `label` is the captured identity the editor names.
  function mark(node, sha256, functionIndex, label, editorHost = null, focusFallback = null) {
    if (!node?.dataset) return;
    if (!hash(sha256) || !index(functionIndex)) {unmark(node); return;}
    if (editorHost) editorHosts.set(node, editorHost); else editorHosts.delete(node);
    if (focusFallback) editorFallbacks.set(node, focusFallback); else editorFallbacks.delete(node);
    node.dataset.wasmSha = sha256;
    node.dataset.wasmFunction = String(functionIndex);
    node.dataset.wasmLabel = label ?? `func ${functionIndex}`;
  }
  function unmark(node) {
    if (!node?.dataset) return;
    delete node.dataset.wasmSha; delete node.dataset.wasmFunction; delete node.dataset.wasmLabel;
  }
  const marked = node => {
    const sha = node?.dataset?.wasmSha, value = Number(node?.dataset?.wasmFunction);
    return hash(sha) && index(value) && node.dataset.wasmFunction === String(value) ? {sha256: sha, function: value, label: node.dataset.wasmLabel} : null;
  };

  // Starts the shared inline editor. The default host is the Sources toolbar
  // slot every source rename already uses.
  function begin({sha256, function: functionIndex, label, host, restore, isCurrent}) {
    const api = names(), controller = api?.controller?.();
    const identity = api?.wasmFunctionIdentity?.(sha256, functionIndex);
    const slot = host ?? document.querySelector('#source-name-host');
    if (!controller || !identity || !slot) return false;
    return controller.begin({identity, label: label ?? `func ${functionIndex}`, host: slot, restore, isCurrent});
  }
  // Where focus returns after the editor closes: the control that started
  // it while it is still in the document, else the view's own fallback (a
  // redrawn button or its canvas), else the marked element when it can take
  // focus. Never the body, where keyboard use would be lost.
  const focusable = node => node?.isConnected && node !== document.body && !node.disabled && (node.tabIndex >= 0 || node.matches?.('button, a[href], input, select, textarea'));
  const editorFallbacks = new WeakMap();
  function beginFrom(node, options = {}) {
    const target = marked(node);
    if (!target) return false;
    const invoker = document.activeElement, fallback = options.fallback ?? editorFallbacks.get(node);
    return begin({...target, host: options.host ?? editorHosts.get(node),
      restore: () => [invoker, fallback?.(), node].find(focusable) ?? null,
      isCurrent: () => node.isConnected && marked(node)?.sha256 === target.sha256 && marked(node)?.function === target.function});
  }

  // Sources Inspect. The listing text is captured-derived and stays exactly
  // as decoded; a name slot and a rename button follow it.
  function decorateInspectRow(node, row, sha256) {
    if (!node?.append || !row || !hash(sha256)) return;
    // The line is a gutter and an excerpt; the name joins the excerpt, after
    // the captured text, so Find and coloring still see only that text.
    const line = node.querySelector?.(':scope > .source-excerpt') ?? node;
    const own = HEADER_KINDS.has(row.kind) && index(row.function_index), target = index(row.target_function_index);
    if (!own && !target) return;
    if (own) {
      mark(node, sha256, row.function_index, `func ${row.function_index}`);
      const slot = nameNode(nameOf(sha256, row.function_index), 'wasm-function-name');
      const rename = document.createElement('button');
      rename.type = 'button'; rename.className = 'wasm-function-rename'; rename.textContent = '✎';
      rename.setAttribute('aria-label', `Rename func ${row.function_index}`);
      rename.title = `Rename func ${row.function_index} (F2)`;
      rename.addEventListener('click', event => {event.stopPropagation(); beginFrom(node);});
      line.append(slot, rename);
    } else {
      mark(node, sha256, row.target_function_index, `func ${row.target_function_index}`);
      if (node.dataset) node.dataset.wasmTarget = 'true';
      line.append(nameNode(nameOf(sha256, row.target_function_index), 'wasm-function-name wasm-function-target'));
    }
  }
  function refreshMarked(root = document) {
    for (const node of root.querySelectorAll?.('.source-line[data-wasm-function]') ?? []) {
      const target = marked(node), slot = node.querySelector('.wasm-function-name');
      if (target && slot) setName(slot, nameOf(target.sha256, target.function));
    }
  }
  function changed() {
    refreshMarked();
    for (const listener of [...listeners]) {
      try {listener();} catch (error) {console.error(error);}
    }
  }

  // An engine without `:modal` (an offline DOM) has no modal dialogs either.
  const modalOpen = () => {try {return Boolean(document.querySelector('dialog:modal'));} catch {return false;}};
  const isMarked = node => node?.matches?.('[data-wasm-function]') && node.isConnected ? node : null;
  // Inspect rows are spans and never take focus: a click leaves it on the
  // code view (#source-code-wrap) or the body. The row the caret selection is
  // in, else the row last pointed at, else the current line names the
  // function under the cursor.
  let pointedRow = null;
  function inspectRow() {
    const code = document.querySelector('#source-code');
    if (!code || code.hidden) return null;
    const selection = globalThis.getSelection?.(), anchor = selection?.rangeCount ? selection.anchorNode : null;
    const element = anchor?.nodeType === 1 ? anchor : anchor?.parentElement;
    const selected = element && code.contains(element) ? element.closest('.source-line') : null;
    if (selected) return isMarked(selected);
    const pointed = pointedRow?.deref?.() ?? null;
    if (pointed && code.contains(pointed)) return isMarked(pointed);
    return isMarked(code.querySelector('.source-line.current-line'));
  }
  // The open Graph stands for the function it draws, wherever WebKit left
  // focus inside the editor.
  function openGraph() {
    const host = document.querySelector('#source-graph-host');
    return host && !host.hidden ? isMarked(host) : null;
  }
  // Which function F2 names, or null to leave the key to the Sources handler
  // (a tree row, a tab or the toolbar renames the file).
  function f2Target(target) {
    const own = target?.closest?.('[data-wasm-function]');
    if (own) return own;
    if (target?.closest?.('.source-tree-row, .source-editor-tab')) return null;
    if (target?.closest?.('#source-code-wrap')) return inspectRow() ?? openGraph();
    if (!target || target === document.body || target === document.documentElement) {
      const sources = document.querySelector('#screen-sources');
      return sources && !sources.hidden ? openGraph() ?? inspectRow() : null;
    }
    return null;
  }
  // F2 renames the function under the cursor, as in a disassembler. Text
  // fields and modal dialogs keep the key. Handling it first stops the
  // Sources handler from renaming the file instead.
  if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
    document.addEventListener('pointerdown', event => {
      const row = event.target?.closest?.('#source-code .source-line');
      if (row) pointedRow = typeof WeakRef === 'function' ? new WeakRef(row) : {deref: () => row};
    }, true);
    document.addEventListener('keydown', event => {
      if (event.key !== 'F2' || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || event.repeat || event.defaultPrevented) return;
      const target = event.target;
      if (target?.closest?.('input, textarea, select, [contenteditable="true"]') || modalOpen()) return;
      const node = f2Target(target);
      if (node && beginFrom(node)) event.preventDefault();
    });
  }

  globalThis.RebWasmFunctionNames = Object.freeze({HEADER_KINDS, nameOf, nameNode, setName, subscribe, changed, mark, unmark,
    begin, beginFrom, decorateInspectRow, refreshMarked,
    key: (sha256, functionIndex) => names()?.wasmFunctionKey?.(sha256, functionIndex) ?? null});
}());
