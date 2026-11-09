/* Cross-references for the current selection. The backend owns the projection
 * (protocol/http-api.md, Cross-references): this module holds one selection's
 * first page and at most a few nearby pages, mounts only visible rows, and
 * does no work while the dock is closed. Captured names reach the DOM as text. */
(() => {
  const dock = document.querySelector('#xrefs-dock');
  const toggle = document.querySelector('#xrefs-toggle');
  const workspace = document.querySelector('#workspace');
  if (!dock || !toggle || !workspace) return;

  const ROW = 44, GROUP = 30, OVERSCAN = 6, PAGE_SIZE = 128, KEEP_PAGES = 1;
  const SELECTION_DEBOUNCE_MS = 120, FILTER_DEBOUNCE_MS = 180, PAGE_DEBOUNCE_MS = 50, SETTLE_MS = 800;
  const FINGERPRINT_CATEGORIES = new Set(['canvas', 'webgl', 'web_audio', 'navigator', 'permissions', 'storage', 'webrtc', 'runtime']);
  const KIND_LABELS = {request_initiator: 'initiator', parent_event: 'parent', host_link: 'host link', request_event: 'lifecycle', child_event: 'child',
    response_artifact: 'response', call: 'call', read: 'read', artifact_creator: 'creator', artifact_capture: 'capture', parent_artifact: 'parent',
    child_artifact: 'child', wasm_import: 'import', wasm_export: 'export', wasm_call: 'call', direct_caller: 'caller', indirect_call: 'indirect',
    dispatch_sample: 'sample', artifact_use: 'use'};

  dock.innerHTML = `<header class="xrefs-head"><div class="xrefs-title"><span>to</span><strong id="xrefs-target">Nothing selected</strong></div>
    <span id="xrefs-counts" class="xrefs-counts"></span><button id="xrefs-close" class="xrefs-close" type="button" aria-label="Close cross-references" title="Close (X)">×</button></header>
    <div class="xrefs-controls"><label class="xrefs-filter"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M7 2.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9zm3.3 7.8 3.2 3.2"/></svg>
    <input id="xrefs-filter" type="text" maxlength="256" placeholder="Filter references" aria-label="Filter references" autocomplete="off" spellcheck="false" /><kbd aria-hidden="true">/</kbd></label>
    <div class="xrefs-pills" role="group" aria-label="Reference direction"><button id="xrefs-in" class="xrefs-pill" type="button" aria-pressed="true">In</button><button id="xrefs-out" class="xrefs-pill" type="button" aria-pressed="true">Out</button></div></div>
    <div id="xrefs-status" class="xrefs-status" role="status" aria-live="polite" hidden></div>
    <div id="xrefs-rows" class="xrefs-rows" role="listbox" aria-label="Cross-references" tabindex="0"><div id="xrefs-space" class="xrefs-space"></div></div>
    <div id="xrefs-detail" class="xrefs-detail-pane" hidden></div>`;
  const $ = id => dock.querySelector(`#${id}`);
  const elements = {target: $('xrefs-target'), counts: $('xrefs-counts'), close: $('xrefs-close'), filter: $('xrefs-filter'), inPill: $('xrefs-in'),
    outPill: $('xrefs-out'), status: $('xrefs-status'), rows: $('xrefs-rows'), space: $('xrefs-space'), detail: $('xrefs-detail')};

  const directions = ['in', 'out'];
  const emptyView = () => ({key: null, selection: null, label: '', status: 'idle', error: '', generation: 0, controller: null, snapshot: null,
    counts: {in: {total: 0, matching: 0}, out: {total: 0, matching: 0}}, gaps: {in: [], out: []}, pages: {in: new Map(), out: new Map()},
    pending: {in: null, out: null}, active: {in: true, out: true}, selected: null, coverage: null, pageError: ''});
  let view = emptyView(), open = false, selectionTimer = 0, settleTimer = 0, filterTimer = 0, pageTimer = 0, frame = 0, returnFocus = null, pageNeeds = [];
  let wasmRow = null;

  const node = (tag, className, text) => {const element = document.createElement(tag); if (className) element.className = className; if (text !== undefined) element.textContent = String(text); return element;};
  const dockAvailable = () => location.protocol === 'http:' || location.protocol === 'https:';
  const pretty = text => String(text).replaceAll('_', ' ');

  // Selection comes from the view the researcher is looking at. It is only
  // read here, and nothing here rebuilds that view.
  function currentSelection() {
    const screen = investigationScreen();
    if (screen === 'traffic') {
      if (state.selectedRequestId === null) return {key: 'traffic:none', empty: 'Select a request to see what points at it.'};
      const candidates = state.requests.filter(request => request.id === state.selectedRequestId);
      const request = candidates[0];
      const identity = candidates.length === 1 ? investigationRequestIdentity(request) : null;
      if (!identity) return {key: `traffic:${state.selectedRequestId}:unavailable`, empty: 'This request has no exact retained identity, so no references can be listed for it.'};
      const label = `${request.method ?? ''} ${typeof trafficTargetParts === 'function' ? trafficTargetParts(request).name : request.path}`.trim();
      return {key: `request:${identity.session}:${identity.process}:${identity.sequence}:${identity.request}`, label,
        params: {kind: 'request', session_id: identity.session, process_id: identity.process, sequence_number: identity.sequence, request_id: identity.request}};
    }
    if (screen === 'sources') {
      const source = selectedSource();
      const identity = investigationArtifactIdentity(source);
      if (!source) return {key: 'sources:none', empty: 'Select a captured source to see what points at it.'};
      if (!identity) return {key: `sources:${source.artifact_id ?? source.url}:unavailable`, empty: 'This source has no exact retained artifact identity.'};
      const params = {kind: 'artifact', session_id: identity.session, artifact_id: identity.artifact};
      let key = `artifact:${identity.session}:${identity.artifact}`;
      if (wasmRow?.artifactId === identity.artifact && state.sourceWasm) {
        params.byte_offset = wasmRow.byteOffset;
        key += `:${wasmRow.byteOffset}`;
      }
      return {key, label: sourceDisplayName(source), params};
    }
    if (screen === 'signals') {
      const match = /^S(\d+):P(\d+):E(\d+)$/.exec(state.selectedSignalEventKey ?? '');
      if (!match) return {key: 'signals:none', empty: 'Select a fingerprint API call to see every use of it.'};
      return {key: `api:${match[1]}:${match[2]}:${match[3]}`, label: '', params: {kind: 'api', session_id: match[1], process_id: match[2], sequence_number: match[3]}};
    }
    if (screen === 'vm') {
      const finding = state.vmFindings?.find(item => item.findingId === state.selectedVmFindingId);
      const workspaceRow = finding && vmOpcodeWorkspaceForFinding(state.vmOpcodeWorkspace, finding);
      if (!workspaceRow) return {key: 'vm:none', empty: 'Select a retained VM handler to see its samples and host links.'};
      const handler = vmOpcodeRows(workspaceRow).find(row => row.key === state.selectedVmHandlerKey);
      if (!handler) return {key: `vm:${finding.findingId}:none`, empty: 'Select a retained VM handler to see its samples and host links.'};
      const artifact = state.artifacts.find(item => item.artifact_id === workspaceRow.interpreter_artifact_id && item.sha256 === workspaceRow.source_artifact_sha256);
      if (!artifact) return {key: `vm:${finding.findingId}:${handler.key}:unavailable`, empty: 'The analyzed artifact for this handler is no longer retained.'};
      return {key: `vm:${artifact.session_id}:${artifact.artifact_id}:${handler.key}`, label: handler.label,
        params: {kind: 'vm_handler', session_id: artifact.session_id, artifact_id: artifact.artifact_id, sha256: artifact.sha256,
          byte_offset: handler.range.start, byte_size: handler.range.end - handler.range.start}};
    }
    return {key: `screen:${screen}`, empty: 'Open Traffic, Sources, VM or Fingerprinting to follow a selection here.'};
  }

  function scheduleSync(delay = SELECTION_DEBOUNCE_MS) {
    if (!open) return;
    clearTimeout(selectionTimer);
    selectionTimer = setTimeout(sync, delay);
  }
  function sync() {
    if (!open) return;
    const selection = currentSelection();
    if (selection.key !== view.key) load(selection);
  }

  function resetView(selection) {
    view.controller?.abort();
    for (const direction of directions) view.pending[direction]?.controller.abort();
    const active = view.active;
    view = {...emptyView(), generation: view.generation + 1, active, key: selection.key, selection, label: selection.label ?? ''};
  }

  function query(extra) {
    const params = new URLSearchParams({...view.selection.params, ...extra});
    const filter = elements.filter.value.trim();
    if (filter) params.set('filter', filter);
    return `/api/xrefs?${params}`;
  }

  function isDocument(document) {
    return document && document.document_kind === 'reb-xrefs' && document.contract_version === 1 && typeof document.selection?.status === 'string' &&
      typeof document.snapshot === 'string' && directions.every(direction => Number.isSafeInteger(document.counts?.[direction]?.total) && Number.isSafeInteger(document.counts[direction].matching) &&
        Array.isArray(document.gaps?.[direction]));
  }

  async function load(selection) {
    // A filter change or retry of the same selection keeps its rows until the
    // answer arrives, so a failure leaves the last understandable evidence.
    const refreshing = selection.key === view.key && view.status === 'ready';
    if (refreshing) {
      view.controller?.abort();
      for (const direction of directions) view.pending[direction]?.controller.abort();
      view.generation += 1;
      view.pageError = '';
    } else resetView(selection);
    if (selection.empty) { view.status = 'empty'; view.error = selection.empty; render(); return; }
    if (!dockAvailable()) { view.status = 'unavailable'; view.error = 'Cross-references read the local backend, which this stored-evidence window does not run. Open a live workspace or the browser development UI.'; render(); return; }
    const generation = view.generation;
    const controller = new AbortController();
    view.controller = controller;
    if (!refreshing) { view.status = 'loading'; render(); }
    try {
      const response = await fetch(query({direction: 'both', limit: PAGE_SIZE}), {cache: 'no-store', signal: controller.signal});
      const document = await readJson(response);
      if (generation !== view.generation) return;
      if (!isDocument(document)) throw new TypeError('The backend returned a malformed cross-reference document.');
      applyDocument(document);
    } catch (error) {
      if (generation !== view.generation || error.name === 'AbortError') return;
      const message = error.message || 'Cross-references could not be read.';
      if (refreshing) { view.pageError = message; renderStatus(); return; }
      view.status = 'error';
      view.error = message;
      render();
    }
  }

  async function readJson(response) {
    const body = await response.json().catch(() => null);
    if (!response.ok) throw new Error(body?.error ?? `Cross-references are unavailable (${response.status}).`);
    return body;
  }

  function applyDocument(document) {
    view.status = document.selection.status === 'resolved' ? 'ready' : 'gone';
    view.error = document.selection.status === 'resolved' ? '' : document.selection.detail ?? 'This selection cannot be resolved.';
    view.snapshot = document.snapshot;
    view.coverage = document.coverage;
    // The view's own name wins, except for a Wasm row, which only the
    // module can name.
    const narrowed = view.selection.params?.kind === 'artifact' && view.selection.params.byte_offset !== undefined;
    view.label = (narrowed ? document.selection.label || view.label : view.label || document.selection.label) || '';
    view.counts = document.counts;
    view.gaps = document.gaps;
    for (const direction of directions) view.pages[direction] = new Map([[0, document.pages?.[direction]?.rows ?? []]]);
    selectFirstNavigable();
    render();
  }

  function refetchFiltered() {
    if (view.selection && !view.selection.empty && dockAvailable()) load({...view.selection, key: view.key});
  }

  function rowAt(direction, offset) {
    const page = Math.floor(offset / PAGE_SIZE);
    return view.pages[direction].get(page)?.[offset - page * PAGE_SIZE] ?? null;
  }

  // Pages are requested one at a time per direction, cancelled when the
  // reader scrolls on, and released once they fall out of the viewport.
  function neededPages(direction, firstOffset, lastOffset) {
    if (view.pending[direction]) {
      const pendingPage = view.pending[direction].page;
      if (pendingPage * PAGE_SIZE > lastOffset || (pendingPage + 1) * PAGE_SIZE <= firstOffset) view.pending[direction].controller.abort();
    }
    for (let page = Math.floor(firstOffset / PAGE_SIZE), last = Math.floor(lastOffset / PAGE_SIZE); page <= last; page += 1) {
      if (view.pages[direction].has(page) || view.pending[direction]?.page === page) continue;
      fetchPage(direction, page);
      return;
    }
  }

  async function fetchPage(direction, page) {
    const controller = new AbortController();
    const generation = view.generation;
    view.pending[direction] = {page, controller};
    try {
      const url = query({direction, offset: page * PAGE_SIZE, limit: PAGE_SIZE, snapshot: view.snapshot});
      const document = await readJson(await fetch(url, {cache: 'no-store', signal: controller.signal}));
      if (generation !== view.generation) return;
      if (!isDocument(document)) throw new TypeError('The backend returned a malformed cross-reference document.');
      view.pages[direction].set(page, document.pages?.[direction]?.rows ?? []);
      schedulePaint();
    } catch (error) {
      if (generation !== view.generation || error.name === 'AbortError') return;
      view.pageError = error.message || 'A page of cross-references could not be read.';
      renderStatus();
    } finally {
      if (view.pending[direction]?.controller === controller) view.pending[direction] = null;
    }
  }

  function releaseFarPages(direction, firstOffset, lastOffset) {
    const firstPage = Math.floor(firstOffset / PAGE_SIZE) - KEEP_PAGES, lastPage = Math.floor(lastOffset / PAGE_SIZE) + KEEP_PAGES;
    for (const page of [...view.pages[direction].keys()]) {
      if (page !== 0 && (page < firstPage || page > lastPage)) view.pages[direction].delete(page);
    }
  }

  function groups() {
    return directions.filter(direction => view.active[direction] && (view.counts[direction].matching > 0 || view.gaps[direction].length > 0))
      .map(direction => ({direction, gaps: view.gaps[direction], count: view.counts[direction].matching}));
  }

  // Navigable items are the gap rows and rows of each visible group, in order.
  function navCount() {
    return groups().reduce((sum, group) => sum + group.gaps.length + group.count, 0);
  }
  function navItem(index) {
    let remaining = index;
    for (const group of groups()) {
      const size = group.gaps.length + group.count;
      if (remaining < size) {
        return remaining < group.gaps.length ? {direction: group.direction, kind: 'gap', offset: remaining}
          : {direction: group.direction, kind: 'row', offset: remaining - group.gaps.length};
      }
      remaining -= size;
    }
    return null;
  }
  function navIndex(item) {
    let before = 0;
    for (const group of groups()) {
      if (group.direction === item.direction) return before + (item.kind === 'gap' ? item.offset : group.gaps.length + item.offset);
      before += group.gaps.length + group.count;
    }
    return -1;
  }
  function selectFirstNavigable() {
    view.selected = navItem(0);
  }

  function layoutHeight() {
    return groups().reduce((sum, group) => sum + GROUP + (group.gaps.length + group.count) * ROW, 0);
  }
  function itemTop(item) {
    let top = 0;
    for (const group of groups()) {
      if (group.direction === item.direction) return top + GROUP + (item.kind === 'gap' ? item.offset : group.gaps.length + item.offset) * ROW;
      top += GROUP + (group.gaps.length + group.count) * ROW;
    }
    return 0;
  }

  function schedulePaint() {
    if (!open || frame) return;
    frame = requestAnimationFrame(() => { frame = 0; paint(); });
    // WebKit can suspend animation frames for an inactive window.
    setTimeout(() => { if (frame) { cancelAnimationFrame(frame); frame = 0; paint(); } }, 60);
  }

  function counted(count) {
    return Number(count).toLocaleString('en-US');
  }
  function kindLabel(row) { return KIND_LABELS[row.kind] ?? pretty(row.kind); }
  function rowId(row) {
    const evidence = row.evidence;
    return evidence.type === 'artifact' ? `artifact ${evidence.artifact_id}${evidence.byte_offset !== undefined ? ` +${evidence.byte_offset}` : ''}` : `#${row.ids.sequence_number}`;
  }

  function rowElement(item, top, navigation) {
    const element = node('div', 'xrefs-row');
    element.style.transform = `translateY(${top}px)`;
    element.setAttribute('role', 'option');
    element.id = `xrefs-option-${navigation}`;
    element.dataset.navigation = String(navigation);
    const selected = view.selected && view.selected.direction === item.direction && view.selected.kind === item.kind && view.selected.offset === item.offset;
    element.setAttribute('aria-selected', String(Boolean(selected)));
    if (item.kind === 'gap') {
      const gap = view.gaps[item.direction][item.offset];
      element.dataset.gap = 'true';
      const name = node('span', 'xrefs-name', gap.name), badge = node('span', 'xrefs-kind', 'gap');
      const detail = node('span', 'xrefs-detail', gap.detail);
      name.title = gap.name; detail.title = gap.detail;
      element.append(name, badge, detail);
      return element;
    }
    const row = rowAt(item.direction, item.offset);
    if (!row) {
      element.dataset.loading = 'true';
      element.append(node('span', 'xrefs-name', 'Reading…'), node('span', 'xrefs-kind', '…'), node('span', 'xrefs-detail', `row ${counted(item.offset + 1)}`), node('span', 'xrefs-id', ''));
      return element;
    }
    const name = node('span', 'xrefs-name', row.name), badge = node('span', 'xrefs-kind', kindLabel(row));
    const detail = node('span', 'xrefs-detail', row.detail), id = node('span', 'xrefs-id', rowId(row));
    name.title = row.name; detail.title = row.detail; id.title = rowId(row);
    element.append(name, badge, detail, id);
    return element;
  }

  function paint() {
    if (!open) return;
    const visibleGroups = groups();
    const height = layoutHeight();
    elements.space.style.height = `${height}px`;
    const top = elements.rows.scrollTop, bottom = top + elements.rows.clientHeight;
    const pieces = [];
    pageNeeds = [];
    let cursor = 0, navBefore = 0;
    for (const group of visibleGroups) {
      const groupEnd = cursor + GROUP + (group.gaps.length + group.count) * ROW;
      if (groupEnd >= top - OVERSCAN * ROW && cursor <= bottom + OVERSCAN * ROW) {
        if (cursor + GROUP >= top - OVERSCAN * ROW && cursor <= bottom + OVERSCAN * ROW) {
          const heading = node('div', 'xrefs-group');
          heading.setAttribute('role', 'presentation');
          heading.style.transform = `translateY(${cursor}px)`;
          heading.append(node('span', '', group.direction === 'in' ? '←' : '→'), node('em', '', group.direction === 'in' ? 'referenced by' : 'points to'), node('b', '', counted(group.count)));
          pieces.push(heading);
        }
        const rowsTop = cursor + GROUP;
        const size = group.gaps.length + group.count;
        const first = Math.max(0, Math.floor((top - rowsTop) / ROW) - OVERSCAN);
        const last = Math.min(size - 1, Math.ceil((bottom - rowsTop) / ROW) + OVERSCAN);
        for (let index = first; index <= last; index += 1) {
          const item = index < group.gaps.length ? {direction: group.direction, kind: 'gap', offset: index}
            : {direction: group.direction, kind: 'row', offset: index - group.gaps.length};
          pieces.push(rowElement(item, rowsTop + index * ROW, navBefore + index));
        }
        const rowFirst = Math.max(0, first - group.gaps.length), rowLast = Math.max(0, last - group.gaps.length);
        if (group.count > 0) {
          pageNeeds.push([group.direction, rowFirst, Math.min(rowLast, group.count - 1)]);
          releaseFarPages(group.direction, rowFirst, rowLast);
        }
      }
      cursor = groupEnd;
      navBefore += group.gaps.length + group.count;
    }
    elements.space.replaceChildren(...pieces);
    // A page is requested once the viewport rests, so a dragged scrollbar asks
    // for the row it stops on and not for every page it passes.
    clearTimeout(pageTimer);
    pageTimer = setTimeout(() => { if (open) for (const need of pageNeeds) neededPages(...need); }, PAGE_DEBOUNCE_MS);
    const selectedElement = view.selected && elements.space.querySelector('[aria-selected="true"]');
    if (selectedElement) elements.rows.setAttribute('aria-activedescendant', selectedElement.id);
    else elements.rows.removeAttribute('aria-activedescendant');
  }

  function renderDetail() {
    const item = view.selected;
    if (!item || view.status === 'empty' || view.status === 'unavailable') { elements.detail.hidden = true; elements.detail.replaceChildren(); return; }
    if (item.kind === 'gap') {
      const gap = view.gaps[item.direction][item.offset];
      elements.detail.hidden = false;
      const head = node('div', 'xrefs-detail-head');
      head.append(node('strong', '', gap.name));
      elements.detail.replaceChildren(head, node('p', '', gap.detail), node('code', '', gap.reason));
      return;
    }
    const row = rowAt(item.direction, item.offset);
    if (!row) { elements.detail.hidden = true; return; }
    const ids = [['session_id', 'session'], ['process_id', 'process'], ['sequence_number', 'seq'], ['navigation_id', 'nav'], ['frame_id', 'frame'], ['artifact_id', 'artifact'], ['request_id', 'request'], ['parent_event_id', 'parent']]
      .filter(([key]) => row.ids[key] !== undefined && row.ids[key] !== null && String(row.ids[key]) !== '0').map(([key, label]) => `${label} ${row.ids[key]}`).join(' · ');
    const time = row.time_ns ? ` · ${typeof evidenceMonotonicLabel === 'function' ? evidenceMonotonicLabel(row.time_ns) : `${row.time_ns} ns`} monotonic` : '';
    const button = node('button', 'secondary-button', 'Open');
    button.type = 'button'; button.id = 'xrefs-open-row';
    button.addEventListener('click', () => openRow(row));
    const head = node('div', 'xrefs-detail-head');
    head.append(node('strong', '', row.name), button);
    elements.detail.hidden = false;
    elements.detail.replaceChildren(head, node('p', '', `${kindLabel(row)} · ${row.state} · ${pretty(row.source)} · ${pretty(row.operation)}${time}`), node('p', '', row.detail), node('code', '', ids));
  }

  function render() {
    const selection = view.selection;
    elements.target.textContent = view.label || (selection?.params ? 'selection' : 'Nothing selected');
    elements.target.title = elements.target.textContent;
    if (view.status === 'ready' || view.status === 'gone') {
      elements.counts.textContent = `${counted(view.counts.in.matching)} in · ${counted(view.counts.out.matching)} out`;
    } else elements.counts.textContent = '';
    elements.inPill.textContent = `In ${view.status === 'ready' || view.status === 'gone' ? counted(view.counts.in.matching) : ''}`.trim();
    elements.outPill.textContent = `Out ${view.status === 'ready' || view.status === 'gone' ? counted(view.counts.out.matching) : ''}`.trim();
    elements.inPill.setAttribute('aria-pressed', String(view.active.in));
    elements.outPill.setAttribute('aria-pressed', String(view.active.out));
    renderStatus();
    const showList = (view.status === 'ready' && navCount() > 0);
    if (!showList) {
      elements.rows.scrollTop = 0;
      elements.space.style.height = '0px';
      elements.space.replaceChildren();
      elements.rows.removeAttribute('aria-activedescendant');
      const message = emptyMessage();
      if (message) elements.space.append(message);
    } else paint();
    renderDetail();
  }

  function emptyMessage() {
    if (view.status === 'ready') {
      const filter = elements.filter.value.trim();
      return filter ? emptyState('No references match this filter', 'The filter only reads names already on the rows.') : emptyState('No recorded references', 'This selection has no links in the retained evidence. Nothing is inferred to fill the gap.');
    }
    if (view.status === 'empty' || view.status === 'unavailable') return emptyState('', view.error);
    if (view.status === 'gone') return emptyState('Selection unavailable', view.error);
    if (view.status === 'loading') return emptyState('', 'Reading references…');
    return null;
  }
  function emptyState(title, text) {
    const element = node('div', 'xrefs-empty');
    if (title) element.append(node('strong', '', title));
    element.append(document.createTextNode(text));
    return element;
  }

  function renderStatus() {
    const status = elements.status;
    status.replaceChildren();
    status.hidden = true;
    delete status.dataset.kind;
    if (view.status === 'error' || view.pageError) {
      status.hidden = false; status.dataset.kind = 'error';
      status.append(document.createTextNode(`${view.status === 'error' ? view.error : view.pageError} `));
      const retry = node('button', '', 'Retry');
      retry.type = 'button';
      retry.addEventListener('click', () => {
        if (view.status === 'error') { refetchFiltered(); return; }
        view.pageError = '';
        renderStatus();
        schedulePaint();
      });
      status.append(retry);
      return;
    }
    const coverage = view.coverage;
    if (!coverage || view.status !== 'ready') return;
    const notes = [];
    if (coverage.status === 'partial') notes.push(`Scan stopped after ${counted(Math.round(Number(coverage.scanned_bytes) / 1048576))} MiB of ${counted(Math.round(Number(coverage.snapshot_bytes) / 1048576))} MiB. Later evidence is not listed.`);
    if (coverage.malformed_records > 0) notes.push(`${counted(coverage.malformed_records)} malformed records skipped.`);
    if (notes.length) { status.hidden = false; status.dataset.kind = coverage.status === 'partial' ? 'cut' : ''; status.textContent = notes.join(' '); }
  }

  function moveSelection(next) {
    const count = navCount();
    if (!count) return;
    const clamped = Math.max(0, Math.min(count - 1, next));
    view.selected = navItem(clamped);
    const top = itemTop(view.selected);
    if (top < elements.rows.scrollTop) elements.rows.scrollTop = Math.max(0, top - 2);
    else if (top + ROW > elements.rows.scrollTop + elements.rows.clientHeight) elements.rows.scrollTop = top + ROW - elements.rows.clientHeight + 2;
    paint();
    renderDetail();
  }

  function selectedRow() {
    const item = view.selected;
    return item?.kind === 'row' ? rowAt(item.direction, item.offset) : null;
  }

  function openRow(row) {
    if (!row) return;
    const evidence = row.evidence;
    const notice = 'Opened from Cross-references. This is the exact retained record; nothing was inferred.';
    if (evidence.type === 'artifact') {
      const identity = investigationArtifactIdentity({session_id: evidence.session_id, artifact_id: evidence.artifact_id, sha256: evidence.sha256, byte_size: evidence.byte_size});
      if (!identity || !openInvestigation({kind: 'artifact', identity, relation: notice})) return;
      if (evidence.byte_offset !== undefined && evidence.kind === 'wasm') {
        state.sourceWasm = false;
        renderSources();
        moveSourceWindow(Math.floor(evidence.byte_offset / 16));
      }
      return;
    }
    if (evidence.category === 'network' && String(evidence.request_id) !== '0') {
      const requests = state.requests.filter(request => {
        const identity = investigationRequestIdentity(request);
        return identity && identity.session === String(evidence.session_id) && identity.request === String(evidence.request_id) && identity.process === String(evidence.process_id);
      });
      if (requests.length === 1) { openInvestigation({kind: 'request', identity: investigationRequestIdentity(requests[0]), relation: notice}); return; }
    }
    if (FINGERPRINT_CATEGORIES.has(evidence.category)) {
      state.selectedSignalEventKey = `S${evidence.session_id}:P${evidence.process_id}:E${evidence.sequence_number}`;
      state.signalDetailOpen = true;
      showScreen('signals');
      renderFingerprintActivity();
      elements.rows.blur();
      document.querySelector('#signal-rows')?.querySelector('[aria-selected="true"]')?.focus({preventScroll: true});
      return;
    }
    showScreen('evidence');
    if (!evidenceWorkspace.openRecord({session_id: evidence.session_id, process_id: evidence.process_id, sequence_number: evidence.sequence_number})) {
      investigationNotice(`Event ${evidence.sequence_number} is outside the retained Evidence window. Its identity stays visible in Cross-references.`, 'unavailable');
    }
  }

  function setOpen(value, focusList = true) {
    if (open === value) return;
    open = value;
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-pressed', String(open));
    dock.hidden = !open;
    if (open) {
      workspace.dataset.xrefsOpen = 'true';
      document.addEventListener('keydown', onDocumentEvent, true);
      document.addEventListener('keyup', onDocumentEvent, true);
      document.addEventListener('click', onDocumentEvent, true);
      settleTimer = setInterval(sync, SETTLE_MS);
      sync();
      if (focusList) elements.rows.focus({preventScroll: true});
    } else {
      delete workspace.dataset.xrefsOpen;
      document.removeEventListener('keydown', onDocumentEvent, true);
      document.removeEventListener('keyup', onDocumentEvent, true);
      document.removeEventListener('click', onDocumentEvent, true);
      clearInterval(settleTimer); clearTimeout(selectionTimer); clearTimeout(filterTimer); clearTimeout(pageTimer);
      view.controller?.abort();
      for (const direction of directions) view.pending[direction]?.controller.abort();
      if (frame) { cancelAnimationFrame(frame); frame = 0; }
      const active = view.active;
      view = {...emptyView(), active};
      wasmRow = null;
      elements.space.replaceChildren();
      elements.detail.hidden = true;
      elements.detail.replaceChildren();
      elements.status.hidden = true;
      elements.target.textContent = 'Nothing selected';
      elements.counts.textContent = '';
    }
  }

  function restoreFocus() {
    const target = returnFocus && returnFocus.isConnected && !returnFocus.closest('[hidden]') ? returnFocus : toggle;
    returnFocus = null;
    target.focus({preventScroll: true});
  }

  function onDocumentEvent(event) {
    if (dock.contains(event.target)) return;
    scheduleSync();
  }

  dock.addEventListener('focusin', event => {
    if (!dock.contains(event.relatedTarget) && event.relatedTarget && event.relatedTarget !== toggle) returnFocus = event.relatedTarget;
  });
  toggle.addEventListener('click', () => setOpen(!open));
  elements.close.addEventListener('click', () => { setOpen(false); restoreFocus(); });
  elements.rows.addEventListener('scroll', schedulePaint, {passive: true});
  elements.rows.addEventListener('click', event => {
    const element = event.target.closest?.('.xrefs-row');
    if (!element) return;
    view.selected = navItem(Number(element.dataset.navigation));
    paint();
    renderDetail();
  });
  elements.rows.addEventListener('dblclick', event => {
    if (event.target.closest?.('.xrefs-row')) openRow(selectedRow());
  });
  elements.rows.addEventListener('keydown', event => {
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    const index = view.selected ? navIndex(view.selected) : -1;
    const page = Math.max(1, Math.floor(elements.rows.clientHeight / ROW) - 1);
    const moves = {ArrowDown: index + 1, ArrowUp: index - 1, PageDown: index + page, PageUp: index - page, Home: 0, End: navCount() - 1};
    if (event.key in moves) { event.preventDefault(); moveSelection(moves[event.key]); return; }
    if (event.key === 'Enter') { event.preventDefault(); openRow(selectedRow()); return; }
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); restoreFocus(); return; }
    if (event.key === '/') { event.preventDefault(); elements.filter.focus(); elements.filter.select(); }
  });
  elements.filter.addEventListener('input', () => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(refetchFiltered, FILTER_DEBOUNCE_MS);
  });
  elements.filter.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      event.preventDefault(); event.stopPropagation();
      if (elements.filter.value) { elements.filter.value = ''; refetchFiltered(); }
      elements.rows.focus({preventScroll: true});
      return;
    }
    if (event.key === 'ArrowDown' || event.key === 'Enter') { event.preventDefault(); elements.rows.focus({preventScroll: true}); }
  });
  for (const [element, direction] of [[elements.inPill, 'in'], [elements.outPill, 'out']]) {
    element.addEventListener('click', () => {
      const other = direction === 'in' ? 'out' : 'in';
      if (view.active[direction] && !view.active[other]) return;
      view.active[direction] = !view.active[direction];
      if (view.selected && !view.active[view.selected.direction]) selectFirstNavigable();
      elements.rows.scrollTop = 0;
      render();
    });
  }
  document.addEventListener('keydown', event => {
    if (event.key !== 'x' && event.key !== 'X') return;
    if (event.ctrlKey || event.metaKey || event.altKey || event.repeat || document.querySelector('dialog:modal')) return;
    if (event.target?.closest?.('input, textarea, select, [contenteditable="true"], .cm-editor')) return;
    event.preventDefault();
    if (!open) { setOpen(true); return; }
    if (dock.contains(document.activeElement)) { setOpen(false); restoreFocus(); return; }
    elements.rows.focus({preventScroll: true});
  });
  // Selecting a Wasm inspection row (click or Tab through its gutter) narrows
  // the artifact selection to that function or import.
  const sourceCode = document.querySelector('#source-code');
  const noteWasmRow = event => {
    if (!state.sourceWasm) return;
    const element = event.target.closest?.('.source-line');
    if (!element) return;
    const row = state.sourceEditorView?.view?.wasmRows?.[Number(element.dataset.localLine)];
    const source = selectedSource();
    if (!row || row.byte_offset == null || !source) return;
    wasmRow = {artifactId: source.artifact_id, byteOffset: row.byte_offset};
    sourceCode.querySelector('.xrefs-source-selected')?.classList.remove('xrefs-source-selected');
    element.classList.add('xrefs-source-selected');
    scheduleSync(0);
  };
  sourceCode?.addEventListener('click', noteWasmRow);
  sourceCode?.addEventListener('focusin', noteWasmRow);
  new ResizeObserver(() => schedulePaint()).observe(elements.rows);
})();
