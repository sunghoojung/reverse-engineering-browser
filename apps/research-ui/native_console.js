(() => {
  const root = document.querySelector('#native-console-panel');
  const element = name => document.querySelector(`#native-console-${name}`);
  const controls = Object.fromEntries(['url', 'start', 'stop', 'notice', 'target', 'refresh', 'clear', 'output', 'scroll', 'connection', 'form', 'source', 'run', 'interrupt', 'filter', 'level', 'mode', 'live-consent'].map(name => [name, element(name)]));
  const toggle = element('toggle');
  const encoder = new TextEncoder();
  const history = [];
  let historyIndex = null, draft = '';
  let session = null, available = false, pending = 0, disconnected = false, initialized = false, documentSource = 'disposable';
  let liveListing = null, liveAvailable = false, listingRunning = false;
  let liveBinding = null, selectedBinding = null;
  controls.mode.value = 'disposable';
  const selectedDocument = () => !!controls.target.value && [...controls.target.options].some(option => option.value === controls.target.value && !option.disabled);
  let partialTargets = false, outputGeneration = 0;
  let queue = Promise.resolve(), generation = 0, pollRunning = false;
  let checking = false, submitting = false, commandNumber = 0, unread = 0;
  // A command runs in the page until it returns; Stop ends it there.
  let commandsRunning = 0, stopping = false;
  // A Console record names its length in 32 bits, so one command is at most
  // 4 GiB as UTF-8 JSON, its escapes included. Nothing else bounds a source.
  const recordLimit = 4294967295;
  const recordBytes = value => encoder.encode(JSON.stringify(value)).length;
  // WebKit lays out in 1/64 px steps of a 32-bit integer, so no element can be
  // taller than about 33.5 million px. A transcript taller than this is drawn
  // compressed into it rather than past it, where its newest rows would be
  // out of reach.
  const transcriptExtent = 1 << 24;
  let sizedSource = '', sourceBytes = 0;
  const sourceSize = () => {
    const value = controls.source.value;
    if (value !== sizedSource) { sizedSource = value; sourceBytes = encoder.encode(value).length; }
    return sourceBytes;
  };
  const formatBytes = n => n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1048576).toFixed(1)} MiB`;
  const numberId = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n;
  const documentStartActions = ['arm_document_start', 'add_document_start', 'remove_document_start', 'clear_document_start'];
  const validState = (value, version = 2) => value?.contract_version === version && ['ready', 'idle'].includes(value.state) &&
    (value.state === 'ready' ? numberId(value.session_id) : value.session_id === null);
  const types = ['undefined', 'null', 'boolean', 'number', 'string', 'bigint', 'symbol', 'function', 'object', 'promise', 'accessor'];
  const levels = ['debug', 'info', 'warning', 'error'];
  function notice(message, error = false) {
    controls.notice.textContent = message; controls.notice.title = message;
    controls.notice.dataset.kind = error ? 'error' : 'status'; controls.notice.hidden = !message;
  }
  function renderControls() {
    root.dataset.session = session ? 'ready' : 'idle';
    root.dataset.documentSource = documentSource;
    const busy = pending || submitting;
    const live = documentSource === 'live_capture';
    const status = checking ? 'checking' : disconnected ? 'disconnected' : busy ? 'working' : session ? 'connected' : initialized && !available && !live ? 'unavailable' : 'idle';
    const badge = element('badge'); badge.textContent = {checking: 'Checking', disconnected: 'Connection lost', working: 'Working', connected: 'Connected', unavailable: 'Unavailable', idle: 'Connect'}[status]; badge.dataset.state = status;
    controls.connection.querySelector('summary').setAttribute('aria-label', `Console connection: ${status}. Session settings`);
    controls.start.disabled = !!busy || checking || listingRunning || !!session || (live ? !liveAvailable || !selectedDocument() || selectedBinding !== liveBinding || !controls['live-consent'].checked : !available);
    controls.clear.disabled = !!busy;
    controls.stop.disabled = !!busy || !session; controls.refresh.disabled = !!busy || checking || !(session || live);
    controls.target.disabled = !!busy || !!(session && live) || !(session || live) || controls.target.options.length <= 1;
    controls.mode.disabled = !!busy || checking || !!session;
    controls.mode.value = live ? 'live_capture' : 'disposable';
    element('live-confirmation').hidden = !live;
    controls['live-consent'].disabled = !!busy || !!session || !selectedDocument();
    element('mode-title').textContent = live ? 'Selected live capture document' : 'Disposable browser session';
    element('mode-description').textContent = live ? 'Commands can change the captured page, cookies, and storage. This is not read-only evaluation. Disconnect stops this console connection, not the capture browser or work already scheduled by a command. Output stays in memory.' : 'Commands can change the selected page. Disconnect removes this disposable browser and profile. Output and history stay in memory only; clear output before sharing.';
    controls.url.disabled = !!busy || checking || !!session || live;
    element('check').hidden = !!session || (live ? liveAvailable : available); element('check').disabled = checking;
    // The next draft stays editable. Only explicit submission is serialized.
    controls.source.disabled = disconnected || !session || !selectedDocument();
    controls.run.disabled = !!busy || controls.source.disabled || !controls.source.value.trim();
    controls.run.textContent = submitting ? 'Running…' : 'Run';
    const commandRunning = commandsRunning > 0 && !!session;
    if (!commandRunning && document.activeElement === controls.interrupt) controls.source.focus();
    controls.run.hidden = commandRunning; controls.interrupt.hidden = !commandRunning;
    controls.interrupt.disabled = stopping; controls.interrupt.textContent = stopping ? 'Stopping…' : 'Stop';
    const liveNotice = 'These documents come from the live capture. Select one, explicitly authorize mutation, then connect. Commands can change that captured page. This console cannot set breakpoints, step, or inspect paused frames.';
    element('composer-status').textContent = commandRunning ? (stopping ? 'Stopping · changes already made stay' : 'Running until it returns · Stop ends it · next draft stays editable') : submitting ? 'Running · next draft stays editable' : disconnected ? 'Connection lost · refresh documents to recover' : !session ? (live ? (controls.target.value ? 'Connect to evaluate in the selected live document' : 'Select a live capture document') : 'Connect a disposable browser to begin') : !controls.target.value ? 'Select the document to execute in' : `Document ${controls.target.value} · ${formatBytes(sourceSize())}`;
    const emptyTitle = element('empty-title'), emptyText = element('empty-text'), emptyAction = element('empty-action');
    emptyTitle.textContent = checking ? 'Checking native Console' : disconnected ? 'Connection interrupted' : !available && initialized && !live ? 'Native Console unavailable' : !session ? (live ? (controls.target.value ? 'Connect to the live capture' : 'Select a live capture document') : 'Connect a disposable browser') : !controls.target.value ? 'Choose an execution document' : 'Ready for your first command';
    emptyText.textContent = disconnected ? 'Your output and draft are preserved. Refresh the document list before continuing; commands are never retried.' : !available && initialized && !live ? 'A rebuilt custom Brave and live backend are required. Check availability after they are ready.' : !session ? (live ? liveNotice : 'Enter an authorized page in Session settings. Commands run in a separate disposable profile.') : !controls.target.value ? 'Select a document above. If the page just opened or navigated, refresh the document list.' : 'Enter an expression below. Expand returned objects to inspect bounded native properties; getters remain unevaluated.';
    emptyAction.textContent = checking ? 'Checking…' : !session ? (live ? (controls.target.value ? 'Connect' : 'Select a document') : available ? 'Session settings' : 'Check availability') : !controls.target.value ? 'Refresh documents' : 'Focus command';
    const privacy = root.querySelector('.native-console-private');
    if (privacy) privacy.textContent = live ? 'Ephemeral · live capture' : 'Ephemeral · disposable profile';
    if (live && session && !selectedDocument()) {
      element('composer-status').textContent = 'Selected document unavailable · disconnect to authorize another';
      emptyTitle.textContent = 'Selected document unavailable';
      emptyText.textContent = 'The selected document changed or closed. Disconnect, select a current document, and authorize again. No replacement document is chosen automatically.';
      emptyAction.textContent = 'Disconnect';
    }
    emptyAction.disabled = checking || !!busy;
    documentStart.render();
    updateOutputState();
  }
  function updateOutputState() {
    const total = transcript.size(), visible = transcript.visible();
    element('empty').hidden = !!total;
    element('no-matches').hidden = !total || !!visible;
    element('output-count').textContent = `${visible === total ? total : `${visible} / ${total}`} entries`;
    element('latest').hidden = !total || atBottom();
    element('latest').textContent = unread ? `${unread} new · Latest ↓` : 'Latest output ↓';
  }
  function atBottom() { return controls.scroll.scrollHeight - controls.scroll.scrollTop - controls.scroll.clientHeight < 40; }
  // Every entry stays, whole, until Clear, and only the entries around the
  // viewport are in the document: a page that logs for hours would otherwise
  // grow the DOM until layout, scrolling and search stall. An entry built from
  // a record (a page message, a document-start record, a boundary) is rebuilt
  // when it scrolls back in. One that holds live state, a command or a result
  // with expandable values, keeps its node while it is detached.
  const transcript = (() => {
    const entries = [], owners = new WeakMap();
    // shown is the filtered order. tops[i] is where shown[i] starts and
    // tops[shown.length] is the transcript's height; an entry that was never
    // rendered counts as the median rendered height until it is, so one very
    // tall entry does not stretch every other.
    let shown = [], tops = [0], stale = false, from = 0, to = 0, follow = true, scheduled = false;
    const heights = new Map();
    let measured = 0, typical = 24, typicalStale = false;
    // position is the transcript offset at the top of the viewport. While the
    // transcript fits, it is the scroll offset. Once it is compressed, a
    // wheel, key or touch scroll moves it by exactly its own distance and a
    // scrollbar drag maps proportionally onto the whole transcript; shift is
    // the scroll offset it was last placed at.
    let position = 0, shift = 0, compressed = false, jump = null;
    // Drawn beyond each edge of the viewport, so a scroll step rarely reaches
    // an edge that is not drawn yet.
    const overscan = 800;
    function count(height, step) {
      const key = Math.round(height), next = (heights.get(key) || 0) + step;
      if (next) heights.set(key, next); else heights.delete(key);
      measured += step; typicalStale = true;
    }
    function estimate() {
      if (typicalStale) {
        typicalStale = false; typical = 24;
        let seen = 0;
        for (const key of [...heights.keys()].sort((a, b) => a - b)) { seen += heights.get(key); if (seen * 2 > measured) { typical = key; break; } }
      }
      return typical;
    }
    // A disclosure, a loaded property page or a narrower panel changes a
    // rendered row's height after it was measured.
    const resized = new ResizeObserver(changes => {
      if (changes.some(change => { const entry = owners.get(change.target); return entry?.node === change.target && entry.height !== change.target.getBoundingClientRect().height; })) schedule();
    });
    const text = entry => entry.build ? entry.text : entry.node.textContent + (entry.command ?? '');
    const level = entry => entry.build ? entry.level : entry.node.dataset.level;
    function matches(entry) {
      const query = controls.filter.value.toLocaleLowerCase(), wanted = controls.level.value;
      return (!query || text(entry).toLocaleLowerCase().includes(query)) && (wanted === 'all' || level(entry) === wanted);
    }
    function node(entry) {
      if (!entry.node) { entry.node = entry.build(); owners.set(entry.node, entry); }
      resized.observe(entry.node);
      return entry.node;
    }
    function offsets() {
      if (!stale) return;
      const size = estimate();
      tops = new Array(shown.length + 1); tops[0] = 0;
      for (let index = 0; index < shown.length; ++index) tops[index + 1] = tops[index] + (shown[index].height ?? size);
      stale = false;
    }
    // The shown entry at transcript offset y.
    function at(y) {
      let low = 0, high = shown.length - 1;
      while (low < high) { const middle = (low + high + 1) >> 1; if (tops[middle] <= y) low = middle; else high = middle - 1; }
      return Math.max(0, low);
    }
    function detach(start, end) {
      for (let index = start; index < end; ++index) {
        const entry = shown[index], row = entry.node;
        if (!row) continue;
        // Focus would fall to the document with the row; keep it in the transcript.
        if (row.contains(document.activeElement)) controls.scroll.focus({preventScroll: true});
        resized.unobserve?.(row); row.remove();
        // A record row is rebuilt when it returns, unless a disclosure in it is open.
        if (entry.build && !row.querySelector('details[open]')) entry.node = null;
      }
    }
    // Keeps shown[start, end) in the document, moving only the rows that
    // enter or leave it.
    function render(start, end) {
      if (end <= from || start >= to) { detach(from, to); from = to = start; }
      else {
        if (start > from) { detach(from, start); from = start; }
        if (end < to) { detach(end, to); to = end; }
      }
      if (start < from) { const head = []; for (let index = start; index < from; ++index) head.push(node(shown[index])); controls.output.prepend(...head); from = start; }
      if (end > to) { const tail = []; for (let index = to; index < end; ++index) tail.push(node(shown[index])); controls.output.append(...tail); to = end; }
    }
    function measure() {
      let changed = false;
      for (let index = from; index < to; ++index) {
        const entry = shown[index], height = entry.node.getBoundingClientRect().height;
        if (height === entry.height) continue;
        if (entry.height != null) count(entry.height, -1);
        count(height, 1); entry.height = height; changed = true;
      }
      if (changed) stale = true;
      return changed;
    }
    function layout() {
      scheduled = false;
      const viewport = controls.scroll.clientHeight;
      // A hidden panel measures nothing; it is laid out when it is shown.
      if (root.hidden || !viewport) return;
      const base = controls.output.getBoundingClientRect().top - controls.scroll.getBoundingClientRect().top + controls.scroll.scrollTop;
      const scrolled = controls.scroll.scrollTop - base, jumped = jump != null;
      offsets();
      const squeezed = tops[shown.length] > transcriptExtent;
      // Where the reader is. Across a change between fitting and compressed,
      // the position stays and the scroll offset moves to it instead.
      if (jumped) position = jump;
      else if (squeezed === compressed) {
        const moved = scrolled - shift;
        position = !squeezed ? scrolled : Math.abs(moved) > 2 * viewport
          ? scrolled / (transcriptExtent - viewport) * (tops[shown.length] - viewport) : position + moved;
      }
      jump = null;
      for (let pass = 0; pass < 8; ++pass) {
        if (follow) position = tops[shown.length] - viewport;
        position = Math.max(0, Math.min(position, tops[shown.length] - viewport));
        // The first visible entry stays where the reader sees it while the
        // entries above it are measured.
        const anchor = at(position), offset = tops[anchor] - position;
        render(shown.length ? at(position - overscan) : 0, shown.length ? Math.min(shown.length, at(position + viewport + overscan) + 1) : 0);
        const changed = measure();
        offsets();
        if (changed && shown.length) position = tops[anchor] - offset;
        if (!changed) break;
      }
      const height = tops[shown.length], drawn = tops[to] - tops[from];
      if (follow) position = height - viewport;
      position = Math.max(0, Math.min(position, height - viewport));
      compressed = height > transcriptExtent;
      let target = position, before = tops[from];
      if (compressed) {
        // The drawn rows sit wherever the reader is scrolled, unless that
        // would put them past either end of the extent, or the scroll offset
        // is at an end the reader has not reached: then the scroll offset
        // moves to where the position maps.
        const range = transcriptExtent - viewport, end = height - viewport;
        target = scrolled; before = target - (position - tops[from]);
        if (jumped || before < 0 || before + drawn > transcriptExtent || target <= 0 && position > 0 || target >= range && position < end) {
          target = position / end * range; before = target - (position - tops[from]);
        }
      }
      controls.output.style.paddingTop = `${before}px`;
      controls.output.style.paddingBottom = `${(compressed ? transcriptExtent : height) - before - drawn}px`;
      if (Math.abs(scrolled - target) >= 1) controls.scroll.scrollTop = base + target;
      shift = controls.scroll.scrollTop - base;
      updateOutputState();
    }
    function schedule() {
      if (scheduled) return;
      scheduled = true; Promise.resolve().then(layout);
    }
    function refilter() {
      detach(from, to); from = to = 0;
      shown = entries.filter(matches); stale = true; schedule();
    }
    controls.scroll.addEventListener('scroll', () => { follow = atBottom(); if (follow) unread = 0; layout(); updateOutputState(); });
    new ResizeObserver(schedule).observe(controls.scroll);
    return {
      size: () => entries.length,
      visible: () => shown.length,
      layout, schedule, refilter,
      // A record entry is {build, text, level}; a live one is {node, command}.
      add(entry) {
        entries.push(entry);
        if (entry.node) owners.set(entry.node, entry);
        if (matches(entry)) { shown.push(entry); if (!stale) tops.push(tops[tops.length - 1] + estimate()); }
        if (!follow) ++unread;
        schedule();
        return entry.node;
      },
      // A live row changed: it may now be taller, or start or stop matching.
      changed(row) {
        const entry = row && owners.get(row);
        if (!entry) return;
        if ((controls.filter.value || controls.level.value !== 'all') && shown.includes(entry) !== matches(entry)) refilter();
        else schedule();
      },
      clear() {
        detach(from, to); from = to = 0;
        entries.length = 0; shown = []; tops = [0]; stale = false; heights.clear(); measured = 0; typical = 24; typicalStale = false;
        follow = true; unread = 0; position = shift = 0; compressed = false; jump = null;
        controls.output.style.paddingTop = controls.output.style.paddingBottom = '0px';
      },
      latest() { follow = true; unread = 0; layout(); updateOutputState(); },
      // Live rows that match, rendered or not.
      find: predicate => entries.filter(entry => !entry.build && predicate(entry.node)),
      // Scrolls one entry to the middle of the viewport and returns its row.
      reveal(entry) {
        if (!shown.includes(entry)) { controls.filter.value = ''; controls.level.value = 'all'; refilter(); }
        offsets();
        const index = shown.indexOf(entry);
        follow = false; jump = tops[index] - (controls.scroll.clientHeight - (entry.height ?? estimate())) / 2;
        layout();
        return entry.node;
      }
    };
  })();
  element('latest').addEventListener('click', () => transcript.latest());
  element('empty-action').addEventListener('click', () => {
    if (!session) {
      if (documentSource === 'live_capture') { if (selectedDocument()) { controls.connection.open = true; if (controls['live-consent'].checked) controls.start.click(); else controls['live-consent'].focus(); } else controls.target.focus(); }
      else if (!available) initialize(true);
      else { controls.connection.open = true; controls.url.focus(); }
    }
    else if (documentSource === 'live_capture' && !selectedDocument()) controls.stop.click();
    else if (!controls.target.value) controls.refresh.click();
    else controls.source.focus();
  });
  function clearTargets() {
    const option = document.createElement('option'); option.value = ''; option.textContent = 'Select a document';
    controls.target.replaceChildren(option); controls.target.title = 'Select a document';
  }
  function invalidateTargets() {
    if (documentSource === 'live_capture' && controls.target.value) targets({targets: [], truncated: false, binding_id: liveBinding});
    else clearTargets();
  }
  function captureState(value) {
    if (value.document_source === 'live_capture') {
      liveListing = value; liveAvailable = value.live_available === true && numberId(value.binding_id);
      liveBinding = numberId(value.binding_id) ? value.binding_id : null;
      if (session) {
        documentSource = 'live_capture';
        if (!selectedBinding) selectedBinding = liveBinding;
      }
    } else { liveListing = null; liveAvailable = false; }
    if (documentSource === 'live_capture') {
      targets(liveListing || {targets: [], truncated: false}, session && numberId(value.selected_target_id) ? value.selected_target_id : controls.target.value);
      if (!liveAvailable) notice(value.message || 'Live capture binding unavailable. Restart the capture; no second browser was launched.', value.binding_state !== 'connecting');
    }
  }
  controls.mode.addEventListener('change', () => {
    if (session || pending || checking) return;
    ++generation; completion.close(); clearTargets(); selectedBinding = null; controls['live-consent'].checked = false;
    documentSource = controls.mode.value === 'live_capture' ? 'live_capture' : 'disposable';
    if (documentSource === 'live_capture') targets(liveListing || {targets: [], truncated: false});
    else notice('Commands run in a separate disposable browser profile.');
    renderControls();
  });
  controls['live-consent'].addEventListener('change', renderControls);
  async function request(action, fields = {}, identity = session) {
    const response = await fetch('/api/native-console/actions', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, cache: 'no-store',
      body: JSON.stringify({action, ...(['start', 'connect_live'].includes(action) ? {} : {session_id: identity}), ...fields})
    });
    const value = await response.json();
    if (!response.ok) throw new Error(typeof value.error === 'string' ? value.error : `Console returned ${response.status}`);
    if (!validState(value, documentStartActions.includes(action) ? 4 : 2) || value.state !== (action === 'stop' ? 'idle' : 'ready') ||
        !['start', 'stop', 'connect_live'].includes(action) && value.session_id !== identity) throw new TypeError('Malformed native console response');
    return value;
  }
  // Stop belongs to the session it was clicked for, not to a document
  // selection, so a selection change while it waits never discards it. It
  // counts as pending from the click, so the badge reads Working rather than
  // Connected and nothing else queues behind it.
  function enqueue(action, fields, apply, {quiet = false, context = false} = {}) {
    const identity = session, target = controls.target.value, epoch = generation, stop = action === 'stop';
    if (stop) { ++pending; renderControls(); }
    const execute = async () => {
      let counted = stop;
      try {
        if (stop && identity !== session) { notice('This Console session had already ended. Nothing was sent.'); return null; }
        if (!stop && (epoch !== generation || context && (!identity || identity !== session || target !== controls.target.value))) {
          if (!quiet) notice('Not sent: the document selection or session changed while this waited. Nothing ran.', true);
          return null;
        }
        if (!quiet && !stop) { ++pending; counted = true; renderControls(); }
        const value = await (action === 'runtime' ? running(() => request(action, fields, identity), quiet) : request(action, fields, identity));
        if (!stop && epoch !== generation) return null;
        disconnected = false; return apply ? apply(value) : value;
      } catch (error) {
        if (stop || epoch === generation) { invalidateTargets(); disconnected = true; notice(`${error.message}. Commands are never retried automatically.`, true); renderControls(); }
        return null;
      } finally { if (counted) { --pending; renderControls(); } }
    };
    const result = queue.then(execute); queue = result.catch(() => {}); return result;
  }
  // Stop shows at once for an explicit command, and for a background one
  // (completion, polling) only once it is slow, so routine requests never
  // flash it.
  async function running(send, quiet) {
    let shown = false;
    const show = () => { shown = true; ++commandsRunning; renderControls(); };
    const slow = quiet ? setTimeout(show, 1000) : (show(), null);
    try { return await send(); }
    finally {
      clearTimeout(slow);
      if (shown) { if (!--commandsRunning) stopping = false; renderControls(); }
    }
  }
  // Bypasses the queue, which the running command holds.
  controls.interrupt.addEventListener('click', async () => {
    if (!session || stopping || !commandsRunning) return;
    stopping = true; renderControls();
    try {
      const value = await request('interrupt', {}, session);
      if (value.command !== 'stopping') { stopping = false; notice('The command had already returned. Nothing was stopped.'); }
    } catch (error) { stopping = false; notice(`${error.message}. Stop was not retried.`, true); }
    renderControls();
  });
  function runtime(command, target = controls.target.value, quiet = false, identity = session, epoch = generation) {
    if (epoch !== generation) return Promise.resolve({status: 'error', text: 'This value belongs to an earlier document selection. Run a new command to inspect a current value.'});
    if (identity !== session) return Promise.resolve({status: 'error', text: 'This value belongs to a disconnected console session.'});
    if (!selectedDocument() || !target || target !== controls.target.value) return Promise.resolve({status: 'error', text: 'Select the original document to inspect this value.'});
    return enqueue('runtime', {target_id: target, command}, value => {
      if (!value.runtime) {
        if (value.status === 'stale_target') { boundary('Document changed. Disconnect and explicitly select the current document.'); invalidateTargets(); renderControls(); }
        return {status: value.status || 'error', text: value.text || 'Runtime response unavailable', request_id: value.request_id};
      }
      const result = value.runtime;
      if (!['ok', 'error', 'exception', 'pending', 'rejected'].includes(result.status)) throw new TypeError('Malformed runtime status');
      result.request_id = value.request_id;
      return result;
    }, {quiet, context: true});
  }
  function targets(value, selected = controls.target.value) {
    if (documentSource === 'live_capture') {
      liveBinding = numberId(value.binding_id) ? value.binding_id : null;
      if (selected && selectedBinding && selectedBinding !== liveBinding && !selected.startsWith('unavailable:')) {
        selected = `unavailable:${selectedBinding}:${selected}`;
        controls['live-consent'].checked = false;
      }
    }
    if (!Array.isArray(value.targets) || typeof value.truncated !== 'boolean' || value.targets.some(target =>
      !numberId(target.id) || typeof target.origin !== 'string' || typeof target.label !== 'string' || typeof target.url !== 'string' ||
      typeof target.main_frame !== 'boolean') || new Set(value.targets.map(target => target.id)).size !== value.targets.length) throw new TypeError('Malformed document listing');
    const invalid = documentSource === 'live_capture' && !!session && value.selected_target_id === null;
    document.dispatchEvent(new CustomEvent('reb:console-documents', {detail: value.targets.map(target => ({url: target.url, main_frame: target.main_frame}))}));
    clearTargets(); partialTargets = value.truncated;
    for (const target of value.targets) {
      const option = document.createElement('option'); option.value = target.id;
      option.textContent = `${target.label || `${target.main_frame ? 'top' : 'frame'} #${target.id}`} · ${target.origin}`;
      option.dataset.url = target.url;
      option.title = `${target.label} · ${target.url} · document ${target.id}`; controls.target.append(option);
    }
    if (!invalid && [...controls.target.options].some(option => option.value === selected)) controls.target.value = selected;
    else if (selected && documentSource === 'live_capture') {
      for (const option of [...controls.target.options]) if (option.value === selected) option.remove();
      const missing = document.createElement('option'); missing.value = selected; missing.disabled = true;
      missing.textContent = `Document ${selected} unavailable · select a current document`;
      controls.target.append(missing); controls.target.value = selected;
      controls['live-consent'].checked = false;
    }
    const liveNotice = 'These documents come from the live capture. Select one, explicitly authorize mutation, then connect. Commands can change that captured page. This console cannot set breakpoints, step, or inspect paused frames.';
    notice(documentSource === 'live_capture'
      ? (value.targets.length ? `${liveNotice}${partialTargets ? ' Document listing is partial.' : ''}` : 'No eligible documents yet. Open an HTTP or HTTPS page in the live capture.')
      : (value.targets.length ? `Select a document in the disposable browser.${partialTargets ? ' Document listing is partial.' : ''}` : 'No eligible documents yet. Open an HTTP or HTTPS page in the disposable browser, then refresh.'));
  }
  function changedRow(row) { transcript.changed(row); }
  function boundary(text) {
    transcript.add({text, build: () => { const row = document.createElement('div'); row.className = 'native-console-boundary'; row.textContent = text; return row; }});
  }
  function button(label, action) {
    const control = document.createElement('button'); control.type = 'button'; control.textContent = label;
    control.addEventListener('click', async event => {
      try { await action(event); }
      catch (error) { notice(`${error.message}. The action was not retried.`, true); }
    }); return control;
  }
  const locationText = value => value && typeof value.url === 'string' && Number.isInteger(value.line) && value.line >= 1 ? `${value.url || 'console'}:${value.line}:${value.column || 1}` : '';
  function location(container, value) {
    if (!locationText(value)) return;
    const control = button(locationText(value), () => {
      const live = documentSource === 'live_capture';
      const detail = {url: value.url, line: value.line, unavailable: false, live};
      document.dispatchEvent(new CustomEvent('reb-console-location', {detail}));
      if (detail.unavailable) notice(live ? `No source for ${value.url} in this evidence workspace.` : `No source for ${value.url} in this evidence workspace. The console runs in a separate disposable browser.`);
    });
    control.className = 'native-console-location'; control.title = documentSource === 'live_capture' ? 'Search captured sources by URL; this document is from the live capture' : 'Search captured sources by URL; this disposable browser is a separate context'; control.setAttribute('aria-label', `Search captured sources by URL: ${value.url}, line ${value.line}`); container.append(control);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); notice('Copied to clipboard.'); }
    catch { notice('Clipboard unavailable. Select the result and use Copy.', true); }
  }
  async function copyValue(value, scope) {
    if (value?.handle && value.type === 'object') {
      const page = await runtime({operation: 'inspect', handle: value.handle, offset: 0}, scope.target, false, scope.session, scope.generation);
      if (page?.status === 'ok') { await copy(JSON.stringify({preview: value.text, properties: page.properties, more: page.more}, null, 2)); return; }
    }
    await copy(value?.text || '');
  }
  function checkValue(value) {
    if (!value || !types.includes(value.type) || typeof value.text !== 'string' || value.handle != null && !numberId(value.handle)) throw new TypeError('Malformed runtime value');
  }
  // Each level expands only when opened, one page at a time, so any depth can be inspected.
  function renderValue(container, value, scope) {
    checkValue(value);
    if (value.handle && ['object', 'function', 'promise'].includes(value.type)) {
      const disclosure = document.createElement('details'); disclosure.className = 'native-console-object';
      const summary = document.createElement('summary'); appendCommandColors(summary, value.text);
      const children = document.createElement('div'); children.className = 'native-console-properties';
      const actions = document.createElement('div'); actions.className = 'native-console-actions';
      const status = document.createElement('div'); status.className = 'native-console-property-status'; status.setAttribute('role', 'status');
      const pager = document.createElement('div'); pager.className = 'native-console-property-pager';
      let loaded = false, offset = 0, nextOffset = 0, loading = false, released = false, retryOffset = 0, pageUnavailable = false, moreAvailable = false;
      const previous = button('Previous properties', () => inspect(pageUnavailable ? 0 : Math.max(0, offset - 16)));
      const more = button('Next properties', () => inspect(nextOffset));
      const retry = button('Retry inspection', () => inspect(retryOffset)); retry.hidden = true;
      previous.disabled = true; more.disabled = true; pager.hidden = true; pager.append(previous, more, retry);
      async function inspect(pageOffset = 0) {
        if (loading || released) return; loading = true; retryOffset = pageOffset;
        let focusBeforeUpdate = null;
        status.textContent = 'Loading properties…'; children.setAttribute('aria-busy', 'true');
        // Keep keyboard focus on stable pager buttons while the request runs.
        // The loading guard rejects repeat activation without disabling focus.
        for (const control of [previous, more, retry]) control.setAttribute('aria-disabled', 'true');
        try {
          const result = await runtime({operation: 'inspect', handle: value.handle, offset: pageOffset}, scope.target, false, scope.session, scope.generation);
          if (!disclosure.isConnected) return;
          focusBeforeUpdate = document.activeElement;
          if (!result || result.status !== 'ok') throw new Error(result?.text || 'Inspection unavailable. Refresh documents if the connection was lost.');
          if (!Array.isArray(result.properties) || result.properties.length > 17 || typeof result.more !== 'boolean' || !Number.isInteger(result.offset) || result.offset < 0 || result.offset > pageOffset + 16 || result.more && result.offset <= pageOffset || result.offset < pageOffset && (result.more || result.properties.length !== 0)) throw new TypeError('Malformed property page.');
          const fragment = document.createDocumentFragment();
          for (const property of result.properties) {
            if (typeof property.name !== 'string') throw new TypeError('Malformed property name.');
            checkValue(property.value);
            const row = document.createElement('div'); row.className = 'native-console-property';
            const name = document.createElement('span'); name.className = 'native-console-property-name'; name.textContent = `${property.name}: `;
            row.append(name); renderValue(row, property.value, scope); fragment.append(row);
          }
          // Replace one property page. Navigating a large object never grows a
          // permanent list or retains detached child pages and their handles.
          children.replaceChildren(fragment); loaded = true; offset = pageOffset; nextOffset = result.offset; moreAvailable = result.more;
          // Native enumeration uses min(live length, requested offset + 16).
          // A live object can shrink below a previously available page.
          pageUnavailable = pageOffset > 0 && !result.more && result.properties.length === 0 && result.offset <= pageOffset;
          previous.textContent = pageUnavailable ? 'First properties' : 'Previous properties';
          retry.textContent = pageUnavailable ? 'Reload this page' : 'Retry inspection'; retry.hidden = !pageUnavailable;
          status.textContent = pageUnavailable ? `This page is no longer available (${result.offset} properties remain). Return to the first page or reload this page if the object changes.` : result.properties.length ? `Properties ${pageOffset + 1}–${result.offset || result.properties.length}${pageOffset === 0 && result.properties.some(property => property.name === '[[Prototype]]') ? ' + prototype' : ''}` : 'No inspectable properties.';
          previous.disabled = offset === 0; more.disabled = !result.more;
          pager.hidden = previous.disabled && more.disabled && retry.hidden;
        } catch (error) {
          status.textContent = `${error.message}${loaded ? ' Previous page preserved.' : ''}`;
          previous.disabled = !loaded || offset === 0; more.disabled = !loaded || !moreAvailable;
          retry.textContent = 'Retry inspection'; pager.hidden = false; retry.hidden = false;
        } finally {
          loading = false; children.setAttribute('aria-busy', 'false');
          for (const control of [previous, more, retry]) control.removeAttribute('aria-disabled');
          if ([previous, more, retry].includes(focusBeforeUpdate) && (focusBeforeUpdate.disabled || focusBeforeUpdate.hidden) &&
              [focusBeforeUpdate, document.body].includes(document.activeElement)) {
            (!previous.disabled ? previous : !more.disabled ? more : !retry.hidden ? retry : summary).focus();
          }
          changedRow(container.closest('.native-console-result'));
        }
      }
      actions.append(button('Copy properties', () => copyValue(value, scope)), button('Store as variable', async () => {
        const result = await runtime({operation: 'store', handle: value.handle}, scope.target, false, scope.session, scope.generation);
        if (result) notice(result.status === 'ok' ? `Stored as ${result.text} in the selected page.` : result.text, result.status !== 'ok');
      }), button('Release', async () => {
        const result = await runtime({operation: 'release', handle: value.handle}, scope.target, false, scope.session, scope.generation);
        if (result?.status === 'ok') { released = true; loaded = true; children.replaceChildren(); summary.textContent = `${value.text} (released)`; status.textContent = 'Value released. Run a new command to inspect it again.'; pager.hidden = true; actionDetails.hidden = true; changedRow(container.closest('article')); }
      }));
      location(actions, value.location);
      if (value.type === 'function') actions.append(button('Show function source', async () => {
        const result = await runtime({operation: 'source', handle: value.handle}, scope.target, false, scope.session, scope.generation);
        if (result?.text && disclosure.isConnected) { pager.hidden = true; status.textContent = result.status === 'ok' ? 'Native function source' : 'Source unavailable'; const source = document.createElement('pre'); appendCommandColors(source, result.text); children.replaceChildren(source); disclosure.open = true; loaded = true; changedRow(container.closest('article')); }
      }));
      // An element describes itself by its tag; window and document describe
      // themselves as a plain Object, and the runtime lists their listeners
      // too (getEventListeners(window)). It refuses any other object, and says so.
      const element = value.text.startsWith('<');
      if (element || value.type === 'object' && value.text === 'Object') actions.append(button('Event listeners', async () => {
        const result = await runtime({operation: 'listeners', handle: value.handle}, scope.target, false, scope.session, scope.generation);
        if (!result) return;
        children.replaceChildren(); pager.hidden = true; status.textContent = 'Registered event listeners'; loaded = true; disclosure.open = true;
        if (result.status !== 'ok') { children.textContent = result.text; return; }
        if (!result.properties?.length) children.textContent = 'No registered listeners.';
        for (const property of result.properties || []) {
          const row = document.createElement('div'); row.className = 'native-console-property'; row.append(document.createTextNode(property.name + ': ')); renderValue(row, property.value, scope); children.append(row);
        }
        changedRow(container.closest('article'));
      }));
      // Monitoring is per element only.
      if (element) actions.append(button('Monitor events', async () => { const result = await runtime({operation: 'monitor', handle: value.handle}, scope.target, false, scope.session, scope.generation); if (result) notice(result.text); }),
        button('Stop monitoring', async () => { const result = await runtime({operation: 'unmonitor', handle: value.handle}, scope.target, false, scope.session, scope.generation); if (result) notice(result.text); }));
      const actionDetails = document.createElement('details'); actionDetails.className = 'native-console-value-actions';
      const actionSummary = document.createElement('summary'); actionSummary.textContent = 'Value actions'; actionDetails.append(actionSummary, actions);
      disclosure.append(summary, status, children, pager, actionDetails); container.append(disclosure);
      disclosure.addEventListener('toggle', () => { if (disclosure.open && !loaded && !retry.hidden) return; if (disclosure.open && !loaded) inspect(); });
      if (value.type === 'promise') {
        actions.append(button('Await', () => awaitValue(container, value, scope)), button('Stop waiting', async () => { container.dataset.wait = String(Number(container.dataset.wait || 0) + 1); container.dataset.awaiting = 'false'; const result = await runtime({operation: 'cancel', handle: value.handle}, scope.target, false, scope.session, scope.generation); if (result) notice(result.text || 'Stopped waiting; page work continues.'); }));
      }
    } else {
      const output = document.createElement('span'); output.className = 'native-console-primitive'; output.dataset.type = value.type;
      output.textContent = value.type === 'string' ? JSON.stringify(value.text) : value.text; container.append(output);
    }
  }
  async function awaitValue(container, value, scope, replace = false) {
    if (container.dataset.awaiting === 'true') return;
    const started = Date.now(); const token = generation;
    // Checks often at first, then once a second, for as long as it takes.
    const delay = () => Date.now() - started < 10000 ? 200 : 1000;
    const wait = String(Number(container.dataset.wait || 0) + 1); container.dataset.wait = wait;
    container.dataset.awaiting = 'true';
    const current = () => container.dataset.wait === wait && container.isConnected && token === generation && session === scope.session && controls.target.value === scope.target;
    async function tick() {
      let polling = false;
      try {
        if (!current()) return;
        const result = await runtime({operation: 'await', handle: value.handle}, scope.target, true, scope.session, scope.generation);
        if (!result || !current()) return;
        if (result.status === 'pending') { polling = true; setTimeout(tick, delay()); return; }
        const settled = document.createElement('div'); settled.className = 'native-console-value';
        if (result.value) { renderValue(settled, result.value, scope); const row = container.closest('article'); row.dataset.status = result.status; row.dataset.level = result.status === 'ok' ? 'result' : 'error'; }
        else settled.textContent = result.text || 'Await stopped';
        if (replace && result.value) { container.replaceChildren(); renderValue(container, result.value, scope); }
        else if (replace) container.replaceChildren(settled);
        else { container.querySelector('summary').textContent = result.status === 'rejected' ? 'Promise {<rejected>}' : result.status === 'ok' ? 'Promise {<fulfilled>}' : value.text; container.append(settled); }
        changedRow(container.closest('article'));
      } finally {
        // Only a newer wait owns the flag, so every other exit lets Await run again.
        if (!polling && container.dataset.wait === wait) container.dataset.awaiting = 'false';
      }
    }
    tick();
  }
  function result(value, source, scope) {
    const row = document.createElement('article'); row.className = 'native-console-result'; row.dataset.status = value.status; row.dataset.requestId = value.request_id || '';
    row.dataset.level = value.status === 'ok' ? 'result' : 'error'; row.dataset.commandId = scope.command; row.dataset.commandNumber = scope.command; row.dataset.consoleSession = scope.session; row.dataset.consoleDocument = scope.target;
    row.setAttribute('aria-label', `Result for command ${scope.command}: ${value.status}`);
    const output = document.createElement('div'); output.className = 'native-console-value';
    row.append(output);
    if (value.value) { row.dataset.type = value.value.type; renderValue(output, value.value, scope); }
    else { output.textContent = value.text || value.status; location(row, value.location); }
    if (Array.isArray(value.stack)) for (const frame of value.stack) { const entry = document.createElement('div'); location(entry, frame); row.append(entry); }
    const details = document.createElement('details'); details.className = 'native-console-result-details';
    const summary = document.createElement('summary'); summary.textContent = '⋯'; summary.setAttribute('aria-label', `Result details: ${value.status}`);
    const label = document.createElement('div'); label.className = 'native-console-result-type'; label.textContent = `${value.status} · session ${scope.session} · document ${scope.target} · ${scope.live ? 'live capture' : 'disposable experiment'}`;
    label.append(button('Copy result', () => value.value ? copyValue(value.value, scope) : copy(value.text || '')), button('Save snippet', () => saveSnippet(source)), button('Experiment activity', async () => {
      // Each read drains the oldest page of this document's activity, so read
      // until none remains and show every page that arrived.
      const events = []; let dropped = 0, read = false, reply;
      do {
        reply = await runtime({operation: 'traffic'}, scope.target, false, scope.session, scope.generation);
        if (reply?.status !== 'ok') break;
        read = true; dropped += reply.dropped || 0;
        for (const event of reply.events || []) events.push(event);
      } while (reply.more === true);
      if (read) document.dispatchEvent(new CustomEvent('reb-console-traffic', {detail: {session: scope.session, target: scope.target, request: value.request_id, events, dropped}}));
    })); details.append(summary, label); row.append(details); transcript.add({node: row, command: source});
    if (value.value?.type === 'promise' && /^\s*await\b/.test(source)) awaitValue(output, value.value, scope, true);
    return row;
  }
  function logRow(message) {
    const row = document.createElement('article'); row.className = 'native-console-result native-console-log'; row.dataset.level = message.level;
    const time = document.createElement('span'); time.className = 'native-console-time'; time.textContent = new Date(message.time).toLocaleTimeString(); row.append(time);
    const output = document.createElement('pre'); output.textContent = message.text; row.append(output); location(row, message);
    if (message.stack) { const details = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = 'Stack'; const stack = document.createElement('pre'); stack.textContent = message.stack; details.append(summary, stack); row.append(details); }
    return row;
  }
  function logs(value, epoch = outputGeneration) {
    if (!Array.isArray(value.messages) || !Number.isInteger(value.dropped) || value.dropped < 0 || value.more != null && typeof value.more !== 'boolean') throw new TypeError('Malformed console messages');
    if (value.messages.some(message => !message || !levels.includes(message.level) || typeof message.text !== 'string' || typeof message.time !== 'number' || !Number.isFinite(message.time) || Math.abs(message.time) > 8640000000000000 || message.stack != null && typeof message.stack !== 'string')) throw new TypeError('Malformed page message');
    if (epoch !== outputGeneration) return;
    if (value.dropped) boundary(`${value.dropped} page messages dropped before delivery.`);
    for (const message of value.messages) {
      transcript.add({level: message.level, build: () => logRow(message),
        text: `${new Date(message.time).toLocaleTimeString()}${message.text}${locationText(message)}${message.stack ? `Stack${message.stack}` : ''}`});
    }
  }

  // Document-start script experiment. A separate opt-in: the panel never arms
  // anything on its own, output is labeled page JavaScript rather than
  // evidence, and every captured value is inserted as text.
  const documentStart = (() => {
    const ds = name => element(`ds-${name}`);
    const sequence = value => typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value);
    // Output sequences only grow within a browser session, whatever the set
    // does, so the cursor only moves forward until the next connection.
    let view = null, cursor = '0', refreshing = false, tick = 0, failed = false, armedKey = '';
    function requested() { return ds('enable').checked === true; }
    function armedCount() { return view?.document_start?.scripts?.length || 0; }
    function permitted() { return view?.document_start?.permitted === true; }
    // The browser may still run a set the owner could not confirm it cleared.
    function unconfirmed() { return view?.document_start?.status === 'unconfirmed'; }
    function message(text, error = false) {
      ds('notice').textContent = text; ds('notice').title = text;
      ds('notice').dataset.kind = error ? 'error' : 'status'; ds('notice').hidden = !text;
    }
    function render() {
      const live = documentSource === 'live_capture';
      const armed = armedCount();
      const badge = ds('badge');
      // The indicator stays outside the settings menu: an armed experiment, or
      // one whose removal was never confirmed, must be visible without opening
      // anything and must never read as off.
      const uncleared = unconfirmed();
      // Before any Console connection, the capture browser's own listing says
      // whether this live capture was launched with the permission. The
      // packaged app grants it by default, so it is shown, not assumed.
      const listed = !session && liveAvailable ? liveListing?.document_start_supported : undefined;
      const livePermitted = listed === true;
      badge.hidden = !session && !armed && !uncleared && !livePermitted;
      badge.textContent = uncleared ? 'Doc-start: unconfirmed' : armed ? `Doc-start: ${armed} armed` : permitted() ? 'Doc-start: ready'
        : livePermitted ? 'Doc-start: permitted' : 'Doc-start: off';
      badge.dataset.state = uncleared ? 'unconfirmed' : armed ? 'armed' : permitted() ? 'ready' : livePermitted ? 'permitted' : 'off';
      const described = uncleared
        ? 'Document-start scripts: clearing was not confirmed, so new matching documents may still run them. Open the experiment settings.'
        : armed ? `Document-start scripts: ${armed} armed. Open the experiment settings.`
          : livePermitted ? 'Document-start scripts: permitted for this live capture, none armed. Arming needs a live Console connection and a separate confirmation. Open the experiment settings.'
            : 'Document-start scripts: none armed. Open the experiment settings.';
      // A narrow header shows only a marker, so the hover title carries the state too.
      badge.setAttribute('aria-label', described); badge.title = described;
      root.dataset.documentStart = badge.dataset.state;
      const status = ds('state');
      status.textContent = failed ? 'Document-start state unavailable. The last known state is preserved; nothing was armed or cleared.'
        : uncleared ? (view.document_start.message || 'Clearing document-start scripts was not confirmed.')
        : !session ? (requested()
            ? 'Permitted for the next disposable session. Connect, then arm a rule. Nothing runs until you arm one.'
            : livePermitted ? 'This live capture permits document-start scripts. Connect to a selected live document, then arm a rule. Nothing runs until you arm one.'
            : listed === false ? 'This live capture does not permit document-start scripts: its browser lacks the rebuilt overlay, or Allow document-start Console scripts was off when it started. Permit them for a disposable session above, or start a new live session with them allowed, under Advanced options in New Live Session…. Nothing is relaunched automatically.'
            : 'Connect a session with this permitted, or start a new live session with Allow document-start Console scripts on, under Advanced options in New Live Session….')
        : permitted() ? `Armed scripts: ${armed}. A matching new document runs them before its own scripts.`
        : (view?.document_start?.message || 'Document-start scripts are not available in this session.');
      ds('enable').disabled = !!session || !!pending || checking || live;
      const ready = !!session && permitted() && !pending && !submitting;
      ds('arm').disabled = !ready || !ds('origin').value.trim() || !ds('source').value.trim() || !ds('consent').checked;
      ds('clear').disabled = !ready;
      for (const name of ['origin', 'frame', 'path', 'source', 'consent']) ds(name).disabled = !ready;
      const scripts = view?.document_start?.scripts || [];
      const list = ds('armed');
      // Rebuilt only when the set changes, so a focused Remove stays focused.
      const key = JSON.stringify(scripts);
      if (key !== armedKey) {
        armedKey = key; list.replaceChildren();
        for (const script of scripts) {
          const item = document.createElement('li');
          const prefix = script.rule.path_prefix ? ` path ${script.rule.path_prefix}*` : ' any path';
          const label = document.createElement('span');
          label.textContent = `#${script.script_id} ${script.rule.origin} · ${script.rule.frame} frame ·${prefix} · ${script.source_bytes} bytes · ${script.digest} · ${script.injected_documents} documents · ${script.records} records · ${script.refused} refused`;
          const remove = button('Remove', () => removeScript(script.script_id)); remove.className = 'native-console-button';
          remove.setAttribute('aria-label', `Remove document-start script ${script.script_id}`);
          item.append(label, remove); list.append(item);
        }
      }
      for (const remove of list.querySelectorAll('button')) remove.disabled = !ready;
      const unsupported = view?.unsupported;
      if (Array.isArray(unsupported) && unsupported.every(entry => typeof entry?.context === 'string')) {
        // Out of scope whatever a rule declares, so a rule that did not match
        // reads differently from a context that is never reached.
        ds('rule-help').textContent = `One exact origin and one frame kind. No pattern, wildcard or host suffix. Never reached: ${unsupported.map(entry => entry.context.replace(/_/g, ' ')).join(', ')}.`;
      }
      const output = view?.document_start?.output;
      const pendingProcesses = view?.document_start?.pending_renderer_processes;
      ds('counters').textContent = !output ? '' :
        `${output.retained} retained · ${output.dropped} dropped · ${output.unattributed} unattributed · ${output.stale} stale · ${pendingProcesses ? `${pendingProcesses} renderer processes not ready yet` : 'every renderer holds this set'}`;
    }
    function reset() {
      view = null; cursor = '0'; failed = false;
      ds('consent').checked = false; message(''); render();
    }
    function check(records) {
      // A read returns the oldest records after the cursor, each whole, a page
      // at a time, so there is no count or size to check, only each shape.
      if (!Array.isArray(records)) throw new TypeError('Malformed document-start output');
      for (const record of records) {
        if (!record || !sequence(record.sequence) || record.provenance !== 'console-document-start-script' ||
            !['injected', 'report', 'script_error', 'refused'].includes(record.record) ||
            !numberId(record.script_id) || !sequence(record.document_id) || !sequence(record.frame_id) ||
            typeof record.top_frame !== 'boolean' || typeof record.text !== 'string' ||
            typeof record.time !== 'number' || !Number.isFinite(record.time) || Math.abs(record.time) > 8640000000000000) {
          throw new TypeError('Malformed document-start record');
        }
      }
    }
    function rows(records, dropped, epoch) {
      // Clearing the transcript invalidates delayed replies without touching
      // the armed set or the browser's retained records.
      if (epoch !== outputGeneration) return;
      if (dropped) boundary(`${dropped} document-start records were dropped before delivery.`);
      for (const record of records) {
        const level = record.record === 'script_error' ? 'error' : record.record === 'refused' ? 'warning' : 'info';
        const provenance = `page JavaScript · console-document-start-script · ${record.record} · script ${record.script_id} · document ${record.document_id} · ${record.top_frame ? 'top' : 'child'} frame`;
        transcript.add({level, build: () => recordRow(record, level, provenance),
          text: `${new Date(record.time).toLocaleTimeString()}${provenance}${record.text}`});
      }
    }
    function recordRow(record, level, provenance) {
      const row = document.createElement('article');
      row.className = 'native-console-result native-console-ds-record';
      row.dataset.level = level;
      row.dataset.record = record.record;
      row.dataset.consoleDocument = record.document_id;
      row.setAttribute('aria-label', `Document-start ${record.record} for script ${record.script_id} in document ${record.document_id}`);
      const time = document.createElement('span'); time.className = 'native-console-time';
      time.textContent = new Date(record.time).toLocaleTimeString(); row.append(time);
      const label = document.createElement('span'); label.className = 'native-console-ds-provenance';
      // Provenance is spelled out on every row: this is page JavaScript the
      // snippet produced, never native capture evidence.
      label.textContent = provenance;
      row.append(label);
      const output = document.createElement('pre'); output.textContent = record.text; row.append(output);
      return row;
    }
    function apply(value, epoch = outputGeneration) {
      if (value?.contract_version !== 4 || !['idle', 'ready'].includes(value.state) ||
          (value.available !== undefined && typeof value.available !== 'boolean') || !value.document_start ||
          !['ok', 'error', 'idle', 'unavailable', 'unconfirmed'].includes(value.document_start.status)) {
        throw new TypeError('Malformed document-start state');
      }
      const next = value.document_start;
      if (!Array.isArray(next.scripts)) throw new TypeError('Malformed armed set');
      for (const script of next.scripts) {
        if (!numberId(script?.script_id) || typeof script.rule?.origin !== 'string' ||
            !['top', 'child'].includes(script.rule.frame) || !/^[0-9a-f]{16}$/.test(script.digest || '') ||
            !Number.isInteger(script.source_bytes)) {
          throw new TypeError('Malformed armed script');
        }
      }
      if (next.output) {
        check(next.output.records);
        if (!sequence(next.output.next_sequence) || !sequence(next.output.oldest_sequence) ||
            !Number.isInteger(next.output.dropped) || next.output.dropped < 0 || typeof next.output.more !== 'boolean') {
          throw new TypeError('Malformed document-start output');
        }
        if (next.output.records.length) {
          rows(next.output.records, next.output.dropped, epoch);
          cursor = next.output.records.at(-1).sequence;
        }
      }
      view = value; failed = false;
    }
    async function refresh(force = false) {
      // A connected panel keeps reading while it is hidden, so its transcript
      // holds what the browser retained before the browser has to evict it.
      if (refreshing || (!force && (root.hidden && !session || pending || submitting))) return;
      if (!force && ++tick % 4) return;
      refreshing = true;
      const epoch = generation, identity = session;
      const execute = async () => {
        try {
          // A backlog arrives a page at a time; read on while more remains.
          for (let more = true; more;) {
            const response = await fetch(`/api/native-console/document-start?after_sequence=${cursor}`, {cache: 'no-store'});
            const value = await response.json();
            if (epoch !== generation || identity !== session) return;
            if (!response.ok) throw new Error(typeof value.error === 'string' ? value.error : `Document-start read returned ${response.status}`);
            apply(value);
            more = value.document_start.output?.more === true && value.document_start.output.records.length > 0;
          }
        } catch (error) {
          // Preserve the last understandable state; a failed read changes nothing.
          if (epoch === generation) { failed = true; message(`${error.message} The read was not retried.`, true); }
        } finally { refreshing = false; render(); }
      };
      const result = queue.then(execute); queue = result.catch(() => {}); return result;
    }
    // Arming adds the script beside the ones already armed, so a set of any
    // size is built one script at a time; Remove and Clear take them away.
    ds('arm').addEventListener('click', () => {
      if (ds('arm').disabled) return;
      const script = {origin: ds('origin').value.trim(), frame: ds('frame').value, source: ds('source').value};
      const prefix = ds('path').value.trim();
      if (prefix) script.path_prefix = prefix;
      // The bound the backend applies: one command is one Console record.
      if (recordBytes({operation: 'add', scripts: [script]}) > recordLimit) {
        message('A document-start command can be at most 4 GiB, counting its JSON escapes. Nothing was armed.', true);
        return;
      }
      enqueue('add_document_start', {scripts: [script], confirm_document_start: true}, value => {
        const armed = value?.document_start?.status === 'ok';
        ds('consent').checked = false;
        apply(value);
        message(armed ? 'Armed. Reload a matching document to run it; documents already open are not injected.' : (value.document_start.text || 'Arming was refused.'), !armed);
        boundary(armed
          ? `Document-start script armed for ${script.origin} ${script.frame} frame. New matching documents run it before their own scripts.`
          : 'Document-start arming was refused. The armed set is unchanged.');
        render();
      });
    });
    function removeScript(id) {
      if (!session || !permitted() || pending || submitting) return;
      enqueue('remove_document_start', {script_ids: [id]}, value => {
        const removed = value?.document_start?.status === 'ok';
        apply(value);
        message(removed ? `Script #${id} removed. New documents stop running it; its records stay.` : (value.document_start.text || 'Removal was refused.'), !removed);
        boundary(removed
          ? `Document-start script #${id} removed. Work it already scheduled in a page is not rolled back.`
          : `Document-start script #${id} was not removed. The armed set is unchanged.`);
        render();
      });
    }
    ds('clear').addEventListener('click', () => {
      if (ds('clear').disabled) return;
      enqueue('clear_document_start', {}, value => {
        const cleared = value?.document_start?.status === 'ok';
        ds('consent').checked = false;
        apply(value);
        message(cleared
          ? 'Document-start scripts cleared. New documents run nothing and a retained report function is inert.'
          : (value?.document_start?.message || value?.document_start?.text || 'Nothing was armed in this session.'), !cleared);
        boundary(cleared
          ? 'Document-start scripts cleared. Work a snippet already scheduled in a page is not rolled back.'
          : 'Document-start scripts were not armed in this session; nothing was cleared.');
        render();
      });
    });
    for (const name of ['origin', 'source', 'path']) ds(name).addEventListener('input', render);
    ds('frame').addEventListener('change', render);
    ds('consent').addEventListener('change', render);
    ds('enable').addEventListener('change', render);
    ds('badge').addEventListener('click', () => {
      controls.connection.open = true; element('ds').open = true;
      (ds('origin').disabled ? ds('enable') : ds('origin')).focus();
    });
    return {refresh, render, reset, requested, armed: armedCount};
  })();

  // A connected panel polls while it is hidden too: the renderer keeps a
  // bounded backlog for an owner that stops reading, and this one never does.
  async function poll() {
    if (pollRunning || !session || disconnected || !controls.target.value || pending) return;
    pollRunning = true;
    const epoch = outputGeneration, context = generation;
    try {
      for (let more = true; more && context === generation && epoch === outputGeneration;) {
        const value = await runtime({operation: 'poll'}, controls.target.value, true);
        if (value?.status !== 'ok') break;
        logs(value, epoch); more = value.more === true && value.messages.length > 0;
      }
    }
    catch (error) {
      if (context === generation) { invalidateTargets(); disconnected = true; notice(`${error.message}. Refresh documents to recover. Commands were not retried.`, true); renderControls(); }
    }
    finally { pollRunning = false; }
  }
  let listingTick = 0;
  async function refreshLiveDocuments(force = false) {
    if ((!force && root.hidden) || session || checking || pending || submitting || listingRunning) return;
    if (!force && ++listingTick % 4) return;
    const epoch = generation; listingRunning = true; renderControls();
    try {
      const response = await fetch('/api/native-console', {cache: 'no-store'});
      const value = await response.json();
      if (!response.ok || !validState(value) || session || epoch !== generation || pending) return;
      available = value.available; captureState(value); renderControls();
    } catch { /* The next availability check reports a hard failure. */ }
    finally { listingRunning = false; renderControls(); }
  }
  // The backend holds one Console session, which another window, an agent or
  // a lost binding can end. Its state read does no native exchange, so a
  // connected panel checks it rather than showing Connected for a session the
  // backend no longer has.
  let watchTick = 0, watching = false;
  async function watchSession(force = false) {
    if ((!force && root.hidden) || !session || disconnected || pending || submitting || checking || watching) return;
    if (!force && ++watchTick % 4) return;
    const identity = session, epoch = generation; watching = true;
    const execute = async () => {
      try {
        const response = await fetch('/api/native-console', {cache: 'no-store'});
        const value = await response.json();
        if (!response.ok || !validState(value) || typeof value.available !== 'boolean' || value.session_id === identity ||
            identity !== session || epoch !== generation || pending || submitting) return;
        ++generation; session = null; completion.close(); controls['live-consent'].checked = false;
        if (documentSource !== 'live_capture') { documentSource = 'disposable'; clearTargets(); }
        available = value.available; captureState(value);
        boundary('This Console session ended outside this window: another window or agent disconnected it, or its browser or binding ended. Nothing was retried.');
        notice(`Console session ended outside this window.${value.message ? ` ${value.message}` : ''}`, true);
        documentStart.reset();
      } catch { /* A failed read changes nothing; the next command reports its own failure. */ }
      finally { watching = false; renderControls(); }
    };
    const result = queue.then(execute); queue = result.catch(() => {}); return result;
  }
  setInterval(() => { poll(); refreshLiveDocuments(); watchSession(); documentStart.refresh(); }, 500);
  // Search covers every entry, rendered or not, and never changes one.
  function filter() { transcript.refilter(); updateOutputState(); }
  controls.filter.addEventListener('input', filter); controls.level.addEventListener('change', filter);
  function search() { element('filter-row').hidden = false; element('search').setAttribute('aria-expanded', 'true'); controls.filter.focus(); controls.filter.select(); }
  function closeSearch() { controls.filter.value = ''; controls.level.value = 'all'; filter(); element('filter-row').hidden = true; element('search').setAttribute('aria-expanded', 'false'); (controls.source.disabled ? element('search') : controls.source).focus(); }
  element('filter-close').addEventListener('click', closeSearch);
  element('search').addEventListener('click', search);
  controls.filter.addEventListener('keydown', event => { if (event.key === 'Escape') { event.preventDefault(); closeSearch(); } });
  element('timestamps').addEventListener('change', event => { root.dataset.timestamps = String(event.target.checked); });
  element('forget').addEventListener('click', () => { history.length = 0; historyIndex = null; draft = ''; notice('Command history forgotten.'); });
  async function initialize(force = false) {
    if (checking || initialized && !force) return;
    checking = true; renderControls();
    try {
      const response = await fetch('/api/native-console', {cache: 'no-store'}); const value = await response.json();
      if (!response.ok || !validState(value) || typeof value.available !== 'boolean') throw new TypeError('Native console unavailable');
      available = value.available; session = value.session_id; initialized = true;
      captureState(value);
      if (documentSource !== 'live_capture') notice(available ? '' : value.message, !available);
    } catch (error) { initialized = true; available = false; notice(`${error.message}. Use Check availability to try again.`, true); }
    checking = false; renderControls();
    if (!root.hidden && root.contains(document.activeElement) && controls.source.disabled) focusPrompt();
  }
  element('check').addEventListener('click', () => initialize(true));
  controls.start.addEventListener('click', () => {
    if (documentSource === 'live_capture') {
      const target = controls.target.value;
      if (!selectedDocument() || !liveAvailable || selectedBinding !== liveBinding || !controls['live-consent'].checked) return;
      enqueue('connect_live', {target_id: target, binding_id: liveBinding, confirm_live: true}, value => {
        ++generation; session = value.session_id; documentSource = 'live_capture'; targets(value);
        if ([...controls.target.options].some(option => option.value === target)) controls.target.value = target;
        controls.connection.open = false;
        boundary('Live capture document connected. This console cannot set breakpoints, step, or inspect paused frames.');
        documentStart.reset(); documentStart.refresh(true);
      });
      return;
    }
    if (!controls.url.reportValidity() || !controls.url.value.trim()) return;
    enqueue('start', {url: controls.url.value.trim(), document_start: documentStart.requested()}, value => {
      ++generation; session = value.session_id; documentSource = 'disposable'; targets(value); controls.connection.open = false;
      boundary(documentStart.requested()
        ? 'Disposable experiment connected with document-start scripts permitted. Nothing runs until you arm a rule.'
        : 'Disposable experiment connected. Select a document.');
      documentStart.reset(); documentStart.refresh(true);
    });
  });
  // Re-read the experiment after either outcome: a failed live Stop can leave
  // a set the browser never confirmed it cleared, and that must stay visible.
  controls.stop.addEventListener('click', () => enqueue('stop', {}, () => {
    ++generation; session = null; controls['live-consent'].checked = false;
    if (documentSource === 'live_capture') {
      boundary('Live capture evaluation disconnected. The capture browser stays open.');
      notice('These documents come from the live capture. Select one, explicitly authorize mutation, then connect. Commands can change that captured page. This console cannot set breakpoints, step, or inspect paused frames.');
    } else {
      documentSource = 'disposable'; clearTargets(); boundary('Experiment disconnected. Retained values released.'); notice('Disposable browser and profile removed.');
    }
    documentStart.reset();
  }).then(() => documentStart.refresh(true)));
  controls.refresh.addEventListener('click', () => !session ? refreshLiveDocuments(true) : enqueue('targets', {}, value => { ++generation; targets(value); controls.connection.open = false; boundary('Document listing refreshed. A missing live document requires disconnect and explicit reselection.'); }));
  controls.target.addEventListener('change', () => {
    selectedBinding = liveBinding;
    ++generation; completion.close(); controls['live-consent'].checked = false; renderControls(); controls.target.title = controls.target.selectedOptions[0]?.title || 'Select a document';
    if (controls.target.value) {
      boundary(`Context selected: ${controls.target.selectedOptions[0].textContent}`);
      notice(documentSource === 'live_capture' ? `These documents come from the live capture. Select one, explicitly authorize mutation, then connect. Commands can change that captured page. This console cannot set breakpoints, step, or inspect paused frames.${partialTargets ? ' Document listing is partial.' : ''}` : (partialTargets ? 'Document listing is partial.' : ''));
      if (session) controls.source.focus(); else controls.start.focus();
      poll();
    }
  });
  function appendCommandColors(container, source) { codeViewColor(container, source, {kind: 'javascript'}); }
  function syncInputMirror() {
    const mirror = element('highlight');
    mirror.style.width = `${controls.source.clientWidth}px`;
    mirror.style.height = `${controls.source.clientHeight}px`;
    mirror.scrollTop = controls.source.scrollTop; mirror.scrollLeft = controls.source.scrollLeft;
  }
  function colorInput() {
    const mirror = element('highlight');
    // Coloring costs work per keystroke, so a very long input is shown plain.
    const value = controls.source.value;
    mirror.replaceChildren(); if (value.length > 65536) mirror.append(document.createTextNode(value)); else appendCommandColors(mirror, value);
    // Preserve the last empty line's geometry and native textarea wrapping.
    mirror.append(document.createTextNode('\n')); syncInputMirror();
  }
  function sizeInput() {
    controls.source.style.height = '26px';
    controls.source.style.height = `${Math.min(108, Math.max(26, root.clientHeight - 170), Math.max(26, controls.source.scrollHeight))}px`;
    colorInput();
  }
  new ResizeObserver(() => { if (!root.hidden) sizeInput(); }).observe(root);
  const completion = createNativeConsoleCompletion(controls.source, element('highlight'), root, async query => {
    if (!session || disconnected || !controls.target.value) return null;
    const result = await runtime({operation: 'complete', path: query.path, prefix: query.prefix}, controls.target.value, true);
    if (result?.status !== 'ok' || !Array.isArray(result.items)) return null;
    return result.items.filter(item => typeof item.name === 'string' && /^[A-Za-z_$][\w$]*$/.test(item.name) && ['property', 'function'].includes(item.kind));
  });
  controls.source.addEventListener('scroll', syncInputMirror); new ResizeObserver(syncInputMirror).observe(controls.source);
  controls.source.addEventListener('input', () => { historyIndex = null; sizeInput(); renderControls(); });
  controls.clear.addEventListener('click', async () => {
    if (submitting || pending) return;
    // Clear invalidates delayed transcript replies, not the native execution
    // context. Queued/new explicit commands retain their document ownership.
    ++outputGeneration;
    transcript.clear(); updateOutputState();
    if (session && controls.target.value && !disconnected) await runtime({operation: 'clear'});
    if (!disconnected) notice('');
    renderControls();
  });
  const snippets = [];
  function saveSnippet(source) {
    if (!snippets.includes(source)) snippets.push(source);
    const select = element('snippets'); select.replaceChildren();
    snippets.forEach((text, index) => { const option = document.createElement('option'); option.value = index; option.textContent = text.split('\n')[0].slice(0, 64); select.append(option); });
    select.disabled = !snippets.length; notice('Snippet saved in this app session.');
  }
  element('load-snippet').addEventListener('click', () => { const source = snippets[Number(element('snippets').value)]; if (source != null) { controls.source.value = source; sizeInput(); renderControls(); controls.connection.open = false; controls.source.focus(); } });
  // Every command stays recallable, whole, until Forget history.
  function remember(source) {
    if (history.at(-1) !== source) history.push(source);
  }
  controls.form.addEventListener('submit', async event => {
    event.preventDefault(); if (submitting || pending || !session || disconnected || !selectedDocument()) return;
    const source = controls.source.value;
    if (!source.trim()) { notice('Enter JavaScript to run.', true); return; }
    if (recordBytes({operation: 'evaluate', source}) > recordLimit) { notice('A command can be at most 4 GiB, counting its JSON escapes. Nothing ran.', true); return; }
    const helper = source.trim().match(/^(copy|inspect|getEventListeners|monitorEvents|unmonitorEvents)\(([\s\S]*)\)\s*;?$/);
    if (helper && !helper[2].trim()) { notice('Enter an expression inside the console utility.', true); return; }
    submitting = true; renderControls();
    completion.close(); historyIndex = null; remember(source); notice(partialTargets ? 'Document listing is partial.' : '');
    const scope = {session, generation, command: ++commandNumber, target: controls.target.value, url: controls.target.selectedOptions[0]?.dataset.url || '', live: documentSource === 'live_capture'};
    controls.source.value = ''; sizeInput(); controls.source.focus();
    const commandRow = document.createElement('article'); commandRow.className = 'native-console-result native-console-command'; commandRow.dataset.level = 'result'; commandRow.dataset.commandId = scope.command; commandRow.dataset.commandNumber = scope.command; commandRow.dataset.consoleSession = scope.session; commandRow.dataset.consoleDocument = scope.target;
    const commandStatus = document.createElement('span'); commandStatus.className = 'native-console-command-status'; commandStatus.textContent = `#${scope.command} · Running`; commandStatus.setAttribute('role', 'status'); commandRow.append(commandStatus);
    const expression = document.createElement('pre'); expression.className = 'native-console-expression'; expression.append(document.createTextNode('> ')); appendCommandColors(expression, source); commandRow.append(expression);
    transcript.add({node: commandRow});
    try {
      const value = await runtime({operation: 'evaluate', source: helper ? helper[2] : source}, scope.target, false, scope.session, scope.generation);
      if (value) {
        commandStatus.textContent = `#${scope.command} · ${value.status === 'ok' ? 'Complete' : value.status === 'stopped' ? 'Stopped' : value.status}`;
        commandRow.dataset.requestId = value.request_id || '';
        commandRow.dataset.level = value.status === 'ok' ? 'result' : 'error';
        await poll();
        if (helper && value.status === 'ok') {
          const kind = helper[1];
          if (kind === 'copy' && value.value) await copyValue(value.value, scope);
          if (kind === 'inspect' && value.value?.location) {
            const detail = {...value.value.location, unavailable: false, live: documentSource === 'live_capture'}; document.dispatchEvent(new CustomEvent('reb-console-location', {detail}));
          }
          if (value.value?.handle && ['getEventListeners', 'monitorEvents', 'unmonitorEvents'].includes(kind)) {
            const reply = await runtime({operation: kind === 'getEventListeners' ? 'listeners' : kind === 'monitorEvents' ? 'monitor' : 'unmonitor', handle: value.value.handle}, scope.target, false, scope.session, scope.generation);
            if (reply?.properties) {
              const row = result(value, source, scope); const output = document.createElement('div'); output.className = 'native-console-properties';
              for (const property of reply.properties) { const item = document.createElement('div'); item.className = 'native-console-property'; item.append(document.createTextNode(property.name + ': ')); renderValue(item, property.value, scope); output.append(item); }
              row.append(output); changedRow(row);
            } else result({status: reply?.status || 'error', text: reply?.text || 'Utility unavailable'}, source, scope);
          } else { const row = result(value, source, scope); if (kind === 'inspect' && value.value?.handle) { const object = row.querySelector('.native-console-object'); if (object) object.open = true; } }
        } else result(value, source, scope);
      } else {
        commandStatus.textContent = `#${scope.command} · Outcome unavailable`;
        commandRow.dataset.level = 'error';
        const failure = document.createElement('p'); failure.className = 'native-console-command-failure'; failure.textContent = 'No confirmed result. The command may have changed page state. It was not retried.'; commandRow.append(failure);
      }
    } catch (error) {
      commandStatus.textContent = `#${scope.command} · Result unavailable`;
      commandRow.dataset.level = 'error'; notice(`${error.message}. The command was not retried.`, true);
    } finally { submitting = false; changedRow(commandRow); renderControls(); }
  });
  function incomplete(source) {
    const tokens = sourcePrettyTokens(source, 'javascript');
    const stack = [];
    for (const token of tokens) {
      if (token.kind !== 'operator') continue;
      for (const char of token.text) {
        if ('([{'.includes(char)) stack.push(char);
        else if (')]}'.includes(char) && stack.at(-1) === '([{'[')]}'.indexOf(char)]) stack.pop();
      }
    }
    return stack.length > 0;
  }
  controls.source.addEventListener('keydown', event => {
    if (event.isComposing) return;
    if (completion.keydown(event)) return;
    if (event.key === 'Enter' && !event.shiftKey) {
      if (!event.metaKey && !event.ctrlKey && incomplete(controls.source.value)) return;
      event.preventDefault(); controls.form.requestSubmit(); return;
    }
    if (event.shiftKey || event.metaKey || event.ctrlKey || event.altKey || !['ArrowUp', 'ArrowDown'].includes(event.key) || controls.source.selectionStart !== controls.source.selectionEnd) return;
    const caret = controls.source.selectionStart, source = controls.source.value;
    // History only takes over on the first/last visual line, including after
    // recall. Interior arrow presses remain normal textarea cursor movement.
    if (event.key === 'ArrowUp' && source.slice(0, caret).includes('\n') || event.key === 'ArrowDown' && source.slice(caret).includes('\n')) return;
    if (historyIndex === null && (event.key !== 'ArrowUp' || caret !== 0 && caret !== source.length)) return;
    if (!history.length) return;
    event.preventDefault();
    if (historyIndex === null) { draft = source; historyIndex = history.length; }
    historyIndex = Math.max(0, Math.min(history.length, historyIndex + (event.key === 'ArrowUp' ? -1 : 1)));
    controls.source.value = historyIndex === history.length ? draft : history[historyIndex];
    controls.source.setSelectionRange(controls.source.value.length, controls.source.value.length);
    if (historyIndex === history.length) historyIndex = null;
    sizeInput(); renderControls();
  });
  function positionConnection() {
    if (!controls.connection.open) return;
    const panel = root.getBoundingClientRect(), summary = controls.connection.querySelector('summary').getBoundingClientRect();
    const menu = controls.connection.querySelector('.native-console-connection-body');
    menu.style.maxHeight = `${Math.max(80, panel.bottom - summary.bottom - 10)}px`;
    menu.style.width = `${Math.min(350, panel.width - 16)}px`;
    menu.style.right = `${summary.right - panel.right + 8}px`;
  }
  controls.connection.addEventListener('toggle', positionConnection);
  new ResizeObserver(positionConnection).observe(root);
  function focusPrompt() {
    if (checking) { controls.connection.querySelector('summary').focus(); return; }
    // While the unavailable empty state is showing, it already explains the gap
    // and offers Check availability; covering it with the settings repeats both.
    // Transcript rows hide that state, and a live document needs the settings
    // to pick it, so those cases still open them.
    if (!session && !available && !liveAvailable && documentSource !== 'live_capture' && !element('empty').hidden) { element('empty-action').focus(); return; }
    if (!session || controls.target.disabled && controls.source.disabled) controls.connection.open = true;
    (session ? controls.source.disabled ? controls.target.disabled ? controls.refresh : controls.target : controls.source : documentSource === 'live_capture' ? (controls.target.value ? controls.start : controls.target) : available ? controls.url : element('check')).focus();
  }
  function setOpen(open) {
    root.hidden = !open; document.querySelector('#workspace').dataset.consoleOpen = String(open);
    toggle.setAttribute('aria-expanded', String(open)); toggle.setAttribute('aria-pressed', String(open));
    if (open) { sizeInput(); initialize(); transcript.layout(); focusPrompt(); poll(); }
    else { completion.close(); controls.connection.open = false; toggle.focus(); }
  }
  toggle.addEventListener('click', () => setOpen(root.hidden)); element('close').addEventListener('click', () => setOpen(false));
  document.addEventListener('pointerdown', event => { if (!controls.connection.contains(event.target)) controls.connection.open = false; });
  root.addEventListener('keydown', event => {
    if (event.key.toLowerCase() === 'f' && (event.metaKey || event.ctrlKey)) { event.preventDefault(); event.stopPropagation(); search(); }
    if (event.key === 'Escape' && controls.connection.open) { event.preventDefault(); event.stopPropagation(); controls.connection.open = false; controls.connection.querySelector('summary').focus(); }
  });
  document.addEventListener('keydown', event => {
    if (event.key.toLowerCase() === 'j' && (event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey) { event.preventDefault(); setOpen(root.hidden); }
  });
  new MutationObserver(() => { if (!root.hidden) initialize(); }).observe(root, {attributes: true, attributeFilter: ['hidden']});
  // The debugger sidebar arms watch rules only through this connection: the
  // live capture document selected and confirmed here, through the same
  // queue, never retried (debugger_sidebar.js).
  globalThis.RebNativeConsole = Object.freeze({
    liveDocument() {
      if (!session || disconnected || documentSource !== 'live_capture' || !selectedDocument()) return null;
      return {session_id: session, target_id: controls.target.value, label: controls.target.selectedOptions[0]?.textContent ?? ''};
    },
    // keep also keeps the rules for later documents of this document's origin
    // and frame kind (protocol/native-debugger-observation-v1.md).
    watch(rules, keep = false) {
      if (!this.liveDocument()) return Promise.resolve({status: 'error', text: 'No live Console connection to a selected document'});
      return runtime(rules ? {operation: 'watch', rules, ...(keep ? {keep: true} : {})} : {operation: 'unwatch'});
    },
    // The command, or else the result, of one evaluation request, opened and
    // scrolled into view; null when the transcript no longer holds it.
    reveal(request, session_id, target_id) {
      const rows = transcript.find(row => row.dataset.requestId === request && row.dataset.consoleSession === session_id && row.dataset.consoleDocument === target_id);
      const entry = rows.find(entry => entry.node.matches('.native-console-command')) ?? rows[0];
      if (!entry) return null;
      if (root.hidden) setOpen(true);
      return transcript.reveal(entry);
    }
  });
  renderControls();
})();
