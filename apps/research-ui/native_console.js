(() => {
  const root = document.querySelector('#native-console-panel');
  const element = name => document.querySelector(`#native-console-${name}`);
  const controls = Object.fromEntries(['url', 'start', 'stop', 'notice', 'target', 'refresh', 'clear', 'output', 'scroll', 'connection', 'form', 'source', 'run', 'filter', 'level'].map(name => [name, element(name)]));
  const toggle = element('toggle');
  const encoder = new TextEncoder();
  const history = [];
  let historyIndex = null, draft = '', historyBytes = 0;
  let session = null, available = false, pending = 0, disconnected = false, initialized = false;
  let outputBytes = 0, removed = 0, partialTargets = false;
  let queue = Promise.resolve(), generation = 0, pollRunning = false;
  const numberId = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n;
  const validState = value => value?.contract_version === 2 && ['ready', 'idle'].includes(value.state) &&
    (value.state === 'ready' ? numberId(value.session_id) : value.session_id === null);
  const types = ['undefined', 'null', 'boolean', 'number', 'string', 'bigint', 'symbol', 'function', 'object', 'promise', 'accessor'];
  function notice(message, error = false) {
    controls.notice.textContent = message; controls.notice.title = message;
    controls.notice.dataset.kind = error ? 'error' : 'status'; controls.notice.hidden = !message;
  }
  function renderControls() {
    root.dataset.session = session ? 'ready' : 'idle';
    const status = pending ? 'working' : session ? disconnected ? 'disconnected' : 'connected' : initialized && !available ? 'unavailable' : 'idle';
    const badge = element('badge'); badge.textContent = status; badge.dataset.state = status;
    controls.connection.querySelector('summary').setAttribute('aria-label', `Console connection: ${status}. Session settings`);
    controls.start.disabled = !!pending || !available || !!session;
    controls.stop.disabled = !!pending || !session; controls.refresh.disabled = !!pending || !session;
    controls.target.disabled = !!pending || !session || controls.target.options.length <= 1;
    controls.url.disabled = !!pending || !!session;
    // Keep the next draft editable while a command is running. Submission stays
    // explicit and serialized; a delayed reply never replaces the next draft.
    controls.source.disabled = disconnected || !session || !controls.target.value;
    controls.run.disabled = !!pending || controls.source.disabled || !controls.source.value.trim();
  }
  function clearTargets() {
    const option = document.createElement('option'); option.value = ''; option.textContent = 'Select a document';
    controls.target.replaceChildren(option); controls.target.title = 'Select a document';
  }
  async function request(action, fields = {}, identity = session) {
    const response = await fetch('/api/native-console/actions', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, cache: 'no-store',
      body: JSON.stringify({action, ...(action === 'start' ? {} : {session_id: identity}), ...fields})
    });
    const value = await response.json();
    if (!response.ok) throw new Error(typeof value.error === 'string' ? value.error : `Console returned ${response.status}`);
    if (!validState(value) || value.state !== (action === 'stop' ? 'idle' : 'ready') ||
        !['start', 'stop'].includes(action) && value.session_id !== identity) throw new TypeError('Malformed native console response');
    return value;
  }
  function enqueue(action, fields, apply, {quiet = false, context = false} = {}) {
    const identity = session, target = controls.target.value, epoch = generation;
    const execute = async () => {
      if (epoch !== generation || context && (!identity || identity !== session || target !== controls.target.value)) return null;
      if (!quiet) { ++pending; renderControls(); }
      try {
        const value = await request(action, fields, identity);
        if (epoch !== generation) return null;
        disconnected = false; return apply ? apply(value) : value;
      } catch (error) {
        if (epoch === generation) { clearTargets(); disconnected = true; notice(`${error.message}. Commands are never retried automatically.`, true); }
        return null;
      } finally { if (!quiet) { --pending; renderControls(); } }
    };
    const result = queue.then(execute); queue = result.catch(() => {}); return result;
  }
  function runtime(command, target = controls.target.value, quiet = false, identity = session) {
    if (identity !== session) return Promise.resolve({status: 'error', text: 'This value belongs to a disconnected console session.'});
    if (!target || target !== controls.target.value) return Promise.resolve({status: 'error', text: 'Select the original document to inspect this value.'});
    return enqueue('runtime', {target_id: target, command}, value => {
      if (!value.runtime) {
        if (value.status === 'stale_target') { boundary('Document changed. Refresh and select the current document.'); clearTargets(); renderControls(); }
        return {status: value.status || 'error', text: value.text || 'Runtime response unavailable'};
      }
      const result = value.runtime;
      if (!['ok', 'error', 'exception', 'pending', 'rejected'].includes(result.status)) throw new TypeError('Malformed runtime status');
      result.request_id = value.request_id;
      return result;
    }, {quiet, context: true});
  }
  function targets(value) {
    if (!Array.isArray(value.targets) || value.targets.length > 64 || typeof value.truncated !== 'boolean' || value.targets.some(target =>
      !numberId(target.id) || typeof target.origin !== 'string' || encoder.encode(target.origin).length > 256 ||
      typeof target.label !== 'string' || encoder.encode(target.label).length > 128 || typeof target.url !== 'string' || encoder.encode(target.url).length > 512 ||
      typeof target.main_frame !== 'boolean' || typeof target.truncated !== 'boolean') || new Set(value.targets.map(target => target.id)).size !== value.targets.length) throw new TypeError('Malformed document listing');
    clearTargets(); partialTargets = value.truncated;
    for (const target of value.targets) {
      const option = document.createElement('option'); option.value = target.id;
      option.textContent = `${target.label || `${target.main_frame ? 'top' : 'frame'} #${target.id}`} · ${target.origin}${target.truncated ? '…' : ''}`;
      option.dataset.url = target.url;
      option.title = `${target.label} · ${target.url} · document ${target.id}`; controls.target.append(option);
    }
    notice(value.targets.length ? `Select a document in the disposable browser.${partialTargets ? ' Document listing is partial.' : ''}` : 'No eligible documents yet. Open an HTTP or HTTPS page in the disposable browser, then refresh.');
  }
  function boundRow(row) {
    if (!row?.isConnected) return;
    const previous = Number(row.dataset.bytes || 0);
    const bytes = encoder.encode(row.textContent).length + encoder.encode(row.dataset.command || '').length;
    row.dataset.bytes = bytes; outputBytes += bytes - previous;
    while (controls.output.children.length > 128 || outputBytes > 262144) {
      const oldest = controls.output.firstElementChild;
      outputBytes -= Number(oldest.dataset.bytes || 0); oldest.remove(); ++removed;
    }
    if (removed) notice(`${removed} older entries removed from this bounded output.`);
    filter();
  }
  function appendRow(row) {
    controls.output.querySelector('.native-console-empty')?.remove();
    const follow = controls.scroll.scrollHeight - controls.scroll.scrollTop - controls.scroll.clientHeight < 40;
    controls.output.append(row); boundRow(row);
    if (follow) controls.scroll.scrollTop = controls.scroll.scrollHeight;
  }
  function boundary(text) {
    const row = document.createElement('div'); row.className = 'native-console-boundary'; row.textContent = text; appendRow(row);
  }
  function button(label, action) {
    const control = document.createElement('button'); control.type = 'button'; control.textContent = label;
    control.addEventListener('click', action); return control;
  }
  function location(container, value) {
    if (!value || typeof value.url !== 'string' || value.url.length > 2048 || !Number.isInteger(value.line) || value.line < 1) return;
    const control = button(`${value.url || 'console'}:${value.line}:${value.column || 1}`, () => {
      const detail = {url: value.url, line: value.line, unavailable: false};
      document.dispatchEvent(new CustomEvent('reb-console-location', {detail}));
      if (detail.unavailable) notice(`No source for ${value.url} in this evidence workspace. The console runs in a separate disposable browser.`);
    });
    control.className = 'native-console-location'; control.title = 'Find corresponding source in this evidence workspace'; container.append(control);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); notice('Copied to clipboard.'); }
    catch { notice('Clipboard unavailable. Select the result and use Copy.', true); }
  }
  async function copyValue(value, scope) {
    if (value?.handle && value.type === 'object') {
      const page = await runtime({operation: 'inspect', handle: value.handle, offset: 0}, scope.target, false, scope.session);
      if (page?.status === 'ok') { await copy(JSON.stringify({preview: value.text, properties: page.properties, truncated: page.more}, null, 2)); return; }
    }
    await copy(value?.text || '');
  }
  function checkValue(value) {
    if (!value || !types.includes(value.type) || typeof value.text !== 'string' || encoder.encode(value.text).length > 2048 || typeof value.truncated !== 'boolean' || value.handle != null && !numberId(value.handle)) throw new TypeError('Malformed runtime value');
  }
  function renderValue(container, value, scope, depth = 0) {
    checkValue(value);
    if (value.handle && ['object', 'function', 'promise'].includes(value.type) && depth < 8) {
      const disclosure = document.createElement('details'); disclosure.className = 'native-console-object';
      const summary = document.createElement('summary'); summary.textContent = `${value.text}${value.truncated ? ' …' : ''}`;
      const children = document.createElement('div'); children.className = 'native-console-properties';
      const actions = document.createElement('div'); actions.className = 'native-console-actions';
      let loaded = false, offset = 0, loading = false;
      async function inspect() {
        if (loading) return; loading = true;
        const result = await runtime({operation: 'inspect', handle: value.handle, offset}, scope.target, false, scope.session);
        loading = false;
        if (!disclosure.isConnected || !result) return;
        if (result.status !== 'ok') { children.textContent = result.text || 'Inspection unavailable'; return; }
        if (!Array.isArray(result.properties) || result.properties.length > 17 || typeof result.more !== 'boolean' || !Number.isInteger(result.offset)) { notice('Malformed property page.', true); return; }
        loaded = true;
        for (const property of result.properties) {
          if (typeof property.name !== 'string' || property.name.length > 2048) continue;
          const row = document.createElement('div'); row.className = 'native-console-property';
          const name = document.createElement('span'); name.className = 'native-console-property-name'; name.textContent = `${property.name}: `;
          row.append(name); renderValue(row, property.value, scope, depth + 1); children.append(row);
        }
        offset = result.offset; more.hidden = !result.more;
        if (result.truncated) children.append(document.createTextNode('Property listing limited to first 65536 indices.'));
        const parent = container.closest('.native-console-result'); if (parent) boundRow(parent);
      }
      const more = button('Load next 16 properties', inspect); more.hidden = true;
      actions.append(button('Copy properties', () => copyValue(value, scope)), button('Store as variable', async () => {
        const result = await runtime({operation: 'store', handle: value.handle}, scope.target, false, scope.session);
        if (result) notice(result.status === 'ok' ? `Stored as ${result.text} in the selected page.` : result.text, result.status !== 'ok');
      }), button('Release', async () => {
        const result = await runtime({operation: 'release', handle: value.handle}, scope.target, false, scope.session);
        if (result?.status === 'ok') { children.replaceChildren(); summary.textContent = `${value.text} (released)`; disclosure.open = false; }
      }));
      location(actions, value.location);
      if (value.type === 'function') actions.append(button('Show function source', async () => {
        const result = await runtime({operation: 'source', handle: value.handle}, scope.target, false, scope.session);
        if (result?.text) { const source = document.createElement('pre'); appendCommandColors(source, result.text); children.replaceChildren(source); disclosure.open = true; loaded = true; boundRow(container.closest('article')); }
      }));
      if (value.text.startsWith('<')) actions.append(button('Event listeners', async () => {
        const result = await runtime({operation: 'listeners', handle: value.handle}, scope.target, false, scope.session);
        if (!result) return;
        children.replaceChildren(); loaded = true; disclosure.open = true;
        if (result.status !== 'ok') { children.textContent = result.text; return; }
        if (!result.properties?.length) children.textContent = 'No registered listeners.';
        for (const property of (result.properties || []).slice(0, 32)) {
          const row = document.createElement('div'); row.className = 'native-console-property'; row.append(document.createTextNode(property.name + ': ')); renderValue(row, property.value, scope, depth + 1); children.append(row);
        }
        if (result.truncated) children.append(document.createTextNode('Listener listing truncated at 32.'));
        boundRow(container.closest('article'));
      }), button('Monitor events', async () => { const result = await runtime({operation: 'monitor', handle: value.handle}, scope.target, false, scope.session); if (result) notice(result.text); }),
      button('Stop monitoring', async () => { const result = await runtime({operation: 'unmonitor', handle: value.handle}, scope.target, false, scope.session); if (result) notice(result.text); }));
      disclosure.append(summary, children, more, actions); container.append(disclosure);
      disclosure.addEventListener('toggle', () => { if (disclosure.open && !loaded) inspect(); });
      if (value.type === 'promise') {
        actions.append(button('Await', () => awaitValue(container, value, scope)), button('Stop waiting', async () => { container.dataset.wait = String(Number(container.dataset.wait || 0) + 1); container.dataset.awaiting = 'false'; const result = await runtime({operation: 'cancel', handle: value.handle}, scope.target, false, scope.session); if (result) notice(result.text || 'Stopped waiting; page work continues.'); }));
      }
    } else {
      const output = document.createElement('span'); output.className = 'native-console-primitive'; output.dataset.type = value.type;
      output.textContent = value.type === 'string' ? JSON.stringify(value.text) : value.text; container.append(output);
      if (value.truncated) container.append(document.createTextNode(' … (truncated)'));
    }
  }
  async function awaitValue(container, value, scope, replace = false) {
    if (container.dataset.awaiting === 'true') return;
    const started = Date.now(); const token = generation;
    const wait = String(Number(container.dataset.wait || 0) + 1); container.dataset.wait = wait;
    container.dataset.awaiting = 'true';
    async function tick() {
      if (container.dataset.wait !== wait || !container.isConnected || token !== generation || session !== scope.session || controls.target.value !== scope.target) return;
      const result = await runtime({operation: 'await', handle: value.handle}, scope.target, true, scope.session);
      if (!result || !container.isConnected || container.dataset.wait !== wait || token !== generation || session !== scope.session || controls.target.value !== scope.target) return;
      if (result.status === 'pending' && Date.now() - started < 10000) { setTimeout(tick, 200); return; }
      container.dataset.awaiting = 'false';
      const settled = document.createElement('div'); settled.className = 'native-console-value';
      if (result.value) { renderValue(settled, result.value, scope); const row = container.closest('article'); row.dataset.status = result.status; row.dataset.level = result.status === 'ok' ? 'result' : 'error'; }
      else settled.textContent = result.status === 'pending' ? 'Promise still pending after 10 seconds. Await again or stop waiting.' : result.text || 'Await stopped';
      if (replace && result.value) { container.replaceChildren(); renderValue(container, result.value, scope); }
      else if (replace) container.replaceChildren(settled);
      else { container.querySelector('summary').textContent = result.status === 'rejected' ? 'Promise {<rejected>}' : result.status === 'ok' ? 'Promise {<fulfilled>}' : value.text; container.append(settled); }
      boundRow(container.closest('article'));
    }
    tick();
  }
  function result(value, source, scope) {
    const row = document.createElement('article'); row.className = 'native-console-result'; row.dataset.status = value.status; row.dataset.requestId = value.request_id || '';
    row.dataset.level = value.status === 'ok' ? 'result' : 'error'; row.dataset.command = source;
    const output = document.createElement('div'); output.className = 'native-console-value';
    row.append(output);
    if (value.value) { row.dataset.type = value.value.type; renderValue(output, value.value, scope); }
    else { output.textContent = value.text || value.status; location(row, value.location); }
    if (Array.isArray(value.stack)) for (const frame of value.stack.slice(0, 16)) { const entry = document.createElement('div'); location(entry, frame); row.append(entry); }
    const details = document.createElement('details'); details.className = 'native-console-result-details';
    const summary = document.createElement('summary'); summary.textContent = value.value?.truncated ? 'Truncated' : '⋯'; summary.setAttribute('aria-label', `Result details: ${value.status}`);
    const label = document.createElement('div'); label.className = 'native-console-result-type'; label.textContent = `${value.status} · session ${scope.session} · document ${scope.target} · disposable experiment`;
    label.append(button('Copy result', () => value.value ? copyValue(value.value, scope) : copy(value.text || '')), button('Save snippet', () => saveSnippet(source)), button('Experiment activity', async () => {
      const reply = await runtime({operation: 'traffic'}, scope.target, false, scope.session);
      if (reply?.status === 'ok') document.dispatchEvent(new CustomEvent('reb-console-traffic', {detail: {session: scope.session, target: scope.target, request: value.request_id, events: reply.events || [], dropped: reply.dropped || 0}}));
    })); details.append(summary, label); row.append(details); appendRow(row);
    if (value.value?.type === 'promise' && /^\s*await\b/.test(source)) awaitValue(output, value.value, scope, true);
    return row;
  }
  function logs(value) {
    if (!Array.isArray(value.messages) || value.messages.length > 32 || !Number.isInteger(value.dropped) || value.dropped < 0) throw new TypeError('Malformed console messages');
    if (value.dropped) boundary(`${value.dropped} page messages dropped before delivery.`);
    for (const message of value.messages) {
      if (!['debug', 'info', 'warning', 'error'].includes(message.level) || typeof message.text !== 'string' || message.text.length > 8192) throw new TypeError('Malformed page message');
      const row = document.createElement('article'); row.className = 'native-console-result native-console-log'; row.dataset.level = message.level;
      const time = document.createElement('span'); time.className = 'native-console-time'; time.textContent = new Date(message.time).toLocaleTimeString(); row.append(time);
      const output = document.createElement('pre'); output.textContent = message.text; row.append(output); location(row, message);
      if (message.truncated) row.append(document.createTextNode(' (truncated)'));
      if (message.stack) { const details = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = 'Stack'; const stack = document.createElement('pre'); stack.textContent = message.stack; details.append(summary, stack); row.append(details); }
      appendRow(row);
    }
  }
  async function poll() {
    if (pollRunning || root.hidden || !session || disconnected || !controls.target.value || pending) return;
    pollRunning = true;
    try { const value = await runtime({operation: 'poll'}, controls.target.value, true); if (value?.status === 'ok') logs(value); }
    finally { pollRunning = false; }
  }
  setInterval(poll, 500);
  function filter() {
    const query = controls.filter.value.toLocaleLowerCase(), level = controls.level.value;
    for (const row of controls.output.children) row.hidden = !!query && !(row.textContent + (row.dataset.command || '')).toLocaleLowerCase().includes(query) || level !== 'all' && row.dataset.level !== level;
  }
  controls.filter.addEventListener('input', filter); controls.level.addEventListener('change', filter);
  function search() { element('filter-row').hidden = false; controls.filter.focus(); controls.filter.select(); }
  element('search').addEventListener('click', search);
  controls.filter.addEventListener('keydown', event => { if (event.key === 'Escape') { event.preventDefault(); controls.filter.value = ''; controls.level.value = 'all'; filter(); element('filter-row').hidden = true; controls.source.focus(); } });
  element('timestamps').addEventListener('change', event => { root.dataset.timestamps = String(event.target.checked); });
  element('forget').addEventListener('click', () => { history.length = 0; historyBytes = 0; historyIndex = null; draft = ''; notice('Command history forgotten.'); });
  async function initialize() {
    if (initialized) return;
    try {
      const response = await fetch('/api/native-console', {cache: 'no-store'}); const value = await response.json();
      if (!response.ok || !validState(value) || typeof value.available !== 'boolean') throw new TypeError('Native console unavailable');
      available = value.available; session = value.session_id; initialized = true; notice(available ? '' : value.message, !available);
    } catch (error) { notice(error.message, true); }
    renderControls(); focusPrompt();
  }
  controls.start.addEventListener('click', () => {
    if (!controls.url.reportValidity() || !controls.url.value.trim()) return;
    enqueue('start', {url: controls.url.value.trim()}, value => { ++generation; session = value.session_id; targets(value); controls.connection.open = false; boundary('Disposable experiment connected. Select a document.'); });
  });
  controls.stop.addEventListener('click', () => enqueue('stop', {}, () => { ++generation; session = null; clearTargets(); boundary('Experiment disconnected. Retained values released.'); notice('Disposable browser and profile removed.'); }));
  controls.refresh.addEventListener('click', () => enqueue('targets', {}, value => { ++generation; targets(value); controls.connection.open = false; boundary('Document listing refreshed. Select the current execution context.'); }));
  controls.target.addEventListener('change', () => {
    ++generation; completion.close(); renderControls(); controls.target.title = controls.target.selectedOptions[0]?.title || 'Select a document';
    if (controls.target.value) { boundary(`Context selected: ${controls.target.selectedOptions[0].textContent}`); notice(partialTargets ? 'Document listing is partial.' : ''); controls.source.focus(); poll(); }
  });
  function appendCommandColors(container, source) {
    const tokenizer = createSourceTokenizer({kind: 'javascript'});
    tokenizer.coloredTokens = SOURCE_HIGHLIGHT_TOKEN_LIMIT - 1024;
    const fragment = document.createDocumentFragment();
    let plain = '';
    const flush = () => { if (plain) fragment.append(document.createTextNode(plain)); plain = ''; };
    source.slice(0, 8192).split('\n').forEach((line, index) => {
      if (index) plain += '\n';
      if (!line) return;
      for (const token of sourceSyntaxTokens(line, tokenizer)) {
        if (token.type === 'plain') plain += token.text;
        else {
          flush();
          const span = document.createElement('span'); span.className = `syntax-${token.type}`;
          span.textContent = token.text; fragment.append(span);
        }
      }
    });
    plain += source.slice(8192); flush(); container.append(fragment);
  }
  function syncInputMirror() {
    const mirror = element('highlight');
    mirror.style.width = `${controls.source.clientWidth}px`;
    mirror.style.height = `${controls.source.clientHeight}px`;
    mirror.scrollTop = controls.source.scrollTop; mirror.scrollLeft = controls.source.scrollLeft;
  }
  function colorInput() {
    const mirror = element('highlight');
    mirror.replaceChildren(); appendCommandColors(mirror, controls.source.value);
    // Preserve the last empty line's geometry and native textarea wrapping.
    mirror.append(document.createTextNode('\n')); syncInputMirror();
  }
  function sizeInput() {
    controls.source.style.height = '26px';
    controls.source.style.height = `${Math.min(150, Math.max(26, controls.source.scrollHeight))}px`;
    colorInput();
  }
  const completion = createNativeConsoleCompletion(controls.source, element('highlight'), root, async query => {
    if (!session || disconnected || !controls.target.value) return null;
    const result = await runtime({operation: 'complete', path: query.path, prefix: query.prefix}, controls.target.value, true);
    if (result?.status !== 'ok' || !Array.isArray(result.items) || result.items.length > 24) return null;
    return result.items.filter(item => typeof item.name === 'string' && /^[A-Za-z_$][\w$]{0,127}$/.test(item.name) && ['property', 'function'].includes(item.kind));
  });
  controls.source.addEventListener('scroll', syncInputMirror); new ResizeObserver(syncInputMirror).observe(controls.source);
  controls.source.addEventListener('input', () => { historyIndex = null; sizeInput(); renderControls(); });
  controls.clear.addEventListener('click', async () => {
    const empty = document.createElement('p'); empty.className = 'native-console-empty'; empty.textContent = 'Select a document to begin.'; empty.hidden = !!controls.target.value;
    controls.output.replaceChildren(empty); outputBytes = 0; removed = 0;
    if (session && controls.target.value && !disconnected) await runtime({operation: 'clear'});
    notice('');
  });
  const snippets = [];
  function saveSnippet(source) {
    if (!snippets.includes(source)) snippets.push(source);
    while (snippets.length > 16 || snippets.reduce((bytes, value) => bytes + encoder.encode(value).length, 0) > 65536) snippets.shift();
    const select = element('snippets'); select.replaceChildren();
    snippets.forEach((text, index) => { const option = document.createElement('option'); option.value = index; option.textContent = text.split('\n')[0].slice(0, 64); select.append(option); });
    select.disabled = !snippets.length; notice('Snippet saved in this app session.');
  }
  element('load-snippet').addEventListener('click', () => { const source = snippets[Number(element('snippets').value)]; if (source != null) { controls.source.value = source; sizeInput(); controls.source.focus(); } });
  function remember(source) {
    if (history.at(-1) === source) return;
    history.push(source); historyBytes += encoder.encode(source).length;
    while (history.length > 128 || historyBytes > 262144) historyBytes -= encoder.encode(history.shift()).length;
  }
  controls.form.addEventListener('submit', async event => {
    event.preventDefault(); if (pending || !session || disconnected || !controls.target.value) return;
    const source = controls.source.value;
    if (!source.trim() || encoder.encode(source).length > 8192) { notice('Enter 1 to 8192 UTF-8 bytes of JavaScript.', true); return; }
    const helper = source.trim().match(/^(copy|inspect|getEventListeners|monitorEvents|unmonitorEvents)\(([\s\S]*)\)\s*;?$/);
    if (helper && !helper[2].trim()) { notice('Enter an expression inside the console utility.', true); return; }
    completion.close(); historyIndex = null; remember(source); notice(partialTargets ? 'Document listing is partial.' : '');
    const scope = {session, target: controls.target.value, url: controls.target.selectedOptions[0]?.dataset.url || ''};
    controls.source.value = ''; sizeInput();
    const commandRow = document.createElement('article'); commandRow.className = 'native-console-result native-console-command'; commandRow.dataset.level = 'result';
    const expression = document.createElement('pre'); expression.className = 'native-console-expression'; expression.append(document.createTextNode('> ')); appendCommandColors(expression, source); commandRow.append(expression); appendRow(commandRow);
    const value = await runtime({operation: 'evaluate', source: helper ? helper[2] : source}, scope.target, false, scope.session);
    if (value) {
      commandRow.dataset.requestId = value.request_id || '';
      commandRow.dataset.level = value.status === 'ok' ? 'result' : 'error';
      await poll();
      if (helper && value.status === 'ok') {
        const kind = helper[1];
        if (kind === 'copy' && value.value) await copyValue(value.value, scope);
        if (kind === 'inspect' && value.value?.location) {
          const detail = {...value.value.location, unavailable: false}; document.dispatchEvent(new CustomEvent('reb-console-location', {detail}));
        }
        if (value.value?.handle && ['getEventListeners', 'monitorEvents', 'unmonitorEvents'].includes(kind)) {
          const reply = await runtime({operation: kind === 'getEventListeners' ? 'listeners' : kind === 'monitorEvents' ? 'monitor' : 'unmonitor', handle: value.value.handle}, scope.target, false, scope.session);
          if (reply?.properties) {
            const row = result(value, source, scope); const output = document.createElement('div'); output.className = 'native-console-properties';
            for (const property of reply.properties.slice(0, 32)) { const item = document.createElement('div'); item.className = 'native-console-property'; item.append(document.createTextNode(property.name + ': ')); renderValue(item, property.value, scope); output.append(item); }
            row.append(output); boundRow(row);
          } else result({status: reply?.status || 'error', text: reply?.text || 'Utility unavailable'}, source, scope);
        } else { const row = result(value, source, scope); if (kind === 'inspect' && value.value?.handle) { const object = row.querySelector('.native-console-object'); if (object) object.open = true; } }
      } else result(value, source, scope);
    }
    renderControls();
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
  function focusPrompt() {
    if (!session) controls.connection.open = true;
    (session ? controls.source.disabled ? controls.target.disabled ? controls.refresh : controls.target : controls.source : controls.url).focus();
  }
  function setOpen(open) {
    root.hidden = !open; document.querySelector('#workspace').dataset.consoleOpen = String(open);
    toggle.setAttribute('aria-expanded', String(open)); toggle.setAttribute('aria-pressed', String(open));
    if (open) { sizeInput(); initialize(); focusPrompt(); poll(); }
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
  renderControls();
})();
