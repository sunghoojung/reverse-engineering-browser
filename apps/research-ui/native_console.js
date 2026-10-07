(() => {
  const root = document.querySelector('#native-console-panel');
  const element = name => document.querySelector(`#native-console-${name}`);
  const controls = Object.fromEntries(['url', 'start', 'stop', 'notice', 'target', 'refresh', 'clear', 'output', 'scroll', 'connection', 'form', 'source', 'run', 'filter', 'level'].map(name => [name, element(name)]));
  const toggle = element('toggle');
  const encoder = new TextEncoder();
  const history = [];
  let historyIndex = null, draft = '', historyBytes = 0;
  let session = null, available = false, pending = 0, disconnected = false, initialized = false;
  let outputBytes = 0, outputNodes = 0, removed = 0, partialTargets = false, outputGeneration = 0;
  let queue = Promise.resolve(), generation = 0, pollRunning = false;
  let checking = false, submitting = false, commandNumber = 0, unread = 0;
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
    const busy = pending || submitting;
    const status = checking ? 'checking' : disconnected ? 'disconnected' : busy ? 'working' : session ? 'connected' : initialized && !available ? 'unavailable' : 'idle';
    const badge = element('badge'); badge.textContent = {checking: 'Checking', disconnected: 'Connection lost', working: 'Working', connected: 'Connected', unavailable: 'Unavailable', idle: 'Connect'}[status]; badge.dataset.state = status;
    controls.connection.querySelector('summary').setAttribute('aria-label', `Console connection: ${status}. Session settings`);
    controls.start.disabled = !!busy || checking || !available || !!session;
    controls.clear.disabled = !!busy;
    controls.stop.disabled = !!busy || !session; controls.refresh.disabled = !!busy || !session;
    controls.target.disabled = !!busy || !session || controls.target.options.length <= 1;
    controls.url.disabled = !!busy || checking || !!session;
    element('check').hidden = !!session || available; element('check').disabled = checking;
    // The next draft stays editable. Only explicit submission is serialized.
    controls.source.disabled = disconnected || !session || !controls.target.value;
    controls.run.disabled = !!busy || controls.source.disabled || !controls.source.value.trim();
    controls.run.textContent = submitting ? 'Running…' : 'Run';
    element('composer-status').textContent = submitting ? 'Running · next draft stays editable' : disconnected ? 'Connection lost · refresh documents to recover' : !session ? 'Connect a disposable browser to begin' : !controls.target.value ? 'Select the document to execute in' : `Document ${controls.target.value} · ${encoder.encode(controls.source.value).length} / 8192 bytes`;
    const emptyTitle = element('empty-title'), emptyText = element('empty-text'), emptyAction = element('empty-action');
    emptyTitle.textContent = checking ? 'Checking native Console' : disconnected ? 'Connection interrupted' : !available && initialized ? 'Native Console unavailable' : !session ? 'Connect a disposable browser' : !controls.target.value ? 'Choose an execution document' : 'Ready for your first command';
    emptyText.textContent = disconnected ? 'Your output and draft are preserved. Refresh the document list before continuing; commands are never retried.' : !available && initialized ? 'A rebuilt custom Brave and live backend are required. Check availability after they are ready.' : !session ? 'Enter an authorized page in Session settings. Commands run in a separate disposable profile.' : !controls.target.value ? 'Select a document above. If the page just opened or navigated, refresh the document list.' : 'Enter an expression below. Expand returned objects to inspect bounded native properties; getters remain unevaluated.';
    emptyAction.textContent = checking ? 'Checking…' : !session ? available ? 'Session settings' : 'Check availability' : !controls.target.value ? 'Refresh documents' : 'Focus command';
    emptyAction.disabled = checking || !!busy;
    updateOutputState();
  }
  function updateOutputState() {
    const rows = [...controls.output.children], visible = rows.filter(row => !row.hidden).length;
    element('empty').hidden = !!rows.length;
    element('no-matches').hidden = !rows.length || !!visible;
    element('output-count').textContent = `${visible === rows.length ? rows.length : `${visible} / ${rows.length}`} entries${removed ? ` · ${removed} older removed` : ''}`;
    element('latest').hidden = !rows.length || atBottom();
    element('latest').textContent = unread ? `${unread} new · Latest ↓` : 'Latest output ↓';
  }
  function atBottom() { return controls.scroll.scrollHeight - controls.scroll.scrollTop - controls.scroll.clientHeight < 40; }
  function followLatest() { controls.scroll.scrollTop = controls.scroll.scrollHeight; unread = 0; updateOutputState(); }
  controls.scroll.addEventListener('scroll', () => { if (atBottom()) unread = 0; updateOutputState(); });
  element('latest').addEventListener('click', followLatest);
  element('empty-action').addEventListener('click', () => {
    if (!session) { if (!available) initialize(true); else { controls.connection.open = true; controls.url.focus(); } }
    else if (!controls.target.value) controls.refresh.click();
    else controls.source.focus();
  });
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
        if (epoch === generation) { clearTargets(); disconnected = true; notice(`${error.message}. Commands are never retried automatically.`, true); renderControls(); }
        return null;
      } finally { if (!quiet) { --pending; renderControls(); } }
    };
    const result = queue.then(execute); queue = result.catch(() => {}); return result;
  }
  function runtime(command, target = controls.target.value, quiet = false, identity = session, epoch = generation) {
    if (epoch !== generation) return Promise.resolve({status: 'error', text: 'This value belongs to an earlier document selection. Run a new command to inspect a current value.'});
    if (identity !== session) return Promise.resolve({status: 'error', text: 'This value belongs to a disconnected console session.'});
    if (!target || target !== controls.target.value) return Promise.resolve({status: 'error', text: 'Select the original document to inspect this value.'});
    return enqueue('runtime', {target_id: target, command}, value => {
      if (!value.runtime) {
        if (value.status === 'stale_target') { boundary('Document changed. Refresh and select the current document.'); clearTargets(); renderControls(); }
        return {status: value.status || 'error', text: value.text || 'Runtime response unavailable', request_id: value.request_id};
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
    const nodes = row.querySelectorAll('*').length + 1; outputNodes += nodes - Number(row.dataset.nodes || 0); row.dataset.nodes = nodes;
    while (controls.output.children.length > 128 || outputBytes > 262144 || outputNodes > 8192) {
      const oldest = controls.output.firstElementChild;
      outputBytes -= Number(oldest.dataset.bytes || 0); outputNodes -= Number(oldest.dataset.nodes || 0); oldest.remove(); ++removed;
    }
    // Eviction stays in the transcript footer, never replacing a transport error.
    filter();
  }
  function appendRow(row) {
    const follow = atBottom();
    const anchor = [...controls.output.children].find(child => child.getBoundingClientRect().bottom >= controls.scroll.getBoundingClientRect().top);
    const top = anchor?.getBoundingClientRect().top;
    controls.output.append(row); boundRow(row);
    if (follow) followLatest();
    else {
      ++unread;
      if (anchor?.isConnected) controls.scroll.scrollTop += anchor.getBoundingClientRect().top - top;
      updateOutputState();
    }
  }
  function boundary(text) {
    const row = document.createElement('div'); row.className = 'native-console-boundary'; row.textContent = text; appendRow(row);
  }
  function button(label, action) {
    const control = document.createElement('button'); control.type = 'button'; control.textContent = label;
    control.addEventListener('click', async event => {
      try { await action(event); }
      catch (error) { notice(`${error.message}. The action was not retried.`, true); }
    }); return control;
  }
  function location(container, value) {
    if (!value || typeof value.url !== 'string' || value.url.length > 2048 || !Number.isInteger(value.line) || value.line < 1) return;
    const control = button(`${value.url || 'console'}:${value.line}:${value.column || 1}`, () => {
      const detail = {url: value.url, line: value.line, unavailable: false};
      document.dispatchEvent(new CustomEvent('reb-console-location', {detail}));
      if (detail.unavailable) notice(`No source for ${value.url} in this evidence workspace. The console runs in a separate disposable browser.`);
    });
    control.className = 'native-console-location'; control.title = 'Search captured sources by URL; this disposable browser is a separate context'; control.setAttribute('aria-label', `Search captured sources by URL: ${value.url}, line ${value.line}`); container.append(control);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); notice('Copied to clipboard.'); }
    catch { notice('Clipboard unavailable. Select the result and use Copy.', true); }
  }
  async function copyValue(value, scope) {
    if (value?.handle && value.type === 'object') {
      const page = await runtime({operation: 'inspect', handle: value.handle, offset: 0}, scope.target, false, scope.session, scope.generation);
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
          if (!Array.isArray(result.properties) || result.properties.length > 17 || typeof result.more !== 'boolean' || !Number.isInteger(result.offset) || result.offset < 0 || result.offset > Math.min(65536, pageOffset + 16) || result.more && result.offset <= pageOffset || result.offset < pageOffset && (result.more || result.properties.length !== 0)) throw new TypeError('Malformed property page.');
          const fragment = document.createDocumentFragment();
          for (const property of result.properties) {
            if (typeof property.name !== 'string' || property.name.length > 2048) throw new TypeError('Malformed property name.');
            checkValue(property.value);
            const row = document.createElement('div'); row.className = 'native-console-property';
            const name = document.createElement('span'); name.className = 'native-console-property-name'; name.textContent = `${property.name}: `;
            row.append(name); renderValue(row, property.value, scope, depth + 1); fragment.append(row);
          }
          // Replace one property page. Navigating a large object never grows a
          // permanent list or retains detached child pages and their handles.
          children.replaceChildren(fragment); loaded = true; offset = pageOffset; nextOffset = result.offset; moreAvailable = result.more;
          // Native enumeration uses min(live length, requested offset + 16).
          // A live object can shrink below a previously available page.
          pageUnavailable = pageOffset > 0 && !result.more && result.properties.length === 0 && result.offset <= pageOffset;
          previous.textContent = pageUnavailable ? 'First properties' : 'Previous properties';
          retry.textContent = pageUnavailable ? 'Reload this page' : 'Retry inspection'; retry.hidden = !pageUnavailable;
          status.textContent = pageUnavailable ? `This page is no longer available (${result.offset} properties remain). Return to the first page or reload this page if the object changes.` : result.properties.length ? `Properties ${pageOffset + 1}–${result.offset || result.properties.length}${pageOffset === 0 && result.properties.some(property => property.name === '[[Prototype]]') ? ' + prototype' : ''}${result.truncated ? ' · limited to first 65536 indices' : ''}` : 'No inspectable properties.';
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
          boundRow(container.closest('.native-console-result'));
        }
      }
      actions.append(button('Copy properties', () => copyValue(value, scope)), button('Store as variable', async () => {
        const result = await runtime({operation: 'store', handle: value.handle}, scope.target, false, scope.session, scope.generation);
        if (result) notice(result.status === 'ok' ? `Stored as ${result.text} in the selected page.` : result.text, result.status !== 'ok');
      }), button('Release', async () => {
        const result = await runtime({operation: 'release', handle: value.handle}, scope.target, false, scope.session, scope.generation);
        if (result?.status === 'ok') { released = true; loaded = true; children.replaceChildren(); summary.textContent = `${value.text} (released)`; status.textContent = 'Value released. Run a new command to inspect it again.'; pager.hidden = true; actionDetails.hidden = true; boundRow(container.closest('article')); }
      }));
      location(actions, value.location);
      if (value.type === 'function') actions.append(button('Show function source', async () => {
        const result = await runtime({operation: 'source', handle: value.handle}, scope.target, false, scope.session, scope.generation);
        if (result?.text && disclosure.isConnected) { pager.hidden = true; status.textContent = result.status === 'ok' ? 'Native function source' : 'Source unavailable'; const source = document.createElement('pre'); appendCommandColors(source, result.text); children.replaceChildren(source); disclosure.open = true; loaded = true; boundRow(container.closest('article')); }
      }));
      if (value.text.startsWith('<')) actions.append(button('Event listeners', async () => {
        const result = await runtime({operation: 'listeners', handle: value.handle}, scope.target, false, scope.session, scope.generation);
        if (!result) return;
        children.replaceChildren(); pager.hidden = true; status.textContent = 'Registered event listeners'; loaded = true; disclosure.open = true;
        if (result.status !== 'ok') { children.textContent = result.text; return; }
        if (!result.properties?.length) children.textContent = 'No registered listeners.';
        for (const property of (result.properties || []).slice(0, 32)) {
          const row = document.createElement('div'); row.className = 'native-console-property'; row.append(document.createTextNode(property.name + ': ')); renderValue(row, property.value, scope, depth + 1); children.append(row);
        }
        if (result.truncated) children.append(document.createTextNode('Listener listing truncated at 32.'));
        boundRow(container.closest('article'));
      }), button('Monitor events', async () => { const result = await runtime({operation: 'monitor', handle: value.handle}, scope.target, false, scope.session, scope.generation); if (result) notice(result.text); }),
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
      const result = await runtime({operation: 'await', handle: value.handle}, scope.target, true, scope.session, scope.generation);
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
    row.dataset.level = value.status === 'ok' ? 'result' : 'error'; row.dataset.command = source; row.dataset.commandId = scope.command; row.dataset.commandNumber = scope.command; row.dataset.consoleSession = scope.session; row.dataset.consoleDocument = scope.target;
    row.setAttribute('aria-label', `Result for command ${scope.command}: ${value.status}`);
    const output = document.createElement('div'); output.className = 'native-console-value';
    row.append(output);
    if (value.value) { row.dataset.type = value.value.type; renderValue(output, value.value, scope); }
    else { output.textContent = value.text || value.status; location(row, value.location); }
    if (Array.isArray(value.stack)) for (const frame of value.stack.slice(0, 16)) { const entry = document.createElement('div'); location(entry, frame); row.append(entry); }
    const details = document.createElement('details'); details.className = 'native-console-result-details';
    const summary = document.createElement('summary'); summary.textContent = value.value?.truncated ? 'Truncated' : '⋯'; summary.setAttribute('aria-label', `Result details: ${value.status}`);
    const label = document.createElement('div'); label.className = 'native-console-result-type'; label.textContent = `${value.status} · session ${scope.session} · document ${scope.target} · disposable experiment`;
    label.append(button('Copy result', () => value.value ? copyValue(value.value, scope) : copy(value.text || '')), button('Save snippet', () => saveSnippet(source)), button('Experiment activity', async () => {
      const reply = await runtime({operation: 'traffic'}, scope.target, false, scope.session, scope.generation);
      if (reply?.status === 'ok') document.dispatchEvent(new CustomEvent('reb-console-traffic', {detail: {session: scope.session, target: scope.target, request: value.request_id, events: reply.events || [], dropped: reply.dropped || 0}}));
    })); details.append(summary, label); row.append(details); appendRow(row);
    if (value.value?.type === 'promise' && /^\s*await\b/.test(source)) awaitValue(output, value.value, scope, true);
    return row;
  }
  function logs(value, epoch = outputGeneration) {
    if (!Array.isArray(value.messages) || value.messages.length > 32 || !Number.isInteger(value.dropped) || value.dropped < 0) throw new TypeError('Malformed console messages');
    if (value.messages.some(message => !message || !['debug', 'info', 'warning', 'error'].includes(message.level) || typeof message.text !== 'string' || message.text.length > 8192 || typeof message.time !== 'number' || !Number.isFinite(message.time) || Math.abs(message.time) > 8640000000000000 || message.stack != null && (typeof message.stack !== 'string' || message.stack.length > 8192))) throw new TypeError('Malformed page message');
    if (epoch !== outputGeneration) return;
    if (value.dropped) boundary(`${value.dropped} page messages dropped before delivery.`);
    for (const message of value.messages) {
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
    const epoch = outputGeneration, context = generation;
    try { const value = await runtime({operation: 'poll'}, controls.target.value, true); if (value?.status === 'ok') logs(value, epoch); }
    catch (error) {
      if (context === generation) { clearTargets(); disconnected = true; notice(`${error.message}. Refresh documents to recover. Commands were not retried.`, true); renderControls(); }
    }
    finally { pollRunning = false; }
  }
  setInterval(poll, 500);
  function filter() {
    const query = controls.filter.value.toLocaleLowerCase(), level = controls.level.value;
    for (const row of controls.output.children) row.hidden = !!query && !(row.textContent + (row.dataset.command || '')).toLocaleLowerCase().includes(query) || level !== 'all' && row.dataset.level !== level;
    updateOutputState();
  }
  controls.filter.addEventListener('input', filter); controls.level.addEventListener('change', filter);
  function search() { element('filter-row').hidden = false; element('search').setAttribute('aria-expanded', 'true'); controls.filter.focus(); controls.filter.select(); }
  function closeSearch() { controls.filter.value = ''; controls.level.value = 'all'; filter(); element('filter-row').hidden = true; element('search').setAttribute('aria-expanded', 'false'); (controls.source.disabled ? element('search') : controls.source).focus(); }
  element('filter-close').addEventListener('click', closeSearch);
  element('search').addEventListener('click', search);
  controls.filter.addEventListener('keydown', event => { if (event.key === 'Escape') { event.preventDefault(); closeSearch(); } });
  element('timestamps').addEventListener('change', event => { root.dataset.timestamps = String(event.target.checked); });
  element('forget').addEventListener('click', () => { history.length = 0; historyBytes = 0; historyIndex = null; draft = ''; notice('Command history forgotten.'); });
  async function initialize(force = false) {
    if (checking || initialized && !force) return;
    checking = true; renderControls();
    try {
      const response = await fetch('/api/native-console', {cache: 'no-store'}); const value = await response.json();
      if (!response.ok || !validState(value) || typeof value.available !== 'boolean') throw new TypeError('Native console unavailable');
      available = value.available; session = value.session_id; initialized = true; notice(available ? '' : value.message, !available);
    } catch (error) { initialized = true; available = false; notice(`${error.message}. Use Check availability to try again.`, true); }
    checking = false; renderControls();
    if (!root.hidden && root.contains(document.activeElement) && controls.source.disabled) focusPrompt();
  }
  element('check').addEventListener('click', () => initialize(true));
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
    controls.source.style.height = `${Math.min(108, Math.max(26, root.clientHeight - 170), Math.max(26, controls.source.scrollHeight))}px`;
    colorInput();
  }
  new ResizeObserver(() => { if (!root.hidden) sizeInput(); }).observe(root);
  const completion = createNativeConsoleCompletion(controls.source, element('highlight'), root, async query => {
    if (!session || disconnected || !controls.target.value) return null;
    const result = await runtime({operation: 'complete', path: query.path, prefix: query.prefix}, controls.target.value, true);
    if (result?.status !== 'ok' || !Array.isArray(result.items) || result.items.length > 24) return null;
    return result.items.filter(item => typeof item.name === 'string' && /^[A-Za-z_$][\w$]{0,127}$/.test(item.name) && ['property', 'function'].includes(item.kind));
  });
  controls.source.addEventListener('scroll', syncInputMirror); new ResizeObserver(syncInputMirror).observe(controls.source);
  controls.source.addEventListener('input', () => { historyIndex = null; sizeInput(); renderControls(); });
  controls.clear.addEventListener('click', async () => {
    if (submitting || pending) return;
    // Clear invalidates delayed transcript replies, not the native execution
    // context. Queued/new explicit commands retain their document ownership.
    ++outputGeneration;
    controls.output.replaceChildren(); outputBytes = 0; outputNodes = 0; removed = 0; unread = 0; updateOutputState();
    if (session && controls.target.value && !disconnected) await runtime({operation: 'clear'});
    if (!disconnected) notice('');
    renderControls();
  });
  const snippets = [];
  function saveSnippet(source) {
    if (!snippets.includes(source)) snippets.push(source);
    while (snippets.length > 16 || snippets.reduce((bytes, value) => bytes + encoder.encode(value).length, 0) > 65536) snippets.shift();
    const select = element('snippets'); select.replaceChildren();
    snippets.forEach((text, index) => { const option = document.createElement('option'); option.value = index; option.textContent = text.split('\n')[0].slice(0, 64); select.append(option); });
    select.disabled = !snippets.length; notice('Snippet saved in this app session.');
  }
  element('load-snippet').addEventListener('click', () => { const source = snippets[Number(element('snippets').value)]; if (source != null) { controls.source.value = source; sizeInput(); renderControls(); controls.connection.open = false; controls.source.focus(); } });
  function remember(source) {
    if (history.at(-1) === source) return;
    history.push(source); historyBytes += encoder.encode(source).length;
    while (history.length > 128 || historyBytes > 262144) historyBytes -= encoder.encode(history.shift()).length;
  }
  controls.form.addEventListener('submit', async event => {
    event.preventDefault(); if (submitting || pending || !session || disconnected || !controls.target.value) return;
    const source = controls.source.value;
    if (!source.trim() || encoder.encode(source).length > 8192) { notice('Enter 1 to 8192 UTF-8 bytes of JavaScript.', true); return; }
    const helper = source.trim().match(/^(copy|inspect|getEventListeners|monitorEvents|unmonitorEvents)\(([\s\S]*)\)\s*;?$/);
    if (helper && !helper[2].trim()) { notice('Enter an expression inside the console utility.', true); return; }
    submitting = true; renderControls();
    completion.close(); historyIndex = null; remember(source); notice(partialTargets ? 'Document listing is partial.' : '');
    const scope = {session, generation, command: ++commandNumber, target: controls.target.value, url: controls.target.selectedOptions[0]?.dataset.url || ''};
    controls.source.value = ''; sizeInput(); controls.source.focus();
    const commandRow = document.createElement('article'); commandRow.className = 'native-console-result native-console-command'; commandRow.dataset.level = 'result'; commandRow.dataset.command = source; commandRow.dataset.commandId = scope.command; commandRow.dataset.commandNumber = scope.command; commandRow.dataset.consoleSession = scope.session; commandRow.dataset.consoleDocument = scope.target;
    const commandStatus = document.createElement('span'); commandStatus.className = 'native-console-command-status'; commandStatus.textContent = `#${scope.command} · Running`; commandStatus.setAttribute('role', 'status'); commandRow.append(commandStatus);
    const expression = document.createElement('pre'); expression.className = 'native-console-expression'; expression.append(document.createTextNode('> ')); appendCommandColors(expression, source); commandRow.append(expression); appendRow(commandRow);
    try {
      const value = await runtime({operation: 'evaluate', source: helper ? helper[2] : source}, scope.target, false, scope.session, scope.generation);
      if (value) {
        commandStatus.textContent = `#${scope.command} · ${value.status === 'ok' ? 'Complete' : value.status}`;
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
            const reply = await runtime({operation: kind === 'getEventListeners' ? 'listeners' : kind === 'monitorEvents' ? 'monitor' : 'unmonitor', handle: value.value.handle}, scope.target, false, scope.session, scope.generation);
            if (reply?.properties) {
              const row = result(value, source, scope); const output = document.createElement('div'); output.className = 'native-console-properties';
              for (const property of reply.properties.slice(0, 32)) { const item = document.createElement('div'); item.className = 'native-console-property'; item.append(document.createTextNode(property.name + ': ')); renderValue(item, property.value, scope); output.append(item); }
              row.append(output); boundRow(row);
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
    } finally { submitting = false; boundRow(commandRow); renderControls(); }
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
    if (!session || controls.target.disabled && controls.source.disabled) controls.connection.open = true;
    (session ? controls.source.disabled ? controls.target.disabled ? controls.refresh : controls.target : controls.source : available ? controls.url : element('check')).focus();
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
