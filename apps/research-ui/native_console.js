(() => {
  const root = document.querySelector('#native-console-panel');
  const element = name => document.querySelector(`#native-console-${name}`);
  const controls = Object.fromEntries(['url', 'start', 'stop', 'notice', 'target', 'refresh', 'clear', 'output', 'form', 'source', 'run'].map(name => [name, element(name)]));
  const toggle = element('toggle');
  let historyIndex = null;
  let draft = '';
  let session = null;
  let available = false;
  let pending = false;
  let disconnected = false;
  let initialized = false;
  let outputBytes = 0;
  let removed = 0;
  const encoder = new TextEncoder();
  const numberId = value => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 18446744073709551615n;
  const validState = value => value?.contract_version === 1 && ['ready', 'idle'].includes(value.state) &&
    (value.state === 'ready' ? numberId(value.session_id) : value.session_id === null);

  function notice(message, error = false) {
    controls.notice.textContent = message;
    controls.notice.title = message;
    controls.notice.dataset.kind = error ? 'error' : 'status';
  }
  function renderControls() {
    root.dataset.session = session ? 'ready' : 'idle';
    element('badge').textContent = `Native · ${pending ? 'working' : session ? disconnected ? 'disconnected' : 'connected' : initialized && !available ? 'unavailable' : 'idle'}`;
    controls.start.disabled = pending || !available || !!session;
    controls.stop.disabled = pending || !session;
    controls.refresh.disabled = pending || !session;
    controls.target.disabled = pending || !session || controls.target.options.length <= 1;
    controls.url.disabled = pending || !!session;
    controls.source.disabled = pending || !session || !controls.target.value;
    controls.run.disabled = controls.source.disabled || !controls.source.value.trim();
    controls.run.textContent = pending ? '…' : 'Run';
  }
  function clearTargets() {
    const option = document.createElement('option');
    option.value = ''; option.textContent = 'Select a document';
    controls.target.replaceChildren(option);
  }
  async function request(action, fields = {}) {
    const response = await fetch('/api/native-console/actions', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action, ...(action === 'start' ? {} : {session_id: session}), ...fields}),
      cache: 'no-store'
    });
    const value = await response.json();
    if (!response.ok) throw new Error(typeof value.error === 'string' ? value.error : `Console returned ${response.status}`);
    if (!validState(value) || value.state !== (action === 'stop' ? 'idle' : 'ready')) throw new TypeError('Malformed native console response');
    if (action !== 'start' && action !== 'stop' && value.session_id !== session) throw new TypeError('Native console session changed');
    return value;
  }
  async function perform(action, fields, apply) {
    if (pending) return;
    pending = true; renderControls();
    try { apply(await request(action, fields)); disconnected = false; }
    catch (error) {
      // Do not repeat commands after a transport failure. Preserve readable
      // results but retire selection until the researcher checks session state.
      clearTargets(); disconnected = true;
      notice(`${error.message}. Commands are never retried automatically.`, true);
    } finally { pending = false; renderControls(); if (action === 'evaluate' && !controls.source.disabled) controls.source.focus(); }
  }
  function targets(value) {
    if (!Array.isArray(value.targets) || value.targets.length > 64 || typeof value.truncated !== 'boolean' ||
        value.targets.some(target => !numberId(target.id) || typeof target.origin !== 'string' ||
          encoder.encode(target.origin).length > 256 || typeof target.truncated !== 'boolean') ||
        new Set(value.targets.map(target => target.id)).size !== value.targets.length) throw new TypeError('Malformed document listing');
    clearTargets();
    for (const target of value.targets) {
      const option = document.createElement('option');
      option.value = target.id; option.textContent = `${target.origin} · document ${target.id}${target.truncated ? '…' : ''}`;
      controls.target.append(option);
    }
    notice(value.targets.length ? `Select a document in the disposable browser.${value.truncated ? ' Document listing is partial.' : ''}`
      : 'No eligible documents yet. Open an HTTP or HTTPS page in the disposable browser, then refresh documents.');
  }
  function result(value, source) {
    if (!['ok', 'malformed', 'stale_target', 'forbidden', 'exception', 'timeout', 'disconnected'].includes(value.status) ||
        !['undefined', 'null', 'boolean', 'number', 'string', 'bigint', 'symbol', 'function', 'object', 'promise'].includes(value.type) ||
        typeof value.text !== 'string' || encoder.encode(value.text).length > 8192 || typeof value.truncated !== 'boolean') throw new TypeError('Malformed console result');
    const empty = controls.output.querySelector('.native-console-empty');
    if (empty) empty.remove();
    const follow = controls.output.scrollHeight - controls.output.scrollTop - controls.output.clientHeight < 40;
    const row = document.createElement('article'); row.className = 'native-console-result'; row.dataset.status = value.status; row.dataset.type = value.type;
    const input = document.createElement('pre'); input.className = 'native-console-expression';
    input.append(document.createTextNode('› ')); appendCommandColors(input, source);
    const label = document.createElement('span'); label.className = 'native-console-result-type'; label.textContent = `${value.status === 'ok' ? value.type : value.status} · document ${controls.target.value}${value.truncated ? ' · truncated' : ''}`;
    label.title = `Session ${value.session_id} · document ${controls.target.value}`;
    const output = document.createElement('pre'); output.className = 'native-console-value'; output.textContent = value.text;
    row.append(input, label, output);
    const bytes = encoder.encode(source).length + encoder.encode(value.text).length;
    row.dataset.bytes = bytes;
    controls.output.append(row); outputBytes += bytes;
    while (controls.output.children.length > 32 || outputBytes > 262144) {
      const oldest = controls.output.firstElementChild;
      outputBytes -= Number(oldest.dataset.bytes || 0); oldest.remove(); ++removed;
    }
    const message = value.status === 'ok' ? `Executed in document ${controls.target.value}.`
      : `${value.text}${value.status === 'stale_target' ? ' Refresh documents to select the current page.' : ''}`;
    notice(`${message}${removed ? ` ${removed} older entries removed from this bounded output.` : ''}`, value.status !== 'ok');
    if (value.status === 'stale_target') clearTargets();
    if (follow) controls.output.scrollTop = controls.output.scrollHeight;
  }
  async function initialize() {
    if (initialized || pending) return;
    pending = true; renderControls();
    try {
      const response = await fetch('/api/native-console', {cache: 'no-store'});
      const value = await response.json();
      if (!response.ok || !validState(value) || typeof value.available !== 'boolean' || typeof value.message !== 'string') throw new TypeError('Native console is unavailable');
      available = value.available; session = value.session_id; initialized = true;
      notice(value.message);
      if (session) controls.output.querySelector('.native-console-empty').textContent = 'Refresh documents and select a page to begin.';
    } catch (error) { notice(error.message, true); }
    finally { pending = false; renderControls(); if (!root.hidden) focusPrompt(); }
  }
  controls.start.addEventListener('click', () => {
    if (!controls.url.reportValidity() || !controls.url.value.trim()) { notice('Enter the URL of a page you are authorized to inspect.', true); controls.url.focus(); return; }
    perform('start', {url: controls.url.value.trim()}, value => { session = value.session_id; targets(value); });
  });
  controls.stop.addEventListener('click', () => perform('stop', {}, () => { session = null; clearTargets(); notice('Session stopped. The disposable browser and profile were removed.'); }));
  controls.refresh.addEventListener('click', () => perform('targets', {}, targets));
  controls.target.addEventListener('change', () => { renderControls(); if (!controls.source.disabled) controls.source.focus(); });
  // Tokenize at most the command limit and reuse the existing source tokenizer.
  // Spans contain text only; coloring cannot interpret captured HTML or evaluate JS.
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
    controls.source.style.height = `${Math.min(66, Math.max(26, controls.source.scrollHeight + 2))}px`;
    colorInput();
  }
  controls.source.addEventListener('scroll', syncInputMirror);
  new ResizeObserver(syncInputMirror).observe(controls.source);
  controls.source.addEventListener('input', () => { historyIndex = null; sizeInput(); renderControls(); });
  controls.clear.addEventListener('click', () => {
    const empty = document.createElement('p'); empty.className = 'native-console-empty'; empty.textContent = 'Output cleared.';
    controls.output.replaceChildren(empty); outputBytes = 0; removed = 0; historyIndex = null;
  });
  controls.form.addEventListener('submit', event => {
    event.preventDefault();
    if (pending || !session || !controls.target.value) return;
    const source = controls.source.value;
    if (!source.trim() || encoder.encode(source).length > 8192) { notice('Enter 1 to 8192 UTF-8 bytes of JavaScript.', true); return; }
    historyIndex = null;
    const target = controls.target.value;
    perform('evaluate', {target_id: target, source}, value => { result(value, source); controls.source.value = ''; sizeInput(); });
  });
  controls.source.addEventListener('keydown', event => {
    if (event.isComposing) return;
    if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); controls.form.requestSubmit(); return; }
    // Recall only commands already present in the bounded output, without a
    // second history buffer or persistent command storage.
    if (event.shiftKey || event.metaKey || event.ctrlKey || event.altKey || !['ArrowUp', 'ArrowDown'].includes(event.key) || (historyIndex === null && controls.source.value.includes('\n')) ||
        controls.source.selectionStart !== controls.source.selectionEnd) return;
    if (historyIndex === null && (event.key !== 'ArrowUp' || controls.source.selectionStart !== 0 && controls.source.selectionStart !== controls.source.value.length)) return;
    const commands = [...controls.output.querySelectorAll('.native-console-expression')];
    if (!commands.length) return;
    event.preventDefault();
    if (historyIndex === null) { draft = controls.source.value; historyIndex = commands.length; }
    historyIndex = Math.max(0, Math.min(commands.length, historyIndex + (event.key === 'ArrowUp' ? -1 : 1)));
    controls.source.value = historyIndex === commands.length ? draft : commands[historyIndex].textContent.slice(2);
    if (historyIndex === commands.length) historyIndex = null;
    sizeInput(); renderControls();
  });
  function focusPrompt() {
    (session ? controls.source.disabled ? controls.target.disabled ? controls.refresh : controls.target : controls.source : controls.url).focus();
  }
  function setOpen(open) {
    root.hidden = !open;
    document.querySelector('#workspace').dataset.consoleOpen = String(open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-pressed', String(open));
    if (open) { sizeInput(); focusPrompt(); }
    else toggle.focus();
  }
  toggle.addEventListener('click', () => setOpen(root.hidden));
  element('close').addEventListener('click', () => setOpen(false));
  document.addEventListener('keydown', event => {
    if (event.key.toLowerCase() === 'j' && (event.metaKey || event.ctrlKey) && !event.altKey && !event.shiftKey) {
      event.preventDefault(); setOpen(root.hidden);
    }
  });
  new MutationObserver(() => { if (!root.hidden) initialize(); }).observe(root, {attributes: true, attributeFilter: ['hidden']});
  renderControls();
})();
