/* Track calls to a JavaScript function in the next capture. The backend
 * resolves a name or a position in one exact retained artifact to one native
 * invocation site (protocol/native-js-invocation-v1.md) and saves it in the
 * app's site set, which the next capture Origin Trace starts arms. Nothing here
 * changes the open page or the running capture. Captured context lines and
 * labels are inserted as text only. */
const INVOCATION_SITE_LIMIT = 8;
const INVOCATION_SITE_NEXT_CAPTURE = 'Tracking starts with the next capture Origin Trace starts, not the open page: a function the page already compiled cannot gain tracking.';

// UTF-8 byte offset of a UTF-16 offset in the original text Sources shows:
// the artifact decoded with its BOM kept. Null outside the retained text or
// between the two halves of a surrogate pair.
function invocationSiteByteOffset(text, offset, limit = text.length) {
  if (typeof text !== 'string' || !Number.isSafeInteger(offset) || offset < 0 || offset >= Math.min(limit, text.length)) return null;
  const code = text.charCodeAt(offset), previous = offset > 0 ? text.charCodeAt(offset - 1) : 0;
  if (code >= 0xdc00 && code <= 0xdfff && previous >= 0xd800 && previous <= 0xdbff) return null;
  return new TextEncoder().encode(text.slice(0, offset)).length;
}

function invocationSitePlural(count, noun) {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

// What the session header says about this capture and the saved set.
function invocationSiteHeader(set) {
  if (!set) return null;
  const session = set.session ?? {}, saved = Number(set.count) || 0;
  const stale = (set.sites ?? []).filter(site => site.retained?.state === 'other_version').length;
  const labels = list => list.map(site => site.label).filter(Boolean).join(', ');
  let text = '', title = '', kind = 'armed';
  if (session.state === 'armed') {
    text = `Tracking ${invocationSitePlural(session.count, 'function')}`;
    title = `This capture tracks calls to ${labels(session.sites ?? [])}.`;
    if (session.digests) {
      text += ' · value digests';
      title += ' Settled string and byte values of these calls are hashed (sensitive capture).';
    }
  } else if (session.state === 'browser_unsupported') {
    kind = 'warning';
    text = `Not tracking ${invocationSitePlural(session.count, 'saved function')}`;
    title = 'This Brave does not define invocation capture, so this session started without the saved functions and records no invocation evidence. Use the Brave released with this Origin Trace.';
  } else if (session.state === 'unreadable') {
    kind = 'warning';
    text = 'Function tracking file unreadable';
    title = 'The site file this capture was given could not be read.';
  } else if (saved > 0) {
    kind = 'saved';
    text = `${invocationSitePlural(saved, 'function')} saved for the next capture`;
    title = `This capture tracks no functions. ${INVOCATION_SITE_NEXT_CAPTURE}`;
  } else {
    return null;
  }
  if (stale) {
    kind = 'warning';
    text += ` · ${stale} will not match`;
    title += ` ${invocationSitePlural(stale, 'saved site')} will not match the script version this session retained.`;
  }
  return {text, title, kind};
}

function createInvocationSitesPanel({root, chip, trackButton, getSource, positionProblem, getPosition, onReveal, onShow,
  fetcher = fetch, protocol = globalThis.location?.protocol}) {
  const model = {available: null, set: null, error: '', status: '', result: null, busy: false, confirmClear: false};
  const node = (tag, text = '', className = '') => {
    const element = document.createElement(tag);
    if (text) element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  const button = (text, action, label) => {
    const element = node('button', text, 'secondary-button');
    element.type = 'button';
    if (label) element.setAttribute('aria-label', label);
    element.addEventListener('click', () => { if (!model.busy) action(); });
    return element;
  };
  const note = node('p', INVOCATION_SITE_NEXT_CAPTURE, 'invocation-sites-note');
  const session = node('p', '', 'invocation-sites-session');
  const form = node('div', '', 'invocation-sites-name');
  form.setAttribute('role', 'search');
  const label = node('label', 'Function name');
  label.setAttribute('for', 'invocation-site-name');
  const input = node('input');
  input.id = 'invocation-site-name';
  input.type = 'text';
  input.setAttribute('maxlength', '256');
  input.setAttribute('spellcheck', 'false');
  input.setAttribute('autocomplete', 'off');
  input.setAttribute('placeholder', 'window.hsw');
  input.setAttribute('aria-describedby', 'invocation-site-status');
  const submit = button('Track', () => trackName());
  submit.dataset.invocationAction = 'track-name';
  form.append(label, input, submit);
  const hint = node('p', 'Or place the cursor in a function, or go to its line and column, and choose Track calls in the toolbar.', 'invocation-sites-hint');
  const status = node('p', '', 'invocation-sites-status');
  status.id = 'invocation-site-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  const result = node('div', '', 'invocation-sites-result');
  const heading = node('h3', '', 'invocation-sites-heading');
  const list = node('ul', '', 'invocation-sites-list');
  list.setAttribute('aria-label', 'Functions saved for the next capture');
  const clear = button('Clear all', () => clearAll());
  clear.dataset.invocationAction = 'clear';
  root.replaceChildren(note, session, form, hint, status, result, heading, list, clear);
  input.addEventListener('keydown', event => {
    if (event.key !== 'Enter' || event.isComposing) return;
    event.preventDefault();
    trackName();
  });

  const unavailableReason = () => {
    if (!['http:', 'https:'].includes(protocol)) return 'Tracking needs the live session’s local API; it is unavailable in stored-evidence native mode.';
    if (model.available === false) return 'This backend does not save invocation sites.';
    return '';
  };
  const sourceReason = source => {
    if (source?.source_type !== 'artifact' || source.kind !== 'javascript') return 'Open one captured JavaScript artifact to track a function in it.';
    if (source.contentLossy) return 'This artifact is not strict UTF-8, so no invocation site can name it.';
    return '';
  };

  async function request(path, body) {
    const response = await fetcher(path, body === undefined ? {cache: 'no-store'}
      : {method: 'POST', cache: 'no-store', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    let value = null;
    try { value = await response.json(); } catch { value = null; }
    if (response.status === 404 && body === undefined) { model.available = false; throw new Error(unavailableReason()); }
    if (!response.ok) throw new Error(typeof value?.error === 'string' ? value.error.slice(0, 1024) : `Invocation sites returned HTTP ${response.status}.`);
    if (!value || typeof value !== 'object') throw new Error('Invocation sites returned an unreadable response.');
    return value;
  }

  async function refresh() {
    if (unavailableReason() && model.available !== false) { model.available = false; render(); return; }
    if (model.available === false) { render(); return; }
    try {
      const set = await request('/api/js-invocation-sites');
      if (set.format !== 'reb-js-invocation-site-set-v1' || !Array.isArray(set.sites)) throw new Error('Invocation sites returned an unexpected document.');
      model.available = true;
      model.set = set;
      model.error = '';
    } catch (error) {
      // Keep the last understandable set; say that it may be stale.
      const message = /[.!?]$/.test(error.message) ? error.message : `${error.message}.`;
      model.error = model.set ? `${message} The list below is from the last successful read.` : message;
    }
    render();
  }

  async function act(body, pending) {
    if (model.busy) return null;
    model.busy = true;
    model.status = pending;
    model.confirmClear = false;
    render();
    try {
      const value = await request('/api/js-invocation-sites/actions', body);
      if (value.set?.format === 'reb-js-invocation-site-set-v1') model.set = value.set;
      model.error = '';
      return value;
    } catch (error) {
      model.status = error.message;
      return null;
    } finally {
      model.busy = false;
      render();
    }
  }

  function describe(resolution) {
    const fn = resolution?.function;
    return fn ? `line ${fn.line}, column ${fn.column}` : '';
  }

  async function add(fields, pending) {
    const source = getSource();
    const reason = unavailableReason() || sourceReason(source);
    if (reason) { model.status = reason; model.result = null; render(); return; }
    const value = await act({action: 'add', session_id: source.session_id, artifact_id: source.artifact_id, ...fields}, pending);
    if (!value) return;
    model.result = value.resolution ?? null;
    const where = describe(value.resolution), label = value.resolution?.label ?? '';
    // A function bound to no name is labeled by its position; say it once.
    const saved = label === `Function at ${where}` ? `the function at ${where}` : `${label} (${where})`;
    model.status = value.added ? `Saved ${saved}. ${INVOCATION_SITE_NEXT_CAPTURE}` : value.resolution?.message ?? 'Nothing was saved.';
    render();
  }

  function trackName() {
    const name = input.value.trim();
    if (!name) { model.status = 'Type a function name such as window.hsw.'; render(); input.focus(); return; }
    add({name}, `Resolving ${name}…`);
  }

  function trackPosition() {
    onShow?.();
    const position = getPosition();
    if (position?.error) { model.status = position.error; model.result = null; render(); return; }
    add({byte_offset: position.byteOffset}, `Resolving the function at line ${position.line + 1}, column ${position.column + 1}…`);
  }

  function remove(site) {
    act({action: 'remove', source_sha256: site.site.source_sha256, anchor_offset: site.site.anchor_offset}, `Removing ${site.label}…`)
      .then(value => { if (value) { model.status = `Removed ${site.label}. A running capture keeps what it armed.`; render(); } });
  }

  function clearAll() {
    if (!model.confirmClear) {
      model.confirmClear = true;
      model.status = 'Choose Confirm clear to remove every saved function.';
      render();
      return;
    }
    act({action: 'clear', confirm: true}, 'Clearing saved functions…')
      .then(value => { if (value) { model.status = `Cleared ${invocationSitePlural(value.cleared, 'saved function')}.`; render(); } });
  }

  function renderCandidates(resolution) {
    result.replaceChildren();
    if (!resolution || resolution.status === 'resolved' || !Array.isArray(resolution.candidates) || resolution.candidates.length === 0) return;
    const shown = resolution.candidates.length, total = Number(resolution.candidate_count) || shown;
    result.append(node('p', resolution.candidate_relation === 'same_final_name'
      ? `Definitions whose name ends the same way (${shown}${total > shown ? ` of ${total}` : ''}):`
      : `Matching definitions (${shown}${total > shown ? ` of ${total}` : ''}):`, 'invocation-sites-candidates-title'));
    const items = node('ol', '', 'invocation-sites-candidates');
    for (const candidate of resolution.candidates) {
      const item = node('li', '', 'invocation-site-candidate');
      const where = `Line ${candidate.line}, column ${candidate.column} · ${candidate.kind}${candidate.binding ? ` · ${candidate.binding}` : ''}`;
      item.append(node('span', where, 'invocation-site-where'), node('code', candidate.context, 'invocation-site-context'));
      const actions = node('span', '', 'invocation-site-actions');
      const show = button('Show', () => onReveal?.(candidate), `Show line ${candidate.line}, column ${candidate.column}`);
      actions.append(show);
      if (candidate.supported && Number.isSafeInteger(candidate.byte_offset)) {
        const track = button('Track this one', () => add({byte_offset: candidate.byte_offset, ...(candidate.binding ? {label: candidate.binding.slice(0, 128)} : {})},
          `Saving the function at line ${candidate.line}, column ${candidate.column}…`), `Track the function at line ${candidate.line}, column ${candidate.column}`);
        track.dataset.invocationAction = 'track-candidate';
        actions.append(track);
      } else {
        actions.append(node('span', candidate.refusal ?? 'This function cannot be tracked from a `(`.', 'invocation-site-refusal'));
      }
      item.append(actions);
      items.append(item);
    }
    result.append(items);
  }

  function renderSession() {
    const state = model.set?.session;
    if (!state) { session.textContent = ''; return; }
    const names = (state.sites ?? []).map(site => site.label).join(', ');
    session.textContent = state.state === 'armed'
      ? `This capture tracks ${names}${state.digests ? ', with settled-value digests (sensitive capture)' : ''}.`
      : state.state === 'browser_unsupported'
        ? `This capture tracks nothing: this Brave does not define invocation capture, so it started without ${invocationSitePlural(state.count, 'saved function')}.`
        : state.state === 'unreadable' ? 'The site file this capture was given could not be read.' : 'This capture tracks no functions.';
  }

  function renderList() {
    const sites = model.set?.sites ?? [];
    heading.textContent = `Saved for the next capture (${sites.length} of ${INVOCATION_SITE_LIMIT})`;
    list.replaceChildren(...sites.map(site => {
      const item = node('li', '', 'invocation-site');
      item.dataset.retained = site.retained?.state ?? 'not_retained';
      item.append(node('strong', site.label, 'invocation-site-label'));
      if (site.source_url) {
        const url = node('span', site.source_url, 'invocation-site-url');
        url.title = site.source_url;
        item.append(url);
      }
      const retained = site.retained ?? {};
      if (retained.state === 'other_version') {
        const warning = node('span', `This session retained another version of this script (artifact ${retained.other_version_artifact_id}). The saved site will not match it.`, 'invocation-site-stale');
        warning.setAttribute('role', 'note');
        item.append(warning);
      } else if (retained.state === 'matches') {
        item.append(node('span', `This session retained the saved version (artifact ${retained.matching_artifact_id}).`, 'invocation-site-meta'));
      }
      item.append(button('Remove', () => remove(site), `Remove ${site.label}`));
      return item;
    }));
    if (!sites.length) list.append(node('li', 'No functions saved. Track one by name or position.', 'invocation-site-empty'));
  }

  function render() {
    const unavailable = unavailableReason();
    const sourceProblem = sourceReason(getSource());
    for (const control of [input, submit]) control.disabled = Boolean(unavailable) || model.busy;
    clear.disabled = Boolean(unavailable) || model.busy || !(model.set?.count > 0);
    clear.textContent = model.confirmClear ? 'Confirm clear' : 'Clear all';
    status.textContent = unavailable || model.error || model.status;
    renderSession();
    renderCandidates(model.result);
    renderList();
    if (trackButton) {
      const reason = unavailable || sourceProblem || positionProblem?.() || '';
      trackButton.disabled = Boolean(reason) || model.busy;
      trackButton.title = reason || 'Track calls to the function at the current position, starting with the next capture';
    }
    if (chip) {
      const header = unavailable ? null : invocationSiteHeader(model.set);
      chip.hidden = !header;
      if (header) {
        chip.textContent = header.text;
        chip.title = header.title;
        chip.dataset.kind = header.kind;
        chip.setAttribute('aria-label', `${header.text}. ${header.title}`);
      }
    }
  }

  trackButton?.addEventListener('click', () => { if (!model.busy) trackPosition(); });
  chip?.addEventListener('click', () => { onShow?.(); input.focus(); });
  render();
  return {model, refresh, render, trackName, trackPosition, input};
}
