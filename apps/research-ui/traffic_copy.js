'use strict';

// Copy as cURL and Copy as fetch for one Traffic row, from the first hop of
// its HAR entry (export_requests_har with rows=<id>): the request the page
// made, with the headers it sent and the body the capture retained. Values
// are copied as captured, credentials included; nothing is sent.

// Pseudo-headers and the ones a client computes from the URL and body.
const TRAFFIC_COPY_SKIPPED = new Set(['host', 'content-length', 'connection', 'transfer-encoding']);

function trafficCopyHeaders(entry) {
  return (entry?.request?.headers ?? []).filter(header => typeof header?.name === 'string' && !header.name.startsWith(':') &&
    !TRAFFIC_COPY_SKIPPED.has(header.name.toLowerCase()) && header._reb_withheld !== true);
}

// What a copy cannot carry: withheld values and a body the capture did not keep whole.
function trafficCopyGaps(entry) {
  const gaps = [];
  if ((entry?.request?.headers ?? []).some(header => header?._reb_withheld === true)) gaps.push('credential values were withheld');
  const data = entry?.request?.postData;
  if (data && data.text === '' && data._reb_base64 === undefined && !['empty', 'no_body'].includes(data._reb_state)) {
    gaps.push(data._reb_state === 'captured' ? 'the captured body could not be read, so the copy sends none'
      : `the body was not retained whole (${String(data._reb_state ?? 'unknown').replaceAll('_', ' ')}), so the copy sends none`);
  }
  if (entry?._reb?.url_complete === false) gaps.push('the URL is not the whole captured target');
  return gaps;
}

function trafficShellQuote(text) {
  return `'${String(text).replaceAll("'", "'\\''")}'`;
}

function trafficCurl(entry) {
  const request = entry.request, data = request.postData;
  const parts = [`curl ${trafficShellQuote(request.url)}`];
  const hasBody = Boolean(data && (data.text !== '' || data._reb_base64 !== undefined));
  if (request.method !== (hasBody ? 'POST' : 'GET')) parts.push(`-X ${trafficShellQuote(request.method)}`);
  for (const header of trafficCopyHeaders(entry)) parts.push(`-H ${trafficShellQuote(`${header.name}: ${header.value}`)}`);
  let prefix = '';
  if (data?._reb_base64 !== undefined) {
    // Binary bytes cannot ride in an argument; the shell decodes them into stdin.
    prefix = `printf %s ${trafficShellQuote(data._reb_base64)} | base64 --decode | `;
    parts.push('--data-binary @-');
  } else if (hasBody) parts.push(`--data-raw ${trafficShellQuote(data.text)}`);
  return prefix + parts.join(' \\\n  ');
}

function trafficFetch(entry) {
  const request = entry.request, data = request.postData;
  const headers = {};
  for (const header of trafficCopyHeaders(entry)) headers[header.name] = header.value;
  const init = {method: request.method, headers};
  const lines = JSON.stringify(init, null, 2).split('\n');
  if (data?._reb_base64 !== undefined) {
    lines.splice(-1, 0, `  "body": Uint8Array.from(atob(${JSON.stringify(data._reb_base64)}), c => c.charCodeAt(0))`);
    lines[lines.length - 3] += ',';
  } else if (data && data.text !== '') {
    lines.splice(-1, 0, `  "body": ${JSON.stringify(data.text)}`);
    lines[lines.length - 3] += ',';
  }
  return `fetch(${JSON.stringify(request.url)}, ${lines.join('\n')});`;
}

// WebKit lets a page write the clipboard only inside the user's action. A
// ClipboardItem holding a promise starts the write there and fills it when the
// read answers; without one the text is written once it arrives.
function trafficClipboardWrite(textPromise) {
  if (typeof ClipboardItem === 'function' && navigator.clipboard?.write) {
    return navigator.clipboard.write([new ClipboardItem({'text/plain': textPromise.then(text => new Blob([text], {type: 'text/plain'}))})]);
  }
  return textPromise.then(text => navigator.clipboard.writeText(text));
}

// The first hop of one row, read from the backend. Credential values are
// asked for: this is the researcher's own local copy.
async function trafficHarEntry(id, fetcher = (input, init) => fetch(input, init)) {
  const response = await fetcher(`/api/requests/har?${new URLSearchParams({rows: id, credential_values: '1'})}`,
    {cache: 'no-store', signal: AbortSignal.timeout(30000)});
  if (!response.ok) {
    const failure = await response.json().catch(() => null);
    throw new Error(failure?.error ?? `the backend returned ${response.status}`);
  }
  const archive = await response.json();
  if (archive?.log?._reb?.complete !== true) throw new Error(archive?.log?._reb?.error ?? 'the archive is incomplete');
  const entry = archive.log.entries.find(candidate => candidate?._reb?.hop === 0 || candidate?._reb?.outcome === 'unlinked');
  if (!entry) throw new Error('the request has no recorded hop');
  return entry;
}

// One menu for a row's right-click and the selection strip's Copy button.
// `select(id, opener)` runs first, so a right-clicked row is the selected one;
// `actions(id)` then lists {label, run, disabled, title, separated} for it.
function createTrafficRowMenu({rows, button, select = () => {}, actions}) {
  let menu = null;
  function close(focus = true) {
    const closing = menu;
    if (!closing) return;
    menu = null;
    closing.remove();
    button?.setAttribute('aria-expanded', 'false');
    if (focus) closing.opener?.focus({preventScroll: true});
  }
  function open(id, opener, x, y) {
    close(false);
    select(id, opener);
    const items = actions(id);
    if (!items.length) return;
    menu = document.createElement('div');
    menu.className = 'column-menu traffic-row-menu';
    menu.setAttribute('role', 'menu');
    menu.setAttribute('aria-label', 'Request actions');
    menu.opener = opener;
    for (const action of items) {
      const item = document.createElement('button');
      item.type = 'button';
      item.setAttribute('role', 'menuitem');
      item.textContent = action.label;
      item.disabled = Boolean(action.disabled);
      if (action.title) item.title = action.title;
      if (action.separated) item.dataset.separated = 'true';
      item.addEventListener('click', () => { close(); action.run(); });
      menu.append(item);
    }
    menu.addEventListener('keydown', event => {
      const enabled = [...menu.querySelectorAll('button:not(:disabled)')];
      const at = enabled.indexOf(document.activeElement);
      if (event.key === 'Escape' || event.key === 'Tab') {
        event.preventDefault();
        event.stopPropagation();
        close();
      } else if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key) && enabled.length) {
        event.preventDefault();
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? enabled.length - 1
          : (at + (event.key === 'ArrowDown' ? 1 : -1) + enabled.length) % enabled.length;
        enabled[next].focus();
      }
    });
    // WebKit does not focus a clicked button: the press would blur the focused
    // item with nowhere to go and close the menu before the click lands.
    menu.addEventListener('mousedown', event => event.preventDefault());
    menu.addEventListener('focusout', event => {
      if (menu && !menu.contains(event.relatedTarget)) close(false);
    });
    // Fixed to the viewport so the list's scroll box cannot clip it.
    document.body.append(menu);
    menu.style.left = `${Math.max(4, Math.min(x, innerWidth - menu.offsetWidth - 4))}px`;
    menu.style.top = `${Math.max(4, Math.min(y, innerHeight - menu.offsetHeight - 4))}px`;
    if (opener === button) button.setAttribute('aria-expanded', 'true');
    menu.querySelector('button:not(:disabled)')?.focus();
  }
  rows?.addEventListener('contextmenu', event => {
    const row = event.target.closest?.('.request-row');
    if (!row?.dataset.requestId) return;
    event.preventDefault();
    open(row.dataset.requestId, row, event.clientX, event.clientY);
  });
  rows?.addEventListener('keydown', event => {
    const row = event.target.closest?.('.request-row');
    if (!row?.dataset.requestId || !(event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10'))) return;
    event.preventDefault();
    const box = row.getBoundingClientRect();
    open(row.dataset.requestId, row, box.left + 24, box.bottom);
  });
  // A press on Copy itself is left to its click, which closes the open menu.
  document.addEventListener('pointerdown', event => {
    if (menu && !menu.contains(event.target) && !button?.contains(event.target)) close(false);
  });
  return {open, close, isOpen: () => menu !== null};
}

if (typeof module === 'object' && module?.exports) module.exports = {trafficCurl, trafficFetch, trafficCopyHeaders, trafficCopyGaps, trafficHarEntry, trafficClipboardWrite};
