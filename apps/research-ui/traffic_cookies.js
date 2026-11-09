// Traffic Cookies tab ("Cookies" in protocol/native-network-v3.md): the
// cookies each hop sent, with the filtered-out ones and their reasons, the
// Set-Cookie cookies it received with every attribute and block reason, and a
// name's provenance across the session. Lists are read after a size and
// SHA-256 check; every captured value is assigned as text.
const TRAFFIC_COOKIE_RETRY_MS = 2000;
const TRAFFIC_COOKIE_PROVENANCE_LISTS = 64;
const trafficCookieViews = new Map();
const trafficCookieStacks = new Map();
const trafficCookieOptions = {showFiltered: false, sort: new Map(), provenance: null};

const trafficCookieExclusions = ['unknown_error', 'http_only', 'secure_only', 'domain_mismatch', 'not_on_path',
  'samesite_strict', 'samesite_lax', 'samesite_unspecified_treated_as_lax', 'samesite_none_insecure', 'user_preferences',
  'failure_to_store', 'noncookieable_scheme', 'overwrite_secure', 'overwrite_http_only', 'invalid_domain', 'invalid_prefix',
  'invalid_partitioned', 'name_value_pair_exceeds_max_size', 'attribute_value_exceeds_max_size', 'domain_non_ascii',
  'third_party_blocked_within_first_party_set', 'port_mismatch', 'scheme_mismatch', 'shadowing_domain',
  'disallowed_character', 'third_party_phaseout', 'no_cookie_content', 'anonymous_context', 'invalid_path',
  'ambiguous_serialization'];
const trafficCookieWarnings = ['samesite_unspecified_cross_site_context', 'samesite_none_insecure',
  'samesite_unspecified_lax_allow_unsafe', 'strict_lax_downgrade_strict_samesite', 'strict_cross_downgrade_strict_samesite',
  'strict_cross_downgrade_lax_samesite', 'lax_cross_downgrade_strict_samesite', 'lax_cross_downgrade_lax_samesite',
  'secure_access_granted_non_cryptographic', 'cross_site_redirect_downgrade_changes_inclusion',
  'attribute_value_exceeds_max_size', 'domain_non_ascii', 'port_mismatch', 'scheme_mismatch',
  'tentatively_allowing_secure_source_scheme', 'shadowing_domain', 'third_party_phaseout'];
const trafficCookieReasonText = {
  http_only: 'it is HttpOnly', secure_only: 'it is Secure and the connection was not',
  domain_mismatch: 'its domain does not match', not_on_path: 'its path does not match',
  samesite_strict: 'it is SameSite=Strict and the request was cross-site',
  samesite_lax: 'it is SameSite=Lax and the request was cross-site',
  samesite_unspecified_treated_as_lax: 'it has no SameSite, which is treated as Lax, and the request was cross-site',
  samesite_none_insecure: 'it is SameSite=None without Secure', user_preferences: 'of the user\'s cookie settings',
  third_party_phaseout: 'third-party cookies are blocked', disallowed_character: 'it has a disallowed character',
  invalid_domain: 'its Domain is invalid', invalid_prefix: 'its __Secure- or __Host- prefix rules are not met',
  overwrite_secure: 'it would overwrite a Secure cookie', overwrite_http_only: 'it would overwrite an HttpOnly cookie',
  name_value_pair_exceeds_max_size: 'its name and value exceed 4096 bytes', port_mismatch: 'its port does not match',
  scheme_mismatch: 'its scheme does not match'
};
const trafficCookieSameSite = [null, 'Unspecified', 'None', 'Lax', 'Strict'];
const trafficCookiePriority = [null, 'Low', 'Medium', 'High'];
const trafficCookieStateNotes = {
  empty: 'No cookies.',
  not_captured_block_limit: 'Longer than the 2 MiB list limit, so only its counts and size were recorded.',
  not_captured_artifact_unavailable: 'Not retained: the artifact channel was unavailable.',
  not_captured_transfer_refused: 'Not retained: the bounded artifact queue refused it.',
  not_captured_session_budget: 'Not retained: this session already retained 64 MiB of header blocks and cookie lists.',
  not_captured_url: 'Not retained: not an HTTP(S) URL, longer than 8 KiB, or its hop was not tracked.'
};

function trafficCookieReasons(bits, names) {
  const out = [];
  for (let bit = 0n; bits >> bit; bit += 1n) {
    if ((bits >> bit) & 1n) out.push(names[Number(bit)] ?? `bit_${bit}`);
  }
  return out;
}

// The cookie list artifact, exactly: RBCK header, `count` cookies, nothing after.
function trafficCookieList(bytes, direction, count) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 16 || String.fromCharCode(...bytes.slice(0, 4)) !== 'RBCK' || view.getUint16(4, true) !== 1 ||
      bytes[6] !== (direction === 'sent' ? 1 : 2) || bytes[7] !== 0 || view.getUint32(8, true) !== count ||
      view.getUint32(12, true) !== 0) return null;
  const decoder = new TextDecoder('utf-8', {fatal: false, ignoreBOM: true});
  const cookies = [];
  let offset = 16;
  for (let index = 0; index < count; index += 1) {
    if (offset + 64 > bytes.length || bytes.slice(offset + 29, offset + 32).some(Boolean) || view.getUint32(offset + 60, true)) return null;
    const lengths = Array.from({length: 6}, (_, item) => view.getUint32(offset + 36 + item * 4, true));
    let text = offset + 64;
    const strings = [];
    for (const length of lengths) {
      if (text + length > bytes.length) return null;
      strings.push(bytes.slice(text, text + length));
      text += length;
    }
    const flags = bytes[offset + 24];
    const cookie = {
      exclusions: trafficCookieReasons(view.getBigUint64(offset, true), trafficCookieExclusions),
      warnings: trafficCookieReasons(view.getBigUint64(offset + 8, true), trafficCookieWarnings),
      expiry: Number(view.getBigInt64(offset + 16, true)), parsed: Boolean(flags & 1), httpOnly: Boolean(flags & 2),
      secure: Boolean(flags & 4), partitioned: Boolean(flags & 8), crossSite: Boolean(flags & 16),
      sameSite: trafficCookieSameSite[bytes[offset + 25]] ?? null, priority: trafficCookiePriority[bytes[offset + 26]] ?? null,
      sourcePort: view.getInt32(offset + 32, true), valueBytes: strings[1],
      name: decoder.decode(strings[0]), value: decoder.decode(strings[1]), domain: decoder.decode(strings[2]),
      path: decoder.decode(strings[3]), partitionSite: decoder.decode(strings[4]), line: decoder.decode(strings[5])
    };
    const shaped = cookie.parsed
      ? (flags & ~0x3f) === 0 && cookie.sameSite && cookie.priority && bytes[offset + 27] >= 1 && bytes[offset + 27] <= 5 &&
        bytes[offset + 28] <= 2
      : direction === 'received' && flags === 0 && !bytes.slice(offset + 16, offset + 36).some(Boolean) &&
        lengths.slice(0, 5).every(length => length === 0);
    if (!shaped || (direction === 'sent' && lengths[5] !== 0)) return null;
    cookie.blocked = cookie.exclusions.length > 0;
    cookie.size = strings[0].length + strings[1].length;
    cookies.push(cookie);
    offset = text;
  }
  return offset === bytes.length ? cookies : null;
}

async function trafficCookieHex(bytes) {
  if (!globalThis.crypto?.subtle) return null;
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
    byte => byte.toString(16).padStart(2, '0')).join('');
}

function trafficCookieView(list, rerender) {
  if (!['captured', 'captured_shared'].includes(list.state)) return null;
  if (typeof location === 'object' && location.protocol === 'file:') return {status: 'unavailable'};
  const refusal = (typeof state === 'object' ? state.events ?? [] : []).find(event =>
    event.type === 'artifact_capture_failed' && event.artifact_id === list.artifactId && event.session_id === list.sessionId);
  if (refusal) return {status: 'refused', reason: typeof decodePayload === 'function' ? decodePayload(refusal) : ''};
  const key = `${list.sessionId}:${list.artifactId}:${list.sha256}`;
  const view = trafficCookieViews.get(key);
  if (view && !(view.retryable && Date.now() - view.failedAt >= TRAFFIC_COOKIE_RETRY_MS)) return view;
  trafficCookieViews.set(key, {status: 'loading'});
  void trafficLoadCookieList(list, key, rerender);
  return view ?? {status: 'loading'};
}

async function trafficLoadCookieList(list, key, rerender) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  const mismatch = message => Object.assign(new Error(message), {integrity: true});
  let view;
  try {
    const response = await fetch(`/api/artifacts/${encodeURIComponent(list.artifactId)}/content?limit=${list.listLength}`,
      {cache: 'no-store', signal: controller.signal});
    if (!response.ok) throw new Error(`the artifact store returned ${response.status}`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length !== list.listLength) throw mismatch('its retained size does not match the cookie record');
    const digest = await trafficCookieHex(bytes);
    if (digest !== null && digest !== list.sha256) throw mismatch('its bytes do not match the recorded SHA-256');
    const cookies = trafficCookieList(bytes, list.direction, list.cookieCount);
    if (!cookies) throw mismatch('its layout does not match the recorded cookie count');
    for (const cookie of cookies) cookie.valueSha256 = cookie.parsed ? await trafficCookieHex(cookie.valueBytes) : null;
    view = {status: 'ready', cookies};
  } catch (error) {
    view = {status: 'error', error: controller.signal.aborted ? 'timed out after 10 seconds'
      : String(error?.message ?? error).replace(/\.$/, ''), retryable: error?.integrity !== true, failedAt: Date.now()};
  } finally {
    clearTimeout(timeout);
  }
  trafficCookieViews.delete(key);
  trafficCookieViews.set(key, view);
  while (trafficCookieViews.size > 128) trafficCookieViews.delete(trafficCookieViews.keys().next().value);
  rerender?.();
}

// Script positions from get_cookie_provenance by process:sequence; a failed read keeps raw positions.
function trafficCookieCallFrames(sessionId, name, rerender) {
  if (typeof location === 'object' && location.protocol === 'file:') return null;
  const key = `${sessionId}:${name}`;
  const known = trafficCookieStacks.get(key);
  if (known && !(known.status === 'error' && Date.now() - known.failedAt >= TRAFFIC_COOKIE_RETRY_MS)) return known.frames ?? null;
  trafficCookieStacks.set(key, {status: 'loading'});
  void (async () => {
    let entry;
    try {
      const response = await fetch(`/api/cookie-provenance?${new URLSearchParams({session_id: sessionId, name})}`,
        {cache: 'no-store', signal: AbortSignal.timeout(10000)});
      if (!response.ok) throw new Error(String(response.status));
      const frames = new Map();
      for (const call of (await response.json()).script ?? []) {
        const top = call.stack?.frames?.[0]?.resolution;
        if (top?.status === 'resolved') frames.set(`${call.process_id}:${call.sequence_number}`, top);
      }
      entry = {status: 'ready', frames};
    } catch {
      entry = {status: 'error', failedAt: Date.now()};
    }
    trafficCookieStacks.set(key, entry);
    while (trafficCookieStacks.size > 64) trafficCookieStacks.delete(trafficCookieStacks.keys().next().value);
    rerender?.();
  })();
  return null;
}

function trafficCookieFrameLabel(frame) {
  const file = String(frame.url ?? '').split(/[?#]/)[0].split('/').filter(Boolean).pop() || `artifact ${frame.artifact_id}`;
  return `${file}:${frame.line ?? '?'}:${frame.column ?? '?'}${frame.function_name ? ` (${frame.function_name})` : ''}`;
}

function trafficCookieExpires(cookie) {
  if (!cookie.parsed) return '';
  return cookie.expiry ? new Date(cookie.expiry).toISOString() : 'Session';
}

function trafficCookieBlockedText(cookie, received) {
  const reasons = cookie.exclusions.map(reason => trafficCookieReasonText[reason] ?? reason.replaceAll('_', ' '));
  if (!reasons.length) return '';
  return `${received ? 'This Set-Cookie was blocked because' : 'Not sent because'} ${reasons.join('; ')}.`;
}

const trafficCookieColumns = [
  ['name', 'Name', cookie => cookie.parsed ? cookie.name : '(unparsed)'],
  ['value', 'Value', cookie => cookie.parsed ? cookie.value : cookie.line],
  ['domain', 'Domain', cookie => cookie.domain],
  ['path', 'Path', cookie => cookie.path],
  ['expires', 'Expires / Max-Age', trafficCookieExpires],
  ['size', 'Size', cookie => cookie.parsed ? cookie.size : ''],
  ['httpOnly', 'HttpOnly', cookie => cookie.httpOnly ? 'Yes' : ''],
  ['secure', 'Secure', cookie => cookie.secure ? 'Yes' : ''],
  ['sameSite', 'SameSite', cookie => cookie.sameSite ?? ''],
  ['partition', 'Partition Key Site', cookie => cookie.partitioned ? cookie.partitionSite : ''],
  ['crossSite', 'Cross Site', cookie => cookie.crossSite ? 'Yes' : ''],
  ['priority', 'Priority', cookie => cookie.priority ?? ''],
  ['blocked', 'Blocked because', cookie => cookie.exclusions.join(', ')]
];

function trafficCookieTable(id, title, cookies, {received, onProvenance}) {
  const sort = trafficCookieOptions.sort.get(id) ?? {column: null, direction: 1};
  const rows = [...cookies];
  if (sort.column) {
    const read = trafficCookieColumns.find(column => column[0] === sort.column)[2];
    rows.sort((left, right) => {
      const [a, b] = [read(left), read(right)];
      return (typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b))) * sort.direction;
    });
  }
  const columns = trafficCookieColumns.filter(column => column[0] !== 'blocked' || rows.some(cookie => cookie.blocked));
  const wrap = trafficNode('div', 'traffic-cookie-table-wrap');
  const table = trafficNode('table', 'traffic-cookie-table');
  table.setAttribute('aria-label', title);
  const head = trafficNode('tr');
  for (const [key, label] of columns) {
    const cell = trafficNode('th');
    cell.scope = 'col';
    cell.setAttribute('aria-sort', sort.column === key ? (sort.direction > 0 ? 'ascending' : 'descending') : 'none');
    const button = trafficNode('button', 'traffic-cookie-sort', label);
    button.type = 'button';
    button.dataset.column = key;
    button.addEventListener('click', () => {
      trafficCookieOptions.sort.set(id, {column: key, direction: sort.column === key ? -sort.direction : 1});
      table.dispatchEvent(new CustomEvent('traffic-cookie-change', {bubbles: true}));
    });
    cell.append(button);
    head.append(cell);
  }
  head.append(trafficNode('th', 'traffic-cookie-actions', ''));
  const thead = trafficNode('thead');
  thead.append(head);
  const body = trafficNode('tbody');
  const status = trafficNode('span', 'traffic-headers-status');
  status.setAttribute('role', 'status');
  for (const cookie of rows) {
    const row = trafficNode('tr', cookie.blocked ? 'traffic-cookie-blocked' : '');
    for (const [key, , read] of columns) {
      const text = String(read(cookie));
      const cell = trafficNode('td', `traffic-cookie-col-${key}`);
      if (key === 'name' && cookie.parsed) {
        const open = trafficNode('button', 'traffic-cookie-name', text);
        open.type = 'button';
        open.title = `Show everything that touched ${text}`;
        open.addEventListener('click', () => onProvenance(cookie.name));
        cell.append(open);
      } else {
        cell.textContent = text;
        if (key === 'value' || key === 'blocked') cell.title = key === 'blocked' ? trafficCookieBlockedText(cookie, received) : text;
      }
      row.append(cell);
    }
    const actions = trafficNode('td', 'traffic-cookie-actions');
    const copy = trafficNode('button', 'traffic-header-copy', 'Copy');
    copy.type = 'button';
    copy.setAttribute('aria-label', `Copy ${cookie.parsed ? cookie.name : 'unparsed line'} value`);
    copy.addEventListener('click', () => trafficCopyText(cookie.parsed ? cookie.value : cookie.line, status));
    actions.append(copy);
    row.append(actions);
    body.append(row);
  }
  table.append(thead, body);
  wrap.append(table, status);
  return wrap;
}

function trafficCookieSection(id, title, list, rerender, {received, onProvenance}) {
  const details = trafficNode('details', 'traffic-headers-section traffic-cookie-section');
  details.open = true;
  details.dataset.section = id;
  details.dataset.state = list.state;
  const summary = trafficNode('summary', '', title);
  summary.append(trafficNode('span', 'traffic-headers-count', String(list.cookieCount)));
  details.append(summary);
  const notes = [trafficCookieStateNotes[list.state] ?? '',
    list.state === 'captured_shared' ? 'Identical to an earlier list of this session, retained once.' : ''].filter(Boolean);
  if (notes.length) details.append(trafficNode('p', 'traffic-headers-note', notes.join(' ')));
  const view = trafficCookieView(list, rerender);
  let key = `${id}|${list.sequenceNumber}|${view?.status ?? list.state}`;
  if (view && view.status !== 'ready') {
    details.append(trafficNode('p', 'traffic-headers-note', view.status === 'loading' ? 'Loading retained cookies…'
      : view.status === 'refused' ? `The artifact receiver refused this list${view.reason ? `: ${view.reason}` : ''}.`
        : view.status === 'unavailable' ? 'Retained cookies are read from the local backend, not from a file.'
          : `Could not read the retained list: ${view.error}.`));
    return {section: details, key};
  }
  if (!view) return {section: details, key};
  let cookies = view.cookies;
  if (!received) {
    const filtered = cookies.filter(cookie => cookie.blocked).length;
    const label = trafficNode('label', 'traffic-cookie-filter');
    const box = trafficNode('input');
    box.type = 'checkbox';
    box.checked = trafficCookieOptions.showFiltered;
    box.addEventListener('change', () => {
      trafficCookieOptions.showFiltered = box.checked;
      box.dispatchEvent(new CustomEvent('traffic-cookie-change', {bubbles: true}));
    });
    label.append(box, ` Show filtered out request cookies (${filtered})`);
    details.append(label);
    if (!trafficCookieOptions.showFiltered) cookies = cookies.filter(cookie => !cookie.blocked);
    key += `|${trafficCookieOptions.showFiltered}`;
  }
  key += `|${JSON.stringify(trafficCookieOptions.sort.get(id) ?? null)}`;
  details.append(cookies.length ? trafficCookieTable(id, title, cookies, {received, onProvenance})
    : trafficNode('p', 'traffic-headers-note', received ? 'No Set-Cookie in this response.' : 'This request sent no cookies.'));
  return {section: details, key};
}

function trafficCookieHops(request) {
  const hops = new Map();
  for (const list of request?.cookieLists ?? []) {
    if (list.malformed) continue;
    if (!hops.has(list.hop)) hops.set(list.hop, {hop: list.hop, sent: [], received: []});
    hops.get(list.hop)[list.direction].push(list);
  }
  return [...hops.values()].sort((left, right) => left.hop - right.hop);
}

// Everything the loaded evidence says about one name: Set-Cookie responses,
// script calls and the requests that sent it. Lists load on demand, at most
// TRAFFIC_COOKIE_PROVENANCE_LISTS distinct ones.
function trafficCookieProvenance(name, {requests = [], events = [], selectRequest, openFrame} = {}, rerender) {
  const section = trafficNode('section', 'traffic-cookie-provenance');
  section.setAttribute('aria-label', `Provenance of ${name}`);
  const heading = trafficNode('div', 'traffic-cookie-provenance-head');
  heading.append(trafficNode('h2', '', `Provenance of ${name}`));
  const close = trafficNode('button', 'secondary-button', 'Close');
  close.type = 'button';
  close.addEventListener('click', () => {
    trafficCookieOptions.provenance = null;
    close.dispatchEvent(new CustomEvent('traffic-cookie-change', {bubbles: true}));
  });
  heading.append(close);
  section.append(heading);
  const bytes = new TextEncoder().encode(name);
  const prefix = Array.from(bytes.slice(0, 24), byte => byte.toString(16).padStart(2, '0')).join('');
  const scripts = events.map(event => event?.type === 'script_cookie' && typeof decodeScriptCookieRecord === 'function'
    ? decodeScriptCookieRecord(event) : null)
    .filter(record => record && record.nameLength === bytes.length && record.namePrefixHex === prefix);
  const setBy = [], sentWith = [];
  const lists = new Set();
  let unread = 0, loading = 0;
  for (const request of requests) {
    for (const list of request.cookieLists ?? []) {
      if (list.malformed || !['captured', 'captured_shared'].includes(list.state)) continue;
      const listKey = `${list.sessionId}:${list.artifactId}`;
      if (!lists.has(listKey) && lists.size >= TRAFFIC_COOKIE_PROVENANCE_LISTS) {
        unread += 1;
        continue;
      }
      lists.add(listKey);
      const view = trafficCookieView(list, rerender);
      if (view?.status === 'loading') loading += 1;
      if (view?.status !== 'ready') continue;
      for (const cookie of view.cookies.filter(item => item.parsed && item.name === name)) {
        (list.direction === 'received' ? setBy : sentWith).push({request, list, cookie});
      }
    }
  }
  const entry = (text, request) => {
    const item = trafficNode('li', '', text);
    if (request && selectRequest) {
      const open = trafficNode('button', 'traffic-cookie-request', 'Show request');
      open.type = 'button';
      open.addEventListener('click', () => selectRequest(request.id));
      item.append(' ', open);
    }
    return item;
  };
  const group = (title, items, empty) => {
    section.append(trafficNode('h3', '', `${title} (${items.length})`));
    const list = trafficNode('ul', 'traffic-cookie-provenance-list');
    list.append(...(items.length ? items : [trafficNode('li', 'traffic-headers-note', empty)]));
    section.append(list);
  };
  const where = (request, list) => `${request.method ?? ''} ${request.path ?? request.id}${list.hop ? ` · hop ${list.hop}` : ''}`.trim();
  group('Set by responses', setBy.map(({request, list, cookie}) => entry(
    `${where(request, list)}${cookie.blocked ? ` — ${trafficCookieBlockedText(cookie, true)}` : ''}`, request)),
  'No retained response set it.');
  const sessionId = scripts.find(record => record.frame)?.sessionId;
  const frames = sessionId ? trafficCookieCallFrames(sessionId, name, rerender) : null;
  group('Script access', scripts.map(record => {
    const resolved = record.frame ? frames?.get(`${record.processId}:${record.sequenceNumber}`) : null;
    const item = entry(`${record.api}${record.count > 1 ? ` × ${record.count}` : ''} in frame ${record.frameId}` +
      `${resolved ? ` at ${trafficCookieFrameLabel(resolved)}` : record.frame ? `, script ${record.frame.scriptId} at character ${record.frame.position}` : ', no script position'}` +
      `${record.stackDigest ? `, stack ${record.stackDigest.slice(0, 12)}` : ''}${record.nameTruncated ? ' (name matched by its first 24 bytes)' : ''}`);
    if (resolved?.artifact_id && openFrame) {
      const open = trafficNode('button', 'traffic-cookie-request', 'Show in Sources');
      open.type = 'button';
      open.addEventListener('click', () => openFrame(resolved));
      item.append(' ', open);
    }
    return item;
  }), 'No recorded document.cookie or Cookie Store call used this name.');
  const writes = new Map(scripts.filter(record => record.write).map(record => [record.valueSha256, record]));
  group('Sent with requests', sentWith.map(({request, list, cookie}) => {
    const write = cookie.valueSha256 ? writes.get(cookie.valueSha256) : null;
    return entry(`${where(request, list)}${cookie.blocked ? ` — ${trafficCookieBlockedText(cookie, false)}`
      : write ? ` — the value ${write.api} wrote` : ''}`, request);
  }), 'No retained request sent it.');
  const notes = [loading ? `Loading ${loading} cookie list${loading === 1 ? '' : 's'}…` : '',
    unread ? `${unread} cookie list${unread === 1 ? ' was' : 's were'} not read past the ${TRAFFIC_COOKIE_PROVENANCE_LISTS}-list limit.` : '']
    .filter(Boolean);
  if (notes.length) section.append(trafficNode('p', 'traffic-headers-note', notes.join(' ')));
  return {section, key: JSON.stringify([name, setBy.length, sentWith.length, scripts.length, loading, unread, frames?.size ?? null])};
}

const trafficCookieRerenders = new WeakMap();

function renderTrafficCookies(container, request, rerender, context = {}) {
  if (!trafficCookieRerenders.has(container)) {
    container.addEventListener('traffic-cookie-change', () => {
      container.dataset.renderKey = '';
      trafficCookieRerenders.get(container)?.();
    });
  }
  trafficCookieRerenders.set(container, rerender);
  if (!request) {
    container.replaceChildren(trafficNode('div', 'exchange-no-selection', 'Select a request to inspect its cookies.'));
    container.dataset.renderKey = '';
    return;
  }
  const onProvenance = name => {
    trafficCookieOptions.provenance = name;
    container.dataset.renderKey = '';
    rerender?.();
  };
  const hops = trafficCookieHops(request);
  const parts = [];
  const malformed = (request.cookieLists ?? []).filter(list => list.malformed).length;
  let message = '';
  if (!Array.isArray(request.cookieLists)) message = 'This row has no native cookie record.';
  else if (!hops.length && !malformed) message = request.hostOnly
    ? 'Cookies are recorded only in content capture sessions.' : 'No cookie list was retained for this request.';
  if (malformed) message = `${message} ${malformed} cookie record${malformed === 1 ? ' is' : 's are'} malformed and not shown.`.trim();
  for (const hop of [...hops].reverse()) {
    const suffix = hops.length > 1 ? ` · hop ${hop.hop}` : '';
    hop.received.forEach((list, index) => parts.push(trafficCookieSection(`received-${hop.hop}-${index}`,
      `Response cookies${suffix}`, list, rerender, {received: true, onProvenance})));
    hop.sent.forEach((list, index) => parts.push(trafficCookieSection(`sent-${hop.hop}-${index}`,
      `Request cookies${suffix}`, list, rerender, {received: false, onProvenance})));
  }
  if (trafficCookieOptions.provenance !== null) parts.unshift(trafficCookieProvenance(trafficCookieOptions.provenance, context, rerender));
  const key = JSON.stringify([request.origin, request.id, message, parts.map(part => part.key)]);
  if (container.dataset.renderKey === key) return;
  container.dataset.renderKey = key;
  const nodes = parts.map(part => part.section);
  if (message) nodes.unshift(trafficNode('p', 'traffic-headers-note', message));
  container.replaceChildren(...nodes);
}

if (typeof module === 'object' && module?.exports) module.exports = {trafficCookieList, trafficCookieHops, renderTrafficCookies};
