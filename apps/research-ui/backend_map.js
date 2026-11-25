/* Backend: the session's guessed backend, from get_backend_map
 * (reb-backend-map-v1, protocol/http-api.md "Backend map"). Stack lists each
 * technology by category with its confidence and the signals it rests on;
 * Hosts lists every host with its role, addresses and route templates. Every
 * name, token and host in the map comes from captured traffic, so all of it
 * is inserted as text. Evidence buttons open the Traffic row they cite. The
 * map is read when the screen opens and on Refresh, and a failed read keeps
 * the last map on screen. */
const BACKEND_MAP_FORMAT = 'reb-backend-map-v1';
/* Detail tokens a Stack row shows before the rest go to its detail pane. */
const BACKEND_MAP_ROW_TOKENS = 2;
const BACKEND_MAP_ROLE = {
  document: 'Document', api: 'First-party API', third_party_api: 'Third-party API', static: 'Static assets',
  first_party: 'First party', third_party: 'Third party'
};
const BACKEND_MAP_STYLE = {
  websocket: 'WebSocket', server_sent_events: 'SSE', grpc_web: 'gRPC-Web', connect: 'Connect', graphql: 'GraphQL',
  trpc: 'tRPC', react_server_components: 'RSC', json: 'JSON', document: 'Document', form: 'Form', other: 'Other'
};
const BACKEND_MAP_SIGNAL = {
  response_header: 'Response header', response_header_prefix: 'Response headers', request_header: 'Request header',
  request_header_prefix: 'Request headers', cookie: 'Cookie name', host: 'Host', path: 'Path', query_key: 'Query name',
  body: 'Response body', request_body: 'Request body', remote_address: 'Remote address', protocol: 'Protocol'
};

const BACKEND_MAP_SCOPE = {
  site: {label: 'Site stack', note: 'Seen on the site\'s own hosts, or implied by something that was'},
  service: {label: 'Services the site uses', note: 'Backend, auth, storage and third-party services seen on their vendors\' hosts'},
  vendor: {label: 'Vendor infrastructure', note: 'How a third party serves its own hosts; it describes the vendor, not the site'}
};

/** A map this view can read: the declared format and every list it walks. */
function isBackendMap(map) {
  return map?.format === BACKEND_MAP_FORMAT && Array.isArray(map.technologies) && Array.isArray(map.hosts) &&
    Array.isArray(map.declared_hosts) && map.coverage && typeof map.coverage === 'object' && Array.isArray(map.limitations);
}

/** One line on what the map covers, and whether it can say much at all. */
function backendMapCoverage(map) {
  const c = map.coverage;
  const n = value => Number(value || 0).toLocaleString();
  const parts = [`${n(c.rows)} requests`, `${n(c.entries_with_response_headers)} with response headers`,
    `${n(c.response_bodies_read)} bodies read`];
  let kind = 'ready';
  let note = '';
  if (!c.rows) {
    kind = 'empty';
    note = 'No requests are captured yet. Load the site in the live session, then refresh.';
  } else if (!c.entries_with_response_headers && !c.entries_with_urls) {
    kind = 'limited';
    note = 'This session kept no URLs or headers (Metadata only), so only hosts and remote addresses are read.';
  } else if (!c.entries_with_response_headers) {
    kind = 'limited';
    note = 'No response headers were captured, so header signals cannot match.';
  }
  if (!c.complete) {
    kind = kind === 'ready' ? 'partial' : kind;
    note = `${note ? `${note} ` : ''}The request index is still catching up; refresh for the rest.`;
  }
  return {kind, text: parts.join(' · '), note};
}

/** Rows of the Stack list, grouped by scope in the map's order (site,
 * service, vendor), each in category order. */
function backendMapGroups(map) {
  const groups = [];
  for (const technology of map.technologies) {
    const scope = BACKEND_MAP_SCOPE[technology.scope] ? technology.scope : 'vendor';
    let group = groups.at(-1);
    if (!group || group.scope !== scope) {
      group = {scope, label: BACKEND_MAP_SCOPE[scope].label, note: BACKEND_MAP_SCOPE[scope].note, items: []};
      groups.push(group);
    }
    group.items.push(technology);
  }
  return groups;
}

function backendMapBasis(technology) {
  if (technology.basis === 'implied') return 'implied';
  if (technology.basis === 'declared') return 'declared';
  return technology.strongest_tier === 'vendor' ? 'marker' : 'convention';
}

function backendMapTokens(technology) {
  const out = [];
  for (const [name, values] of Object.entries(technology.details || {})) {
    for (const value of values) out.push({name, value: value.value, count: value.count});
  }
  return out;
}

function createBackendMapPanel({root, openRow, openArtifact = () => {}}) {
  if (!root) return {setVisible() {}, refresh() {}, map: () => null};
  const $ = selector => root.querySelector(selector);
  const status = $('.backend-map-status');
  const notice = $('.backend-map-notice');
  const refreshButton = $('.backend-map-refresh');
  const tabs = [...root.querySelectorAll('[data-backend-tab]')];
  const panels = {stack: $('#backend-panel-stack'), hosts: $('#backend-panel-hosts')};
  const partyButtons = [...root.querySelectorAll('[data-backend-party]')];
  let map = null, tag = null, visible = false, controller = null, loading = false;
  let tab = 'stack', party = 'all', selectedTechnology = null, selectedHost = null;

  const element = (tagName, className, text) => {
    const node = document.createElement(tagName);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };
  const button = (className, text, onClick, title) => {
    const node = element('button', className, text);
    node.type = 'button';
    if (title) node.title = title;
    node.addEventListener('click', onClick);
    return node;
  };
  const setData = (node, key, value) => { if (node.dataset) node.dataset[key] = value; };

  function say(kind, text) {
    setData(notice, 'kind', kind);
    notice.textContent = text;
    notice.hidden = !text;
  }

  // Up and Down move between a list's buttons, as the Traffic list does.
  function arrowList(list) {
    list.addEventListener('keydown', event => {
      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
      const items = [...list.querySelectorAll('.backend-map-item')];
      const index = items.indexOf(document.activeElement);
      if (index < 0) return;
      const next = items[index + (event.key === 'ArrowDown' ? 1 : -1)];
      if (!next) return;
      event.preventDefault();
      next.focus();
      next.click();
    });
  }

  // A citation: the row, hop and header it rests on, and the hop's time, or
  // the script artifact it was read from.
  function evidenceButton(place, label, compact = false) {
    if (place.artifact_id !== undefined) {
      return button('backend-map-evidence', `${label ? `${label} ` : ''}script artifact ${place.artifact_id}`,
        () => openArtifact(place.artifact_id), `Open artifact ${place.artifact_id} in Sources (SHA-256 ${place.sha256})`);
    }
    const where = compact ? `row ${place.row_id}` : `row ${place.row_id} · hop ${place.hop}${place.header ? ` · ${place.header}` : ''}`;
    return button('backend-map-evidence', label ? `${label} ${where}` : where, () => openRow(place.row_id),
      `Open ${place.row_id} in Traffic (request ${place.request_id}, hop ${place.hop}${place.header ? `, ${place.header}` : ''}, at ${place.time_ns} ns)`);
  }

  function technologyRow(technology) {
    const item = button('backend-map-item', null, () => { selectedTechnology = technology.id; renderStack(); focusSelected('stack'); });
    setData(item, 'technology', technology.id);
    setData(item, 'basis', technology.basis);
    item.setAttribute('aria-pressed', String(technology.id === selectedTechnology));
    const name = element('span', 'backend-map-name', technology.name);
    const confidence = element('span', 'backend-map-confidence', `${technology.confidence}`);
    confidence.title = 'Confidence: the sum of the distinct signals\' reviewed weights, capped at 100. Not a probability.';
    const meta = element('span', 'backend-map-meta');
    meta.append(element('span', 'backend-map-category', technology.category_label || technology.category));
    const basis = element('span', 'backend-map-badge', backendMapBasis(technology));
    setData(basis, 'basis', backendMapBasis(technology));
    meta.append(basis);
    if (technology.party !== 'implied') meta.append(element('span', 'backend-map-side', technology.party === 'first_party' ? '1st party' : technology.party === 'mixed' ? 'mixed' : '3rd party'));
    for (const token of backendMapTokens(technology).slice(0, BACKEND_MAP_ROW_TOKENS)) {
      meta.append(element('span', 'backend-map-token', token.value));
    }
    item.append(name, confidence, meta);
    return item;
  }

  function technologyDetail(technology) {
    const pane = element('div', 'backend-map-detail-body');
    pane.append(element('h2', 'backend-map-detail-title', technology.name));
    const facts = element('dl', 'backend-map-facts');
    const fact = (label, value) => { facts.append(element('dt', null, label), element('dd', null, value)); };
    fact('Category', technology.category_label || technology.category);
    fact('Confidence', `${technology.confidence} of 100 · ${technology.basis === 'implied' ? 'implied, not seen directly'
      : technology.basis === 'declared' ? 'only declared: named in a policy, CORS header or body, not contacted' : 'seen directly'}`);
    fact('Scope', BACKEND_MAP_SCOPE[technology.scope]?.label ?? technology.scope);
    if (technology.implied_by.length) fact('Implied by', technology.implied_by.map(id => map.technologies.find(item => item.id === id)?.name ?? id).join(', '));
    if (technology.hosts.length) fact('Hosts', technology.hosts.join(', '));
    const tokens = backendMapTokens(technology);
    if (tokens.length) fact('Captured', tokens.map(token => `${token.name.replaceAll('_', ' ')} ${token.value} ×${token.count}`).join(', '));
    pane.append(facts);
    if (!technology.signals.length) {
      pane.append(element('p', 'backend-map-none', 'No signal of its own matched; it is listed because a matched technology implies it.'));
    }
    for (const signal of technology.signals) {
      const block = element('section', 'backend-map-signal');
      setData(block, 'tier', signal.tier);
      const head = element('div', 'backend-map-signal-head');
      head.append(element('span', 'backend-map-signal-on', BACKEND_MAP_SIGNAL[signal.on] ?? signal.on),
        element('span', 'backend-map-badge', signal.tier === 'vendor' ? 'marker' : 'convention'),
        element('span', 'backend-map-weight', `weight ${signal.weight}`));
      block.append(head, element('p', 'backend-map-signal-text', signal.description));
      for (const host of signal.hosts) {
        const line = element('div', 'backend-map-signal-host');
        setData(line, 'declared', String(Boolean(host.declared)));
        line.append(element('span', 'backend-map-host-name', host.host));
        if (host.declared) line.append(element('span', 'backend-map-badge', 'declared'));
        else line.append(element('span', 'backend-map-count', `×${host.count}`));
        line.append(evidenceButton(host.first, host.declared ? 'Named in' : 'First'));
        if (host.last) line.append(evidenceButton(host.last, 'Last'));
        block.append(line);
      }
      pane.append(block);
    }
    if (technology.references.length) {
      const refs = element('p', 'backend-map-refs', `Reviewed against: ${technology.references.join(' · ')}`);
      pane.append(refs);
    }
    return pane;
  }

  function renderStack() {
    const list = $('.backend-map-stack-list');
    const detail = $('.backend-map-stack-detail');
    list.replaceChildren();
    detail.replaceChildren();
    const groups = backendMapGroups(map);
    const shown = groups.flatMap(group => group.items);
    if (!shown.some(item => item.id === selectedTechnology)) selectedTechnology = shown[0]?.id ?? null;
    if (!shown.length) {
      list.append(element('p', 'backend-map-none', 'No signal matched. Absence is not evidence: the site may hide its stack or the capture may lack headers.'));
    }
    for (const group of groups) {
      const section = element('div', 'backend-map-group');
      section.setAttribute('role', 'group');
      section.setAttribute('aria-label', group.label);
      const title = element('h3', 'backend-map-group-title', `${group.label} (${group.items.length})`);
      title.title = group.note;
      section.append(title);
      for (const technology of group.items) section.append(technologyRow(technology));
      list.append(section);
    }
    const technology = map.technologies.find(item => item.id === selectedTechnology);
    if (technology) detail.append(technologyDetail(technology));
    else detail.append(element('p', 'backend-map-none', 'Select a technology to see the evidence it rests on.'));
  }

  function counts(object, labels = null) {
    return Object.entries(object || {}).sort((a, b) => b[1] - a[1])
      .map(([key, count]) => `${labels?.[key] ?? key} ${count.toLocaleString()}`).join(' · ') || 'none';
  }

  function hostRow(host) {
    const item = button('backend-map-item', null, () => { selectedHost = host.host; renderHosts(); focusSelected('hosts'); });
    setData(item, 'host', host.host);
    setData(item, 'party', host.party);
    item.setAttribute('aria-pressed', String(host.host === selectedHost));
    const meta = element('span', 'backend-map-meta');
    meta.append(element('span', 'backend-map-badge', BACKEND_MAP_ROLE[host.role] ?? host.role));
    for (const id of host.technologies.slice(0, 3)) meta.append(element('span', 'backend-map-token', map.technologies.find(item => item.id === id)?.name ?? id));
    item.append(element('span', 'backend-map-name', host.host), element('span', 'backend-map-confidence', host.entries.toLocaleString()), meta);
    item.title = `${host.host}: ${host.entries} entries`;
    return item;
  }

  function hostDetail(host) {
    const pane = element('div', 'backend-map-detail-body');
    pane.append(element('h2', 'backend-map-detail-title', host.host));
    const facts = element('dl', 'backend-map-facts');
    const fact = (label, value) => { facts.append(element('dt', null, label), element('dd', null, value)); };
    fact('Role', `${BACKEND_MAP_ROLE[host.role] ?? host.role} · ${host.party === 'first_party' ? 'first party' : 'third party'}${host.site ? ` (${host.site})` : ''}`);
    fact('Requests', `${host.rows.toLocaleString()} rows · ${host.entries.toLocaleString()} hops · ${host.entries_with_response_headers.toLocaleString()} with response headers`);
    fact('Methods', counts(host.methods));
    fact('Statuses', counts(host.statuses));
    fact('Protocols', counts(host.protocols));
    fact('API styles', counts(host.api_styles, BACKEND_MAP_STYLE));
    fact('Addresses', host.addresses.length
      ? host.addresses.map(address => `${address.address}${address.ranges.length ? ` (${address.ranges.join(', ')})` : ''} ×${address.count}`).join(', ')
      : 'none captured');
    if (host.technologies.length) fact('Technologies', host.technologies.map(id => map.technologies.find(item => item.id === id)?.name ?? id).join(', '));
    if (host.cors.exposed.length) fact('CORS exposes', host.cors.exposed.join(', '));
    if (host.cors.allowed.length) fact('CORS accepts', host.cors.allowed.join(', '));
    if (host.cors.requested.length) fact('Page asked to send', host.cors.requested.join(', '));
    pane.append(facts);
    pane.append(element('h3', 'backend-map-group-title', `Routes (${host.routes.length.toLocaleString()})`));
    if (!host.routes.length) pane.append(element('p', 'backend-map-none', 'No non-static request with a known path.'));
    else {
      const table = element('table', 'backend-map-routes');
      const head = element('tr');
      for (const label of ['Method', 'Route', 'Server route', 'Style', 'Count', 'Statuses', 'Query names', 'Evidence']) head.append(element('th', null, label));
      const thead = element('thead');
      thead.append(head);
      table.append(thead);
      const bodyRows = element('tbody');
      for (const route of host.routes) {
        const tr = element('tr');
        setData(tr, 'style', route.api_style);
        const evidence = element('td');
        if (route.first) evidence.append(evidenceButton(route.first, null, true));
        tr.append(element('td', 'backend-map-method', route.method), element('td', 'backend-map-template', route.template),
          element('td', 'backend-map-template', route.matched_paths.join(', ')),
          element('td', null, BACKEND_MAP_STYLE[route.api_style] ?? route.api_style), element('td', 'backend-map-number', route.count.toLocaleString()),
          element('td', null, counts(route.statuses)), element('td', 'backend-map-template', route.query_keys.join(', ')), evidence);
        bodyRows.append(tr);
      }
      table.append(bodyRows);
      const wrap = element('div', 'backend-map-table-wrap');
      wrap.tabIndex = 0;
      wrap.setAttribute('role', 'region');
      wrap.setAttribute('aria-label', `Routes of ${host.host}`);
      wrap.append(table);
      pane.append(wrap);
    }
    if (host.static.count) {
      pane.append(element('h3', 'backend-map-group-title', `Static assets (${host.static.count.toLocaleString()})`));
      pane.append(element('p', 'backend-map-template', host.static.prefixes.map(prefix => `${prefix.prefix} ×${prefix.count}`).join(' · ')));
    }
    return pane;
  }

  function declaredRow(declared) {
    const item = button('backend-map-item', null, () => { selectedHost = `declared:${declared.host}`; renderHosts(); focusSelected('hosts'); });
    setData(item, 'host', declared.host);
    setData(item, 'declared', 'true');
    item.setAttribute('aria-pressed', String(`declared:${declared.host}` === selectedHost));
    const meta = element('span', 'backend-map-meta');
    for (const source of declared.sources.slice(0, 3)) meta.append(element('span', 'backend-map-badge', source));
    for (const id of declared.technologies.slice(0, 2)) meta.append(element('span', 'backend-map-token', map.technologies.find(item => item.id === id)?.name ?? id));
    item.append(element('span', 'backend-map-name', `${declared.wildcard ? '*.' : ''}${declared.host}`), element('span', 'backend-map-confidence', 'named'), meta);
    return item;
  }

  function declaredDetail(declared) {
    const pane = element('div', 'backend-map-detail-body');
    pane.append(element('h2', 'backend-map-detail-title', `${declared.wildcard ? '*.' : ''}${declared.host}`));
    const facts = element('dl', 'backend-map-facts');
    const fact = (label, value) => { facts.append(element('dt', null, label), element('dd', null, value)); };
    fact('Named by', declared.sources.join(', '));
    fact('Party', declared.party === 'first_party' ? 'first party' : 'third party');
    fact('Contacted', declared.contacted ? 'yes, this session also sent it requests' : 'no request to it was captured');
    if (declared.technologies.length) fact('Points at', declared.technologies.map(id => map.technologies.find(item => item.id === id)?.name ?? id).join(', '));
    pane.append(facts, element('p', 'backend-map-none', 'A policy, Link or CORS header, or a URL in a body, says the site may use this host. It is not evidence the backend called it.'));
    const where = element('div', 'backend-map-signal-host');
    where.append(evidenceButton(declared.first, 'Named in'));
    pane.append(where);
    return pane;
  }

  function renderHosts() {
    const list = $('.backend-map-host-list');
    const detail = $('.backend-map-host-detail');
    list.replaceChildren();
    detail.replaceChildren();
    const hosts = map.hosts.filter(host => party === 'all' || host.party === party);
    const declared = map.declared_hosts.filter(host => !host.contacted && (party === 'all' || host.party === party));
    const keys = [...hosts.map(host => host.host), ...declared.map(host => `declared:${host.host}`)];
    if (!keys.includes(selectedHost)) selectedHost = keys[0] ?? null;
    if (!keys.length) list.append(element('p', 'backend-map-none', map.hosts.length ? 'No host matches this party filter.' : 'No hosts yet.'));
    if (hosts.length) {
      const section = element('div', 'backend-map-group');
      section.setAttribute('role', 'group');
      section.setAttribute('aria-label', 'Contacted hosts');
      section.append(element('h3', 'backend-map-group-title', `Contacted (${hosts.length})`));
      for (const host of hosts) section.append(hostRow(host));
      list.append(section);
    }
    if (declared.length) {
      const section = element('div', 'backend-map-group');
      section.setAttribute('role', 'group');
      section.setAttribute('aria-label', 'Named but not contacted');
      const title = element('h3', 'backend-map-group-title', `Named, not contacted (${declared.length})`);
      title.title = 'Hosts a CSP, Report-To, NEL, Link or CORS header, or a URL in a body, names without a captured request to them';
      section.append(title);
      for (const host of declared) section.append(declaredRow(host));
      list.append(section);
    }
    if (selectedHost?.startsWith('declared:')) {
      const found = map.declared_hosts.find(item => `declared:${item.host}` === selectedHost);
      if (found) detail.append(declaredDetail(found));
    } else {
      const host = map.hosts.find(item => item.host === selectedHost);
      if (host) detail.append(hostDetail(host));
      else detail.append(element('p', 'backend-map-none', 'Select a host to see its routes.'));
    }
  }

  function focusSelected(which) {
    const list = which === 'stack' ? $('.backend-map-stack-list') : $('.backend-map-host-list');
    list.querySelector('.backend-map-item[aria-pressed="true"]')?.focus({preventScroll: false});
  }

  function render() {
    for (const node of tabs) {
      const selected = node.dataset.backendTab === tab;
      node.setAttribute('aria-selected', String(selected));
      node.tabIndex = selected ? 0 : -1;
    }
    for (const [name, panel] of Object.entries(panels)) panel.hidden = name !== tab;
    for (const node of partyButtons) node.setAttribute('aria-pressed', String(node.dataset.backendParty === party));
    const partyGroup = root.querySelector('.backend-map-party');
    if (partyGroup) partyGroup.hidden = tab !== 'hosts';
    if (!map) return;
    const coverage = backendMapCoverage(map);
    const seen = map.technologies.filter(item => item.basis === 'direct').length;
    const site = map.technologies.filter(item => item.scope === 'site').length;
    status.textContent = `${seen.toLocaleString()} seen · ${site.toLocaleString()} in the site stack · ${coverage.text}`;
    setData(status, 'kind', coverage.kind);
    if (!loading) say(coverage.kind === 'ready' ? 'ready' : coverage.kind, coverage.note);
    if (tab === 'stack') renderStack();
    else renderHosts();
    const limits = $('.backend-map-limits');
    if (limits && limits.dataset?.digest !== map.rule_set?.sha256) {
      limits.replaceChildren(...map.limitations.map(text => element('li', null, text)));
      setData(limits, 'digest', map.rule_set?.sha256 ?? '');
      $('.backend-map-rules').textContent = `Rules ${map.rule_set.format} reviewed ${map.rule_set.reviewed}: ${map.rule_set.technologies} technologies, ${map.rule_set.signals} signals. Address ranges retrieved ${map.rule_set.ranges.retrieved}. No request is sent and nothing is looked up.`;
    }
  }

  async function refresh() {
    controller?.abort();
    const current = new AbortController();
    controller = current;
    loading = true;
    refreshButton.disabled = true;
    root.setAttribute('aria-busy', 'true');
    if (!map) say('loading', 'Reading every captured request…');
    try {
      const headers = tag ? {'If-None-Match': tag} : {};
      const response = await fetch('/api/backend-map', {cache: 'no-store', headers, signal: current.signal});
      if (current.signal.aborted) return;
      if (response.status === 304 && map) {
        loading = false;
        render();
        return;
      }
      const body = await response.json().catch(() => null);
      if (!response.ok) throw new Error(body?.error || `the backend answered ${response.status}`);
      if (!isBackendMap(body)) throw new Error('the answer is not a reb-backend-map-v1 document');
      map = body;
      tag = response.headers.get('etag');
      loading = false;
      render();
    } catch (error) {
      if (current.signal.aborted) return;
      loading = false;
      // The last map stays; the notice says it is older than the store.
      say('error', map ? `Refresh failed (${error.message}); showing the previous map.` : `The backend map could not be read: ${error.message}.`);
    } finally {
      if (controller === current) {
        loading = false;
        refreshButton.disabled = false;
        root.removeAttribute('aria-busy');
        controller = null;
      }
    }
  }

  tabs.forEach((node, index) => {
    node.addEventListener('click', () => { tab = node.dataset.backendTab; render(); });
    node.addEventListener('keydown', event => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
      event.preventDefault();
      const next = tabs[(index + (event.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
      tab = next.dataset.backendTab;
      render();
      next.focus();
    });
  });
  partyButtons.forEach(node => node.addEventListener('click', () => { party = node.dataset.backendParty; render(); }));
  refreshButton.addEventListener('click', () => refresh());
  arrowList($('.backend-map-stack-list'));
  arrowList($('.backend-map-host-list'));

  return {
    setVisible(next) {
      const opened = next && !visible;
      visible = next;
      if (!next) { controller?.abort(); return; }
      if (opened) refresh();
    },
    refresh,
    map: () => map
  };
}

if (typeof module === 'object' && module?.exports) module.exports = {isBackendMap, backendMapCoverage, backendMapGroups, backendMapTokens, createBackendMapPanel};
