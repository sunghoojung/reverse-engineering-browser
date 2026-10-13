/* Explicit cold-path catalog reads. Never derive identity from displayed URL,
 * native correlation, rounded timestamps, or a reusable CDP protocol ID. */
function apiCatalogIdentity(coverage, source) {
  const bounded = (value, max) => typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= max;
  if (!bounded(coverage?.instance_id, 128) || !Number.isSafeInteger(coverage?.capture_epoch) || coverage.capture_epoch < 0 ||
      !bounded(source?.request_id, 8192) || !bounded(source?.target_id, 4096) ||
      typeof source?.started_monotonic_ms !== 'number' || !Number.isFinite(source.started_monotonic_ms) || source.started_monotonic_ms < 0) return null;
  return {instance: coverage.instance_id, epoch: coverage.capture_epoch, request: source.request_id,
    target: source.target_id, started: source.started_monotonic_ms};
}
function apiCatalogRequestIdentity(request) {
  const record = request?.captureRecord, owner = request?.captureOwner;
  if (!record || !Array.isArray(owner) || owner.length !== 2 || request.id !== record.id || request.tabId !== record.target_id) return null;
  return apiCatalogIdentity({instance_id: owner[0], capture_epoch: owner[1]},
    {request_id: record.id, target_id: record.target_id, started_monotonic_ms: record.started_monotonic_ms});
}
function apiCatalogResolveSource(identity, requests) {
  const unavailable = message => ({record: null, message});
  if (!identity) return unavailable('Exact source identity is unavailable.');
  const candidates = requests.filter(request => {
    const current = apiCatalogRequestIdentity(request);
    return current && ['instance', 'epoch', 'request', 'target', 'started'].every(key => current[key] === identity[key]);
  });
  if (candidates.length !== 1 || requests.filter(request => request.id === identity.request).length !== 1) {
    return unavailable(candidates.length ? 'Source is ambiguous in Traffic. Nothing was opened.' : 'Source is not retained in the current Traffic window, or its instance, epoch or start changed.');
  }
  return {record: candidates[0], message: 'Exact captured source is retained. Open it for raw values, Field trace or Save to Collection.'};
}

function isApiObservationCatalog(value) {
  const object = item => item !== null && typeof item === 'object' && !Array.isArray(item);
  const keys = (item, names) => object(item) && Object.keys(item).length === names.length && names.every(key => Object.hasOwn(item, key));
  const text = (item, max) => typeof item === 'string' && item.length <= max && new TextEncoder().encode(item).length <= max;
  const count = (item, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(item) && item >= 0 && item <= max;
  const list = (item, max, check) => Array.isArray(item) && item.length <= max && item.every(check);
  const names = item => list(item, 64, name => text(name, 256)) && new Set(item).size === item.length;
  const types = ['array', 'boolean', 'null', 'number', 'object', 'string'];
  const shape = item => {
    if (!keys(item, ['root_type', 'node_count', 'max_depth_observed', 'properties']) || !types.includes(item.root_type) ||
        !count(item.node_count, 2048) || !item.node_count || !count(item.max_depth_observed, 16)) return false;
    let pathBytes = 0;
    const paths = new Set();
    return list(item.properties, 64, field => {
      if (!keys(field, ['path', 'types', 'observations']) || !count(field.observations, 2048) || !field.observations ||
          !list(field.types, 6, type => types.includes(type)) || !field.types.length || new Set(field.types).size !== field.types.length ||
          !list(field.path, 16, part => keys(part, ['kind']) && part.kind === 'array-element' ||
            keys(part, ['kind', 'name']) && part.kind === 'property' && text(part.name, 256)) || !field.path.length) return false;
      pathBytes += new TextEncoder().encode(JSON.stringify(field.path)).length;
      const key = apiCatalogPathKey(field.path);
      if (paths.has(key)) return false;
      paths.add(key);
      return pathBytes <= 16384;
    });
  };
  const side = item => {
    if (!keys(item, ['header_names', 'header_names_omitted', 'headers_truncated', 'body']) || !names(item.header_names) ||
        !count(item.header_names_omitted) || typeof item.headers_truncated !== 'boolean') return false;
    const body = item.body;
    if (!keys(body, ['state', 'mime', 'status', 'reason', 'shape']) || !text(body.state, 32) || !text(body.mime, 512)) return false;
    return body.status === 'observed' ? body.reason === null && shape(body.shape) : body.status === 'unavailable' && body.shape === null &&
      ['body_unavailable', 'body_truncated', 'base64_not_analyzed', 'not_json_media_type', 'body_byte_limit', 'malformed_json', 'duplicate_json_key', 'shape_resource_limit'].includes(body.reason);
  };
  if (!keys(value, ['format', 'coverage', 'limits', 'endpoints', 'limitations']) || value.format !== 'reb-api-observation-catalog-v1') return false;
  const coverage = value.coverage;
  if (!keys(coverage, ['instance_id', 'capture_epoch', 'debugger_generation', 'capture_enabled', 'debugger_state', 'retained_records',
    'window_records', 'older_records_not_examined', 'capture_dropped_records', 'skipped_records']) || !text(coverage.instance_id, 128) ||
    !count(coverage.capture_epoch) || !count(coverage.debugger_generation) || typeof coverage.capture_enabled !== 'boolean' || !text(coverage.debugger_state, 32) ||
    !count(coverage.retained_records, 1000) || !count(coverage.window_records, 64) || !count(coverage.older_records_not_examined) ||
    !count(coverage.capture_dropped_records) || !count(coverage.skipped_records, coverage.window_records) ||
    coverage.window_records + coverage.older_records_not_examined !== coverage.retained_records) return false;
  const limits = {records: 64, url_bytes: 8192, body_bytes: 32768, names_per_surface: 64, name_bytes: 256,
    shape_nodes: 2048, shape_depth: 16, shape_fields: 64, shape_path_bytes: 16384};
  if (!keys(value.limits, Object.keys(limits)) || !Object.entries(limits).every(([key, expected]) => value.limits[key] === expected) ||
      !list(value.limitations, 8, item => text(item, 2048))) return false;
  let observations = 0;
  return list(value.endpoints, 64, endpoint => keys(endpoint, ['method', 'origin', 'path', 'observations']) &&
    text(endpoint.method, 32) && endpoint.method.length > 0 && text(endpoint.origin, 8192) && text(endpoint.path, 8192) &&
    Array.isArray(endpoint.observations) && endpoint.observations.length > 0 && list(endpoint.observations, 64, observation => {
      observations++;
      return observations <= 64 && keys(observation, ['source', 'state', 'status', 'query_parameters', 'request', 'response']) &&
        keys(observation.source, ['request_id', 'target_id', 'started_monotonic_ms']) && apiCatalogIdentity(coverage, observation.source) !== null &&
        (observation.state === null || text(observation.state, 32)) && (observation.status === null || Number.isSafeInteger(observation.status)) &&
        keys(observation.query_parameters, ['names', 'omitted']) && names(observation.query_parameters.names) && count(observation.query_parameters.omitted) &&
        side(observation.request) && side(observation.response);
    })) && observations + coverage.skipped_records === coverage.window_records;
}

function apiCatalogShapePath(path) {
  return '$' + path.map(part => part.kind === 'array-element' ? '[*]' : `[${JSON.stringify(part.name)}]`).join('');
}
function apiCatalogPathKey(path) {
  // Canonical typed coordinates distinguish a literal "*" from an array item,
  // even when JSON object members arrive in a different serialization order.
  return JSON.stringify(path.map(part => part.kind === 'property' ? ['property', part.name] : ['array-element']));
}
function apiCatalogSearchText(endpoint, observation) {
  const fields = [endpoint.method, endpoint.origin, endpoint.path, observation.status ?? '', observation.state ?? '',
    ...observation.query_parameters.names];
  for (const side of [observation.request, observation.response]) {
    fields.push(...side.header_names, side.body.mime, side.body.reason ?? '');
    if (side.body.status === 'observed') {
      fields.push(side.body.shape.root_type);
      for (const field of side.body.shape.properties) {
        fields.push(apiCatalogShapePath(field.path), ...field.types);
        for (const part of field.path) if (part.kind === 'property') fields.push(part.name);
      }
    }
  }
  return fields.join('\n').toLowerCase();
}
function apiCatalogFilter(index, query, response) {
  const needle = String(query).slice(0, 256).trim().toLowerCase();
  return index.map(entry => ({endpoint: entry.endpoint, observations: entry.observations.filter(({observation, text}) =>
    (!needle || text.includes(needle)) && (response === 'all' ||
      response === 'json' && observation.response.body.status === 'observed' ||
      response === 'unavailable' && observation.response.body.status === 'unavailable' ||
      response === 'error' && observation.status >= 400 && observation.status <= 599))
    .map(item => item.observation)})).filter(entry => entry.observations.length);
}
function apiCatalogCompareBodies(reference, comparison) {
  if (reference.status !== 'observed' || comparison.status !== 'observed') return {
    available: false, reference: reference.status === 'observed' ? 'observed' : reference.reason,
    comparison: comparison.status === 'observed' ? 'observed' : comparison.reason, differences: []
  };
  const fields = shape => new Map([
    ['[]', {path: [], types: [shape.root_type], observations: 1}],
    ...shape.properties.map(field => [apiCatalogPathKey(field.path), field])
  ]);
  const before = fields(reference.shape), after = fields(comparison.shape), differences = [];
  for (const key of new Set([...before.keys(), ...after.keys()])) {
    const left = before.get(key), right = after.get(key);
    const types = field => field ? [...field.types].sort().join(' | ') : null;
    if (!left || !right || types(left) !== types(right) || left.observations !== right.observations) {
      differences.push({path: (left ?? right).path, reference: left ?? null, comparison: right ?? null});
    }
  }
  return {available: true, differences};
}
function installApiObservationCatalog({getRequests, openRequest, fetchCatalog = (...args) => fetch(...args)}) {
  const byId = id => document.getElementById(id);
  const dialog = byId('api-catalog'), trigger = byId('open-api-catalog'), refresh = byId('api-catalog-refresh');
  const status = byId('api-catalog-status'), content = byId('api-catalog-content');
  const search = byId('api-catalog-search'), responseFilter = byId('api-catalog-response');
  const clear = byId('api-catalog-clear'), filterStatus = byId('api-catalog-filter-status');
  let snapshot = null, pending = null, revision = 0, links = [], index = [], expanded = new Set(), renderRevision = 0;
  const node = (tag, value, className = '') => {
    const item = document.createElement(tag);
    item.textContent = value; item.className = className;
    return item;
  };
  const notice = (message, kind = '') => { status.textContent = message; status.dataset.kind = kind; };
  const sync = () => {
    if (!links.length) return;
    // One ledger snapshot per update. Keep duplicate IDs together so narrowing
    // the lookup cannot hide an ambiguous visible Traffic row.
    const requestsById = new Map();
    for (const request of getRequests()) {
      const candidates = requestsById.get(request.id) ?? [];
      candidates.push(request); requestsById.set(request.id, candidates);
    }
    for (const link of links) {
      const result = apiCatalogResolveSource(link.identity, requestsById.get(link.identity?.request) ?? []);
      link.button.disabled = !result.record;
      link.message.textContent = result.message;
      link.message.dataset.kind = result.record ? '' : 'warning';
    }
  };
  const appendSide = (parent, label, side) => {
    const detail = node('details', '', 'api-catalog-side');
    const body = side.body;
    detail.append(node('summary', `${label} JSON shape · ${body.status === 'observed' ? body.shape.root_type : 'unavailable'}`));
    detail.append(node('p', `Header names: ${side.header_names.length ? side.header_names.map(name => JSON.stringify(name)).join(', ') : '(none observed)'} · omitted occurrences: ${side.header_names_omitted} · upstream headers truncated: ${side.headers_truncated ? 'yes' : 'no'}`));
    detail.append(node('p', `Body state: ${body.state} · media type: ${body.mime || '(unknown)'}`));
    if (body.status === 'unavailable') detail.append(node('p', `Shape unavailable: ${body.reason}. No empty or complete schema is inferred.`, 'api-catalog-unknown'));
    else {
      detail.append(node('p', `${body.shape.node_count} observed nodes · maximum depth ${body.shape.max_depth_observed}. Types and occurrence counts describe this body only; required or optional fields are unknown.`));
      const fields = node('ul', '', 'api-catalog-shape');
      fields.append(node('li', `$ · ${body.shape.root_type} · root`));
      for (const field of body.shape.properties) fields.append(node('li', `${apiCatalogShapePath(field.path)} · ${field.types.join(' | ')} · ${field.observations} occurrence(s)`));
      detail.append(fields);
    }
    parent.append(detail);
  };
  const appendComparison = (parent, observations) => {
    if (observations.length < 2) return;
    const panel = node('section', '', 'api-catalog-comparison');
    panel.append(node('h4', 'Compare two observations'), node('p',
      'Compare retained JSON types and occurrence counts. A field seen in only one body is not an inferred optional field or API change. Values and causality are not compared.'));
    const controls = node('div', '', 'api-catalog-compare-controls');
    const select = label => {
      const wrapper = node('label', label), input = node('select', '');
      observations.forEach((observation, index) => {
        const option = node('option', `#${index + 1} · status ${observation.status ?? 'unknown'} · ${observation.source.started_monotonic_ms} ms`);
        option.value = String(index); input.append(option);
      });
      wrapper.append(input); controls.append(wrapper); return input;
    };
    const reference = select('Reference observation'), comparison = select('Comparison observation');
    reference.value = '0'; comparison.value = '1';
    const button = node('button', 'Compare observed structure', 'secondary-button'); button.type = 'button';
    const result = node('div', '', 'api-catalog-comparison-result'); result.setAttribute('aria-live', 'polite');
    const invalidate = () => {
      result.replaceChildren();
      const left = observations[Number(reference.value)].source, right = observations[Number(comparison.value)].source;
      button.disabled = ['request_id', 'target_id', 'started_monotonic_ms'].every(key => left[key] === right[key]);
      if (button.disabled) result.append(node('p', 'Choose two different captured source identities.'));
    };
    reference.addEventListener('change', invalidate); comparison.addEventListener('change', invalidate);
    button.addEventListener('click', () => {
      result.replaceChildren();
      const left = observations[Number(reference.value)], right = observations[Number(comparison.value)];
      result.append(node('p', `Reference #${Number(reference.value) + 1}: ${left.source.request_id} · comparison #${Number(comparison.value) + 1}: ${right.source.request_id}. Exact source links remain below.`));
      for (const side of ['request', 'response']) {
        const report = apiCatalogCompareBodies(left[side].body, right[side].body);
        const title = side === 'request' ? 'Request' : 'Response';
        result.append(node('h4', `${title} JSON structure`));
        if (!report.available) {
          result.append(node('p', `Comparison unavailable. Reference: ${report.reference}; comparison: ${report.comparison}. An unavailable shape is never an empty object.`, 'api-catalog-unknown'));
          continue;
        }
        result.append(node('p', report.differences.length
          ? `${report.differences.length} observed difference(s). Occurrence counts are within each body, not request frequencies.`
          : 'No observed structural differences. Equal types and counts do not establish equal values or equivalent behavior.'));
        const list = node('ul', '', 'api-catalog-differences');
        const description = field => field ? `${[...field.types].sort().join(' | ')} · ${field.observations} occurrence(s)` : 'Not observed in this body';
        for (const difference of report.differences) {
          const row = node('li', '');
          row.append(node('strong', apiCatalogShapePath(difference.path)),
            node('span', `Reference: ${description(difference.reference)}`),
            node('span', `Comparison: ${description(difference.comparison)}`));
          list.append(row);
        }
        result.append(list);
      }
    });
    controls.append(button); panel.append(controls, result); parent.append(panel); invalidate();
  };
  const render = () => {
    links = [];
    const ownRender = ++renderRevision;
    const matches = apiCatalogFilter(index, search.value, responseFilter.value);
    const count = matches.reduce((sum, entry) => sum + entry.observations.length, 0);
    const total = index.reduce((sum, entry) => sum + entry.observations.length, 0);
    search.disabled = false; responseFilter.disabled = false;
    clear.disabled = !search.value && responseFilter.value === 'all';
    filterStatus.textContent = `${count} of ${total} observations · ${matches.length} of ${snapshot.endpoints.length} endpoint groups match. Snapshot coverage below is unchanged.`;
    const coverage = snapshot.coverage;
    const overview = node('section', '', 'api-catalog-coverage');
    overview.append(node('h3', `${snapshot.endpoints.length} endpoint group(s)`));
    overview.append(node('p', `Capture ${coverage.capture_enabled ? 'enabled' : 'off'} · debugger ${coverage.debugger_state} · generation ${coverage.debugger_generation}`));
    overview.append(node('p', `${coverage.window_records} examined of ${coverage.retained_records} retained · ${coverage.older_records_not_examined} older records not examined · ${coverage.skipped_records} skipped records · ${coverage.capture_dropped_records} capture evictions. These are separate coverage limits.`));
    const ownership = node('details', '', 'api-catalog-identity');
    ownership.append(node('summary', 'Snapshot identity and limits'), node('p', `Backend instance: ${coverage.instance_id || '(unavailable)'} · capture epoch: ${coverage.capture_epoch}`),
      node('p', `At most ${snapshot.limits.records} records; ${snapshot.limits.body_bytes} complete UTF-8 bytes per JSON body; ${snapshot.limits.names_per_surface} names per surface; ${snapshot.limits.shape_nodes} shape nodes, depth ${snapshot.limits.shape_depth} and ${snapshot.limits.shape_fields} field paths.`));
    for (const limitation of snapshot.limitations) ownership.append(node('p', limitation));
    overview.append(ownership);
    content.replaceChildren(overview);
    if (!snapshot.endpoints.length) content.append(node('p', coverage.capture_enabled
      ? 'No eligible HTTP(S) endpoint observations in this snapshot. Check the debugger state and skipped-record count above.'
      : 'Content capture is off. The catalog does not enable it. Native host-only metadata cannot supply endpoint observations.', 'api-catalog-empty'));
    if (snapshot.endpoints.length && !matches.length) content.append(node('p',
      'No observations match these filters. Clear filters to inspect the retained snapshot; no newer records were fetched.', 'api-catalog-empty'));
    for (const {endpoint, observations} of matches) {
      const group = node('details', '', 'api-catalog-endpoint');
      group.append(node('summary', `${endpoint.method} ${endpoint.origin}${endpoint.path} · ${observations.length} of ${endpoint.observations.length} observation(s)`));
      const expand = (updateSources = true) => {
        if (ownRender !== renderRevision) return;
        if (group.open) expanded.add(endpoint); else expanded.delete(endpoint);
        if (!group.open || group.dataset.rendered) return;
        group.dataset.rendered = 'true';
        appendComparison(group, observations);
        for (const [index, observation] of observations.entries()) {
          const record = node('article', '', 'api-catalog-observation');
          record.append(node('h4', `#${index + 1} · Status ${observation.status ?? 'unknown'} · ${observation.state ?? 'unknown lifecycle'}`));
          const source = observation.source;
          const identity = apiCatalogIdentity(coverage, source);
          const exact = node('details', '', 'api-catalog-identity');
          exact.append(node('summary', 'Exact captured source'), node('p', `Request: ${source.request_id} · target: ${source.target_id} · original start: ${source.started_monotonic_ms} ms · instance: ${coverage.instance_id} · epoch: ${coverage.capture_epoch}`));
          const button = node('button', 'Open captured request', 'secondary-button'); button.type = 'button';
          const message = node('p', '', 'api-catalog-source-status');
          message.setAttribute('role', 'status');
          button.addEventListener('click', () => {
            const result = apiCatalogResolveSource(identity, getRequests());
            if (!result.record) {sync(); notice(result.message, 'warning'); return;}
            if (!openRequest(result.record)) {notice('The exact Traffic handoff was refused. The catalog remains open.', 'warning'); return;}
            dialog.close();
          });
          links.push({identity, button, message});
          record.append(button, message, exact);
          const query = observation.query_parameters;
          record.append(node('p', `Query names: ${query.names.length ? query.names.map(name => JSON.stringify(name)).join(', ') : '(none observed)'} · omitted occurrences: ${query.omitted}`));
          appendSide(record, 'Request', observation.request); appendSide(record, 'Response', observation.response);
          group.append(record);
        }
        if (updateSources) sync();
      };
      group.addEventListener('toggle', () => expand());
      group.open = expanded.has(endpoint);
      if (group.open) expand(false);
      content.append(group);
    }
    sync();
  };
  const read = async () => {
    if (pending) return;
    const ownRevision = ++revision, controller = new AbortController(); pending = controller;
    refresh.disabled = true; content.setAttribute('aria-busy', 'true');
    notice(snapshot ? 'Refreshing snapshot. Previous observations remain readable.' : 'Loading observed endpoints…');
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetchCatalog('/api/network/catalog', {cache: 'no-store', signal: controller.signal});
      if (!response.ok) throw new Error(`Catalog returned HTTP ${response.status}.`);
      const text = await response.text();
      if (new TextEncoder().encode(text).length > 4 * 1024 * 1024) throw new Error('Catalog exceeded its response budget.');
      const value = JSON.parse(text);
      if (!isApiObservationCatalog(value)) throw new Error('Malformed or unsupported catalog response.');
      if (ownRevision !== revision) return;
      snapshot = value; expanded = new Set();
      // Build once per explicit snapshot, never for every keystroke or poll.
      // The validated input already bounds this to 64 observations / 4 MiB.
      index = value.endpoints.map(endpoint => ({endpoint, observations: endpoint.observations.map(observation =>
        ({observation, text: apiCatalogSearchText(endpoint, observation)}))}));
      render();
      notice('Snapshot loaded. Refresh deliberately for newer observations; source availability follows the current Traffic window.');
    } catch (error) {
      if (ownRevision !== revision) return;
      const reason = error.name === 'AbortError' ? 'Catalog read timed out.' : error instanceof SyntaxError ? 'Malformed catalog JSON.' : error.message;
      notice(`${reason} ${snapshot ? 'Previous snapshot preserved.' : 'No catalog snapshot loaded.'} Use Refresh snapshot to retry.`, 'warning');
    } finally {
      clearTimeout(timeout);
      if (ownRevision === revision) {pending = null; refresh.disabled = false; content.setAttribute('aria-busy', 'false');}
    }
  };
  trigger.addEventListener('click', () => {dialog.showModal(); sync(); if (!snapshot) void read();});
  refresh.addEventListener('click', () => void read());
  search.addEventListener('input', () => {if (snapshot) render();});
  responseFilter.addEventListener('change', () => {if (snapshot) render();});
  clear.addEventListener('click', () => {
    search.value = ''; responseFilter.value = 'all'; if (snapshot) render(); search.focus();
  });
  byId('api-catalog-close').addEventListener('click', () => dialog.close());
  // Keep workspace shortcuts behind the modal inert; native Tab/Enter/Escape
  // and text selection retain their usual browser behavior.
  dialog.addEventListener('keydown', event => {
    event.stopPropagation();
    if (event.altKey && ['ArrowLeft', 'ArrowRight'].includes(event.key) ||
        (event.ctrlKey || event.metaKey) && ['p', 'j'].includes(event.key.toLowerCase())) event.preventDefault();
  });
  dialog.addEventListener('close', () => {
    const canceled = Boolean(pending);
    revision++; pending?.abort(); pending = null; refresh.disabled = false; content.setAttribute('aria-busy', 'false');
    if (snapshot && canceled) notice('Catalog refresh canceled. Previous snapshot preserved.');
    if (!snapshot) notice('No snapshot loaded. Reopen to read the catalog.');
  });
  return {sync};
}
