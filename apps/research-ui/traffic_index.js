/* Traffic rows from the backend request index (protocol/request-index-v1.md).
 * One read in flight at a time; a failed read keeps the last answer. */
const TRAFFIC_INDEX_DEADLINE_MS = 10000;
const TRAFFIC_DETAIL_PAGE = 200;
const TRAFFIC_DETAIL_PAGES = 16;

function trafficIndexParameters({sort, direction, needle, tabId, domain, type, named, flags = {}, range = null}) {
  const parameters = new URLSearchParams({sort, order: direction < 0 ? 'desc' : 'asc'});
  if (needle) parameters.set('q', needle);
  if (tabId !== 'all') parameters.set('tab_id', tabId === 'unresolved' ? 'unattributed' : tabId);
  if (domain !== 'all') parameters.set('domain', domain);
  if (type !== 'all') parameters.set('type', type);
  if (named.length) parameters.set('named', named.join(','));
  for (const [flag, key] of [['failed', 'failed'], ['invert', 'invert'], ['hideInternal', 'hide_internal'], ['thirdParty', 'third_party']]) {
    if (flags[flag]) parameters.set(key, '1');
  }
  if (range) {
    parameters.set('from_ns', String(range.from));
    parameters.set('to_ns', String(range.to));
  }
  return parameters.toString();
}

function createTrafficIndex({fetcher = (input, init) => fetch(input, init), onChange = () => {}} = {}) {
  let wanted = null, answer = null, error = null, inFlight = null, stale = true, etag = null, etagUrl = null, unsupported = false;

  function url({query, start, locate}, through) {
    const parameters = new URLSearchParams(query);
    parameters.set('offset', String(start));
    parameters.set('limit', String(TRAFFIC_ROW_LIMIT));
    if (through !== null) parameters.set('since', String(through));
    const ids = locate.filter(Boolean);
    if (ids.length) parameters.set('locate', [...new Set(ids)].join(','));
    return `/api/requests?${parameters}`;
  }

  async function read() {
    const request = wanted;
    stale = false;
    // `added` then counts matching rows indexed since the previous answer.
    const through = answer?.query === request.query ? answer.document.through : null;
    const target = url(request, through);
    const headers = target === etagUrl && etag ? {'If-None-Match': etag} : {};
    try {
      const response = await fetcher(target, {cache: 'no-store', headers, signal: AbortSignal.timeout(TRAFFIC_INDEX_DEADLINE_MS)});
      if (response.status === 304 && answer) {
        error = null;
        return;
      }
      // A workspace without the index is not asked again.
      if (response.status === 404) unsupported = true;
      if (!response.ok) throw new Error(`the request index returned HTTP ${response.status}`);
      const document = await response.json();
      if (!document || document.format !== 'reb-request-index-v1' || !Array.isArray(document.requests)) {
        throw new Error('the request index answer is malformed');
      }
      const previous = answer;
      answer = {query: request.query, start: request.start, origin: request.origin, document,
        rows: document.requests.map(row => trafficIndexRequest(row, request.origin)),
        added: previous?.query === request.query && previous.document.index.epoch === document.index.epoch ? document.added ?? 0 : 0};
      etag = response.headers.get('ETag');
      etagUrl = target;
      error = null;
    } catch (failure) {
      etag = null;
      error = failure?.name === 'TimeoutError' ? 'the request index did not answer within 10 seconds' : String(failure?.message ?? failure);
    } finally {
      inFlight = null;
      onChange();
      if (stale || !same(wanted, request)) schedule();
    }
  }
  function same(left, right) {
    return Boolean(left && right) && left.query === right.query && left.start === right.start &&
      left.origin === right.origin && left.locate.join(',') === right.locate.join(',');
  }
  function schedule() {
    if (!inFlight && wanted && !unsupported) inFlight = read();
  }

  return {
    // Returns the last answer, which may cover another block or query.
    want(request) {
      const changed = !same(wanted, request);
      wanted = request;
      if (changed || stale) schedule();
      return answer;
    },
    invalidate() {
      stale = true;
      schedule();
    },
    // A poll that changed nothing still retries a failed read. Only polls call
    // this and a read in flight is left alone, so a failing read runs once per
    // poll at most and cannot spin.
    retry() {
      if (error === null || inFlight) return;
      stale = true;
      schedule();
    },
    answer: () => answer,
    error: () => error,
    pending: () => Boolean(inFlight),
    row(id) {
      return answer?.rows.find(request => request.id === id) ?? null;
    },
    // Each member is read forward from the row's first offset, up to its record count.
    // `partial` means some records were not read, so a missing one is unknown, not absent.
    async events(row, signal) {
      const events = new Map();
      let partial = row.members_limited === true;
      for (const member of row.members) {
        let after = row.first_offset, remaining = member.records;
        for (let page = 0; page < TRAFFIC_DETAIL_PAGES && remaining > 0; page += 1) {
          const parameters = new URLSearchParams({session_id: member.session_id, process_id: String(member.process_id),
            request_id: member.request_id, category: 'network', after, limit: String(Math.min(remaining, TRAFFIC_DETAIL_PAGE))});
          const response = await fetcher(`/api/events?${parameters}`, {cache: 'no-store', signal});
          if (!response.ok) throw new Error(`the event store returned HTTP ${response.status}`);
          const body = await response.json();
          if (!Array.isArray(body?.events) || !body.query) throw new Error('the event store answer is malformed');
          for (const event of body.events) events.set(`${event.session_id}:${event.process_id}:${event.sequence_number}`, event);
          remaining -= body.events.length;
          if (body.query.malformed_lines > 0) partial = true;
          const next = body.query.next_after;
          if (!(body.query.limited || body.query.budget_exhausted) || BigInt(next) >= BigInt(row.end_offset)) break;
          after = next;
        }
        if (remaining > 0) partial = true;
      }
      const order = event => [BigInt(event.monotonic_time_ns), BigInt(event.process_id), BigInt(event.sequence_number)];
      return {partial, events: [...events.values()].sort((left, right) => {
        const [a, b] = [order(left), order(right)];
        for (let index = 0; index < a.length; index += 1) if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
        return 0;
      })};
    }
  };
}
