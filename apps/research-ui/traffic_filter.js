/* Traffic filters over the newest window: the search grammar, Invert,
 * Failed only, Third-party only, Hide browser-internal and the time range.
 * The request index applies the same rules to the whole session
 * (apps/origin-trace-backend/src/request_index.rs); make request-index-check
 * holds the two to one fixture. Filters never change a row. */
const TRAFFIC_FILTER_KEYS = Object.freeze(['domain', 'method', 'status-code', 'larger-than', 'mime-type']);
const TRAFFIC_TIMELINE_BUCKETS = 120;

// A valid token value, or null; larger-than yields its byte count (k = 1024).
function trafficFilterBytes(key, value) {
  if (!value) return null;
  if (key === 'status-code') return /^\d{1,3}$/.test(value) ? 0 : null;
  if (key === 'larger-than') {
    const match = /^(\d{1,9})([km]?)$/.exec(value);
    return match ? Number(match[1]) * (match[2] === 'k' ? 1024 : match[2] === 'm' ? 1048576 : 1) : null;
  }
  if (key === 'method') return /^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(value) ? 0 : null;
  return 0;
}

// DevTools-style tokens; `-word` excludes text and `-key:value` negates a token.
function trafficParseFilter(input) {
  const needle = String(input ?? '').trim().toLowerCase();
  const filter = {needle, text: '', exclude: [], tokens: [], active: false};
  const free = [];
  for (const word of needle.split(/\s+/).filter(Boolean)) {
    const negated = word.length > 1 && word.startsWith('-');
    const body = negated ? word.slice(1) : word;
    const colon = body.indexOf(':');
    const key = colon > 0 ? body.slice(0, colon) : '';
    const bytes = TRAFFIC_FILTER_KEYS.includes(key) ? trafficFilterBytes(key, body.slice(colon + 1)) : null;
    if (bytes !== null) filter.tokens.push({key, value: body.slice(colon + 1), negated, bytes});
    else if (negated) filter.exclude.push(body);
    else free.push(word);
  }
  filter.text = free.join(' ');
  filter.active = Boolean(filter.text || filter.exclude.length || filter.tokens.length);
  return filter;
}

function trafficGlob(pattern, text) {
  const parts = pattern.split('*');
  if (parts.length === 1) return pattern === text;
  if (!text.startsWith(parts[0])) return false;
  let at = parts[0].length;
  for (const part of parts.slice(1, -1)) {
    const found = text.indexOf(part, at);
    if (found < 0) return false;
    at = found + part.length;
  }
  const last = parts.at(-1);
  return text.length >= at + last.length && text.endsWith(last);
}

function trafficHostOf(domain) {
  const at = domain.lastIndexOf(':');
  return at >= 0 && /^\d+$/.test(domain.slice(at + 1)) ? domain.slice(0, at) : domain;
}

// Without a public suffix list: the last two labels, or three after a short
// second level and a two-letter country code (example.co.uk).
function trafficSite(domain) {
  const host = trafficHostOf(String(domain ?? '')).toLowerCase();
  if (!host || host === 'unknown') return null;
  if (host.startsWith('[') || !host.includes('.') || /^[\d.]+$/.test(host)) return host;
  const labels = host.split('.'), count = labels.length;
  const keep = count >= 3 && labels[count - 1].length === 2 && labels[count - 2].length <= 3 ? 3 : 2;
  return labels.slice(Math.max(0, count - keep)).join('.');
}

// WebUI loads (chrome://resources, newtab) reach no browser loader record and
// name a single-label host.
function trafficBrowserInternal(request) {
  if (typeof request?.browserInternal === 'boolean') return request.browserInternal;
  const host = String(request?.path ?? '').trim();
  return request?.loaderObserved === false && request.targetKind === 'host' && /^[a-z0-9-]+$/i.test(host) &&
    host.toLowerCase() !== 'localhost';
}

// A row whose site differs from its tab's latest top-level document at its start.
function trafficThirdPartyIds(requests) {
  const documents = new Map();
  requests.forEach((request, ordinal) => {
    if (!request.mainFrame || !request.tabId || request.tabId === '0') return;
    if (!documents.has(request.tabId)) documents.set(request.tabId, []);
    documents.get(request.tabId).push({first: request.firstTimestamp, ordinal, request});
  });
  for (const list of documents.values()) {
    list.sort((a, b) => a.first < b.first ? -1 : a.first > b.first ? 1 : a.ordinal - b.ordinal);
  }
  const ids = new Set();
  requests.forEach((request, ordinal) => {
    const list = documents.get(request.tabId), own = trafficSite(trafficRequestDomain(request));
    if (!list || own === null) return;
    let document = null;
    for (const entry of list) {
      if (entry.first > request.firstTimestamp || (entry.first === request.firstTimestamp && entry.ordinal > ordinal)) break;
      document = entry;
    }
    const site = document ? trafficSite(trafficRequestDomain(document.request)) : null;
    if (site !== null && site !== own) ids.add(request.id);
  });
  return ids;
}

function trafficTokenMatches(token, request) {
  if (token.key === 'domain') {
    const domain = trafficRequestDomain(request).toLowerCase();
    return trafficGlob(token.value, domain) || trafficGlob(token.value, trafficHostOf(domain));
  }
  if (token.key === 'method') return String(request.method).toLowerCase() === token.value;
  if (token.key === 'status-code') return typeof request.status === 'number' && request.status === Number(token.value);
  if (token.key === 'larger-than') return Number.isSafeInteger(request.transferSize) && request.transferSize > token.bytes;
  return request.mimeType === token.value;
}

function trafficTimeline(requests) {
  let first = null, last = null;
  const timed = requests.filter(request => typeof request.firstTimestamp === 'bigint' && typeof request.lastTimestamp === 'bigint');
  for (const request of timed) {
    if (first === null || request.firstTimestamp < first) first = request.firstTimestamp;
    if (last === null || request.lastTimestamp > last) last = request.lastTimestamp;
  }
  const buckets = new Array(TRAFFIC_TIMELINE_BUCKETS).fill(0);
  if (first !== null) {
    const span = last - first + 1n;
    for (const request of timed) buckets[Number((request.firstTimestamp - first) * BigInt(TRAFFIC_TIMELINE_BUCKETS) / span)] += 1;
  }
  return {first, last, buckets};
}

// `scoped` already passed the tab, domain and type filters; `textMatches` is
// trafficSearchRequests over it for filter.text. The timeline covers every row
// the time range would admit, so the strip keeps the whole picture.
function trafficApplyFilter(scoped, textMatches, filter, {flags = {}, range = null, all = scoped} = {}) {
  const thirdParty = flags.thirdParty ? trafficThirdPartyIds(all) : null;
  const matches = new Map(), scope = [];
  let hiddenInternal = 0, transferred = 0, resources = 0;
  for (const request of scoped) {
    if ((flags.failed && !trafficRequestFailed(request)) || (thirdParty && !thirdParty.has(request.id))) continue;
    const haystack = `${request.method} ${request.path} ${request.status}`.toLowerCase();
    const found = textMatches.has(request.id) && filter.exclude.every(text => !haystack.includes(text)) &&
      filter.tokens.every(token => trafficTokenMatches(token, request) !== token.negated);
    if (found === Boolean(flags.invert && filter.active)) continue;
    const inRange = !range || (request.firstTimestamp <= range.to && request.lastTimestamp >= range.from);
    if (flags.hideInternal && trafficBrowserInternal(request)) {
      hiddenInternal += inRange ? 1 : 0;
      continue;
    }
    scope.push(request);
    if (!inRange) continue;
    matches.set(request.id, textMatches.get(request.id) ?? {label: 'Filter'});
    transferred += Number.isSafeInteger(request.transferSize) ? request.transferSize : 0;
    resources += Number.isSafeInteger(request.resourceSize) ? request.resourceSize : 0;
  }
  return {matches, hiddenInternal, sizes: {transferred, resources}, timeline: trafficTimeline(scope)};
}
