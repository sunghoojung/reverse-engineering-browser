/* Tabs of Traffic rows from tab_id, tab_set and request_tab_link records
 * (protocol/native-network-v3.md "Request owners and tabs"). A row without a
 * tab is a capture error that stays listed, never a catch-all group. */
(function (global) {
  const LINK_KINDS = Object.freeze({1: 'Dedicated worker', 2: 'Shared worker', 3: 'Service worker', 4: 'Service worker'});
  const OWNER_KINDS = new Set([17, 18, 19]);
  const PART_TABS = 26;

  function bytesOf(event, size) {
    if (event?.protocol_version !== 3 || event.category !== 'network' || event.payload_size !== size ||
        typeof event.payload !== 'string' || !new RegExp(`^[0-9a-f]{${size * 2}}$`, 'i').test(event.payload)) return null;
    return Uint8Array.from(event.payload.match(/../g), byte => Number.parseInt(byte, 16));
  }

  // The request-free envelope of both records; same rules as include/reb/tab_link.hpp.
  function quietEnvelope(event) {
    return event.flags === 0 && event.status_code === 0 && event.error_code === 0 && event.resource_type === 0 &&
      event.scheme_class === undefined && event.loader_kind === undefined &&
      ['navigation_id', 'artifact_id', 'request_id', 'encoded_data_length', 'decoded_body_length']
        .every(key => event[key] === '0') &&
      ['browser_context_id_high', 'browser_context_id_low'].every(key => (event[key] ?? '0') === '0') &&
      ['session_id', 'sequence_number'].every(key => typeof event[key] === 'string' && event[key] !== '0') &&
      event.process_id > 0;
  }

  function decodeTabSet(event) {
    const bytes = event?.type === 'tab_set' ? bytesOf(event, 128) : null;
    if (!bytes || !quietEnvelope(event) || event.frame_id === '0' || event.initiator_process_id !== 0 ||
        event.initiator_request_id !== 0) return null;
    const view = new DataView(bytes.buffer);
    const part = view.getUint16(6, true), total = view.getUint32(16, true), count = view.getUint16(20, true);
    const setId = view.getBigUint64(8, true);
    const tabs = Array.from({length: PART_TABS}, (_, index) => view.getUint32(24 + 4 * index, true));
    const expected = Math.min(PART_TABS, total - part * PART_TABS);
    if (view.getUint16(0, true) !== 1 || view.getUint16(2, true) !== 128 || !OWNER_KINDS.has(bytes[4]) ||
        (bytes[5] & ~1) || view.getUint16(22, true) || setId === 0n || total === 0 ||
        part >= Math.ceil(total / PART_TABS) || count !== expected ||
        tabs.some((tab, index) => index < count ? tab === 0 || (index > 0 && tab <= tabs[index - 1]) : tab !== 0) ||
        event.tab_id !== tabs[0] || (part === 0) !== (event.parent_event_id === '0')) return null;
    return {setId: setId.toString(), ownerKind: bytes[4], lastClients: Boolean(bytes[5] & 1), part, total,
      tabs: tabs.slice(0, count), session: event.session_id};
  }

  function decodeTabLink(event) {
    const bytes = event?.type === 'request_tab_link' ? bytesOf(event, 24) : null;
    if (!bytes || !quietEnvelope(event) || !(event.initiator_process_id > 0) || event.parent_event_id === '0') return null;
    const view = new DataView(bytes.buffer);
    const setId = view.getBigUint64(8, true), count = view.getUint32(16, true);
    if (view.getUint16(0, true) !== 1 || view.getUint16(2, true) !== 24 || !(bytes[4] >= 1 && bytes[4] <= 4) ||
        bytes[5] || bytes[6] || bytes[7] || view.getUint32(20, true) || setId === 0n || count === 0 ||
        (count === 1) !== (event.tab_id !== 0)) return null;
    return {kind: bytes[4], setId: setId.toString(), count,
      row: `S${event.session_id}:R${event.initiator_process_id}:${event.initiator_request_id}`};
  }

  // Complete sets only; a set missing a part keeps the tabs it has and says so.
  function tabSetsFrom(events) {
    const sets = new Map();
    for (const event of events) {
      const part = decodeTabSet(event);
      if (!part) continue;
      const key = `${part.session}:${part.setId}`;
      const set = sets.get(key) ?? {total: part.total, lastClients: part.lastClients, parts: new Map()};
      set.parts.set(part.part, part.tabs);
      sets.set(key, set);
    }
    for (const set of sets.values()) {
      set.tabs = [...set.parts.values()].flat().sort((left, right) => left - right);
      set.complete = set.tabs.length === set.total;
    }
    return sets;
  }

  function linkLabel(link) {
    const name = LINK_KINDS[link.kind];
    if (link.kind === 1) return name;
    if (link.kind === 4) return `${name} · last ${link.count === 1 ? 'client' : `${link.count} clients`}`;
    return `${name} · ${link.count} ${link.count === 1 ? 'tab' : 'tabs'}`;
  }

  // Adds tabIds, tabLink and tabLinkLabel to each row; evidence is not changed.
  function attachRequestTabs(rows, events) {
    const sets = tabSetsFrom(events);
    const links = new Map();
    for (const event of events) {
      const link = decodeTabLink(event);
      if (link) links.set(link.row, {...link, set: sets.get(`${event.session_id}:${link.setId}`) ?? null});
    }
    for (const row of rows) {
      const tabs = new Set((row.events ?? []).map(event => event.tab_id).filter(tab => tab > 0));
      const link = links.get(row.id) ?? null;
      for (const tab of link?.set?.tabs ?? []) tabs.add(tab);
      row.tabIds = [...tabs].sort((left, right) => left - right).map(String);
      row.tabLink = link && {kind: link.kind, count: link.count, complete: Boolean(link.set?.complete)};
      row.tabLinkLabel = link ? linkLabel(link) : '';
    }
    return rows;
  }

  function rowTabs(row) {
    if (Array.isArray(row.tabIds)) return row.tabIds;
    return row.tabId && row.tabId !== '0' ? [row.tabId] : [];
  }

  // Native rows only: sample rows carry no capture identity to resolve.
  function isUnresolved(row) {
    return row.origin === 'live' && rowTabs(row).length === 0;
  }

  // The tab's current page: the host of its newest main-frame navigation.
  function tabPageLabel(requests, domainOf) {
    let newest = null;
    for (const request of requests) {
      const start = (request.events ?? []).find(event => event.type === 'request_started');
      if (start?.loader_kind === 1 && start.resource_type === 0 &&
          (!newest || BigInt(start.monotonic_time_ns) > BigInt(newest.time))) {
        newest = {time: start.monotonic_time_ns, request};
      }
    }
    if (newest) return domainOf(newest.request);
    return requests.map(domainOf).find(domain => domain && domain !== 'unknown') ?? '';
  }

  function unresolvedNotice(count) {
    return count ? `${count} ${count === 1 ? 'request' : 'requests'} without a tab (capture error)` : '';
  }

  const api = Object.freeze({decodeTabSet, decodeTabLink, tabSetsFrom, attachRequestTabs, rowTabs, isUnresolved,
    tabPageLabel, unresolvedNotice, linkLabel});
  global.RebRequestTabs = api;
  if (typeof module === 'object' && module?.exports) module.exports = api;
})(globalThis);
