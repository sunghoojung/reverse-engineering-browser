/* Scheme classes and counted browser-internal exclusions
 * (protocol/native-network-v3.md) for Traffic and Sources. Hiding is a view
 * filter over retained evidence; it never changes or drops a record. */
(function (global) {
  const INTERNAL_SCHEME_CLASSES = Object.freeze({16: 'chrome', 17: 'chrome-untrusted', 18: 'brave',
    19: 'devtools', 20: 'chrome-search'});
  const WEBUI_RENDERER_CLASS = 64;
  const INTERNAL_URL = /^(?:brave|chrome|chrome-search|chrome-untrusted|devtools):/i;

  // Same rules as include/reb/network_scope.hpp and tools/validate-evidence-store.py.
  function decodeCaptureExclusion(event) {
    if (event?.type !== 'capture_exclusion' || event.protocol_version !== 3 || event.category !== 'network' ||
        event.flags !== 0 || event.payload_size !== 16 || typeof event.payload !== 'string' ||
        !/^[0-9a-f]{32}$/i.test(event.payload) || event.tab_id !== 0 || event.initiator_request_id !== 0 ||
        event.status_code !== 0 || event.error_code !== 0 || event.resource_type !== 0 ||
        event.scheme_class !== undefined || !(event.process_id > 0) ||
        ['navigation_id', 'frame_id', 'artifact_id', 'parent_event_id', 'request_id', 'encoded_data_length',
          'decoded_body_length'].some(key => event[key] !== '0') ||
        ['browser_context_id_high', 'browser_context_id_low'].some(key => (event[key] ?? '0') !== '0') ||
        ['session_id', 'sequence_number'].some(key => typeof event[key] !== 'string' || event[key] === '0')) return null;
    const bytes = Uint8Array.from(event.payload.match(/../g), byte => Number.parseInt(byte, 16));
    const view = new DataView(bytes.buffer);
    const exclusionClass = bytes[4];
    const count = view.getBigUint64(8, true);
    if (view.getUint16(0, true) !== 1 || view.getUint16(2, true) !== 16 || bytes[5] || bytes[6] || bytes[7] ||
        count === 0n || !(exclusionClass in INTERNAL_SCHEME_CLASSES || exclusionClass === WEBUI_RENDERER_CLASS) ||
        (exclusionClass === WEBUI_RENDERER_CLASS && event.initiator_process_id !== 0)) return null;
    return {exclusionClass, count, producer: `${event.session_id}:${event.initiator_process_id}`};
  }

  // Each record is one producer's cumulative count for one class.
  function captureExclusionTotals(events) {
    const newest = new Map();
    for (const event of Array.isArray(events) ? events : []) {
      const value = decodeCaptureExclusion(event);
      if (!value) continue;
      const key = `${value.producer}:${value.exclusionClass}`;
      if (!newest.has(key) || newest.get(key).count < value.count) newest.set(key, value);
    }
    const totals = {requests: 0n, renderers: 0n, byScheme: new Map()};
    for (const {exclusionClass, count} of newest.values()) {
      if (exclusionClass === WEBUI_RENDERER_CLASS) {
        totals.renderers += count;
        continue;
      }
      const scheme = INTERNAL_SCHEME_CLASSES[exclusionClass];
      totals.requests += count;
      totals.byScheme.set(scheme, (totals.byScheme.get(scheme) ?? 0n) + count);
    }
    return totals;
  }

  function captureExclusionNotice(totals) {
    const parts = [];
    if (totals?.requests > 0n) {
      parts.push(`${totals.requests} browser-internal ${totals.requests === 1n ? 'request' : 'requests'} not recorded`);
    }
    if (totals?.renderers > 0n) {
      parts.push(`${totals.renderers} WebUI ${totals.renderers === 1n ? 'renderer' : 'renderers'} not admitted`);
    }
    return parts.join(' · ');
  }

  // A row recorded before scheme classes is browser-internal when only the
  // renderer saw it and its host is one bare label, as chrome://resources was.
  function isBrowserInternalRequest(request) {
    if (!request || typeof request !== 'object') return false;
    if (Number.isInteger(request.schemeClass) && request.schemeClass > 0) {
      return Object.hasOwn(INTERNAL_SCHEME_CLASSES, request.schemeClass);
    }
    return request.hostOnly === true && request.browserObserved === false && typeof request.path === 'string' &&
      /^[a-z0-9][a-z0-9-]*$/i.test(request.path) && request.path.toLowerCase() !== 'localhost';
  }

  function isBrowserInternalSourceUrl(url) {
    return typeof url === 'string' && INTERNAL_URL.test(url);
  }

  // Keeps order; the internal count is reported whether or not it is hidden.
  function browserInternalView(items, predicate, hide) {
    const visible = [];
    let internal = 0;
    for (const item of items) {
      const match = predicate(item);
      if (match) internal += 1;
      if (!(hide && match)) visible.push(item);
    }
    return {visible, internal, hidden: hide ? internal : 0};
  }

  // Shown only while there is something to hide or the filter is on.
  function renderBrowserInternalToggle(button, internal, hide) {
    if (!button) return;
    button.hidden = internal === 0 && !hide;
    button.setAttribute('aria-pressed', String(hide));
    const label = hide ? `Show browser-internal (${internal} hidden)` : `Hide browser-internal (${internal})`;
    if (button.textContent !== label) button.textContent = label;
  }

  const api = Object.freeze({decodeCaptureExclusion, captureExclusionTotals, captureExclusionNotice,
    isBrowserInternalRequest, isBrowserInternalSourceUrl, browserInternalView, renderBrowserInternalToggle});
  global.RebNetworkScope = api;
  if (typeof module === 'object' && module?.exports) module.exports = api;
})(globalThis);
