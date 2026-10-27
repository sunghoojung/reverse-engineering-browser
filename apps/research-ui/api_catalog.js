/* Exact identity for retained Traffic records. Never derive identity from a
 * displayed URL, native correlation, rounded timestamps, or a reusable CDP
 * protocol ID. The observed API catalog that read CDP Traffic bodies through
 * GET /api/network/catalog was removed with CDP: native network records keep
 * no bodies to infer shapes from. */
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

// app.js still installs the catalog entry point. Keep it hidden and inert;
// nothing is fetched and no dialog opens.
function installApiObservationCatalog() {
  const trigger = document.getElementById('open-api-catalog');
  if (trigger) trigger.hidden = true;
  return {sync() {}};
}
