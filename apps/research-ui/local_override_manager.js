/* Explicit, ephemeral browser File snapshots for the existing local override API. */
(function (global) {
  'use strict';
  const maximum = 65536;
  const media = ['text/plain; charset=utf-8', 'text/javascript; charset=utf-8', 'application/json; charset=utf-8', 'text/css; charset=utf-8'];
  const bytes = value => new TextEncoder().encode(value);
  async function snapshot(file) {
    if (!file || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > maximum) throw Error('Choose one UTF-8 file of at most 64 KiB.');
    // Slice bounds allocation even if a File changes or its reported size is stale.
    const buffer = await file.slice(0, maximum + 1).arrayBuffer();
    if (buffer.byteLength !== file.size || buffer.byteLength > maximum) throw Error('The selected file changed or exceeds 64 KiB. Select it again.');
    let body;
    try { body = new TextDecoder('utf-8', {fatal:true, ignoreBOM:true}).decode(buffer); }
    catch { throw Error('The selected file is not exact UTF-8. Binary and compressed files are unsupported.'); }
    const original = new Uint8Array(buffer), encoded = bytes(body);
    if (encoded.length !== original.length || encoded.some((value,index) => value !== original[index])) throw Error('The file cannot be represented as exact UTF-8.');
    const sha256 = Array.from(new Uint8Array(await global.crypto.subtle.digest('SHA-256', buffer)), value => value.toString(16).padStart(2,'0')).join('');
    return Object.freeze({body, bytes:buffer.byteLength, sha256});
  }
  function context(session) {
    const experiment = session?.request_interception, scope = session?.action_scope;
    if (!['running','paused'].includes(session?.state) || experiment?.isolated !== true || !['ready','error'].includes(experiment.state) ||
        !Number.isSafeInteger(experiment.experiment_id) || experiment.experiment_id < 1 ||
        typeof experiment.target_id !== 'string' || !experiment.target_id || bytes(experiment.target_id).length > 4096 || /[\x00-\x1f\x7f]/.test(experiment.target_id) ||
        experiment.target_id !== session.target?.id || scope?.mode !== 'target' || scope.target_id !== experiment.target_id) return null;
    return {targetId:experiment.target_id, experimentId:experiment.experiment_id};
  }
  function prepare(asset, options, selected, now = Date.now()) {
    let url;
    try { url = new URL(options.url); } catch { throw Error('Enter one exact canonical HTTP(S) URL.'); }
    if (!selected || typeof options.url !== 'string' || bytes(options.url).length > 2048 || /[^\x21-\x7e]/.test(options.url) || url.href !== options.url ||
        !['http:','https:'].includes(url.protocol) || url.username || url.password || url.hash || options.url.includes('#')) throw Error('Select the exact disposable target scope and enter a canonical credential-free HTTP(S) URL without a fragment.');
    if (!asset || typeof asset.body !== 'string' || bytes(asset.body).length !== asset.bytes || asset.bytes > maximum || !/^[0-9a-f]{64}$/.test(asset.sha256) ||
        options.reviewed !== true || !media.includes(options.contentType) || !['GET','HEAD'].includes(options.method) ||
        !Number.isSafeInteger(options.ttlMs) || options.ttlMs < 1000 || options.ttlMs > 300000 || !Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(now + options.ttlMs)) throw Error('Review the snapshot and choose a supported method, content type and lifetime (1–300 seconds).');
    return Object.freeze({action:'configure_request_interception',mode:'fulfill',url_pattern:'*',method_filter:options.method,response_code:200,
      response_headers:Object.freeze({'content-type':options.contentType}),response_body:asset.body,
      local_override:Object.freeze({version:1,exact_url:url.href,target_id:selected.targetId,experiment_id:selected.experimentId,expires_at_ms:now + options.ttlMs,asset_sha256:asset.sha256})});
  }
  function canArm(action, session, now = Date.now()) {
    const selected = context(session), local = action?.local_override;
    return Boolean(local && selected && selected.targetId === local.target_id && selected.experimentId === local.experiment_id && local.expires_at_ms > now && local.expires_at_ms - now <= 300000);
  }
  function disarm(action) {
    if (!action?.local_override) throw Error('No exact local override identity is available to disarm.');
    return {action:'configure_request_interception',mode:'continue',url_pattern:'*',expected_local_override:{metadata:action.local_override,
      method_filter:action.method_filter,content_type:action.response_headers['content-type']}};
  }
  function summaryMatches(action, experiment) {
    if (!action || !experiment || experiment.target_id !== action.local_override.target_id || experiment.experiment_id !== action.local_override.experiment_id) return false;
    const rule = experiment.rule, url = new URL(action.local_override.exact_url); url.search = '';
    return rule?.mode === 'fulfill' && rule.method_filter === action.method_filter && rule.response_code === 200 && rule.response_body_bytes === (action.response_body_bytes ?? bytes(action.response_body).length) &&
      Object.entries({...action.local_override, exact_url:url.href}).every(([key,value]) => rule.local_override?.[key] === value);
  }
  function install({root, getSession, contextKey, busy, run}) {
    if (!root) return {render() {}};
    const find = name => root.querySelector(`[data-override-${name}]`);
    const input = find('file'), preview = find('preview'), facts = find('facts'), status = find('status'), review = find('review');
    const prepareButton = find('prepare'), armButton = find('arm'), disarmButton = find('disarm'), clearButton = find('clear');
    let asset = null, prepared = null, attempted = null, preparedContext = null, attemptedContext = null;
    let revision = 0, pending = false, loading = false, lastContext = contextKey(), message = 'Choose one file. Nothing is prepared or armed.', outcome = 'none';
    const ready = () => !pending && !busy();
    const sameOwner = action => {
      const experiment = getSession()?.request_interception;
      return experiment?.isolated === true && experiment.target_id === action?.local_override.target_id && experiment.experiment_id === action?.local_override.experiment_id;
    };
    function render() {
      const currentContext = contextKey();
      if (lastContext !== currentContext) { prepared = null; preparedContext = null; review.checked = false; lastContext = currentContext; }
      const selected = context(getSession()), active = attempted?.local_override;
      prepareButton.disabled = !ready() || !asset || !review.checked || !selected;
      armButton.disabled = !ready() || !prepared || preparedContext !== contextKey() || !canArm(prepared,getSession());
      disarmButton.disabled = !ready() || !attempted || outcome === 'disarmed' || attemptedContext !== contextKey() || !sameOwner(attempted);
      clearButton.disabled = pending;
      input.disabled = pending;
      for (const name of ['url','method','type','ttl','review']) find(name).disabled = pending;
      review.disabled = pending || loading || !asset;
      const lines = [message];
      if (selected) lines.push(`Selected target ${selected.targetId} · experiment ${selected.experimentId}`);
      if (!selected) lines.push('Create an isolated context, then apply Target scope to its primary page.');
      if (prepared) lines.push(`Prepared only: ${prepared.method_filter} ${prepared.local_override.exact_url}\nTarget ${prepared.local_override.target_id} · experiment ${prepared.local_override.experiment_id}\nSHA-256 ${prepared.local_override.asset_sha256}\nExpires ${new Date(prepared.local_override.expires_at_ms).toISOString()}${Date.now() >= prepared.local_override.expires_at_ms ? ' (expired; prepare again)' : ''}`);
      if (active) {
        const current = attemptedContext === contextKey() && sameOwner(attempted);
        lines.push(`${outcome === 'armed' ? 'Arm acknowledged' : outcome === 'disarmed' ? 'Disarm acknowledged' : 'Operation outcome unknown'}: ${attempted.method_filter} ${active.exact_url}\nTarget ${active.target_id} · experiment ${active.experiment_id}\nSHA-256 ${active.asset_sha256}\nOriginal expiry ${new Date(active.expires_at_ms).toISOString()}`);
        if (!current) lines.push('The disposable session changed. This identity cannot operate on the new session.');
        else if (outcome !== 'disarmed' && Date.now() >= active.expires_at_ms) lines.push('Expired: new fulfillment admission is blocked. In-flight completion is not recalled.');
        else if (outcome !== 'disarmed') lines.push(summaryMatches(attempted,getSession()?.request_interception) ? 'Current public rule summary matches; its URL query is omitted by the backend.' : 'Current public rule summary differs or is unavailable. Do not assume this override is active.');
      }
      status.textContent = lines.join('\n\n');
    }
    function invalidate() { prepared = null; preparedContext = null; review.checked = false; render(); }
    input.addEventListener('change', async () => {
      const token = ++revision; loading = true; asset = null; preview.value = ''; facts.textContent = ''; invalidate();
      const file = input.files?.[0];
      if (!file) { loading = false; message = 'No file selected.'; render(); return; }
      message = 'Reading a bounded local byte snapshot…'; render();
      try {
        const next = await snapshot(file);
        if (token !== revision) return;
        asset = next; review.checked = false; preview.value = next.body;
        facts.textContent = `${file.name} · ${next.bytes} bytes · SHA-256 ${next.sha256}`;
        message = 'Snapshot loaded as inert text. Review it before preparing. Later file edits do not change these bytes.';
      } catch (error) { if (token !== revision) return; message = error.message; }
      loading = false; render();
    });
    for (const name of ['url','method','type','ttl']) find(name).addEventListener('input', invalidate);
    review.addEventListener('change', () => { prepared = null; preparedContext = null; render(); });
    prepareButton.addEventListener('click', () => {
      if (!ready()) return;
      try {
        prepared = prepare(asset,{url:find('url').value,method:find('method').value,contentType:find('type').value,ttlMs:Number(find('ttl').value)*1000,reviewed:review.checked},context(getSession()));
        preparedContext = contextKey(); message = 'Prepared snapshot. Arm explicitly to replace the single rule slot. No request has been sent.';
      } catch (error) { prepared = null; message = error.message; }
      render();
    });
    async function apply(disarming) {
      if (!ready()) return;
      const action = disarming ? attempted : prepared, key = disarming ? attemptedContext : preparedContext;
      if (!action || key !== contextKey() || (disarming ? !sameOwner(action) : !canArm(action,getSession()))) { message = 'The exact context or prepared lifetime is no longer valid. Nothing was sent.'; render(); return; }
      pending = true; attempted = Object.freeze({local_override:action.local_override, method_filter:action.method_filter, response_headers:action.response_headers,
        response_body_bytes:action.response_body_bytes ?? bytes(action.response_body).length}); attemptedContext = key; outcome = 'unknown';
      message = 'Waiting for the local backend. No automatic retry will be sent.'; render();
      try {
        const response = await run(disarming ? disarm(action) : action);
        if (key !== contextKey() || !response || response.ok !== true || response.experiment?.target_id !== action.local_override.target_id ||
            response.experiment?.experiment_id !== action.local_override.experiment_id ||
            (disarming ? response.experiment?.rule?.mode !== 'continue' : !summaryMatches(action,response.experiment))) throw Error('The operation was not confirmed. It may still be armed until its original expiry. Inspect the Experiment before another explicit action.');
        outcome = disarming ? 'disarmed' : 'armed';
        message = disarming ? 'The exact override was disarmed.' : 'The override was armed. A later matching disposable-page request may execute replacement JavaScript. No request was generated by Arm.';
        if (disarming) { prepared = null; preparedContext = null; }
      } catch (error) { message = `${error.message} No automatic retry was sent.`; }
      finally { pending = false; render(); }
    }
    armButton.addEventListener('click', () => apply(false));
    disarmButton.addEventListener('click', () => apply(true));
    clearButton.addEventListener('click', () => {
      if (pending) return;
      ++revision; loading = false; asset = null; prepared = null; preparedContext = null; preview.value = ''; facts.textContent = ''; input.value = ''; review.checked = false;
      // Keep the exact guarded-disarm identity until the panel closes or reloads.
      message = 'Local preview cleared. Clearing does not disarm a rule; use Disarm for the retained exact identity.'; render();
    });
    let timer = global.setInterval(render,1000);
    global.addEventListener?.('pagehide', () => { global.clearInterval(timer); timer = null; });
    global.addEventListener?.('pageshow', () => { if (timer === null) timer = global.setInterval(render,1000); render(); });
    render(); return {render};
  }
  const api = {snapshot,context,prepare,canArm,disarm,summaryMatches,install};
  global.RebLocalOverrideManager = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
