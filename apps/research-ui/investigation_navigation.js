/* One in-memory navigation boundary. Identities are evidence, URLs are search hints.
 * No raw captures, drafts or DOM nodes are retained in history or browser storage. */
/** @typedef {{type:'captured-artifact',session:string,artifact:string,sha256:string,bytes:number}} InvestigationArtifact
 * @typedef {{type:'captured-request',session:string,process:string,sequence:string,request:string}} InvestigationRequest
 * @typedef {{type:'debugger-request',id:string,target:string,protocol:string,started:string}} InvestigationDebuggerRequest
 * All references are exact retained identities, never URL or name matches. */
const INVESTIGATION_HISTORY_LIMIT = 24;
const investigationId = value => {
  const text = typeof value === 'bigint' ? String(value) : typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : value;
  return typeof text === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(text) && BigInt(text) <= 18446744073709551615n ? text : null;
};
function investigationEventIdentity(event) {
  if (!event) return null;
  const session = investigationId(event.session_id), process = investigationId(event.process_id), sequence = investigationId(event.sequence_number);
  return session && session !== '0' && process && process !== '0' && sequence && sequence !== '0'
    ? {type: 'captured-event', session, process, sequence} : null;
}
function investigationArtifactIdentity(artifact) {
  const session = investigationId(artifact?.session_id), artifactId = investigationId(artifact?.artifact_id);
  return session && session !== '0' && artifactId && artifactId !== '0' && /^[0-9a-f]{64}$/.test(artifact?.sha256) && Number.isSafeInteger(artifact?.byte_size) && artifact.byte_size >= 0
    ? {type: 'captured-artifact', session, artifact: artifactId, sha256: artifact.sha256, bytes: artifact.byte_size} : null;
}
// Match the Sources owner tuple without serializing unbounded debugger strings.
// Oversized/unknown metadata cannot be replayed as an exact live-source return.
function investigationScriptIdentity(source) {
  if (!source || typeof source.script_id !== 'string') return null;
  const id = source.script_id, target = source.target_id ?? state.debuggerSession?.target?.id ?? '', hash = source.hash;
  if ([id, target, hash].some(value => typeof value !== 'string' || !value.length || value.length > 256)) return null;
  const context = source.execution_context_id ?? null, line = source.start_line ?? 0, column = source.start_column ?? 0, length = source.length ?? null;
  if ([context, length].some(value => value !== null && (!Number.isSafeInteger(value) || value < 0)) ||
      [line, column].some(value => !Number.isSafeInteger(value) || value < 0)) return null;
  return {type:'live-script', id, target, hash, context, line, column, length};
}
function investigationRequestIdentity(request) {
  if (!request || request.origin !== 'live') return null;
  // CDP/native correlation is currently host+method+time. It cannot promote a
  // debugger request to an exact native-event identity.
  if (request.protocolRequestId || String(request.operation).startsWith('cdp_')) {
    if (typeof request.id !== 'string' || request.id.length > 256 || typeof request.tabId !== 'string' || request.tabId.length > 256 || typeof request.protocolRequestId !== 'string' || request.protocolRequestId.length > 256) return null;
    const started = investigationId(request.firstTimestamp);
    return started ? {type: 'debugger-request', id: request.id, target: request.tabId, protocol: request.protocolRequestId, started} : null;
  }
  const root = requestTraceRoot(request), event = investigationEventIdentity(root);
  const requestId = investigationId(root?.request_id);
  return event && requestId && requestId !== '0' ? {...event, type: 'captured-request', request: requestId} : null;
}
function investigationSame(left, right) {
  if (!left || !right || left.type !== right.type) return false;
  const fields = { 'captured-event': ['session','process','sequence'], 'captured-request': ['session','process','sequence','request'],
    'captured-artifact': ['session','artifact','sha256','bytes'], 'debugger-request': ['id','target','protocol','started'], 'live-script': ['id','target','hash','context','line','column','length'] }[left.type];
  return Boolean(fields) && fields.every(field => left[field] === right[field]);
}
function investigationResolve(identity, records, identityOf) {
  if (!identity) return {status: 'unavailable', message: 'Exact captured identity is unavailable.'};
  const exact = records.filter(record => investigationSame(identity, identityOf(record)));
  if (exact.length > 1) return {status: 'ambiguous', message: 'More than one retained record has this identity. Choose the evidence explicitly.'};
  if (exact.length === 1) return {status: 'ready', record: exact[0]};
  return {status: 'stale', message: 'This exact evidence is no longer retained, or its session or content changed. Nothing was fetched or recaptured.'};
}
function createInvestigationHistory({snapshot, restore, changed, limit = INVESTIGATION_HISTORY_LIMIT}) {
  const back = [], forward = [];
  const boundedLimit = Math.min(INVESTIGATION_HISTORY_LIMIT, Math.max(1, limit));
  const update = () => changed({back: back.at(-1) ?? null, forward: forward.at(-1) ?? null, count: back.length + forward.length});
  const push = entry => { back.push(entry); while (back.length + forward.length > boundedLimit) back.shift(); };
  function move(from, to) {
    if (!from.length) return false;
    const current = snapshot(), target = from.at(-1);
    if (!restore(target)) { update(); return false; }
    from.pop(); to.push(current); update(); return true;
  }
  return {record() { forward.length = 0; push(snapshot()); update(); }, back: () => move(back, forward), forward: () => move(forward, back),
    clear() {back.length = 0; forward.length = 0; update();}, update};
}

let investigationNavigation = null;
let investigationRestore = false;
let investigationRevision = 0;
let investigationRange = null;
let investigationPendingReturn = null;
let investigationPassiveSource = false;
let investigationDecoderOrigin = null;
const investigationNames = {traffic:'Requests', backtrace:'Backtrace', sources:'Sources', tools:'Decoder', signals:'Fingerprinting', 'api-collection':'Collection', 'field-provenance':'Field trace', experiments:'Experiments', analyst:'Analyst', memory:'Memory', vm:'VM candidates'};
const investigationScreen = () => document.querySelector('.screen:not([hidden])')?.id.replace('screen-', '') ?? 'traffic';
function investigationSelector(node, root = document, stableOnly = false) {
  if (!node || !root.contains(node)) return null;
  if (node.id) return `#${CSS.escape(node.id)}`;
  if (stableOnly) {
    // Dynamic rows may reorder while a local read is pending. Never restore
    // focus by ordinal position into a different piece of evidence.
    for (const key of ['requestId','traceKey','artifactId','scriptId']) {
      const value = node.dataset?.[key];
      if (!value || value.length > 256 || key === 'traceKey' && value.startsWith('gap:')) continue;
      const attribute = key.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`);
      const selector = `[data-${attribute}="${CSS.escape(value)}"]`;
      if (root.querySelectorAll(selector).length === 1 && root.querySelector(selector) === node) return selector;
    }
    return null;
  }
  const parts = [];
  for (let current = node; current && current !== root && parts.length < 8; current = current.parentElement) {
    if (current.id) {parts.unshift(`#${CSS.escape(current.id)}`); break;}
    const siblings = [...(current.parentElement?.children ?? [])].filter(other => other.localName === current.localName);
    parts.unshift(`${current.localName}:nth-of-type(${siblings.indexOf(current) + 1})`);
  }
  const selector = parts.join(' > ');
  return selector.length <= 512 && root.querySelector(selector) === node ? selector : null;
}
function investigationNotice(message, status = 'ready') {
  const bar = document.querySelector('#investigation-navigation');
  bar.hidden = false; bar.dataset.status = status;
  if (status !== 'ready') bar.querySelector('details').open = true;
  document.querySelector('#investigation-notice').textContent = message;
}
function investigationSnapshot() {
  const screen = investigationScreen(), root = document.querySelector(`#screen-${screen}`);
  const request = state.requests.find(item => item.id === state.selectedRequestId);
  const source = selectedSource();
  const scroll = [];
  const panes = '.exchange-content, .detail-pane, .sources-editor, .sources-navigator, .debug-panes, .trace-inspector, .trace-list-pane, .decoder-column, .tools-shell, #request-rows, #source-code-wrap, #source-tree, #backtrace-steps, #decoder-input, #decoder-output';
  for (const node of new Set([root, ...root.querySelectorAll(panes)])) {
    if (scroll.length >= 32) break;
    const selector = investigationSelector(node, root);
    if (selector) scroll.push({selector, top: Math.min(node.scrollTop, 1e8), left: Math.min(node.scrollLeft, 1e8)});
  }
  return {screen, label: investigationNames[screen] ?? 'workspace', request: investigationRequestIdentity(request),
    artifact: investigationArtifactIdentity(source), script: source?.source_type === 'script' ? investigationScriptIdentity(source) ?? {unavailable:true} : null,
    consoleScope: screen === 'traffic' && root.dataset.consoleTraffic === 'true' ? {session:document.querySelector('#console-experiment-traffic').dataset.session, target:document.querySelector('#console-experiment-traffic').dataset.document} : null,
    runtimeHook: screen === 'traffic' && state.selectedRuntimeHookRequest ? {...state.selectedRuntimeHookRequest} : null,
    inspectorTab: state.inspectorTab, fieldTab: state.fieldTab, fieldPath: String(state.selectedField?.path ?? '').slice(0,1024),
    sourceRange: investigationSame(investigationRange?.identity, investigationArtifactIdentity(source)) ? {start:investigationRange.start,end:investigationRange.end} : null,
    traceRow: state.selectedTraceRow, traceGap: investigationSelectedGap(), decoderStep: state.decoderSelectedStepId,
    sourceFormatted: state.sourceFormatted, sourceDeobfuscated: state.sourceDeobfuscated, sourceWasm: state.sourceWasm,
    focus: investigationSelector(document.activeElement, root, true), scroll,
    notice: document.querySelector('#investigation-notice').textContent.slice(0,1024)};
}
function restoreInvestigation(entry) {
  let request, source;
  if (entry.screen === 'sources' && entry.script?.unavailable) {
    investigationNotice('Return unavailable: the original live script identity was unknown or exceeded the bounded navigation metadata limit.', 'unavailable'); return false;
  }
  if (['traffic','backtrace'].includes(entry.screen) && !entry.consoleScope && !entry.runtimeHook && entry.request) {
    request = investigationResolve(entry.request, state.requests, investigationRequestIdentity);
    if (request.status !== 'ready') {investigationNotice(`Return unavailable: ${request.message}`, request.status); return false;}
    if (state.requests.filter(item => item.id === request.record.id).length !== 1) {investigationNotice('Return unavailable: Requests cannot disambiguate this reused row identifier.', 'ambiguous'); return false;}
  }
  if (entry.screen === 'sources' && entry.artifact) {
    source = investigationResolve(entry.artifact, state.artifacts, investigationArtifactIdentity);
    if (source.status !== 'ready') {investigationNotice(`Return unavailable: ${source.message}`, source.status); return false;}
    if (state.artifacts.filter(item => item.artifact_id === source.record.artifact_id).length !== 1) {investigationNotice('Return unavailable: Sources cannot disambiguate this reused artifact identifier.', 'ambiguous'); return false;}
  }
  if (entry.screen === 'sources' && entry.script) {
    const candidates = (state.debuggerSession?.scripts ?? []).filter(item => item.script_id === entry.script.id && !state.staleScriptIds?.has(item.script_id));
    const matches = candidates.filter(item => investigationSame(entry.script, investigationScriptIdentity(item)));
    if (matches.length !== 1 || candidates.length !== 1) {investigationNotice('Return unavailable: the original live script detached, changed or is ambiguous.', 'stale'); return false;}
  }
  if (entry.consoleScope) {
    const panel = document.querySelector('#console-experiment-traffic');
    if (panel.dataset.session !== entry.consoleScope.session || panel.dataset.document !== entry.consoleScope.target) {investigationNotice('Return unavailable: this separate Console activity view has been replaced.', 'stale'); return false;}
  }
  if (entry.runtimeHook && (runtimeHooksState()?.session_id !== entry.runtimeHook.sessionId || !runtimeHooksState()?.requests.some(item => item.id === entry.runtimeHook.id))) {investigationNotice('Return unavailable: the isolated request trail expired.', 'stale'); return false;}
  retireInvestigationReturn();
  investigationRestore = true;
  try {
    if (request && state.selectedRequestId !== request.record.id) selectRequest(request.record.id, entry.request);
    if (entry.screen === 'traffic') {
      if (entry.consoleScope) document.querySelector('#screen-traffic').dataset.consoleTraffic = 'true';
      else delete document.querySelector('#screen-traffic').dataset.consoleTraffic;
      document.querySelector('#console-experiment-traffic').hidden = !entry.consoleScope;
      state.selectedRuntimeHookRequest = entry.runtimeHook;
      state.inspectorTab = entry.inspectorTab; state.fieldTab = entry.fieldTab; state.selectedField = fieldSets[entry.fieldTab]?.find(field => field.path === entry.fieldPath) ?? null; renderInspector();}
    if (entry.screen === 'backtrace') state.selectedTraceRow = entry.traceRow;
    if (source && selectArtifact(source.record.artifact_id, null, {passive:true, identity:entry.artifact}) === false) return false;
    if (entry.screen === 'sources' && entry.script && selectScript(entry.script.id) === false) return false;
    if (entry.screen === 'sources') {
      investigationPassiveSource = true;
      state.sourceFormatted = entry.sourceFormatted; state.sourceDeobfuscated = entry.sourceDeobfuscated; state.sourceWasm = entry.sourceWasm;
    }
    if (entry.screen === 'tools' && state.decoderSteps.some(step => step.id === entry.decoderStep)) state.decoderSelectedStepId = entry.decoderStep;
    showScreen(entry.screen, document.querySelector('#investigation-back'));
    const revision = investigationRevision;
    const returningRange = source && entry.sourceRange && !entry.sourceFormatted && !entry.sourceDeobfuscated;
    investigationPendingReturn = {revision, source: Boolean(returningRange)};
    const read = returningRange ? sourceFactsPanel.navigate(entry.sourceRange)
      : entry.screen === 'backtrace' && (!state.originTrace || state.originTraceKey !== originTraceSelection()?.key)
        ? refreshOriginTrace() : null;
    investigationNotice(entry.notice || `Returned to ${entry.label}. Existing drafts are preserved.`);
    Promise.resolve(read).then(() => requestAnimationFrame(() => {
      if (investigationPendingReturn?.revision === revision) investigationPendingReturn = null;
      if (revision !== investigationRevision || !investigationContextMatches(entry)) return;
      if (entry.screen === 'backtrace') {
        if (state.originTraceStatus === 'error') {investigationNotice(`Return trace unavailable: ${state.originTraceError}`, 'unavailable'); return;}
        const restoredRow = entry.traceRow?.startsWith('gap:') ? investigationGapKey(entry.traceGap) : entry.traceRow;
        state.selectedTraceRow = restoredRow;
        renderBacktrace();
        if (entry.traceRow && (!restoredRow || state.selectedTraceRow !== restoredRow)) investigationNotice('The request trace was reopened, but its previously selected step is no longer retained.', 'stale');
      }
      const root = document.querySelector(`#screen-${entry.screen}`);
      for (const saved of entry.scroll) {const node = root.matches(saved.selector) ? root : root.querySelector(saved.selector); if (node) {node.scrollTop = saved.top; node.scrollLeft = saved.left;}}
      const focus = entry.focus && root.querySelector(entry.focus);
      (focus ?? document.querySelector('#investigation-back')).focus({preventScroll:true});
    }));
    return true;
  } finally {investigationRestore = false;}
}
function investigationSelectedGap() {
  const match = /^gap:(\d+):(\d+)$/.exec(state.selectedTraceRow ?? '');
  if (!match) return null;
  const after = Number(match[1]);
  const gap = state.originTrace?.gaps?.filter(item => item.after_step === after)[Number(match[2])];
  const event = investigationEventIdentity(state.originTrace?.steps?.[after]?.event);
  return gap && event ? {event, reason:gap.reason, detail:gap.detail.slice(0,1024)} : null;
}
function investigationGapKey(saved) {
  if (!saved) return null;
  const gaps = state.originTrace?.gaps ?? [];
  const matches = gaps.filter(gap => gap.reason === saved.reason && gap.detail === saved.detail &&
    investigationSame(saved.event, investigationEventIdentity(state.originTrace?.steps?.[gap.after_step]?.event)));
  if (matches.length !== 1) return null;
  const gap = matches[0];
  return `gap:${gap.after_step}:${gaps.filter(item => item.after_step === gap.after_step).indexOf(gap)}`;
}
function investigationContextMatches(entry) {
  if (investigationScreen() !== entry.screen) return false;
  if (entry.screen === 'sources') {
    const source = selectedSource();
    if (entry.artifact && state.artifacts.filter(item => item.artifact_id === entry.artifact.artifact).length !== 1) return false;
    if (entry.artifact && !investigationSame(entry.artifact, investigationArtifactIdentity(source))) return false;
    if (entry.script && !investigationSame(entry.script, investigationScriptIdentity(source))) return false;
    if (state.sourceFormatted !== entry.sourceFormatted || state.sourceDeobfuscated !== entry.sourceDeobfuscated || state.sourceWasm !== entry.sourceWasm) return false;
  }
  if (['traffic','backtrace'].includes(entry.screen) && entry.request && !entry.consoleScope && !entry.runtimeHook) {
    if (state.requests.filter(item => item.id === state.selectedRequestId).length !== 1 ||
        !investigationSame(entry.request, investigationRequestIdentity(state.requests.find(item => item.id === state.selectedRequestId)))) return false;
  }
  return true;
}
function retireInvestigationReturn() {
  investigationRevision += 1;
  const pending = investigationPendingReturn;
  investigationPendingReturn = null;
  if (pending?.source || sourceFactsPanel.model?.status === 'loading-source') sourceFactsPanel.cancel('A newer interaction retired this original-range return.');
}
function investigationBeforeSelection() { retireInvestigationReturn(); }
function investigationBeforeScreen(name) {
  if (!investigationRestore && investigationNavigation && name !== investigationScreen()) investigationNavigation.record();
  retireInvestigationReturn();
}
function openInvestigation({kind, identity, relation, inspectorTab, range}) {
  if (!['artifact','request','trace'].includes(kind)) {investigationNotice('This investigation destination is unavailable.', 'unavailable'); return false;}
  const artifact = kind === 'artifact';
  const result = investigationResolve(identity, artifact ? state.artifacts : state.requests, artifact ? investigationArtifactIdentity : investigationRequestIdentity);
  if (result.status !== 'ready') {investigationNotice(result.message, result.status); return false;}
  if (!artifact && state.requests.filter(item => item.id === result.record.id).length !== 1) {investigationNotice('This row identifier is shared by multiple retained requests. Requests cannot disambiguate it.', 'ambiguous'); return false;}
  if (artifact && state.artifacts.filter(item => item.artifact_id === result.record.artifact_id).length !== 1) {
    investigationNotice('This artifact identifier is shared by multiple retained records. The current Sources selector cannot disambiguate it.', 'ambiguous'); return false;
  }
  if (artifact && !['javascript','wasm','source_map','response_body'].includes(result.record.kind)) {investigationNotice('This retained artifact has no Sources view. Its identity remains in the trace.', 'unavailable'); return false;}
  if (artifact && range && (result.record.kind !== 'javascript' || !sourceFactsRange(range, result.record.byte_size))) {investigationNotice('This original byte range is unavailable through the verified JavaScript Facts view.', 'unavailable'); return false;}
  if (kind === 'trace' && identity.type !== 'captured-request') {
    investigationNotice('A debugger/native host-and-time match is correlation only. No exact captured request trace link is available.', 'unavailable'); return false;
  }
  const destination = artifact ? 'sources' : kind === 'trace' ? 'backtrace' : 'traffic';
  if (artifact || investigationScreen() === destination) investigationNavigation?.record();
  if (artifact) {
    investigationRestore = true;
    try {
      if (selectArtifact(result.record.artifact_id, null, {passive: true, identity}) === false) return false;
      showScreen(destination);
    } finally {investigationRestore = false;}
    const revision = investigationRevision;
    requestAnimationFrame(() => {if (revision === investigationRevision && investigationScreen() === 'sources') elements.sourceCodeWrap.focus({preventScroll:true});});
    if (range) void sourceFactsPanel.navigate(range);
  }
  else {
    showScreen(destination);
    delete document.querySelector('#screen-traffic').dataset.consoleTraffic;
    document.querySelector('#console-experiment-traffic').hidden = true;
    state.selectedRuntimeHookRequest = null;
    renderRuntimeHookTraffic();
    if (state.selectedRequestId !== result.record.id) selectRequest(result.record.id, identity);
    if (inspectorTab) {state.inspectorTab = inspectorTab; renderInspector();}
    const ready = kind === 'trace' ? refreshOriginTrace() : null;
    const revision = investigationRevision;
    Promise.resolve(ready).then(() => requestAnimationFrame(() => {
      if (revision !== investigationRevision || investigationScreen() !== destination ||
          !investigationSame(identity, investigationRequestIdentity(state.requests.find(item => item.id === state.selectedRequestId)))) return;
      const focus = kind === 'trace' ? [...elements.backtraceSteps.querySelectorAll('.trace-row')].find(row => row.dataset.traceKey === state.selectedTraceRow) ?? elements.traceLoad
        : [...elements.requestRows.querySelectorAll('.request-row')].find(row => row.dataset.requestId === state.selectedRequestId) ?? elements.requestFilter;
      focus?.focus({preventScroll:true});
    }));
  }
  investigationNotice(relation || (artifact ? 'Exact retained session, artifact and SHA-256. No execution or value flow is implied.' : 'Exact retained request identity.'));
  return true;
}
function investigationTraceArtifact(step) {
  const session = investigationId(step?.event?.session_id), id = investigationId(step?.artifact_id);
  if (!session || !id || id === '0') return {status:'unavailable', message:'No source artifact identity was recorded for this trace step.'};
  const matches = state.artifacts.filter(item => investigationId(item.session_id) === session && investigationId(item.artifact_id) === id);
  if (matches.length === 1 && state.artifacts.filter(item => investigationId(item.artifact_id) === id).length > 1) return {status:'ambiguous', message:'This artifact identifier is reused across retained sessions; Sources cannot disambiguate it.'};
  if (matches.length !== 1) return {status:matches.length ? 'ambiguous' : 'unavailable', message:matches.length ? 'Multiple retained artifacts match this trace identity.' : 'The source artifact for this exact session is not retained. No refetch is attempted.'};
  if (!['javascript','wasm','source_map','response_body'].includes(matches[0].kind)) return {status:'unavailable', message:'This retained artifact has no Sources view. Its identity remains in this trace.'};
  const identity = investigationArtifactIdentity(matches[0]);
  return identity ? {status:'ready', identity} : {status:'unavailable', message:'Artifact hash or byte-size identity is unavailable.'};
}
function investigationAllowDecoderReplace() {
  if (state.decoderPending || state.jwtPending) {investigationNotice('Wait for or cancel the current Decoder operation before opening another value.', 'unavailable'); return false;}
  if ((toolsElements.input.value || state.decoderSteps.length) && !window.confirm('Replace the current Decoder input and chain with this selected value? Existing source and request evidence stay unchanged.')) return false;
  return true;
}
function investigationDecode(value, origin) {
  if (!investigationAllowDecoderReplace()) return false;
  const bytes = typeof value === 'string' ? provenanceDecoderBytes(value) : value;
  if (!(bytes instanceof Uint8Array) || bytes.length > 65536) {investigationNotice('Decode links require an exact representable value of at most 64 KiB.', 'unavailable'); return false;}
  showScreen('tools');
  resetDecoderChain('Selected bytes copied. Choose a transformation explicitly; navigation never runs one.');
  toolsElements.inputEncoding.value = 'base64'; toolsElements.input.value = decoderBytesToBase64(bytes);
  investigationDecoderOrigin = {route: origin.route, description: String(origin.description).slice(0,1024), key: decoderCurrentInputKey()};
  setToolsTab('decoder'); renderInvestigationDecoder();
  investigationNotice(origin.description);
  const revision = investigationRevision;
  requestAnimationFrame(() => {if (revision === investigationRevision && investigationScreen() === 'tools') toolsElements.operation.focus({preventScroll:true});});
  return true;
}
function renderInvestigationDecoder() {
  const panel = document.querySelector('#investigation-decoder-origin');
  if (!panel) return;
  panel.hidden = !investigationDecoderOrigin;
  if (!investigationDecoderOrigin) return;
  const current = investigationDecoderOrigin.key === decoderCurrentInputKey();
  panel.querySelector('p').textContent = `${investigationDecoderOrigin.description} ${current ? 'Input matches this handoff. Transformations are local interpretations, not proof of page value flow.' : 'Input changed. This origin describes the earlier handoff, not the current bytes.'}`;
  panel.dataset.status = current ? 'ready' : 'stale';
  panel.querySelector('button').disabled = !investigationDecoderOrigin.route;
}
function rememberInvestigationRange(source, range) {
  investigationRange = {identity: investigationArtifactIdentity(source), start: range.start, end: range.end};
  document.querySelector('#investigation-decode-range').disabled = !investigationRange.identity || range.end - range.start > 65536;
}
function syncInvestigationRange(source) {
  const saved = investigationRange;
  document.querySelector('#investigation-decode-range').disabled = !saved || !investigationSame(saved.identity, investigationArtifactIdentity(source)) || sourceFactsPanel.original(source) === undefined || state.sourceFormatted || state.sourceDeobfuscated || saved.end - saved.start > 65536;
}
function decodeInvestigationRange() {
  const source = selectedSource(), saved = investigationRange;
  const original = sourceFactsPanel.original(source);
  if (!saved || !investigationSame(saved.identity, investigationArtifactIdentity(source)) || original === undefined || state.sourceFormatted || state.sourceDeobfuscated) {
    investigationNotice('Select an Original bytes link in Facts first. A preview or derived view cannot supply exact original bytes.', 'stale'); return;
  }
  const bytes = new TextEncoder().encode(original).subarray(saved.start, saved.end);
  investigationDecode(bytes, {route:{kind:'artifact', identity:saved.identity, range:{start:saved.start,end:saved.end}, relation:`Original source bytes [${saved.start}, ${saved.end}) · UTF-8 byte offsets, SHA-256 verified.`}, description:`Captured source · session ${saved.identity.session} · artifact ${saved.identity.artifact} · original bytes [${saved.start}, ${saved.end}) · SHA-256 ${saved.identity.sha256}.`});
}
function investigationSourceSearch({url}) {
  if (typeof url !== 'string' || url.length > 8192) return false;
  const matches = capturedSources().filter(source => source.url === url).slice(0,20);
  const panel = document.querySelector('#investigation-source-search');
  panel.replaceChildren(); panel.hidden = false;
  const description = document.createElement('p');
  description.textContent = `Console source search: ${matches.length ? `${matches.length} retained URL match${matches.length === 1 ? '' : 'es'} (at most 20 shown). Choose a candidate.` : 'No retained captured source has this URL.'} Console uses a separate disposable browser. URL matches do not verify shared identity, line offsets or causality. Nothing was fetched.`;
  panel.append(description);
  for (const source of matches) {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'secondary-button';
    button.textContent = `Inspect candidate · session ${source.session_id} · artifact ${source.artifact_id}`;
    const identity = investigationArtifactIdentity(source); button.disabled = !identity;
    button.addEventListener('click', () => {if (openInvestigation({kind:'artifact', identity, relation:'User-selected URL search candidate. Its relation to the separate Console browser is unverified; Console line offsets were not applied.'})) panel.hidden = true;});
    panel.append(button);
  }
  const close = document.createElement('button'); close.type = 'button'; close.className = 'secondary-button'; close.textContent = 'Close search';
  close.addEventListener('click', () => {panel.hidden = true; document.querySelector('#native-console-toggle').focus();}); panel.append(close);
  investigationNotice('Source search only. The Console browser has no captured-artifact identity.', 'unverified');
  return true;
}
function initializeInvestigationNavigation() {
  investigationNavigation = createInvestigationHistory({snapshot:investigationSnapshot, restore:restoreInvestigation, changed:({back,forward,count}) => {
    const previous = document.querySelector('#investigation-back'), next = document.querySelector('#investigation-forward');
    if (count) document.querySelector('#investigation-navigation').hidden = false;
    previous.disabled = !back; next.disabled = !forward;
    previous.textContent = back ? `Back to ${back.label}` : 'Back'; next.textContent = forward ? `Forward to ${forward.label}` : 'Forward';
    document.querySelector('#investigation-history-count').textContent = `${count}/${INVESTIGATION_HISTORY_LIMIT} in-memory stops`;
  }});
  document.querySelector('#investigation-back').addEventListener('click', () => investigationNavigation.back());
  document.querySelector('#investigation-forward').addEventListener('click', () => investigationNavigation.forward());
  document.querySelector('#investigation-clear').addEventListener('click', () => {investigationNavigation.clear(); investigationNotice('Return history cleared. Workspace drafts and captured evidence are unchanged.');});
  document.querySelector('#investigation-decode-range').addEventListener('click', decodeInvestigationRange);
  document.querySelector('#investigation-decoder-origin button').addEventListener('click', () => {if (investigationDecoderOrigin?.route) openInvestigation(investigationDecoderOrigin.route);});
  toolsElements.input.addEventListener('input', renderInvestigationDecoder);
  toolsElements.inputEncoding.addEventListener('change', renderInvestigationDecoder);
  for (const type of ['pointerdown','wheel','keydown']) document.addEventListener(type, event => {
    retireInvestigationReturn();
  }, {capture: true, passive: type === 'wheel'});
  document.addEventListener('keydown', event => {
    if (!event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || !['ArrowLeft','ArrowRight'].includes(event.key) || event.target.matches?.('input,textarea,select,[contenteditable="true"]')) return;
    event.preventDefault(); if (event.key === 'ArrowLeft') investigationNavigation.back(); else investigationNavigation.forward();
  });
  investigationNavigation.update();
}

// A Collection recipe is a user-created template, never a captured request.
// Retain only the selected identity and bounded template fields while this one
// explicit copy is pending; the normal return trail owns the source location.
function investigationCollectionTemplate(request) {
  if (!request || request.hostOnly || request.urlTruncated || typeof request.path !== 'string' || request.path.length > 8192 ||
      typeof request.method !== 'string' || !/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$/.test(request.method)) return null;
  try {
    const url = new URL(request.path);
    if (!['http:','https:'].includes(url.protocol) || url.username || url.password) return null;
    url.search = ''; url.hash = '';
    const name = url.pathname.split('/').filter(Boolean).at(-1) || url.hostname;
    return {name: `${request.method} ${name}`.slice(0,128), url:url.href, method:request.method};
  } catch {return null;}
}
async function copyInvestigationRequestToCollection() {
  if (state.investigationCollectionImportPending) return null;
  const selected = state.requests.find(request => request.id === state.selectedRequestId);
  const identity = investigationRequestIdentity(selected);
  const template = investigationCollectionTemplate(selected);
  if (!identity || !template || state.requests.filter(request => request.id === selected?.id).length !== 1) {
    investigationNotice('Copy unavailable: choose one retained request with an exact identity and a complete credential-free HTTP URL. Host-only or truncated metadata cannot supply a Collection URL.', 'unavailable'); return null;
  }
  const revision = investigationRevision;
  const sourceId = selected.id;
  const ownsSelection = () => {
    if (revision !== investigationRevision || investigationScreen() !== 'traffic' || state.selectedRequestId !== sourceId) return false;
    const candidates = state.requests.filter(request => request.id === sourceId);
    const current = candidates.length === 1 ? candidates[0] : null;
    const currentTemplate = investigationCollectionTemplate(current);
    return investigationSame(identity, investigationRequestIdentity(current)) && currentTemplate?.method === template.method && currentTemplate.url === template.url;
  };
  state.investigationCollectionImportPending = true;
  const label = elements.requestCollectionPivot.textContent;
  elements.requestCollectionPivot.textContent = 'Copying…'; renderInspector();
  try {
    if (!await refreshApiCollection()) {
      if (ownsSelection()) investigationNotice('Collection could not be refreshed. No copy was created; its existing drafts remain unchanged.', 'unavailable');
      return null;
    }
    if (!ownsSelection()) return null;
    const id = await createCollectionRequest(template, {focus:false});
    if (!Number.isSafeInteger(id) || id < 1) {
      if (ownsSelection()) investigationNotice(state.apiCollectionMessage || 'Collection declined the copy. Save or discard its existing draft before retrying.', 'unavailable');
      return null;
    }
    const saved = state.apiCollection.requests.filter(request => request.id === id);
    if (saved.length !== 1 || saved[0].method !== template.method || saved[0].url !== template.url || saved[0].body !== '' || saved[0].headers.length || saved[0].variables.length) {
      if (ownsSelection()) investigationNotice('Collection replied, but the copied recipe could not be verified. Check Collection before retrying.', 'unavailable');
      return null;
    }
    if (!ownsSelection()) return id;
    showScreen('api-collection', elements.requestCollectionPivot);
    investigationNotice(`Copied method and query-free URL to Collection recipe #${id}. This is a saved template, not captured evidence or proof of execution. Back returns to the retained request. No request was sent.`);
    const destinationRevision = investigationRevision, createdAt = saved[0].created_at_ms;
    requestAnimationFrame(() => {
      if (destinationRevision === investigationRevision && investigationScreen() === 'api-collection' && state.collectionSelectedRequestId === id &&
          state.apiCollection.requests.some(request => request.id === id && request.created_at_ms === createdAt)) elements.collectionRequestName.focus({preventScroll:true});
    });
    return id;
  } finally {
    state.investigationCollectionImportPending = false;
    elements.requestCollectionPivot.textContent = label; renderInspector();
  }
}
