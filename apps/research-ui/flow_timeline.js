/* Tracked-call timeline for the Flow workspace. One track per recorded
 * JavaScript invocation, in each renderer's own record order, never wall-clock
 * time. The records come from one filtered, paged `/api/events` read; every
 * bound below is visible as a count, so nothing is dropped silently. The read
 * also takes the budget refusals (overflow identities and `gap` markers) so a
 * sample count never reads as every execution when some were refused. */
const FLOW_TIMELINE_TYPES = ['wasm_dispatch_observation', 'wasm_indirect_observation', 'wasm_dispatch_overflow', 'wasm_indirect_overflow',
  'js_invocation_start', 'js_invocation_settle', 'js_invocation_request', 'gap'];
// Every type above is a `vm` record; the category keeps other producers' gap markers out.
const FLOW_TIMELINE_CATEGORY = 'vm';
/* Native budgets cap these streams (256 starts and 256 requests per
 * configuration, 16 br_table and 16 call_indirect samples), so a few pages
 * cover a session; the caps keep a long store from filling the page. */
const FLOW_TIMELINE_LIMITS = Object.freeze({pageSize: 1000, pagesPerRead: 4, maxRecords: 8000, maxPageBytes: 8 * 1024 * 1024,
  maxTracks: 64, maxSamples: 512, maxRequests: 128, maxGapMarks: 64, maxGapReasons: 6, unit: 22, gapCap: 6, labelEvery: 96});
// A complete read is read again quietly when Flow redraws this long after it.
const FLOW_TIMELINE_STALE_MS = 15000;
// The decoded settle names its value kind (protocol/native-js-invocation-v1.md).
const FLOW_VALUE_NAMES = {bigint: 'BigInt', array_buffer: 'ArrayBuffer', array_buffer_view: 'typed array'};
// A settle reached by a synchronous return or throw ran start to settle without yielding.
const FLOW_SYNC_VIA = new Set(['sync_return', 'sync_throw']);
const FLOW_INVOCATION_STATES = ['not observed', 'none', 'inside', 'unknown'];

/** A canonical unsigned decimal sequence number as a BigInt, else null. */
function flowSeq(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value > 0) return BigInt(value);
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value)) return null;
  const seq = BigInt(value);
  return seq <= 18446744073709551615n ? seq : null;
}
const flowSeqOrder = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const flowNumber = value => Number(value).toLocaleString('en-US');
const flowHex = value => `+0x${Number(value).toString(16)}`;

/** What a settle returned, from its kind and length; never its content. */
function flowValueLabel(kind, length) {
  const name = FLOW_VALUE_NAMES[kind] ?? (kind || 'value');
  if (!Number.isSafeInteger(length) || length <= 0) return name;
  if (kind === 'string') return `${name} · ${flowNumber(length)} UTF-16 units`;
  if (kind === 'array') return `${name} · ${flowNumber(length)} elements`;
  if (kind === 'array_buffer' || kind === 'array_buffer_view') return `${name} · ${flowNumber(length)} bytes`;
  return name;
}

/** A gap counter from a page: a canonical unsigned decimal string, else 0. */
function flowCount(value) {
  if (value === '0' || value === 0) return 0n;
  return flowSeq(value) ?? 0n;
}
/** A `gap` marker as the backend reads it (protocol/http-api.md): a payload
 * naming a producer reason is a named gap; any other marker is a queue drop
 * that weighs its canonical decimal payload, else one record. */
function flowGapRecord(event, key, seq) {
  const hex = typeof event.payload === 'string' && event.payload.length <= 512 && event.payload.length % 2 === 0 && /^[0-9a-f]*$/i.test(event.payload) ? event.payload : '';
  let text = '';
  if (event.payload_truncated !== true) for (let at = 0; at < hex.length; at += 2) text += String.fromCharCode(Number.parseInt(hex.slice(at, at + 2), 16));
  const named = /^[a-z][a-z0-9_]{0,127}$/.test(text) && typeof event.category === 'string' && /^[a-z][a-z0-9_]{0,31}$/.test(event.category);
  const count = !named && /^[1-9][0-9]{0,19}$/.test(text) ? BigInt(text) : 0n;
  return {key, seq, process: event.process_id, reason: named ? text : null, weight: count > 0n && count <= 18446744073709551615n ? count : 1n};
}
/** Which stream of this timeline a gap reason belongs to. */
function flowGapStream(reason) {
  if (reason.startsWith('native_js_invocation_request_')) return 'requests';
  if (reason.startsWith('native_js_invocation_')) return 'calls';
  if (reason.startsWith('native_wasm_dispatch_')) return 'br_table';
  if (reason.startsWith('native_wasm_indirect_')) return 'call_indirect';
  return 'other';
}
const FLOW_GAP_GLOSS = {
  native_js_invocation_budget_incomplete: 'the 256-call budget filled; later calls were not recorded',
  native_js_invocation_site_budget_incomplete: 'a site’s 64-call budget filled; its later calls were not recorded',
  native_js_invocation_request_budget_incomplete: 'the 256-request budget filled; later requests were not recorded',
  native_js_invocation_transport_unavailable: 'admitted records were rejected on their way out of the renderer',
  native_js_invocation_input_unavailable: 'records were refused as invalid or outside a live document',
  native_js_invocation_settle_unavailable: 'a settle ran after its document went away and was not recorded'
};
/** What a gap reason means, in a few words; the reason itself is always shown. */
function flowGapGloss(reason) {
  const slot = /^native_js_invocation_site_(\d+)_(compiled_before_arming|unsupported_function)$/.exec(reason);
  if (slot) return slot[2] === 'compiled_before_arming' ? `site slot ${slot[1]} compiled before arming, so its calls were not recorded` : `site slot ${slot[1]} is a generator, constructor or initializer, so it was not tracked`;
  if (FLOW_GAP_GLOSS[reason]) return FLOW_GAP_GLOSS[reason];
  if (/_filtered$/.test(reason)) return 'the sample policy excluded these executions';
  if (/budget|limit/.test(reason)) return 'a sampling budget filled; later executions were not sampled';
  return 'records were lost';
}

/** Folds filtered event records into per-process tracks.
 * Wasm records join a track only by the invocation ID they carry (state 2,
 * inside). Invocation records join by the backend's decoded `js_invocation`
 * object; without one they are counted as undecoded and draw nothing, so a
 * backend that does not decode them still shows the Wasm-only tracks. */
function flowTimelineModel(events) {
  const counts = {records: 0, starts: 0, settles: 0, requests: 0, samples: 0, outside: 0, invalid: 0, undecoded: 0, duplicates: 0, conflicts: 0, gaps: 0, overflow: 0};
  const processes = new Map(), seen = new Set();
  let decoded = false;
  const processOf = id => {
    if (!processes.has(id)) processes.set(id, {process: id, tracks: new Map(), outside: [], requests: [], gaps: [], overflow: []});
    return processes.get(id);
  };
  const trackOf = (owner, invocation) => {
    let track = owner.tracks.get(invocation);
    if (!track) {
      track = {key: `${owner.process}:${invocation}`, process: owner.process, invocation, slot: null, start: null, settle: null, samples: [], requests: []};
      owner.tracks.set(invocation, track);
    }
    return track;
  };
  for (const event of Array.isArray(events) ? events : []) {
    if (!event || typeof event !== 'object' || !FLOW_TIMELINE_TYPES.includes(event.type)) continue;
    const seq = flowSeq(event.sequence_number), process = event.process_id;
    if (seq === null || !Number.isSafeInteger(process) || process < 0) { counts.invalid += 1; continue; }
    const key = `${process}:${seq}`;
    if (seen.has(key)) { counts.duplicates += 1; continue; }
    seen.add(key); counts.records += 1;
    const owner = processOf(process);
    if (event.type === 'gap') {
      counts.gaps += 1;
      owner.gaps.push(flowGapRecord(event, key, seq));
      continue;
    }
    if (event.type === 'wasm_dispatch_overflow' || event.type === 'wasm_indirect_overflow') {
      // An execution a budget refused, not an observation: it names no module
      // and no call, so it only says which sites ran more than was sampled.
      const row = event.wasm_overflow, kind = event.type === 'wasm_dispatch_overflow' ? 'br_table' : 'call_indirect';
      if (row !== undefined && (!row || row.status !== 'decoded')) { counts.invalid += 1; continue; }
      const entry = !row ? {key, seq, process, kind, undecoded: true}
        : row.kind === 'omitted' && Number.isSafeInteger(row.omitted_count) && row.omitted_count > 0 ? {key, seq, process, kind, omitted: row.omitted_count}
          : row.kind === 'identity' && Number.isSafeInteger(row.function_index) && Number.isSafeInteger(row.module_byte_offset) ? {key, seq, process, kind, function_index: row.function_index, offset: row.module_byte_offset}
            : null;
      if (!entry) { counts.invalid += 1; continue; }
      counts.overflow += 1;
      owner.overflow.push(entry);
      continue;
    }
    if (event.type.startsWith('wasm_')) {
      const row = event.wasm_observation;
      if (!row || row.status !== 'decoded' || !Number.isSafeInteger(row.function_index) || !Number.isSafeInteger(row.module_byte_offset)) { counts.invalid += 1; continue; }
      const inside = row.js_invocation_state === 2 && Number.isSafeInteger(row.js_invocation_id) && row.js_invocation_id > 0;
      const sample = {key, seq, process, kind: event.type === 'wasm_dispatch_observation' ? 'br_table' : 'call_indirect',
        artifact_id: String(event.artifact_id ?? '0'), function_index: row.function_index, offset: row.module_byte_offset,
        selector: Number.isSafeInteger(row.selector) ? row.selector : null, tableCount: Number.isSafeInteger(row.table_count) ? row.table_count : null,
        sampleIndex: Number.isSafeInteger(row.sample_index) ? row.sample_index : null, state: Number.isSafeInteger(row.js_invocation_state) ? row.js_invocation_state : 0,
        invocation: inside ? String(row.js_invocation_id) : null, callee: Number.isSafeInteger(row.callee_function_index) ? row.callee_function_index : null,
        resolution: typeof row.resolution === 'string' ? row.resolution : null};
      counts.samples += 1;
      if (inside) trackOf(owner, sample.invocation).samples.push(sample);
      else { owner.outside.push(sample); counts.outside += 1; }
      continue;
    }
    const js = event.js_invocation;
    if (!js || typeof js !== 'object') { counts.undecoded += 1; continue; }
    decoded = true;
    if (js.status !== 'decoded') { counts.invalid += 1; continue; }
    const kind = event.type.slice('js_invocation_'.length);
    const invocation = js.invocation_id === null || js.invocation_id === undefined || String(js.invocation_id) === '0' ? null : String(js.invocation_id);
    if (kind === 'request') {
      const entry = {key, seq, process, request: String(js.request_id), invocation: js.inside === true ? invocation : null};
      counts.requests += 1;
      owner.requests.push(entry);
      if (entry.invocation) trackOf(owner, entry.invocation).requests.push(entry);
      continue;
    }
    if (!invocation) { counts.invalid += 1; continue; }
    const track = trackOf(owner, invocation);
    if (Number.isSafeInteger(js.site_slot)) track.slot ??= js.site_slot;
    if (kind === 'start') {
      if (track.start) { counts.conflicts += 1; continue; }
      counts.starts += 1;
      track.start = {key, seq, parent: js.parent_invocation_id ? String(js.parent_invocation_id) : null, parentUnknown: js.parent_unknown === true,
        argumentCount: Number.isSafeInteger(js.argument_count) ? js.argument_count : null,
        site: typeof js.source_sha256 === 'string' && Number.isSafeInteger(js.anchor_offset) ? {sha256: js.source_sha256, anchor: js.anchor_offset} : null};
    } else {
      if (track.settle) { counts.conflicts += 1; continue; }
      counts.settles += 1;
      track.settle = {key, seq, fulfilled: js.fulfilled !== false,
        valueKind: typeof js.value_kind === 'string' ? js.value_kind : '',
        valueLength: Number.isSafeInteger(js.value_length) ? js.value_length : null, via: typeof js.via === 'string' ? js.via : null};
    }
  }
  const list = [...processes.values()].map(flowTimelineProcess);
  // The busiest renderer first: calls, then samples and requests; a process
  // that holds only gap markers comes last but is still listed.
  const items = view => view.outside.length + view.requests.length + view.tracks.reduce((sum, track) => sum + track.samples.length, 0);
  list.sort((a, b) => b.tracks.length - a.tracks.length || items(b) - items(a) || a.process - b.process);
  return {processes: list, counts, decoded};
}

/** One process's refusals and losses, each counted: named gap reasons, queue
 * drop markers and the overflow records that name refused executions. */
function flowGapSummary(owner) {
  const named = new Map(), overflow = {br_table: {identities: 0, omitted: 0, undecoded: 0}, call_indirect: {identities: 0, omitted: 0, undecoded: 0}};
  const streams = {calls: false, requests: false, br_table: false, call_indirect: false};
  let dropped = 0n;
  for (const gap of owner.gaps) {
    if (!gap.reason) { dropped += gap.weight; continue; }
    const entry = named.get(gap.reason) ?? {reason: gap.reason, stream: flowGapStream(gap.reason), count: 0};
    entry.count += 1; named.set(gap.reason, entry);
    if (entry.stream in streams) streams[entry.stream] = true;
  }
  for (const item of owner.overflow) {
    const tally = overflow[item.kind];
    // Several omitted records of one budget epoch hold the same running
    // count, so the largest is a floor, never a sum.
    if (item.omitted) tally.omitted = Math.max(tally.omitted, item.omitted);
    else if (item.undecoded) tally.undecoded += 1;
    else tally.identities += 1;
    streams[item.kind] = true;
  }
  return {named: [...named.values()], dropped, overflow, streams, records: owner.gaps.length + owner.overflow.length};
}
/** Plain sentences for one process's gaps, at most `maxGapReasons` reasons. */
function flowGapNotes(gaps) {
  const limits = FLOW_TIMELINE_LIMITS;
  if (!gaps?.records) return [];
  const notes = gaps.named.slice(0, limits.maxGapReasons).map(entry => `${entry.reason} ×${entry.count} (${flowGapGloss(entry.reason)})`);
  if (gaps.named.length > limits.maxGapReasons) notes.push(`${gaps.named.length - limits.maxGapReasons} more gap reasons`);
  for (const kind of ['br_table', 'call_indirect']) {
    const tally = gaps.overflow[kind], parts = [];
    if (tally.identities) parts.push(`${flowNumber(tally.identities)} named in overflow records`);
    if (tally.omitted) parts.push(`at least ${flowNumber(tally.omitted)} more omitted`);
    if (tally.undecoded) parts.push(`${flowNumber(tally.undecoded)} overflow ${tally.undecoded === 1 ? 'record' : 'records'} this backend does not decode`);
    if (parts.length) notes.push(`${kind} executions the sample budget refused: ${parts.join(', ')}`);
  }
  if (gaps.dropped > 0n) notes.push(`${gaps.dropped.toLocaleString('en-US')} ${gaps.dropped === 1n ? 'record' : 'records'} dropped by a full queue`);
  return notes;
}

/** Orders one process's records and applies the drawing bounds. */
function flowTimelineProcess(owner) {
  const limits = FLOW_TIMELINE_LIMITS;
  const first = track => [track.start?.seq, track.samples[0]?.seq, track.requests[0]?.seq, track.settle?.seq].filter(seq => seq !== undefined).reduce((a, b) => (a < b ? a : b));
  const tracks = [...owner.tracks.values()];
  for (const track of tracks) {
    track.samples.sort((a, b) => flowSeqOrder(a.seq, b.seq));
    track.requests.sort((a, b) => flowSeqOrder(a.seq, b.seq));
    track.first = first(track);
    const ends = [track.settle?.seq, track.samples.at(-1)?.seq, track.requests.at(-1)?.seq, track.start?.seq].filter(seq => seq !== undefined);
    track.last = ends.reduce((a, b) => (a > b ? a : b));
  }
  tracks.sort((a, b) => flowSeqOrder(a.first, b.first) || (Number(a.invocation) - Number(b.invocation)));
  owner.outside.sort((a, b) => flowSeqOrder(a.seq, b.seq));
  owner.requests.sort((a, b) => flowSeqOrder(a.seq, b.seq));
  // Sites: every sample at one (module, function, offset, kind), in record order.
  const sites = new Map();
  const allSamples = [...tracks.flatMap(track => track.samples), ...owner.outside].sort((a, b) => flowSeqOrder(a.seq, b.seq));
  for (const sample of allSamples) {
    const siteKey = `${sample.artifact_id}:${sample.function_index}:${sample.offset}:${sample.kind}`;
    if (!sites.has(siteKey)) sites.set(siteKey, {key: siteKey, kind: sample.kind, artifact_id: sample.artifact_id, function_index: sample.function_index, offset: sample.offset, samples: [], histogram: new Map(), tableCount: sample.tableCount});
    const site = sites.get(siteKey);
    sample.site = siteKey; sample.ordinal = site.samples.length + 1;
    site.samples.push(sample);
    if (sample.selector !== null) site.histogram.set(sample.selector, (site.histogram.get(sample.selector) ?? 0) + 1);
  }
  for (const track of tracks) track.samples.forEach((sample, index) => { sample.callOrdinal = index + 1; });
  // Refusals: an overflow identity names a function and offset but no module,
  // so it counts against every sampled site there; a stream with any refusal
  // or loss keeps its sample counts from reading as every execution.
  const gaps = flowGapSummary(owner), byPlace = new Map();
  for (const site of sites.values()) { const place = `${site.function_index}:${site.offset}:${site.kind}`; byPlace.set(place, [...(byPlace.get(place) ?? []), site]); }
  for (const item of owner.overflow) {
    if (item.function_index === undefined) continue;
    for (const site of byPlace.get(`${item.function_index}:${item.offset}:${item.kind}`) ?? []) site.refused = (site.refused ?? 0) + 1;
  }
  for (const site of sites.values()) {
    site.shortfall = site.refused ? `${flowNumber(site.refused)} more ${site.refused === 1 ? 'execution' : 'executions'} at this offset refused`
      : gaps.streams[site.kind] ? `the ${site.kind} stream has refused or lost samples`
        : gaps.dropped > 0n ? 'records of this renderer were dropped' : null;
  }
  owner.gaps.sort((a, b) => flowSeqOrder(a.seq, b.seq));
  owner.overflow.sort((a, b) => flowSeqOrder(a.seq, b.seq));
  const gapMarks = [...owner.gaps, ...owner.overflow].sort((a, b) => flowSeqOrder(a.seq, b.seq));
  // Bounds, each counted.
  const drawn = tracks.slice(0, limits.maxTracks);
  const hidden = {tracks: tracks.length - drawn.length, samples: 0, requests: 0, gaps: Math.max(0, gapMarks.length - limits.maxGapMarks)};
  let budget = limits.maxSamples;
  for (const track of tracks) {
    if (!drawn.includes(track)) { hidden.samples += track.samples.length; track.drawnSamples = []; continue; }
    track.drawnSamples = track.samples.slice(0, Math.max(0, budget));
    budget -= track.drawnSamples.length;
    hidden.samples += track.samples.length - track.drawnSamples.length;
  }
  const outside = owner.outside.slice(0, Math.max(0, budget));
  hidden.samples += owner.outside.length - outside.length;
  const drawnRequests = owner.requests.slice(0, limits.maxRequests);
  hidden.requests = owner.requests.length - drawnRequests.length;
  return {process: owner.process, tracks, drawn, outside: owner.outside, drawnOutside: outside, requests: owner.requests, drawnRequests, sites, hidden,
    gaps, gapMarks, drawnGaps: gapMarks.slice(0, limits.maxGapMarks)};
}

/** Record order as x positions. A run of records nobody here names is
 * compressed to one gap, marked as a break, so order stays exact and the
 * spacing between neighbours stays readable. */
function flowTimelineAxis(seqs) {
  const {unit, gapCap, labelEvery} = FLOW_TIMELINE_LIMITS;
  const sorted = [...new Map(seqs.map(seq => [String(seq), seq])).values()].sort(flowSeqOrder);
  const points = [], breaks = [], cap = BigInt(gapCap);
  let x = 0;
  sorted.forEach((seq, index) => {
    if (index) {
      const delta = seq - sorted[index - 1];
      if (delta > cap) breaks.push({x: x + (gapCap * unit) / 2, after: sorted[index - 1], before: seq, skipped: delta - 1n});
      x += Number(delta > cap ? cap : delta) * unit;
    }
    points.push({seq, x});
  });
  const ticks = [];
  let last = -Infinity;
  for (const point of points) {
    const afterBreak = breaks.some(item => item.x > last && item.x < point.x);
    if (point.x - last >= labelEvery || afterBreak) { ticks.push(point); last = point.x; }
  }
  const index = new Map(points.map(point => [String(point.seq), point.x]));
  const at = seq => {
    const hit = index.get(String(seq));
    if (hit !== undefined || !points.length) return hit ?? 0;
    let low = 0, high = points.length - 1;
    if (seq <= points[0].seq) return 0;
    if (seq >= points[high].seq) return points[high].x;
    while (high - low > 1) { const mid = (low + high) >> 1; if (points[mid].seq <= seq) low = mid; else high = mid; }
    const a = points[low], b = points[high], span = Number(b.seq - a.seq);
    return a.x + (b.x - a.x) * Number(seq - a.seq) / (span || 1);
  };
  return {width: x, points, ticks, breaks, x: at};
}

/* Tracks are named by invocation, with the site slot in the detail line.
 * `/api/js-invocation-sites` lists what the backend's own launcher armed and
 * names no session, so its labels cannot be tied to the session this
 * timeline reads and are not applied. */
function flowTrackName(track) { return `call #${track.invocation}`; }
/** What a track's settle says, or what is missing. */
function flowTrackOutcome(track) {
  if (!track.settle) return track.start ? 'not settled in the records read' : 'start and settle not read';
  const outcome = track.settle.fulfilled ? 'fulfilled' : 'rejected';
  return `${outcome} · ${flowValueLabel(track.settle.valueKind, track.settle.valueLength)}`;
}
/** "sample 3 of 16 read", and, when the stream refused or lost executions,
 * says so: a count is of the records read, never of every execution. */
function flowSampleCount(sample, site) {
  const base = `sample ${sample.ordinal} of ${site?.samples.length ?? '?'} read`;
  return site?.shortfall ? `${base}, ${site.refused ? 'more refused here' : 'not every execution'}` : base;
}
function flowSampleLabel(sample, site) {
  const where = `func ${sample.function_index} ${flowHex(sample.offset)} ${sample.kind}`;
  const value = sample.kind === 'br_table' ? `selector ${sample.selector ?? 'unknown'}${sample.tableCount !== null && sample.selector !== null && sample.selector >= sample.tableCount ? ' (default)' : ''}`
    : `callee ${sample.resolution === 'resolved' && sample.callee !== null ? `func ${sample.callee}` : sample.resolution ?? 'unknown'}`;
  const count = `${sample.kind} sample ${sample.ordinal} of ${site?.samples.length ?? '?'} read${site?.shortfall ? ` (${site.shortfall})` : ''}`;
  return `${count} at ${where}, ${value}, sequence ${sample.seq.toLocaleString('en-US')}`;
}

/** One gap mark's tooltip: the reason, the refused execution, or the drop. */
function flowGapMarkText(gap) {
  if (gap.reason) return `${gap.reason} (${flowGapGloss(gap.reason)})`;
  if (gap.kind && gap.undecoded) return `${gap.kind} overflow record this backend does not decode`;
  if (gap.kind && gap.omitted) return `at least ${flowNumber(gap.omitted)} ${gap.kind} executions the sample budget omitted`;
  if (gap.kind) return `${gap.kind} execution the sample budget refused at func ${gap.function_index} ${flowHex(gap.offset)}`;
  return `${gap.weight.toLocaleString('en-US')} ${gap.weight === 1n ? 'record' : 'records'} dropped by a full queue`;
}

/**
 * The timeline view. `fetchJSON(url, signal)` returns a parsed page;
 * `onSelect(selection | null)` and `onFollow(selection)` report the chosen
 * sample, call or request to the workspace, `onPartial(partial)` follows
 * every read, and `describeRequest(process, request)` names a renderer
 * request when the app lists it.
 */
function createFlowTimeline({root, fetchJSON, onSelect, onFollow, onPartial, describeRequest}) {
  const limits = FLOW_TIMELINE_LIMITS;
  const make = (tag, className = '', text = '') => { const element = document.createElement(tag); if (className) element.className = className; if (text) element.textContent = text; return element; };
  root.classList.add('flow-timeline');
  const banner = make('div', 'flow-tl-banner'); banner.hidden = true; banner.setAttribute('role', 'status');
  const bannerText = make('span', 'flow-tl-banner-text');
  const bannerAction = make('button', 'secondary-button flow-tl-banner-action'); bannerAction.type = 'button'; bannerAction.hidden = true;
  banner.append(bannerText, bannerAction);
  // Refusals and losses stay stated apart from the read banner, so a refresh
  // notice never replaces them.
  const gapNotice = make('p', 'flow-tl-gaps'); gapNotice.hidden = true; gapNotice.setAttribute('role', 'note');
  // A long notice scrolls, so it takes a tab stop of its own.
  gapNotice.tabIndex = 0;
  const state = make('div', 'flow-tl-state'); state.setAttribute('role', 'status'); state.setAttribute('aria-live', 'polite');
  const stateTitle = make('strong', '', ''), stateText = make('p', '', '');
  const stateRetry = make('button', 'secondary-button', 'Retry'); stateRetry.type = 'button'; stateRetry.hidden = true;
  state.append(stateTitle, stateText, stateRetry);
  const scroll = make('div', 'flow-tl-scroll');
  const canvas = make('div', 'flow-tl-canvas'); canvas.setAttribute('role', 'group'); canvas.setAttribute('aria-label', 'Tracked calls in record order');
  scroll.append(canvas);
  const detail = make('div', 'flow-tl-detail'); detail.setAttribute('aria-live', 'polite');
  const detailText = make('span', 'flow-tl-detail-text', '');
  const detailFollow = make('button', 'secondary-button flow-tl-follow', 'Open in CFG'); detailFollow.type = 'button'; detailFollow.hidden = true;
  detail.append(detailText, detailFollow);
  root.append(banner, gapNotice, state, scroll, detail);
  const processSelect = make('select', 'flow-tl-process'); processSelect.setAttribute('aria-label', 'Renderer process'); processSelect.hidden = true;

  let session = null, events = [], model = null, view = null, cursor = '0', partial = false, status = 'idle', error = null;
  let generation = 0, controller = null, loadedAt = 0, chosenProcess = null, selected = null, items = new Map();
  // Gap counters of the pages read. They describe the byte range each page
  // scanned, every session and record type in it, not this session alone.
  const noScan = () => ({sequence: 0n, sequenceSaturated: false, drops: 0n, dropsSaturated: false});
  let scan = noScan();
  // Pages behind the records held. A refresh reads at least as many again,
  // so it never undoes a Read more or shrinks the view.
  let pagesHeld = 0;

  function setState(kind, title = '', text = '', retry = false) {
    status = kind;
    root.dataset.state = kind;
    state.hidden = kind === 'ready';
    stateTitle.textContent = title; stateText.textContent = text; stateRetry.hidden = !retry;
  }
  function setBanner(text, action = null, handler = null) {
    banner.hidden = !text; bannerText.textContent = text || '';
    bannerAction.hidden = !action; bannerAction.textContent = action || '';
    bannerAction.onclick = handler;
  }
  stateRetry.addEventListener('click', () => load(session));

  /** Reads the session's records from the start of the store, forward. */
  async function load(next, {more = false, quiet = false} = {}) {
    if (!next) { reset(); setState('idle', 'No session yet', 'Tracked calls appear once a session has recorded requests.'); return; }
    // A new session starts empty; reset first so it cannot cancel this read.
    if (String(next) !== String(session)) reset();
    controller?.abort();
    const owner = ++generation, abort = new AbortController();
    controller = abort;
    session = String(next);
    const collected = more ? events.slice() : [], scanned = more ? {...scan} : noScan();
    let after = more ? cursor : '0', pages = 0, done = false;
    if (!model) setState('loading', 'Reading tracked calls…', 'Invocation records and Wasm samples, in record order.');
    else if (!quiet) setBanner('Refreshing tracked calls…');
    try {
      const budget = more ? limits.pagesPerRead : Math.max(limits.pagesPerRead, pagesHeld);
      while (pages < budget && collected.length < limits.maxRecords) {
        const parameters = new URLSearchParams({session_id: session, category: FLOW_TIMELINE_CATEGORY, type: FLOW_TIMELINE_TYPES.join(','), after, limit: String(limits.pageSize)});
        const body = await fetchJSON(`/api/events?${parameters}`, abort.signal);
        if (owner !== generation) return;
        if (!body || !Array.isArray(body.events) || !body.query || typeof body.query !== 'object') throw new TypeError('The event store returned a malformed page.');
        collected.push(...body.events.slice(0, limits.maxRecords - collected.length));
        pages += 1;
        scanned.sequence += flowCount(body.sequence_gaps); scanned.drops += flowCount(body.queue_drops);
        scanned.sequenceSaturated ||= body.sequence_gaps_saturated === true; scanned.dropsSaturated ||= body.queue_drops_saturated === true;
        const query = body.query;
        if (!query.limited && !query.budget_exhausted) { done = true; break; }
        if (typeof query.next_after !== 'string' || query.next_after === after) { done = true; break; }
        after = query.next_after;
      }
      events = collected; cursor = after; partial = !done; error = null; loadedAt = Date.now(); scan = scanned; pagesHeld = (more ? pagesHeld : 0) + pages;
      model = flowTimelineModel(events);
      render();
      onPartial(partial);
    } catch (failure) {
      if (owner !== generation || failure?.name === 'AbortError') return;
      error = failure?.message || 'The read failed.';
      if (model) { setBanner(`Could not refresh tracked calls: ${error} Showing the records read before.`, 'Retry', () => load(session)); }
      else setState('error', 'Could not read tracked calls', error, true);
    } finally {
      if (controller === abort) controller = null;
    }
  }
  function reset() {
    controller?.abort(); controller = null; generation += 1;
    events = []; model = null; view = null; cursor = '0'; partial = false; loadedAt = 0; chosenProcess = null; selected = null; items = new Map(); scan = noScan(); pagesHeld = 0;
    canvas.replaceChildren(); detailText.textContent = ''; detailFollow.hidden = true; setBanner(''); gapNotice.textContent = ''; gapNotice.hidden = true;
    processSelect.replaceChildren(); processSelect.hidden = true;
  }

  function currentProcess() {
    if (!model?.processes.length) return null;
    return model.processes.find(item => item.process === chosenProcess) ?? model.processes[0];
  }
  function render() {
    const processes = model?.processes ?? [];
    const options = processes.map(item => {
      const option = make('option', '', `renderer ${item.process} · ${item.tracks.length} ${item.tracks.length === 1 ? 'call' : 'calls'}${item.gaps.records ? ' · gaps' : ''}`);
      option.value = String(item.process); return option;
    });
    processSelect.replaceChildren(...options);
    processSelect.hidden = processes.length < 2;
    view = currentProcess();
    if (view) { chosenProcess = view.process; processSelect.value = String(view.process); }
    const counts = model?.counts;
    const notes = [];
    if (partial) notes.push(`Read the first ${flowNumber(events.length)} records; later records were not read.`);
    if (view?.hidden.tracks) notes.push(`${view.hidden.tracks} more ${view.hidden.tracks === 1 ? 'call' : 'calls'} not drawn.`);
    if (view?.hidden.samples) notes.push(`${view.hidden.samples} more ${view.hidden.samples === 1 ? 'sample' : 'samples'} not drawn.`);
    if (view?.hidden.requests) notes.push(`${view.hidden.requests} more ${view.hidden.requests === 1 ? 'request' : 'requests'} not drawn.`);
    if (counts?.undecoded) notes.push(`${counts.undecoded} invocation ${counts.undecoded === 1 ? 'record' : 'records'} not decoded by this backend, so calls are grouped from Wasm samples only and have no start or settle.`);
    if (counts?.invalid) notes.push(`${counts.invalid} malformed ${counts.invalid === 1 ? 'record' : 'records'} skipped.`);
    if (counts?.conflicts) notes.push(`${counts.conflicts} repeated start or settle ${counts.conflicts === 1 ? 'record' : 'records'} kept apart.`);
    setBanner(notes.join(' '), partial && events.length < limits.maxRecords ? 'Read more' : null, partial ? () => load(session, {more: true}) : null);
    renderGaps(processes);
    if (!view) {
      canvas.replaceChildren(); items = new Map();
      setState('empty', 'No tracked calls in this session',
        counts?.records ? 'The records read hold no drawable call or sample.' : 'Track calls to a function from Sources, then start a new capture. Wasm br_table and call_indirect samples need a rebuilt browser.');
      detailText.textContent = ''; detailFollow.hidden = true;
      return;
    }
    setState('ready');
    draw();
    // A selection the records still hold stays, drawn or not.
    if (selected && !describe(selected)) selected = null;
    paintSelection();
  }
  /** The gap notice: this renderer's refusals and losses, which other
   * renderers have some, and the scanned range's missing and dropped records. */
  function renderGaps(processes) {
    const parts = [];
    const lines = flowGapNotes(view?.gaps);
    if (lines.length) parts.push(`Gaps in renderer ${view.process}: ${lines.join('; ')}.`);
    const others = processes.filter(item => item !== view && item.gaps.records).map(item => item.process);
    if (others.length) parts.push(`${others.length === 1 ? 'Renderer' : 'Renderers'} ${others.join(', ')} also ${others.length === 1 ? 'has' : 'have'} gaps.`);
    const counted = [];
    if (scan.sequence > 0n) counted.push(`${scan.sequence.toLocaleString('en-US')}${scan.sequenceSaturated ? ' or more' : ''} sequence ${scan.sequence === 1n ? 'number' : 'numbers'} missing`);
    if (scan.drops > 0n) counted.push(`${scan.drops.toLocaleString('en-US')}${scan.dropsSaturated ? ' or more' : ''} ${scan.drops === 1n ? 'record' : 'records'} dropped by a full queue`);
    if (counted.length) parts.push(`In the store range read, across every session and record type: ${counted.join(', ')}.`);
    gapNotice.textContent = parts.join(' ');
    gapNotice.hidden = !parts.length;
  }
  processSelect.addEventListener('change', () => { chosenProcess = Number(processSelect.value); selected = null; render(); onSelect(null); });

  // Geometry, in CSS pixels. The label column stays put while the tracks scroll.
  const G = {label: 152, axis: 26, track: 50, lane: 42, left: 24, right: 48, chip: 188};
  function draw() {
    const seqs = [];
    for (const track of view.drawn) {
      for (const seq of [track.start?.seq, track.settle?.seq]) if (seq !== undefined) seqs.push(seq);
      for (const sample of track.drawnSamples) seqs.push(sample.seq);
      for (const request of track.requests) seqs.push(request.seq);
    }
    for (const sample of view.drawnOutside) seqs.push(sample.seq);
    for (const request of view.drawnRequests) seqs.push(request.seq);
    for (const gap of view.drawnGaps) seqs.push(gap.seq);
    const axis = flowTimelineAxis(seqs);
    const X = seq => G.label + G.left + axis.x(seq);
    const rows = [...(view.drawnGaps.length ? [{type: 'gaps'}] : []), ...view.drawn.map(track => ({type: 'track', track})), ...(view.drawnOutside.length ? [{type: 'outside'}] : []), ...(view.drawnRequests.length ? [{type: 'requests'}] : [])];
    let top = G.axis;
    const nodes = [];
    items = new Map();
    const width = G.label + G.left + axis.width + G.right;
    // Axis: tick labels at record positions, and a mark where records were compressed.
    const axisRow = make('div', 'flow-tl-axis'); axisRow.style.width = `${width}px`;
    for (const tick of axis.ticks) {
      const label = make('span', 'flow-tl-tick', tick.seq.toLocaleString('en-US')); label.style.left = `${X(tick.seq)}px`; axisRow.append(label);
      const rule = make('span', 'flow-tl-rule'); rule.style.left = `${X(tick.seq)}px`; nodes.push(rule);
    }
    for (const item of axis.breaks) {
      const mark = make('span', 'flow-tl-break', '≈'); mark.style.left = `${G.label + G.left + item.x}px`;
      // The skipped numbers are not all records: some may never have been stored.
      mark.title = `${item.skipped.toLocaleString('en-US')} sequence ${item.skipped === 1n ? 'number' : 'numbers'} between ${item.after.toLocaleString('en-US')} and ${item.before.toLocaleString('en-US')} hold no record drawn here: records of other types, or numbers with no stored record; this read cannot tell which`;
      axisRow.append(mark);
    }
    nodes.push(axisRow);
    // Request chips that would overlap stack in levels; a fourth level is not
    // drawn but counted, so the lane stays readable.
    const chipLevels = new Map();
    let levels = 1, crowded = 0;
    {
      const ends = [];
      for (const request of view.drawnRequests) {
        const x = X(request.seq);
        let level = ends.findIndex(end => end <= x);
        if (level < 0) level = ends.length;
        if (level >= 3) { crowded += 1; continue; }
        ends[level] = x + G.chip + 6; chipLevels.set(request.key, level);
        levels = Math.max(levels, level + 1);
      }
    }
    for (const row of rows) {
      const height = row.type === 'track' ? G.track : row.type === 'requests' ? 10 + levels * 32 : row.type === 'gaps' ? 30 : G.lane;
      const line = make('div', `flow-tl-row flow-tl-row-${row.type}`); line.style.top = `${top}px`; line.style.height = `${height}px`; line.style.width = `${width}px`;
      const labelCell = make('div', 'flow-tl-label');
      if (row.type === 'track') {
        const {track} = row;
        line.dataset.track = track.key;
        const name = make('button', 'flow-tl-call', flowTrackName(track)); name.type = 'button'; name.dataset.key = `call:${track.key}`; name.dataset.seq = String(track.first); name.tabIndex = -1;
        name.setAttribute('aria-label', `${flowTrackName(track)}, ${flowTrackOutcome(track)}, ${track.samples.length} samples, ${track.requests.length} requests`);
        name.addEventListener('click', () => choose({type: 'call', key: `call:${track.key}`}));
        items.set(`call:${track.key}`, name);
        const outcome = make('span', 'flow-tl-meta', flowTrackOutcome(track)); outcome.title = flowTrackOutcome(track);
        labelCell.append(name, outcome);
        const mid = height / 2;
        const from = track.start?.seq ?? track.first, to = track.settle?.seq ?? track.last;
        const open = make('span', `flow-tl-open${track.start ? '' : ' flow-tl-open-uncut'}${track.settle ? '' : ' flow-tl-open-unsettled'}`);
        open.style.left = `${X(from)}px`; open.style.width = `${Math.max(2, X(to) - X(from))}px`; open.style.top = `${mid - 1}px`;
        open.title = track.start && track.settle ? 'Open from its start record to its settle record' : flowTrackOutcome(track);
        line.append(open);
        if (track.start && track.settle && FLOW_SYNC_VIA.has(track.settle.via)) {
          const run = make('span', 'flow-tl-run'); run.style.left = `${X(track.start.seq)}px`; run.style.width = `${Math.max(4, X(track.settle.seq) - X(track.start.seq))}px`; run.style.top = `${mid - 5}px`;
          // Records between start and settle are made while the call ran (the
          // samples and requests on this track among them), so the span is
          // not "nothing else happened".
          run.title = 'Settled synchronously: it returned or threw without a promise, so it ran without yielding from its start record to its settle record. Samples and requests on this track were recorded inside it; other records in that range can come from other threads.';
          line.append(run);
        }
        if (track.start) { const mark = make('span', 'flow-tl-start'); mark.style.left = `${X(track.start.seq)}px`; mark.style.top = `${mid - 12}px`; mark.title = `start · sequence ${track.start.seq.toLocaleString('en-US')}${track.start.argumentCount !== null ? ` · ${track.start.argumentCount} arguments` : ''}`; line.append(mark); }
        if (track.settle) { const mark = make('span', `flow-tl-settle${track.settle.fulfilled ? '' : ' flow-tl-rejected'}`); mark.style.left = `${X(track.settle.seq)}px`; mark.style.top = `${mid - 12}px`; mark.title = `${flowTrackOutcome(track)} · sequence ${track.settle.seq.toLocaleString('en-US')}`; line.append(mark); }
        for (const request of track.requests) { const mark = make('span', 'flow-tl-request-mark'); mark.style.left = `${X(request.seq)}px`; mark.style.top = `${mid + 6}px`; mark.title = `request #${request.request} started inside this call`; line.append(mark); }
        for (const sample of track.drawnSamples) line.append(sampleButton(sample, X, mid));
        if (track.drawnSamples.length < track.samples.length) {
          const more = make('span', 'flow-tl-more', `+${track.samples.length - track.drawnSamples.length} not drawn`);
          more.style.left = `${X(track.last) + 12}px`; more.style.top = `${mid - 8}px`; line.append(more);
        }
      } else if (row.type === 'gaps') {
        labelCell.append(make('span', 'flow-tl-lane-name', 'Gaps'), make('span', 'flow-tl-meta', `${view.gaps.records} refused or lost${view.hidden.gaps ? `, ${view.hidden.gaps} not drawn` : ''}`));
        for (const gap of view.drawnGaps) {
          const mark = make('span', 'flow-tl-gap'); mark.style.left = `${X(gap.seq)}px`; mark.style.top = `${height / 2 - 9}px`;
          mark.title = `${flowGapMarkText(gap)} · sequence ${gap.seq.toLocaleString('en-US')}`;
          line.append(mark);
        }
      } else if (row.type === 'outside') {
        labelCell.append(make('span', 'flow-tl-lane-name', 'Not in a tracked call'), make('span', 'flow-tl-meta', 'no call, or call unknown'));
        for (const sample of view.drawnOutside) line.append(sampleButton(sample, X, height / 2));
      } else {
        labelCell.append(make('span', 'flow-tl-lane-name', 'Requests'), make('span', 'flow-tl-meta', crowded ? `${crowded} more overlap, not drawn` : `issued in renderer ${view.process}`));
        for (const request of view.drawnRequests) {
          if (!chipLevels.has(request.key)) continue;
          const known = describeRequest(view.process, request.request);
          const chip = make('button', `flow-tl-chip${request.invocation ? '' : ' flow-tl-chip-unknown'}`); chip.type = 'button'; chip.tabIndex = -1;
          chip.dataset.key = `request:${request.key}`; chip.dataset.seq = String(request.seq);
          chip.append(make('span', 'flow-tl-chip-name', known?.label ?? `request #${request.request}`), make('span', 'flow-tl-chip-meta', request.invocation ? `in #${request.invocation}` : 'call unknown'));
          chip.style.left = `${X(request.seq)}px`; chip.style.top = `${6 + chipLevels.get(request.key) * 32}px`; chip.style.width = `${G.chip}px`;
          chip.setAttribute('aria-label', `${known?.label ?? `Renderer request ${request.request}`}, ${request.invocation ? `started inside call #${request.invocation}` : 'started while a call was open, which one is unknown'}, sequence ${request.seq.toLocaleString('en-US')}`);
          chip.addEventListener('click', () => choose({type: 'request', key: `request:${request.key}`}));
          items.set(`request:${request.key}`, chip);
          line.append(chip);
        }
      }
      line.prepend(labelCell);
      nodes.push(line);
      top += height;
    }
    canvas.style.width = `${width}px`; canvas.style.height = `${top + 8}px`;
    canvas.replaceChildren(...nodes);
    // The one tab stop is set by paintSelection, which always follows.
  }
  function sampleButton(sample, X, mid) {
    const site = view.sites.get(sample.site);
    const button = make('button', `flow-tl-sample flow-tl-${sample.kind}`); button.type = 'button'; button.tabIndex = -1;
    button.dataset.key = `sample:${sample.key}`; button.dataset.seq = String(sample.seq);
    button.style.left = `${X(sample.seq) - 9}px`; button.style.top = `${mid - 21}px`;
    button.append(make('span', 'flow-tl-tick-mark'), make('span', 'flow-tl-value', sample.kind === 'br_table' ? String(sample.selector ?? '?') : 'ci'));
    button.setAttribute('aria-label', flowSampleLabel(sample, site));
    button.title = flowSampleLabel(sample, site);
    button.addEventListener('click', () => choose({type: 'sample', key: `sample:${sample.key}`}));
    items.set(`sample:${sample.key}`, button);
    return button;
  }

  /** The selection as the workspace reads it. */
  function describe(choice) {
    if (!choice || !view) return null;
    const [type, raw] = [choice.type, choice.key.slice(choice.key.indexOf(':') + 1)];
    if (type === 'call') {
      const track = view.tracks.find(item => item.key === raw);
      return track ? {type, key: choice.key, track, label: flowTrackName(track)} : null;
    }
    if (type === 'request') {
      const request = view.requests.find(item => item.key === raw);
      if (!request) return null;
      const track = request.invocation ? view.tracks.find(item => item.invocation === request.invocation) ?? null : null;
      return {type, key: choice.key, request, track, process: view.process, label: describeRequest(view.process, request.request)?.label ?? `request #${request.request}`};
    }
    const sample = [...view.tracks.flatMap(track => track.samples), ...view.outside].find(item => item.key === raw);
    if (!sample) return null;
    const site = view.sites.get(sample.site);
    const track = sample.invocation ? view.tracks.find(item => item.invocation === sample.invocation) ?? null : null;
    return {type: 'sample', key: choice.key, sample, site, track, process: view.process, label: `sample ${sample.ordinal}`, count: flowSampleCount(sample, site)};
  }
  function choose(choice, {silent = false, focus = false} = {}) {
    selected = choice;
    paintSelection();
    const info = describe(choice);
    if (focus) items.get(choice?.key)?.focus({preventScroll: false, focusVisible: true});
    if (!silent) onSelect(info);
    return info;
  }
  /** The one tab stop: the selected item when it is drawn, else the drawn
   * item nearest it in record order, else the first. */
  function tabStopFor(info) {
    if (!items.size) return null;
    if (info && items.has(info.key)) return items.get(info.key);
    const at = info?.type === 'sample' ? info.sample.seq : info?.type === 'request' ? info.request.seq : info?.track ? info.track.first : null;
    let best = null, distance = null;
    if (at !== null) for (const element of items.values()) {
      const seq = flowSeq(element.dataset.seq);
      if (seq === null) continue;
      const gap = seq > at ? seq - at : at - seq;
      if (distance === null || gap < distance) { best = element; distance = gap; }
    }
    return best ?? items.values().next().value;
  }
  /** Why a selection the records hold is not drawn, or ''. */
  function notDrawn(info) {
    if (!info || items.has(info.key)) return '';
    if (info.type === 'request') return view.drawnRequests.includes(info.request) ? 'not drawn: its chip is past the third row of overlapping chips' : `not drawn: past the ${limits.maxRequests} requests drawn`;
    if (info.track && !view.drawn.includes(info.track)) return `not drawn: ${info.type === 'call' ? 'it is' : 'its call is'} past the ${limits.maxTracks} calls drawn`;
    return info.type === 'sample' ? `not drawn: past the ${limits.maxSamples} samples drawn for this renderer` : 'not drawn';
  }
  function paintSelection() {
    const info = describe(selected), stop = tabStopFor(info);
    for (const [key, element] of items) {
      element.setAttribute('aria-pressed', String(key === selected?.key));
      element.tabIndex = element === stop ? 0 : -1;
    }
    for (const row of canvas.querySelectorAll('.flow-tl-row-track')) row.toggleAttribute('data-selected', Boolean(info?.track && row.dataset.track === info.track.key));
    if (!info) { detailText.textContent = view ? 'Pick a sample, a call or a request. Enter on a sample opens its block in the CFG.' : ''; detailFollow.hidden = true; return; }
    if (info.type === 'sample') {
      const sample = info.sample;
      detailText.textContent = [`${sample.kind} ${info.count}`, info.track ? `${flowTrackName(info.track)} · ${sample.callOrdinal} of ${info.track.samples.length}` : `outside a tracked call (${FLOW_INVOCATION_STATES[sample.state] ?? 'unknown'})`,
        `func ${sample.function_index} ${flowHex(sample.offset)}`, sample.kind === 'br_table' ? `selector ${sample.selector ?? 'unknown'}` : `callee ${sample.resolution === 'resolved' ? `func ${sample.callee}` : sample.resolution ?? 'unknown'}`,
        `seq ${sample.seq.toLocaleString('en-US')} · renderer ${sample.process}`, notDrawn(info)].filter(Boolean).join(' · ');
      detailFollow.hidden = false;
    } else if (info.type === 'call') {
      const track = info.track;
      detailText.textContent = [flowTrackName(track), track.slot !== null ? `site slot ${track.slot}` : '', flowTrackOutcome(track), `${track.samples.length} samples`, `${track.requests.length} requests`,
        track.start ? `seq ${track.start.seq.toLocaleString('en-US')}${track.settle ? ` → ${track.settle.seq.toLocaleString('en-US')}` : ''}` : '', notDrawn(info)].filter(Boolean).join(' · ');
      detailFollow.hidden = true;
    } else {
      detailText.textContent = [info.label, info.track ? `started inside ${flowTrackName(info.track)}` : 'started while a call was open; which one is unknown', `seq ${info.request.seq.toLocaleString('en-US')}`, notDrawn(info)].filter(Boolean).join(' · ');
      detailFollow.hidden = true;
    }
  }
  detailFollow.addEventListener('click', () => { const info = describe(selected); if (info) onFollow(info); });

  // Keyboard: one tab stop; arrows move along and between rows, J and K step
  // samples in record order, Enter follows a sample into the CFG.
  canvas.addEventListener('keydown', event => {
    if (event.altKey || event.ctrlKey || event.metaKey || event.isComposing) return;
    const target = event.target?.closest?.('[data-key]');
    if (!target || !items.has(target.dataset.key)) return;
    const key = event.key;
    let next = null;
    if (key === 'ArrowLeft' || key === 'ArrowRight') next = neighbour(target, key === 'ArrowRight' ? 1 : -1);
    else if (key === 'ArrowUp' || key === 'ArrowDown') next = verticalNeighbour(target, key === 'ArrowDown' ? 1 : -1);
    else if (!event.shiftKey && (key === 'j' || key === 'J' || key === 'k' || key === 'K')) next = stepElement(target.dataset.key, key.toLowerCase() === 'j' ? 1 : -1);
    else if (key === 'Home' || key === 'End') { const list = [...items.values()]; next = key === 'Home' ? list[0] : list.at(-1); }
    else if (key === 'Enter') {
      event.preventDefault(); event.stopPropagation();
      const info = choose({type: target.dataset.key.split(':')[0], key: target.dataset.key});
      if (info) onFollow(info);
      return;
    } else return;
    event.preventDefault(); event.stopPropagation();
    if (!next) return;
    target.tabIndex = -1; next.tabIndex = 0;
    choose({type: next.dataset.key.split(':')[0], key: next.dataset.key}, {focus: true});
  });
  const rowOf = element => element.closest('.flow-tl-row');
  const leftOf = element => parseFloat(element.style.left) || 0;
  function neighbour(element, direction) {
    const row = rowOf(element);
    const list = [...row.querySelectorAll('[data-key]')].sort((a, b) => leftOf(a) - leftOf(b) || (a.classList.contains('flow-tl-call') ? -1 : 1));
    const at = list.indexOf(element);
    return list[at + direction] ?? null;
  }
  function verticalNeighbour(element, direction) {
    const rows = [...canvas.querySelectorAll('.flow-tl-row')];
    const x = element.classList.contains('flow-tl-call') ? -1 : leftOf(element);
    for (let at = rows.indexOf(rowOf(element)) + direction; at >= 0 && at < rows.length; at += direction) {
      const candidates = [...rows[at].querySelectorAll('[data-key]')];
      if (!candidates.length) continue;
      return candidates.reduce((best, item) => (Math.abs((item.classList.contains('flow-tl-call') ? -1 : leftOf(item)) - x) < Math.abs((best.classList.contains('flow-tl-call') ? -1 : leftOf(best)) - x) ? item : best));
    }
    return null;
  }
  function orderedSamples() {
    return [...items.keys()].filter(key => key.startsWith('sample:')).map(key => ({key, sample: describe({type: 'sample', key})?.sample})).filter(item => item.sample).sort((a, b) => flowSeqOrder(a.sample.seq, b.sample.seq));
  }
  function stepElement(fromKey, direction) {
    const list = orderedSamples();
    if (!list.length) return null;
    let at = list.findIndex(item => item.key === fromKey);
    if (at < 0) {
      // From a call or a request, start at its first sample.
      const info = describe({type: fromKey.split(':')[0], key: fromKey});
      at = info?.track ? list.findIndex(item => item.sample.invocation === info.track.invocation) - (direction > 0 ? 1 : 0) : -1;
    }
    const next = list[Math.max(0, Math.min(list.length - 1, at + direction))];
    return items.get(next.key) ?? null;
  }

  return {
    processSelect,
    /** Loads when the session changes, else refreshes quietly when stale. */
    sync(next) {
      if (String(next ?? '') !== String(session ?? '') || (!model && status !== 'loading' && status !== 'error')) { load(next); return; }
      if (model && !partial && !controller && Date.now() - loadedAt > FLOW_TIMELINE_STALE_MS) load(session, {quiet: true});
    },
    refresh: () => load(session),
    /** Selects by key ("sample:<process>:<seq>", "call:<process>:<inv>" or "request:..."). */
    select(key, {focus = false, silent = true} = {}) {
      if (!key) { selected = null; paintSelection(); return null; }
      const type = key.split(':')[0];
      if (!describe({type, key})) return null;
      const info = choose({type, key}, {silent, focus});
      items.get(key)?.scrollIntoView?.({block: 'nearest', inline: 'center'});
      return info;
    },
    clear() { selected = null; paintSelection(); },
    selection: () => describe(selected),
    /** Steps the selected sample (direction 1 or -1) within its site. */
    stepSample(direction) {
      const info = describe(selected);
      const list = info?.type === 'sample' ? info.site.samples : null;
      if (!list) return null;
      const next = list[info.sample.ordinal - 1 + direction];
      return next ? this.select(`sample:${next.key}`, {silent: false}) : null;
    },
    /** Every sample of one function, by site, for the CFG and the Related rail. */
    samplesFor(artifactId, functionIndex) {
      if (!view) return [];
      return [...view.sites.values()].filter(site => site.artifact_id === String(artifactId) && site.function_index === functionIndex);
    },
    focus() {
      const target = items.get(selected?.key) ?? [...items.values()].find(item => item.tabIndex === 0) ?? items.values().next().value;
      if (target) { target.focus({focusVisible: true}); return true; }
      return false;
    },
    /** One line for the pane head and the tabs. */
    summary() {
      if (status === 'loading') return 'reading…';
      if (status === 'error') return 'read failed';
      if (!view) return model ? 'none recorded' : '';
      const samples = view.tracks.reduce((sum, track) => sum + track.samples.length, 0) + view.outside.length;
      return `${view.tracks.length} ${view.tracks.length === 1 ? 'call' : 'calls'} · ${samples} ${samples === 1 ? 'sample' : 'samples'} · renderer ${view.process} record order${partial ? ' · partial' : ''}${view.gaps.records ? ' · gaps' : ''}`;
    },
    /** The tracked call whose start or settle record is `record`
     * ("process:sequence"), described as select() describes it, or null. */
    callAt(record) {
      const track = view?.tracks.find(item => item.start?.key === record || item.settle?.key === record);
      return track ? describe({type: 'call', key: `call:${track.key}`}) : null;
    }
  };
}
