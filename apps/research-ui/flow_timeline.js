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
// A complete read continues quietly when Flow redraws this long after it.
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

/* Helpers the Flow workspace shares; flow_workspace.js loads after this file. */
/** An element with a class, text and attributes; captured values only ever
 * go in as text. */
function flowElement(tag, className = '', text = '', attributes = {}) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text) element.textContent = text;
  for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, value);
  return element;
}
/** A button with a class, text and, when given, an accessible name. */
function flowButton(className, text = '', label = '') {
  const element = flowElement('button', className, text);
  element.type = 'button';
  if (label) element.setAttribute('aria-label', label);
  return element;
}
const flowNumber = value => Number(value).toLocaleString('en-US');
const flowHex = value => `+0x${Number(value).toString(16)}`;
/** `one` for a count of one (a number or a BigInt), else `many`. */
const flowPlural = (count, one, many = `${one}s`) => (Number(count) === 1 ? one : many);

/** What a settle returned, from its kind and length; never its content. */
function flowValueLabel(kind, length) {
  const name = FLOW_VALUE_NAMES[kind] ?? (kind || 'value');
  if (!Number.isSafeInteger(length) || length <= 0) return name;
  if (kind === 'string') return `${name} · ${flowNumber(length)} UTF-16 units`;
  if (kind === 'array') return `${name} · ${flowNumber(length)} elements`;
  if (kind === 'array_buffer' || kind === 'array_buffer_view') return `${name} · ${flowNumber(length)} bytes`;
  return name;
}

/** Which stream of this timeline a gap reason belongs to. */
function flowGapStream(reason) {
  if (reason.startsWith('native_js_invocation_request_')) return 'requests';
  if (reason.startsWith('native_js_invocation_')) return 'calls';
  if (reason.startsWith('native_wasm_dispatch_')) return 'br_table';
  if (reason.startsWith('native_wasm_indirect_')) return 'call_indirect';
  return 'other';
}
/** What a budget that filled left out, by the stream it belongs to. */
const FLOW_GAP_BUDGETS = {calls: 'a call budget filled; later calls were not recorded', requests: 'a request budget filled; later requests were not recorded',
  br_table: 'a sampling budget filled; later executions were not sampled', call_indirect: 'a sampling budget filled; later executions were not sampled',
  other: 'a budget or limit was reached; later records were not recorded'};
/** What a named gap means, in a few words, read from the reason's shape in
 * the order the backend's session summary reads it (gap_meaning in
 * session_summary.rs), with the evidence models' sampling labels. An
 * invocation site's own reasons name the site slot. The reason itself is
 * always shown beside it. */
function flowGapMeaning(reason) {
  const slot = /^native_js_invocation_site_(\d+)_(compiled_before_arming|unsupported_function)$/.exec(reason);
  if (slot) return slot[2] === 'compiled_before_arming' ? `site slot ${slot[1]} compiled before arming, so its calls were not recorded` : `site slot ${slot[1]} is a generator, constructor or initializer, so it was not tracked`;
  if (samplePolicyFilterGapLabels.has(reason) || reason.includes('filtered')) return 'the sample policy excluded these executions before they took a sample slot';
  if (reason.includes('limit_or_invalid') || reason.includes('module_invalid')) return 'records were refused as malformed or outside a structural bound';
  if (samplingBudgetGapLabels.has(reason)) return `the ${samplingBudgetGapLabels.get(reason)} sampling budget filled; later executions were not sampled`;
  if (/budget|limit|capped/.test(reason)) return FLOW_GAP_BUDGETS[flowGapStream(reason)];
  if (/unavailable|lost/.test(reason)) return 'a capture stage was unavailable, so these were not recorded';
  if (/unresolved|mismatch|omitted|unbound/.test(reason)) return 'their linkage could not be established, so they were recorded without it';
  if (/unsupported|left_liftoff/.test(reason)) return 'the execution was outside document Liftoff code, so it was named and not sampled';
  return 'the capture refused or dropped these records';
}

/** Folds filtered event records into per-process tracks.
 * Wasm records join a track only by the invocation ID they carry (state 2,
 * inside). Invocation records join by the backend's decoded `js_invocation`
 * object; without one they are counted as undecoded and draw nothing, so a
 * backend that does not decode them still shows the Wasm-only tracks. */
function flowTimelineModel(events) {
  const model = {counts: {records: 0, starts: 0, settles: 0, requests: 0, samples: 0, outside: 0, invalid: 0, undecoded: 0, duplicates: 0, conflicts: 0, gaps: 0, overflow: 0}, decoded: false};
  const processes = new Map(), seen = new Set(), counts = model.counts;
  for (const event of events) {
    if (!isPlainObject(event) || !FLOW_TIMELINE_TYPES.includes(event.type)) continue;
    const seq = flowSeq(event.sequence_number), process = event.process_id;
    if (seq === null || !Number.isSafeInteger(process) || process < 0) { counts.invalid += 1; continue; }
    const record = {key: `${process}:${seq}`, seq, process};
    if (seen.has(record.key)) { counts.duplicates += 1; continue; }
    seen.add(record.key);
    counts.records += 1;
    if (!processes.has(process)) processes.set(process, {process, tracks: new Map(), outside: [], requests: [], gaps: [], overflow: []});
    const owner = processes.get(process);
    if (event.type === 'gap') flowReadGap(event, record, owner, counts);
    else if (event.type.endsWith('_overflow')) flowReadOverflow(event, record, owner, counts);
    else if (event.type.startsWith('wasm_')) flowReadSample(event, record, owner, counts);
    else flowReadInvocation(event, record, owner, model);
  }
  const list = [...processes.values()].map(flowTimelineProcess);
  // The busiest renderer first: calls, then samples and requests; a process
  // that holds only gap markers comes last but is still listed.
  const items = view => view.outside.length + view.requests.length + view.tracks.reduce((sum, track) => sum + track.samples.length, 0);
  list.sort((a, b) => b.tracks.length - a.tracks.length || items(b) - items(a) || a.process - b.process);
  return {processes: list, counts, decoded: model.decoded};
}
/** The track of one invocation in a process, made on first use. */
function flowTrackOf(owner, invocation) {
  if (!owner.tracks.has(invocation)) owner.tracks.set(invocation, {key: `${owner.process}:${invocation}`, process: owner.process, invocation, slot: null, start: null, settle: null, samples: [], requests: []});
  return owner.tracks.get(invocation);
}
/** A `gap` marker: a payload naming a producer reason is a named gap; any
 * other marker is a queue drop weighing its decimal count, else one record
 * (protocol/http-api.md). */
function flowReadGap(event, record, owner, counts) {
  if (typeof event.payload !== 'string') { counts.invalid += 1; return; }
  counts.gaps += 1;
  owner.gaps.push({...record, reason: namedGapOf(event)?.reason ?? null, weight: countReportedQueueDrops([event])});
}
/** An execution a budget refused, not an observation: it names no module
 * and no call, so it only says which sites ran more than was sampled. */
function flowReadOverflow(event, record, owner, counts) {
  const row = event.wasm_overflow, kind = event.type === 'wasm_dispatch_overflow' ? 'br_table' : 'call_indirect';
  if (row !== undefined && row?.status !== 'decoded') { counts.invalid += 1; return; }
  let entry = null;
  if (!row) entry = {...record, kind, undecoded: true};
  else if (row.kind === 'omitted' && Number.isSafeInteger(row.omitted_count) && row.omitted_count > 0) entry = {...record, kind, omitted: row.omitted_count};
  else if (row.kind === 'identity' && Number.isSafeInteger(row.function_index) && Number.isSafeInteger(row.module_byte_offset)) entry = {...record, kind, function_index: row.function_index, offset: row.module_byte_offset};
  if (!entry) { counts.invalid += 1; return; }
  counts.overflow += 1;
  owner.overflow.push(entry);
}
/** A br_table or call_indirect sample; it joins a track only by the
 * invocation ID it carries while inside one (state 2). */
function flowReadSample(event, record, owner, counts) {
  const row = event.wasm_observation;
  if (row?.status !== 'decoded' || !Number.isSafeInteger(row.function_index) || !Number.isSafeInteger(row.module_byte_offset)) { counts.invalid += 1; return; }
  const inside = row.js_invocation_state === 2 && Number.isSafeInteger(row.js_invocation_id) && row.js_invocation_id > 0;
  const integer = value => (Number.isSafeInteger(value) ? value : null);
  const sample = {...record, kind: event.type === 'wasm_dispatch_observation' ? 'br_table' : 'call_indirect',
    artifact_id: String(event.artifact_id ?? '0'), function_index: row.function_index, offset: row.module_byte_offset,
    selector: integer(row.selector), tableCount: integer(row.table_count), sampleIndex: integer(row.sample_index), state: integer(row.js_invocation_state) ?? 0,
    invocation: inside ? String(row.js_invocation_id) : null, callee: integer(row.callee_function_index), resolution: typeof row.resolution === 'string' ? row.resolution : null};
  counts.samples += 1;
  if (inside) flowTrackOf(owner, sample.invocation).samples.push(sample);
  else { owner.outside.push(sample); counts.outside += 1; }
}
/** An invocation start, settle or request, by the backend's decoded
 * `js_invocation` object; without one it is counted as undecoded. */
function flowReadInvocation(event, record, owner, model) {
  const {counts} = model, js = event.js_invocation;
  if (!isPlainObject(js)) { counts.undecoded += 1; return; }
  model.decoded = true;
  if (js.status !== 'decoded') { counts.invalid += 1; return; }
  const kind = event.type.slice('js_invocation_'.length);
  const invocation = js.invocation_id === null || js.invocation_id === undefined || String(js.invocation_id) === '0' ? null : String(js.invocation_id);
  if (kind === 'request') {
    const entry = {...record, request: String(js.request_id), invocation: js.inside === true ? invocation : null};
    counts.requests += 1;
    owner.requests.push(entry);
    if (entry.invocation) flowTrackOf(owner, entry.invocation).requests.push(entry);
    return;
  }
  if (!invocation) { counts.invalid += 1; return; }
  const track = flowTrackOf(owner, invocation);
  if (Number.isSafeInteger(js.site_slot)) track.slot ??= js.site_slot;
  if (track[kind]) { counts.conflicts += 1; return; }
  if (kind === 'start') {
    counts.starts += 1;
    track.start = {key: record.key, seq: record.seq, parent: js.parent_invocation_id ? String(js.parent_invocation_id) : null, parentUnknown: js.parent_unknown === true,
      argumentCount: Number.isSafeInteger(js.argument_count) ? js.argument_count : null,
      site: typeof js.source_sha256 === 'string' && Number.isSafeInteger(js.anchor_offset) ? {sha256: js.source_sha256, anchor: js.anchor_offset} : null};
  } else {
    counts.settles += 1;
    track.settle = {key: record.key, seq: record.seq, fulfilled: js.fulfilled !== false, valueKind: typeof js.value_kind === 'string' ? js.value_kind : '',
      valueLength: Number.isSafeInteger(js.value_length) ? js.value_length : null, via: typeof js.via === 'string' ? js.via : null};
  }
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
  const notes = gaps.named.slice(0, limits.maxGapReasons).map(entry => `${entry.reason} ×${entry.count} (${flowGapMeaning(entry.reason)})`);
  if (gaps.named.length > limits.maxGapReasons) notes.push(`${gaps.named.length - limits.maxGapReasons} more gap reasons`);
  for (const kind of ['br_table', 'call_indirect']) {
    const tally = gaps.overflow[kind], parts = [];
    if (tally.identities) parts.push(`${flowNumber(tally.identities)} named in overflow records`);
    if (tally.omitted) parts.push(`at least ${flowNumber(tally.omitted)} more omitted`);
    if (tally.undecoded) parts.push(`${flowNumber(tally.undecoded)} overflow ${flowPlural(tally.undecoded, 'record')} this backend does not decode`);
    if (parts.length) notes.push(`${kind} executions the sample budget refused: ${parts.join(', ')}`);
  }
  if (gaps.dropped > 0n) notes.push(`${gaps.dropped.toLocaleString('en-US')} ${flowPlural(gaps.dropped, 'record')} dropped by a full queue`);
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
    site.shortfall = site.refused ? `${flowNumber(site.refused)} more ${flowPlural(site.refused, 'execution')} at this offset refused`
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
/** A sample's value: the br_table selector, marked when it takes the
 * default arm, or the call_indirect callee. */
function flowSampleValue(sample) {
  if (sample.kind === 'br_table') return `selector ${sample.selector ?? 'unknown'}${sample.tableCount !== null && sample.selector !== null && sample.selector >= sample.tableCount ? ' (default)' : ''}`;
  return `callee ${sample.resolution === 'resolved' && sample.callee !== null ? `func ${sample.callee}` : sample.resolution ?? 'unknown'}`;
}
/** What the CFG and Lineage say beside a picked sample's count: its call,
 * its value and its sequence. */
function flowSampleLine(chosen) {
  return [chosen.track ? flowTrackName(chosen.track) : 'outside a tracked call', flowSampleValue(chosen.sample), `seq ${chosen.sample.seq.toLocaleString('en-US')}`].join(' · ');
}
function flowSampleLabel(sample, site) {
  const where = `func ${sample.function_index} ${flowHex(sample.offset)} ${sample.kind}`;
  const count = `${sample.kind} sample ${sample.ordinal} of ${site?.samples.length ?? '?'} read${site?.shortfall ? ` (${site.shortfall})` : ''}`;
  return `${count} at ${where}, ${flowSampleValue(sample)}, sequence ${sample.seq.toLocaleString('en-US')}`;
}

/** One gap mark's tooltip: the reason, the refused execution, or the drop. */
function flowGapMarkText(gap) {
  if (gap.reason) return `${gap.reason} (${flowGapMeaning(gap.reason)})`;
  if (gap.kind && gap.undecoded) return `${gap.kind} overflow record this backend does not decode`;
  if (gap.kind && gap.omitted) return `at least ${flowNumber(gap.omitted)} ${gap.kind} executions the sample budget omitted`;
  if (gap.kind) return `${gap.kind} execution the sample budget refused at func ${gap.function_index} ${flowHex(gap.offset)}`;
  return `${gap.weight.toLocaleString('en-US')} ${flowPlural(gap.weight, 'record')} dropped by a full queue`;
}

/** One page of the filtered event read, parsed, within the page byte budget. */
async function flowTimelinePage(url, signal) {
  const response = await fetch(url, {cache: 'no-store', signal});
  if (!response.ok) throw await responseError(response, `The event store returned ${response.status}.`);
  const buffer = await response.arrayBuffer();
  if (buffer.byteLength > FLOW_TIMELINE_LIMITS.maxPageBytes) throw Error('An event page was larger than the page budget.');
  return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(buffer));
}

/**
 * The timeline view. `onSelect(selection | null)` and `onFollow(selection)` report the chosen
 * sample, call or request to the workspace, `onPartial(partial)` follows
 * every read, and `describeRequest(process, request)` names a renderer
 * request when the app lists it.
 */
function createFlowTimeline({root, onSelect, onFollow, onPartial, describeRequest}) {
  const limits = FLOW_TIMELINE_LIMITS;
  root.classList.add('flow-timeline');
  // The read banner: partial reads, bounds, refresh failures and Read more.
  const banner = flowElement('div', 'flow-tl-banner', '', {role: 'status', hidden: ''});
  const bannerText = flowElement('span', 'flow-tl-banner-text');
  const bannerAction = flowButton('secondary-button flow-tl-banner-action');
  bannerAction.hidden = true;
  banner.append(bannerText, bannerAction);
  // Refusals and losses stay stated apart from the read banner, so a refresh
  // notice never replaces them. A long notice scrolls, so it takes a tab stop.
  const gapNotice = flowElement('p', 'flow-tl-gaps', '', {role: 'note', tabindex: '0', hidden: ''});
  // Loading, empty and failed reads.
  const state = flowElement('div', 'flow-tl-state', '', {role: 'status', 'aria-live': 'polite'});
  const stateTitle = flowElement('strong'), stateText = flowElement('p');
  const stateRetry = flowButton('secondary-button', 'Retry');
  stateRetry.hidden = true;
  state.append(stateTitle, stateText, stateRetry);
  const scroll = flowElement('div', 'flow-tl-scroll');
  const canvas = flowElement('div', 'flow-tl-canvas', '', {role: 'group', 'aria-label': 'Tracked calls in record order'});
  scroll.append(canvas);
  // The detail line: what is selected, and Open in CFG for a sample.
  const detail = flowElement('div', 'flow-tl-detail', '', {'aria-live': 'polite'});
  const detailText = flowElement('span', 'flow-tl-detail-text');
  const detailFollow = flowButton('secondary-button flow-tl-follow', 'Open in CFG');
  detailFollow.hidden = true;
  detail.append(detailText, detailFollow);
  root.append(banner, gapNotice, state, scroll, detail);
  // The renderer picker, which the workspace puts in the pane head.
  const processSelect = flowElement('select', 'flow-tl-process', '', {'aria-label': 'Renderer process', hidden: ''});

  // The read: its session, records, cursor and state.
  let session = null, events = [], cursor = '0', partial = false, status = 'idle', error = null;
  let generation = 0, controller = null, loadedAt = 0;
  // What is drawn: the model, the shown renderer, the selection and the items.
  let model = null, view = null, chosenProcess = null, selected = null, items = new Map();
  // Gap counters of the pages read. They describe the byte range each page
  // scanned, every session and record type in it, not this session alone.
  const noScan = () => ({sequence: 0n, sequenceSaturated: false, drops: 0n, dropsSaturated: false});
  let scan = noScan();

  function setState(kind, title = '', text = '', retry = false) {
    status = kind;
    root.dataset.state = kind;
    state.hidden = kind === 'ready';
    stateTitle.textContent = title;
    stateText.textContent = text;
    stateRetry.hidden = !retry;
  }
  function setBanner(text, action = null, handler = null) {
    banner.hidden = !text;
    bannerText.textContent = text || '';
    bannerAction.hidden = !action;
    bannerAction.textContent = action || '';
    bannerAction.onclick = handler;
  }
  stateRetry.addEventListener('click', () => load(session));

  /** Reads the session's records forward. A full read starts at the store's
   * start and reads at least as many records as it held, so it never undoes
   * Read more. `more` continues from where the last page stopped and adds
   * what is new; a `quiet` read shows no banner and, when nothing is new,
   * redraws nothing. */
  async function load(next, {more = false, quiet = false} = {}) {
    if (!next) { reset(); setState('idle', 'No session yet', 'Tracked calls appear once a session has recorded requests.'); return; }
    // A new session starts empty; reset first so it cannot cancel this read.
    if (String(next) !== String(session)) reset();
    controller?.abort();
    const owner = ++generation, abort = new AbortController();
    controller = abort;
    session = String(next);
    const collected = more ? events.slice() : [], scanned = more ? {...scan} : noScan(), held = more ? 0 : events.length;
    let after = more ? cursor : '0', pages = 0, done = false;
    if (!model) setState('loading', 'Reading tracked calls…', 'Invocation records and Wasm samples, in record order.');
    else if (!quiet) setBanner('Refreshing tracked calls…');
    try {
      while ((pages < limits.pagesPerRead || collected.length < held) && collected.length < limits.maxRecords) {
        const parameters = new URLSearchParams({session_id: session, category: FLOW_TIMELINE_CATEGORY, type: FLOW_TIMELINE_TYPES.join(','), after, limit: String(limits.pageSize)});
        const body = await flowTimelinePage(`/api/events?${parameters}`, abort.signal);
        if (owner !== generation) return;
        if (!body || !Array.isArray(body.events) || !body.query || typeof body.query !== 'object') throw new TypeError('The event store returned a malformed page.');
        collected.push(...body.events.slice(0, limits.maxRecords - collected.length));
        pages += 1;
        scanned.sequence += captureWideTotal(body.sequence_gaps) ?? 0n; scanned.drops += captureWideTotal(body.queue_drops) ?? 0n;
        scanned.sequenceSaturated ||= body.sequence_gaps_saturated === true; scanned.dropsSaturated ||= body.queue_drops_saturated === true;
        // The next read continues where this page stopped; a cursor that
        // does not move ends the read.
        const query = body.query, from = after;
        if (typeof query.next_after === 'string') after = query.next_after;
        if (!query.limited && !query.budget_exhausted) { done = true; break; }
        if (after === from) { done = true; break; }
      }
      const unchanged = collected.length === events.length && partial === !done && scanned.sequence === scan.sequence && scanned.drops === scan.drops
        && scanned.sequenceSaturated === scan.sequenceSaturated && scanned.dropsSaturated === scan.dropsSaturated;
      events = collected;
      cursor = after;
      partial = !done;
      error = null;
      loadedAt = Date.now();
      scan = scanned;
      if (more && quiet && unchanged) return;
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
    events = []; cursor = '0'; partial = false; loadedAt = 0; scan = noScan();
    model = null; view = null; chosenProcess = null; selected = null; items = new Map();
    canvas.replaceChildren();
    detailText.textContent = '';
    detailFollow.hidden = true;
    setBanner('');
    gapNotice.textContent = '';
    gapNotice.hidden = true;
    processSelect.replaceChildren();
    processSelect.hidden = true;
  }

  function currentProcess() {
    if (!model?.processes.length) return null;
    return model.processes.find(item => item.process === chosenProcess) ?? model.processes[0];
  }
  function render() {
    const processes = model?.processes ?? [];
    const options = processes.map(item => {
      const option = flowElement('option', '', `renderer ${item.process} · ${item.tracks.length} ${flowPlural(item.tracks.length, 'call')}${item.gaps.records ? ' · gaps' : ''}`);
      option.value = String(item.process); return option;
    });
    processSelect.replaceChildren(...options);
    processSelect.hidden = processes.length < 2;
    view = currentProcess();
    if (view) { chosenProcess = view.process; processSelect.value = String(view.process); }
    const counts = model?.counts;
    const notes = [];
    if (partial) notes.push(`Read the first ${flowNumber(events.length)} records; later records were not read.`);
    if (view?.hidden.tracks) notes.push(`${view.hidden.tracks} more ${flowPlural(view.hidden.tracks, 'call')} not drawn.`);
    if (view?.hidden.samples) notes.push(`${view.hidden.samples} more ${flowPlural(view.hidden.samples, 'sample')} not drawn.`);
    if (view?.hidden.requests) notes.push(`${view.hidden.requests} more ${flowPlural(view.hidden.requests, 'request')} not drawn.`);
    if (counts?.undecoded) notes.push(`${counts.undecoded} invocation ${flowPlural(counts.undecoded, 'record')} not decoded by this backend, so calls are grouped from Wasm samples only and have no start or settle.`);
    if (counts?.invalid) notes.push(`${counts.invalid} malformed ${flowPlural(counts.invalid, 'record')} skipped.`);
    if (counts?.conflicts) notes.push(`${counts.conflicts} repeated start or settle ${flowPlural(counts.conflicts, 'record')} kept apart.`);
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
    // Drawing replaces every item, so keyboard focus moves to the same
    // item again, or to the tab stop when it is gone.
    const focused = canvas.contains(document.activeElement) ? document.activeElement.dataset.key : null;
    draw();
    // A selection the records still hold stays, drawn or not.
    if (selected && !describe(selected)) selected = null;
    paintSelection();
    if (focused) (items.get(focused) ?? tabStopFor(describe(selected)))?.focus({preventScroll: true});
  }
  /** The gap notice: this renderer's refusals and losses, which other
   * renderers have some, and the scanned range's missing and dropped records. */
  function renderGaps(processes) {
    const parts = [];
    const lines = flowGapNotes(view?.gaps);
    if (lines.length) parts.push(`Gaps in renderer ${view.process}: ${lines.join('; ')}.`);
    const others = processes.filter(item => item !== view && item.gaps.records).map(item => item.process);
    if (others.length) parts.push(`${flowPlural(others.length, 'Renderer')} ${others.join(', ')} also ${flowPlural(others.length, 'has', 'have')} gaps.`);
    const counted = [];
    if (scan.sequence > 0n) counted.push(`${scan.sequence.toLocaleString('en-US')}${scan.sequenceSaturated ? ' or more' : ''} sequence ${flowPlural(scan.sequence, 'number')} missing`);
    if (scan.drops > 0n) counted.push(`${scan.drops.toLocaleString('en-US')}${scan.dropsSaturated ? ' or more' : ''} ${flowPlural(scan.drops, 'record')} dropped by a full queue`);
    if (counted.length) parts.push(`In the store range read, across every session and record type: ${counted.join(', ')}.`);
    gapNotice.textContent = parts.join(' ');
    gapNotice.hidden = !parts.length;
  }
  processSelect.addEventListener('change', () => { chosenProcess = Number(processSelect.value); selected = null; render(); onSelect(null); });

  // Geometry, in CSS pixels. The label column stays put while the tracks scroll.
  const G = {label: 152, axis: 26, track: 50, lane: 42, left: 24, right: 48, chip: 188};
  /** Places an element at a left offset, and optionally a top and a width. */
  function place(element, left, top = null, width = null) {
    element.style.left = `${left}px`;
    if (top !== null) element.style.top = `${top}px`;
    if (width !== null) element.style.width = `${width}px`;
    return element;
  }
  /** A drawn item: one stop of the timeline's keyboard model. */
  function item(element, key, seq) {
    element.dataset.key = key;
    element.dataset.seq = String(seq);
    element.tabIndex = -1;
    items.set(key, element);
    return element;
  }
  function draw() {
    const axis = flowTimelineAxis(drawnSeqs());
    const X = seq => G.label + G.left + axis.x(seq);
    const width = G.label + G.left + axis.width + G.right;
    items = new Map();
    const {axisRow, rules} = drawAxis(axis, X, width);
    const chips = stackChips(X);
    const rows = [...(view.drawnGaps.length ? [{type: 'gaps'}] : []), ...view.drawn.map(track => ({type: 'track', track})),
      ...(view.drawnOutside.length ? [{type: 'outside'}] : []), ...(view.drawnRequests.length ? [{type: 'requests'}] : [])];
    const heights = {track: G.track, gaps: 30, outside: G.lane, requests: 10 + chips.levels * 32};
    const nodes = [...rules, axisRow];
    let top = G.axis;
    for (const row of rows) {
      const height = heights[row.type];
      const line = flowElement('div', `flow-tl-row flow-tl-row-${row.type}`);
      line.style.top = `${top}px`;
      line.style.height = `${height}px`;
      line.style.width = `${width}px`;
      const label = flowElement('div', 'flow-tl-label');
      if (row.type === 'track') drawTrack(line, label, row.track, X, height / 2);
      else if (row.type === 'gaps') drawGaps(line, label, X, height / 2);
      else if (row.type === 'outside') drawOutside(line, label, X, height / 2);
      else drawRequests(line, label, X, chips);
      line.prepend(label);
      nodes.push(line);
      top += height;
    }
    canvas.style.width = `${width}px`;
    canvas.style.height = `${top + 8}px`;
    canvas.replaceChildren(...nodes);
    // The one tab stop is set by paintSelection, which always follows.
  }
  /** The sequence of everything drawn, for the record-order axis. */
  function drawnSeqs() {
    const seqs = [];
    for (const track of view.drawn) {
      if (track.start) seqs.push(track.start.seq);
      if (track.settle) seqs.push(track.settle.seq);
      for (const sample of track.drawnSamples) seqs.push(sample.seq);
      for (const request of track.requests) seqs.push(request.seq);
    }
    for (const entry of [...view.drawnOutside, ...view.drawnRequests, ...view.drawnGaps]) seqs.push(entry.seq);
    return seqs;
  }
  /** Tick labels at record positions with their rules, and a mark where
   * records were compressed. */
  function drawAxis(axis, X, width) {
    const axisRow = flowElement('div', 'flow-tl-axis');
    axisRow.style.width = `${width}px`;
    const rules = [];
    for (const tick of axis.ticks) {
      axisRow.append(place(flowElement('span', 'flow-tl-tick', tick.seq.toLocaleString('en-US')), X(tick.seq)));
      rules.push(place(flowElement('span', 'flow-tl-rule'), X(tick.seq)));
    }
    for (const gap of axis.breaks) {
      const mark = place(flowElement('span', 'flow-tl-break', '≈'), G.label + G.left + gap.x);
      // The skipped numbers are not all records: some may never have been stored.
      mark.title = `${gap.skipped.toLocaleString('en-US')} sequence ${flowPlural(gap.skipped, 'number')} between ${gap.after.toLocaleString('en-US')} and ${gap.before.toLocaleString('en-US')} hold no record drawn here: records of other types, or numbers with no stored record; this read cannot tell which`;
      axisRow.append(mark);
    }
    return {axisRow, rules};
  }
  /** Request chips that would overlap stack in levels; a chip past the third
   * level is not drawn but counted, so the lane stays readable. */
  function stackChips(X) {
    const level = new Map(), ends = [];
    let crowded = 0;
    for (const request of view.drawnRequests) {
      const x = X(request.seq);
      let at = ends.findIndex(end => end <= x);
      if (at < 0) at = ends.length;
      if (at >= 3) { crowded += 1; continue; }
      ends[at] = x + G.chip + 6;
      level.set(request.key, at);
    }
    return {level, crowded, levels: Math.max(1, ends.length)};
  }
  /** One tracked call: its name and outcome, the open span, a running span
   * for a synchronous settle, its start, settle and request marks, and its samples. */
  function drawTrack(line, label, track, X, mid) {
    line.dataset.track = track.key;
    const name = item(flowButton('flow-tl-call', flowTrackName(track)), `call:${track.key}`, track.first);
    name.setAttribute('aria-label', `${flowTrackName(track)}, ${flowTrackOutcome(track)}, ${track.samples.length} samples, ${track.requests.length} requests`);
    name.addEventListener('click', () => choose({type: 'call', key: `call:${track.key}`}));
    const outcome = flowElement('span', 'flow-tl-meta', flowTrackOutcome(track));
    outcome.title = flowTrackOutcome(track);
    label.append(name, outcome);
    const from = track.start?.seq ?? track.first, to = track.settle?.seq ?? track.last;
    const open = place(flowElement('span', `flow-tl-open${track.start ? '' : ' flow-tl-open-uncut'}${track.settle ? '' : ' flow-tl-open-unsettled'}`), X(from), mid - 1, Math.max(2, X(to) - X(from)));
    open.title = track.start && track.settle ? 'Open from its start record to its settle record' : flowTrackOutcome(track);
    line.append(open);
    if (track.start && track.settle && FLOW_SYNC_VIA.has(track.settle.via)) {
      const run = place(flowElement('span', 'flow-tl-run'), X(track.start.seq), mid - 5, Math.max(4, X(track.settle.seq) - X(track.start.seq)));
      // Records between start and settle are made while the call ran (the
      // samples and requests on this track among them), so the span is not
      // "nothing else happened".
      run.title = 'Settled synchronously: it returned or threw without a promise, so it ran without yielding from its start record to its settle record. Samples and requests on this track were recorded inside it; other records in that range can come from other threads.';
      line.append(run);
    }
    if (track.start) {
      const mark = place(flowElement('span', 'flow-tl-start'), X(track.start.seq), mid - 12);
      mark.title = `start · sequence ${track.start.seq.toLocaleString('en-US')}${track.start.argumentCount !== null ? ` · ${track.start.argumentCount} arguments` : ''}`;
      line.append(mark);
    }
    if (track.settle) {
      const mark = place(flowElement('span', `flow-tl-settle${track.settle.fulfilled ? '' : ' flow-tl-rejected'}`), X(track.settle.seq), mid - 12);
      mark.title = `${flowTrackOutcome(track)} · sequence ${track.settle.seq.toLocaleString('en-US')}`;
      line.append(mark);
    }
    for (const request of track.requests) {
      const mark = place(flowElement('span', 'flow-tl-request-mark'), X(request.seq), mid + 6);
      mark.title = `request #${request.request} started inside this call`;
      line.append(mark);
    }
    for (const sample of track.drawnSamples) line.append(sampleButton(sample, X, mid));
    const hidden = track.samples.length - track.drawnSamples.length;
    if (hidden) line.append(place(flowElement('span', 'flow-tl-more', `+${hidden} not drawn`), X(track.last) + 12, mid - 8));
  }
  function drawGaps(line, label, X, mid) {
    label.append(flowElement('span', 'flow-tl-lane-name', 'Gaps'), flowElement('span', 'flow-tl-meta', `${view.gaps.records} refused or lost${view.hidden.gaps ? `, ${view.hidden.gaps} not drawn` : ''}`));
    for (const gap of view.drawnGaps) {
      const mark = place(flowElement('span', 'flow-tl-gap'), X(gap.seq), mid - 9);
      mark.title = `${flowGapMarkText(gap)} · sequence ${gap.seq.toLocaleString('en-US')}`;
      line.append(mark);
    }
  }
  function drawOutside(line, label, X, mid) {
    label.append(flowElement('span', 'flow-tl-lane-name', 'Not in a tracked call'), flowElement('span', 'flow-tl-meta', 'no call, or call unknown'));
    for (const sample of view.drawnOutside) line.append(sampleButton(sample, X, mid));
  }
  /** The Requests lane: a chip per request started inside a call, dashed
   * when the call it was started in is unknown. */
  function drawRequests(line, label, X, chips) {
    label.append(flowElement('span', 'flow-tl-lane-name', 'Requests'), flowElement('span', 'flow-tl-meta', chips.crowded ? `${chips.crowded} more overlap, not drawn` : `issued in renderer ${view.process}`));
    for (const request of view.drawnRequests) {
      if (!chips.level.has(request.key)) continue;
      const known = describeRequest(view.process, request.request);
      const chip = item(flowButton(`flow-tl-chip${request.invocation ? '' : ' flow-tl-chip-unknown'}`), `request:${request.key}`, request.seq);
      chip.append(flowElement('span', 'flow-tl-chip-name', known?.label ?? `request #${request.request}`), flowElement('span', 'flow-tl-chip-meta', request.invocation ? `in #${request.invocation}` : 'call unknown'));
      place(chip, X(request.seq), 6 + chips.level.get(request.key) * 32, G.chip);
      chip.setAttribute('aria-label', `${known?.label ?? `Renderer request ${request.request}`}, ${request.invocation ? `started inside call #${request.invocation}` : 'started while a call was open, which one is unknown'}, sequence ${request.seq.toLocaleString('en-US')}`);
      chip.addEventListener('click', () => choose({type: 'request', key: `request:${request.key}`}));
      line.append(chip);
    }
  }
  function sampleButton(sample, X, mid) {
    const site = view.sites.get(sample.site);
    const button = item(flowButton(`flow-tl-sample flow-tl-${sample.kind}`), `sample:${sample.key}`, sample.seq);
    place(button, X(sample.seq) - 9, mid - 21);
    button.append(flowElement('span', 'flow-tl-tick-mark'), flowElement('span', 'flow-tl-value', sample.kind === 'br_table' ? String(sample.selector ?? '?') : 'ci'));
    button.setAttribute('aria-label', flowSampleLabel(sample, site));
    button.title = flowSampleLabel(sample, site);
    button.addEventListener('click', () => choose({type: 'sample', key: `sample:${sample.key}`}));
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
    detailText.textContent = info ? detailLine(info).filter(Boolean).join(' · ') : view ? 'Pick a sample, a call or a request. Enter on a sample opens its block in the CFG.' : '';
    // Only a sample opens in the CFG.
    detailFollow.hidden = info?.type !== 'sample';
  }
  /** The detail line's parts for the selection, ending with why it is not drawn. */
  function detailLine(info) {
    const seq = value => value.toLocaleString('en-US');
    if (info.type === 'sample') {
      const sample = info.sample;
      const call = info.track ? `${flowTrackName(info.track)} · ${sample.callOrdinal} of ${info.track.samples.length}` : `outside a tracked call (${FLOW_INVOCATION_STATES[sample.state] ?? 'unknown'})`;
      return [`${sample.kind} ${info.count}`, call, `func ${sample.function_index} ${flowHex(sample.offset)}`, flowSampleValue(sample), `seq ${seq(sample.seq)} · renderer ${sample.process}`, notDrawn(info)];
    }
    if (info.type === 'call') {
      const track = info.track;
      const span = track.start ? `seq ${seq(track.start.seq)}${track.settle ? ` → ${seq(track.settle.seq)}` : ''}` : '';
      return [flowTrackName(track), track.slot !== null ? `site slot ${track.slot}` : '', flowTrackOutcome(track), `${track.samples.length} samples`, `${track.requests.length} requests`, span, notDrawn(info)];
    }
    return [info.label, info.track ? `started inside ${flowTrackName(info.track)}` : 'started while a call was open; which one is unknown', `seq ${seq(info.request.seq)}`, notDrawn(info)];
  }
  detailFollow.addEventListener('click', () => { const info = describe(selected); if (info) onFollow(info); });

  // Keyboard: one tab stop; arrows move along and between rows, J and K step
  // samples in record order, Enter follows a sample into the CFG.
  const choiceOf = element => ({type: element.dataset.key.split(':')[0], key: element.dataset.key});
  /** The item a key moves to from `target`, null for none there, or
   * undefined for a key the timeline leaves alone. */
  function moveFrom(target, event) {
    const key = event.key.toLowerCase();
    // J and K with Shift are not steps.
    if (event.shiftKey && (key === 'j' || key === 'k')) return undefined;
    switch (key) {
      case 'arrowleft': return neighbour(target, -1);
      case 'arrowright': return neighbour(target, 1);
      case 'arrowup': return verticalNeighbour(target, -1);
      case 'arrowdown': return verticalNeighbour(target, 1);
      case 'j': return stepElement(target.dataset.key, 1);
      case 'k': return stepElement(target.dataset.key, -1);
      case 'home': return items.values().next().value;
      case 'end': return [...items.values()].at(-1);
      default: return undefined;
    }
  }
  canvas.addEventListener('keydown', event => {
    if (event.altKey || event.ctrlKey || event.metaKey || event.isComposing) return;
    const target = event.target.closest?.('[data-key]');
    if (!target || !items.has(target.dataset.key)) return;
    if (event.key === 'Enter') {
      event.preventDefault();
      event.stopPropagation();
      const info = choose(choiceOf(target));
      if (info) onFollow(info);
      return;
    }
    const next = moveFrom(target, event);
    if (next === undefined) return;
    event.preventDefault();
    event.stopPropagation();
    if (!next) return;
    target.tabIndex = -1;
    next.tabIndex = 0;
    choose(choiceOf(next), {focus: true});
  });
  const rowOf = element => element.closest('.flow-tl-row');
  const leftOf = element => parseFloat(element.style.left) || 0;
  function neighbour(element, direction) {
    const row = rowOf(element);
    const list = [...row.querySelectorAll('[data-key]')].sort((a, b) => leftOf(a) - leftOf(b) || (a.classList.contains('flow-tl-call') ? -1 : 1));
    const at = list.indexOf(element);
    return list[at + direction] ?? null;
  }
  /** The item in the next row that way nearest this one's position; a call
   * name sits left of every mark. */
  function verticalNeighbour(element, direction) {
    const rows = [...canvas.querySelectorAll('.flow-tl-row')];
    const x = place => (place.classList.contains('flow-tl-call') ? -1 : leftOf(place));
    for (let at = rows.indexOf(rowOf(element)) + direction; at >= 0 && at < rows.length; at += direction) {
      const candidates = [...rows[at].querySelectorAll('[data-key]')];
      if (candidates.length) return candidates.reduce((best, item) => (Math.abs(x(item) - x(element)) < Math.abs(x(best) - x(element)) ? item : best));
    }
    return null;
  }
  /** The drawn samples in record order. */
  function orderedSamples() {
    return [...items.keys()]
      .filter(key => key.startsWith('sample:'))
      .map(key => ({key, sample: describe({type: 'sample', key})?.sample}))
      .filter(entry => entry.sample)
      .sort((a, b) => flowSeqOrder(a.sample.seq, b.sample.seq));
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
    /** Reads when the session changes; a complete read gone stale continues
     * quietly. A partial read waits for Read more. */
    sync(next) {
      if (String(next ?? '') !== String(session ?? '') || (!model && status !== 'loading' && status !== 'error')) { load(next); return; }
      if (model && !partial && !controller && Date.now() - loadedAt > FLOW_TIMELINE_STALE_MS) load(session, {more: true, quiet: true});
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
      return `${view.tracks.length} ${flowPlural(view.tracks.length, 'call')} · ${samples} ${flowPlural(samples, 'sample')} · renderer ${view.process} record order${partial ? ' · partial' : ''}${view.gaps.records ? ' · gaps' : ''}`;
    },
    /** The tracked call whose start or settle record is `record`
     * ("process:sequence"), described as select() describes it, or null. */
    callAt(record) {
      const track = view?.tracks.find(item => item.start?.key === record || item.settle?.key === record);
      return track ? describe({type: 'call', key: `call:${track.key}`}) : null;
    }
  };
}
