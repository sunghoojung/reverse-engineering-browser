// Client for get_source_format; its whitespace-only layout maps back by walking both texts in step.

const SOURCE_FORMAT_LIMITS = Object.freeze({entries: 4, characters: 24 * 1024 * 1024, segments: 1500000, timeout: 180000, sourceBytes: 16 * 1024 * 1024});
const SOURCE_FORMAT_REASONS = Object.freeze({
  'parse-failed': 'Oxc could not parse this file', 'output-limit': 'the Oxc layout exceeds its size limit',
  'fidelity-check-failed': 'the Oxc layout failed its token check', 'memory-limit': 'Oxc reached its memory limit',
  'nesting-limit': 'the file nests too deeply for Oxc'
});

// ECMAScript WhiteSpace and LineTerminator, the separators the layout may change.
function sourceFormatSpace(code) {
  return code === 32 || (code >= 9 && code <= 13) || code === 0xa0 || code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) || code === 0x2028 || code === 0x2029 ||
    code === 0x202f || code === 0x205f || code === 0x3000 || code === 0xfeff;
}

// Verbatim UTF-16 segments shared by both texts, or null when anything but whitespace differs.
function sourceWhitespaceSegments(original, formatted, limit = SOURCE_FORMAT_LIMITS.segments) {
  const segments = [];
  let from = 0, to = 0;
  for (;;) {
    const originalStart = from, derivedStart = to;
    while (from < original.length && to < formatted.length && original.charCodeAt(from) === formatted.charCodeAt(to)) {from++; to++;}
    if (from > originalStart) {
      if (segments.length === limit) return null;
      segments.push({kind: 'verbatim', original_start: originalStart, original_end: from, derived_start: derivedStart, derived_end: to});
    }
    if (from === original.length && to === formatted.length) return segments;
    const skippedFrom = from, skippedTo = to;
    while (from < original.length && sourceFormatSpace(original.charCodeAt(from))) from++;
    while (to < formatted.length && sourceFormatSpace(formatted.charCodeAt(to))) to++;
    if (from === skippedFrom && to === skippedTo) return null;
  }
}

// Original offsets of a formatted range whose ends are not whitespace.
function sourceFormatRawRange(segments, start, end) {
  if (!(end > start)) return null;
  const first = derivedOriginalOffset(segments, start);
  const last = derivedOriginalOffset(segments, end - 1);
  return first === null || last === null ? null : {start: first, end: last + 1};
}

function sourceFormatEligible(source) {
  return source?.source_type === 'artifact' && source.kind === 'javascript' && typeof source.content === 'string' &&
    !source.contentTruncated && !source.contentLossy && Number(source.byte_size) <= SOURCE_FORMAT_LIMITS.sourceBytes;
}

function createSourceFormatClient({request = (...args) => fetch(...args), onChange = () => {}} = {}) {
  const entries = new Map();
  const key = source => `${source.session_id}|${source.artifact_id}|${source.sha256}`;
  const bound = () => {
    let characters = 0, segments = 0;
    for (const entry of entries.values()) {characters += entry.view?.text.length ?? 0; segments += entry.view?.segments.length ?? 0;}
    for (const [name, entry] of entries) {
      if (entries.size <= SOURCE_FORMAT_LIMITS.entries && characters <= SOURCE_FORMAT_LIMITS.characters && segments <= SOURCE_FORMAT_LIMITS.segments) break;
      if (entry.status === 'loading') continue;
      characters -= entry.view?.text.length ?? 0; segments -= entry.view?.segments.length ?? 0;
      entries.delete(name);
    }
  };
  async function load(name, source, original, entry) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SOURCE_FORMAT_LIMITS.timeout);
    try {
      const response = await request(`/api/source-format?session_id=${encodeURIComponent(source.session_id)}&artifact_id=${encodeURIComponent(source.artifact_id)}`,
        {cache: 'no-store', signal: controller.signal});
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error || `Formatter returned ${response.status}`);
      if (payload?.schema !== 'source-format-v1' || payload.mapping !== 'whitespace-only' || String(payload.source?.artifact_id) !== String(source.artifact_id) || payload.source?.sha256 !== source.sha256) {
        throw new Error('Formatter response does not match this artifact');
      }
      if (payload.status !== 'formatted') {
        Object.assign(entry, {status: 'unavailable', notice: SOURCE_FORMAT_REASONS[payload.reason] ?? 'the Oxc layout is unavailable'});
        return;
      }
      const segments = typeof payload.text === 'string' ? sourceWhitespaceSegments(original, payload.text) : null;
      if (!segments) throw new Error('Formatter text differs from the evidence beyond whitespace');
      entry.view = {text: payload.text, segments, offset_unit: 'utf-16-code-unit', language: 'javascript', changed: payload.text !== original,
        engine: 'oxc', sourceInput: original};
      entry.status = 'ready';
    } catch (error) {
      Object.assign(entry, {status: 'error', notice: `Oxc layout unavailable: ${controller.signal.aborted ? 'timed out' : String(error?.message ?? error).slice(0, 240)}`});
      entry.notice = entry.notice.replace(/\.$/, '');
    } finally {
      clearTimeout(timer);
      if (entries.get(name) === entry) {bound(); onChange(source);}
    }
  }
  return {
    // null: not eligible. {pending}: wait. {fallback, notice}: use the in-page formatter.
    view(source, original) {
      if (!sourceFormatEligible(source) || original !== source.content) return null;
      const name = key(source);
      let entry = entries.get(name);
      if (!entry) {
        entry = {status: 'loading'};
        entries.set(name, entry);
        load(name, source, original, entry);
      }
      if (entry.status === 'loading') return {pending: true};
      if (entry.status === 'ready') return entry.view;
      return {fallback: true, notice: entry.notice};
    },
    // A failed layout is retried the next time the researcher asks for it.
    forget(source) {
      if (!source) return;
      const name = key(source);
      if (['error', 'unavailable'].includes(entries.get(name)?.status)) entries.delete(name);
    }
  };
}
