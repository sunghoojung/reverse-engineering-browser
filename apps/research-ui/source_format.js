// Client for get_source_format and the in-page layout. Both change only whitespace, so one map walks either back to its input.

const SOURCE_FORMAT_LIMITS = Object.freeze({entries: 4, characters: 64 * 1024 * 1024, timeout: 180000, sourceBytes: 16 * 1024 * 1024,
  wholeBytes: 4 * 1024 * 1024, pageLines: 1000, pages: 16});
const SOURCE_FORMAT_REASONS = Object.freeze({
  'parse-failed': 'Oxc could not parse this file', 'output-limit': 'the Oxc layout exceeds its size limit',
  'fidelity-check-failed': 'the Oxc layout failed its token check', 'memory-limit': 'Oxc reached its memory limit',
  'nesting-limit': 'the file nests too deeply for Oxc'
});

function sourceLayoutTask(task) {
  try {
    if (task.op !== 'map') return prettyPrintSource(task.source, task.value);
    const map = sourceWhitespaceMap(task.original, task.formatted);
    return map ? {map} : {error: 'Formatter text differs from the evidence beyond whitespace'};
  } catch (error) {
    return {error: String(error?.message ?? error).slice(0, 240)};
  }
}

// Layouts run in a dedicated worker so a 16 MiB bundle cannot block the UI.
// Without a worker, or after it fails, they run on the page after one task.
function createSourceLayoutWorker({spawn = typeof Worker === 'function' ? () => new Worker('source_format.js') : null,
  defer = callback => setTimeout(callback, 0)} = {}) {
  let worker = null, failed = !spawn, sequence = 0;
  const pending = new Map();
  const local = (task, resolve) => defer(() => resolve(sourceLayoutTask(task)));
  const fail = () => {
    failed = true;
    worker?.terminate();
    worker = null;
    for (const [id, {task, resolve}] of pending) {pending.delete(id); local(task, resolve);}
  };
  return {
    run: task => new Promise(resolve => {
      if (!failed && !worker) {
        try {
          worker = spawn();
          worker.onmessage = ({data}) => {
            const entry = pending.get(data?.id);
            if (entry) {pending.delete(data.id); entry.resolve(data.result);}
          };
          worker.onerror = event => {event?.preventDefault?.(); fail();};
          worker.onmessageerror = fail;
        } catch {
          fail();
        }
      }
      if (failed) {local(task, resolve); return;}
      const id = ++sequence;
      pending.set(id, {task, resolve});
      worker.postMessage({id, task});
    })
  };
}

function sourceFormatLanguage(source) {
  if (source?.kind === 'javascript') return 'javascript';
  if (!['request_body', 'response_body'].includes(source?.kind)) return null;
  if (['javascript', 'json'].includes(source.language)) return source.language;
  const type = String(source.mime_type ?? '').split(';')[0].trim().toLowerCase();
  if (type === 'application/json' || type === 'text/json' || type.endsWith('+json')) return 'json';
  return /^(?:text|application)\/(?:x-)?(?:java|ecma)script$/.test(type) ? 'javascript' : null;
}

function sourceFormatEligible(source) {
  return source?.source_type === 'artifact' && Boolean(sourceFormatLanguage(source)) && typeof source.content === 'string' &&
    !source.contentTruncated && !source.contentLossy && Number(source.byte_size) <= SOURCE_FORMAT_LIMITS.sourceBytes;
}

function createSourceFormatClient({request = (...args) => fetch(...args), onChange = () => {}, layouts = createSourceLayoutWorker()} = {}) {
  const entries = new Map();
  const key = (source, mode) => `${mode}|${source.session_id}|${source.artifact_id}|${source.sha256}|${sourceFormatLanguage(source)}`;
  const size = entry => entry.view?.text.length ?? [...entry.pages?.values() ?? []].reduce((sum, page) => sum + (page.view?.text.length ?? 0), 0);
  // The newest layout stays even when it alone exceeds the budget; evicting it would refetch it.
  const bound = keep => {
    let characters = 0;
    for (const entry of entries.values()) characters += size(entry);
    for (const [name, entry] of entries) {
      if (entries.size <= SOURCE_FORMAT_LIMITS.entries && characters <= SOURCE_FORMAT_LIMITS.characters) break;
      if (entry.status === 'loading' || name === keep) continue;
      characters -= size(entry);
      entries.delete(name);
    }
  };
  const fail = (entry, error, aborted) => {
    const notice = `Oxc layout unavailable: ${aborted ? 'timed out' : String(error?.message ?? error).slice(0, 240)}`;
    Object.assign(entry, {status: 'error', notice: notice.replace(/\.$/, '')});
  };
  async function read(source, window, signal) {
    const language = ['request_body', 'response_body'].includes(source.kind) && source.language ? `&language=${source.language}` : '';
    const range = window ? `&start_line=${window.start}&line_count=${window.count}` : '';
    const response = await request(`/api/source-format?session_id=${encodeURIComponent(source.session_id)}&artifact_id=${encodeURIComponent(source.artifact_id)}${language}${range}`,
      {cache: 'no-store', signal});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error || `Formatter returned ${response.status}`);
    if (payload?.schema !== 'source-format-v1' || payload.mapping !== 'whitespace-only' || String(payload.source?.artifact_id) !== String(source.artifact_id) || payload.source?.sha256 !== source.sha256) {
      throw new Error('Formatter response does not match this artifact');
    }
    if (payload.status === 'formatted' && typeof payload.text !== 'string') throw new Error('Formatter returned no text');
    return payload;
  }
  async function load(name, source, original, entry) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SOURCE_FORMAT_LIMITS.timeout);
    try {
      const payload = await read(source, null, controller.signal);
      if (payload.status !== 'formatted') {
        Object.assign(entry, {status: 'unavailable', notice: SOURCE_FORMAT_REASONS[payload.reason] ?? 'the Oxc layout is unavailable'});
        return;
      }
      const checked = await layouts.run({op: 'map', original, formatted: payload.text});
      if (!checked.map) throw new Error(checked.error ?? 'Formatter text differs from the evidence beyond whitespace');
      entry.view = {text: payload.text, map: checked.map, offset_unit: 'utf-16-code-unit', language: payload.language, changed: payload.text !== original,
        engine: 'oxc', sourceInput: original};
      entry.status = 'ready';
    } catch (error) {
      fail(entry, error, controller.signal.aborted);
    } finally {
      clearTimeout(timer);
      if (entries.get(name) === entry) {bound(name); onChange(source);}
    }
  }
  // One block of a large layout, checked against its slice of the original between two anchors.
  async function loadPage(name, source, original, entry, block) {
    const page = {status: 'loading'};
    entry.pages.set(block, page);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SOURCE_FORMAT_LIMITS.timeout);
    const stride = SOURCE_FORMAT_LIMITS.pageLines;
    try {
      const payload = await read(source, {start: block * stride + 1, count: stride}, controller.signal);
      if (payload.status !== 'formatted') {
        Object.assign(entry, {status: 'unavailable', notice: SOURCE_FORMAT_REASONS[payload.reason] ?? 'the Oxc layout is unavailable'});
        return;
      }
      const lines = payload.line_count, anchors = payload.anchors?.source_utf16;
      if (!Number.isSafeInteger(lines) || lines < 1 || payload.anchors?.lines !== stride || !Array.isArray(anchors) ||
          anchors.length !== Math.ceil(lines / stride) || anchors.some((at, rank) => !Number.isSafeInteger(at) || at > original.length || (rank && at < anchors[rank - 1])) ||
          (entry.lineCount !== undefined && (entry.lineCount !== lines || entry.anchors.join() !== anchors.join())) ||
          payload.window?.start_line !== block * stride + 1 || payload.window.line_count !== Math.min(stride, lines - block * stride)) {
        throw new Error('Formatter window does not match its layout');
      }
      Object.assign(entry, {lineCount: lines, anchors});
      const base = anchors[block], input = original.slice(base, anchors[block + 1] ?? original.length);
      const checked = await layouts.run({op: 'map', original: input, formatted: payload.text});
      if (!checked.map) throw new Error(checked.error ?? 'Formatter text differs from the evidence beyond whitespace');
      page.view = {paged: true, text: payload.text, map: checked.map, sourceInput: input, base, block, lineBase: block * stride, lineCount: lines,
        anchors, stride, offset_unit: 'utf-16-code-unit', language: payload.language, changed: true, engine: 'oxc'};
      page.status = 'ready';
      entry.status = 'ready';
      for (const [other, value] of entry.pages) {
        if (entry.pages.size <= SOURCE_FORMAT_LIMITS.pages) break;
        if (other !== block && value.status !== 'loading') entry.pages.delete(other);
      }
    } catch (error) {
      fail(entry, error, controller.signal.aborted);
    } finally {
      clearTimeout(timer);
      if (entry.pages.get(block) === page && page.status === 'loading') entry.pages.delete(block);
      if (entries.get(name) === entry) {bound(name); onChange(source);}
    }
  }
  const settled = entry => entry.status === 'ready' ? null : entry.status === 'loading' ? {pending: true} : {fallback: true, notice: entry.notice};
  return {
    // The whole layout of a body. null: not eligible. {pending}: wait. {fallback, notice}: use the in-page layout.
    view(source, original) {
      if (!sourceFormatEligible(source) || original !== source.content) return null;
      if (Number(source.byte_size) > SOURCE_FORMAT_LIMITS.wholeBytes) return {fallback: true, notice: 'Oxc lays out bodies up to 4 MiB here'};
      const name = key(source, 'whole');
      let entry = entries.get(name);
      if (!entry) {
        entry = {status: 'loading'};
        entries.set(name, entry);
        load(name, source, original, entry);
      }
      return settled(entry) ?? entry.view;
    },
    // The 1,000-line page holding formatted line `line`; while it loads, `previous` is the page shown last.
    page(source, original, line = 0) {
      if (!sourceFormatEligible(source) || original !== source.content) return null;
      const name = key(source, 'page');
      let entry = entries.get(name);
      if (!entry) entries.set(name, entry = {status: 'loading', pages: new Map(), shown: null});
      // The first page names the layout's length, so a saved line past its end cannot be asked for.
      const block = entry.lineCount === undefined ? 0 : Math.max(0, Math.min(entry.anchors.length - 1, Math.floor(line / SOURCE_FORMAT_LIMITS.pageLines)));
      if (entry.status === 'error' || entry.status === 'unavailable') return settled(entry);
      const page = entry.pages.get(block);
      if (!page) loadPage(name, source, original, entry, block);
      if (page?.status !== 'ready') return {pending: true, previous: entry.pages.get(entry.shown)?.view ?? null, lineCount: entry.lineCount};
      entry.pages.delete(block);
      entry.pages.set(block, page);
      entry.shown = block;
      return page.view;
    },
    // A failed layout is retried the next time the researcher asks for it.
    forget(source) {
      if (!source) return;
      for (const mode of ['whole', 'page']) {
        const name = key(source, mode);
        if (['error', 'unavailable'].includes(entries.get(name)?.status)) entries.delete(name);
      }
    },
    // The in-page whitespace layout of any pretty-printable text.
    layout(source, value) {
      return layouts.run({op: 'layout', source: {kind: source.kind, mime_type: source.mime_type, url: source.url}, value});
    }
  };
}

if (typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope) {
  importScripts('source_syntax.js');
  self.onmessage = ({data}) => {
    const result = sourceLayoutTask(data.task);
    self.postMessage({id: data.id, result}, result.map ? [result.map.anchors.buffer] : []);
  };
}
