// Client for get_source_format and the in-page layout. Both change only whitespace, so one map walks either back to its input.

const SOURCE_FORMAT_LIMITS = Object.freeze({entries: 4, characters: 64 * 1024 * 1024, timeout: 180000, sourceBytes: 16 * 1024 * 1024});
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

function sourceFormatEligible(source) {
  return source?.source_type === 'artifact' && source.kind === 'javascript' && typeof source.content === 'string' &&
    !source.contentTruncated && !source.contentLossy && Number(source.byte_size) <= SOURCE_FORMAT_LIMITS.sourceBytes;
}

function createSourceFormatClient({request = (...args) => fetch(...args), onChange = () => {}, layouts = createSourceLayoutWorker()} = {}) {
  const entries = new Map();
  const key = source => `${source.session_id}|${source.artifact_id}|${source.sha256}`;
  // The newest layout stays even when it alone exceeds the budget; evicting it would refetch it.
  const bound = keep => {
    let characters = 0;
    for (const entry of entries.values()) characters += entry.view?.text.length ?? 0;
    for (const [name, entry] of entries) {
      if (entries.size <= SOURCE_FORMAT_LIMITS.entries && characters <= SOURCE_FORMAT_LIMITS.characters) break;
      if (entry.status === 'loading' || name === keep) continue;
      characters -= entry.view?.text.length ?? 0;
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
      if (typeof payload.text !== 'string') throw new Error('Formatter returned no text');
      const checked = await layouts.run({op: 'map', original, formatted: payload.text});
      if (!checked.map) throw new Error(checked.error ?? 'Formatter text differs from the evidence beyond whitespace');
      entry.view = {text: payload.text, map: checked.map, offset_unit: 'utf-16-code-unit', language: 'javascript', changed: payload.text !== original,
        engine: 'oxc', sourceInput: original};
      entry.status = 'ready';
    } catch (error) {
      Object.assign(entry, {status: 'error', notice: `Oxc layout unavailable: ${controller.signal.aborted ? 'timed out' : String(error?.message ?? error).slice(0, 240)}`});
      entry.notice = entry.notice.replace(/\.$/, '');
    } finally {
      clearTimeout(timer);
      if (entries.get(name) === entry) {bound(name); onChange(source);}
    }
  }
  return {
    // null: not eligible. {pending}: wait. {fallback, notice}: use the in-page layout.
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
