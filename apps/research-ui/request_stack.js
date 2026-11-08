/* Initiator tab: the native request call stack (protocol/native-network-v3.md)
 * and the request initiator chain. Frames come from get_request_stack;
 * captured names and URLs are inserted as text only. */
const REQUEST_STACK_STATES = Object.freeze({1: 'captured', 2: 'no_script', 3: 'unsupported_thread',
  4: 'not_retained_artifact_unavailable', 5: 'not_retained_budget'});

const REQUEST_STACK_NOTES = Object.freeze({
  unsupported_thread: 'Stacks are recorded only on the document main thread. This request started in a worker or worklet.',
  not_retained_artifact_unavailable: 'The stack was walked but its frames were not retained: the Artifact category was off.',
  not_retained_budget: 'The stack was walked but its frames were not retained: this renderer already sent 1,024 stacks in this capture.'
});

const REQUEST_STACK_REASONS = Object.freeze({
  script_identity_missing: 'no script identity record',
  source_unavailable: 'source unavailable',
  source_not_retained: 'source not retained',
  source_artifact_missing: 'source artifact missing',
  source_artifact_unreadable: 'source artifact unreadable',
  source_not_utf8: 'source is not UTF-8',
  position_outside_source: 'position outside the retained source'
});

function requestStackBytes(event) {
  const hex = typeof event?.payload === 'string' ? event.payload : '';
  if (hex.length !== 256 || !/^[0-9a-f]+$/.test(hex)) return null;
  return Uint8Array.from(hex.match(/../g), byte => Number.parseInt(byte, 16));
}

function requestStackFrameValid(bytes, at, isAsync) {
  const view = new DataView(bytes.buffer, bytes.byteOffset + at, 16);
  const [kind, flags, combinator, script, detail] =
    [view.getUint8(0), view.getUint8(1), view.getUint16(2, true), view.getUint32(4, true), view.getUint32(12, true)];
  if (kind === 1) return !isAsync && script !== 0 && combinator === 0 && (flags & ~3) === 0;
  if (kind === 2) return !isAsync && script !== 0 && combinator === 0 && flags === 0;
  if (kind === 3) return isAsync && script !== 0 && combinator === 0 && (flags & ~2) === 0;
  if (kind === 4) return isAsync && script === 0 && combinator >= 1 && combinator <= 3 && flags === 0 && detail === 0;
  return false;
}

/* The request_initiator_stack payload rules of include/reb/request_stack.hpp,
 * or null for a malformed record. */
function decodeRequestStackRecord(event) {
  const bytes = requestStackBytes(event);
  if (!bytes || event.category !== 'network' || event.type !== 'request_initiator_stack' ||
      event.flags !== 0 || event.artifact_id !== '0' || event.request_id === '0' ||
      event.initiator_request_id !== 0 || event.initiator_process_id !== 0 ||
      BigInt(event.parent_event_id) === 0n || BigInt(event.parent_event_id) >= BigInt(event.sequence_number)) return null;
  const view = new DataView(bytes.buffer);
  if (view.getUint16(0, true) !== 1 || view.getUint16(2, true) !== 128 || view.getUint16(6, true) !== 0 ||
      bytes.subarray(80).some(Boolean)) return null;
  const state = REQUEST_STACK_STATES[bytes[4]];
  const flags = bytes[5];
  const [total, recorded, omitted] = [8, 12, 16].map(at => view.getUint32(at, true));
  const [asyncFrames, segments] = [view.getUint16(20, true), view.getUint16(22, true)];
  const [wasm, scripts] = [view.getUint32(24, true), view.getUint32(28, true)];
  if (!state || (flags & ~0x0f) !== 0) return null;
  const record = {state, total, recorded, omitted, asyncFrames, segments, wasm,
    framesOmitted: Boolean(flags & 2), asyncTruncated: Boolean(flags & 4)};
  if (state === 'no_script' || state === 'unsupported_thread') {
    return (flags & ~8) === 0 && !bytes.subarray(8, 80).some(Boolean) ? record : null;
  }
  const frames = recorded + asyncFrames;
  const valid = recorded >= 1 && recorded <= 1024 && recorded + omitted === total &&
    (omitted !== 0) === record.framesOmitted && (omitted === 0 || recorded === 1024) &&
    asyncFrames <= 32 && segments <= asyncFrames && (!record.asyncTruncated || asyncFrames === 32) &&
    (!(flags & 1) || state === 'captured') && wasm <= frames && scripts <= frames &&
    bytes.subarray(32, 64).some(Boolean) && requestStackFrameValid(bytes, 64, false);
  return valid ? record : null;
}

function requestStackFile(url) {
  const text = String(url ?? '');
  try {
    const parsed = new URL(text);
    return parsed.pathname.split('/').filter(Boolean).pop() || parsed.host || text;
  } catch {
    return text;
  }
}

function requestStackFrameText(frame) {
  const resolution = frame.resolution ?? {};
  if (frame.kind === 'wasm') {
    const name = resolution.function_name ?? `wasm-function[${frame.function_index}]`;
    const at = `0x${Number(frame.module_offset).toString(16)}`;
    return resolution.status === 'resolved'
      ? `${name} @ ${requestStackFile(resolution.url)}:${at}`
      : `wasm-function[${frame.function_index}] @ script ${frame.script_id}:${at} · ${REQUEST_STACK_REASONS[resolution.reason] ?? 'unresolved'}`;
  }
  if (resolution.status !== 'resolved') {
    return `(script ${frame.script_id}) @ offset ${frame.position} · ${REQUEST_STACK_REASONS[resolution.reason] ?? 'unresolved'}`;
  }
  const name = resolution.function_name ?? '(anonymous)';
  const file = frame.eval ? `VM${frame.script_id}` : requestStackFile(resolution.url);
  return `${name} @ ${file}:${resolution.line}:${resolution.column}`;
}

const REQUEST_STACK_SEPARATORS = Object.freeze({await: 'await', promise_all: 'Promise.all',
  promise_all_settled: 'Promise.allSettled', promise_any: 'Promise.any'});

function createRequestStackPanel({open, refresh, load = null}) {
  const cache = new Map();
  const fetchStack = load ?? (async parameters => {
    const response = await fetch(`/api/request-stack?${new URLSearchParams(parameters)}`, {cache: 'no-store'});
    if (!response.ok) throw new Error(`Request stack store returned ${response.status}`);
    return response.json();
  });

  function heading(text) {
    const node = document.createElement('div');
    node.className = 'request-stack-heading';
    node.setAttribute('role', 'heading');
    node.setAttribute('aria-level', '3');
    node.textContent = text;
    return node;
  }
  function note(text) {
    const node = document.createElement('div');
    node.className = 'field-empty';
    node.textContent = text;
    return node;
  }
  function row(text, className) {
    const item = document.createElement('li');
    item.className = className;
    item.textContent = text;
    return item;
  }

  function frameList(stack) {
    const list = document.createElement('ol');
    list.className = 'request-stack-frames';
    list.setAttribute('aria-label', 'Request call stack frames, innermost first');
    for (const frame of stack.frames ?? []) {
      const separator = REQUEST_STACK_SEPARATORS[frame.kind];
      if (separator) list.append(row(separator, 'request-stack-separator'));
      if (frame.kind.startsWith('promise_')) continue;
      const item = document.createElement('li');
      item.className = 'request-stack-frame';
      const text = requestStackFrameText(frame);
      if (frame.resolution?.status === 'resolved' && frame.resolution.artifact_id) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'request-stack-open';
        button.textContent = text;
        button.title = `Open in Sources: ${frame.resolution.url ?? ''}`;
        button.addEventListener('click', () => open(frame));
        item.append(button);
      } else {
        item.textContent = text;
      }
      list.append(item);
      if (stack.omitted_after_index === frame.index) {
        list.append(row(`${Number(stack.omitted).toLocaleString('en-US')} frames omitted`, 'request-stack-separator'));
      }
    }
    return list;
  }

  function stackSection(request) {
    const nodes = [heading('Request call stack')];
    const initiated = request?.events?.find(event => event.type === 'request_initiated') ?? null;
    const stackEvent = initiated ? (request.details ?? []).find(event => event.type === 'request_initiator_stack' &&
      event.parent_event_id === initiated.sequence_number && event.process_id === initiated.process_id &&
      event.session_id === initiated.session_id) ?? null : null;
    if (!stackEvent) {
      nodes.push(note(initiated
        ? 'No request call stack record. Request stacks are recorded with REB_NATIVE_REQUEST_STACKS=1, and a record that left the retained window is not shown.'
        : 'No renderer request record, so no call stack is attributed to this request.'));
      return nodes;
    }
    const record = decodeRequestStackRecord(stackEvent);
    if (!record) {
      nodes.push(note('The request call stack record is malformed.'));
      return nodes;
    }
    if (record.state === 'no_script') {
      nodes.push(row('Parser', 'request-stack-parser'));
      nodes.push(note('No JavaScript was running when the renderer started this request: the HTML parser, a preload, or a start the loader deferred.'));
      return nodes;
    }
    if (record.state === 'unsupported_thread') {
      nodes.push(note(REQUEST_STACK_NOTES[record.state]));
      return nodes;
    }
    const key = [stackEvent.session_id, stackEvent.process_id, stackEvent.request_id, stackEvent.sequence_number].join(':');
    let entry = cache.get(key);
    if (!entry && typeof location !== 'undefined' && location.protocol !== 'file:') {
      entry = {status: 'loading'};
      cache.set(key, entry);
      fetchStack({process_id: String(stackEvent.process_id), request_id: stackEvent.request_id, session_id: stackEvent.session_id})
        .then(body => {
          entry.status = body?.status === 'recorded' && body.request?.sequence_number === stackEvent.sequence_number
            ? 'ready' : 'error';
          entry.document = body;
          entry.error = entry.status === 'error' ? 'The stored stack no longer matches this request record.' : null;
        }, error => {
          entry.status = 'error';
          entry.error = error.message;
        })
        .finally(() => refresh());
    }
    if (REQUEST_STACK_NOTES[record.state]) nodes.push(note(REQUEST_STACK_NOTES[record.state]));
    if (!entry || entry.status === 'loading') {
      nodes.push(note(`${record.total} synchronous frames${record.asyncFrames ? ` and ${record.asyncFrames} async frames` : ''}. Resolving frames from retained sources.`));
      return nodes;
    }
    if (entry.status === 'error') {
      nodes.push(note(entry.error || 'The request call stack is unavailable.'));
      return nodes;
    }
    const stack = entry.document;
    if (!stack.frames_retained && record.state === 'captured') {
      nodes.push(note('The frames artifact is not retained; only the innermost frame is shown.'));
    }
    nodes.push(frameList(stack));
    if (record.asyncTruncated) nodes.push(note('The await chain continues past 32 frames.'));
    nodes.push(note(`Async callers not shown: ${(stack.async_callers_not_shown ?? []).join(', ')}.`));
    return nodes;
  }

  function render(container, request, chainNodes) {
    container.replaceChildren(...stackSection(request), heading('Request initiator chain'), ...chainNodes);
  }

  return {render};
}
