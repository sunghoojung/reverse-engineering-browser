/* Initiator tab: the native request call stack (protocol/native-network-v3.md)
 * and the request initiator chain. Frames come from get_request_stack;
 * captured names and URLs are inserted as text only. */
const REQUEST_STACK_STATES = Object.freeze({1: 'captured', 2: 'no_script', 3: 'unsupported_thread',
  4: 'not_retained_artifact_unavailable', 5: 'not_retained_budget', 6: 'not_walked_thread_limit'});

// Budgets are per thread: the document main thread and each worker keep their own.
const REQUEST_STACK_NOTES = Object.freeze({
  unsupported_thread: 'Stacks are recorded on the document main thread and in dedicated, shared and service workers. This request started on another thread: a worklet, or a loader thread that runs no script.',
  not_retained_artifact_unavailable: 'The stack was walked but its frames were not retained: the Artifact category was off.',
  not_retained_budget: 'The stack was walked but its frames were not retained: this thread already sent 1,024 stacks for requests, navigations, cookie writes and debugger observations in this capture.',
  not_walked_thread_limit: 'No stack was walked: 32 workers in this renderer already had stack tables, so this one had none until another worker shut down.'
});

const REQUEST_STACK_REASONS = Object.freeze({
  script_identity_missing: 'no script identity record',
  script_identity_outside_scan: 'not in the scanned range',
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

const REQUEST_STACK_THREADS = Object.freeze({1: 'document', 2: 'dedicated_worker', 3: 'shared_worker', 4: 'service_worker'});
const REQUEST_STACK_THREAD_NAMES = Object.freeze({document: 'the document main thread',
  dedicated_worker: 'a dedicated worker', shared_worker: 'a shared worker', service_worker: 'a service worker'});

/* The 16-byte stack scope at `at`: its thread kind, or null when malformed. */
function requestStackScope(bytes, at) {
  const view = new DataView(bytes.buffer, bytes.byteOffset + at, 16);
  const thread = REQUEST_STACK_THREADS[bytes[at]];
  const key = view.getBigUint64(8, true);
  if (!thread || bytes.subarray(at + 1, at + 8).some(Boolean) || (thread === 'document') !== (key === 0n)) return null;
  return thread;
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
 * or null for a malformed record. Version 2 adds the task chain, version 3
 * the scope: the thread whose isolate the frames' script IDs belong to. */
function decodeRequestStackRecord(event) {
  const bytes = requestStackBytes(event);
  if (!bytes || event.category !== 'network' || event.type !== 'request_initiator_stack' ||
      event.flags !== 0 || event.artifact_id !== '0' || event.request_id === '0' ||
      event.initiator_request_id !== 0 || event.initiator_process_id !== 0 ||
      BigInt(event.parent_event_id) === 0n || BigInt(event.parent_event_id) >= BigInt(event.sequence_number)) return null;
  const view = new DataView(bytes.buffer);
  const version = view.getUint16(0, true);
  const scoped = version === 3;
  const tasks = version === 2 || scoped;
  const taskSegments = view.getUint16(6, true);
  const state = REQUEST_STACK_STATES[bytes[4]];
  if ((version !== 1 && !tasks) || view.getUint16(2, true) !== 128 || (!tasks && taskSegments !== 0) ||
      bytes.subarray(scoped ? 96 : 80).some(Boolean)) return null;
  // A thread with no worker or document isolate (state 3) names no scope;
  // only version 3 has the thread limit (state 6), which names its worker.
  if (state === 'not_walked_thread_limit' && !scoped) return null;
  const thread = scoped && state !== 'unsupported_thread' ? requestStackScope(bytes, 80) : null;
  if (scoped && (state === 'unsupported_thread' ? bytes.subarray(80, 96).some(Boolean) : !thread)) return null;
  const flags = bytes[5];
  const [total, recorded, omitted] = [8, 12, 16].map(at => view.getUint32(at, true));
  const [asyncFrames, segments] = [view.getUint16(20, true), view.getUint16(22, true)];
  const [wasm, scripts] = [view.getUint32(24, true), view.getUint32(28, true)];
  if (!state || (flags & ~(tasks ? 0x1f : 0x0f)) !== 0) return null;
  const record = {state, thread, total, recorded, omitted, asyncFrames, segments, wasm, taskSegments,
    framesOmitted: Boolean(flags & 2), asyncTruncated: Boolean(flags & 4),
    chainCut: tasks && Boolean(flags & 8), chainTruncated: Boolean(flags & 16)};
  if (state === 'no_script' || state === 'unsupported_thread' || state === 'not_walked_thread_limit') {
    return (flags & ~(tasks ? 0 : 8)) === 0 && taskSegments === 0 && !bytes.subarray(8, 80).some(Boolean) ? record : null;
  }
  const frames = recorded + asyncFrames;
  const chain = tasks
    ? taskSegments <= 32 && segments === asyncFrames + taskSegments && (!record.chainTruncated || taskSegments === 32)
    : segments <= asyncFrames;
  const valid = recorded >= 1 && recorded <= 1024 && recorded + omitted === total &&
    (omitted !== 0) === record.framesOmitted && (omitted === 0 || recorded === 1024) &&
    asyncFrames <= 32 && chain && (!record.asyncTruncated || asyncFrames === 32) &&
    (!(flags & 1) || state === 'captured') && wasm <= frames && scripts <= frames &&
    bytes.subarray(32, 64).some(Boolean) && requestStackFrameValid(bytes, 64, false);
  return valid ? record : null;
}

/* The renderer and sequence a navigation_initiator_link names, or null. */
function decodeNavigationLink(event) {
  const bytes = requestStackBytes(event);
  if (!bytes || event.category !== 'network' || event.type !== 'navigation_initiator_link' ||
      event.flags !== 0 || event.artifact_id !== '0' || event.request_id === '0' ||
      BigInt(event.parent_event_id) === 0n) return null;
  const view = new DataView(bytes.buffer);
  const processId = view.getUint32(4, true);
  const sequence = view.getBigUint64(8, true);
  if (view.getUint16(0, true) !== 1 || view.getUint16(2, true) !== 128 || processId === 0 || sequence === 0n ||
      bytes.subarray(16).some(Boolean)) return null;
  return {processId, sequence: sequence.toString()};
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

const REQUEST_STACK_TASKS = Object.freeze({set_timeout: 'setTimeout', set_interval: 'setInterval',
  request_animation_frame: 'requestAnimationFrame', request_idle_callback: 'requestIdleCallback',
  post_message: 'postMessage', xhr_send: 'XMLHttpRequest.send', post_task: 'scheduler.postTask',
  event: 'Event or observer', microtask: 'Microtask', message_port: 'MessagePort.postMessage',
  broadcast_channel: 'BroadcastChannel.postMessage', worker_message: 'Worker postMessage'});

// A microtask whose registering call was recorded reads as that call.
const REQUEST_STACK_REGISTRATIONS = Object.freeze({then: 'Promise.then', catch: 'Promise.catch',
  finally: 'Promise.finally', await: 'await'});

const REQUEST_STACK_TASK_NOTES = Object.freeze({
  not_recorded: 'the call that registered it is not recorded: promise registration stacks were off (REB_NATIVE_PROMISE_STACKS=1 records them)',
  not_recorded_promise_stacks_on: 'the call that registered it is not recorded: promise registration stacks were on, but this thread remembered no registration for it (a builtin such as Promise.all registered it, capture was off when it was registered, or 2,048 later registrations replaced it)',
  no_script: 'scheduled while no script ran (the browser, the parser or a native callback); the chain ends here',
  origin_rejected: 'its task origin did not validate (forged, damaged or longer than 1,544 bytes), so the sender is not known; the chain ends here',
  not_retained_artifact_unavailable: 'frames not retained: the Artifact category was off',
  not_retained_budget: 'frames not retained: this thread already sent 1,024 scheduling stacks in this capture',
  not_retained_budget_registration: 'frames not retained: this thread already sent 1,024 promise registration stacks in this capture',
  artifact_missing: 'frames artifact missing'
});

/* The note for a task segment without retained frames, or null. */
function requestStackTaskNote(segment) {
  if (segment.state === 'captured') return segment.frames_retained ? null : REQUEST_STACK_TASK_NOTES.artifact_missing;
  if (segment.state === 'not_recorded' && segment.promise_stacks_on) return REQUEST_STACK_TASK_NOTES.not_recorded_promise_stacks_on;
  if (segment.state === 'not_retained_budget' && segment.kind === 'microtask') return REQUEST_STACK_TASK_NOTES.not_retained_budget_registration;
  return REQUEST_STACK_TASK_NOTES[segment.state] ?? null;
}

const REQUEST_STACK_NAVIGATIONS = Object.freeze({location: 'a location assignment', form_submission: 'a form submission',
  window_open: 'window.open', other_script: 'script'});

const REQUEST_STACK_RETRY_MS = 2000;
const REQUEST_STACK_CACHE = 32;

function createRequestStackPanel({open, refresh, load = null}) {
  const cache = new Map();
  const fetchStack = load ?? (async parameters => {
    const response = await fetch(`/api/request-stack?${new URLSearchParams(parameters)}`, {cache: 'no-store', signal: AbortSignal.timeout(10000)});
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

  function frameItem(frame) {
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
      list.append(frameItem(frame));
      if (stack.omitted_after_index === frame.index) {
        list.append(row(`${Number(stack.omitted).toLocaleString('en-US')} frames omitted`, 'request-stack-separator'));
      }
    }
    // Each async task that led here, nearest first, with the stack that scheduled it.
    for (const segment of stack.task_segments ?? []) {
      const label = REQUEST_STACK_REGISTRATIONS[segment.registration] ?? REQUEST_STACK_TASKS[segment.kind] ?? 'Async task';
      // A segment a message carried names the thread or process that posted it.
      const where = segment.scope && segment.scope.elsewhere
        ? ` · on ${REQUEST_STACK_THREAD_NAMES[segment.scope.thread] ?? 'another thread'}${segment.scope.other_process ? ` in process ${segment.scope.process_id}` : ''}`
        : '';
      list.append(row(`${label}${where}`, 'request-stack-separator'));
      const frames = segment.frames ?? [];
      const reason = requestStackTaskNote(segment);
      if (reason && (!frames.length || !segment.frames_retained)) list.append(row(reason, 'request-stack-note'));
      for (const frame of frames) list.append(frameItem(frame));
      if (segment.bounded) {
        list.append(row(`stopped at ${segment.kind === 'microtask' ? 32 : 256} frames`, 'request-stack-separator'));
      }
    }
    if (stack.task_chain_cut) list.append(row('Earlier async callers were not recorded', 'request-stack-separator'));
    return list;
  }

  // Reads a stack from get_request_stack once, then again after a transient failure.
  function resolved(key, parameters, sequence) {
    let entry = cache.get(key);
    const retry = entry?.retryable && Date.now() - entry.failedAt >= REQUEST_STACK_RETRY_MS;
    if ((!entry || retry) && typeof location !== 'undefined' && location.protocol !== 'file:') {
      const next = {status: 'loading'};
      cache.delete(key);
      cache.set(key, next);
      while (cache.size > REQUEST_STACK_CACHE) cache.delete(cache.keys().next().value);
      fetchStack(parameters)
        .then(body => {
          next.status = body?.status === 'recorded' && body.request?.sequence_number === sequence ? 'ready' : 'error';
          next.document = body;
          if (body?.status === 'outside_scan') {
            // Unknown, not absent. Only an index still catching up can change the answer;
            // otherwise another read would scan the same bytes to the same result.
            Object.assign(next, {error: 'This stack is not in the scanned range of the event store, so it is unknown rather than missing.',
              retryable: body.index_behind === true, failedAt: Date.now()});
            return;
          }
          next.error = next.status === 'error' ? 'The stored stack no longer matches this request record.' : null;
        }, error => {
          Object.assign(next, {status: 'error', retryable: true, failedAt: Date.now(),
            error: error?.name === 'TimeoutError' ? 'The request stack store did not answer within 10 seconds.' : error.message});
        })
        .finally(() => refresh());
      entry ??= next;
    }
    return entry;
  }

  function stackNodes(stack, record) {
    const nodes = [];
    if (!stack.frames_retained && stack.state === 'captured') {
      nodes.push(note('The frames artifact is not retained; only the innermost frame is shown.'));
    }
    nodes.push(frameList(stack));
    if (record?.asyncTruncated || stack.async_truncated) nodes.push(note('The await chain continues past 32 frames.'));
    if (stack.task_chain_truncated) nodes.push(note('The task chain continues past 32 segments.'));
    if (stack.async_callers_not_shown?.length) {
      nodes.push(note(`Async callers not shown: ${stack.async_callers_not_shown.join(', ')}.`));
    }
    return nodes;
  }

  // A browser navigation row: the stack its navigation_initiator_link names.
  function navigationSection(request, linkEvent, link) {
    const key = [linkEvent.session_id, link.processId, 'navigation', link.sequence].join(':');
    const entry = resolved(key, {process_id: String(link.processId), navigation_sequence: link.sequence,
      session_id: linkEvent.session_id}, link.sequence);
    if (!entry || entry.status === 'loading') return [note('Script started this navigation. Resolving frames from retained sources.')];
    if (entry.status === 'error') return [note(entry.error || 'The navigation stack is unavailable.')];
    const stack = entry.document;
    const nodes = [note(`Started by ${REQUEST_STACK_NAVIGATIONS[stack.navigation?.kind] ?? 'script'}.`)];
    if (REQUEST_STACK_NOTES[stack.state]) nodes.push(note(REQUEST_STACK_NOTES[stack.state]));
    return [...nodes, ...stackNodes(stack, null)];
  }

  function stackSection(request) {
    const nodes = [heading('Request call stack')];
    const initiated = request?.events?.find(event => event.type === 'request_initiated') ?? null;
    const stackEvent = initiated ? (request.details ?? []).find(event => event.type === 'request_initiator_stack' &&
      event.parent_event_id === initiated.sequence_number && event.process_id === initiated.process_id &&
      event.session_id === initiated.session_id) ?? null : null;
    if (!stackEvent) {
      const linkEvent = initiated ? null : (request?.details ?? []).find(event => event.type === 'navigation_initiator_link') ?? null;
      const link = linkEvent ? decodeNavigationLink(linkEvent) : null;
      if (link) return [...nodes, ...navigationSection(request, linkEvent, link)];
      nodes.push(note(linkEvent
        ? 'The navigation initiator link is malformed.'
        : initiated
          ? 'No request call stack record. Request stacks are recorded with REB_NATIVE_REQUEST_STACKS=1, and a record that left the retained window is not shown.'
          : 'No renderer request record, and no script navigation stack names this request.'));
      return nodes;
    }
    const record = decodeRequestStackRecord(stackEvent);
    if (!record) {
      nodes.push(note('The request call stack record is malformed.'));
      return nodes;
    }
    if (record.state === 'no_script') {
      const worker = record.thread && record.thread !== 'document';
      nodes.push(row(worker ? 'Worker loader' : 'Parser', 'request-stack-parser'));
      nodes.push(note(worker
        ? `No JavaScript was running when ${REQUEST_STACK_THREAD_NAMES[record.thread]} started this request: its script or module loader, or a start the loader deferred.`
        : 'No JavaScript was running when the renderer started this request: the HTML parser, a preload, or a start the loader deferred.'));
      return nodes;
    }
    if (record.state === 'unsupported_thread') {
      nodes.push(note(REQUEST_STACK_NOTES[record.state]));
      return nodes;
    }
    if (record.state === 'not_walked_thread_limit') {
      nodes.push(note(`Started in ${REQUEST_STACK_THREAD_NAMES[record.thread]}.`), note(REQUEST_STACK_NOTES[record.state]));
      return nodes;
    }
    const key = [stackEvent.session_id, stackEvent.process_id, stackEvent.request_id, stackEvent.sequence_number].join(':');
    const entry = resolved(key, {process_id: String(stackEvent.process_id), request_id: stackEvent.request_id,
      session_id: stackEvent.session_id}, stackEvent.sequence_number);
    if (REQUEST_STACK_NOTES[record.state]) nodes.push(note(REQUEST_STACK_NOTES[record.state]));
    if (record.thread && record.thread !== 'document') nodes.push(note(`Started in ${REQUEST_STACK_THREAD_NAMES[record.thread]}.`));
    if (!entry || entry.status === 'loading') {
      nodes.push(note(`${record.total} synchronous frames${record.asyncFrames ? ` and ${record.asyncFrames} async frames` : ''}${record.taskSegments ? ` after ${record.taskSegments} async tasks` : ''}. Resolving frames from retained sources.`));
      return nodes;
    }
    if (entry.status === 'error') {
      nodes.push(note(entry.error || 'The request call stack is unavailable.'));
      return nodes;
    }
    nodes.push(...stackNodes(entry.document, record));
    return nodes;
  }

  function render(container, request, chainNodes) {
    container.replaceChildren(...stackSection(request), heading('Request initiator chain'), ...chainNodes);
  }

  return {render};
}
