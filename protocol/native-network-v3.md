# Native network v3

Status: source candidate. The overlay and patches compile only against the
portable harnesses here; patched Brave compilation and a live run are still
required (see [Acceptance](#acceptance)).

Version 3 adds network records that are children of v1 lifecycle records, in
the v3 320-byte envelope. Nothing in a v1 or v2 record changes.
[SAFETY.md](../SAFETY.md) governs capture and export.

## Request initiator stacks

The synchronous JavaScript and WebAssembly stack, plus V8's `await` chain, that
was running when a renderer started a request. Frames are identities only:
no strings, no values, no debugger.

### Gate

- V8 flag `--reb-request-stacks`, off by default. The launcher adds it for
  `REB_NATIVE_REQUEST_STACKS=1`, which needs Network (256) and Artifact (1024).
  `make live` leaves it off. The packaged app sets it when the mask allows
  both, and with `REB_NATIVE_REQUEST_STACKS_IF_SUPPORTED=1` drops it, with a
  launch log line, from a Brave that does not define it.
- Blink installs the stack provider only when V8 reports the flag on. Without
  it a request start costs one atomic load and nothing is walked.
- The renderer walks only on the document main thread, for a request whose
  `request_initiated` record was admitted.

### `request_initiator_stack` (type 34)

Category `network`, child of the renderer's `request_initiated` record:
`parent_event_id` is that record's sequence, with the same process, thread,
frame and renderer `request_id`. Payload 128 bytes, little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | state |
| 5 | 1 | flags |
| 6 | 2 | reserved, zero |
| 8 | 4 | total synchronous depth |
| 12 | 4 | recorded synchronous frames, at most 1,024 |
| 16 | 4 | omitted synchronous frames |
| 20 | 2 | async frames, at most 32 |
| 22 | 2 | async segments |
| 24 | 4 | Wasm frames among the recorded ones |
| 28 | 4 | distinct scripts among the recorded frames |
| 32 | 32 | stack digest: SHA-256 of the stack artifact content |
| 64 | 16 | innermost frame, in the frame layout below |
| 80 | 48 | reserved, zero |

| State | Meaning |
| ---: | --- |
| 1 `captured` | Frames walked; the digest names the stack artifact |
| 2 `no_script` | No JavaScript or Wasm was on the stack: the parser, a preload, or a start the loader deferred |
| 3 `unsupported_thread` | Not the document main thread (workers, worklets) |
| 4 `not_retained_artifact_unavailable` | Frames walked; Artifact category off or no artifact path |
| 5 `not_retained_budget` | Frames walked; this configuration already sent 1,024 stacks |

Flags: bit 0 the stack artifact was queued with this record; bit 1 frames were
omitted; bit 2 the `await` chain reached 32 frames and may continue; bit 3 task-attributed
async callers (timers, event listeners, `promise.then` callbacks, message
handlers) were not captured. Bit 3 is always set in version 1. Other bits are
zero.

Validation, shared by the C++ core, the Python validator and the backend:

- States 1, 4 and 5 have a nonzero digest, an innermost frame, recorded at
  least 1, `recorded + omitted == total` and `recorded <= 1024`. Omitted is
  nonzero exactly when bit 1 is set, and then recorded is 1,024.
- States 2 and 3 have every count, the digest and the innermost frame zero, and
  only bit 3 may be set.
- Bit 0 only with state 1. Async segments never exceed async frames. Wasm
  frames and distinct scripts never exceed recorded plus async frames.
- The envelope's `artifact_id` is zero: the browser assigns artifact IDs.

### Frame layout

16 bytes, innermost first:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | kind: 1 JavaScript, 2 Wasm, 3 `await` (async function), 4 promise combinator |
| 1 | 1 | flags: bit 0 constructor call, bit 1 top-level script code |
| 2 | 2 | combinator for kind 4: 1 `Promise.all`, 2 `Promise.allSettled`, 3 `Promise.any`; else 0 |
| 4 | 4 | V8 script ID (the Wasm module's script for kind 2); 0 only for kind 4 |
| 8 | 4 | kinds 1, 3: source position, UTF-16 offset into the script source; kind 2: module byte offset; kind 4: promise index |
| 12 | 4 | kinds 1, 3: function start position; kind 2: function index; kind 4: 0 |

Script IDs are unique in one renderer process's main isolate, so a frame is
read with the record's `process_id`.

### Stack artifact

Kind 10 `stack`, capture origin 12 `request_stack`, not sensitive, MIME
`application/x-reb-stack`, URL `reb-stack:sha256-<hex digest>`,
`creator_event_id` the record's sequence. Its manifest SHA-256 is the record's
digest. Content:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `RBSK` (`0x4b534252`) |
| 4 | 2 | version, `1` |
| 6 | 2 | header size, `32` |
| 8 | 2 | frame size, `16` |
| 10 | 2 | record flags bits 1 and 2 |
| 12 | 4 | total synchronous depth |
| 16 | 4 | recorded synchronous frames |
| 20 | 4 | omitted synchronous frames |
| 24 | 2 | async frames |
| 26 | 2 | async segments |
| 28 | 4 | reserved, zero |
| 32 | 16 x n | recorded synchronous frames, then async frames |

A stack deeper than 1,024 keeps the innermost 512 and the outermost 512 frames;
the omitted frames lie between index 511 and 512. Async frames follow the
synchronous ones in chain order; in version 1 each async frame is one segment.

Each renderer remembers 256 digests it sent in the current configuration. A
repeated stack sends no artifact. A digest that falls out of that table is sent
again, never dropped. The renderer sends at most 1,024 stack artifacts per
configuration.

### `script_identity` (type 35)

Category `network`, `request_id` 0, child of the `request_initiator_stack`
record that first named the script in this configuration. Same process,
thread and frame. Both records share the Network and Artifact gate.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | kind: 1 JavaScript, 2 Wasm |
| 5 | 1 | flags |
| 6 | 2 | reserved, zero |
| 8 | 4 | V8 script ID, nonzero |
| 12 | 4 | start line in its document or resource, 0-based |
| 16 | 4 | start column, 0-based |
| 20 | 4 | reserved, zero |
| 24 | 8 | execution context ID of the script's realm |
| 32 | 8 | source length: UTF-8 bytes, or Wasm wire bytes |
| 40 | 32 | SHA-256 of those bytes |
| 72 | 56 | reserved, zero |

Flags: bit 0 `eval` or `new Function` script; bit 1 the source was queued as
an artifact with this record as creator; bit 2 source longer than 16 MiB, not
hashed; bit 3 source unavailable; bit 4 not retained: Artifact category off or
the source budget is spent. Exactly one of bit 1, bit 2, bit 3, bit 4 or none
(a Wasm module, never re-sent) holds. A digest is present unless bit 2 or 3.

JavaScript sources are retained as kind 1 `javascript`, capture origin 13
`stack_script`, at most 512 sources and 64 MiB per renderer configuration, with
the script URL, or the document URL for an inline script, as the artifact URL.
Wasm modules are not re-sent: the compile-time Wasm artifacts join by SHA-256.
A network script the body tee retained also joins by SHA-256.

The renderer remembers 1,024 script IDs it described in the current
configuration; an evicted script is described again.

## Resolution

`get_request_stack` (`GET /api/request-stack?process_id=&request_id=`, the
renderer identity) returns the newest stack record for that request with its
frames:

- A JavaScript frame resolves through `(process_id, script_id)` to its identity
  record, then by SHA-256 to a retained `javascript` artifact, to one-based line
  and column (UTF-16 columns, the identity record's start line and column
  added on the script's first line), and to the enclosing function name read
  at the function start position. `eval` and `new Function` frames resolve to
  their `dynamic_javascript` artifacts the same way.
- A Wasm frame resolves to its function index, and to its name when the
  retained module has a name section.
- A frame that does not resolve keeps its raw identity and a reason. Nothing is
  guessed.

`get_events` with `request_id` returns the stack record beside the lifecycle
records.

## Consumers

- The broker accepts both types only when `IsValidEvent` accepts them.
- The trace index treats `request_initiator_stack` as a request child: it never
  becomes the request's latest lifecycle record.
- The backend's network window keeps `request_initiator_stack` records.
- Origin Trace's Initiator tab shows "Request call stack" with `await`
  separators and an "N frames omitted" marker, opening Sources at a resolved
  frame, and "Request initiator chain" from the request's initiator edges.
  `no_script` reads "Parser". Captured values are inserted as text.

## Hot path and bounds

- Flag off: one atomic load per request start.
- Flag on, inactive session or category off: the existing `request_initiated`
  checks; no walk.
- Active: one V8 walk into a frame buffer allocated once when the provider is
  installed (1,056 frames), one SHA-256 of at most 16,928 bytes, one 320-byte
  record. First sightings add one artifact, and for each new script one record
  and one source copy.

## Validation

`tests/request_stack_test.cpp` (in `make native-tests`) checks layout parity
with the overlay, every state, the frame bounds and malformed records.
`make native-probe-admission-check` drives the real renderer sink with a
fixture provider: disabled, 150 and 5,000 frames, Wasm and `await` frames,
repeated stacks, table eviction, budgets and script identity.
`make request-stack-wire-check` compares the C++ verdicts with the Python
validator and the Initiator decoder and renders the Initiator panel in a DOM
model. The backend's `request_stack` tests resolve inline, `eval`, Wasm and
`await` frames and refuse to guess unresolved ones.

## Acceptance

Still required before declaring this browser-ready:

1. Replay all stacks and overlays on a disposable initialized pinned checkout,
   run `make brave-doctor` and `make brave-probe-check`, and compile.
2. A 150-frame stack through framework wrappers matches DevTools' synchronous
   initiator stack frame for frame.
3. A 5,000-deep recursion records 1,024 frames, the omitted count and depth.
4. Frames into an inline script, an `eval` script and a network script resolve
   to file, line and column. A `fetch` from a Wasm import shows Wasm frames.
   An `await` chain shows its async frames.
5. Repeated requests from one call site send their stack once.
6. Measure added time per request at p50 and p99 on a request-heavy page before
   keeping the packaged default on.
7. Script-initiated navigations (`location`, `form.submit`, `window.open`) and
   task-attributed async callers are not recorded yet.
