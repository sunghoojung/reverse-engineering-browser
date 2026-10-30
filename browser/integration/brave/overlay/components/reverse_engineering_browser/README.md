# Reverse Engineering Browser native probes

This component owns renderer-side and browser-side boundaries for native probe
events. Project-wide authorization, capture, and privacy policy is in
[`SAFETY.md`](../../../../../../SAFETY.md).

Generated Blink binding probes observe calls and property reads from an
explicit 90-interface allowlist across Canvas, WebGL, WebGPU, Web Audio,
browser, layout, font, media, Permissions, Storage, and WebRTC surfaces.
Generic DOM interfaces retain only fingerprint-relevant measurement and
capability members. V8 use counters add selected cross-engine Math functions,
Intl constructors, locale-sensitive formatting, and timezone-offset reads as
Runtime events. Generated non-Canvas bindings and V8 counters retain the first
observation of each call site per capture session so repeated timing and Math
loops cannot crowd later unique surfaces out of the bounded queue. Lower-level
Canvas and WebGL call sites also cover supported internal drawing, readback,
and capability-query paths, with overlapping generated callbacks excluded to
avoid duplicates. Each metadata event contains only a fixed operation name and
never retains arguments, text, pixels, or return values. The inactive sink path
performs one atomic emitter check and returns without allocating, blocking, or
changing the surface result.

While capture is active, renderer operations resolve the current Blink frame
token only after the policy check. The browser-process host maps that token to
its top-level tab, leaving worker and detached-frame events unattributed. A
local Stop command closes the broker connection; the browser socket client
detects that disconnect promptly and disables every renderer host and browser
capture sink. No page script controls probe activation.

Canvas output is a separate, explicit sensitive-capture mode. When enabled for
the session, a successful `HTMLCanvasElement.toDataURL()` result of at most 2
MiB becomes a `canvas_data_url` artifact linked by `creator_event_id` to the
exact readback operation. Larger or invalid results still produce metadata but
no artifact. Renderer code passes the output one way to the browser process;
the browser remains the only owner of the authenticated artifact connection.

Web Audio call sites observe selected graph construction, connection, source
start, offline rendering, analyser readback, and audio-buffer readback APIs.
Each event contains one fixed operation name. Audio samples, rendered buffers,
node parameters, and return values are never copied into the event record. Web
Audio uses category-mask bit `4`; disabled or expired calls return before
sequence assignment and queue insertion.

The renderer request hook records the request identifier immediately after
Chromium allocates it. The browser hook observes Brave's existing URL loader
factory and client proxies, preserving the request, initiator process, frame,
status, size, redirect, cache, and service-worker metadata needed to reconstruct
a lifecycle. While capture is enabled, the proxy resolves initiator process,
frame, and opaque BrowserContext identity on the first observed lifecycle event
and caches them for the request. This keeps completion correlated after
renderer exit, disambiguates profile-local Brave request IDs, and adds no work
to the inactive path.

An authorized session registers a non-blocking, non-throwing emitter that
copies the fixed 320-byte record into a bounded shared-memory queue. Each
renderer has one multi-producer queue because probes can run on its render
thread and worker threads. Mojo carries session configuration and coalesced
wake-ups while event records remain in shared memory. Session configuration
includes an immutable category bitmask and a monotonic expiration deadline.
Renderer and browser-process sinks check both values before queue insertion,
and the browser session checks them again before socket delivery. The
browser-side session starts only after its Unix-socket client authenticates to
the local event broker. It uses another bounded queue and a dedicated writer
thread, so network and renderer capture paths never wait for the socket.
The shared renderer sink uses only its injected emitter callback, which reports
admitted, policy-rejected or queue-full status. The sink never links back into
the renderer transport; queue-full status keeps dispatch loss accounting from
counting a ring rejection twice.
Both event queues reuse 8,192 slots (3,146,048 bytes per queue); that capacity is
an in-flight bound, not a lifetime limit on captured events. A full queue drops
without blocking and preserves visible, saturating drop accounting. The larger
bound adds burst headroom; it does not prove a public-demo load is lossless.
The component test retains 4,096 synthetic Canvas calls without coalescing and
rejects legacy/wrong-size mappings. Both browser and renderer must be rebuilt;
the transport checks exact mapping bytes before reading the queue's version,
record size and capacity. A producer that stays ahead of the consumer can still
drop. Rebuilt-browser runtime acceptance is separate. Coalesced
wake-ups use an acquire/release exchange on every announcement and clear: a
producer racing with the consumer's empty check either becomes visible to that
check or owns a new wake-up. A load-only already-pending shortcut can strand an
event without a notification, even when the queue has free space.

`make demo && build/reb-event-demo` exercises capacity, weighted drops,
saturation, slot reuse, and the concurrent notification handoff using the same
native queue as the renderer. `build/reb-event-demo --queue-iterations 5000000`
extends the handoff stress run and bounded batch throughput measurement. These
synthetic checks do not launch a browser, enable capture, or prove performance
inside a built Brave application.

Payload capture is limited to a bounded metadata prefix. Network request
prefixes contain only the method and destination host. URL paths, queries,
fragments, bodies, credentials, authorization headers, and cookies are not
captured.

Large artifact bytes use the separate 128-byte framed contract and 32-byte
acknowledgment in `common/native_artifact_header.h`. Only the browser-process
bridge owns that receiver connection. JavaScript and WASM response bodies are
copied by an asynchronous Mojo tee with a 16 MiB per-artifact limit and a 32
MiB active capture budget. Accepted dynamic JavaScript and WASM byte-buffer API
inputs use a separate one-way Mojo submission with the same per-artifact cap.
The browser copies renderer-owned shared memory before validation and records
the stable execution context plus exact capture origin. A dedicated writer
thread drains a 16-artifact, 32 MiB queue to the authenticated artifact socket.
Successful evidence is emitted only after receiver acknowledgment; every local
or remote rejection becomes an `artifact_capture_failed` event. Artifact bytes
do not enter the renderer event ring, and arbitrary response bodies still
require explicit sensitive-capture authorization under
[`SAFETY.md`](../../../../../../SAFETY.md).

Bounded VM investigation metadata uses `NativeVmFindingPayload` from
`common/native_vm_finding.h` inside the existing event record. The record keeps
interpreter, guest program, invocation, host binding, hypothesis, and coverage
findings distinct. Guest bytes remain in the artifact channel and are linked by
artifact ID instead of being copied through the renderer queue.
`NativeVmDispatchSamplePayload` adds a fixed 128-byte dispatch-sample ABI.
`RecordVmDispatchSample` copies one caller-supplied observation into the probe
queue and admits at most 16 samples per capture configuration. Observations
past that budget, and samples whose emit is rejected before the queue, stay on
a counter. `PublishVmDispatchBudgetGap` writes one `vm`/`gap` record whose
decimal payload is the exact unreported count and whose artifact id is the
interpreter. A full probe queue still counts its own drops and returns the
budget slot so a later observation can be retained. The dispatch writer copies
the observation it is given and does not call `Debug::SetBreakPoint`. Opt-in
callers are the owned register interpreter and two captured-byte shapes.
`EnableOwnedRegisterSampling` arms `owned-register-v1`.
`EnableJavaScriptSwitchSampling` arms `javascript-switch-dispatch-v1`, which
`CaptureRuntimeTypedArray` runs on the checkpoint bytes before the artifact
size gate. `EnableWasmBrTableSampling` arms `wasm-br-table-dispatch-v1`.
Chromium patch `0016-sample-wasm-br-table-dispatch.patch` passes module bytes
to `ObserveCapturedWasmModule` before artifact capture is gated. Each shape
emits one invocation finding and then calls `RecordVmDispatchSample` for every
committed step. The 16-sample budget becomes one vm gap, a full probe queue
keeps its own drop count, and a 32-step walk that has not halted counts one
extra loss. Reconfigure clears every opt-in. Ignition, Liftoff, and TurboFan
are not sampled. A rebuilt browser still needs the Wasm patch applied and a
live page run before those program counters are browser evidence.
See the [capability boundary and acceptance gates](../../../../../../protocol/vm-opcode-workspace-v2.md#native-browser-capability-boundary).
The VM category also permits 32-byte through 16-MiB snapshots of runtime-created
`ArrayBuffer`, `Uint8Array`, `Uint16Array`, and `Uint32Array` data. The V8 hook
uses an embedder callback and never wraps JavaScript constructors. At most 16
snapshots are submitted per renderer and per browser session, then all bytes
use the existing bounded artifact transfer queue.

Native JavaScript dispatch observations (`js_dispatch_observation`, event 21)
use `common/native_js_dispatch.h` for the 128-byte payload and the fixed 44-byte
site records, and `common/native_js_dispatch_sites.h` for the browser-side
canonical site file. The renderer sink exposes a pulled epoch and an
allocation-free admission predicate to V8, never calls the frame-id provider on
that path, and claims one of 256 configuration samples and one of 64 site samples
before emitting through the ordinary ring. A full ring returns both claims and
keeps its drop count; budget, emitter, invalid-input and compiled-before-arming
refusals are coalesced gaps. See the
[contract](../../../../../../protocol/native-js-dispatch-v1.md).

Renderer code never writes files or sockets directly.

The dedicated-worker source foundation uses a separate, dormant process-wide
pool: four 2 MiB slots for one explicitly selected worker, allocated only on the
control path. Native compile hooks have no production activation caller yet;
CDP extraction remains unchanged. See the
[worker-source contract](../../../../../../protocol/native-worker-source-v1.md)
for encoding, sensitive approval, exact identity, loss reporting, unsupported
shared/service workers, and the missing browser/IPC/API acceptance gates.

The current event envelope does not yet carry a trustworthy origin identity,
so origin allowlisting is intentionally not inferred from bounded payload text.

### Network artifact creator identity

Accepted network-body artifacts emit `artifact_captured.parent_event_id` naming
the browser's actual `response_started` sequence, identical to the manifest's
`creator_event_id`. The artifact sink keeps its admission session and generation
across body completion and transfer acknowledgement. Reconfiguration, including
reactivation with the same numeric session ID, retires old callbacks; they cannot
enqueue late bodies or report an old ACK under the new session. Bytes already
enqueued are not retractable, so downstream exact linkage requires the retained
successful capture event as well as the manifest and response. Generated/runtime
artifacts never inherit this network parent relation.

`make native-artifact-capture-check` compiles the actual network/artifact sinks
against narrow platform/Mojo adapters, then uses the production receiver, event
broker and VM analyzer. This is component-pipeline evidence, not proof of Mojo
forwarding, Chromium compilation, or a matched-browser end-to-end run.
