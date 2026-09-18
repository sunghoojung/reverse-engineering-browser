# Reverse Engineering Browser native probes

This component owns renderer-side and browser-side boundaries for native probe
events.

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
require explicit sensitive-capture authorization.

Bounded VM investigation metadata uses `NativeVmFindingPayload` from
`common/native_vm_finding.h` inside the existing event record. The record keeps
interpreter, guest program, invocation, host binding, hypothesis, and coverage
findings distinct. Guest bytes remain in the artifact channel and are linked by
artifact ID instead of being copied through the renderer queue.

Renderer code never writes files or sockets directly.

The current event envelope does not yet carry a trustworthy origin identity,
so origin allowlisting is intentionally not inferred from bounded payload text.
