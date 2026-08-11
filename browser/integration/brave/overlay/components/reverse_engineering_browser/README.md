# Reverse Engineering Browser native probes

This component owns renderer-side and browser-side boundaries for native probe
events.

The first call site observes `HTMLCanvasElement::toDataURL` through Brave's
existing Chromium source override. The inactive path performs one atomic
emitter check and returns without allocating, blocking, or changing the Canvas
result.

The renderer request hook records the request identifier immediately after
Chromium allocates it. The browser hook observes Brave's existing URL loader
factory and client proxies, preserving the request, initiator process, frame,
status, size, redirect, cache, and service-worker metadata needed to reconstruct
a lifecycle. While capture is enabled, the proxy resolves initiator process,
frame, and opaque BrowserContext identity on the first observed lifecycle event
and caches them for the request. This keeps completion correlated after
renderer exit, disambiguates profile-local Brave request IDs, and adds no work
to the inactive path.

An authorized session will register a non-blocking, non-throwing emitter that
copies the fixed 320-byte record into its bounded transport. Until that
transport is registered, probes remain dormant and no events are produced.
Payload capture is limited to a bounded metadata prefix. Network request
prefixes contain only the method and destination host. URL paths, queries,
fragments, bodies, credentials, authorization headers, and cookies are not
captured.

The browser-process transport and session-scoped emitter registration are the
next integration layer. Renderer code must never write files or sockets
directly.
