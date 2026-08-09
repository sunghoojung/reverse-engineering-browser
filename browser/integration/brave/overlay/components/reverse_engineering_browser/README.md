# Reverse Engineering Browser native probes

This component is the renderer-side boundary for native probe events.

The first call site observes `HTMLCanvasElement::toDataURL` through Brave's
existing Chromium source override. The inactive path performs one atomic
emitter check and returns without allocating, blocking, or changing the Canvas
result.

An authorized renderer session will register a non-blocking emitter that copies
the fixed 128-byte record into its bounded transport. Until that transport is
registered, probes remain dormant and no events are produced.

The browser-process transport and session-scoped emitter registration are the
next integration layer. Renderer code must never write files or sockets
directly.
