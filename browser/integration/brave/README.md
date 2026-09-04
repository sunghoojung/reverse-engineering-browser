# Brave Integration

This directory is the tracked source of truth for changes applied to Brave.
The large upstream checkout lives at `browser/worktree/src/brave` and remains
ignored by the parent repository.

## Layout

- `overlay/` contains complete authored files, mirroring their `brave-core`
  destination paths.
- `patches/` contains small edits to upstream-owned files.

Apply the tracked integration to the local checkout with:

```sh
./scripts/sync-browser-integration.sh
```

Initialize Chromium with `./scripts/bootstrap-brave.sh --init` first. The sync
command verifies the tracked Brave and Chromium pins, preflights both checkouts
and every patch before copying overlays, is safe to run again, and applies each
patch only when needed. Revision mismatches fail with the current and expected
commits without changing either checkout.

The integration now observes renderer request initiation and the browser-side
request, redirect, response, completion, and failure lifecycle. It reuses
Brave's production `BraveProxyingURLLoaderFactory` and client proxy instead of
installing a second interception layer. The capture boundary records metadata
and a bounded payload prefix only. Request payload prefixes contain the method
and destination host, not URL paths, queries, fragments, or credentials.
Browser lifecycle records also carry Chromium's opaque 128-bit BrowserContext
token, which disambiguates Brave request IDs generated independently per
profile without exposing a profile path.

All probes remain dormant until a session-scoped, non-blocking, non-throwing
emitter is registered. Their inactive paths perform one atomic load and do not
change network, Canvas, or Web Audio behavior. The Web Audio probe records only
fixed operation names for selected graph construction, connection, rendering,
and readback calls. It never copies audio samples or rendered buffers. Web Audio
uses category-mask bit `4`; the renderer sink rejects the call before assigning
a sequence number when that bit is disabled or the session has expired.
Renderer events use a bounded shared-memory queue with Mojo lifecycle control
and coalesced wake-ups. The browser process
authenticates to the event broker with a session identifier and a mode-0600
token file, then sends exact fixed-size records over a Unix socket. A bounded
browser-process queue keeps those socket writes off the capture paths.

Native quiet mode is an explicit launch-time option. Its Chromium patch adds a
disabled-by-default V8 flag that returns from the shared debugger-statement
runtime handler before Inspector pause handling. Because compiled `debugger;`
statements from normal scripts, `eval`, functions, frames, and workers all use
that V8 handler, the rule does not depend on source rewriting or CDP. The live
launcher also omits the remote-debugging endpoint in this mode. Ordinary V8
behavior remains unchanged unless the session passes
`--js-flags=--reb-ignore-debugger-statements`.

When the Artifact category is authorized, the browser process recognizes
JavaScript and WebAssembly responses, removes URL credentials, queries, and
fragments from stored metadata, and asynchronously tees at most 16 MiB per
response. The original response pipe remains the page's source of bytes. A
separate queue permits at most 16 pending artifacts and 32 MiB of queued
content, then transfers frames over an authenticated user-only socket. Brave
emits `artifact_captured` only after a durable receiver acknowledgment and
emits `artifact_capture_failed` for limits, incomplete bodies, queue pressure,
disconnects, and receiver rejection.

The same category enables runtime-generated source capture. Blink submits only
accepted dynamic JavaScript, and V8 exposes copied byte buffers used by
`WebAssembly.compile`, `WebAssembly.Module`, and `WebAssembly.instantiate`.
Renderer hooks perform one inactive atomic check, cap each submission at 16
MiB, and send bytes one way to the browser process. The browser copies shared
memory before validation, sanitizes the context URL, assigns the artifact ID,
and remains the only process that owns the authenticated artifact socket.
