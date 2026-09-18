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
command verifies the tracked Brave, Chromium, and V8 pins, preflights all three
checkouts and every patch before copying overlays, is safe to run again, and
applies each patch only when needed. Revision mismatches fail with the current
and expected commits without changing any checkout.

The integration now observes renderer request initiation and the browser-side
request, redirect, response, completion, and failure lifecycle. It reuses
Brave's production `BraveProxyingURLLoaderFactory` and client proxy instead of
installing a second interception layer. The capture boundary records metadata
and a bounded payload prefix only. Request payload prefixes contain the method
and destination host, not URL paths, queries, fragments, or credentials.
Browser lifecycle records also carry the top-level `FrameTreeNodeId` as a
session-local tab identifier. This lets Origin Trace organize requests by tab
and destination domain without capturing tab titles or URL paths.
Browser lifecycle records also carry Chromium's opaque 128-bit BrowserContext
token, which disambiguates Brave request IDs generated independently per
profile without exposing a profile path.

All probes remain dormant until a session-scoped, non-blocking, non-throwing
emitter is registered. Their inactive paths perform one atomic load and do not
change browser behavior. Generated Blink Web IDL callbacks observe an explicit
90-interface allowlist across Canvas, WebGL, WebGPU, Web Audio, browser, layout,
font, media, Permissions, Storage, and WebRTC surfaces. Generic DOM interfaces
use member allowlists so routine rendering calls do not flood the evidence.
Selected V8 Math functions, Intl constructors, locale-sensitive formatting,
and timezone-offset reads emit Runtime operations through V8's existing
use-counter callback. Each event records a fixed property or operation name and
never retains arguments or return values. Generated non-Canvas callbacks and
V8 counters emit the first observation of each call site per capture session,
which preserves broad coverage during repetitive timing or Math loops.
Lower-level Canvas, WebGL, and Web
Audio hooks cover selected internal Blink paths; generator exclusions prevent
double counting where those hooks overlap. The fingerprint category-mask bits
are `1`, `2`, `4`, `8`, `16`, `32`, `64`, and `2048`; disabled or expired calls
return before sequence assignment.

The V8 Math allowlist follows the cross-engine functions exercised by
[CreepJS](https://github.com/abrahamjuliot/creepjs): `acos`, `acosh`, `asin`,
`asinh`, `atan`, `atan2`, `atanh`, `cbrt`, `cos`, `cosh`, `exp`, `expm1`,
`hypot`, `log`, `log1p`, `log10`, `pow`, `sin`, `sinh`, `sqrt`, `tan`, and
`tanh`. Origin Trace observes these named operations at their V8 builtin entry
points. It does not attempt to trace every JavaScript function or arithmetic
operator, which would add prohibitive volume and change the workload being
measured.

Canvas drawing metadata does not contain text, pixel data, or drawing
arguments. When `--reb-capture-canvas-images` is explicitly present for an
authorized session, the renderer may also submit the complete data URL returned
by `HTMLCanvasElement.toDataURL()`. That output is marked sensitive, linked to
the exact readback event, limited to 2 MiB, and sent through the separate
artifact channel. It is disabled by default and never enters the renderer event
ring.
Renderer events use a bounded shared-memory queue with Mojo lifecycle control
and coalesced wake-ups. The browser process
authenticates to the event broker with a session identifier and a mode-0600
token file, then sends exact fixed-size records over a Unix socket. A bounded
browser-process queue keeps those socket writes off the capture paths.
Both event queues hold 1,024 records. Full queues still drop rather than block
the renderer; a dropped gap report carries the number of source records it
represents into the next queue's drop counter. Queue-wide gap reports remain
unattributed because both queues can mix tabs and frames. Sequence discontinuities
and queue-drop reports may describe the same missing records and must not be
added together.

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
