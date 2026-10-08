# Brave Integration

This directory is the tracked source of truth for changes applied to Brave.
The large upstream checkout lives at `browser/worktree/src/brave` and remains
ignored by the parent repository. Project-wide authorization and capture policy
is in [SAFETY.md](../../../SAFETY.md); this guide describes the
browser integration's enforcement details.

## Native worker source foundation

The dormant dedicated-worker source foundation adds bounded native compile
observations for classic scripts and JavaScript modules. It has no production
activation or transport yet, and the working CDP worker extractor is unchanged.
Shared/service workers remain unsupported. See the
[status, privacy gates, identity contract, and release checklist](../../../protocol/native-worker-source-v1.md).

## Native worker metadata foundation

The separate dormant [metadata queue and projection](../../../protocol/native-worker-observation-v1.md)
models dedicated-worker lifecycle, compile identity and exact tagged direct-message
pairs without retaining message bodies. Patch 0011 adds disabled pinned Blink
observation points and carries a separate tag through direct in-process messages.
The dormant [authority and acknowledged transfer state machines](../../../protocol/native-worker-transfer-v1.md)
now define the document/partition lease and bounded batch contract. Service
observers, Mojo adapters, production controller, broker/UI adapter and activation
remain unimplemented.

## Native proxy-container foundation

The separate `proxy_policy` target provides dependency-free native policy and
group-intent validation. It is not linked to browser routing or enabled UI.
The separate `proxy_partition_adapter` target adds BrowserContext-owned,
one-shot snapshot restore and typed native proxy preparation. Successful
preparation still returns runtime-blocked; neither target is linked into routing.
Run `make native-proxy-policy-check` for offline policy/restore/group-transfer checks.
With an initialized, synchronized pinned Chromium checkout and generated build,
compile and run the native adapter suite from the Chromium source directory:

```sh
autoninja -C out/Component_arm64 brave/components/reverse_engineering_browser:proxy_partition_adapter_unittests
out/Component_arm64/proxy_partition_adapter_unittests
```

This suite evaluates native rules and parameter preparation without opening
network contexts or sockets. It is not ordinary repository CI or browser-level
transport/isolation coverage. See
[the v1 contract](../../../protocol/native-proxy-containers-v1.md) and
[pinned architecture](../../../docs/architecture/native-proxy-containers.md)
before adding a native network hook; ordinary groups do not isolate traffic.

## Native console

The disabled-by-default native console is a separate mutation path. Patch 0011
wires the browser session and per-frame renderer agent; the overlay owns their
Mojo contract and bounded local transport. It evaluates explicit commands in a
selected main-world context inside a disposable browser profile. It creates no
CDP endpoint and makes no undetectability guarantee. See
[Native Console v2](../../../protocol/native-console-v2.md) for ownership,
wire layouts, limits, and real-browser checks after rebuilding.
Eligible HTTP and HTTPS documents must belong to a profile directory immediately
inside the owned user-data root, including the fresh browser's `Default` profile.
The user-data root itself is not a BrowserContext profile path.

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
V8 counters deduplicate each native binding site after its first accepted
renderer-ring insertion in a capture configuration. A full renderer ring counts
the drop and leaves that site eligible on a later call after capacity returns.
Concurrent same-site callers make one bounded claim attempt; configuration
changes invalidate old claims even when a session ID is reused. This sampling
is per renderer process and native binding site, not per JavaScript call site,
document, or navigation. Renderer admission does not confirm downstream queue,
broker, or evidence-store delivery and does not guarantee complete coverage.
Lower-level Canvas, WebGL, and Web
Audio hooks cover selected internal Blink paths; generator exclusions prevent
double counting where those hooks overlap. The fingerprint category-mask bits
are `1`, `2`, `4`, `8`, `16`, `32`, `64`, and `2048`; calls already disabled or
expired at the sink return before sequence assignment. Transport admission
rechecks the generation, session, category, and expiration before ring insertion.

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

Embedder-requested debugger pauses retain V8's agent break reason. This lets
other attached inspector sessions recognize an XHR/fetch or DOM breakpoint
owned by a peer, rather than failing V8's debug assertion because they have no
local break details. The V8 patch includes
`debugger/reb-break-program-multiple-sessions` for the inspector test harness.
It changes pause attribution only; it does not suppress breakpoints or alter
capture policy.

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
