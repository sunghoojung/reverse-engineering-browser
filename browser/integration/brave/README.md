# Brave Integration

This directory is the tracked source of truth for changes applied to Brave.
The large upstream checkout lives at `browser/worktree/src/brave` and remains
ignored by the parent repository. Project-wide authorization and capture policy
is in [SAFETY.md](../../../SAFETY.md); this guide describes the
browser integration's enforcement details.

## Research build without bundled consumer services

Patch 0014 disables Brave Talk, Wallet, News, Rewards, Leo AI and both VPN
architectures at build time using the pinned upstream's existing feature flags.
The related VPN panels/helpers and Leo agent/tab-management features follow their
parent flags. These are build defaults, not profile preferences or runtime UI
hiding. A generated `args.gn` can still override a default. The integrated
build rejects that file when any of the seven flags is `true` unless it also
sets `reb_enable_bundled_brave_services = true`. That marker is accepted only
when at least one of those seven flags is `true`. Talk, Wallet, VPN, Leo,
Rewards, and News remain
in a browser that was already built; they leave the running UI only after a
rebuild from these defaults.

This does not remove all Brave/Chromium network traffic or provide an
Ungoogled-Chromium privacy guarantee. Shields, browser security updates, Safe
Browsing, ordinary browsing and the REB observation controls are unchanged.
Existing installed browsers are unchanged until rebuilt. No profile data,
wallet, subscription or account is deleted or modified.

`python3 tools/check-brave-services.py` checks the tracked patch contract and
the args.gn samples. The integrated build also runs
`python3 tools/check-brave-services.py --args out/Component_arm64/args.gn`
after preparation creates that file. To evaluate the patched sources after
synchronizing the pinned Brave checkout, run
`python3 tools/check-brave-services.py --brave browser/worktree/src/brave --gn /path/to/gn`
to evaluate the actual patched GN files across desktop/mobile and
production/development and branding combinations. This uses minimal platform/branding stubs;
it does not replace a full Chromium build or the native runtime acceptance gate.

## Early native network capture

The source candidate now activates the existing opt-in transport before profile
startup and snapshots owned-profile request admission before Shields decisions.
It records bounded lifecycle metadata and explicit incomplete teardown/handoff
observations. See [the startup contract and coverage matrix](../../../protocol/native-network-startup-v1.md)
for unsupported SW-synthetic/renderer-memory-cache paths and the required patched
browser build/runtime acceptance. Source/component checks do not prove complete
initial traffic capture.

## Native worker source foundation

The dormant dedicated-worker source foundation adds bounded native compile
observations for classic scripts and JavaScript modules. It has no production
activation or transport yet, and worker extraction has no CDP fallback.
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
selected main-world context. A disposable profile is the default. An explicit
live-capture binding evaluates in a document the capture browser is already
showing, keeps remote debugging, and does not exit that browser when the
channel drops. It still cannot set breakpoints, step, or inspect paused frames.
It creates no CDP endpoint and makes no undetectability guarantee. See
[Native Console v2](../../../protocol/native-console-v2.md) for ownership,
wire layouts, limits, and real-browser checks after rebuilding.
Eligible HTTP and HTTPS documents must belong to a profile directory immediately
inside the owned user-data root, including the fresh browser's `Default` profile.
The user-data root itself is not a BrowserContext profile path.
The explicit disposable root is resolved at startup to match Chromium's
canonical profile paths, including macOS `/tmp` and `/var` aliases. An invalid
root stays ineligible rather than admitting a fallback browser profile.

## Layout

- `overlay/` contains complete authored files, mirroring their `brave-core`
  destination paths.
- `patches/` contains small edits to upstream-owned files.

Keep V8 edits in `patches/v8/`, relative to the independent V8 checkout.
The synchronization script rejects destinations belonging to a nested Git
checkout before changing any stack. Its temporary-index replay includes added
patch files, so overlapping patches can be recognized without rewriting the
working tree or real index on repeated builds.

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
Both event queues hold 8,192 records. Full queues still drop rather than block
the renderer; a dropped gap report carries the number of source records it
represents into the next queue's drop counter. Queue-wide gap reports remain
unattributed because both queues can mix tabs and frames. Sequence discontinuities
and queue-drop reports may describe the same missing records and must not be
added together.

Native quiet mode is an explicit launch-time option. Its V8 patch adds a
disabled-by-default V8 flag that returns from the shared debugger-statement
runtime handler before Inspector pause handling. Because compiled `debugger;`
statements from normal scripts, `eval`, functions, frames, and workers all use
that V8 handler, the rule does not depend on source rewriting or CDP. The live
launcher also omits the remote-debugging endpoint in this mode. Ordinary V8
behavior remains unchanged unless the session passes
`--js-flags=--reb-ignore-debugger-statements`.
For inspector-detecting JavaScript VMs, launch with
`REB_NATIVE_QUIET_MODE=1` and authorize the VM category. This path does not
start the V8 debug agent, enable `Runtime` or `Debugger`, or call
`Debug::SetBreakPoint`. It therefore avoids the `Runtime.enable` signal watched
by obfuscator.io `vmDebugProtection.inspectorDetection`.

Embedder-requested debugger pauses retain V8's agent break reason. This lets
other attached inspector sessions recognize an XHR/fetch or DOM breakpoint
owned by a peer, rather than failing V8's debug assertion because they have no
local break details. The V8 patch includes
`debugger/reb-break-program-multiple-sessions` for the inspector test harness.
It changes pause attribution only; it does not suppress breakpoints or alter
capture policy.

When the Artifact category is authorized, the browser process recognizes
JavaScript and WebAssembly responses, preserves the observed source URL
(including credentials, queries and fragments) in local artifact metadata, and
asynchronously tees at most 16 MiB per response. The original response pipe remains the page's source of bytes. A
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
memory before validation, preserves the bounded context URL, assigns the artifact ID,
and remains the only process that owns the authenticated artifact socket.

The VM category separately enables runtime-buffer snapshots for `ArrayBuffer`,
`Uint8Array`, `Uint16Array`, and `Uint32Array` constructor results. V8 invokes
an embedder callback after initialization; no JavaScript constructor or host
builtin is wrapped. Buffers from 32 bytes through 16 MiB are copied into
`bytecode_buffer` artifacts, with at most 16 snapshots per session sharing the
existing 16-artifact, 32-MiB transfer queue.

Runtime snapshots now carry exact allocating-script provenance. After the VM
capture gate, V8 exposes the innermost JavaScript frame's native script identity,
source and script URL without enabling Inspector. Source is copied once per
execution-context/script identity and configuration (at most 16 entries per
renderer sequence). The browser scopes that identity by renderer, execution
context and frame, assigns a `runtime_allocating_script` JavaScript artifact,
and writes its ID into the buffer's `parent_artifact_id`. No document-URL or
likely-VM guessing is involved. A missing source/URL or exhausted registry emits
an explicit capture failure. Network source artifacts remain independent.

The exact-script source and buffer share the existing bounded artifact queue;
a failed source transfer can therefore leave an unresolved parent. VM Lab keeps
that snapshot unjoined and describes runtime snapshot unavailability. This is
capture evidence, not a guarantee that every allocation or script was retained.

Native generated artifacts still report unknown navigation ID `0`; this change
adds no browser navigation-identity provider. The allocating source and buffer
share that value. Execution-context tokens change on document replacement and
are part of both renderer cache and browser registry keys, preventing a reused
V8 script ID or frame token from selecting a previous document's source. Offline
nonzero-navigation mismatch tests verify the workspace join contract, not a
live navigation-ID producer.


### Runtime byte-buffer admission

The renderer keeps a buffer only when its exact allocating script has a trusted
captured `candidate`/`likely-vm` observation, is captured eval/Function source, or
has a static dispatch-loop observation and the buffer is at least 256 bytes.
The independent 32-byte floor, 16-snapshot session cap, and VM opt-in remain.
Rejected unrelated allocations do not consume the cap. Their
`runtime_buffer_no_vm_signal` reason is coalesced once per configuration/thread;
a full event ring does not mark the reason sent, so later rejections can retry. Source metadata drops
credentials, query strings and fragments. Only hierarchical HTTP, HTTPS and
owned-fixture URLs are supported; opaque, scheme-relative and other schemes
fail closed. Missing/unsafe URLs produce
`allocating_script_url_unavailable` rather than a document-URL guess.

`RegisterRuntimeScriptObservation` is a bounded (64 entries), thread-local native
integration seam keyed by configuration generation, execution context and V8
script ID. Callers must retain the observation-time generation and register only
trusted detector outputs for that exact captured source. A URL or a large buffer
is never classification evidence. Stale observations and context mismatches fail
closed. Native V8 eval/Function provenance remains a keep-list row. When the
allocating script's source is copied, the renderer classifies that source on
the same thread before the keep-list read: a non-executing scan of at most
256 KiB and 256 functions, using the offline detector's structural weights
(dispatch-loop 20, instruction pointer 20, indexed bytecode 20, state 15,
handlers 15, exit 5). Only the winning function region sets flags. A dispatch
loop scores 20, so it is a candidate and is admitted from 32 bytes; likely-VM
still requires that same region to contain the dispatch loop, at least 60
points, and at least 3 rule families. The URL and the buffer length are not
classification evidence. An unterminated function in a fully visible source,
or more than 256 functions, fails closed. Source past the 256 KiB prefix is
not classified. Anti-bot lexical rules stay offline and do not admit buffers.
The scanner uses bounded spans and fixed arrays over one checked allocation;
token lengths come from string views, including `instructionPointer`. Allocation
failure still declines classification. The registration API is not page-facing.

The forward masking lexer retains operand and delimiter context while removing
comments, quoted/template strings and regex literals. This distinguishes division
after a literal or function expression from a regex after an operator, control
condition or statement block. It is still a bounded heuristic, not a JavaScript
parser; template interpolation is not classified independently.

The 64-entry observation cache pins positive signals and rotates negative entries,
so the first 64 ordinary allocating scripts do not starve a later VM. A retained
entry is never rescanned. Evicted negatives may be reconsidered, but all source
conversion/scan attempts, including failed conversions and allocation failures,
share a 256-attempt budget per configuration generation and renderer thread.
Each prefix is at most 256 KiB. Prefix conversion uses the constant-time UTF-16
length and V8's processed-character count rather than a full-source UTF-8 length
walk; truncation stays explicit even at a multibyte boundary. Cache and budget
reset on configuration replacement, even for the same
session ID. A full positive table or exhausted budget reports
`runtime_script_classification_limit`; unavailable classification reports
`runtime_script_classification_unavailable`, never a false no-VM conclusion.
These omissions are separately coalesced and retried after ring rejection.
The 16-snapshot cap is unchanged. Rejected creator metadata produces no runtime
artifact and consumes neither snapshot quota nor an allocating-source cache slot.
Snapshot reservations are owned by monotonically increasing generations, so a
stale capture cannot consume or release a replacement configuration's quota.
Generation checks reject stale work at admission boundaries, including after
emitter callbacks; they do not wait for already-admitted in-flight transfers.



### Runtime buffer task-checkpoint timing

Runtime constructors now enqueue safe V8 object/source/context handles instead
of copying zero-filled allocation bytes. A posted native task samples eligible
buffers after the current JavaScript turn, including synchronous indexed stores,
`set`, `fill` and DataView writes. The event is named
`runtime_typed_array_task_checkpoint_snapshot`: this is a bounded checkpoint,
**not proof initialization finished**. Later-task initialization may occur after
it, and no arbitrary write/guest tracing or page API wrappers are installed.
The allocator identity is captured at allocation and survives writes by another
script. The currently executing mutator never becomes the source parent.

Pending storage is separately capped at 16 objects and 32 MiB including whole
backing-buffer lengths and source UTF-8 sizes (a tiny view cannot retain a giant
backing buffer). Rejected pending entries name `runtime_buffer_checkpoint_limit`.
Disable, expiry or generation changes stop the drain before retained handle
access or byte copying. Context destruction, detach, shared/resizable backing,
and changed lengths fail closed at the checkpoint with named omissions. Isolate
teardown releases V8 globals before disposal; a surviving weak posted task sees
a null isolate. A missing task/checkpoint before teardown is explicitly
`runtime_buffer_checkpoint_unavailable`. No persisted allocation bytes are
claimed for that case. VM-off retains no handles and performs no byte copy.

The compiled component test exercises the actual bounded native queue and sink
with an owned buffer, allocator A/mutator B, session changes, detach rejection
and teardown. `tests/fixtures/runtime-buffer-checkpoint.html` is the owned browser
runtime regression for indexed/set/DataView initialization and cross-script
identity. It requires a rebuilt patched browser; component tests and pinned
patch applicability do not substitute for running that fixture in Chromium.

For a one-file patch compatibility repair in a recorded initialized checkout,
use the guarded `advance-patch` procedure in
[the integrated build guide](../../../docs/development/integrated-brave-build.md).
It preflights the complete old/new ordered stack and preserves source receipts,
backups and real index entries; do not hand-edit the generated checkout. The
runtime buffer callback obtains its isolate from Blink's execution context,
which is supported at the pinned V8 revision; a missing context emits the
existing omission reason.

## Native Wasm dispatch (opt-in)

Rebuilt browsers can record physical `br_table` operands with
`REB_NATIVE_WASM_DISPATCH=1` through the native launcher, or manually with
`--js-flags=--reb-wasm-br-table-dispatch`. This is Liftoff-only instrumentation,
not arbitrary interpreter guest-PC recovery. See
[wire contract and verification limits](../../../protocol/native-wasm-dispatch-v1.md).

Guest-state capture additionally needs `REB_NATIVE_WASM_GUEST_ADAPTER`, which
makes the launcher add `--reb-wasm-guest-capture`. That flag compiles a call on
every Wasm function entry (frame identity) and numeric-local descriptors for
each `br_table`; without it, physical dispatch observation alone pays neither
cost. See [native guest observations](../../../protocol/native-wasm-guest-v1.md).
All CDP capture/transport functionality has been removed from the companion.
