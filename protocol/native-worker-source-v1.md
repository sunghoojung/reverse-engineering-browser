# Native dedicated-worker source foundation v1

## Implementation status and scope

This is a dormant renderer-side foundation, not a completed native extractor.
There is no production configuration caller, IPC transport, browser worker
authorization controller, artifact adapter, or UI/API cutover. The existing
CDP worker list and `Debugger.getScriptSource` path remain unchanged.

The pinned hooks observe successful classic-script and JavaScript-module
compilation in a dedicated-worker execution context. They cover the common
compile boundaries used by the entry script, `importScripts`, and module
dependencies, including streaming/cache branches. A compile observation does
not prove that a module was instantiated or evaluated. Parse failures produce
no source record. Actual browser coverage remains unverified until the pinned
browser builds and the acceptance matrix below passes.

Shared workers and service workers explicitly return `kUnsupportedWorker`.
Worklets and document contexts are not captured. Worker `eval`/`Function`, V8
script IDs, source-map retrieval, function breakpoints, value/closure capture,
network interception, and Ghostwire's runtime discovery are outside this first
slice. The existing generated-source artifact hooks are a different path; this
foundation does not claim to migrate or complete them.

The reference is [Ghostwire's worker example](https://github.com/sofianeelhor/ghostwire/tree/c3377f8be59fc2b2f2a620bbae75714902b0c114/examples/obfuscated_app),
used as research only. This work installs no Ghostwire code, injects no page
script, starts no debugger endpoint, changes no JavaScript result, and makes no
stealth or undetectability promise.

## Authority, identity, and ownership

The queue starts disabled and allocates no payload pool until its control-path
`Configure` receives a complete policy. Configuration requires:

- A nonzero session ID and strictly increasing nonzero generation
- A future monotonic expiration
- Full nonzero 128-bit browser-context, renderer-incarnation, and exact
  dedicated-worker tokens
- An explicit sensitive-source approval flag, false by default

Only a future browser-owned controller may supply a production policy after
proving that the exact worker belongs to the selected disposable experiment.
A renderer PID, URL, category mask, tab guess, or another worker with a matching
low token half is insufficient. The renderer-incarnation token must be new on
restart; a reused OS PID cannot identify a source. Configure and Disable belong
to one serialized control sequence. The public C++ test interface does not
itself authenticate its caller and is not a security boundary against a
compromised renderer.

`Begin` gives a generation-bound ticket before source processing. Capture
rechecks it under the queue lock and after copying. Old tickets cannot silently
submit source into a replacement session, even if the worker token is unchanged.
At Chromium `151.0.7922.108`, `DedicatedWorkerGlobalScope` returns its dedicated
worker token as its execution-context token; all 128 bits are preserved. The
parent context token is an observation hint only. No frame, tab, navigation,
browser ownership, or causal edge is inferred from it.

A local source observation is identified by browser context, renderer
incarnation, session, generation, full worker token, and sequence. Neither a URL
nor a V8 script number substitutes for this tuple. Capture order is local to
this process; it is not a cross-process causal clock.

The 144-byte `NativeWorkerSourceHeader` in `common/native_worker_source.h` is a
versioned **local queue ABI**, not an existing artifact v1 or socket record.
Its size and important offsets are checked at compile time. Do not reinterpret
it as `NativeArtifactHeader` or repurpose the latter's reserved bytes.

Before future publication, the browser must independently verify context and
worker ownership, copy untrusted renderer bytes, validate the header and exact
UTF-8 sizes, hash the complete source with SHA-256, and assign the normalized
artifact identity. SHA-256 is deliberately not claimed or fabricated by this
foundation. Preserve the full source identity tuple beside that digest: equal
content does not imply equal worker, context, session, or capture observation.
The existing normalized protocol and evidence-store owners remain authoritative.

## Bounds, encoding, and privacy

The control path allocates four fixed slots, each holding at most 2 MiB of
UTF-8 source and 8,192 bytes of URL metadata. The pool is approximately 8 MiB
plus URL/header storage per explicitly configured renderer. It remains allocated
for reuse until destruction, but used payload bytes are cleared on dequeue,
disable, reconfiguration, and successful retirement cleanup.

Capture uses only borrowed Latin-1 or UTF-16 spans. It does not retain Blink
objects, V8 handles, callback pointers, or source views. Latin-1 is encoded as
UTF-8, not reinterpreted as UTF-8. Valid surrogate pairs are preserved; unpaired
surrogates are explicitly rejected rather than silently replaced. Empty
JavaScript is valid. Input and output lengths are checked before bounded
encoding, and a source is complete or rejected, never truncated into a
supposedly complete artifact. The API/UI consumer must label the resulting
encoding as UTF-8 source text, not original network response bytes.

Sources that are eligible for parking report an explicit unavailable-source gap;
the hook never calls their potentially locking, decompressing or disk-reading
`ToString()` path. Non-parkable strings are borrowed synchronously. This is a
deliberate coverage limit rather than permission to block a worker on storage.

Source bytes can contain secrets or personal content, so every accepted header
is sensitive. No source is copied without the explicit per-session gate and
exact-worker match. HTTP(S) URL metadata removes credentials, queries, and
fragments before insertion. Opaque/blob/data/file/custom URLs are omitted with
`kOpaqueOmitted`. Encoding/size/control-character failures, missing hosts,
malformed bracket structure, and malformed or out-of-range explicit ports use
`kInvalidOmitted`. Missing URLs use `kAbsent`.

The allocation-free authority check admits only nonempty ASCII letter/digit/hyphen
labels of at most 63 characters, without leading/trailing hyphens, separated by
dots. A single trailing dot is allowed; the name before it is at most 253 bytes.
Optional ports must contain decimal digits and have a value from 0 through
65535. Bracketed authorities (including valid IPv6) and other host forms outside
this subset use `kUnsupportedAuthorityOmitted`. No IPv6, IDNA, percent-decoded
host, numeric-address interpretation, DNS lookup, or complete WHATWG URL parser
is implemented here. `kSanitized` means the retained metadata was redacted and
passed this narrow admission grammar; it does **not** assert URL validity,
canonicalization, origin identity, or target authorization. In particular,
numeric-looking names are not validated as IP addresses. The future browser
adapter must use the browser's canonical URL parser and independently verify
ownership before persistence/publication.

An omitted URL is not reconstructed from a page URL or guessed from a source
hash. HTTP(S) paths remain potentially sensitive and belong to the
same explicitly approved source capture. No automatic execution, persistence,
export, telemetry, file write, or socket occurs here.

The inactive hook checks one atomic generation before source conversion or token
work. Active probes use `try_lock`, never wait for a lock, allocate, spin for
queue capacity, perform I/O, or invoke JavaScript. Work is bounded by the fixed
source and URL limits. Configure/Disable may wait on the control path; they are
not probe operations. The future transport must reserve bounded downstream
credits before copying or posting Mojo messages, and keep those credits until
acknowledgment. Popping this local queue alone is not downstream backpressure.

## Gaps and lifecycle

`attempted`, `dropped`, `retired`, `stale`, and `contended` are saturating,
process-lifetime counters. `queued` and `pending_gap` describe the current
policy. Successful records carry the local attempted sequence and the number
of rejected source attempts since the previous accepted record. Queue-full,
malformed source, and oversized source failures count as drops. Contention is
reported separately and remains unattributed because it can race a policy
change. It is not silently included in a later worker's gap.

Expiration, disabled capture, unsupported worker kinds, and wrong-worker
attempts do not consume a source sequence. Stale tickets have an explicit
status and counter. Discarded queued records count as `retired`. Reconfiguration
clears pending per-generation gaps without erasing aggregate drop totals.
Sequence gaps, `dropped_before`, and aggregate drop counters overlap and must
not be added together. A final status read is necessary even if no later source
arrives to carry a gap.

The dedicated-worker `Dispose` hook atomically revokes only the matching current
generation. It never revokes a newer generation based on a stale snapshot. If
the queue is busy, revocation still happens immediately; storage cleanup is
deferred until control-path disable/reconfiguration/destruction. Dequeue refuses
revoked/expired data, and a retirement racing its bounded copy clears the output
and returns a stale status. A future browser adapter must revalidate again
before publication to handle retirement after dequeue's final check.

The future controller must revoke capture on navigation, experiment disposal,
renderer exit, worker termination, IPC disconnect, session expiry, and browser
restart. Shared/service-worker lifetimes must never be inferred from a page
navigation. Native list/read/retirement state, terminal drop reporting, and
bounded acknowledged transport are blockers to production activation.

## Validation and release gates

`make demo && build/reb-event-demo` exercises the actual dependency-free queue:
disabled and denied policies; exact token matching; unsupported worker kinds;
Latin-1/UTF-16 encoding; URL redaction/omission; empty/malformed/oversized source;
authority admission and unsupported-host distinctions, including the reported
empty-host, unmatched-bracket and out-of-range-port regressions;
the 2 MiB boundary; output buffer limits; queue overflow and recovery; stale
generations; retirement; expiration; and concurrent capture/dequeue accounting.
These are protocol/foundation tests, not browser acceptance.

Chromium patch `0010-observe-dedicated-worker-sources.patch` targets these exact
files at `151.0.7922.108`:

- `third_party/blink/renderer/bindings/core/v8/v8_script_runner.cc`, Git blob
  `ecb68ce4e23d76b82da09ffb4ee60619a9a35462`
- `third_party/blink/renderer/core/workers/worker_global_scope.cc`, Git blob
  `d7453149e4ac065f481f4197df6a25a8178e84a7`

The patch was forward/reverse preflighted against byte-verified downloads of
these pinned files. No earlier tracked patch touches them. This proves only
this patch's source-context applicability, not the full synchronization stack,
GN dependency correctness, native compilation, or runtime behavior. Apply the
complete integration only through `scripts/sync-browser-integration.sh` in a
clean, correctly pinned initialized checkout.

Before activation or CDP replacement:

1. Run the complete pinned Brave/Chromium/V8 synchronization and GN checks.
   Compile the renderer sink, `v8_script_runner.o`, `worker_global_scope.o`, and
   full browser; these objects are included in `brave-probe-check`.
2. Implement browser-authoritative exact-worker selection and generation-bound,
   acknowledged, bounded IPC with terminal gaps and explicit sensitive approval.
3. Implement normalized artifacts/source identity, full-content hashing, source
   list/read and stale-selection semantics without weakening the existing API.
4. Test owned localhost classic, module, imported, nested, blob, empty,
   short-lived and restarted dedicated workers; identical URLs with different
   source bytes; identical source bytes in different workers/contexts; Unicode
   and invalid encoding; parse/CSP failures; caches and streaming compilation.
5. Test disabled capture, wrong/baseline contexts, consent absent, expiry,
   queue/IPC pressure, disconnect, navigation, termination, process reuse and
   restart. Require explicit unsupported results for shared/service workers and
   unavailable coverage for unimplemented eval/Function capture.
6. Compare the visible source list/read behavior against the current CDP route.
   Do not remove that working route until genuine native parity is demonstrated.

On the implementation host, no initialized `browser/worktree/src/brave` exists.
`make brave-doctor`, `make brave-probe-check`, and sync stop at that missing
checkout. GN, Xcode, Rust/Cargo, and clang-format are also absent, and the roughly
29 GiB available disk is below the documented 150 GiB initialization minimum.
No browser build, browser runtime acceptance, UI cutover, or complete native
migration is claimed.
