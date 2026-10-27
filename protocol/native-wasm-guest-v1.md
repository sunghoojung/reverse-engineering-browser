# Native Wasm guest observations v1

This opt-in path captures actual Liftoff numeric locals and linear-memory bytes
inside Brave/V8. It does not use CDP, execute an emulator, or accept page-reported
PCs. A reviewed adapter interprets these observations; arbitrary interpreter
semantics cannot be inferred from a `br_table` selector alone.

## Enablement and supported target

Use a rebuilt browser containing the ordered V8/Chromium patches and overlay.
Set `REB_NATIVE_WASM_DISPATCH=1` and
`REB_NATIVE_WASM_GUEST_ADAPTER=/absolute/path/adapter.json` when launching a
native session. The category mask must include VM (512) and artifacts (1024);
include Canvas (1) for the public fixture's synchronous host probe.
The adapter is immutable for the browser lifetime, bounded to 8192 bytes, and
must exactly match canonical compact JSON (no trailing newline). See
[native-wasm-guest-adapter-v1.schema.json](native-wasm-guest-adapter-v1.schema.json).
Restart the browser to change it. Capture remains subject to session/category,
expiration, document, artifact authorization, and resource limits.

The pinned [public QuickJS fixture](../tools/quickjs-native-fixture/README.md)
provides a real, unmodified interpreter and a source/binary-verified mapping:
function 414, dispatch module offset 132727, opcode-address i32 local 320.
Bytecode base/length are bounded memory chains from local 10. The Rust verifier
checks the exact module digest and actual compiled fetch/selector/bounds pattern.
Other adapters are explicitly adapter-declared, not automatically verified ISA
recovery. This target establishes no hCaptcha-specific support.

## Capture and identity

Event 18 (`wasm_guest_dispatch`) and event 19 (`wasm_guest_invocation`) each have
128-byte version-1 little-endian payloads. Their authoritative offsets and
encoders are `include/reb/wasm_guest.hpp` and overlay
`common/native_wasm_guest_wire.h`; no native structure padding is serialized.
The event header retains the original renderer process/sequence identity.
Invocation events identify exact module, instance, activation and retained
adapter artifact. Dispatch events retain raw PC-local bits, checked signed
adjustment, resolved byte-offset PC, selector, separately decoded opcode,
bytecode artifact/range, and recipe SHA-256. Dispatch parent is its exact
invocation event. Wide identity, raw-bit, memory-base and adjustment JSON fields use canonical
decimal strings. The resolved PC is a bounded JSON integer (at most 65535).

Numeric local indices include parameters and are not limited to the first 32
locals. Compiler metadata and active-frame checks control access; reference
values and host addresses are never exposed. Memory snapshots reject shared
memory and out-of-bounds/overflowing ranges. A snapshot is at most 65536 bytes;
adapter sample limit is 1–256, with a 16 MiB aggregate bytecode-snapshot budget
(module and adapter artifacts are additional). The renderer retains
at most 128 distinct sampled activations per capture configuration; this can
stop coverage before the sample limit. Separately, the engine bounds its active
frame/instance bookkeeping. Resource exhaustion
fails closed rather than silently resetting a budget or inventing observations.

Module and adapter artifacts are acknowledged before publishing invocation
records; snapshots are acknowledged before dispatch records. Pending host
records retain original parent IDs and wait for that exact retained dispatch.
Rejection, navigation, expiry and bounded-queue loss clear the binding; they do
not retarget it to the last successful sample. Delayed IDs retract provisional
sequence holes in broker/Rust/JS/Swift summaries. Explicit drops remain drops.

## Host causality and limits

Configured direct import call offsets are validated against module code,
including helper functions. At a synchronous native host probe the actual Wasm
stack must contain the same instance and interpreter activation as the current
retained instruction. Reentry uses its own activation; returns, traps, exceptions
and new dispatch failures invalidate stale parents. An empty import list proves
no host association. Parent invocation token zero means nesting is not asserted.

Native host reports expose a semantic guest position only for the source-verified
dataflow binding; explicit adapters retain raw observations without upgrading
the declared PC mapping to proof. A direct host parent proves synchronous
execution position, not request-value
provenance. Async work, cross-process network causality, workers/documentless
contexts, unsupported tiers or mappings, and arbitrary guest ISA decoding are
not inferred. The old physical-dispatch event 17 remains distinct from guest
instruction observations.

## Validation status

Portable native admission/ACK tests, actual C++-encoded cross-language fixtures,
strict Rust artifact/site validation, and actual-script offline UI tests cover
contracts and rejection paths. Running the public interpreter normally proves
its fixture behavior only, not that the patched hook fired. Compiled V8 cctests
and a rebuilt Brave run retaining QuickJS guest records and synchronous Canvas
parents are separate required acceptance layers. Do not describe source replay,
mocked boundaries, or offline DOM tests as full browser runtime acceptance.
