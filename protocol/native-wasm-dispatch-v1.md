# Native Wasm dispatch observations v1

This path instruments Brave/V8 C++ directly. There is no CDP, JavaScript
injection, caller-fed sampler or fallback. It is partial work toward #327,
not arbitrary interpreter guest-PC recovery.

## Enablement

Rebuild Brave with all tracked V8, Chromium and overlay changes. With the native
live-session launcher, set `REB_NATIVE_WASM_DISPATCH=1` explicitly; VM and
artifact categories must both be enabled. Manual browser launches may use
`--js-flags=--reb-wasm-br-table-dispatch`. The flag alone does not authorize or
activate capture: the session must be active, connected and unexpired.

The diagnostic flag forces Liftoff-only compilation and disables native-module
cache reuse/deserialization. It is not a performance-neutral profiler. Only
executing `br_table` instructions in document contexts are supported; workers,
jitless execution and `call_indirect` are not implemented.

## Producer and identity

The compiler inserts a C++ builtin/runtime call before an executing `br_table`.
An allocation-free admission predicate runs before V8 frame lookup. The runtime
supplies the actual unsigned selector, function index, instruction byte offset
and explicit arm count. A module offset is a physical Wasm address, **not an
interpreter guest PC**, and a selector is not automatically a guest opcode.

Blink supplies exact document identity and native capture context. Renderer and
browser validate the session, generation, category, expiry and document token.
The browser captures the module through the artifact receiver and emits the
observation only after accepted ACK. Stale navigation/configuration callbacks
are rejected. This version captures one module artifact per observation, capped
at 16 observations per capture configuration and 16 MiB per module. Queue,
transport and budget losses are explicit incompleteness, never invented samples.

## Wire contract

Event type `wasm_dispatch_observation` (numeric17), category `vm`, protocol3.
The accepted artifact ID lives in the event envelope. Parent event and
navigation IDs remain zero rather than inventing causality. Runtime artifacts
use existing capture origin `unknown`; the typed event establishes provenance.

The payload is exactly128bytes, explicitly little-endian:

| Offset | Field | Type |
| --- | --- | --- |
|0|version (1)|u16|
|2|size (128)|u16|
|4|function index|u32|
|8|module instruction offset|u32|
|12|unsigned selector|u32|
|16|explicit table arm count|u32|
|20|sample index (0–15)|u32|
|24|reserved, all zero|104bytes|

Offsets start at8 and are below16MiB. Function index and count are below16MiB.
Any u32 selector is legal; selector>=count denotes the default arm. Scope IDs,
sequence and monotonic time are required; wide identities remain decimal strings.
Unknown versions, nonzero reserved bytes, malformed length/encoding and invalid
envelope flags are rejected consistently by C++, Rust and JavaScript.

## Reader and viewer

Rust verifies artifact digest and exact session/frame/artifact scope, then parses
the real module function/site/count before matching a selector to a static arm.
Imported function indices and multiple sites sharing a selector are distinct.
Native observations are separate from legacy guest-VM samples; no sentinel or
overloaded guest fields are used. The viewer labels guest PC unknown. Context
links can be correlated, but host-call causality and guest positions remain
unproven without genuine parent/invocation evidence.

## Validation boundary

`make check` includes actual C++ encoding → Rust verified artifact/workspace →
shipped JavaScript validation, including malformed and maximum-width goldens.
Portable native tests cover admission, expiry, masks, cap/drop, ACK and lifecycle.
These do not prove that a full Brave browser builds or the native V8 cctests run.
Before live acceptance, replay complete stacks on the pinned Brave-initialized
tree, compile the browser and run an owned two-selector Wasm fixture, including
navigation, disable/expiry and transport-loss cases. #327 remains open until its
remaining guest-PC/host-causality acceptance criteria are actually demonstrated.
