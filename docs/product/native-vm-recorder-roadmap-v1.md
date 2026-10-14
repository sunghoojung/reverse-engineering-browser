# Native cooperative VM recording: integration roadmap

## Scope and evidence

This milestone records an **owned, cooperative fixture interpreter** in native
C++. It is a recorder foundation, not an active Brave guest-VM tracer. It does
not recover a target site's instruction decoder or keys, recognize arbitrary
virtualization products, hide inspector presence, or establish undetectability.
PR171's imported VM traces remain imported evidence; a native implementation
must earn a separate provenance label through the acceptance checks below.

A recorder can change timing, allocation and scheduling even when program outputs
match. Differential tests support only the listed fixture programs and inputs;
they do not prove observational equivalence for arbitrary web programs.

## Verified existing extension points

All paths below are relative to
`browser/integration/brave/overlay/components/reverse_engineering_browser/`.

- `renderer/native_console_agent.{h,cc}`: frame-associated commands check an
  exact document token and monotonic expiration before running. Context release
  resets retained runtime state. A future recording control must preserve these
  checks and revoke its recorder on context release/navigation, disable and
  expiry. A previous document must never start recording in its replacement.
- `common/native_console.mojom`: current methods are Describe, Runtime and
  Evaluate. There is **no** trace control/stream method today. Add a typed,
  versioned control interface rather than tunnelling arbitrary trace bytes into
  evaluation source or extending an enum without updating every consumer.
- `renderer/native_console_runtime.{h,cc}`: retains bounded V8 values and offers
  explicit runtime commands. It is not an instruction interpreter. A later
  owned-fixture adapter may copy validated primitive fixture state at its
  explicit callback; do not enumerate arbitrary objects or invoke getters to
  fabricate a snapshot.
- `renderer/native_probe_sink.{h,cc}`: serialized configuration, generation
  claims, expiration and nonblocking ring admission. Successful admission is
  not delivery. Rich snapshots do not belong in the fixed event ring; emit a
  bounded reference/summary only after designing an explicit record contract.
- `browser/native_artifact_capture_sink.{h,cc}`: bounded reservation and transfer
  completion for JavaScript/Wasm source artifacts. VM traces need a distinct
  artifact kind and validators across every boundary before reusing this path;
  do not label trace JSON as JavaScript to bypass existing type checks.

These extension points are active infrastructure, but the proposed adapter is
not present. Dedicated-worker observation foundations are a separate dormant
path and do not confer worker VM tracing support.

## Smallest useful sequence

1. **Native recorder foundation (this candidate):** bounded typed C++ records,
   explicit session/document/generation/expiry admission, source sequence and
   retained count, losses and unknown state. Cooperative stack/register fixtures
   call the recorder at dispatch boundaries. Compare traced and untraced output,
   final state and independently specified instruction semantics. Keep native
   compilation and deterministic fixtures available without a Chromium build.
2. **Owned-fixture Brave adapter:** a separate opt-in command selects a compiled
   fixture identifier and fixed input, never arbitrary target code. Bind control
   to exact frame/document and expiry. Feed copied primitive step data to the
   recorder from the owned fixture's explicit callback. Verify live document
   replacement, disable, stale generation, deadline and backpressure behavior.
   No page-wide mutation, debug endpoint concealment, or implicit activation.
3. **Evidence and existing VM view:** version the typed transport and trace
   artifact contract; validate lengths before allocation on both sides; retain
   immutable source/program hash, fixture revision, capture backend and build
   identity, document/session/epoch and run identity. Preserve the native
   canonical contract: its unsigned 64-bit values, PC range, explicit effects,
   evidence classes and loss counters are not losslessly representable by the
   imported reb-vm-trace-v1 int32/16-bit-PC snapshot contract. Add a versioned
   native view, or a checked partial projection with every rejected/omitted
   field disclosed; never cast, truncate or silently discard evidence. Expose
   inspect/step/validate through matching agent-accessible offline commands.
   A retained artifact receipt, not ring admission, establishes delivery.
   Imported backend labels such as native never authenticate a capture.

Each slice needs separate review and can be a separate PR. No browser acceptance
claim is made until the adapter and live tests exist.

## Trace contract requirements

Record opcode and instruction position using a declared PC unit. Operand reads,
register/stack/memory reads and writes must identify the recorder's direct
cooperative observation or remain unknown. A changed snapshot alone establishes
a changed value, not the read set or causal operation. A cooperative fixture
reports its own operation; inference and semantic validation are separate facts.
Use scalar typed cells and bounded sparse memory, never host addresses, V8
handles, secrets inferred from unrelated objects or raw heap dumps.

Every trace carries initial-state coverage, before/after state coverage,
sequence, capture configuration identity, loss reasons and truncation. Invalid,
expired, stale, disabled and capacity-limited admissions must be distinguishable.
Missing records break continuity and cannot support a complete-path claim.
Source sequence gaps and downstream loss counts may overlap; do not add them
without a documented relationship. Counters saturate rather than wrap.

## Acceptance matrix (full staged target, not a completed checklist)

The current native fixture covers constants 7/5, addition to 12, guest memory
address 16, taken/untaken branches, jump and halt, structural malformed inputs,
generation/document/expiry refusal and capacity loss. Counter saturation is
checked at the increment primitive boundary, not by executing 2^64 calls.
Broader operand cases, transport and browser acceptance below remain future
work. Scope admission is recorder-local generation plus document identity;
the core does not authenticate a browser session or Chromium document token.

- Stack and register fixtures: arithmetic, constants, loads/stores, taken and
  untaken branches, jumps and halt; fixed edge operands and invalid operands.
- Traced versus untraced runs: exact output, final PC, register/stack/memory and
  termination reason, using independent expected results for opcode effects.
- Unknown cells and unsupported instructions remain explicit; no synthesized
  values or invented byte offsets. Repeated and contradictory opcode effects
  remain inspectable rather than forced into one meaning.
- Recorder disabled, expired and revoked; wrong document/session/generation;
  stale commands after navigation; bounded inputs, record capacity, oversized
  state, numeric overflow, loss saturation and ordering.
- Transport stage: malformed enums and lengths, artifact integrity/hash mismatch,
  cancellation and disconnect, process crashes, queue saturation and failed
  final delivery. No producer blocks waiting for UI/broker consumption.
- Browser stage: pinned overlay synchronization and native compilation; actual
  Brave owned-fixture capture with native control, no CDP dependency in capture;
  rendered existing-VM-view import/step/validate at required viewports.

Do not conflate passing native fixture tests with browser transport acceptance.
Keep unavailable platform checks explicit and preserve production resource
limits and existing request/console geometry assertions.

## Future owned-browser control experiments

Native capture and debugger observation are separate experimental factors. A
future owned-fixture harness must distinguish an exposed endpoint, a connected
client, target attachment, enabled Runtime/Debugger domains, installed
breakpoints, actual pauses, evaluation, and tracing. Change one declared
condition at a time in paired fresh runs; retain baseline-versus-baseline runs
to measure nondeterminism. Use a fixed independent outcome channel in every
condition, and record the channel itself as part of the experiment.

Compare expected outputs, termination and typed guest state separately from
raw file hashes. Run identifiers, timestamps, formatting, transport chunking
and loss can change a trace hash without changing program semantics. Agreement
on owned cases supports those cases only; it does not establish general
noninterference, reliable target-key recovery or invisible instrumentation.
This candidate implements neither a browser experiment harness nor any
anti-debugger evasion.
