# VM Dynamic Debug v1

## Status

This document is the authoritative product and architecture specification for
the first *dynamic* virtual-machine laboratory. Detection remains
[`anti-bot-vm-detection-v1.md`](./anti-bot-vm-detection-v1.md). This milestone
adds inspector-free runtime observation, post-decrypt bytecode snapshots, and
an evidence-linked opcode workspace.

Authorization, capture, and experiment boundaries are defined in
[`SAFETY.md`](../../SAFETY.md). Use this capability only on systems the
researcher owns or is explicitly authorized to test.

## Why this exists

Modern JavaScript VM obfuscators (including obfuscator.io Pro) compile
function bodies into custom bytecode and wrap the interpreter with defenses
that treat Chrome DevTools Protocol as a hostile inspector:

- `vmDebugProtection.inspectorDetection` reacts to `Runtime.enable` and an
  active `Debugger` domain. Opening DevTools, Puppeteer, Playwright, or
  Origin Trace's current debugger transport all trip it. After a hit the
  protected code throws decoy errors such as `Uncaught 0` until reload.
- `vmSelfDefending` hashes its own source, detects hooked builtins, and
  breaks under headless, jsdom, and page-side wrappers.
- `vmBytecodeArrayEncoding` plus an async key getter ships ciphertext. The
  plaintext guest program exists only after a runtime decode into a
  `Uint8Array` / `ArrayBuffer`.
- `vmStatefulOpcodes` and `vmRegisterBased` make opcode meaning depend on
  position or registers, so a static switch table is not a complete ISA.
- `vmCallContextOpcodes` makes a lifted interpreter lie unless it is invoked
  through real call sites.

Origin Trace v1 already *detects* dispatch loops. It cannot debug them. The
live debugger speaks CDP. Native quiet mode drops CDP and also drops every
dynamic tool. This milestone closes that hole without attaching Inspector.

## Release promise

In an authorized session with the VM category enabled, Origin Trace:

1. Observes the page without enabling the CDP `Runtime` or `Debugger`
   domains.
2. Snapshots candidate guest bytecode *after* runtime decode, as original
   bytes in the artifact channel.
3. Reconstructs a bounded opcode workspace from interpreter source plus
   those snapshots, with explicit unknowns for stateful and context-gated
   opcodes.
4. Shows that workspace in VM Lab next to the existing detection findings.

This version does not promise a complete guest decompiler, exact value
provenance through every opcode, or an invisible Inspector that still
speaks CDP.

## Decisions

### Avoid Inspector rather than hide it

Hiding an attached Inspector is a cat-and-mouse game against detectors that
watch `Runtime.enable`, console wrapping, `debugger;` timing, and window
chrome. The supported research path is a **stealth VM session**:

- Do not start `--remote-debugging-port`.
- Do not construct `reb-debugger-transport`.
- Do not send `Runtime.enable` or `Debugger.enable`.
- Keep native quiet-mode's `--js-flags=--reb-ignore-debugger-statements`.
- Capture through native probes and the artifact channel only.

Sources continues to show captured artifacts. Breakpoints, watches, and the
console stay unavailable in this mode and the UI says so.

A later milestone may add a patched Inspector that does not wrap console or
set JS-observable debug flags. It is out of scope here because obfuscator.io
documents `Runtime.enable` itself as the detector, not only an open docked
DevTools window.

### Native observation, not page hooks

Page JavaScript is never the probe. Wrapping `Function.prototype`,
`Uint8Array`, or host builtins is exactly what `vmSelfDefending` hashes.
Probes live in V8 and Blink, stay allocation-free while disabled, and never
change `Function.prototype.toString` or builtin identity.

### Bytecode is an artifact, not an event payload

Guest bytes after decrypt travel on the existing artifact channel. The
renderer event ring still carries only the 128-byte `VmFindingPayload` or
the new compact `VmDispatchSamplePayload`. Artifact identity links them.

### Two-tier opcode claims

Opcode rows use the same epistemic states as detection:

- `observed`: a native snapshot or dispatch sample recorded this opcode at
  this program counter.
- `inferred`: static handler extraction from interpreter source.
- `correlated`: a sample and a handler share an index without a proven
  decode.
- `unknown`: stateful, context-gated, or truncated.

No row is labelled `confirmed` until a later isolated experiment traces
that opcode against explicit inputs.

## Capture additions

### Artifact kind and origin

Add to the mirrored artifact ABI (`include/reb/artifact.hpp` and
`native_artifact_header.h`):

| Enum | Value | Meaning |
| --- | ---: | --- |
| `ArtifactKind::kBytecodeBuffer` | 6 | Raw guest program bytes, not JavaScript source |
| `ArtifactCaptureOrigin::kRuntimeTypedArray` | 7 | Snapshot of a `JSTypedArray` / `ArrayBuffer` after construction or a bounded in-place decode |

Keep protocol version 1 of the 128-byte artifact header. New enumerators are
additive. Receivers must reject unknown kind/origin pairs the same way they
reject other generated artifacts.

Limits:

- 32 bytes minimum, 16 MiB maximum, same cap as other generated artifacts.
- At most 16 typed-array snapshots per session and 32 MiB queued, sharing
  the existing generated-artifact queue.
- Inactive path: one atomic load, then return.
- Content is original bytes. Do not inflate, decrypt, or interpret in the
  renderer.

### Typed-array probe

When the VM category is authorized, a V8/Blink hook observes construction of
`Uint8Array`, `Uint16Array`, `Uint32Array`, and `ArrayBuffer` copies whose
byte length is in range. Preferred insertion points follow the existing
runtime-generated artifact patch: one inactive check, copy into the
one-way Mojo submission, browser process owns the socket.

Do not wrap the JavaScript constructors. Hook the C++ initialization path
used by builtins.

Heuristic keep-list (any one is enough to submit, subject to the session
cap):

- allocating script is already a `likely-vm` or `candidate` artifact;
- buffer is produced inside `eval` / `Function` source that was itself
  captured;
- buffer length is at least 256 bytes and the allocating frame's script
  contains a dispatch-loop observation.

Every snapshot records creator event, execution context, frame, source URL
(credentials/query/fragment stripped), digest, truncation, and an
unavailable reason when the copy is dropped.

Allocator lookup skips at most eight builtin constructor frames before reading
the innermost authored JavaScript frame, including its inlined function. It does
not fall back past an authored frame with unavailable script metadata. This keeps
typed-array constructors from hiding their allocating script.

### Dispatch samples

Add `EventType::kVmDispatchSample = 16` with JSON name `vm_dispatch_sample`.
Payload is a 128-byte `VmDispatchSamplePayload`:

```text
u16 protocol_version = 1
u16 payload_size = 128
u32 instruction_pointer
u32 opcode                 // offset 8
u32 handler_index
u32 sample_index
u32 reserved_alignment     // offset 20, must be zero
u64 finding_id             // offset 24, must be nonzero
u64 investigation_id
u64 interpreter_artifact_id
u64 bytecode_artifact_id
u8  flags                  // v1 requires zero
u8  operand_count
u16 reserved0
u32 reserved1
u64 reserved2
40-byte reserved
16-byte reserved tail
```

The struct must be standard-layout, trivially copyable, unique-object
representation, exactly 128 bytes, with `static_assert` offsets matching
the overlay copy in `native_vm_dispatch.h`.

v1 producers may emit samples only from a bounded offline fixture or from a
future native sampler. The ABI and UI must accept them now. A missing
sampler is an explicit coverage omission, not a silent empty table.

Do not enable V8's debug agent to collect samples. A later sampler may use
the CPU profiler or a function-entry counter. `Debug::SetBreakPoint` is
forbidden in this milestone because it activates Inspector-adjacent state.

## Cold-path opcode workspace

Store a derived document at
`ARTIFACT_STORE/analysis/vm-opcode-workspace-v2.json`. Schema:
[`protocol/vm-opcode-workspace-v2.schema.json`](../../protocol/vm-opcode-workspace-v2.schema.json).

The analyzer reads:

- the existing `vm-analysis-v1` document;
- JavaScript interpreter regions already scored as dispatch loops;
- captured `kBytecodeBuffer` artifacts;
- any `vm_dispatch_sample` events.

It writes, per likely-vm artifact:

- handler candidates extracted from `switch` cases, function arrays, or
  object maps inside the dispatch region;
- operand width guesses from adjacent indexed reads;
- bytecode hex preview from the linked snapshot (cap 4096 bytes in the
  document, full bytes remain in the artifact store);
- coverage: byte-attributed ranges versus retained snapshot bytes; an
  instruction-index sample alone does not characterize a byte;
- residual unknowns for stateful, register-based, and call-context
  opcodes.

Handler extraction is deterministic and bounded. It never executes captured
JavaScript. Switch-case integer labels become inferred opcode numbers.
A source citation includes the visible case body or function body, including
nested helpers, rather than only its label. Nested switch labels do not become
outer handler opcodes. An adjacent 1-, 2-, or 4-byte indexed-read sequence yields
a static operand-width guess; absent, nonadjacent, conditional, or repeated
reads retain width 0 with an explanation. This is not a runtime layout proof.
Computed property names stay unknown. Selectors must be a direct indexed byte
read, literal, or a bounded chain of preceding immutable `const` aliases to one; transformed,
position-dependent, saved-state, and unresolved selectors do not establish a
fixed opcode mapping. The analyzer retains at most 1024 distinct handlers and
reports `handler-limit` when additional candidates are omitted.

## VM Lab UI

Keep the current finding list. When a selected finding has an opcode
workspace:

- **Handlers** table: opcode, handler source range, epistemic state,
  sample count, guest position with units, selected handler index, bytecode
  artifact ID and notes.
- **Bytecode** panel: hex of the snapshot, digest, producer origin,
  truncation, Open-in-Sources for the interpreter artifact.
- **Coverage** bar: characterized / total snapshot bytes, plus named
  omissions.
- **Session mode** chip: stored `CDP attached`, `Native stealth`, or unknown.
  [Capture provenance](../../protocol/capture-provenance-v1.md) records how the
  exact input session launched. An omitted DevTools endpoint is not evidence
  of undetectability or a statement about the current debugger connection.

Empty, malformed-workspace, partial-coverage, and sampler-unavailable
states remain visible. Captured bytes render as text, never as HTML.

Keyboard: the handler table is an option list with the same arrow-key
pattern as the finding list.

## Fixture corpus

Repository-owned programs, never live vendor samples:

1. Tiny stack VM with a `while` + `switch` and a `Uint8Array` program.
2. Same VM after a trivial XOR decode into a new `Uint8Array` (models
   encoded bytecode without shipping an obfuscator).
3. Register-machine variant with explicit `regs[]`.
4. Negative: packed/minified non-VM script with a long switch.

CI asserts:

- (1) and (3) become `likely-vm` and grow an opcode workspace with
  inferred handlers;
- (2) links a `kBytecodeBuffer` snapshot in the fixture event/artifact
  store and shows post-decode bytes, not the XOR source string;
- (4) stays non-VM and produces no workspace.

## Brave integration

Tracked sources only:

- overlay files under
  `browser/integration/brave/overlay/components/reverse_engineering_browser/`;
- ordered patches under `browser/integration/brave/patches/v8/` and
  `patches/chromium/`;
- ABI twins in `include/reb/`.

Never edit `browser/worktree/`. Inactive probes remain one atomic load.
Drops increment the existing generated-artifact gap path.

Launch wiring: `REB_NATIVE_QUIET_MODE=1` already omits CDP. Stealth VM
sessions reuse that path and also set the VM category mask. Document the
combination as the supported way to study inspector-detecting VMs.

## Out of scope

- Recovering async encoding keys from the network as a special case of
  Traffic (existing request capture already stores the response if
  authorized; this milestone only snapshots the decoded buffer).
- Automatic lifting of guest bytecode to JavaScript.
- Generalized opcode confirmation beyond the explicitly tested owned inputs.
- Target-specific vendor packs.
- MCP.

## Acceptance gates

1. A stealth session does not open a DevTools WebSocket or send
   `Runtime.enable`.
2. Fixture (2) retains post-decode bytecode bytes as a
   `kBytecodeBuffer` artifact with origin `kRuntimeTypedArray`.
3. VM Lab renders handlers, bytecode preview, coverage, and stealth-mode
   copy for fixture (1) without a CDP debugger.
4. ABI tests lock payload size, offsets, and unknown-enum rejection.
5. `make lint`, `make check`, and the research-ui VM tests pass. Brave
   probe compilation is reported honestly when the toolchain is absent.

Owned cooperative dispatch emission and exact v2 retention are specified in
[VM opcode workspace v2](../../protocol/vm-opcode-workspace-v2.md). This does not
implement arbitrary-site guest dispatch. Input-specific owned confirmation is
provided separately below.

## WebAssembly dispatch workspaces

A `likely-vm` WebAssembly finding gets one workspace. Decoding remains static
and never instantiates the module. Handler arms come from the detector-selected
function and from other functions in its bounded direct-call and in-loop
`call_indirect` table neighborhood. Unrelated functions do not contribute
candidates. `runtime: webassembly` distinguishes this view from JavaScript
handlers. `br_table` selector indices are inferred dispatch candidates; they do
not prove an identity mapping to guest opcodes. Source byte ranges cite the
dispatch instruction, not a recovered handler body. Default arms and dynamic
`call_indirect` targets have null opcode, unknown state and zero samples. Label
depths and table identifiers are never presented as known handler indices.
Guest semantics and the stack/register model remain explicit residual unknowns.
Module-wide ranking keeps every decoded `br_table` and `call_indirect`. A small `br_table` is a CFF/relooper
candidate. A large `br_table` is a handler-table candidate: selector index to a
Wasm branch target, with repeated labels reported as a unique-target count.
`call_indirect` is an indirect funcref candidate; its arm count stays null, and
a static element funcref count is fanout evidence only. A proven guest opcode
ISA requires guest program-counter and bytecode-stream evidence. Static arms do
not invent a guest PC, registers, or a stack. Owned fixtures and live captures
share that schema.
The same 1024-candidate and 16-snapshot caps apply. Non-VM modules have no
workspace. Without a runtime snapshot, the guest-byte walk stops at
`static-module-only` and does not invent a program counter or characterized
bytes.

## Owned input-specific confirmation

The opcode workspace exposes an explicit **Isolated owned opcode experiment**
for the exact native reference sources and effect declarations. Select owned
addition or nonzero branch, enter the compiled inputs 7 and 5 and an expected
value/next instruction index, then run a separate disposable native helper.
Results are stored separately as confirmed for those inputs, mismatch, unsupported
or unknown; no handler receives a universal confirmed label. See the
[experiment contract](../../protocol/owned-opcode-experiments-v1.md).

## Host event positions

The [host-links report](../../protocol/vm-host-links-v1.md) records a guest position only for an exact scoped parent dispatch sample with validated invocation. When no samples were retained, every same-scope host row stays `state=unknown`, `reason=dispatch-samples-unavailable`, and `guest_position` null. VM Lab says that this is static-only: the workspace can still list inferred handlers, and the rows are session/navigation/frame correlation, not a Wasm loader and not request-value provenance. Shared frame/invocation and request correlations do not become exact value provenance. The opt-in owned clock fixture provides a real, explicitly synthetic native callback boundary for validation. `reb-native-vm-fixture --emit-dispatch-events-v1` is the offline producer for real samples; it does not sample a captured page module.
