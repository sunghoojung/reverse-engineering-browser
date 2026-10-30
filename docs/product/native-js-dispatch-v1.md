# Native JavaScript dispatch-site probe v1

Status: design review (step 1 of probe P3). This document answers the bytecode
flushing, code cache, compilation-path, tiering, arming-scope and shape
questions for a V8 probe that observes JavaScript dispatch at the static
interpreter-candidate sites the analyzer already finds. Its conclusion and the
conditions it depends on are in [Verdict](#verdict). The wire contract is
versioned separately under `protocol/` with the implementation.

Static analysis ([dispatch classification v1](../../protocol/vm-dispatch-classification-v1.md))
classifies every JavaScript dispatch site and gates opcode claims. Runtime
observed claims and `nested_guests`
([workspace v2](../../protocol/vm-opcode-workspace-v2.md#observed-claims-and-nested-guests))
already exist, but for JavaScript they are only artifact-scoped and nesting is
never linked, because nothing observes a live JavaScript dispatch. This probe
closes that gap without page JavaScript, CDP, or the V8 debugger.

## Pinned sources reviewed

| Source | Revision | Scope |
| --- | --- | --- |
| V8 | `20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921` (15.1.206.16) | `src/interpreter`, `src/codegen/compiler.cc`, `src/snapshot/code-serializer.cc`, `src/flags`, `src/heap/marking-visitor-inl.h`, `src/execution`, `src/baseline`, `src/objects/shared-function-info*` |
| Brave patches to V8 | `brave-core` `v1.95.52` `patches/v8/` | `BUILD.gn`, `src/codegen/compiler.cc` (Page Graph hook in `GetFunctionFromEval`), `src/flags/flag-definitions.h` (`additive_safe_int_feedback`) |
| REB V8 stack | `patches/v8/0000` through `0009` | replayed in lexical order on top of the Brave patches |
| Chromium | `151.0.7922.108` | `third_party/blink/renderer/bindings/core/v8/` (`v8_initializer.cc`, `script_streamer.cc`, `v8_code_cache.cc`) |

No Brave patch touches `bytecode-generator.cc`, `interpreter.cc`,
`code-serializer.cc` or the runtime functions. Line numbers below refer to the
pinned V8 tree after the Brave and REB V8 patches.

## Which AST shapes are dispatch sites

The probe instruments exactly two of the five JavaScript static instructions.
Each maps one V8 AST node, found by its V8 source position, to one static site.

| Static `instruction` | Static `dispatch_kind` | V8 node and position | Probe |
| --- | --- | --- | --- |
| `switch` | `switch_on_value` | `SwitchStatement`, position of the `switch` keyword (`parser-base.h:6476`) | yes |
| `indexed call` (`t[k](...)`) | `handler_table`, or `threaded` in a handler cycle | `Call` of type `KEYED_PROPERTY_CALL` (`ast.cc:1060`); anchor is the callee `Property` position, the `[` token (`parser-base.h:4386`) | yes |
| `indexed call` (`t[k].call(...)`, `t[k].apply(...)`) | as above | `NAMED_PROPERTY_CALL` named `call` or `apply` whose receiver is a keyed `Property`; anchor is that inner `[` | yes |
| `aliased call` (`const h = t[k]; h(s)`) | `handler_table` | plain variable call; the selector was read at an earlier load | no, `js-dispatch-shape-unobservable` |
| `self call` (`h = h(s)`) | `threaded` | plain variable call | no, `js-dispatch-shape-unobservable` |
| `if ladder` | `compare_chain` | a chain of `CompareOperation` and jumps, no single node | no, `js-dispatch-shape-unobservable` |

Optional-chain keyed calls (`t?.[k]()`, `t[k]?.()`), super, private and
spread-through-`%reflect_apply` calls are not instrumented. The analyzer
never arms them and reports them with the same unobservable reason, so a
static interpreter candidate is never silently treated as unobserved. A V8
`Call` position is not used as an anchor: for a keyed call it is the `(` token
but for `t[k].call(...)` it is the `call` identifier (`Token::IsCallable`), so
it is not a stable anchor.

### Site naming

Static sites are named by artifact ID and the UTF-8 byte offset of the
candidate node (`location.byte_offset`, Oxc `span.start`). V8 knows neither
the artifact nor UTF-8 offsets. An armed site is therefore named by a key both
sides can compute exactly from the same text:

- `source_sha256`: SHA-256 of the script source as V8 compiles it, encoded as
  UTF-16LE code units. The analyzer decodes the artifact as strict UTF-8 and
  removes one leading U+FEFF, because Blink's decoder strips the byte-order
  mark before V8 sees the text. V8 hashes its own `Script::source()` string
  (one-byte strings are widened). This is not the artifact digest, which hashes
  raw bytes; both are recorded.
- `source_length`: the source length in UTF-16 code units.
- `anchor_offset`: UTF-16 code-unit offset in that text of the `switch`
  keyword, or of the `[` that opens the callee's computed member. The analyzer
  finds the `[` by scanning forward from the end of the member's object span,
  skipping only whitespace, comments, `)` and `?.`; any other character refuses
  the site (`js-dispatch-anchor-unresolved`) rather than guessing.
- `shape`: `switch` or `indexed-call`.

A site name is `(source_sha256, source_length, anchor_offset, shape)`. Two
scripts with equal text are the same site, by design: a reload compiles a new
V8 `Script` with a new script ID, and the probe must follow it. An artifact
decoded by Blink with a different charset produces a different key and never
binds; that absence is reported, not inferred. Inline scripts and worker
scripts have no captured JavaScript artifact today, so the analyzer has
nothing to arm for them.

## Bytecode flushing

V8 ages every flushable `SharedFunctionInfo` once per major GC and flushes its
bytecode when the age reaches `bytecode_old_age` (default 6,
`flag-definitions.h:2827`; `MarkingVisitorBase::VisitSharedFunctionInfo` and
`IsOld`, `marking-visitor-inl.h:455` and `:542`). Old bytecode is visited
weakly, so a `BytecodeArray` still referenced from a live interpreter or
Sparkplug frame stays marked and is not flushed. A running dispatch loop is
therefore never flushed under its own activation.

Arming is not stored in the bytecode. The bytecode generator asks the
per-isolate arming table at generation time. When flushed bytecode is
regenerated it asks again, so:

- arming persists across a flush while the same configuration is active;
- regeneration after arming changed emits the new decision, including plain
  bytecode when the site is no longer armed;
- re-emission is bounded: one regeneration emits at most one runtime call per
  armed anchor in that function (at most 8 per isolate), and every sample is
  charged to the embedder's per-configuration budget, not to a bytecode
  instance, so repeated flushes cannot multiply captured records.

Two caveats are part of the contract. A function that was armed keeps
optimization disabled after a later unarmed regeneration (see
[Tiering](#tiering)); its bytecode is identical to unarmed bytecode. And the
lazy source-position collector (below) regenerates bytecode for an existing
array, so it must never run in capture mode.

### Lazy source positions are a regeneration hazard

`Compiler::CollectSourcePositions` (`compiler.cc:2939`) reparses a compiled
function and reruns the bytecode generator only to attach a source-position
table to the existing `BytecodeArray`. If arming differed between the first
compile and this rerun, the table would describe different bytecode. The
probe flag therefore implies `--no-enable-lazy-source-positions`: every
compile records positions eagerly (`parse-info.cc:36`), and
`CollectSourcePositions` is unreachable (`shared-function-info-inl.h:414`,
`:871`). This costs memory for position tables, only in capture mode.

## Code cache, compilation cache and streaming

Every path that installs bytecode without running the generator on the main
thread must be closed while the probe flag is set, or the site is silently
missed. Five such paths exist at the pin:

| Path | Evidence | Decision while `--reb-js-dispatch-capture` is set |
| --- | --- | --- |
| Blink and V8 code cache consumption (`kConsumeCodeCache`, main thread or `BackgroundDeserializeTask`) | `CodeSerializer::Deserialize` and `SerializedCodeData::SanityCheckWithoutSource` (`code-serializer.cc:789`) | Refused. `SanityCheckWithoutSource` rejects every cache (`kFlagsMismatch`), so V8 marks it rejected and compiles through the generator. Independently, the flag is a non-default flag and changes `FlagList::Hash()` (`flags.cc:499`), so caches produced without it already mismatch. |
| Code cache production (`ScriptCompiler::CreateCodeCache`, `CreateCodeCacheForFunction`) | `CodeSerializer::Serialize` (`code-serializer.cc:52`) already returns null for asm.js | Refused (returns null). Blink skips a null cache (`v8_code_cache.cc:582`). No bytecode compiled in capture mode, armed or not, is written to disk. |
| In-memory script and eval compilation cache, including a partial hit that reuses an existing `Script` and its compiled inner functions (`compiler.cc:4056`, `:4142`, `:3379`) | `CompilationCache::IsEnabledScriptAndEval` (`compilation-cache.h:221`) | Disabled by implication (`--no-compilation-cache`). A reload or a repeated `eval` compiles fresh. |
| Script streaming, which compiles top-level and eager functions off-thread before the source string is attached to the `Script` | `ScriptCompiler::StartStreaming` returns null without `--script-streaming` (`api.cc:2795`) | Disabled by implication. Blink falls back to a main-thread compile (`script_streamer.cc:739`, `kV8CannotStream`; inline streaming checks `CanStream()`). |
| Lazy compile dispatcher and parallel compile tasks | experimental, off by default (`flag-definitions.h:3194`) | Disabled by implication, so all JavaScript bytecode is generated on the main thread, where the arming table lives. |

The probe chooses refusal over per-script cache screening because a cache
entry cannot be attributed to an armed site without hashing it, and a script
compiled while unarmed could later be armed. Refusal also gives the simplest
proof: in capture mode there is no route to installed bytecode that bypasses
`BytecodeGenerator`. Its cost (no code caching, no streaming, no in-memory
compilation cache, eager source positions) applies to the whole browser while
the flag is set and is the research-mode cost, like the Liftoff-only Wasm
dispatch flag.

## Lazy compilation, eval, Function and late arming

- Lazy functions compile on first call through `Compiler::Compile`
  (`compiler.cc:3046`) and run the generator on the main thread, so they
  consult the arming table current at that moment.
- `eval` compiles through `Compiler::GetFunctionFromEval` (`compiler.cc:3356`).
  `new Function` builds `(function anonymous(...\n) {\n...\n})` in
  `CreateDynamicFunction` and compiles it through `GetFunctionFromString`
  (`compiler.cc:3608`) into the same path. The V8 `Script` source is that exact
  synthesized string, which is also what the dynamic-JavaScript artifact
  capture receives. Brave's Page Graph hook in `GetFunctionFromEval` runs after
  compilation and does not change it.
- Arming that happens after a function already has bytecode cannot add a call
  to that bytecode. The probe does not patch bytecode in place and does not use
  the debugger's instrumented-bytecode machinery. Instead, when the arming
  table changes, V8 scans the isolate's script list once, hashes only scripts
  whose UTF-16 length equals an armed length, and for each matching script finds
  the innermost `SharedFunctionInfo` containing each armed anchor. If that
  function is compiled and its bytecode was not generated with that anchor
  armed, the site is reported `compiled_before_arming` for that script. Inner
  functions that are not compiled yet are armed when they compile. The site
  becomes observable after bytecode regeneration or a reload.

## Tiering

Armed sites are a `CallRuntime` bytecode, so every tier that compiles from the
bytecode sees them. Sparkplug compiles `CallRuntime` as a runtime call
(`baseline-compiler.cc:1603`). Rather than relying on Maglev and Turbofan
preserving the call (both would, because the runtime function has side effects
and needs a frame state), armed functions are never optimized: generation
calls `SharedFunctionInfo::DisableOptimization(kNeverOptimize)` for every
function that contains an armed site. That reason is terminal and is honored by
Maglev (`compiler.cc:1353`), Turbofan and tier-up (`tiering-manager.cc:331`,
`compiler.cc:4558`), OSR (`compiler.cc:4489`, `tiering-manager.cc:259`)
and inlining (`shared-function-info-inl.h:455`, `kHasOptimizationDisabled`).

This is required, not only convenient: activation identity is a register in
the armed function's frame, and parent linkage reads that register from
enclosing frames with `UnoptimizedJSFrame::ReadInterpreterRegister`
(`frames.h:1231`), which works for interpreter and Sparkplug frames. An inlined
or optimized armed frame would make that read impossible without deoptimizer
state translation. Only functions that contain an armed site lose optimization
(at most 8 per isolate); their handlers and callers tier normally. This changes
the timing of those functions and is declared, like the Liftoff-only Wasm mode.
Already optimized code is never armed: arming only happens at generation, and
flushing discards optimized code together with the bytecode it was built from.

## Arming scope, expiry and cost

- **Configuration.** The researcher supplies at most 8 sites in an immutable
  file for the browser lifetime, as with the Wasm guest adapter. The browser
  validates it and sends it with each renderer configuration. The renderer
  sink owns the active configuration generation, budgets and expiry.
- **Per isolate, pulled by V8.** V8 holds a fixed per-isolate copy of the
  armed sites and the embedder epoch. It pulls the epoch from the embedder at
  generation and at each trace, and refreshes the sites when the epoch changes,
  so configuration can change on any thread without V8 calls from that thread.
  Epoch 0 means inactive: disable, expiry or a configuration without sites
  clears the armed table, and new compiles emit plain bytecode.
- **Per document.** Arming matches script text, not documents. Each
  observation is admitted only in a live local document context and carries
  its frame identity. Workers, worklets and service workers have no arming and
  are unsupported.
- **Expiry.** The embedder's admission predicate rechecks session, category,
  generation and expiry before any frame walk or handle. Already armed bytecode
  keeps its call after expiry and returns at that check.
- **Cost when the flag is off.** The generator reads one flag per function and
  emits byte-identical bytecode. No runtime call exists, no cache or streaming
  setting changes. This is tested by comparing bytecode arrays.
- **Cost when the flag is on but a script is unarmed.** That script's bytecode
  is byte-identical. Per function compile the generator compares the script's
  UTF-16 length with at most 8 armed lengths, and hashes a script at most once
  per epoch when a length matches (a fixed cache of recent bindings). The
  browser-wide cache, streaming and source-position settings above apply.
- **Cost of an armed site.** One runtime call per dispatch. After the budget
  is spent the call returns at the admission predicate without walking frames.

## Activation and parent activation

A function with at least one armed site gets one extra register, the
activation register, initialized to `undefined` like every register. Each
armed site passes it to the runtime call and stores the returned value back.
On the first admitted trace in a frame the runtime allocates an activation ID
from a per-isolate counter that is never reset; a value below the current
epoch's floor is treated as unallocated, so an activation never carries an
ID from a previous configuration. Generators and async functions save and
restore the register with their other registers, so a resumed activation keeps
its ID.

The parent is found once, when the activation ID is allocated. V8 walks at
most 64 JavaScript frames outward from the caller of the armed frame and stops
at the first frame whose function contains a currently armed anchor:

- if that frame's activation register holds an ID of the current epoch, it is
  the parent;
- otherwise (that activation has not dispatched in this configuration yet) the
  parent is unknown and flagged, never taken from a frame further out.

Frames without armed anchors are skipped. Because the walk reads the live
register of a live frame, the parent cannot be a stale or reused frame. A
parent is a call-stack relation at the child's first dispatch: it supports
nesting when the analyzer also proves the sites differ and are interpreter
candidates, and it never proves that a specific outer handler drove the child.
A walk that hits the 64-frame bound is flagged as truncated.

## Bounds and loss

| Bound | Value | When exceeded |
| --- | --- | --- |
| Armed sites per configuration | 8 | file rejected at browser startup, no arming |
| Samples per configuration | 256 | one coalesced `gap` (`native_js_dispatch_budget_incomplete`) per configuration |
| Samples per site | 64 | that site's admission predicate returns false; one coalesced gap per configuration names the per-site limit |
| Frames walked for a parent | 64 | `parent_search_truncated` flag in the record |
| Activation parents retained per configuration | 256 | later activations carry the `parent_unknown` flag |
| Script bindings cached per epoch | 64 | the oldest is evicted and rehashed on demand; no loss |
| Renderer ring | 8,192 records | existing visible drop counter |

Every refusal of an admitted sample before the ring (emitter rejected,
invalid record) is one coalesced gap per configuration and reason. A
`compiled_before_arming` status is a gap naming the site slot. Nothing copies
arguments, receivers or string contents: a string, symbol, BigInt or object
selector records only its kind, a number records its low 32 bits only when it
is an integer, and a handler records only its script ID and source span.

## Verdict

No blocker. At the pinned sources the probe can be made:

- **disabled by default**: a new flag, off by default, with byte-identical
  bytecode when it is off or when a site is unarmed;
- **bounded**: fixed per-isolate tables, at most 8 armed sites, at most one
  runtime call per armed anchor per generation, a 64-frame parent walk only
  for a new admitted activation, and the 256 and 64 sample budgets;
- **loss-visible**: every path that would install bytecode without the
  generator is closed in capture mode, late arming is reported per script and
  site, and every budget, refusal and queue loss is a gap or counter.

The conditions above are part of the design. A change that re-enables code
caching, streaming, the compilation cache or lazy source positions in capture
mode, or allows optimizing an armed function, reopens this review.

## Implementation map

| Layer | Change |
| --- | --- |
| V8 | patch `v8/0010`: flag and implications, arming table and SHA-256 binding, generator emission for the two shapes, `Runtime_RebTraceJsDispatch`, cache refusal, cctests |
| Chromium | patch `chromium/0020`: install the V8 callbacks in `V8Initializer`, admit only live local documents |
| Overlay | wire header, site-file parsing, renderer budgets and gaps, Mojo configuration, browser forwarding |
| Protocol and analyzer | event `js_dispatch_observation`, C++/Rust/JavaScript validators, site-scoped JavaScript observed claims, JavaScript nesting through the parent activation, arming export |

Acceptance needs ordered replay on the pinned sources, the V8 cctests in
`tools/check-native-v8-runtime.py`, renderer budget, expiry and queue-loss
checks, bytecode identity for unarmed code, and the flush, re-arm and
code-cache cases decided here. A rebuilt Brave run on an owned two-level
fixture is the remaining live acceptance layer.
