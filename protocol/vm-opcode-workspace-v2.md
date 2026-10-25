# VM opcode workspace v2

The [schema](vm-opcode-workspace-v2.schema.json) owns the derived document at
`ARTIFACT_STORE/analysis/vm-opcode-workspace-v2.json` and the existing
`GET /api/analysis/vm/opcodes` response. The UI rejects v1 instead of guessing
missing identities, units, effects or coverage. Historical v1 files are not
rewritten. The source analysis remains a separately digested document.

## Scope and identity

Each workspace preserves its interpreter artifact ID, full source artifact
SHA-256, finding ID, runtime, and capture mode. Unknown capture mode remains
`unknown`; an absent provenance sidecar has a null input digest. Document hashes
use the existing sorted-key, ASCII-escaped canonical JSON with the
`document_digest` member excluded. Hashes identify content, not authenticity,
authorization or correctness of a researcher's artifact binding.

Each retained dispatch sample has the original event identity
`{session_id,process_id,sequence_number}`, PC, opcode, selected handler index,
sample index, operand count, finding/investigation IDs and interpreter/bytecode
artifact IDs. uint64 IDs remain canonical decimal strings. PC/opcode/index
fields preserve the existing uint32 payload exactly. Host payloads are not
copied into this document. No instruction bytes or operand values are inferred
from these numbers.

Admission requires the full version-1 128-byte dispatch payload, clean reserved
bytes, nonzero finding/investigation/interpreter IDs, exact payload interpreter
identity, and matching event artifact/session/navigation/frame. Truncated
payloads and conflicting event identities are rejected. Repeated identical
records are deduplicated by the existing input reader. Matching an opcode alone
never establishes interpreter identity.

`sample_count` counts all accepted samples for the workspace, including opcodes
without static handlers. JavaScript and Wasm workspaces both admit a
`vm_dispatch_sample` whose interpreter artifact id is that workspace's
artifact. `samples` retains the first 4096 in input order; further
accepted samples still count and add `sample-limit`. Handler counts include only
the accepted samples of that opcode; document counts sum workspace counts.
Unmatched opcodes stay in samples and residual unknowns. No accepted samples
and no dispatch-budget loss produces `sampler-unavailable`, preserving static
handler candidates.

A `vm` `gap` whose artifact id is the interpreter and whose payload is a
decimal count is a dispatch-budget loss. The workspace adds
`dispatch-sample-budget` with that summed count and keeps coverage incomplete.
`sampler-unavailable` stays reserved for a workspace that retained no samples
and has no such loss. The 16-sample cap is one gap weight, not one gap per
dropped step.

## Native browser capability boundary

The `vm_finding` and `vm_dispatch_sample` ABIs, a caller-fed bounded writer,
and an automatic guest-interpreter sampler are separate capabilities. The owned
register interpreter is one opt-in sampler. It stays disabled until
`EnableOwnedRegisterSampling` accepts the active VM capture session and nonzero
finding, investigation, interpreter, and bytecode identities. Reconfigure clears
that opt-in. While enabled, `SampleOwnedRegisterInvocation` runs the compiled
`owned-register-v1` program and is the observation path that calls
`RecordVmDispatchSample`. Each invocation emits one dynamic `vm_finding` labeled
`owned-register-v1`, then one sample per committed instruction. The program
counter is that fixture's instruction index. The handler index copies the
fixture opcode. Operand values are not copied. Further steps past the 16-sample
budget stay on the dispatch-loss counter and publish as one vm gap. A full
probe queue counts those steps on `DroppedCount` and returns the budget slot.
Two further opt-in shapes read captured bytes and call the same writer.
`javascript-switch-dispatch-v1` steps a typed-array checkpoint whose bytes are
opcodes 16–19. Its program counter is the opcode byte index.
`wasm-br-table-dispatch-v1` steps the first function of a Wasm module when that
body decodes inside a fixed opcode subset and contains `br_table`. Its program
counter is the module byte offset. The handler index copies the opcode. A walk
stops after 32 committed steps; if the program has not halted, one extra
dispatch loss is counted. Both stay disabled until their Enable call accepts
the VM session and nonzero finding, investigation, interpreter, and bytecode
identities. Reconfigure clears them. Ignition, Liftoff, TurboFan, and every
other interpreter shape still have no sampler. A detected dispatch loop, a high
static score, or a retained buffer that does not match these shapes does not
produce a program counter.

A workspace with no admitted samples and no dispatch-budget loss retains static
handlers and the explicit `sampler-unavailable` omission, leading with the
observed absence of retained samples and the automatic sampler limitation.
A budget gap records that observations were dropped after the writer admitted
its 16-sample cap. That omission is present when the capped trace still holds
some samples, and it replaces `sampler-unavailable` when every observation was
dropped. The host-links report keeps `guest_position` null and
`dispatch-samples-unavailable`. VM Lab labels that report static-only so a
list of unknown network edges is not mistaken for an empty workspace or a
recovered guest PC. The stdout fixture export below demonstrates
the transport/consumer contract. The owned-register opt-in runs that register
program into the renderer queue. The page shapes run only when their opt-in is
enabled and a captured buffer matches. Rebuilding the browser does not sample
Ignition or compiled Wasm. `reb-native-vm-fixture --emit-dispatch-events-v1`
is the offline way to prove this consumer with real samples and no browser.
`javascript-switch-dispatch-v1` and `wasm-br-table-dispatch-v1` are separate
probe opt-ins; that CLI does not emit them.

A future native adapter must first establish exact captured interpreter and
bytecode identities, invocation boundaries, PC units and the observed dispatch
site. It must emit bounded, opt-in, non-blocking records with explicit losses,
retain native host-call parentage, and remain allocation-free while inactive.
It must not infer an instruction-index PC from a source offset, static switch
case, host call, shared frame, request ID, URL or time proximity. The arbitrary
JavaScript/Wasm runtime does not expose a universal guest PC; interpreter-specific
semantics require a separately reviewed implementation, not enabling a flag.

The owned-register probe opt-in is accepted by the admission harness: disabled
by default, one invocation marker, instruction-index program counters, a visible
16-sample gap, and a full-queue drop that returns the budget slot. The two page
shapes are accepted there the same way, including the typed-array entry for the
JavaScript program and `ObserveCapturedWasmModule` for the Wasm module. The
Wasm bytes reach that entry from Chromium patch
`0016-sample-wasm-br-table-dispatch.patch`, which calls it before artifact
capture is gated. That patch has not been replayed on the pinned Chromium
checkout in this change. A Brave/Xcode build is still required to prove a live
page typed array and a live `WebAssembly.compile` produce the same program
counters. Ignition and Liftoff remain an open gap, not a successful empty trace.

## Owned producer and instruction units

The explicit `reb-native-vm-fixture --emit-dispatch-events-v1` mode executes only
the two compiled repository-owned fixtures. It does not attach to a browser,
enable CDP, evaluate a captured source, modify baseline tabs or discover targets.
It captures each native instruction in fixed recorder storage, then exports one
invocation marker followed by one `MakeVmDispatchSample` event per instruction.
No file/socket I/O occurs during fixture dispatch. Existing disabled, batch and
interactive helper modes are unchanged; no event export occurs implicitly.

All arguments below are required exactly once. Identity arguments are canonical
nonzero uint64 values, selected explicitly by the researcher. They are reference
claims, not verification that a supplied artifact came from the native runtime.
The output is an ordinary native event stream consumed by the existing broker:

~~~sh
build/reb-native-vm-fixture --emit-dispatch-events-v1 --fixture register \
  --session-id 101 --navigation-id 102 --frame-id 103 --invocation-id 104 \
  --finding-id 105 --investigation-id 106 \
  --interpreter-artifact-id 107 --bytecode-artifact-id 108 \
  | build/reb-event-broker --store /private/disposable/events.jsonl
~~~

Use a fresh disposable evidence store. The broker's retained JSONL, rather than
successful stdout writes, establishes delivery. Export failures are not retried.
`stack` selects the other fixed program. Both execute nine instructions with
PCs 0,1,2,3,4,5,6,8,10, opcodes 1,1,2,3,4,5,6,7,8 and fixed input 7/5.
PCs are instruction indices, never offsets into the serialized program manifest.
The producer's handler index is its compiled opcode selection.

The first event is an existing version-1 `vm_finding`: invocation kind, unknown
host runtime, observed confidence, dynamic flag, zero source/count/reserved
fields, nonzero finding/investigation/invocation IDs, related bytecode ID, and
exact `owned-register-v1` or `owned-stack-v1` label. Each sample's
`parent_event_id` points to that marker. The analyzer checks the complete typed
payload, matching source artifact, session/navigation/frame/process,
finding/investigation/bytecode IDs, and earlier exact parent event. Only this
explicit bound declaration yields `instruction-index` plus the original
`invocation_id` and `invocation_event`. A matching label or frame alone does not.
Absent/invalid marker evidence keeps units `unknown` and both invocation fields
null. The sample itself can still be retained with unknown units.

The inert [reference fixtures](../tools/fixtures/native-vm-dispatch/references.json)
bind exact source hashes to the owned program manifest. They describe native
opcode 1–8 and can supply static source rows for the synthetic integration test;
they are declared reference sources, not captured JavaScript execution.
The analyzer never executes them. Existing JavaScript demo opcodes 80–83/16–19
are not renamed to make native samples appear to match.

## Bounded interpretation

The v2 shape includes closed effect, byte-coverage and traversal records for
subsequent analyzers. Empty `effects` does not mean no state effects. Without a
supported attribution, characterized bytes remain zero, all retained snapshot
bytes remain uncharacterized, and coverage is partial. An instruction-index PC
cannot characterize a byte without a separate verified mapping.
`uncharacterized-bytecode` names this limitation when bytes are present.
Traversal defaults to an `entry-unavailable` frontier and `complete:false`.
A WebAssembly module with static dispatch arms and no runtime snapshot uses
`static-module-only` instead of an empty `snapshot-unavailable` frontier.
These fields never promote a handler to universally confirmed semantics.

The UI shows sampled PC with units, selected handler index and bytecode artifact
ID on each matching handler row. It displays at most four position summaries
per row and reports additional accepted/retained counts. The selected-handler
inspector pages through every retained sample in groups of 32 and exposes its
complete recorded fields. Missing positions are explicitly unknown.
Malformed refreshes retain the last valid workspace and detection findings.

## Validation

`make native-tests` rejects short and dirty-reserved dispatch payloads.
`make native-vm-recorder-check` runs both owned producers through the broker and
checks all 18 dispatch records, scope, marker, fields and invalid CLI arguments.
`make e2e` additionally binds the inert reference sources and checks the actual
analyzer's handler counts, exact source digest, samples, PC units and incomplete
byte coverage. Rust workspace tests exercise identity mismatch, malformed and
truncated payloads, unknown opcodes, scoped marker mismatch, retention bounds,
all-sample counts, content digest/schema validity and v1 rejection. UI contract
tests cover sample projection, strict v2 validation and preserved failure state.

## Captured module instruction preview

A WebAssembly workspace may expose `captured_module_preview`, a bounded slice
of the dispatch instruction shared by the most selectors (then lowest offset).
Its `artifact_id` is the interpreter module, `byte_offset` is the original module
offset, and `byte_count` is the complete instruction size. `preview_hex` retains
at most 4096 bytes and `truncated` names any omitted suffix. The workspace source
digest identifies the full captured module, not a digest of this slice.

This is source evidence, not a runtime memory or guest-bytecode snapshot. It does
not populate `snapshots`, `bytecode_artifact_id`, snapshot counts, byte coverage,
or traversal inputs. Missing runtime bytes retain their explicit omission even
when the module instruction preview is visible.

The optional `dispatch_inventory` is the same static inventory exposed in the
VM detector's `frontend`. It counts all decoded `br_table` and `call_indirect`
sites, including those outside loops, and retains at most 256 ranked metadata
records. `site_count` is the complete decoded count; `omitted_site_count` counts
unlisted records, not missing module traversal. A truncated inventory also adds
`dispatch-inventory-limit` to coverage omissions. `arm_count` is the number of
explicit `br_table` targets, excluding the default (and not the number of unique
targets); it is null for `call_indirect` because the target count is unknown.

Ranking v1 orders in-loop sites before non-loop sites, then tables with at least
32 arms, their arm count, function structural score, IP-like local/global
read/write pattern, loop depth, function body size, small-table arm count, and
lowest module offset. `selected_byte_offset` names the top in-loop site, or null
when none exists. Small tables are `cff-helper-candidate`, a heuristic label,
not proof of CFF. Larger tables are `dispatch-candidate`, not proven guest ISAs.
The ranking does not increase the detector's confidence or score. A Wasm
`candidate` with an in-loop dispatch can expose a static workspace even without
sufficient independent evidence for `likely-vm`.

The UI's Dispatch sites panel lists the bounded inventory and can select an
already retained site. Unrelated sites remain outside the retained neighborhood;
listing metadata never expands the neighborhood or runs the module. A refresh
preserves an explicit retained-handler selection. The initial listing emits the
ranked site first, even when a smaller site occurs earlier in the same function.
Static selectors still do not prove guest opcode binding without samples.

A WebAssembly workspace keeps static arms from the detector-selected function
and from a bounded neighborhood of that function: direct calls within three
hops, either direction, and functions named by element segments of tables those
functions use with in-loop `call_indirect`. At most 32 functions are retained.
The extractor retains at most 1024 site metadata records per function, always
preserving the selected ranked site, and reports `dispatch-site-limit` when that
bound is reached. It expands arms lazily into the global 1024-handler budget;
a large table does not allocate one arm array per site or stop module decoding.
Further in-loop dispatch functions stay out under `dispatch-neighborhood`.
Selector numbers remain `inferred` and local to one `br_table`. Default and
`call_indirect` arms stay `unknown`. An observed sample binds an opcode only
when that number appears on one static arm; a repeated selector stays unbound.

`captured_module_preview` is still the one dispatch instruction shared by the
most retained arms, then the lowest module offset. When no runtime snapshot was
retained, guest-byte traversal does not start. The frontier reason is
`static-module-only`, and coverage records `static-module-dispatch` beside
`sampler-unavailable` and `snapshot-bytes-unavailable` when those absences
apply. Module offsets are not a guest PC, and characterized bytes stay zero.

## Retained guest-byte coverage

`coverage.handler_count` remains a separate table count. The progress fraction is
`characterized_bytes / retained_snapshot_bytes`, or zero without retained
bytes. `uncharacterized_bytes` is the remainder. The denominator counts only
verified snapshot previews, at most 4096 bytes per snapshot and 16 snapshots.
It is not the original allocation size, opcode count, or runtime execution
coverage.

Attributions name their snapshot artifact, byte offset, byte size, opcode,
opcode/operand role and evidence class. Byte counts are the union of retained
ranges within each artifact; repeated ranges do not increase coverage. Ranges
past the preview are rejected and named, never counted as retained bytes.
The producer retains at most 4096 attribution records; `attribution-limit`
names further omissions, while the v2 schema's larger envelope remains stable.
The UI independently checks opcode bytes, nonoverlapping instruction spans,
operand boundaries and union counts before accepting a document.

Complete byte coverage requires nonempty retained bytes, zero uncharacterized
bytes, no omissions, and no residual unknowns. A 100% retained-byte fraction
can still be partial when the snapshot was truncated or an unknown remains.
`uncharacterized-bytecode`, `snapshot-preview-truncated`,
`snapshot-bytes-unavailable` and `attribution-outside-preview` make those gaps
visible. A static-only initializer retains its distinct omission instead of
also being described as an absent runtime snapshot. No source decoder, native
instruction-index mapping or missing operand layout is invented for coverage.

## Declarative owned effects

The producer attaches bounded effect rows only for the exact full source hashes
of the repository-owned [declarations](../tools/fixtures/vm-workspace-effects/README.md).
Their closed vocabulary describes operands, declared reads/writes, control flow,
and optional atomic/superoperator spans. It contains no expression, script,
import, decoder, evaluator, or arbitrary identifier execution surface. Operand
bytes use only the explicitly owned unsigned little-endian layout; null sizes,
locations, indices and values remain unknown. Static operand-width guesses and
changed snapshot cells are never substituted for missing declarations.

The byte-encoded fixtures declare a literal one-byte opcode and a code encoding.
Only reachable instruction and operand spans are attributed; unknown opcodes,
layouts or truncated instructions stop the corresponding path. This is
structural characterization, not execution coverage. Native reference fixtures
retain instruction-index units and null byte layouts, so they cannot contribute
byte attribution. Inferred effects remain inferred even when the handler has an
observed dispatch sample. Distinct incompatible effect rows are retained; a
contradicted row or inconsistent known meanings prevents choosing one meaning.
Unknown atomic groups and fused instructions stay null.

The effects panel exposes every row's evidence class, operand layout, access
sets and flow without interpreting captured code. All retained declarations are
reachable through 32-row pages; paging does not change the bounded document.
`tools/check-owned-vm-helper.py` verifies native declarations against the same
independent fixed-fixture transition goldens used by the native semantics check.

## Reachable instruction graph

Byte traversal starts only at a source-bound declared byte entry for each joined
snapshot. Native instruction-index samples never supply entry positions. The
walker follows fallthrough, both conditional branches, literal/operand targets,
and calls plus their possible continuation. It does not evaluate predicates,
execute captured code or modules, infer call-stack returns, or run a site decoder.
Unsigned little-endian target operands must fit uint32; unknown/indirect targets
are retained as null edges with `unknown-target` frontier entries.

Each artifact/byte position is visited once; cycles do not imply runtime
termination. Instruction spans cannot overlap. Unknown opcodes, missing layouts,
conflicting effects, truncated instructions, unavailable snapshots, out-of-range
targets, and preview gaps name their frontier reason. All skipped snapshots and
truncated tails keep the graph partial even when a retained prefix reaches halt.
Limits are 16 entries, 4096 instructions, 8192 edges, and 256 frontier rows; a
limit is explicit rather than silently reported complete. A complete graph may
still leave unreachable retained bytes uncharacterized, and sample/analysis
omissions independently keep byte coverage partial.

The UI renders static instruction positions and outgoing edges, followed by the
unresolved frontier. Instruction positions use 32-row pages that expose the full
bounded graph without changing the document. Frontend validation
checks opcode bytes, effect identity, exact implied outgoing edges, nonoverlap,
reachability from entries, complete snapshot entries and resolved destinations.

## Caller-supplied report fallback

The [caller report writer](vm-dispatch-input-v1.md) provides a bounded local
analysis-only import path. Its `vm_dispatch_report` records are not native
`vm_dispatch_sample` events. Optional sample `provenance` preserves the exact
`caller-supplied` source and input/artifact digests; unknown sources fail closed.
Caller reports count toward retained samples but cannot promote a handler,
validate PC units or establish invocation/host parentage. They keep
`caller-samples-unverified`; without native samples the existing native sampler
and host-link omissions also remain. Mixed reports never promote caller-only
opcodes. The UI labels their positions and exposes their provenance audit.
