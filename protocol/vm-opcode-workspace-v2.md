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
without static handlers. `samples` retains the first 4096 in input order; further
accepted samples still count and add `sample-limit`. Handler counts include only
the accepted samples of that opcode; document counts sum workspace counts.
Unmatched opcodes stay in samples and residual unknowns. No accepted samples
produces `sampler-unavailable`, preserving static handler candidates.

## Native browser capability boundary

The tracked Brave overlay currently declares the `vm_finding` and
`vm_dispatch_sample` ABIs but has no producer of guest invocation markers or
guest dispatch samples. Its runtime source and typed-array checkpoint capture
are not a guest instruction trace. Canvas observations, a detected dispatch
loop, a high static score, a Wasm dispatch instruction and a retained buffer
cannot establish which guest opcode ran or its program counter. More of those
records cannot fill the missing runtime channel.

A workspace with no admitted samples retains static handlers and the explicit
`sampler-unavailable` omission with this distinction. The host-links report
keeps `guest_position` null and `dispatch-samples-unavailable`. The owned fixture
below demonstrates the transport/consumer contract only, not support for a
captured JavaScript or Wasm interpreter. Merely rebuilding the existing overlay
will not add the missing emitter.

A future native adapter must first establish exact captured interpreter and
bytecode identities, invocation boundaries, PC units and the observed dispatch
site. It must emit bounded, opt-in, non-blocking records with explicit losses,
retain native host-call parentage, and remain allocation-free while inactive.
It must not infer an instruction-index PC from a source offset, static switch
case, host call, shared frame, request ID, URL or time proximity. The arbitrary
JavaScript/Wasm runtime does not expose a universal guest PC; interpreter-specific
semantics require a separately reviewed implementation, not enabling a flag.

Acceptance requires pinned native patch replay and compilation, disabled,
expired, full-queue and teardown regressions, and a rebuilt-browser run against
an owned known interpreter with expected PC/opcode/invocation sequences and
exact host-parent links. The fixture differential tests and a static component
compile are necessary but cannot substitute for this browser-runtime evidence.
Until that adapter and acceptance exist, missing live guest positions remain
an open capability gap, not a successful empty trace.

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
