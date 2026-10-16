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
`byte-attribution-unavailable` names this limitation when bytes are present.
Traversal defaults to an `entry-unavailable` frontier and `complete:false`.
These fields never promote a handler to universally confirmed semantics.

The UI shows sampled PC with units, selected handler index and bytecode artifact
ID on each matching handler row. It displays at most four position summaries
per row and reports additional accepted/retained counts. The complete bounded
sample prefix remains in the document. Missing positions are explicitly unknown.
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
