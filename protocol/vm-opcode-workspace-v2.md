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

Native Wasm workspaces keep three separate streams. `sample_count` covers only
the `samples` records above. `native_wasm_observation_count` counts physical
`br_table` executions and `native_guest_sample_count` counts adapter-interpreted
guest samples, with matching per-handler `native_wasm_sample_count` and
`native_guest_sample_count`. V8 emits both a physical observation and a guest
sample for one execution at an adapter dispatch site, so the two native counts
overlap and are never added together or into `sample_count`. A consumer that
needs a lower bound on distinct executions at one handler uses the largest of
the three counts. Producers before 2.7.0 summed all three into `sample_count`;
consumers read those documents with that older arithmetic.

Producer 2.14.0 adds a fourth native stream to every Wasm workspace.
`native_wasm_indirect_observations` keeps at most 4096 accepted
`wasm_indirect_observation` rows and `native_wasm_indirect_observation_count`
counts every accepted one; `native-wasm-indirect-observation-limit` names the
rest and `native-wasm-indirect-observation-invalid` counts rejected records.
A row names the exact `call_indirect` or `return_call_indirect` instruction
(function, module byte offset and its table immediate), the dynamic `slot`, the
`resolution` of the table entry the call was about to use (`resolved`, `null`,
`out-of-bounds`, `foreign` or `unresolved`) and, only when resolved, the callee
function index in this module. A slot is not a guest opcode. These rows never
change a handler row or `sample_count`. See
[native Wasm dispatch](native-wasm-dispatch-v1.md#call_indirect-observations).

Each `native_wasm_observations` and `native_guest_samples` row carries
`monotonic_time_ns`, the accepted native event's monotonic time as a canonical
unsigned decimal string, like the other 64-bit identifiers. A consumer can show
when a retained row happened after its event has left the bounded event window.
The field is optional: producers before 2.8.0 omit it, and their documents stay
valid.

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

## Universal VM shape

Protection VMs differ in bytecode. The pieces a researcher can ask about stay
the same:

1. Guest program. The bytecode or word stream the dispatcher reads.
2. Virtual PC. The guest position of the current word, in that program's units.
3. Dispatcher and handler table. An opcode or selector chooses a handler-table
   entry.
4. Machine state. A stack, registers, or both.
5. Host bridge. Imports or JavaScript builtins the guest calls.

A static `br_table`, JavaScript `switch`, or `call_indirect` is only piece 3
until something proves the others. Arm count is not an ISA size. This producer
does not assume a fixed opcode cardinality and does not score site names.

## Evidence class

`evidence_class` is one closed claim about a workspace. The same vocabulary,
except `guest-opcode-isa`, labels each static dispatch candidate. A candidate
is never a proven guest ISA.

| Class | What it claims |
| --- | --- |
| `guest-opcode-isa` | A retained sample whose units are `instruction-index` or `byte-offset` binds one opcode to one handler, or an exact-hash owned effect declaration does. Repeated selectors and `unknown` PC units do not. |
| `handler-table-candidate` | Static selector arms map to entries: a `br_table` with at least 32 explicit arms, or integer JavaScript cases. Not a guest ISA. |
| `call-indirect-table` | A `call_indirect` or an element/funcref segment. Targets are not guest opcodes. `arm_count` stays null when the selected entry is dynamic. |
| `cff-helper` | A `br_table` with fewer than 32 explicit arms. Ranking demotes it behind larger in-loop tables. Not a guest ISA. |

The 32-arm cutoff is the major-table rank from dispatch inventory v1. It
separates small state-machine helpers from larger static tables. It is not a
claim that a VM has 32 opcodes. A table of 100 or more arms and an 11-arm
helper fall on opposite sides of that cutoff. The larger site stays
`handler-table-candidate` until samples or owned effects prove a guest ISA.

`sampler-unavailable` and `static-module-only` stay an omission and a frontier
reason. They are not evidence classes. A static-only workspace keeps unknown
guest PCs. `model` stays `stack`, `register`, or `unknown`. `unknown` means
stack or registers are unproven. `machine_state.register_count` and
`machine_state.stack_observed` appear only when effect cells name those
spaces. A null register index does not invent a register file. Spelling in a
page script does not fill `machine_state`.

`handler_tables` keeps the top 8 ranked dispatch sites and up to 4 element
tables. Each `br_table` records an exact `arm_count` and clusters selectors
that share a label depth. `selector_count` is exact. `selectors` lists at most
32 indexes, so a prefix is not a shorter table. The flat handler list is still
capped at 1024 and still emits the ranked site first. Element clusters group
duplicate funcref slots. They are `call-indirect-table`, not opcodes.

Element selectors are real table slots. Producer 2.9.0 places each active
segment at its evaluated offset (`i32.const`, a defined immutable constant
global, or extended-const arithmetic over them), in segment order, so a later
segment overwrites an earlier slot and a segment at offset 1 starts at slot 1.
Earlier producers numbered slots from 0 across the merged segment list, which
shifted every slot of an offset segment. `segments` lists each active segment
with `placement` `placed`, `relative` (the offset reads an imported global,
directly or through a defined global, so its slots are unknown and are not
clustered), `out-of-range` (the segment ends past the table's declared
minimum, so it is not placed), `unreached` (an earlier segment is out of
range, so instantiation traps before applying this one) or `unresolved`. At
most 64 segments are listed; `omitted_segment_count` counts the rest. Passive
and declared segments fill no table and are not listed. `entry_count` counts placed slots whose
function is statically known; a `ref.null` item empties a slot and any other
non-`ref.func` item leaves the slot's function unknown. A table whose placed
slots exceed 1,000,000 is not expanded into a handler table or matching slots;
the workspace counts such tables in an `element-table-limit` omission.

## Dispatch classification

Producer 2.9.0 copies the analysis result's
[`dispatch_classification`](vm-dispatch-classification-v1.md) onto each
workspace. Only `interpreter-candidate` sites, a cursor-like selector re-derived
in a loop or each step of a threaded chain or cycle, can carry guest-opcode
claims:

- JavaScript handler recovery is unchanged and alone decides tier and score.
  The opcode-claim gate is a post-filter on its handlers: a switch case
  survives only at an interpreter-candidate switch, a table entry only when the
  region (nested functions included) dispatches through that table's own
  binding at an interpreter-candidate site, including from the table's own
  handlers or through a self call `h = h(s)` tied to it. The gate resolves a table name to
  its declaring function scope, so a nested function's own `ops` is a
  different table. Each removed claim adds why: a router, a site that is not a
  cursor-advancing loop, a table with no structural classification, a table
  binding that cannot be resolved with certainty, or a site not classified
  because of the work limit.
- The gate reads the full classification from the same metered run that
  produced the analysis, not the 256 listed sites and not a second pass.
- When the gate removes handlers, the workspace records the `handler-withheld`
  omission with their count instead of `handler-unavailable`, and the analysis
  keeps the tier recovery decided.
- Wasm arms keep their physical selector indexes. A retained sample proves
  `guest-opcode-isa` through an arm only when the arm's site is an interpreter
  candidate. A residual unknown counts retained sites that are not.
- Older documents without the field keep their original rules.

The viewer recomputes each site's role from its three fields, so a document
cannot assert an interpreter role its structure does not support.

A workspace with no recovered arms omits `evidence_class`. That absence is not
a guest ISA and not an empty workspace; `handler-unavailable` still names the gap.

### Worked static module

A static pass over one captured module
(`sha256 b9613db05423e4f5619fe2bd69ccc55fb6eb4ae7fa362731ad38aee4e2ad5c94`)
counted 731 `br_table` sites, 47 of them with at least 100 explicit arms. The
largest were function 248 (747 labeled arms, 742 unique targets), function 631
(746), and function 703 (599). One funcref table had 170 slots and 153 unique
functions. No plaintext guest bytecode stream was present, and no guest opcode
ISA was proven. For that binary the five pieces were: guest program absent as
plaintext, virtual PC unproven, handler table present as Wasm dispatch
surfaces rather than opcode-to-handler, stack or registers unproven, host
imports present.

Those counts are an honesty example. Scoring does not look for a site name, a
hash, or an opcode count of 11, 100, or 747. The same ladder on that shape
ranks each ≥100-arm site ahead of an 11-arm helper, labels the large sites
`handler-table-candidate`, the small site `cff-helper`, and the funcref table
`call-indirect-table`, and refuses `guest-opcode-isa`. The module bytes are
not in this repository. Producer version 2.5.0 emits the class.

## Observed claims and nested guests

Producer 2.12.0 adds two optional fields that interpret retained runtime rows.
Neither changes a handler row, a sample, the evidence class, the tier or the
score. Both are derived only from rows retained in the same document, so every
event identity they name resolves to a row the viewer already holds. When a
stream's 4096-row retention limit is reached, claims cover only the retained
prefix and the existing limit omission names the rest.

`observed_claims` lists at most 256 claims. One claim aggregates the retained
rows of one stream that agree on site, selector, opcode and handler. Its
`confidence` is always `observed`, never `structural`. A claim exists only at
an interpreter-candidate site of the same metered classification:

| `stream` | Rows | Site | Selector | Opcode | Handler |
| --- | --- | --- | --- | --- | --- |
| `native-guest` | `native_guest_samples` | `exact` function and module offset | br_table selector | opcode the adapter decoded from the guest snapshot | `br-table-arm` |
| `native-wasm` | `native_wasm_observations` | `exact` | br_table selector | null; a selector is not a guest opcode | `br-table-arm` |
| `native-wasm-indirect` | `resolved` rows of `native_wasm_indirect_observations` | `exact` | table slot | null | `table-entry`: table and callee function |
| `dispatch-sample` | native JavaScript `samples` | `sole-interpreter-candidate` or `artifact` | null | sampled opcode | `handler-index`, the sampler's selected handler |

A JavaScript dispatch sample names its interpreter artifact, not a dispatch
site. Its claims attach only when the artifact has an interpreter-candidate
site. They name that site only when the complete classification (no omission
other than `handler-binding-unproven`) has exactly one; otherwise the site is
null and attribution is `artifact`. WebAssembly claims need an exact site, so
Wasm `vm_dispatch_sample` rows and caller reports never become claims.

`events` lists the first 8 supporting event identities in row order and
`sample_count` counts every supporting retained row. `static_claim` compares
the claim with the unchanged static claim and is recomputed by the viewer:

- JavaScript: the surviving handler row for the same opcode `agrees` when it
  names the observed handler (a table entry's `handler_index`, or a switch
  case's own value) and `disagrees` otherwise. With no surviving row, an opcode
  that recovery found and the claim gate removed is `withheld`; any other is
  `absent`.
- WebAssembly: the static row for the observed arm (same site, `opcode` equal
  to the selector) `agrees` when the guest opcode equals that selector and
  `disagrees` when the adapter decoded another guest opcode for the same arm,
  as with a masked or decoded opcode stream. A physical observation names no
  opcode and only agrees. A default arm and an arm outside the retained
  neighborhood or handler budget have no static opcode claim and are `absent`.

- WebAssembly `call_indirect` (producer 2.14.0): the static claim is the
  element segments' entry for the observed slot of the site's table, from the
  same metered table layout as `handler_tables`. A placed function `agrees`
  when it is the observed callee and `disagrees` otherwise; a placed null slot
  that ran a function `disagrees`. `opcode` is the slot, `handler_index` the
  placed function (null for a null slot) and `byte_offset` the site. A table
  filled at run time, through a relative, unresolved or passive segment or an
  unexpanded oversized table, or an entry whose function is not statically
  known, is `withheld` for an unplaced slot. Any other unplaced slot is
  `absent`. The viewer checks the comparison for consistency and against every
  listed element cluster that holds the slot, since clusters list at most 32
  slots.

A disagreement never edits either claim. It adds one residual unknown that
counts the disagreeing claims, so coverage stays incomplete. Rows that cannot
supply a claim stay retained and are counted: `observed-claims-not-interpreter`
for native rows at a site that is not a classified interpreter candidate,
`observed-claims-unresolved-callee` for `call_indirect` rows whose entry was
null, out of bounds, from another instance or unresolved,
`observed-claims-unsited` for dispatch samples without a usable site, and
`observed-claim-limit` past 256 claims.

`nested_guests` is a WebAssembly-only list of at most 64 inner interpreters.
A native guest activation becomes a nested guest when its invocation marker
names a nonzero `parent_invocation_id` whose rows are retained here, and both
activations share session, process, renderer thread and instance, the parent
began first, both sites are interpreter candidates, the child runs at another
dispatch site, and the child's first guest buffer (memory, base, length)
differs from the outer dispatch's. A child at the parent's own site is a
reentrant activation of one dispatcher, such as a guest call, and is not
nested. The outer handler is the parent's last retained dispatch sample before
the child's invocation marker. `basis` is `contiguous-sequence` when every
renderer sequence number between them is retained and none is a gap or another
guest dispatch; otherwise it is `nearest-retained`, which does not prove the
exact driving dispatch. A window longer than 4096, or past 65536 lookups shared
by the workspace, is not scanned and stays `nearest-retained`. The inner side lists its own observed
opcodes (at most 64, with `omitted_opcode_count`) and its retained samples.
Other activations that name a parent are counted as `nested-guest-unproven`;
`nested-guest-limit` counts nested guests past 64.

Live capture does not produce nested guests yet. The renderer writes
`parent_invocation_id` 0 (nesting not asserted), and one adapter covers one
dispatch site per browser lifetime, so an inner interpreter at another site is
not guest-captured. JavaScript samplers record no dispatch site, handler
location or call stack. The analyzer path is exercised with owned synthetic
programs in `vm_opcode_observed.rs`; its exported store backs the rendered VM
Lab acceptance.

VM Lab shows both lists on a Runtime claims tab. A contradicting claim keeps
both statements and an amber rule; each nested guest names the inner site,
invocation and buffer, the outer site, handler and dispatch event, and its
basis. The tab appears only when the workspace carries claims, nested guests
or a claim omission.

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
explicit `br_table` targets, excluding the default, and is null for
`call_indirect`. `unique_target_count` is the number of distinct Wasm label
targets for a `br_table`, including the default, so repeated arms cluster; it
is null for `call_indirect`. `element_fanout` counts static funcref initializers
in active element segments for that `call_indirect` table. It is null when that
table has no active segment, when the segment is passive or declarative, or
when the site is a `br_table`. Fanout does not fill in `arm_count`. Owned
fixtures and live captures use these same fields.

Ranking v1 orders in-loop sites before non-loop sites, then sites whose scale is
at least 32, that scale, function structural score, IP-like local/global
read/write pattern, loop depth, function body size, small-site scale, and
lowest module offset. Scale is `arm_count` for `br_table` and `element_fanout`
for `call_indirect`, or zero when fanout is unknown. `selected_byte_offset`
names the top in-loop site, or null when none exists. A `br_table` below 32
arms is `cff-helper-candidate`: a CFF or relooper candidate, not proof of CFF.
A `br_table` at or above 32 arms is `dispatch-candidate`: a handler-table
candidate from selector index to Wasm branch target. Repeated labels do not
demote that site and do not prove a guest ISA. `call_indirect` is
`indirect-handler-candidate`, a funcref-handler candidate. A proven guest
opcode ISA is not emitted from static arms. It would require guest
program-counter and bytecode-stream evidence, which this inventory does not
invent, and it does not invent registers or a guest stack. The ranking does
not increase the detector's confidence or score. A Wasm `candidate` with an
in-loop dispatch can expose a static workspace even without sufficient
independent evidence for `likely-vm`.

The UI's Dispatch sites panel lists the bounded inventory and can select an
already retained site. Each collapsed summary shows the rank, explicit arm
count and unique branch targets or the static element fanout, and one of the
three candidate labels. The ranked default row starts open. Enter or Space on
Select retained site clears a handler filter that hides that row, then selects
it. Unrelated sites remain outside the retained neighborhood; listing metadata
never expands the neighborhood or runs the module. A refresh preserves an
explicit retained-handler selection. The initial listing emits the ranked site
first, even when a smaller site occurs earlier in the same function. Static
selectors still do not prove guest opcode binding without samples.

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

Producer 2.11.0 shares the artifact classification budget with table layout and
the lexical claim gate. The gate indexes complete tokens and lexical extents,
including arrows, implicit function bindings and loop heads. Ambiguous bindings
withhold claims; budget exhaustion remains visible even if a workspace cannot
be completed. See [dispatch classification](vm-dispatch-classification-v1.md).

Producer 2.13.0 recovers function-array tables: a function or arrow
element's opcode is its position in the literal, and the gate requires the
element's AST position to match. Recovery follows a dispatched name through
plain aliases (`t = ops`) and called temporaries (`h = ops[op]; h(s)`), a
rotated selector through every one of its writes, and a selector returned by a
fetch helper. Earlier producers
recovered no handlers for these shapes, so an analysis could demote a real
interpreter to `candidate`. Its gate also keeps the handlers of a threaded
table, one whose handlers return or tail-call `ops[code[pc++]]`, when the
classification proves that chain or cycle is an interpreter candidate.

Producer 2.14.0 reads native `call_indirect` observations into
`native_wasm_indirect_observations` and derives `native-wasm-indirect` observed
claims from them. A threaded or handler-table interpreter whose table is filled
at run time, which static recovery withholds, therefore gets observed handler
claims naming the callee each slot actually ran, compared with the element
segments' claim for that slot. Static recovery, tier and score are unchanged.
