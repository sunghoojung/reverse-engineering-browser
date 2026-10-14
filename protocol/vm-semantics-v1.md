# VM execution semantics v1

Status: bounded offline supplied-evidence workflow, inside Traffic → VM findings.
This does not install a native guest-interpreter capture hook. Existing VM
candidate detection remains unchanged. No captured code is executed.

## Input and identity

Import `reb-vm-trace-v1` JSON, at most 1 MiB and 256 steps. Unknown fields and
duplicate JSON keys are refused. Numeric tokens must be canonical safe integers: no exponent/fraction spellings, negative zero, overflow or rounding. Identity is exactly `trace_id`,
`investigation_id`, `finding_id`, `artifact_id`, `artifact_sha256`, `scope_id`,
and `backend`. IDs use 1–128 ASCII letters/digits/underscore/dot/colon/hyphen;
SHA-256 is 64 lowercase hex characters. Backend is fixture/native/cdp/external.
These are supplied claims, not proof of source authenticity or an existing
artifact linkage. The CLI separately hashes the exact input bytes.

Architecture is stack/register. Coverage contains boolean complete,
nonnegative safe-integer dropped_steps, and at most 16 limitation strings of
256 UTF-16 units each. Complete coverage cannot claim dropped steps or gaps.
This describes retained trace continuity, not total program behavior.

A step has exactly sequence (nonnegative safe integer), opcode (1–8 bytes of
lowercase hex), operands (0–8 signed int32 values), instruction_size (1–64 supplied PC units), before, after and evidence_refs (1–8 bounded IDs).
PC units are capture-adapter-defined, not assumed source-byte offsets.
Operands are already-decoded supplied values: their byte layout and actual
operand-read provenance remain unknown. IDs must be strictly increasing.
Consecutive sequence IDs require identical adjacent after/before state; gaps
are allowed only with incomplete coverage. A halted state cannot execute.

State has pc (0–65535), halted (boolean), registers (at most 64 values), stack
(at most 128), and memory (at most 256 sorted unique [address,value] pairs).
Addresses are 0–65535. Values are signed int32 or null (unknown). An absent
memory cell is unknown, never assumed zero. Array absence and unknown cells
remain distinguished in change reports. Snapshot differences establish changed
state, not reads, intermediate writes or causal dependence. Raw arbitrary host
memory, strings, object graphs, pointers and credentials are outside this schema.

## Declarative hypotheses

`reb-vm-hypothesis-v1` contains exact trace_id and at most 256 unique mappings,
each exactly opcode and operation. Opcodes must occur in the trace. Supported
operations and ordered operand conventions:

| Operation | Operands | Effect |
|---|---|---|
| stack_const | value | Push value, advance PC |
| stack_add | none | Pop right/left, push int32 modular sum, advance |
| register_const | destination, value | Write register, advance |
| register_add | destination, left register, right register | Modular sum, advance |
| load | destination register, memory address | Read known cell, write register, advance |
| store | memory address, source register | Write known register value, advance |
| jump | target PC | Set PC |
| branch_zero | condition register, target PC | Branch if known zero, else advance |
| halt | none | Set halted, preserve PC |

Advance means before.pc + instruction_size; overflowing the PC bound is
unsupported. Stack/register arithmetic operations require matching architecture.
Unknown reads, invalid register/address/arity or unsupported semantics return
unsupported, without fabricating a prediction. Arithmetic uses two's-complement
modulo 2^32; this is a hypothesis, not a universal VM rule. No expressions,
JavaScript source, resolver calls or dynamic plugins are accepted.

## Linked snapshot model

The shared offline model exports `step(trace, sequence)`,
`compareSteps(leftTrace, leftSequence, rightTrace, rightSequence)`, and
`occurrences(trace, location, page = 0, pageSize = 16)`. Every entry point
validates the complete bounded trace. Sequence arguments are exact numeric
nonnegative safe integers, excluding negative zero; strings, missing IDs and
out-of-range indexes are refused rather than coerced, clamped or aligned.
The sequence is the retained execution ID, never an array index or PC value.

`step` returns `reb-vm-step-v1`: exact identity, architecture, coverage, the
original retained `step`, legacy `changes`, `evidence_refs`, `reads: "unknown"`,
warnings and `equivalence_proven: false`. `previous_sequence` and
`next_sequence` identify neighboring retained steps, with null at either edge.
They can span gaps; the report warns about retained gaps and incomplete
coverage. It never fabricates intervening execution.

The `cells` array includes all locations present in either selected snapshot,
including unchanged and unknown values. Exact namespaces are `pc`, `halted`,
`registers:N` (0–63), `stack:N` (0–127), and `memory:N` (0–65535), in that order
with numeric index ordering. Indices use canonical decimal spelling. Register,
stack and memory index 0 remain three different locations. Unobserved addresses
are not enumerated as a zero-filled memory image. A step has at most 706 cells:
two scalars, 64 registers, 128 stack slots and the union of two 256-cell memory
snapshots. None of these recorded locations are silently truncated.

Each cell contains `location`, `before: {present, value}`,
`after: {present, value}`, `changed` and `status`. Present null is unknown;
absent is `{present: false, value: null}`; known zero is
`{present: true, value: 0}`. Scalars are always present. `changed` records a
snapshot representation difference, including changed presence or a known/
unknown transition. It does not assert a read or a write. `status` is:

- `observed_equal`: both sides are present with known, exactly equal values.
- `different`: presence differs, or both present known values differ. A
  presence difference describes available evidence, not an inferred value.
- `unknown`: either present value is null, or both locations are absent.

Equal unknown values and matching absence never establish value equality.
These statuses describe supplied observations, not proven semantics.

`compareSteps` returns `reb-vm-step-comparison-v1` with the complete selected
`left` and `right` step reports, warnings, `equivalence_proven: false`, and
`cells` over their exact location union. Every comparison cell contains
`location`, `left_before`, `left_after`, `right_before`, `right_after`,
`before_status`, `after_status`, and `status`. The four snapshots use the same
present/value structure. Boundary statuses compare left with right;
the combined status is different if either boundary differs, otherwise unknown
if either is unknown, otherwise observed_equal. Identity, coverage and evidence
references remain separate in each selected side. Different architectures are
allowed with an explicit warning. Names and indices do not prove that runtime
storage corresponds. Differences in supplied investigation, finding, artifact
ID/hash or scope produce an explicit cross-source warning. PC and instruction
size units are adapter-defined and may differ between traces. Matching identity
claims, artifact hashes or exact input-file hashes cannot establish alignment.
There is no automatic sequence, opcode, PC, instruction or location alignment
and no whole-trace equivalence claim. The comparison includes at most 1,218
locations (four disjoint 256-cell memory snapshots plus arrays and scalars).

`occurrences` returns `reb-vm-location-occurrences-v1` with identity,
architecture, coverage, exact `location`, `items`, `total`, `page`,
`page_size`, `next_page`, page-local `evidence_refs`, unknown reads, warnings
and `equivalence_proven: false`. An item is a retained step where that exact
location is present before or after, including unchanged/unknown observations.
Items contain sequence, opcode, before, after, changed, status and evidence_refs.
Pages are zero-based; page sizes are 1–64 and the page offset must be a safe
integer. Invalid locations or pagination are refused. A valid location with
no retained occurrence and pages past the end return empty items, never a
neighboring location or step. `total` is at most 256; `next_page` is null at
the end. Occurrences are snapshot observations, not accesses or reads.

## Reports and agent CLI

`node tools/vm-semantics.mjs inspect TRACE.json OUTPUT.json` lists exact identity,
coverage, steps, changed cells, observed PC edges and candidate operations.
Candidate operations are those fitting every retained observation for that
opcode under the fixed operand convention. Multiple candidates remain ambiguous;
no candidate is unknown. Neither outcome proves semantics.

`node tools/vm-semantics.mjs step TRACE.json SEQUENCE OUTPUT.json` returns one
exact retained state transition, including evidence references.

`node tools/vm-semantics.mjs compare LEFT.json LEFT_SEQUENCE RIGHT.json RIGHT_SEQUENCE OUTPUT.json`
compares two explicitly selected retained steps through the shared linked model.
Its envelope is exactly `left_source_sha256`, `right_source_sha256`, and `result`.
The two source hashes cover the exact input file bytes and remain distinct from
each trace's supplied artifact identity. Sequences use canonical nonnegative
decimal safe integers and are selected independently, with no inferred alignment.
Both traces independently satisfy the 1 MiB and 256-step input bounds.
The existing inspect, step and validate CLI report shapes remain unchanged;
the legacy CLI step command projects its fields from the shared step model.

`node tools/vm-semantics.mjs validate TRACE.json HYPOTHESES.json OUTPUT.json`
compares declarative predictions to each entire supplied after-state. Outcomes:
matched, contradicted, unsupported or unknown (no mapping). Counterexamples
include expected/observed states. Reports always set equivalence_proven:false.
Passes cover only supplied cases, not an unobserved branch or complete program.

All CLI commands require regular nonsymlink UTF-8 JSON files, never connect to
a browser or endpoint, and create a new private output atomically. Existing
paths are never replaced. Reports are capped at 4 MiB and include exact source
and hypothesis hashes where applicable. Treat reports as local capture-sensitive
data; exporting them needs the same review as their input.

## UI and validation

The existing VM view contains an explicit file import, a step selector,
register/stack/memory before/after view, opcode candidates and separate explicit
hypothesis validation. It does not synthesize findings into the existing list.
Malformed input preserves the last valid trace. Clear invalidates pending reads;
newer hypothesis imports own their result. Captured text is never HTML.

`node tools/check-vm-semantics.mjs` uses independently implemented owned stack
and register interpreters, all nine operations, wrong hypotheses, unknown state,
continuity/gap failures, bounds, overflow and the real CLI. The existing rendered
Traffic browser gate additionally exercises this view's import/keyboard/layout
path. Native capture and vendor/protected-VM support require separate reviewed
adapters and golden differential tests; neither is asserted by this contract.

`node tools/check-vm-linked-model.mjs` independently authored snapshots verify
exact sequence selection, namespace isolation, complete state cells,
unknown/absent/zero distinctions, manual comparison, identity and evidence
retention, occurrence bounds/pagination, malformed inputs and input immutability.

The UI bounds visible location rows to 64 per page for selected states and
manual comparisons. It exposes the visible range, filtered/recorded totals and
explicit previous/next controls; no cells are removed from model reports or
collapsed raw audits. Opcode groups, support links, validation links and hypothesis mismatch rows also
use 64-item pages; occurrence pages show 16 items. Paging preserves the selected
exact step and location and restores focus to a usable page control. Support
navigation brings a retained selected location onto its page when the active
filter includes it; otherwise the UI explicitly labels it hidden/absent.
Counterexample navigation shows all locations and reveals/focuses its first
observed mismatch, or focuses the step heading if that location is absent.
