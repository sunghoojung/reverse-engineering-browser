# Contextual VM runtime evidence v1

Status: bounded offline supplied-observation linkage. This is not a native
capture format, recorder, authenticity claim, vendor decoder or execution tool.
Use only observations and fixtures from authorized research. No capture hooks,
secret extraction, evaluation, persistence or uploads are introduced.

## API and strict boundary

Load `captured_client.js`, `vm_contextual.js`, then
[`vm_contextual_evidence.js`](../apps/research-ui/vm_contextual_evidence.js).
The browser global is `vmContextualEvidence`; CommonJS exports the same API:

- `parseEvidence(input)` validates JSON text or a plain JSON-data object and
  returns an independent copy.
- `await link(definition, image, evidence, options = {})` freshly calls contextual
  `analyze` and requires an exact match of all five identity fields. Options are
  the contextual decoder's `max_instructions` only. An imported analysis report
  cannot substitute for the definition/image inputs.

The [contextual decoder contract](vm-contextual-v1.md) defines identifiers,
canonical identity, symbolic decoder states and contextual instruction IDs.
Evidence input is limited to 1 MiB serialized UTF-8, 50,000 structural nodes,
16 nesting levels, 4096 events and 256 gaps, whichever bound is reached first.
Exact aggregate JSON UTF-8 bytes are checked incrementally while copying,
before any full-document serialization. Duplicate keys, unknown fields, noncanonical integer tokens,
unsafe integers, negative zero, getters, hidden properties, custom prototypes,
symbols, sparse arrays, non-JSON values and cycles are rejected. Untrusted text
is never evaluated and consumers must render all values as text, not HTML.

## Evidence input

Every object has exactly the fields shown; none are optional:

- `format`: `reb-vm-contextual-evidence-v1`.
- `identity`: exact `build_id`, `definition_id`, `image_id`,
  `image_bytes_sha256`, `definition_canonical_sha256` from fresh analysis.
- `capture_id`, `run_id`, `context_id`: nonempty identifiers scoping every event
  to one explicitly supplied capture, run and VM execution context. Mixing
  contexts/runs requires separate documents, never ID guessing or timestamp joins.
- `mapping_provenance`: `{kind:"supplied",reference:<identifier>}` naming the
  researcher's mapping provenance. This does not authenticate the mapping.
- `events`: ordered array of the following records.
- `gaps`: ordered, nonoverlapping explicit loss declarations.

An event has `event_id` (unique within the document), `sequence` (strictly
increasing safe nonnegative integer), `kind` (`step` or `jump`), `pc` (0–65535
byte offset), `decoder_state` (identifier or null), `raw_opcode` (one or two
lowercase hex bytes), and `to`. A step's `to` is null; a jump's `to` is exactly
`{pc,decoder_state}`, using the same bounds. A jump is an explicit supplied
observation of a transition, not an inference from adjacent steps. In particular,
null state is unknown and never the literal string `null`.

A gap is `{after_sequence,missing_count}`. Both are safe nonnegative integers;
missing count must be positive and their sum safe. The missing interval is
`(after_sequence, after_sequence+missing_count]`. Intervals cannot overlap or
contain a retained event. A declared gap may extend beyond the retained tail.
Detected sequence holes and explicit gaps are separately reported; they may
refer to the same loss and must not be summed as unique missing events. The
first retained sequence does not imply recording started at zero; absent
prefix/tail evidence remains unknown.

## Linkage and observed overlay

Output format is `reb-vm-contextual-evidence-analysis-v1`, with `analysis`,
`evidence`, `links`, `observed_edges`, `diagnostics`, `complete:false`, `warnings`.
The analysis and evidence are fresh independent data. Every link or edge is
local to this report and must be retained together with its full identity.
Matching labels alone across reports does not establish linkage.

A link has `event_id`, `sequence`, `instruction_id` (context ID or null), and
`status`. `linked` requires matching PC, known state, exact opcode width/bytes,
and an instruction present in the freshly decoded report. Other statuses are
`out_of_range`, `unknown_state`, `opcode_mismatch`, `not_decoded`, or the
contextual decoder's terminal diagnostic (`unknown_mapping`,
`truncated_instruction`, `invalid_operand`, `instruction_budget`). Observed
contexts never seed decoding or infer absent mappings/states. Adjust entries in
the supplied image explicitly to decode a context not otherwise visited.

Each explicit jump yields one separately labeled overlay record:

- `event_id`, `sequence`, `capture_id`, `run_id`, `context_id`,
  `mapping_provenance` preserve the observation's provenance.
- `from_instruction_id`, `from_offset`, `from_decoder_state`, `from_status`
  describe source linkage; the corresponding `to_*` fields describe destination.
- `kind:"observed_jump"`, `evidence:"supplied_runtime"` distinguish the overlay
  from all declared static edges.
- `status:"observed"` means the source linked; `unlinked` means it did not.
  Neither authenticates capture. An unresolved destination remains null even
  when the source links. Consumers must not attach unlinked sources to CFG nodes.
- `declared_relation` is `matches_declared` for an exact declared destination
  PC and known state, `unresolved_declared` if declared target/state is unknown,
  `differs_from_declared` for disagreement, or `unknown` for an unlinked source
  or unknown observed destination state. This is comparison, not semantic proof.

The destination is a contextual address reference, not an independent claim
that its opcode executed: only the source event carries observed opcode bytes.
Declared CFG nodes, edges, coverage and pseudocode are never mutated. Dynamic
static targets stay unknown even when an overlay shows one supplied observation.
No edge is derived from adjacency, bridged over gaps, or generalized to another
run. No unobserved path or handler is labeled unreachable, false or a decoy.

Diagnostics include unlinked event reasons, detected `sequence_gap` intervals,
and explicit `reported_gap` intervals. `complete` always remains false, even
with contiguous retained events and full byte decoding. Hashes establish input
identity, not authenticity, permission, capture completeness or equivalence.

## Validation and authored example

`node tools/check-vm-contextual-evidence.mjs` checks strict parsing, full identity
mismatches, multiple contexts at one PC, unknown states, dynamic targets,
source byte mismatches, instruction budgets, explicit and detected gaps, and
separation of declared and observed paths.

[`tools/fixtures/vm-contextual/`](../tools/fixtures/vm-contextual/) contains
`definition.json`, `image.json` and `evidence.json`: a deliberately authored
three-byte example, not a captured vendor artifact. A declared dynamic jump
remains unresolved while a supplied jump observation references a separately
seeded halt context. The unused middle byte is not classified as dead or decoy.
