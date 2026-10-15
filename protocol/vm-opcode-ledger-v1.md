# Opcode evidence ledger v1

The [JSON schema](vm-opcode-ledger-v1.schema.json) and
[`tools/vm-opcode-ledger.mjs`](../tools/vm-opcode-ledger.mjs) define a bounded,
offline ledger of researcher assertions about an explicit declarative VM
layout. This supplements [static decoding](vm-definition-v1.md); it does not
change opcode semantics, decode bytes again, run tests, execute code or capture
a target. Use only authorized, reviewed local material under [SAFETY](../SAFETY.md).

## Import, inspect and export

`node tools/vm-agent.mjs opcode-ledger --definition VM.json --input LEDGER.json`
validates both files and emits `reb-vm-opcode-ledger-analysis-v1` JSON to stdout.
Its `ledger` property is the validated, round-trippable import/export document.
Save that property explicitly to a new local file using your JSON tooling to
export; the command never writes files, fetches citations or contacts a backend.
`capabilities` advertises this operation separately from static and live controls.

A ledger has exactly `format: "reb-vm-opcode-ledger-v1"`, `definition_id`,
`definition_source_sha256`, and `entries`. The hash must match the exact UTF-8
bytes of the supplied definition, including whitespace. This binds a layout
revision, not a bytecode image, runtime trace or session. It is not an authenticity
or semantic-correctness attestation. Definition edits require deliberate ledger
review and rebinding; there is no automatic migration or promotion.

Each entry names one declared `opcode`, with:

- `status`: `observed`, `inferred`, or `unmodeled`. These are researcher labels,
  not independently verified facts. Observed/inferred require nonempty `meaning`
  and at least one `source_refs` citation. Unmodeled requires `meaning: null`.
- `handler_location`: null or `{artifact_id, byte_offset}`. Offset is a canonical
  safe integer from 0 through 9007199254740991, in bytes within the named artifact.
  Artifact existence, length, location and correspondence are not checked.
- `operand_format`: null or a short researcher description. The output also
  includes the existing definition's operand layout and endianness, separately;
  this note cannot override the decoder or establish runtime operand behavior.
- `source_refs` and `test_refs`: arrays of `{artifact_id, event_id}`; event ID may
  be null. IDs are unresolved researcher citations, not session-scoped identity
  or content-hash binding. They are never fetched or treated as verified evidence.
- `test_status`: `not_run`, `passed`, `failed`, or `inconclusive`. Not-run requires
  empty test refs; the others require at least one. These are supplied reports,
  not test execution or proof that the claim holds. A failed test is retained
  without silently changing the researcher status.
- `unresolved_questions`: an explicit array of short questions. No missing answer
  is filled in from a declared mnemonic, test label or apparent coverage.

## Bounds and coverage

Both files are at most 1 MiB, strict UTF-8 JSON with duplicate keys rejected.
Ledger integer tokens must be canonical nonnegative safe integers. Unknown
fields, duplicate opcode entries, undeclared opcodes, mismatched definition
identity/hash and duplicate references within each reference list are refused.
There are at most 256 entries, 16 refs in each list, and 16 questions per entry.
Text is limited to 1024 Unicode code points; controls, bidirectional overrides
and lone surrogates are refused. Identifiers use the existing bounded ASCII
identifier vocabulary. Text containing markup remains inert JSON data; any
future view must render it as text, never HTML or instructions. Nothing is
redacted: review before sharing an export or putting it in an agent's context.

Coverage counts only the explicitly declared opcode table. Every missing ledger
entry is listed as unmodeled, with null meaning and not-run tests. Missing entries
are counted separately and are not inserted into the exported ledger. Coverage
is neither runtime execution coverage nor percentage of recovered semantics;
opcodes absent from the definition are outside this denominator. The report
preserves `declared_operation: "unknown"` even if a ledger asserts an observed
meaning. References are always marked unverified and tests unexecuted.

`node tools/check-vm-opcode-ledger.mjs` exercises the real agent command, export
round-trip, source preservation, exact identity failures, unknowns, malformed
and oversized input, no-network operation and no-symlink file loading.

Design inspiration: the [VMCrack write-up](https://blog.deobfuscate.io/reversing-vmcrack)
illustrates iterative handler interpretation and remaining uncertainty. It is
not an authority for the imported evidence or this implementation's semantics;
no challenge code, execution or bypass technique is included.
