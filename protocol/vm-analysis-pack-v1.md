# VM analysis packs and instruction-set comparison v1

This is an offline, data-only interpretation layer. It never changes capture,
executes source, recovers a site decoder, fetches a URL, or grants authorization.
See [SAFETY.md](../SAFETY.md), the [pack schema](vm-analysis-pack-v1.schema.json),
[VM analysis v1](vm-analysis-v1.schema.json), and
[opcode workspace v2](vm-opcode-workspace-v2.md).

## Pack

`contract_version: 1`, `document_kind: vm-analysis-pack`, `pack_id`, `version`,
`rules`, and `families` are required. Unknown fields at every level are refused.
A pack contains at most 64 existing `antibot.*` rule IDs, each with a weight
0–100 and an inert label. IDs are unique. Labels permit Unicode alphanumerics,
spaces, and `. _ : / -`; they are text, never templates or code. Pack IDs and
program families use lowercase ASCII identifiers. No expressions, decoder
callbacks, URLs, imports, or executable extensions are supported.

Each of at most 256 family bindings maps one exact `source_artifact_sha256` to
one `program_family`. A source may appear only once. This is a researcher's
explicit declaration that two builds belong to a family, **not authentication
of that declaration or proof that their behavior is equivalent**.

The bundled [generic anti-bot pack](../apps/origin-trace-backend/assets/anti-bot-pack-v1.json)
reproduces all current lexical and runtime relevance weights. Applying it uses
the existing additive score capped at 100. A custom pack overrides only the
named relevance weights and adds labels. Omitted rules keep their original
observation weights and are listed in `generic_weight_fallbacks`. Structural VM
scores, tiers, observations, unknowns, omissions, and profile inputs stay intact.
There is no detector migration: the original detector remains the baseline.

## Offline application

```sh
cargo run --locked --manifest-path apps/origin-trace-backend/Cargo.toml \
  --bin origin-trace-vm-pack -- apply \
  --pack apps/origin-trace-backend/assets/anti-bot-pack-v1.json \
  --analysis /path/to/vm-analysis-v1.json --output /path/to/ranking.json
```

The version-1 `vm-pack-application` report contains `pack_digest`, the input
`analysis_digest`, the complete unchanged `generic_analysis`, and `rankings`.
Each ranking has `artifact_id`, the overlay `anti_bot_score`, the original
`generic_anti_bot_score`, applied `{rule_id, label}` rows, and fallback rule IDs.
Failed analysis rows remain in `generic_analysis` and are not ranked. `omissions`
is empty because inputs are either fully accepted or rejected; original input
omissions are preserved inside the complete generic document. `limitations`
states the scope of the overlay.

## Offline comparison

```sh
cargo run --locked --manifest-path apps/origin-trace-backend/Cargo.toml \
  --bin origin-trace-vm-pack -- compare \
  --pack tools/fixtures/vm-analysis-packs/pack.json \
  --left tools/fixtures/vm-analysis-packs/build-a.workspace.json --left-artifact 1 \
  --right tools/fixtures/vm-analysis-packs/build-b.workspace.json --right-artifact 1 \
  --output /tmp/owned-vm-comparison.json
```

Each input must satisfy workspace v2, pass recomputation of `document_digest`,
and contain exactly one selected interpreter artifact. Duplicate numeric opcode
rows and inconsistent summary/coverage counts are refused. Retained samples may
be fewer than total samples because the producer bounds retention. Both selected source hashes must have the same declared
program family. Identity is the input document digest, exact interpreter
artifact ID, and selected workspace source-artifact SHA-256. Original source
bytes are not supplied to this command, so their declared hashes cannot be
independently recomputed here.

An effect shape includes all fields of one consistent effect meaning except
local `effect_id` and `evidence_class`. Equivalent declarations with distinct
evidence IDs may describe that same meaning; incompatible meanings within one
handler remain `ambiguous` with all original evidence retained. An exact shape
appearing once on **both** sides
is matched: equal opcodes are `unchanged`, different opcodes are `moved`. A shape
repeated on either side produces `ambiguous` rows retaining each original row;
no arbitrary pairing or numeric-opcode fallback resolves that ambiguity.
Unmatched known effects at the same opcode are `changed`. Other known rows are
`left-only` or `right-only`.

A contradicted effect remains `contradicted`. Null opcodes, unknown handler
state, empty/unknown effects, missing instruction size or operand coordinates,
unknown flow, duplicate effect/operand IDs, overlapping or out-of-instruction
operand ranges, dangling operand/target references, and incompatible
operation/flow declarations, overflowing u64 cell values/indices, or group spans
beyond 65,536 bytes remain `unknown`; they are never promoted by another row's
label or a numeric opcode match. Effect equality is a comparison hypothesis,
not proof of execution or semantic equivalence. Distinct but equivalent effect
representations may remain unmatched. No fuzzy matching is attempted.

The version-1 `vm-instruction-set-comparison` report has:

- `program_family`, `pack_digest`, and the literal
  `family_binding: pack-declaration-not-authentication`;
- `left` and `right` identities with `workspace_digest`,
  `source_artifact_sha256`, and `interpreter_artifact_id`;
- `rows` containing `status`, `match_basis`, nullable `effect_shape_digest`,
  and nullable **complete original** `left` and `right` handler rows;
- complete original left/right `residual_unknowns` and `coverage`;
- `behavioral_equivalence_proven: false`, `omissions`, and `limitations`.

Rows are deterministic in opcode/status order. Unknowns and contradictions are
not discarded even when they do not match. The fixture moves constant opcode
1 to 9, retains halt opcode 2, changes opcode 4's effect, and preserves unknown
opcode 7 and contradicted opcode 8 from each build. These are explicitly owned,
unexecuted fixture declarations, not claims about recovered real-world code.

## Integrity and local limits

Every output includes `contract_version: 1`, `document_kind`, and
`document_digest`. A digest is SHA-256 of canonical JSON with sorted object keys,
compact separators, and lowercase ASCII `\uXXXX` escapes for non-ASCII UTF-16
code units, excluding the document's own `document_digest` field. Pack digests
cover the entire pack. The analysis/workspace input digest is recomputed using
that same existing canonical convention. Integer JSON only is accepted;
duplicate keys, including escaped spellings of the same key, are refused.

Inputs are regular non-symlink files, capped at 16 MiB, depth 32, 500,000
structural/string tokens and 8,192 UTF-8 bytes per JSON string/key. Packs are
additionally capped at 64 KiB of canonical JSON. Reports are capped at 32 MiB;
limits reject the whole operation rather than producing a silently partial
report. Output is a private (0600 on Unix), atomic, no-clobber file in an existing
directory. The command uses no network or browser connection. It prints only
the output digest and `network_requests: 0` after successful publication.
Reports can retain sensitive local evidence. Review any report before sharing;
this command is not an export redactor and never uploads a report.
