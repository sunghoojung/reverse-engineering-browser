# Contextual VM decoding v1

Status: bounded offline supplied-definition model; **vendor compatibility is
unverified**. This extends neither the static v1 wire format nor the native
owned-fixture recorder. The public model is
[`vm_contextual.js`](../apps/research-ui/vm_contextual.js), browser global
`vmContextual` and CommonJS. Load `captured_client.js` first in a browser.

`parseDefinition(input)` and `parseImage(input)` validate and copy JSON text or
plain JSON-data objects. `await analyze(definition, image, options = {})`
revalidates both inputs and returns `reb-vm-contextual-analysis-v1`.
The only option is `max_instructions`, integer 1–4096 (default 4096).
No input is executed, fetched, persisted, uploaded or used as an expression.

## Strict input boundary

Each document is at most 1 MiB, 50,000 structural nodes and 16 nested levels.
Duplicate JSON keys, noncanonical integer tokens (including negative zero,
exponents and fractions), unknown fields, accessors, custom prototypes, sparse
arrays, symbols, non-JSON values and cycles are rejected. Numbers must be safe
integers. Each entry point returns independent data, never input references.
Object inputs are charged incrementally for their exact JSON UTF-8 size, including
keys, escaping and punctuation, before any whole-document serialization. Shared
string references count on every occurrence. The validators in the versioned
model are the normative contract.

An identifier is 1–128 ASCII letters/digits/underscore/dot/colon/hyphen. A name
is 1–32 ASCII letters/digits/underscore, beginning with a letter or underscore.
Hashes are exactly 64 lowercase hexadecimal characters. Decoder states are
bounded symbolic identifiers or null (unknown), never secret keys or memory
snapshots. Null is not the string `null` and never matches a mapping.

## Per-build definition

`reb-vm-contextual-definition-v1` has exactly:

- `format`: `reb-vm-contextual-definition-v1`.
- `build_id`, `definition_id`: identifiers.
- `image_sha256`: expected hash of decoded image bytes for this definition.
- `architecture`: `stack` or `register`.
- `opcode_bytes`: 1 or 2 literal bytes, never reversed by operand endianness.
- `operand_endianness`: `little` or `big`.
- `register_count`: 0 for stack; 1–64 for register.
- `instructions`: 1–256 uniquely named declarations.
- `mappings`: 0–4096 exact contextual mappings, referencing at most 256 states.

An instruction has exactly `instruction_id`, `mnemonic`, `operands`,
`operations`, `flow`. Instruction IDs use the identifier grammar; mnemonics use
name grammar. Operands are the same ordered 0–8 fields as
[static v1](vm-definition-v1.md): exact `name`, `width` (1/2/4), `signed` and
`kind` (immediate/register/address/offset), with its role, endian and architecture
restrictions. Integers are decoded from bytes immediately after the opcode.

`operations` is 1–8 ordered `{operation,args}` declarations using static v1's
abstract rendering vocabulary and operand roles. Each references the enclosing
instruction's operands. Only the final operation may be unknown or have control
flow. Known final operation and flow must agree, as in static v1. Repeated writes
retain their declared order. These are macro-operation renderings, not a VM
executor, numeric-width guarantee, stack-safety analysis or equivalence proof.

Flow is exactly `{kind}` for next/return/halt/unknown. Jump/branch/call are
exactly `{kind,target}`; target is either static v1's `{operand,base}` or null.
Null explicitly means a dynamic/unknown target, not zero. A non-null target is
absolute for an address operand or relative to the instruction end for a signed
offset operand. This model does not decode an encoded target operand.

A mapping has exactly:

- `pc`: byte offset 0–65535.
- `decoder_state`: non-null identifier.
- `raw_opcode`: exactly opcode_bytes lowercase hex bytes.
- `instruction_id`: an existing declaration.
- `next_decoder_state`: identifier or null.

The entire `(pc, decoder_state, raw_opcode)` tuple must be unique, even when
outputs would agree. No wildcard, fallback global mapping, inferred state,
callback, seed derivation or imported JavaScript is supported. The supplied
next state applies to every declared successor of that instruction. Edge-specific
state transitions are not represented in v1; a definition requiring them must
leave the next state unknown rather than claim a guessed state.

## Image and identity

`reb-vm-contextual-image-v1` has exactly `format`, `image_id`, `definition_id`,
`build_id`, `bytes_hex`, `entry_contexts`.

- IDs follow identifier grammar and definition/build IDs must match the definition.
- `bytes_hex` is even-length lowercase hex representing 0–65536 bytes.
- `entry_contexts` is 1–64 unique `{offset,decoder_state}` pairs. Offset is a
  byte offset 0–65535. State is an identifier or null.

The actual image SHA-256 must match definition.image_sha256 before decoding.
Output `identity` is exactly `build_id`, `definition_id`, `image_id`,
`image_bytes_sha256`, `definition_canonical_sha256`. The canonical hash uses
UTF-8 JSON with recursively sorted object keys and preserved array order.
`provenance` additionally retains exact input-text SHA-256 hashes as
`definition_source_sha256` and `image_source_sha256`, null for object inputs.
For exact file-byte provenance, callers must supply fatal-decoded UTF-8 without
BOM removal or newline normalization. IDs and hashes bind retained inputs only;
they establish neither authenticity, capture linkage, ownership nor permission.

## Contextual decoding and CFG

A bounded deterministic worklist starts from entries in supplied order. It
visits each `(offset,state)` once. Distinct states at the same offset remain
separate instruction contexts; the same pair reached twice is not re-executed.
The model interprets no branch condition and retains both declared possibilities.

A decoded instruction contains `id`, `offset`, `decoder_state`, `raw_opcode`,
`instruction_id`, `next_decoder_state`, `mnemonic`, `size`, `bytes_hex`, decoded
`operands`, `operations`, `flow`, `semantics_status` and `pseudocode`.
Its ID is `context:<offset>:<state>`. Unknown contexts use `?` internally, which
cannot collide with a valid state. IDs are local to a report; cross-report
linkage must also bind the full report identity. Size remains 1–34 bytes.
Each operand preserves exact byte offset/hex and decoded numeric value.
Semantics status is declared or unknown, never observed or proven.

Out-of-range PC, unknown state, absent exact mapping, truncated instruction,
invalid register and instruction budget produce terminal diagnostics for that
context. No instruction, state transition or pseudocode is fabricated there.
Independent queued contexts continue. No linear resynchronization or scanning
past an unknown instruction occurs. Explicit contexts can overlap byte ranges;
this model makes no claim of a unique global instruction partition.

CFG nodes contain `instruction_id` (context ID), `offset`, `decoder_state` and
`reachable:true`, meaning reached under supplied declarations only. Edges have
exactly `from_instruction_id`, `from_offset`, `from_decoder_state`,
`to_instruction_id`, `to_offset`, `to_decoder_state`, `kind`, `status`, and
`evidence:'declared_static'`. Only resolved edges get a non-null destination ID.

- next: fallthrough; jump: jump; branch: branch_taken and branch_not_taken.
- call: call and conservative assumed call_continuation, not evidence of return.
- return/unknown: unresolved null-destination edge; halt: no successor.
- Null targets have status unknown_target. Other statuses are resolved,
  out_of_range, unknown_state, unknown_mapping, truncated_instruction,
  invalid_operand and instruction_budget.

Entries retain their pair and resulting status. `cfg.complete` is always false.
Observed runtime transitions must remain separately labeled and identity-bound;
this model supplies none and cannot prove that an unobserved handler is a decoy.

Each pseudocode line contains context `instruction_id`, `offset`,
`decoder_state`, zero-based `operation_index`, `text`, and declared/unknown
`status`. All macro lines refer to the one physical byte range. Resolved flow
rendering includes destination state, not just an ambiguous address. Text must
be inserted inertly. The top-level ordered pseudocode list preserves worklist
and operation order.

Coverage reports `total_bytes`, unique `decoded_bytes`, `undecoded_bytes`,
`instruction_count`, `context_count`, and `stopped_contexts`. Decoded bytes are a
union, not a sum across overlapping contexts. Full byte coverage does not mean
complete paths or observed execution. At most 4096 instructions yield 8192 edges,
8192+64 attempted contexts, and 32768 operation lines plus up to 4096 explicitly
labeled unknown-operation flow lines. There is no path enumeration.

## Acceptance and exclusions

Run `node tools/check-vm-contextual.mjs`. Independent authored fixtures cover
same bytes/different positions, same PC/different states, two build mappings,
known original sum behavior, ordered macro effects, contextual branches/loops,
dynamic targets, unknown state/mapping stops, hash mismatch, malformed inputs,
truncation, invalid operands and budgets. Existing static v1 fixtures are not
silently reinterpreted.

These are generic capabilities, not evidence of support for a vendor release.
Obfuscator.io compatibility requires genuine owned source/output fixture pairs
with recorded version/options and independently checked expected behavior.
Whole-array/per-instruction decryption, seed recovery, unknown handler discovery,
secret extraction, anti-debug bypass and native guest instrumentation are out of
scope. An explicitly supplied decoded image can be analyzed without establishing
support for the encoding that produced it.
