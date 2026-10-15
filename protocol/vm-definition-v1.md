# Declarative static VM analysis v1

This is a bounded offline decoder for explicitly supplied byte layouts and
semantic declarations. It does not discover an ISA, execute bytecode, validate
the declarations, install plugins or attach to a process. Imported execution
traces and their observed-occurrence graphs remain governed by
[VM execution semantics v1](vm-semantics-v1.md). Fixed native owned-fixture
controls remain a separate [owned VM debugger](owned-vm-debugger-v1.md).

The model is `apps/research-ui/vm_static.js`, exposed as browser `vmStatic` and
CommonJS. All entry points revalidate their arguments and return independent
JSON data. `parseDefinition(input)` and `parseImage(input)` are synchronous;
`await analyze(definitionInput, imageInput, options = {})` computes SHA-256 with
WebCrypto before returning `reb-vm-static-analysis-v1`. `options` accepts only
`max_instructions`, an integer from 1 through 4096, default 4096.

Input is JSON text or a plain JSON-data object. Text is limited to 1 MiB per
document and rejects duplicate keys, unknown fields, unpaired surrogates and
noncanonical integer tokens, including exponents, fractions and negative zero.
Object inputs reject unsafe numbers, cycles, accessors, serialization hooks,
non-JSON values, sparse arrays and custom prototypes. The object structure is
bounded to 50,000 nodes and 16 nested levels. Imported text is never interpreted
as JavaScript, HTML, an expression, a URL or a module.

The closed JSON Schemas are
[definition](vm-definition-v1.schema.json),
[bytecode image](vm-bytecode-v1.schema.json), and
[analysis report](vm-static-analysis-v1.schema.json).
Runtime validation additionally enforces cross-field invariants that ordinary
JSON Schema cannot express: unique opcode/operand names, named operand-role
references, definition/image ID equality, and decoded offset/value relationships.
JSON Schema alone does not validate raw JSON token spelling or duplicate keys.

## Definition

`reb-vm-definition-v1` has exactly these fields:

- `format`: `reb-vm-definition-v1`.
- `definition_id`: 1–128 ASCII letters, digits, underscore, dot, colon or hyphen.
- `architecture`: `stack` or `register`.
- `opcode_bytes`: 1 or 2. Opcodes are literal byte sequences. Operand endianness
  never reverses or numerically reinterprets opcode bytes.
- `operand_endianness`: `little` or `big`, shared by all integer operands.
- `register_count`: exactly 0 for stack architecture; 1–64 for register.
- `opcodes`: 1–256 opcode declarations with unique `code` values.

An opcode has exactly `code`, `mnemonic`, `operands`, `semantics`, and `flow`.
`code` is lowercase hexadecimal of exactly `opcode_bytes` bytes. `mnemonic`
and operand names are 1–32 ASCII letters/digits/underscores, starting with a
letter or underscore. Mnemonics are display labels, never executed symbols.

`operands` contains 0–8 ordered fields, each exactly `name`, `width`, `signed`,
and `kind`. Names are unique within the instruction. Width is 1, 2 or 4 bytes;
there are no bitfields, implicit padding, variable-length integers, indirect
decoder callbacks or alignment guesses. Operands immediately follow the opcode.
Kinds are `immediate`, `register`, `address`, and `offset`:

- `immediate` may be signed or unsigned.
- `register` is unsigned and must decode below `register_count`. Stack
  definitions cannot declare a register operand.
- `address` is unsigned. A control target is an absolute byte offset into the
  supplied image, never a host address or an adapter-defined trace PC unit.
  An address used by load/store is only a declared abstract VM memory address.
- `offset` is signed two's complement. A relative target uses the byte offset
  immediately after the instruction plus this signed value.

Instruction size is 1–34 bytes. A decoded number is exact within signed/unsigned
32-bit operand bounds. Encoding width says nothing about runtime value width.

`semantics` is exactly `{operation, args}`. `args` are ordered operand names,
not expression strings. Supported declarations are:

| Operation | Operand roles in `args` | Abstract rendering |
| --- | --- | --- |
| unknown | none | Unknown semantics; preserve declared mnemonic |
| nop | none | No declared data operation |
| stack_const | immediate | Push supplied literal |
| stack_add | none | Pop right and left; push their declared addition |
| stack_drop | none | Pop one value |
| stack_dup | none | Push a copy of the current top value |
| register_const | register, immediate | Assign literal to register |
| register_move | register, register | Copy source to destination |
| register_add | register, register, register | Assign declared sum |
| load | register, address | Assign abstract memory value to register |
| store | address, register | Assign register to abstract memory |
| jump | none | Follow separately declared target |
| branch_zero | register | Test declared register against zero |
| stack_branch_zero | none | Pop and test declared stack value against zero |
| call | none | Declared call and conservative assumed continuation |
| return | none | Return destination unknown |
| halt | none | No declared successor |

Stack operations require stack architecture. Register operations, load, store
and `branch_zero` require register architecture. Unused operand declarations are
retained without inventing an effect. Repeating an argument name is permitted
when it has the required role. The model does not evaluate any operation or
check stack underflow, register values, flags, aliasing or memory availability.
Addition's runtime width, overflow and flags are unspecified; `add` in
pseudocode does not assert integer wrapping or numeric equivalence. This is an
abstract rendering language, not a complete operational semantics.

`flow` is exactly `{kind}` except `jump`, `branch`, and `call`, which require
`{kind, target: {operand, base}}`. `base` is `absolute` for an address operand or
`next` for a signed offset operand. Other flow kinds are `next`, `return`,
`halt`, and `unknown` and forbid target fields.

Known operation/flow pairs must agree. `jump`, `call`, `return`, and `halt`
require their matching kind; both zero-test operations require `branch`; all
other known operations require `next`. `unknown` semantics may declare any
valid flow separately, without upgrading its semantic status to known.

## Bytecode image and hashes

`reb-vm-bytecode-v1` is exactly:

- `format`: `reb-vm-bytecode-v1`.
- `image_id` and `definition_id`: bounded identifiers as above.
- `entry_offsets`: 1–64 unique integers from 0 through 65535.
- `bytes_hex`: lowercase, even-length hex representing 0–65536 bytes.

The image and definition IDs must match. Entries may be outside retained bytes
or inside an operand; these become explicit unresolved entry diagnostics rather
than guessed instructions. An empty image is valid and retains unresolved
entries. There are no data regions, load addresses or external references in v1.
The report preserves the entire validated definition and the original hex image,
including the undecoded suffix. Analysis never rewrites these inputs.

Report `provenance` distinguishes four hashes:

- `definition_canonical_sha256`: UTF-8 JSON of the validated definition with
  recursively sorted object keys, preserved array order, and no whitespace.
- `definition_source_sha256`: exact UTF-8 input text, or null for object input.
- `image_bytes_sha256`: the actual bytes represented by `bytes_hex`.
- `image_source_sha256`: exact UTF-8 image JSON text, or null for object input.

Callers importing files must use fatal UTF-8 decoding and pass the original
text to preserve file-byte identity; no BOM stripping, newline normalization,
parse/reserialize step or replacement-character decoding is permitted. The
model hashes strings, not unknown original filesystem encodings. Hashes bind
these inputs only. IDs and declarations remain supplied, unauthenticated claims
and establish no captured artifact identity, authorization or semantic truth.

## Decode and target resolution

Decoding walks a single contiguous prefix starting at byte zero. Entry points
affect graph reachability, not instruction alignment. Halt, return and jump
declarations do not stop linear decoding: later bytes may contain functions or
unreachable instructions, but are still interpreted only under this explicit
all-code format assumption.

At an unknown opcode, incomplete opcode/operand, invalid register operand or
instruction budget, decoding stops before that instruction. The validated
prefix, exact stopped offset, reason and undecoded bytes remain visible. The
model never resynchronizes after an unknown opcode or recursively interprets
an operand byte as a new instruction. No synthetic decoded instruction is
created for the unknown suffix.

`coverage` has `decoded_bytes`, `total_bytes`, `instruction_count`,
`undecoded_bytes`, and `stop_reason`: `end`, `unknown_opcode`,
`truncated_instruction`, `invalid_operand`, or `instruction_budget`.
Full byte decoding means only that these layouts cover the supplied image.

Each instruction retains stable `id: "insn:<offset>"`, byte `offset`, `size`,
`bytes_hex`, literal `opcode`, `mnemonic`, complete decoded `operands`,
`operation`, `args`, `semantics_status`, declared `flow`, and linked
`pseudocode`. An operand additionally retains its exact byte `offset`, original
`bytes_hex`, and numeric `value`. `semantics_status` is `declared` or `unknown`,
never proven, inferred or observed.

Targets are `resolved` only at an already decoded instruction start;
`mid_instruction` inside a decoded instruction; `undecoded` in the remaining
image suffix; `out_of_range` outside `[0, total_bytes)`; or `unknown` when the
flow supplies no destination. End-of-image fallthrough is out of range, not an
implicit halt. Arithmetic is bounded and exact; no target wraps around.

## Static CFG and linked pseudocode

`cfg` is instruction-level, not recovered basic blocks. Its nodes contain
`instruction_id`, `offset`, and `reachable`. Entries preserve requested offsets
and resolution status. Edges have exactly `from_offset`, nullable `to_offset`,
`kind`, `status`, and `evidence: "declared_static"`:

- `next`: one `fallthrough` edge.
- `jump`: one `jump` edge.
- `branch`: `branch_taken` and `branch_not_taken`, regardless of actual values.
- `call`: `call` plus `call_continuation` to the next instruction. The latter is
  explicitly a conservative assumed continuation, never evidence of a return.
- `return`: an unresolved `return` edge with null destination. Calling
  convention, return stack and return destinations remain unknown.
- `unknown`: an `unknown` edge with null destination.
- `halt`: no edge.

Reachability follows resolved declared edges from resolved entries, including
assumed call continuations. False means not reached by this declared graph,
not proof that runtime execution cannot reach that byte. Unresolved targets
never become nodes. `cfg.complete` and `equivalence_proven` are always false.
Static edges never merge with or masquerade as observed trace edges.

Every pseudocode line has `instruction_id`, `offset`, `text`, and `status`
(`declared` or `unknown`). Lines appear both with their instruction and in the
top-level ordered `pseudocode` list. They are a finite rendering of the table
above. Addresses use lowercase hex padded to at least four digits. Unresolved
targets render explicitly as, for example,
`unresolved(0x0001, mid_instruction)`. Return renders `return unknown_target;`.
Unknown operations render `unknown_semantics(MNEMONIC);` with a separately
labeled declared-flow line when applicable. All text must be displayed inertly.
No generated line is executable source, an expression callback or a proof.

The report is bounded to 4096 instructions/nodes, 8192 edges, 8192 pseudocode
lines, 64 entries, and 8257 diagnostics. Diagnostics cover invalid targets,
invalid entries and the first decode stop. Warnings describe persistent trust
and interpretation limits. There is no CFG path enumeration or unbounded
recursion. `max_instructions` can further reduce work without erasing the image.

## Owned acceptance fixtures and limits

`tools/fixtures/vm-static/` contains independent authored stack/register
definitions and inert images, including branches, calls, unknown returns,
mid-instruction targets and an unknown-opcode suffix. They are not captures,
the native helper's program format, the earlier 16bitjs compatibility fixture,
or evidence of support for any upstream VM.

Unsupported formats include encoded opcode bitfields, variable-width opcodes,
embedded code/data tables, encrypted or self-modifying code, runtime-installed
handlers, indirect branch target recovery, arbitrary calling conventions and
source-language reconstruction. A user must supply a supported declarative
layout explicitly; similarity to a known VM never authorizes reinterpretation.

The model has no filesystem, network, persistence, target instrumentation or
execution effects. Original image bytes and definitions can still contain
private information; exporting or sharing them is a separate deliberate action
under [SAFETY.md](../SAFETY.md).
