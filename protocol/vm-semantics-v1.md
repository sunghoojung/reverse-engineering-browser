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

## Reports and agent CLI

`node tools/vm-semantics.mjs inspect TRACE.json OUTPUT.json` lists exact identity,
coverage, steps, changed cells, observed PC edges and candidate operations.
Candidate operations are those fitting every retained observation for that
opcode under the fixed operand convention. Multiple candidates remain ambiguous;
no candidate is unknown. Neither outcome proves semantics.

`node tools/vm-semantics.mjs step TRACE.json SEQUENCE OUTPUT.json` returns one
exact retained state transition, including evidence references.

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
