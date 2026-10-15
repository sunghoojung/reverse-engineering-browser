# VM semantics workflow v1: implementation plan

## Scope

Extend the existing Traffic → VM findings view, preserving detection and source links. Add an explicit local execution-trace import, state/step inspector, opcode evidence map, control-flow edges, and user/agent-authored semantic hypotheses with differential validation. No remote endpoint, vendor obfuscator, arbitrary interpreter or captured script is executed by this workflow.

## Evidence contract

`reb-vm-trace-v1` is capture-backend-neutral. Required identity: trace ID, investigation/finding IDs, source artifact ID and SHA-256, capture backend, scope ID and architecture (`stack` or `register`). Coverage records completeness, dropped steps and limitations; imported claims are labeled supplied evidence, not verified native capture.

Each ordered step records sequence, program counter before/after, opcode bytes and supplied decoded operands, state before/after, supplied PC increment, and source evidence references. Operand byte ranges and explicit read/write instrumentation are deferred; v1 snapshot deltas do not establish them. Values are tagged finite int32 or unknown, never silently coerced. Memory is a bounded sparse address/value map; absent cells mean unknown, not zero. Register and stack indexes retain distinct namespaces. Gaps break continuity. Snapshot deltas establish changed cells only, never reads or causality.

`reb-vm-hypothesis-v1` links an opcode to a small declarative semantic operation under the fixed documented operand convention. Validation reports link supporting step IDs. User-defined operand layouts are deferred. Labels distinguish observed changes, inferred semantics, contradicted hypotheses and unknown operations. No executable expressions, scripts or dynamic imports are accepted.

`reb-vm-validation-v1` records hypothesis/trace hashes, per-step expected/observed effects and mismatch/unsupported outcomes. Passing observed cases does not prove general equivalence. Report tested input coverage and preserve counterexamples.

## Agent-accessible workflow

Offline JSON CLI commands: validate trace; list steps/opcodes; inspect one exact step; validate a supplied hypothesis set; export a deterministic report. Each command is read-only except an explicit private no-overwrite output file. API contracts use the same strict parser/model as the UI, so agents do not need screenshots to inspect state.

## UI

Within the current VM view: import status and exact artifact identity; keyboard-selectable step list; register/stack/memory before/after changes; opcode table with supporting observations; hypothesis validation and counterexamples. Inert text only. Trace changes reset selected-step ownership. Invalid imports leave the previous valid trace visible and clearly identified.

## Owned fixtures and validation

Independent toy stack/register interpreters cover constants, arithmetic, loads/stores, conditional/unconditional branches and halt. Golden traces are generated from known semantics; independently implemented declarative validators compare effects. Include wrong opcode mappings, unknown cells, mismatched PC/state, gaps, overflow, malformed bounds and unsupported operations. Full UI keyboard/narrow-layout tests remain required before acceptance.

## Native integration boundary

Existing Brave Blink/V8 probes and shared-memory/Mojo/socket transport are real native foundations, but they do not currently establish a general guest-opcode trace. A later reviewed native adapter must emit the same identity/bounds/coverage records and pass the owned fixture differential tests. This version makes no invisible-debugger, anti-CDP evasion, proprietary VM support or universal opcode-recovery claim.

## Retained execution presentation

The UI-only follow-on gives Execution its own full-height VM-local workspace,
while keeping Findings mounted. A sequence-ordered, 64-row retained listing links
trace/opcode navigation to Instruction/Registers/Stack/Memory inspection and an
initially closed evidence area. Narrow layouts use explicit Listing/State/Evidence
panes. The Instruction tab retains a complete paged snapshot overview in addition
to namespace-specific tabs. The exact shared report remains authoritative.

Supplied PC units, opcode hex and decoded operands are labeled separately from
inferred/ambiguous candidate meanings. Raw instruction bytes, operand layout,
static boundaries and PC-to-source mapping remain unavailable. This presentation
adds no trace fields, native capture, execution controls or alignment. The complete
selected-step UI audit retains every shared report field; CLI compatibility is
unchanged. See the [UI operating guide](../../apps/research-ui/README.md#retained-execution-workspace)
for layout, keyboard behavior and validation entry points.
