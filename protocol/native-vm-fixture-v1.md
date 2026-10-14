# Owned native VM fixture v1

Status: local, cooperative C++ fixture and deterministic JSON CLI export. Not a browser
wire protocol, not an input to the existing imported-trace VM analyzer, and not a
replacement for native event or artifact contracts. See [usage and
limitations](../apps/reb-native-vm-fixture/README.md).

## Typed local records

NativeVmRecorder retains at most 64 VmRecordedStep values. A constructor may lower
capacity, including zero; larger requests clamp to 64. Each record owns a step, one
before snapshot and one after snapshot. There are at most four operands, eight
read/write effects, eight registers, eight stack slots, and eight sparse guest memory
cells per snapshot. No host pointer is stored. Objects are trivially copyable but their
compiler padding/layout is not a serialization contract; never export their object
bytes.

A step has a numeric opcode with evidence tag, typed operands, typed read/write effects,
and before/after PC, halted state, register, stack and sparse-memory state. Location
tags are immediate, register, stack, or memory; effects cannot be immediate. Register
and stack indices are bounded to 0–7; memory indices are guest addresses. Read values
are inputs and write values are outputs. Snapshots describe active locations and stack
removal. The core does not prove effects agree with the snapshots: these remain producer
assertions. Partial views must set partial; unknown locations/values must not be
fabricated.

Evidence is observed, inferred, or unknown, retained without promotion. Unknown values
and unknown PC/opcode use zero bits. Unused array slots must be zero/default
initialized. Unknown enum values, excess counts, duplicate sparse addresses, and data
hidden in unused slots are malformed. Known guest bits are unsigned 64-bit values, not
automatically interpreted as integers, floats, strings, pointers, or secrets.

## Lifecycle and loss

Explicit enable requires nonzero session/document/invocation IDs and expiry greater than
current tick. Every enable attempt clears retained values, scope and statistics first.
Each enable attempt advances a nonwrapping internal generation; exhausted generation
space makes enable fail closed. Producers capture generation once per invocation and
pass it with every record. A stale generation returns stale_generation and increments
that rejection counter before checking time, so stale work cannot expire or move the
current clock. Document mismatch is also rejected before clock checks. Caller must
supply trusted monotonic ticks and unique fixture document identities. These uint64 IDs
are not Chromium document tokens; a future adapter must preserve the full opaque browser
identity without truncation. At now >= expires_at, or on clock rollback, recording
returns expired, increments expired once, and latches disabled. Subsequent calls return
disabled until a fresh enable. Navigation or detachment must call InvalidateDocument; an
unrelated document token returns wrong_document without retaining that step. Disable
preserves previous records.

For matching-document, unexpired calls, attempted increments before validation. Its
1-based value is the record sequence; malformed attempts leave sequence gaps. Full
storage never overwrites earlier records and increments full. The malformed, full,
wrong_document, stale_generation, expired, exhausted, and retained partial counts remain
observable even if no further record fits. Partial counts records having any
step/snapshot partial flag; it is a coverage warning, not a dropped record count.
Disabled calls are not attempts and do not increment counters or inspect step contents.
Rejected document/generation calls are not matching-document attempts. There is no
drain, background thread, silent truncation, auto-export, or automatic re-enable.

Record time and expiry are caller clock ticks, not Unix time or wall time. Counters
saturate at UINT64_MAX, never wrap. If attempted cannot advance, recording increments
exhausted and latches disabled instead of issuing a duplicate sequence. The saturating
increment primitive is checked at compile time at the maximum boundary; enormous live
attempt counts are not exercised in fixture tests. Only one owner/thread may call the
object.

## JSON CLI output

Schema is reb-owned-vm-fixture-v1; fixture is register or stack. Backend is cooperative-
native-fixture; fixture_revision is 1 and program_id is owned-register-v1 or owned-
stack-v1, identifying the reviewed C++ fixture revision, not a content hash. PC units
are instruction-index; value_semantics is unsigned-64-bit-bits and termination_reason is
halt (the CLI rejects a fixture that fails to halt in its 16-instruction budget). These
fields describe the synthetic program even when instruction retention is disabled. The
session_id, document_id, invocation_id, expires_at, and generation are decimal strings.
Disabled invocation has zero scope IDs, no records, and zero counters. Each record has
decimal-string sequence and tick, numeric opcode, opcode_evidence, boolean partial,
operands, effects, before, and after.

Operands contain location, decimal-string index, and value. Effects additionally have
access (read or write). A value contains decimal string bits and evidence. Snapshots
contain decimal-string pc, pc_evidence, boolean partial and halted, registers, stack,
and memory. Registers/stack are active-value arrays indexed from zero. Memory is a
sparse array of objects with decimal-string guest_address and value. 64-bit evidence
values and identity fields use strings to avoid JavaScript rounding. The bounded
diagnostic counts attempted, recorded, and the loss object's counters are JSON numbers
in this nine-instruction CLI fixture.

This format has no importer yet. Any future analyzer/UI projection must preserve scope,
evidence classifications, partial flags and final loss counters, and must not treat
missing instructions as observed execution.
