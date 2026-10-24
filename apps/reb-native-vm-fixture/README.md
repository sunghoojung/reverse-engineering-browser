# Owned native VM fixture recorder

This command runs two tiny, repository-owned C++ interpreters. They cooperate by
passing each completed guest instruction to the recorder. It does **not** capture
arbitrary JavaScript/Wasm guest VMs, attach to a browser, bypass detection, extract
keys, or infer opcode semantics. Browser activation is not implemented. The
private cooperative control mode supports the owned-fixture debugger; existing
browser and VM import contracts are unchanged.

~~~sh
make native-vm-fixture
build/reb-native-vm-fixture                          # no retained instructions
build/reb-native-vm-fixture --enable-owned-fixture    # register fixture JSON
build/reb-native-vm-fixture --enable-owned-fixture --stack
make native-vm-recorder-check
make owned-vm-helper-check
~~~

The two fixtures compute 7 + 5, store 12 at guest memory address 16, then load it. They then execute an untaken zero branch, an unconditional
jump, a taken nonzero branch, and halt. Nine instructions execute; skipped
PCs 7 and 9 are never fabricated as observed records.
Opcode 1 loads an immediate, 2 adds, 3 stores, and 4 loads memory. Opcodes 5–8 mean branch-if-zero, jump, branch-if-nonzero,
and halt. Program counters
are instruction indices. Registers, stack slots, and sparse memory are
fixture-owned unsigned 64-bit values; no host addresses or arbitrary process
memory are accessed. Cleared stack slots are unknown, with zero bits.
The CLI emits synthetic fixture values only, to stdout on explicit invocation.
The probe opt-in is separate: `SampleOwnedRegisterInvocation` walks the register
program, and `EnableOwnedRegisterSampling` is what lets that walk call
`RecordVmDispatchSample`. It is off unless a VM capture session opts in.
The stdout export does not enable it.

The [local API and JSON contract](../../protocol/native-vm-fixture-v1.md)
describe bounds and lifecycle. Run tests through Make: paired traced/untraced
execution compares **all final state**, including PC, registers, stack, and
memory. Capacity loss also preserves the final state. This proves semantic
noninterference for these fixtures, not timing equivalence or transparency on
real-world interpreters.

## Ownership and lifecycle

The single-threaded core is in include/reb/native_vm_recorder.hpp and
src/analysis/native_vm_recorder.cpp. It owns fixed storage, performs no I/O,
and allocates nothing on construction or recording. Disabled recording returns
before inspecting the supplied step. Snapshot creation in this CLI is always
performed for test simplicity; a future producer must gate snapshot work too.

Enable supplies nonzero session/document/invocation IDs and an expiry in a
caller-owned monotonic clock domain. The fixture uses ticks 1–9 and expiry 100.
A document mismatch rejects the record; navigation/detachment explicitly
invalidates the recorder. Expiry or clock rollback latches it disabled.
Disable retains old records for inspection. Enable (even invalid enable)
clears prior values and counters so invocations cannot mix. Records can only be
read, not drained; capacity loss remains visible in counters after the last
record. This is a bounded per-invocation collector, not a transport queue.

The recorder validates structural bounds and evidence tags, not whether caller
assertions describe a real execution. It is not an authorization boundary or a
cross-process ABI. Browser integration must add trusted lifecycle admission,
bounded transport, and visible enablement before real capture can be claimed.

Each enable advances an internal nonwrapping generation. Producers retain that
generation for the invocation and pass it on every record; stale work cannot
record into or expire a newly enabled invocation, even on the same document.
The fixture document ID is local, not a truncated Chromium document token.

## Paused, single-instruction control mode

The backend launches this executable with explicit
`--control-owned-fixture-v1` and exact fixture, scope, run generation, and lifetime
arguments. Its initial framed response is paused at PC 0 with zero executed
instructions and empty history. An inspect request is inert; each guarded
execute_one request commits one real instruction and reports the complete
snapshot and retained transition. Halt is the ninth real instruction. There is
no arbitrary program, path, expression, browser adapter, or mutable state input.

`include/reb/owned_vm_fixture.hpp` and `src/analysis/owned_vm_fixture.cpp` own the
resumable single-owner interpreter. The legacy batch path now repeatedly calls
that same ExecuteOne operation without changing its output or deterministic
clock. Control mode uses actual steady-clock nanoseconds and rejects expiry
before an instruction can start. Scope, request-ID and exact count guards
prevent stale or repeated requests from executing. An instruction's validated
next-state copy is committed atomically before recording; recorder loss cannot
change its semantics.

The [private framing contract](../../protocol/owned-vm-helper-v1.md) defines
fixed 40-byte requests, 24-byte response headers, 32 KiB JSON bound, strict CLI
arguments, lifecycle, statuses, and tests. Do not call this mode from page
JavaScript or expose its pipe as a network service. The backend owns Run pacing,
Pause/quiescence, request timeouts, an independent 60-second lifetime timer,
stderr draining, and killing/reaping its exact child. Closing input exits the
helper; a crash or missing execution reply must never trigger an automatic retry.

The native-focused check compares all 18 transitions with independently authored
goldens, tests real framing and expiry, and verifies inert initialization,
inspect, repeated/stale controls, short reads, EOF, max uint64 fields, and
bounded serialization. Direct tests also exercise invalid internal state and
capacity loss without introducing an arbitrary-input production interface.

## Explicit dispatch event export

`--emit-dispatch-events-v1` is the separate opt-in native event-stream mode for
the existing broker. It is the offline way to prove the workspace consumer with
real dispatch samples and no browser. It exports one typed invocation marker
plus one dispatch sample for each of the nine executed instructions, using
fixed bounded capture before any output. The
[workspace v2 contract](../../protocol/vm-opcode-workspace-v2.md)
defines the required scope/artifact arguments, private disposable-store example,
unit evidence and declared-reference limitations. It introduces no browser
attachment or automatic code execution, and it does not invent a guest PC for a
captured page module. `javascript-switch-dispatch-v1` and
`wasm-br-table-dispatch-v1` are separate probe opt-ins for matching captured
buffers; this CLI does not emit those shapes. Use `make native-vm-recorder-check`
for actual producer-to-broker checks and `make e2e` for analyzer linkage.
