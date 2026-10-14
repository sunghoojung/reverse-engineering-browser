# Owned native VM fixture recorder

This command runs two tiny, repository-owned C++ interpreters. They cooperate by
passing each completed guest instruction to the recorder. It does **not** capture
arbitrary JavaScript/Wasm guest VMs, attach to a browser, bypass detection, extract
keys, or infer opcode semantics. Browser activation and UI ingestion are not
implemented. Existing browser and VM import contracts are unchanged.

~~~sh
make native-vm-fixture
build/reb-native-vm-fixture                          # no retained instructions
build/reb-native-vm-fixture --enable-owned-fixture    # register fixture JSON
build/reb-native-vm-fixture --enable-owned-fixture --stack
make native-vm-recorder-check
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
