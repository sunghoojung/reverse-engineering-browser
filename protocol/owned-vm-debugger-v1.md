# Owned native VM debugger v1

This opt-in provider controls two repository-authored native fixtures. It is not
Brave guest-VM capture. Imported trace v1 remains read-only and is never dispatched
to a helper. The original native recorder contract is unchanged.

## Public API

GET `/api/vm-debugger` reads the cached `reb-owned-vm-debug-session-v1` view without
creating a helper or advancing execution. POST `/api/vm-debugger/actions` accepts
one strict JSON object of at most 2048 bytes, with one `application/json`
Content-Type and optional UTF-8 charset. Actions are create, run, pause, step,
stop, reset and close. OpenAPI defines their exact required fields and rejects
unknown fields. The backend parses duplicate fields before conversion to generic
JSON. Agent clients can discover these operations with `reb-api list --json` and
inspect them with `reb-api describe`; read-only mode must reject all control
operations before dispatch.

Create chooses only register or stack. Other controls identify the backend
instance, session, run and generation. Run and Step additionally carry the exact
control revision; Step also carries the expected executed count. Command IDs are
explicit and bounded. No action is implicitly retried. GET
`/api/vm-debugger/trace` requires all four identity selectors and exports the same
bounded cached view. A stale identity is an error, never a request for the latest
run. Exporting does not advance execution.

## Execution and evidence

Creation starts paused at count zero with a confirmed initial snapshot and empty
history. Step commits at most one native instruction. Run schedules one instruction
per 250 ms tick without catch-up bursts. Pause acknowledgment waits for any
in-flight instruction boundary. Stop and Close dispose the child; uncertain
in-flight execution remains explicitly unknown. Reset creates fresh run identity,
generation and lifetime; it never resumes automatically. Leaving the view does
not pause a fixture. Every run expires after 60 seconds, including paused time.

All native 64-bit values and counters remain canonical decimal strings. Unknown,
observed and inferred values are distinct, and an absent cell is not zero. The
live cursor and historical selection are independent. Initial state is not a
fabricated instruction. At most 64 records are retained. Recorder loss counters,
termination reason, diagnostic truncation and execution-state uncertainty remain
visible in the view and raw audit. UI opcode names are declared semantics of the
fixed fixtures, not recovered meanings of arbitrary imported opcodes.

Program provenance hashes the exact checked-in two-program manifest bytes. A
separate fixture selector identifies the program within that manifest. The manifest digest is not a raw-bytecode digest. Build identity
hashes the configured helper file with bounded reads and metadata checks; it is
not remote attestation or proof against a concurrent file replacement race.

## Bounds and transport

The helper uses a private binary-framed pipe, specified in
[owned-vm-helper-v1.md](owned-vm-helper-v1.md). The backend has one owner, bounded
normal and reserved urgent mailboxes, a five-second initial-reply timeout and
two-second instruction-exchange timeout. Initial-reply timing starts after
synchronous configured-file checks, hashing and OS process spawn return. The
64 MiB file cap is a byte bound, not a wall-time guarantee for filesystem or OS
calls. Pause/Stop may queue during this setup but cannot be admitted until it
returns; no guest instruction executes during setup or initial handshake. The
60-second run lifetime starts before setup and is never renewed by it. Replies
are capped at 32768 bytes before allocation. Public
views are capped at 1 MiB, diagnostics retain at most 8192 bytes, and helper-file
hashing accepts at most 64 MiB. Protocol failure retires the run; it does not retry
a possibly completed instruction. Failed disposal blocks replacement.

## Validation

`make owned-vm-helper-check` covers native core, private codec and both real helper
programs against 18 independent golden transitions. Rust tests cover strict
contracts and actor races. The ignored `owned_vm_real_helper_control_and_independent_goldens`
test requires `REB_OWNED_VM_TEST_HELPER` pointing to the built helper. The UI
controller test distinguishes authored response tests from actual backend/helper
rendered acceptance. Native packaging must include `OriginTraceOwnedVmFixture`;
stored-evidence mode explicitly reports this provider unavailable.
