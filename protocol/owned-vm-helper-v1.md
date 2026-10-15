# Private owned VM helper protocol v1

This is the private stdin/stdout protocol between the Origin Trace backend and
its exact owned `reb-native-vm-fixture` child. It is not an HTTP, browser, socket,
plugin, bytecode-import, expression-evaluation, or arbitrary-process protocol.
The executable and all arguments are selected by backend code. Scope IDs are
process-local identifiers, not a claimed browser/document attachment.

The two fixed programs and inputs are declared in
[owned-vm-programs-v1.json](owned-vm-programs-v1.json). The existing
[native recorder and batch export](native-vm-fixture-v1.md) remain unchanged.

## Launch and ownership

~~~text
reb-native-vm-fixture --control-owned-fixture-v1 --fixture register \
  --session-id 17 --document-id 17 --invocation-id 17 \
  --run-generation 17 --lifetime-ms 60000
~~~

The mode must be the first argument. All six named arguments are required once;
ordering among their pairs is immaterial. Unknown/missing/duplicate arguments
are rejected before a response or execution. Fixture is exactly `register` or
`stack`. IDs and generation are nonzero canonical decimal uint64 strings.
Lifetime is a canonical decimal integer in 1..60000 milliseconds. No signs,
leading zeroes, whitespace, floating-point notation, paths, bytecode, source,
operands, state writes, or environment-selected program are accepted.

One process owns one resumable interpreter and one recorder. It has no worker
threads, listeners, callbacks, or background dispatch. Initialization enables a
fresh recorder once (its internal recorder generation is 1), then sends response
ID 0/status 0 with paused state, PC 0, count 0, no retained transition, and zero
stats. It does not execute the first instruction. `run_generation` is the
backend's independent generation, never the recorder's generation.

The owner starts one instruction only by sending `execute_one`. The backend's
Run pacing, Pause/quiescence, HTTP identities, retained history, and lifecycle
are outside this protocol. A blocked input is not an execution loop. EOF at a
frame boundary exits successfully; EOF within a frame exits with code 2, one
fixed diagnostic, and no dispatch for that incomplete frame. A failed write
exits with code 1. The owner must bound exchange/startup times, continuously drain
stderr, kill/reap the exact child on stop/expiry/failure, and never retry an
uncertain instruction. It enforces the 60-second lifetime even with no input;
the helper independently rejects expired dispatches when input arrives.

## Request framing

Integers are unsigned, explicitly little endian. Do not dump C++ or Rust object
storage. Requests are exactly 40 bytes, with no payload or length field:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | magic `0x314d5652`, bytes `52 56 4d 31` (`RVM1`) |
| 4 | 2 | version `1` |
| 6 | 2 | operation: inspect `1`, execute_one `2`, close `3` |
| 8 | 8 | request_id |
| 16 | 8 | expected_run_generation |
| 24 | 8 | expected_executed_count |
| 32 | 8 | reserved, exactly zero |

The reader owns only a 40-byte input buffer and accumulates short reads without
interpreting a partial request. Multiple requests can be contiguous in the pipe;
a valid complete frame remains valid if followed by a malformed later frame.
There is no variable-size native request allocation or request JSON parser.

Request IDs are nonzero and strictly increasing, not necessarily consecutive.
Every well-framed increasing ID is consumed, including when a generation/count
guard rejects the operation. Repeating that ID with corrected fields never
dispatches. Zero, lower, or reused IDs reject without changing the high-water
mark. Generation and count must exactly match even for inspect/close. Guards
are checked in this order: framing, request ID, generation, count, identifier
exhaustion, real monotonic expiry, operation. Stale generation/count rejection
does not inspect or expire the current run's deadline and does not attempt a
recorder write. A current guarded request with ID UINT64_MAX returns resource
limit and retires without dispatch; the ID must never wrap.

The clock is `steady_clock`, expressed as monotonic nanoseconds. An admitted
instruction uses its admission tick for the recorder. Expiry at equality, a
clock rollback, or an invalid zero clock rejects before `ExecuteOne`; an
instruction admitted earlier may finish its single atomic commit. No later
instruction may begin after expiry. This is not a timing-noninterference claim.

## Response framing and statuses

Each response is exactly a 24-byte header followed by `payload_bytes` UTF-8 JSON
bytes, with no newline or terminator:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | magic `0x314d5652` |
| 4 | 2 | version `1` |
| 6 | 2 | status below |
| 8 | 8 | matching request_id, or `0` for initialization |
| 16 | 4 | payload_bytes, greater than zero and at most 32768 |
| 20 | 4 | reserved, exactly zero |

| Value | Status | Instruction and lifetime effect |
| --- | --- | --- |
| 0 | ok | Init/inspect: none. Execute: exactly one committed instruction. |
| 1 | malformed | No dispatch; failed reply then exit code 2. |
| 2 | stale_generation | No dispatch; process remains available. |
| 3 | count_mismatch | No dispatch; process remains available. |
| 4 | request_id | No dispatch; process remains available. |
| 5 | expired | No dispatch; expired reply then clean exit. |
| 6 | halted | No dispatch; ninth/halt instruction already committed. |
| 7 | resource_limit | No dispatch; failed reply then clean exit. |
| 8 | fixture_error | No dispatch; failed reply then exit code 2. |
| 9 | closed | No dispatch; stopped reply then clean exit. |

The ninth instruction itself returns status 0 with state `halted`; subsequent
execute requests return status 6. Inspect on a halted fixture returns status 0.
A close after halt returns status 9 and preserves the halted snapshot. There
are no unsolicited messages after initialization. Malformed full requests echo
the request ID bytes but have no execution authority; a receiver should retire
on any protocol violation rather than using error data as a retry grant.

## Exact JSON payload

Every response has exactly these fields. No arbitrary strings are accepted from
the pipe or CLI and echoed into JSON; fixture names, states, enums, units, and
schema strings are compiled constants. All IDs, counts, PCs, addresses, indices,
values, sequences, and ticks are canonical decimal uint64 strings. Opcode is a
uint32 JSON integer and fixture revision is the JSON integer 1.

- `schema`: `reb-owned-vm-helper-v1`
- `fixture`: `register` or `stack`
- `program_id`: `owned-register-v1` or `owned-stack-v1`
- `fixture_revision`: 1
- `session_id`, `document_id`, `invocation_id`, `run_generation`: launch identity
- `state`: `paused`, `halted`, `expired`, `stopped`, or `failed`
- `executed_count`: exact completed instructions, including a committed halt
- `retained_count`: exact recorder retained count
- `snapshot`: current complete native snapshot
- `transition`: null except on a successfully retained ExecuteOne result; then
  the exact existing native record shape, including sequence/tick and before/after
- `recorder_result`: null for initialization, inspect, close, and rejected
  controls; otherwise `recorded`, `stale_generation`, `exhausted`, `disabled`,
  `expired`, `wrong_document`, `malformed`, or `full`
- `stats`: exactly `attempted`, `recorded`, `full`, `malformed`, `wrong_document`,
  `stale_generation`, `exhausted`, `expired`, `partial`, all uint64 strings
- `tick_units`: `monotonic-nanoseconds`

Snapshot and transition shapes are the existing
[native fixture contract](native-vm-fixture-v1.md), unchanged: observed/inferred/
unknown evidence, typed operands, explicit read/write effects, sparse memory,
and before/after snapshots. Unknown values have zero stored bits; absent sparse
memory is not an observed zero. Array lengths carry active counts. Bounds are
8 registers, 8 stack slots, 8 memory cells, 4 operands, and 8 effects. Each memory
address is unique. No hidden inactive-slot values enter the serialized shape.

A successful instruction remains committed if the recorder is full or disabled;
current snapshot/count stay authoritative while transition is null. Stats are
reported even if there is no new retained record. Control expiry itself does
not fabricate a recorder attempt, expired record, or sequence gap. The backend
retains acknowledged transitions; this helper does not resend an entire history.

The initial register response, for the launch above, is:

~~~json
{"schema":"reb-owned-vm-helper-v1","fixture":"register","program_id":"owned-register-v1","fixture_revision":1,"session_id":"17","document_id":"17","invocation_id":"17","run_generation":"17","state":"paused","executed_count":"0","retained_count":"0","snapshot":{"pc":"0","pc_evidence":"observed","partial":false,"halted":false,"registers":[{"bits":"0","evidence":"unknown"},{"bits":"0","evidence":"unknown"},{"bits":"0","evidence":"unknown"}],"stack":[],"memory":[]},"transition":null,"recorder_result":null,"stats":{"attempted":"0","recorded":"0","full":"0","malformed":"0","wrong_document":"0","stale_generation":"0","exhausted":"0","expired":"0","partial":"0"},"tick_units":"monotonic-nanoseconds"}
~~~

ExecuteOne request ID 1/generation 17/count 0 returns status 0, count/retained
count `"1"`, PC `"1"`, observed r0 `"7"`, `recorder_result: "recorded"`, and a
sequence-1 transition with opcode 1, immediate-7 operand, observed write of 7 to
r0, and the exact initial/updated snapshots. Its tick is an actual monotonic
nanosecond reading, never a fixed example value or wall-clock timestamp.

## Resource and serializer bounds

The fixed programs execute exactly nine instructions. A separate nonwrapping
16-dispatch hard budget is enforced before mutation. Recorder storage remains
64 records; it is not an unbounded queue. Snapshot reads have no execution side
effects. The interpreter commits from a validated local next-state copy and
performs no I/O, allocation, callbacks, or locking in the dispatch/Record path.

Response serialization uses a fixed 32768-byte stream buffer. Any overflow
fails before a header is sent, rather than truncating identity/state or growing
storage. The native self-test exercises maximum legal uint64 values, all native
slot/operand/effect bounds, and the longest applicable enums: maximum snapshot
is 1808 bytes and maximum record is 5306 bytes. Snapshot + record + a conservative
1024-byte envelope is below 8192 bytes; 32768 remains a hard independent wire
bound. These enum-only payloads have no free-form text requiring unpredictable
JSON escaping. Exactly-32768 and 32769-byte writes are separately tested. Actual
fixed-program responses are smaller; all 18 golden transitions with maximum
scope IDs use under 2 KiB, including the real monotonic tick.

The helper emits at most one fixed diagnostic line on invalid CLI/partial input,
never request contents or a JSON diagnostic on stdout. The backend must still
drain/cap stderr at 8192 bytes, expose truncation if exceeded, and use sanitized
summaries: a replaced/crashed helper is not trusted to honor its normal bound.

## Validation and compatibility

- `tools/check-owned-vm-fixture.cpp`: inert initial/snapshot state, atomic commit,
  paired traced/untraced state per instruction, capacity 0/2/64, halt no-op,
  internal corrupted state, hard budget, uint64 codec, exact expiry equality,
  rollback, wire offsets, and exact JSON-buffer boundary.
- `tools/check-owned-vm-helper.py`: actual process framing, independent goldens
  for all 18 transitions, paused waiting, inspect, split/short reads, malformed
  frames, queued frame after failure, stale/reused IDs, generation/count guards,
  max uint64 identities, expiry before dispatch, close and EOF.
- `tools/fixtures/owned-vm-golden-transitions-v1.json`: independent expected
  states/operands/effects authored before implementation, not generated from it.
- `tools/check-native-vm-recorder.py`: unchanged legacy CLI/self-test contract.

The no-argument, `--enable-owned-fixture`, and `--stack` batch paths retain the
exact prior JSON schema/output, deterministic ticks, and explicit capture rule.
A batch invocation still executes synchronously; only the explicit new control
mode is a resumable process. Tests do not claim browser attachment, arbitrary
VM support, timing invisibility, or proof of researcher authorization.
