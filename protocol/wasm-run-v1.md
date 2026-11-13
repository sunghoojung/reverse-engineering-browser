# WASM run v1

`POST /api/wasm/runs` (`run_wasm_function`) runs one function of a captured core
WebAssembly module offline and returns a `wasm-run-v1` record.
`GET /api/wasm/runs` (`get_wasm_runs`) reads stored records without running
anything. The [OpenAPI schema](openapi.json) defines `WasmRunRequest`,
`WasmRun`, `WasmRuns` and `WasmTypedValue`. The policy that permits this one
form of execution is in [SAFETY](../SAFETY.md#observation-and-experiments).

## Boundary

- **Explicit only.** A request runs only with `confirm_offline_execution: true`.
  Without it the request is refused with 400 before the artifact is read.
  Nothing in Origin Trace starts a run automatically, from an analysis, or on a
  schedule, and a run is never retried.
- **Offline interpreter.** The module runs in `wasmi` 2.0.0, a pure-Rust
  interpreter with fuel metering and no JIT, inside the backend process. It is
  built with its `validate`, `simd` and `deterministic` features: modules are
  fully validated before they run, and NaN results are canonicalized so a run
  is reproducible. A browser engine may produce a different NaN bit pattern.
- **Every import is a stub.** A function import returns the values the request
  supplies for it (`results` on every call, or one `sequence` entry per call)
  and otherwise traps. Imported memories and tables are fresh and empty, and
  imported globals are zero; `other_imports` says so for each. No filesystem,
  network, clock, randomness, browser, page or other host state is reachable,
  so the caller must supply every nondeterministic import.
- **Captured bytes stay evidence.** The artifact is found by `artifact_id`; its
  size and SHA-256 must match the manifest and the request's `sha256`, or the
  request fails (500 integrity, 409 mismatch). The captured bytes are never
  modified. A run is a derived experiment record in
  `artifacts/analysis/wasm-runs-v1.json`, never captured evidence.

## Execution copy

The interpreter reaches functions only by export name and would run a start
function inside instantiation, where no deadline can stop it. The backend
therefore compiles a rewritten copy: it drops the start section and adds
private exports for the target, for the start function when `run_start` is set,
and for memory 0. Every other section is copied byte for byte. The record keeps
`provenance.module_sha256` (the captured bytes) and `executed_module_sha256`
(the copy). `function.byte_offset` and `function.byte_end` locate the target's
body in the captured bytes.

Data and element segments initialize as usual. With `run_start` the start
function runs first, under the same budget; otherwise `start_function.ran` is
false. `memory_writes` are applied next, then the target is called with
`args`. `memory_reads` are taken after the call whatever the outcome, so a
trapped run still shows the memory it left.

## Request

The target is exactly one of `export` (an exported function name) or
`function_index` (a defined function, counting imported functions first). An
imported index is refused with 400 because it would only call its own stub.
`args` must match the function's parameter types, and each stub's values must
match its import's result types; a mismatch is a 400 that names both type
lists, and is checked before any module code runs. A stub that names no
function import, or two stubs for one import, is refused.

Values are `{type, value}` with string values of at most 64 characters, so
they can be copied between `args`, stubs, `results` and `expect`:

| Type | Accepted | Returned |
| --- | --- | --- |
| `i32`, `i64` | signed or unsigned decimal of that width: an optional `-`, then `0` or digits without a leading zero; no `+` | signed decimal |
| `f32`, `f64` | an optionally negative decimal with optional fraction and exponent (`1.5`, `-0`, `1e300`), `inf`, `-inf`, or `nan:0x` with the exact bit pattern in exactly 8 (f32) or 16 (f64) hexadecimal digits; a finite literal that rounds to infinity is refused | the shortest form that reads back to the same bits (`1001.0`, `1e300`), `inf`, `-inf` or `nan:0x` |
| `v128` | one to 32 hexadecimal digits (optional `0x`, no sign), lane 0 in the low bits | `0x` and 32 digits |
| `funcref`, `externref` | `null` | `null` or `non-null` |

`expect` holds test vectors: `results`, and at most one `memory` entry per
`memory_reads` index with the expected bytes; a second entry for the same read
is refused with 400. The record's `expectation` reports `results_match`, each
memory `match`, and `all_match` (which also requires the outcome `returned`).
The one-entry-per-read rule bounds the size of a request and its record. It is
not a disclosure control: an expectation is answered only to a caller that may
read the run's values anyway (see below).

## Limits

| Limit | Default | Maximum |
| --- | --- | --- |
| `fuel` | 100,000,000 | 10,000,000,000 |
| `memory_pages` (64 KiB pages, total across every memory) | 256 | 1,024 |
| `table_elements` (total across every table) | 10,000 | 1,000,000 |
| `call_depth` | 1,000 | 10,000 |
| `deadline_ms` (wall clock, from when the run starts reading the module) | 2,000 | 10,000 |

Fixed bounds: a 16 MiB module (larger artifacts are refused before compilation,
which no deadline can interrupt), a 1 MiB request body, 1,000 arguments, 256
stubs with up to 256 sequence entries, 16 writes of at most 256 KiB in total,
16 reads of at most 32 KiB in total, 256 recorded import calls with up to 16
arguments and 16 results each (`args_truncated`, `results_truncated`), 16
memories and 16 tables, 64 operators in any constant expression, 262,144
element segment items, one expected memory entry per read (so at most 16),
captured import and export names cut to 128 bytes and outcome messages to 1,024
in the record, a 4 MiB record, 64 stored runs and a 16 MiB store. A limit
outside its range is refused with 400.

A record always fits the 128 KiB that `reb-api mcp` returns inline, so a Full
client gets every byte it read rather than a structural summary. Reads are
returned as hex, so their 32 KiB cap is 64 KiB of text. If the pretty-printed
record would still exceed 120 KiB, it is trimmed in this order until it fits:
the import call list is emptied (`import_calls_total` and
`import_calls_truncated` stay), the request echo is replaced by its size
(`provenance.inputs_digest` still names it), `imports` and `other_imports` keep
their first 32 entries, `results` keeps its first 64 values, and
`function.type` becomes its two counts. `size_trimmed` lists each step taken and
is empty otherwise. Outcomes, counts, memory reads, digests and the expectation
are never trimmed; the expectation is computed before any trimming.

The memory and table limits are totals: every memory and every table the run
creates, imported or defined, and every growth, counts against one budget each.
A module with more than 16 memories or tables ends as `memory_limit` or
`table_limit` before anything is created. A constant expression (a global,
table, element or data initializer) over 64 operators is refused with 422
before the interpreter sees it, because wasmi builds and evaluates one
recursively, one native stack frame per operator; real modules use one to
three. Every function is compiled when the module is (eager compilation), so a
large body costs no fuel and a call never stops for compilation. Element
segments hold at most 262,144 items in total, active or passive, because
instantiation materializes every one; data segments are bounded by the module
size.

Compilation and instantiation cannot be interrupted. They are bounded only by
those caps: the 16 MiB module, 64-operator constant expressions and 262,144
element items. Their time counts toward the deadline, and a deadline that
passes during them ends the run as `deadline_exceeded` in phase `instantiate`
before any function is called. Compiling needs about 25 to 30 times the module
size in memory at its peak (a 6.9 MB body of nested ifs peaked near 320 MB
resident), so a module at the 16 MiB cap can hold about 480 MB of the backend's
memory while it compiles.

Fuel is granted in 100,000-unit slices. The deadline is checked before each
call, between slices and at every import call, so a run ends within one
100,000-unit slice or one import call of the deadline, where checking only
between 1,000,000-unit slices let a loop of import calls run three times past
it. A
refused `memory.grow` returns -1 to the module, as the specification
requires, and is counted in `memory_grow_denied` (`table_grow_denied` for
tables). One run is admitted per backend at a time; a second gets 409. Once
admitted, a dropped HTTP connection does not cancel the run or its storage.

## Outcomes

`outcome.status` names exactly one ending, in `outcome.phase` (`instantiate`,
`start`, `prepare` or `call`):

| Status | Meaning |
| --- | --- |
| `returned` | The target returned; `results` holds its values. |
| `trap` | A Wasm trap; `trap_kind` is `unreachable`, `memory_out_of_bounds`, `table_out_of_bounds`, `indirect_call_to_null`, `integer_division_by_zero`, `integer_overflow`, `bad_conversion_to_integer`, `indirect_call_type_mismatch` or `out_of_system_memory`. |
| `import_trap` | A function import without a stub (`reason: no_stub`) or with an exhausted sequence (`sequence_exhausted`) was called; `outcome.import` names it. |
| `fuel_exhausted` | The fuel limit was reached. |
| `deadline_exceeded` | The wall-clock deadline was reached: before a call, between fuel slices, at an import call, or (phase `instantiate`) while the module was compiled and instantiated. |
| `call_depth_exceeded` | The call depth or value stack limit was reached (`trap_kind: stack_overflow`). |
| `memory_limit`, `table_limit` | A memory or table the module declares or imports exceeds its limit at instantiation, or a growth that must succeed was refused. |
| `instantiation_failed` | Instantiation failed for another reason, such as an out-of-bounds data segment. |
| `memory_write_out_of_bounds` | A requested write does not fit memory 0; the target was not called. |

`byte_offset` is always null: wasmi 2.0.0 does not report the instruction
offset of a trap, and the record does not invent one. Errors that are not
outcomes are HTTP errors and store nothing: 400 for request problems, 404 for
a missing artifact, export or function, 409 for a hash mismatch or a busy
runner, and 422 for an empty, malformed or component module, or one the
interpreter's validation rejects. Each message names its cause.

## Record

Besides the outcome, a record carries `function` (index, export name, body
range, type), `results`, `fuel_consumed`, `elapsed_ms`, `imports` (each function
import, its stub kind and call count), `other_imports`, `import_calls` (each
attempted call in order: `sequence`, `function_index`, `module`, `field`,
`args`, `args_truncated`, `outcome`, `results`, `results_truncated`),
`import_calls_total` and
`import_calls_truncated`, `memory_pages_after`, `memory_reads` (status `read`,
`out_of_bounds` or `no_memory`, with `sha256` and `hex`), `expectation`, the
`request` as run (without its confirmation) and `provenance`: `artifact_id`,
`module_sha256`, `module_byte_size`, `run_id_source`, `inputs_digest` (SHA-256 of the request
without its confirmation), the interpreter and its version, the effective
limits, and the rewrite. The record is checked against the `WasmRun` contract
before it is stored; a record that fails is neither stored nor returned, and
the 500 says so without quoting any value. The POST result adds `stored` and
`store_error`; when storage fails, or the record exceeds 4 MiB, the record is
still returned with `stored: false`.

The store keeps the newest 64 runs; older ones are evicted and counted in
`evicted_runs`. An unreadable store is an integrity failure, not a request
error: `GET /api/wasm/runs` answers 500 with code `artifact_integrity` and says
how to recover. The next run moves the file aside as
`analysis/wasm-runs-v1.json.unreadable-<milliseconds>`, never overwriting or
deleting it, starts a new store, and names the moved file in its
`store_notice`. `GET /api/wasm/runs` takes optional `artifact_id` and `limit`
(1 to 64, default 1) and returns runs newest first with the matching `total`.
One record always inlines through `reb-api mcp`; ask for more with a larger
`limit` when the records are small, or larger listings may come back as a
structural summary.

## Content and agent access

Running captured code is a content read. A run's results and memory bytes are
the values the code computed, and every other part of the record can disclose
them too: the outcome and trap kind, `fuel_consumed`, `import_calls_total` and
the import call list, memory and table growth, `elapsed_ms`, and the answers to
repeated expectations. A review recovered an 11-byte secret from the import call
count and the fuel of 11 runs, and four bytes from 305 runs of one-byte
expectations, at a level that omitted every value field. No part of a record is
safe to show to a caller that may not read content.

So, through `reb-api mcp`, both operations are in `x-reb-mcp.content_reads`:
`run_wasm_function` and `get_wasm_runs` are listed only with `--allow-content`,
which only `--permission full` sets, and `run_wasm_function` also needs
`--allow-effects` (it is effectful: `code-execution`, `filesystem-write`) and
`confirm_offline_execution`. At Read only, Ask for actions and Auto-approve
actions neither is listed, and a call is refused before any request is sent. The
in-app agent applies the same rule. `x-reb-mcp.run_values` (every `value`,
`hex`, `sha256`, `results_match`, `match` and `inputs_digest` replaced by a
content marker below `--allow-content`) stays as a second line, not as the
protection. `run_id` ends in 24 hex digits of a random nonce, so it says
nothing about the inputs: 96 bits from the operating system, or, if
`/dev/urandom` cannot be read, two randomly keyed hashes of the time and a
counter. `provenance.run_id_source` says which (`os_random` or
`hashed_fallback`), and the backend logs the fallback. No error message quotes a value. The native stored-evidence window
(`reb://`) does not host the interpreter and answers 503.

## Validation

Rust unit tests in `apps/origin-trace-backend/src/wasm_run.rs` run the
synthetic fixtures in `tools/fixtures/wasm-runs/` through a return, traps,
fuel exhaustion, a deadline, a start function that never returns, supplied and
missing import stubs, a sequence that runs out, memory writes, bounded and
out-of-bounds reads, denied growth, a memory over its limit, and malformed,
empty, invalid and imported targets. Regression tests cover a 100,000-operator
global initializer (it aborted the backend), memory and table totals across
several memories and tables, a function body over 200 KB, float results such
as `1e300`, exact float spellings, the deadline at an import call, and capped
import results. `tests/http.rs` covers the confirmation refusal, hash mismatch,
contract shapes, storage and listing, and that the captured bytes and manifest
are unchanged after runs. `tests/mcp_stdio.rs` checks that `--permission`
read-only, ask and auto neither list nor send either operation and that full
runs, and keeps the review's proofs of concept (repeated expectations, fuel and
import counts, and a read-only listing of a Full run's inputs digest) as tests
that those channels are closed below Full access.
