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

Values are `{type, value}` with string values, so they can be copied between
`args`, stubs, `results` and `expect`:

| Type | Accepted | Returned |
| --- | --- | --- |
| `i32`, `i64` | signed or unsigned decimal of that width | signed decimal |
| `f32`, `f64` | decimal, `inf`, `-inf`, or `nan:0x` with the exact bit pattern | the same forms |
| `v128` | one hexadecimal integer (optional `0x`), lane 0 in the low bits | `0x` and 32 digits |
| `funcref`, `externref` | `null` | `null` or `non-null` |

`expect` holds test vectors: `results`, and `memory` entries naming a
`memory_reads` index and the expected bytes. The record's `expectation` reports
`results_match`, each memory `match`, and `all_match` (which also requires the
outcome `returned`). A caller below Full access, whose results omit values and
bytes, can still learn whether its vectors matched.

## Limits

| Limit | Default | Maximum |
| --- | --- | --- |
| `fuel` | 100,000,000 | 10,000,000,000 |
| `memory_pages` (64 KiB pages, any memory) | 256 | 1,024 |
| `table_elements` | 10,000 | 1,000,000 |
| `call_depth` | 1,000 | 10,000 |
| `deadline_ms` (wall clock, from when the run starts reading the module) | 2,000 | 10,000 |

Fixed bounds: a 16 MiB module (larger artifacts are refused before compilation,
which no deadline can interrupt), a 1 MiB request body, 1,000 arguments, 256
stubs with up to 256 sequence entries, 16 writes and 16 reads of at most 256
KiB each in total, 256 recorded import calls with up to 16 arguments each, 64
stored runs and a 16 MiB store. A limit outside its range is refused with 400.

Fuel is granted in 1,000,000-unit slices; the deadline is checked between
slices. A refused `memory.grow` returns -1 to the module, as the specification
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
| `deadline_exceeded` | The wall-clock deadline was reached between fuel slices. |
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
`args`, `outcome`, `results`), `import_calls_total` and
`import_calls_truncated`, `memory_pages_after`, `memory_reads` (status `read`,
`out_of_bounds` or `no_memory`, with `sha256` and `hex`), `expectation`, the
`request` as run (without its confirmation) and `provenance`: `artifact_id`,
`module_sha256`, `module_byte_size`, `inputs_digest` (SHA-256 of the request
without its confirmation), the interpreter and its version, the effective
limits, and the rewrite. The POST result adds `stored` and `store_error`; when
storage fails the record is still returned with `stored: false`.

The store keeps the newest 64 runs; older ones are evicted and counted in
`evicted_runs`. `GET /api/wasm/runs` takes optional `artifact_id` and `limit`
(1 to 64, default 16) and returns runs newest first with the matching `total`.

## Content and agent access

Return values, stub values, import arguments and memory bytes derive from the
captured code and are content. Through `reb-api mcp`, `run_wasm_function` is
effectful (`code-execution`, `filesystem-write`) and is listed only with
`--allow-effects`; `get_wasm_runs` is a read. Below Full access
(`--omit-content`), every `value` and `hex` field is omitted, while outcomes,
trap kinds, counts, digests, import names and expectation matches remain. The
native stored-evidence window (`reb://`) does not host the interpreter and
answers 503.

## Validation

Rust unit tests in `apps/origin-trace-backend/src/wasm_run.rs` run the
synthetic fixtures in `tools/fixtures/wasm-runs/` through a return, traps,
fuel exhaustion, a deadline, a start function that never returns, supplied and
missing import stubs, a sequence that runs out, memory writes, bounded and
out-of-bounds reads, denied growth, a memory over its limit, and malformed,
empty, invalid and imported targets. `tests/http.rs` covers the confirmation
refusal, hash mismatch, contract shapes, storage and listing, and that the
captured bytes and manifest are unchanged after runs.
