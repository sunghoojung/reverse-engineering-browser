# Owned opcode experiments v1

`POST /api/analysis/vm/experiments` is explicit opt-in execution of one of two
repository-owned fixed native fixtures. It creates its own disposable native
helper, independently of the live VM debugger and browser. No baseline tab,
page JavaScript, CDP Runtime/Debugger, captured code, URL, or arbitrary program
is an execution input. See [SAFETY](../SAFETY.md).

The researcher chooses the exact workspace digest, source SHA, interpreter,
finding, effect ID, fixture, opcode, explicit inputs, and expected effect.
Only the declared native reference source hashes and inferred/observed effect
rows for owned addition (opcode 2) and nonzero branch (opcode 7) are selectable.
A different source or effect is refused. The result records a digest of the
exact effect declaration and fixture revision. Source binding is a declared
reference, not attestation that captured JavaScript ran natively.

## Inputs and meaning

The native program accepts only its compiled inputs 7 and 5. Both must be
explicit in the request. Other inputs are stored as `unsupported` without
starting a helper; they are never replaced silently. The arithmetic expectation
is computed independently in Rust with unsigned 64-bit wrapping addition. The
branch prediction tests that independently calculated value for nonzero and
chooses instruction index 10 or 9. Requested expectation, independent prediction,
and native observation are separate report fields.

A dedicated helper is stepped through the selected instruction, retaining its
observed dispatch, compiled handler index, before/after instruction indices,
selected state value, exact run/invocation/record identity, helper binary hash,
and program manifest hash. The native core's branch PC remains an instruction
index; no byte offset is invented. The selected helper is stopped and reaped
before a successful result is returned. Partial or unknown native evidence,
helper failure, or uncertain disposal cannot confirm a hypothesis.

`confirmed` requires agreement among explicit input, requested expectation,
independent prediction, and native observation. `mismatch` retains a
counterexample, including a wrong expected value or PC. `unknown` preserves
uncertain execution. These statuses belong to this experiment and tested inputs
only. Neither the workspace handler nor any other input is promoted globally.
The UI lists input, expected/observed result and PC movement, with the explicit
non-generalization notice.

## Storage and lifecycle

The strict schema is [owned-opcode-experiments-v1.schema.json](owned-opcode-experiments-v1.schema.json).
GET reads `artifacts/analysis/owned-opcode-experiments-v1.json` without starting
execution. POST requires JSON, at most 4 KiB, and the existing exact loopback
request trust boundary. Unknown and duplicate request keys are rejected before
conversion to generic JSON. Native values remain canonical uint64 strings.

At most one experiment is admitted and at most 64 results/1 MiB are retained.
At capacity the next action is refused, without eviction. The exact command ID
is retained: the same request returns its stored result, while changed content
with the same ID is refused. A pending receipt is written before execution;
HTTP cancellation does not cancel native cleanup or persistence. A pending
receipt read after interruption is shown as unknown and never automatically
replayed. The helper enforces the existing 60-second lifetime and bounded
exchange deadlines. Disk failures or a lost HTTP reply mean the result is
unknown to the caller; use Read saved results, not an automatic retry.

## Validation

Focused Rust tests cover exact bindings, strict requests, independent prediction,
unsupported input without helper startup, and the real helper's register/stack
addition and branch plus four wrong-expectation counterexamples. Set
`REB_OWNED_VM_TEST_HELPER` to the built owned fixture and run the ignored
`vm_experiment::tests::owned_experiment_real_native_add_branch_and_wrong_expectation`
test. UI validator tests reject forged confirmations and malformed records.
