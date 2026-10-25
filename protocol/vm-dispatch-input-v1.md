# Caller-supplied dispatch reports v1

`origin-trace-vm-dispatch-writer` is an explicit **analysis-only** fallback for
retaining caller reports alongside a captured Wasm artifact. It is not a sampler,
a native probe, a CDP pause hook, or evidence that a caller actually observed
execution. It never evaluates a module, attaches to a page, changes a live store,
or discovers a guest PC. Use it only for authorized, already collected values.

## Input and invocation

Build with `make origin-trace-backend`. Supply one UTF-8 JSON object, no comments,
duplicate properties or additional fields. All fields below are required:

```json
{
  "contract_version": 1,
  "source": "caller-supplied",
  "interpreter_artifact_id": "107",
  "source_artifact_sha256": "FULL_LOWERCASE_SHA256_FROM_THE_CAPTURED_ARTIFACT",
  "session_id": "101",
  "navigation_id": "102",
  "frame_id": "103",
  "finding_id": "105",
  "investigation_id": "106",
  "samples": [
    {
      "instruction_pointer": 7,
      "opcode": 0,
      "handler_index": 0,
      "sample_index": 0,
      "operand_count": 0
    }
  ]
}
```

These numbers illustrate the format, not observations to reuse. Replace every
identity, digest and reported value with the actual authorized input. A module
byte offset, CDP source offset, static selector, host call, request timestamp,
or frame correlation is **not** a guest PC. Unknown guest positions should not
be submitted as guessed numbers. The caller must obtain positions and selected
handlers from its own understood runtime adapter. This tool cannot validate
that interpretation or the caller's authorization.

```sh
apps/origin-trace-backend/target/debug/origin-trace-vm-dispatch-writer \
  --artifacts /private/capture/artifacts \
  --input /private/reports.json \
  --output /private/new-dispatch-reports.jsonl
```

If `CARGO_TARGET_DIR` is set, use its `debug/` binary instead. The output parent
must already exist. Existing files or symlinks are not overwritten or appended.
The entire input and artifact are validated before one atomic private (0600 on
Unix) file is published. A failed write does not authorize retrying elsewhere.
No HTTP route or MCP tool is added; effects permissions are unchanged.

Input is bounded to 2 MiB and 1–4096 samples. Identity strings must be canonical
nonzero uint64 decimal values. Sample PC, opcode, handler and sample index must
be uint32 JSON integers; operand count must be uint8. Sample indices must
increase strictly, but need not be contiguous. There is no implicit truncation,
retry, fabricated gap count, or conversion from strings/floats. Unknown fields,
versions, sources, zero/overflowed identities, duplicate fields and malformed
samples fail the whole input. The artifact must match the selected ID, full
SHA-256, session, navigation and frame. Its bytes are verified against the full
manifest digest and version-1 Wasm header, with a 64 MiB artifact limit. Manifest
scans are limited to 10000 records, 64 MiB and the existing read deadline.
Verification binds bytes and scope; it does not authenticate a runtime sample.

## Output and provenance

The output is JSONL for the existing `origin-trace-vm --events` analysis reader,
not a native broker transport stream. Each record has type `vm_dispatch_report`
and the existing fixed 128-byte dispatch payload layout. There is deliberately
no native event enum or wire opcode for this report. Do not pipe it to the native
broker or live event ingestion API; their contracts are unchanged.

Reports use a separate analysis identity namespace: process ID zero, with a
nonzero sequence derived from the input SHA-256 plus the row index. Native VM analysis
admission continues to require nonzero process IDs. Reimporting the identical
input deduplicates; a conflicting report identity is rejected, never silently
substituted. Even an unlikely digest-prefix collision cannot collide with a
native event, invocation or host parent. These are report identities, not the
original runtime process/sequence. Time, parent, bytecode artifact and thread
remain zero/unknown. The writer never creates an invocation marker.

A mandatory closed `dispatch_provenance` object carries `source: caller-supplied`,
`source_artifact_sha256`, and `input_sha256`. The report reader requires it even
when reading previously serialized JSONL. Missing, unknown, malformed or
wrong-artifact provenance cannot fall back to a native sample. The source tag
is preserved as optional `provenance` on each workspace sample. Legacy native
samples remain unchanged. PC units remain `unknown`, invocation fields remain
null, and neither a caller-provided parent nor a forged label changes this.

To analyze reports with existing host evidence, create a **new disposable
analysis input** from a consistent copy of the captured evidence and the report
file, then run the existing analyzer against a disposable artifact-store copy:

```sh
cat /private/copy/events.jsonl /private/new-dispatch-reports.jsonl \
  > /private/new-analysis-input.jsonl
apps/origin-trace-backend/target/debug/origin-trace-vm \
  --artifacts /private/copy/artifacts --events /private/new-analysis-input.jsonl
```

Do not append to or rewrite an active capture. The analyzer writes derived files
inside the selected artifact store. Its existing bounded input and conflicting
identity omissions still apply. Review omissions rather than assuming every
row was retained. Existing static detection thresholds still control whether a
workspace is created; this writer does not force a non-VM artifact into one.
Raw reports stay local and must not be automatically shared.

A structurally accepted caller report increases workspace `sample_count` and
matching unique-handler counts, but **never** upgrades that handler to observed.
The UI labels positions `Caller-reported`, displays provenance in the sample
audit, and keeps `caller-samples-unverified`. Caller-only workspaces also keep
`sampler-unavailable` (or the existing dispatch budget loss) and host links keep
`dispatch-samples-unavailable` with null guest positions. A real native sample
can independently confirm its own opcode; it cannot confirm a different opcode
that only has caller reports. Mixed provenance never removes the caller warning.

## Enabling a native sampler versus this fallback

The native `NativeProbeSink::RecordVmDispatchSample` writer only serializes
observations supplied by a reviewed runtime producer. It does not discover a
universal guest PC. `EnableOwnedRegisterSampling` and
`EnableWasmBrTableSampling` require an active VM capture session and exact,
nonzero finding/investigation/interpreter/bytecode identities; reconfiguration
clears the opt-in. The latter's `ObserveCapturedWasmModule` entry recognizes only
the narrow `wasm-br-table-dispatch-v1` shape described in
[workspace v2](vm-opcode-workspace-v2.md#native-browser-capability-boundary).
It is not arbitrary live Liftoff/TurboFan dispatch instrumentation, and module
instruction offsets must not be promoted to guest-interpreter positions.
There is no flag here that enables an absent native sampler or adds a CDP
fallback. A matched, rebuilt browser and an independently verified runtime
adapter are still needed to prove live attached-page behavior.

Owned-fixture exports and these authored regression tests prove the serializer,
admission, workspace and provenance boundaries only. They are not substitutes
for live guest-PC acceptance. This fallback therefore does not close the live
sampling or native host-causality gap in issue 327.
