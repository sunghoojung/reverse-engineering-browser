# Development Tools

This directory is for offline artifact inspectors, trace converters, schema generators, and test-data utilities.

Tools must consume the shared protocol or stored evidence. They should not create a second instrumentation path that disagrees with the browser and broker.

The [cookie browser import](../protocol/cookie-import-v1.md) has been removed:
the former CLI exits with an explicit refusal before reading input or launching
a browser. It has no CDP transport or fallback. Only bounded offline export
validation and name/value-free review remain. Run
`node tools/check-cookie-import.mjs` and
`python3 tools/check-cookie-import-terminal.py` for synthetic offline and
no-browser-launch refusal checks; browser acceptance is no longer supported.

Use `node tools/export-captured-client.mjs --input request.json --output project.zip`
with Node.js 22+ to export a reviewed, previously saved `reb-network-request-v1`
response (the retired `get_network_request` format) through
the existing Go/JavaScript client generator. Raw is the default;
`--mode redacted_copy` requests an explicit best-effort copy. This offline tool
never contacts a target or replaces an output. See
[client project export](../docs/product/client-project-v1.md#offline-exact-response-export)
for identity, privacy, input bounds and file-safety requirements.
`--python-client requests` or `--python-client httpx` selects a
[Python-only project](../docs/product/python-client-project-v1.md); its explicitly
versioned timeouts are per-operation, not the Go/JavaScript overall deadline.

Run `python3 tools/validate-evidence-store.py path/to/events.jsonl` to validate
normalized protocol v2 or v3 evidence, including runtime fingerprint operations
and artifact capture success or failure records. Validation checks record shape,
inline payload bounds, and sensitive HTTP metadata; it does not prove capture
completeness. Keep its category and event-type allowlists aligned with
[`include/reb/event.hpp`](../include/reb/event.hpp).

The CDP candidate bridge, live browser debugger, and associated browser-control
harnesses have been removed. `node tools/check-origin-trace-debugger.mjs
--field-provenance-only` checks retained offline models and native evidence UI
contracts. Former rendered-browser flags fail explicitly; this is not rendered
acceptance. The C++/Rust/JavaScript native observation gate is part of `make check`.

Use `node tools/export-captured-har.mjs --input request.json --output request.har` for bounded offline [HAR 1.2 export](../docs/product/har-export-v1.md). New source timing is required; unknown required phases are refused, never filled with zeros.
Use `node tools/export-graphql-sdl.mjs --input introspection.json --output schema.graphql` for [offline GraphQL introspection to SDL](../docs/product/graphql-sdl-v1.md). It reads saved schema JSON only and never queries a target.

Use `node tools/vm-semantics.mjs --help` for offline VM trace inspection, observed paths, paged location occurrences, exact-step retrieval and declarative opcode hypothesis validation. The [v1 contract](../protocol/vm-semantics-v1.md) distinguishes supplied state observations, inferred candidates and unknown semantics. Explicit output paths use private no-overwrite publication. The same models back the existing VM view.

Use `node tools/vm-agent.mjs --help` for the optional [bounded VM agent facade](../docs/development/vm-agent.md): offline JSON capabilities and supplied-trace analyses, strict exact-run reads, and explicit scoped controls for existing owned native fixtures. Imported traces remain inert; the facade never creates sessions or retries uncertain commands.

Use `node tools/vm-agent.mjs opcode-ledger --definition VM.json --input LEDGER.json`
for the [offline opcode evidence ledger](../protocol/vm-opcode-ledger-v1.md), including
strict import validation, exportable entries and explicitly bounded definition-table
coverage. Source references and test statuses remain unverified researcher assertions.
Use `node tools/vm-agent.mjs create-opcode-ledger --definition VM.json` for an
empty hash-bound ledger on stdout, or
`node tools/vm-semantics.mjs create-ledger VM.json NEW-LEDGER.json` for a private,
no-overwrite local file. Both create the existing reimportable ledger contract.

The CDP Traffic, debugger and browser capture comparison workflows were removed
with their make targets. Native event transport tests and offline UI model tests
remain in the normal gates; `make rendered-ui-check` drives the packaged app. Full live-browser acceptance requires a rebuilt
instrumented Brave and is not established by these offline checks.

## Integrated browser inputs

`brave_patch_contract.py` validates patch destinations against their independent
Git checkout owners and supplies scoped paths for temporary-index replay.
`check-integrated-brave-state.py` preserves pinned source receipts; its explicit
`adopt` mode accepts only verified tooling or byte-equivalent patch-routing
handoffs, without changing the previous receipt. The bounded Git fixtures in
`check-integrated-brave-state-test.py` exercise replay, added files, ownership,
receipt preservation and rejected production/upstream changes. See the
[integrated build guide](../docs/development/integrated-brave-build.md) for the
complete command and remaining runtime gates.

The integrated input guard also provides `advance-patch` for a one-file native
patch compatibility fix. It validates the prior receipt, clean source ancestry,
unchanged pins/overlays/patch inventory and ordered replay before changing the
verified destination. Private before/after backups and an audit permit checked
recovery; unknown edits and conflicting receipts are preserved. See
[the integrated build guide](../docs/development/integrated-brave-build.md).

## Native broker allocation benchmarks

`benchmark-event-json.cpp` compares the allocating compatibility API with the
caller-owned serialization buffer, including allocation counts, output-size
checksums, and alternating run order. Build it with the same compiler and flags
as the native broker:

```sh
c++ -std=c++20 -O2 -Iinclude tools/benchmark-event-json.cpp src/capture/event.cpp \
  -o /tmp/reb-event-json-benchmark
/tmp/reb-event-json-benchmark 2000000
```

Compare two real broker executables with:

```sh
python3 tools/benchmark-event-broker.py \
  --baseline /path/to/old/reb-event-broker \
  --candidate /path/to/new/reb-event-broker
```

The tool uses the same generated, bounded 200,000-record fixture. It alternates run order after
one warmup per executable, verifies exact SHA-256 equality of every evidence
store and all broker/index statistics, and reports both wall time and child
CPU time. Each fixture group has four Canvas records followed by one renderer
request and three exactly linked browser lifecycle records. Stream sequences
remain contiguous. The default enables both sidecars; `--without-sidecars`
measures the event store alone. `--transport socket` exercises authenticated
local IPC and per-batch live flushes when the host permits Unix sockets.
Temporary synthetic evidence is removed at exit.

Build both revisions with the same compiler and flags on the same host. Keep
competing builds stopped when comparing elapsed time; cloud-host scheduling and
filesystem contention can dominate this small allocation change. These are
component and real-broker measurements, not rebuilt-Brave performance or capture
completeness evidence.

## hcap-vm-rev

Reconstructive hCaptcha HSW spoof-surface inventories and fixtures under `tools/hcap-vm-rev/`. **Not a solver.** See that directory README.
