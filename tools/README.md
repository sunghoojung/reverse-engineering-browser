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

## Live acceptance

`check-live-acceptance.py` runs the paired-release
[live acceptance](../docs/development/paired-release.md#7-live-acceptance)
through a Brave built from this tree. It serves the owned fixtures in
`live_acceptance/` on 127.0.0.1, plus `localhost` at the same port as a second
site, and starts one visibly labeled `--localhost-only` session per kind:

| Session | Start | Areas |
| --- | --- | --- |
| `content` | The runbook's content flags, promise stacks on | baseline, #425 tabs, #427 headers, #428 bodies, #429 stacks, #430 cookies, #434 phase 1 debugger, #436 limits, Wasm sampling windows and reset |
| `budget` | The content flags with 1 MiB request and response budgets | #428 and #436 budgets run out and are shown |
| `metadata` | Without `--request-content`, `--confirm-sensitive-capture` and `--canvas-images` | No header, cookie or body value is recorded; an `eval` frame reports `source_not_retained` |
| `no-stacks` | Without `--request-stacks` | No stack walk runs |

It drives each page with `session_action` `open_url` (a trusted click opens the
#425 popup), compares the stored evidence with the requests the fixture server
received and the responses it sent, and ends each session with `end`. Each case
prints `PASS`, `FAIL`, `SKIP` with its reason, or `MANUAL` with the exact steps
when it needs a person, DevTools, a profiler or HTTPS. A `SKIP` (the machine
could not set the case up, such as no brotli encoder or fewer than 30 service
worker clients) or `MANUAL` case never passes, and the final `RESULT` line
counts both. The command exits 1 on any `FAIL` and 2, after
`UNAVAILABLE: ...`, when no browser is given.

```sh
REB_BRAVE_BINARY="/path/to/Brave Browser Development" make live-acceptance-check
REB_BRAVE_BINARY="..." LIVE_ACCEPTANCE_SESSION=content make live-acceptance-check
python3 tools/check-live-acceptance.py --brave "..." --session content --only stacks,headers \
  --sessions-root /absolute/kept-evidence
python3 tools/check-live-acceptance.py --serve --port 8765   # fixture pages for the MANUAL steps
```

Without `--sessions-root` each session's evidence is removed after the run. The
Python brotli module or a `brotli` executable enables the brotli case.
`check-live-acceptance-test.py`, part of `make lint`, needs no browser: it
requests every fixture route, syntax-checks the page scripts and compares the
expected stack frames with the frames V8 records (with Node.js), and runs each
check against a stand-in backend with the real API's JSON shapes, on matching
and on differing evidence.

## Integrated browser inputs

`brave_patch_contract.py` validates patch destinations against their independent
Git checkout owners, finds each ordered stack's applied prefix in a private
index, and holds the per-workspace source lock that sync, bootstrap, the
integrated build and `advance-patch` share.
`check-integrated-brave-state.py` preserves pinned source receipts and the
build intents (`begin`) that let an interrupted init, sync or preparation
resume; its explicit `adopt` mode accepts only verified tooling or
byte-equivalent patch-routing handoffs, without changing the previous receipt.
The bounded Git fixtures in `check-integrated-brave-state-test.py` exercise
replay, added files, ownership, interrupted phases, out-of-order stacks, the
lock, receipt preservation and rejected production/upstream changes. See the
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
