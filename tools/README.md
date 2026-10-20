# Development Tools

This directory is for offline artifact inspectors, trace converters, schema generators, and test-data utilities.

Tools must consume the shared protocol or stored evidence. They should not create a second instrumentation path that disagrees with the browser and broker.

`node tools/import-browser-cookies.mjs --browser /absolute/path/to/chromium` is
the separate [private user-operated cookie import](../protocol/cookie-import-v1.md)
tool. It accepts a strict Chrome/Firefox JSON export subset, privately applies
and verifies it in a fresh short-lived off-record browser context, and requires
a second local confirmation before browsing. It does not attach to capture or
expose an agent/API import action. Real credentials require a user handoff.
Use `node tools/check-cookie-import.mjs` for synthetic tests; add
`--browser /absolute/path/to/chromium` for sandbox-preserving real-browser
set/verify/clear/dispose acceptance with synthetic cookies and no navigation.

Use `node tools/export-captured-client.mjs --input request.json --output project.zip`
with Node.js 22+ to export a reviewed saved `get_network_request` response through
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

`node tools/check-origin-trace-debugger.mjs --candidate-bridge-ui-browser` runs
an additive first-time candidate journey against the actual backend and installed
Chromium (`REB_UI_CHROMIUM`). Build `origin-trace-backend`, `debugger-transport`
`deob-worker-build` and `broker` first. The fixture starts the existing native
event broker with a private socket to use the supported live-session path; a
standalone debugger launch without a broker remains idle. No native probe
producer is fabricated: request evidence comes from actual CDP capture.
The owned loopback fixture explicitly enables
network-content capture for its synthetic loopback traffic. Its Page and
Worker actions are separate, and its candidate is a literal inside a synchronous
function. The Worker is created only by its explicit button; Page-only identity
checks do not start asynchronous Worker discovery. Read-only readiness checks
require the actual disposable target catalog, expected Page source count and
Worker script/request before the corresponding bind, without retries. The older debugger fixture and backend-action checks are unchanged.

This mode clicks the rendered Traffic field, Trace value, Find sources and
Test this candidate controls before explicitly creating/opening a disposable
page, selecting a target, binding, confirming capture and arming observation.
Changed full bytes, duplicate sources and the wrong selected worker must fail
before the matched Page baseline. CDP supplies native pointer, wheel and keyboard
input; DOM evaluation is read-only, never a substitute application action.
Screenshots at 1440, 760 and 360 pixels and a phase/input receipt are written to
`build/candidate-bridge-ui-qa/`. A failed receipt is not rendered acceptance.
Run in exact-head CI when local browser launch is unavailable; never override
browser sandbox policy to make this check run. This does not establish native
macOS WebKit acceptance, A/B/A comparison or persistence.

The candidate journey also holds delivery of one genuine successful bind response
using CDP response-stage interception, presses the visible **Stop waiting**
control, then releases the original response or records browser-aborted delivery.
It verifies no late binding/consent restoration or automatic retry and preserves
visible drafts. The backend may already have added its observation definition;
the test inspects and removes that definition through the visible control before
its separate normal bind/baseline flow. Remaining exhaustive Return, Close,
navigation and source-preparation races are controller-model coverage, not
rendered interruption claims.

The owned Stop Worker button terminates the wrong-target fixture worker before
fresh navigation; readiness verifies actual target/catalog absence rather than
relying on garbage collection or browser history caching.
The positive candidate path explicitly starts from a fresh Worker-free document,
binds the Page candidate, then uses the owned Worker button to create a new
separate target. It verifies the Page binding survives that unrelated target's
source discovery before explicit capture/arming and the genuine Page baseline.
Target-relevant stale-source refusal remains a separate boundary.

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

`make traffic-capture-check` owns the HTTP capture regression gate used by CI
and `make backend-e2e`. It checks owned-process cleanup, deterministic page
discovery (including initialization errors/timeouts and retry), flattened CDP
session lifecycle, and actual Chromium capture. Set `ORIGIN_TRACE_TEST_BROWSER`
to the installed browser path for the real-browser check. Synthetic checks cover
faults deterministically; they do not replace real-browser acceptance.
