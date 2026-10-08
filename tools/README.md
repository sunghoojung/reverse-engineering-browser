# Development Tools

This directory is for offline artifact inspectors, trace converters, schema generators, and test-data utilities.

Tools must consume the shared protocol or stored evidence. They should not create a second instrumentation path that disagrees with the browser and broker.

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
function. The older debugger fixture and backend-action checks are unchanged.

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
