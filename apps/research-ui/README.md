# Origin Trace

Origin Trace reads local event, trace, signal, and artifact stores. The macOS
application is the normal product path; the Python server supports browser
development and live debugger sessions.

## Run

```sh
make app
```

This builds deterministic demo evidence, packages `build/Origin Trace.app`,
and opens the native application. The bundle contains its UI assets and native
helpers. It does not need the Python development server for stored evidence.

For browser development:

```sh
make ui
```

Open `http://127.0.0.1:7319`. For a live capture with the pinned custom Brave
build, use `make live`. Follow the [browser setup](../../browser/README.md)
before starting a live session.

For a live capture without a DevTools connection:

```sh
REB_NATIVE_QUIET_MODE=1 make live
```

Quiet mode keeps native evidence capture and Captured Sources available.
Live Page sources, breakpoints, stepping, watches, and console controls remain
disconnected. It does not guarantee that the custom browser is undetectable.

## Code ownership

| Location | Responsibility |
| --- | --- |
| `index.html`, `app.css` | Document structure and visual layout |
| `app_state.js`, `evidence_models.js`, `app.js` | Initial state and DOM bindings, evidence validation and projection, interaction and rendering |
| `source_syntax.js` | Source names, display formatting, and bounded tokenization without DOM or application state |
| `server.py`, `evidence_store.py` | HTTP routing and responses, bounded evidence reads and validation |
| `debugger_bridge.py`, `debugger/` | Session orchestration, transport, request validation, limits, and fixed runtime programs |
| `api_collection.py`, `local_analyst.py`, `durable_files.py` | Workspace contracts, explicit analyst execution, durable private file replacement |
| `decoder_service.py`, `origin_trace.py`, `vm_analyzer.py` | Native decoder adapter, trace projection, and offline VM analysis |
| `macos/` | Native shell, evidence readers, and helper processes |
| [`tests/research_ui/`](../../tests/research_ui/) | Python, HTTP, protocol, and UI contract tests |

The browser scripts load in the order declared in `index.html`. They use the
same page scope so the native shell and browser development path share one
implementation without a bundler. `evidence_models.js` contains evidence
validation and projections; `source_syntax.js` owns source display algorithms.
Live refresh and DOM updates belong in `app.js`. Source algorithm tests load
the shipped script directly, independently of application startup.
The native scheme handler and packaging script explicitly list shipped assets.

Debugger support modules must not import the session coordinator or the HTTP
server. Pure request validation does not require a browser connection. The
coordinator owns session locks, authorization, cancellation, and feature
lifecycle transitions.

## Validate

```sh
make ui-test
```

Run a focused module from the repository root with both source and test paths:

```sh
PYTHONPATH=apps/research-ui:tests/research_ui python3 -m unittest test_debugger_bridge
```

UI changes also require interaction through the native app. Run the complete
[quality gate](../../CONTRIBUTING.md#quality-gate) before handoff, including app
build and signature verification when packaging changes.

See the [Origin Trace reference](../../docs/product/origin-trace-reference.md)
for workspace behavior, limits, command-line options, and evidence guarantees.
Versioned wire and storage contracts belong in [`protocol/`](../../protocol/).

### Interface styling

The shared shell uses DevTools-style neutral surfaces, thin pane dividers, and
blue selection accents in both themes. Evidence owns the available width;
Traffic stacks its request list above the inspector below 900 px. Session
counts come from loaded requests, and sample evidence stays visibly labeled.
Keep labels at least 10 px and reserve stronger color for selection, connection
state, errors, and evidence confidence.

Tool workspaces put the next action before implementation details. Decoder
controls follow input, transformation, and result order; chain editing stays
beside the step list. JWT test-token creation is an optional disclosure below
inspection. Use the interface font for instructions and labels, and monospace
for captured values, code, and identifiers. Empty states explain how to begin.

Backtraces lets the researcher select a captured request, load its recorded
predecessors, and select a row to inspect event identifiers, values, and source.
Empty traces show a next action rather than a graph or coverage meter. Gaps and
shared-identifier matches remain explicit. Refresh failures retain the previous
trace, and arrow keys move between trace rows.

Sources navigation exposes Page and Captured collections. Unimplemented
Workspace and Overrides tabs are omitted until they provide a usable workflow.

The Sources sidebar starts closed without an attached debugger. Details opens
source metadata and connection status; attached sessions show debugger controls
by default. The toggle remains available at narrow window sizes.

VM analysis is a secondary Traffic view, reached through Related VM candidates
for a selected request. It has a Back to traffic control and no primary tab.

Experiments uses a shared tab row and three panes for session setup, editing,
and results. Each pane scrolls independently on wide windows; narrow windows
stack the results below the forms. Page scope, session metadata, resource
limits, request restrictions, response comparison, and advanced object search
use native disclosures. Switching tools preserves form drafts and disclosure
state. Page scope is shown only for Interceptor and Automation, which support it.
Repeater keeps method and URL controls above a persistent request-response split.
Headers and query parameters use compact key-value rows with per-row enable and
remove controls; query rows preserve duplicate names and update the request URL.
