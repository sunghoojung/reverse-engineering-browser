# Origin Trace

Origin Trace reads local event, trace, signal, and artifact stores. The macOS
application is the normal product path; the Python server supports browser
development and live debugger sessions.

## Run

```sh
make app
```

This packages `build/Origin Trace.app` and opens the native application with no
bundled evidence. The bundle contains its UI assets and native helpers. It does
not need the Python development server for stored evidence.
Each normal Origin Trace launch, including reopening it from the Dock, also
opens the custom Brave Browser Development app, then restores the Origin Trace
window and keeps it in front. Origin Trace looks beside its own app bundle, in
the local `browser/worktree/` build output, and among registered applications. A
`REB_BRAVE_BINARY` override takes precedence. This does not start a live capture
session. When custom Brave is already running, clicking Origin Trace leaves the
browser untouched and brings Origin Trace forward once. Use `make live` for the
pinned custom Brave capture workflow.

For an explicit development session with deterministic sample evidence:

```sh
make app-demo
```

Demo stores and Canvas drawing fixtures are development inputs. They are not
copied into the application bundle or used by `make app`.

For browser development:

```sh
make ui
```

Open `http://127.0.0.1:7319`. For a live capture with the pinned custom Brave
build, use `make live`. Follow the [browser setup](../../browser/README.md)
before starting a live session.

Native evidence capture retains host-level network metadata by default. Enable
full CDP Traffic inspection for one live session with:

```sh
REB_CDP_NETWORK_CAPTURE=1 make live
```

This enables full URLs, request and response headers, available POST data, and
response-body retrieval for the attached tab. Authorization, cookie,
proxy-authorization, and set-cookie values are always redacted. Request and
response bodies are retained only in memory by the local UI bridge, limited to
128 KiB per side, and discarded when the live session ends. The Origin Trace
title bar visibly changes to `Live content` while this mode is active.

Redirect hops retain their own status, response headers, and elapsed time when
CDP starts the next request. Their response bodies are explicitly unavailable;
the destination's body is never substituted for an earlier hop.

All eight fingerprint metadata families are enabled by the standard live
launcher. To retain the exact data URL returned by Canvas readback for one
authorized session, run:

```sh
REB_CAPTURE_CANVAS_IMAGES=1 make live
```

Canvas image capture is disabled by default because rendered output can contain
page content. Enabled output stays in the local session artifact store, is
limited to 2 MiB per image, and is joined to its exact `toDataURL` event. The UI
continues to show operation names when image capture is off or an image exceeds
the limit.

For a live capture without a DevTools connection:

```sh
REB_NATIVE_QUIET_MODE=1 make live
```

Quiet mode keeps native evidence capture and Captured Sources available.
Live Page sources, breakpoints, stepping, watches, and console controls remain
disconnected. It does not guarantee that the custom browser is undetectable.

If the attached renderer crashes, Sources shows `Crashed`, clears stale paused
frames, and retains captured evidence. Reload the browser tab to resume the
debugger connection. A connected browser socket alone does not imply that its
renderer is still running.

## Workspace layout

Traffic, Collection, Sources, and Fingerprinting are available in the sidebar.
Expand **Advanced** for Backtraces, Memory, Experiments, Analyst, and Tools.
Navigation into an advanced tool reveals its group automatically on desktop. On
narrow windows navigation moves above the workspace and closes after selection.

Traffic places the request list beside the inspector on wide windows, and above
it on smaller windows. Use **All types** beside search to filter by resource
type; the control shows the active filter. Escape closes an open navigation or
filter disclosure and restores focus. Request and response content retain their
own tabs and scroll areas. Timing and waterfall columns remain in the wider
stacked request table; use the Evidence inspector for timing in the compact list.

The dark theme uses [Rosé Pine Moon](https://rosepinetheme.com/palette/), with
slightly brighter secondary labels for legibility. Appearance switches to the
existing light theme.

Fingerprinting starts with an Overview of active surfaces and captured Canvas
output. **Show inactive surfaces** reveals the rest of the supported families.
Surface chips open filtered Activity. Each Canvas card keeps replay comparison,
drawing calls, and evidence identifiers in expandable sections; open sections
and summary focus survive evidence refreshes. Activity opens its details pane
when an event is selected, or with **Details**. Decoder processing limits and
result statistics are likewise available in expanders beside their controls.

Advanced workspaces keep the primary task visible and secondary information in
expandable sections. Backtraces groups correlation identifiers separately from
relationship facts. Memory places its four modes above the search and results.
Experiments separates setup, request, and response, with activity logs collapsed.
Analyst prioritizes the editor and evidence permissions; folder settings, storage,
variables, execution limits, and history can be expanded as needed. Tools keeps
input and output visible with transformation history available on demand.

## Code ownership

| Location | Responsibility |
| --- | --- |
| `index.html`, `app.css` | Document structure and visual layout |
| `app_state.js`, `evidence_models.js`, `app.js` | Initial state and DOM bindings, evidence validation and projection, interaction and rendering |
| `traffic_view.js` | Bounded request/response body views, explicit missing-data states, and labeled sample exchanges |
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

The shared shell uses neutral charcoal surfaces, thin pane dividers, and
blue selection accents in both themes. Traffic places a full-width, striped
request table above the inspector, with independently scrolling panes. Compact
resource filters share the search row on wide windows and wrap below it on
narrow windows. Selected-field actions sit beside the evidence on wide windows
and below it on narrow windows. Session
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

Fingerprinting is a first-class session workspace for Canvas, WebGL, Web Audio,
device, layout, and WebGPU APIs, Permissions, Storage, WebRTC, and Runtime activity.
Rendering is the primary view: an eight-card surface overview reports event
count, distinct operations, and the most active operation before the Canvas
readback cards.
Each card separates exact captured output, replay availability, ordered drawing
functions, and stable evidence identity. The explicit development demo
reconstructs both images locally from its visible, bounded call sequence; it
does not present those pixels as native capture. A live readback lists up to 128
supported Canvas operation names observed earlier in the same renderer stream.
When the session explicitly enables Canvas image capture, the exact bounded
`toDataURL` result is shown as captured output. The UI keeps the newest 24
readbacks and loads at most 48 MiB of Canvas preview data. The native format
still does not retain drawing arguments or a canvas object identifier, so local
replay remains unavailable and the earlier-call relationship stays
renderer-scoped.

The fingerprint workspace scopes Rendering and Activity to a captured browser
tab, all tabs, or explicitly unattributed events. The selected tab is a stable
top-level frame-tree identifier; renderer events without a live frame context
remain unattributed instead of being guessed from process ID. Activity keeps
native probe operations newest first, calls out newly arrived rows, preserves
the reading position while older rows are inspected, and renders at most 500
matching operations. Latest jumps back to the top and marks the scoped new
rows seen. The Stop probes button disables the native session through the
local broker without closing the browser. Clear events is available after
capture stops, requires confirmation, and truncates only this session's event,
trace, and request-profile stores. Canvas artifact files and other saved files
remain on disk. Detailed identifiers stay behind a disclosure. The
captured-tab buttons are historical evidence, not an open-tab count. In a live
debugger session, the browser target list supplies a separately labeled current
page-tab count, refreshed as targets open and close. Quiet mode and a lost
debugger connection show that count as unavailable rather than guessing from
captured events. The footer separates missing per-process sequence IDs from
reported queue drops, since a gap report can describe the same missing IDs.
The custom browser observes generated Web IDL callbacks for a selected native
allowlist across all eight families, in addition to the lower-level Canvas,
WebGL, and Web Audio hooks needed by internal Blink paths and selected V8 Math,
Intl, and timezone hooks. Generic DOM bindings retain only measurement and
capability members, preventing ordinary page rendering from overwhelming the
timeline. Generated non-Canvas and V8 probes retain the first observation per
call site in each capture session, while lower-level Canvas drawing hooks keep
their renderer order for readback inspection. Coverage is broad but
intentionally does not claim every browser API.
Request link view separates observed parent chains from same-context
correlation and exposes zero-count families instead of hiding coverage. The
view never claims that an observed value was transmitted or that a particular
fingerprinting vendor produced the activity.

Sources navigation exposes Page and Captured collections. Page removes scripts
when their execution context is destroyed or cleared, including removed frames
and full navigations. URL breakpoint definitions and captured evidence remain;
only resolved locations in retired scripts are discarded. Unimplemented
Workspace and Overrides tabs are omitted until they provide a usable workflow.
File rows reserve their remaining width for the filename, with full URLs in
tooltips and source metadata in Details. Folder rows retain their item counts.
Clicking original source records the UTF-16 column across syntax spans, so the
Hook pivot can target a function inside a minified line. Inline script offsets
are included; readable representations cannot change the runtime cursor.
Find counts literal, case-insensitive occurrences within rendered lines, including
multiple matches on one minified line. Enter advances and Shift+Enter goes back,
wrapping through the first 1000 matches with a visible `+` when results are capped.
The selected occurrence scrolls into view and supplies the original-source Hook
location. Formatted search is display-only; captured bytes are never rewritten.

The Sources sidebar starts closed without an attached debugger. Details opens
source metadata and connection status; attached sessions show debugger controls
by default. The toggle remains available at narrow window sizes.

VM analysis is a secondary Traffic view, reached through Related VM candidates
for a selected request. It has a Back to traffic control and no primary tab.

Experiments puts its mode switcher and current connection state in one compact
toolbar above three stable setup, editor, and result panes. Each pane scrolls
independently on wide windows; narrow windows stack the results below the forms.
Scope, session metadata, resource limits, request restrictions, response
comparison, and advanced object search use native disclosures. Switching tools
preserves form drafts and disclosure state. Scope is shown only for Interceptor
and Automation, which support it.

Repeater keeps method, URL, and Send in one command row above a persistent
request-response split. Session actions appear only after a browser target is
connected. Request tabs share the pane header, while idle badges and footers stay
hidden until they contain useful state. Headers and query parameters use compact
key-value rows with per-row enable and remove controls; query rows preserve
duplicate names and update the request URL.

Traffic opens directly to inline Request and Response tabs: independently scrolling bodies on wide
windows, and a Request/Response switch below 900 px. Body shows syntax-colored, line-numbered JSON; Raw body preserves captured text.
Live traffic is grouped by captured browser tab, with an All tabs scope and a
domain selector inside the active scope. Protocol v3 events carry the stable
top-level browser tab identifier; older evidence remains available under the
Unattributed scope. The UI retains the newest 5,000 events per refresh while
the complete append-only evidence remains on disk.
The pane menu offers JSON tree, Find, Wrap, and Copy. Text, JavaScript, XML, and
HTML remain inert text, and binary records use hex. Headers and query parameters
have separate views. Search filters visible fields or lines; selecting a leaf
reveals its complete retained value with Copy and Decode actions. Evidence opens the existing Payload, Signals, Initiator, and Timing tools.

The viewer distinguishes uncaptured, redacted, loading, failed, explicitly
empty, and truncated bodies. Its local preview is bounded to 128 KiB, 1,000 JSON
nodes, 24 levels, and 2,000 displayed text lines; limits are visible and raw/copy
operate on the retained preview. Sample exchanges are labeled in both panes.
Default native network metadata supplies no request/response header or body
bytes, so the viewer reports them as not captured. Explicit CDP network capture
projects the attached tab's full request lifecycle into Traffic and correlates
it with matching native events when their host, method, and monotonic timing
agree. CDP body retrieval can still report unavailable content for streaming,
evicted, cached, or protocol-internal responses rather than inventing bytes.
