# Origin Trace

Origin Trace reads local event, trace, signal, and artifact stores. The macOS
application is the normal product path. The [Rust backend](../origin-trace-backend/)
serves browser development and live debugger sessions, with the same HTTP
contracts and tools. The native Brave broker, artifact receiver, probes, and
wire formats remain C++. See the [backend boundary](../../docs/architecture/origin-trace-backend-boundary.md).

Project-wide authorization, capture, and privacy policy is in
[SAFETY.md](../../SAFETY.md); this guide describes the product's current controls
and limits.

## Run

```sh
make app
```

This packages `build/Origin Trace.app` and opens a complete live capture
session. Before launch, the app asks whether the session should retain metadata
only or bounded request and response content. The default isolated research
profile uses Chromium's mock Keychain so launch does not stop on a macOS password
prompt; do not save credentials in that profile. An explicit checkbox opts into
macOS Keychain encryption when credential storage is required. The app does not
mark the session live until the browser debugger endpoint is ready, and the
failure dialog can retry the same privacy mode without restarting Origin Trace.
**New Live Session…** in the application menu reopens these controls.

The app creates a private evidence directory and isolated browser
profile, starts its bundled broker, artifact receiver, debugger transport,
analysis helpers, and loopback UI, then launches Brave Browser Development with
all safe metadata categories enabled. Closing Origin Trace stops the session
processes. Evidence remains under `~/Library/Application Support/Origin
Trace/sessions/live/`.

Origin Trace looks beside its app bundle, in the local `browser/worktree/`
build output, and among registered applications for Brave Browser Development.
A `REB_BRAVE_BINARY` override takes precedence. The app bundles its Rust live
debugger and VM analyzer, so Python is not required. A startup problem is shown explicitly
and leaves the stored-evidence interface available offline.
Pass an explicit evidence-store or demo argument, or set
`REB_DISABLE_AUTOMATIC_LIVE_SESSION=1`, when opening the native stored-evidence
interface without starting Brave.

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

Native evidence capture retains host-level network metadata by default. Choose
**Full request and response content** in the native launch dialog to enable CDP
Traffic inspection for one live session. Command-line development sessions can
select the same mode with:

```sh
REB_CDP_NETWORK_CAPTURE=1 make live
```

This enables full URLs, request and response headers, available POST data, and
response-body retrieval for the attached tab. Authorization, cookie,
proxy-authorization, and set-cookie values are always redacted. Request and
response bodies are retained only in memory by the local UI bridge, limited to
128 KiB per side, and discarded when the live session ends. The Origin Trace
title bar visibly changes to `Live content` while this mode is active.
The content-capture label remains visible during connection failures. If the
native broker disconnects while CDP capture continues, the shell shows
`Network only`; Traffic reports both the broker failure and ongoing bounded
network capture. Broker gaps, queue drops, and network-window evictions remain
visible across either refresh path. A debugger failure retains recorded requests
and explicitly reports that network capture is unavailable.
Failed refreshes request a complete validated response on retry, so an unchanged
ETag cannot leave the connection warning stuck after recovery.
Rejected debugger actions, including a full Watch list, retain their own error
without marking active network capture or the live tab count disconnected.
Short windows keep at least one request row visible when status warnings wrap.

The live launcher disables Brave background networking, component updates, and
sync for its isolated research profile. Browser diagnostics are retained in the
session's private `brave.log`, separate from coordinator failures. The native
app pre-creates the matching macOS cache sandbox path before launch.

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

Traffic keeps a full-width request table above the inspector, including on wide
windows. Each row shows the URL path and query over its host; host-only native
metadata is labeled without implying that a path was captured. Status, type,
method, and elapsed time remain visible where width permits. The selected
request exposes its complete URL and a Copy URL action. New requests follow the
bottom of the list while the researcher is there; scrolling up preserves the
reading position and offers a new-request jump button. Use **All types** beside
search to filter by resource type. Escape closes an open navigation or filter
disclosure and restores focus. Request and response content retain their own
tabs and scroll areas.

Choose **Include headers and bodies** beside Traffic search to find a literal,
case-insensitive value in retained request or response text. Each result names
its first matching location; selecting a content match opens that side's Header
or Raw body view with Find filled in. URL, method, and status remain searchable.
Tab, domain, and resource filters scope the search before content is inspected.
Search never enables capture or fetches missing bodies. Binary and uncaptured
bodies are excluded, and retained prefixes and redacted headers limit coverage.
Large captures use an explicit 8-million UTF-16-unit search budget, newest
requests first. A partial-search notice reports inspected and omitted coverage
and suggests narrowing filters. See the [content search design](../../docs/product/traffic-content-search-v1.md).

The dark theme uses [Rosé Pine Moon](https://rosepinetheme.com/palette/), with
slightly brighter secondary labels for legibility. Appearance switches to the
existing light theme.

Field trace can send its original request string through explicit Decoder steps
and search attached sources for the selected result. Original evidence remains
visible beside a derived search value and transformation history; matches are
labeled decoded candidates. The handoff rejects binary or oversized results,
edited inputs, and changed field selections.

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
| `field_provenance.js`, `../origin-trace-backend/src/provenance.rs` | Selected request strings, bounded source candidates, replay evidence, source identity checks, and explicit value-flow gaps |
| `request_value_test.js` | Ephemeral request-value capture controls, observation selection, and comparison rendering |
| `pane_layout.js` | Shared pointer and keyboard pane resizing, responsive constraints, and local size preferences |
| `traffic_view.js` | Bounded request/response body views, explicit missing-data states, and labeled sample exchanges |
| `source_syntax.js` | Source names, display formatting, and bounded tokenization without DOM or application state |
| `../origin-trace-backend/src/app.rs`, `evidence.rs` | Loopback HTTP routing and bounded evidence reads |
| `../origin-trace-backend/src/debugger/` | CDP sessions, transport ownership, request validation, hooks, experiments, and automation |
| `../origin-trace-backend/src/workspace.rs`, `analyst.rs`, `durable.rs` | Workspace contracts, explicit analyst execution, private durable replacement |
| `../origin-trace-backend/src/decoder.rs`, `origin_trace.rs`, `vm.rs` | Native decoder adapter, trace projection, and VM analysis |
| `macos/` | Native shell, evidence readers, and helper processes |

The browser scripts load in the order declared in `index.html`. They use the
same page scope so the native shell and browser development path share one
implementation without a bundler. `evidence_models.js` contains evidence
validation and projections; `source_syntax.js` owns source display algorithms.
Live refresh and DOM updates belong in `app.js`.
The native scheme handler and packaging script explicitly list shipped assets.

Debugger support modules must not import the session coordinator or the HTTP
server. Pure request validation does not require a browser connection. The
coordinator owns session locks, authorization, cancellation, and feature
lifecycle transitions.

## Validate

```sh
make lint
make check
make e2e
```

UI changes also require interaction through the native app. Run the complete
[quality gate](../../CONTRIBUTING.md#quality-gate) before handoff, including app
build and signature verification when packaging changes.

See the [Origin Trace reference](../../docs/product/origin-trace-reference.md)
for workspace behavior, limits, command-line options, and evidence guarantees.
Versioned wire and storage contracts belong in [`protocol/`](../../protocol/).

### Interface styling

The shared shell uses neutral charcoal surfaces, thin pane dividers, and
blue selection accents in both themes. Traffic places a full-width
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
Hooks panel can target a function inside a minified line. Inline script offsets
are included; readable representations cannot change the runtime cursor.
In a connected session, **Hooks** opens the shared Runtime Hooks workspace
beside the Sources editor, with its ephemeral hit trail below the code. The
panel creates and manages the same disposable Experiment context used by
Experiments; its header labels the isolation and links back to Experiments.
Targeting guidance stays in the **Targeting help** disclosure, while armed
status uses a compact hit count.
Selecting a hit returns to the original live source location when that script
is still attached. Captured or pretty-printed sources cannot prefill a runtime
location, and an unavailable script is reported rather than guessed.
Runtime Hooks resolves a selected cursor against the original live JavaScript with
the bundled Rust parser. It chooses the innermost function, including anonymous
callbacks and arrows, and shows its start and V8 entry-search position before
arming. A cursor outside a function is rejected rather than creating a hook at
an unrelated statement. In an isolated Experiment context, Sources also lists
dedicated-worker scripts with a Worker label. The Hooks panel can select one of
those scripts; ordinary page-debugger gutters remain disabled for worker
sources. Runtime Hooks can arm page and worker definitions together, with
commands and hit records identified by target. Live-function-object mode takes
a side-effect-free expression such as `self.onmessage` in the selected target
and captures entry only; it does not discover closure-held functions
automatically. Worker attachment runs off the page-target watcher; a failed
attachment drops its scripts and retries with bounded backoff. The breakpoint
active setting is shared with attached workers. While armed, page and worker requests
appear as bounded, redacted metadata. Links to nearby hits are labeled
temporal/inferred, not causal proof.
Selecting one of these requests opens a separate ephemeral trail in
Traffic, with links back to retained hits. It is not merged into the captured
request ledger or presented as a proven initiator chain.
The optional [Request Value Test](../../docs/product/request-value-test-v2.md)
starts from **Test a request value** in Session or an isolated request's Traffic
trail. Its controls stay with the disposable-page setup, separate from the hit
trail. Select a method, query-free URL, and one JSON, form, query, header, or
raw-text value, confirm capture, then reproduce the request. No hook is needed
for observation. The active capture summary is separate from editable drafts;
changing a draft requires fresh confirmation, and restarting capture erases the
previous observations. Field names and JSON Pointers are used exactly as entered.
The comparison defaults to distinct available observations from the same target,
keeps a selected pair across refreshes, and remains usable while hooks are armed.
For an intervention, first collect a return-hook baseline, then disarm and replace
that hook with a synchronous return override before repeating the same input.
A matched comparison is intervention-associated, never complete value provenance.
The value preview is erased with the disposable context.
[Request Field Provenance v1](../../docs/product/request-field-provenance-v1.md)
connects Traffic's JSON tree and Query selection to that workflow through
**Trace value**. It shows observed request call sites, bounded original-source
text candidates, and equal-string replay hook candidates. **Test value** prefills
the exact selector; **Field trace** returns from the test. Source links require
retained target, script, and source hash identity.
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
request-response split. Compare responses includes a Rust-generated body line diff
with source line numbers, nearby context, newline markers, and explicit limits.
Polling preserves the diff's focus and scroll position. Session actions appear only after a browser target is
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

Captured `text/html` responses also expose **Preview** beside **Raw body**.
Preview reconstructs a bounded, presentation-only HTML tree inside an opaque
sandboxed frame. It blocks scripts, navigation, submission, network resources,
and external stylesheets; supported inline presentation styles survive.
Short windows scroll the request ledger and inspector instead of collapsing
the preview beneath its controls.
Omitted images appear as text placeholders. Capture truncation and the
1,000-node / 24-level rendering limits remain visible. Preview never fetches
the original URL, changes captured bytes, or enables content capture. Body and
Raw body continue to show inert source text. See
[HTML Response Preview v1](../../docs/product/html-response-preview-v1.md).

## Deobfuscation engines

Deobfuscation stays inside **Sources**. Select a JavaScript source and use the
**Deob** toggle to switch between original evidence and the mapped derived view.
The adjacent **{ }** control pretty prints JavaScript, JSON, CSS, and HTML using
the detected source type. It can format either the original evidence or the
active deobfuscated representation, so an unchanged deobfuscation result does
not leave a minified bundle on one line. Pretty printing changes only display
whitespace, keeps source-line mappings back to the captured bytes, and never
rewrites stored evidence. Input is capped at 2 MiB and formatted output at 4
MiB, with 250,000 lexical tokens and 500,000 mapping segments as pathological
input guards.
**Details > Deobfuscation** shows analysis, limits, omissions, and retry actions. The native app ships a Rust/Oxc worker for bounded static AST rewriting
over captured artifacts. It needs no Python runtime. Building the app
requires a current stable Rust toolchain (`rustup toolchain install stable`).
The Rust backend preserves classification, formatting, and literal-table
analysis for captured artifacts and live scripts. The Deobfuscation details
name the engine. Dynamic decoding remains unimplemented and is reported as an omission. Static table substitution is
restricted to non-escaping local tables with proven own-index reads.

Failed analysis remains visible until **Retry analysis** is selected. A failed
retry retains the last successful result. Source selection does not switch the
Sources editor away from original evidence. The UI retains at most eight analysis
documents and distinguishes source hashes and debugger targets in its cache.
The [versioned contract](../../protocol/deobfuscation-v1.md) defines source-map
units and how native replacements map back to their original expressions.

The production Rust AST passes and their ReverseJS comparison are documented in
[method coverage](../../docs/product/deobfuscation-method-coverage.md). The browser
server uses a built worker when available (debug before release), or the explicit
`REB_DEOBFUSCATOR_WORKER` executable. Worker failures remain errors; a missing
worker makes AST operations unavailable with an explicit error. Deob stays inside Sources.

## Programmatic HTTP access

The Rust backend's endpoints are described in the
[OpenAPI 3.1 specification](../../protocol/openapi.json). Run
`apps/origin-trace-backend/target/debug/reb-api list` from the repository root to discover
CLI operations. The `call` command requires an explicit loopback URL or the
server's `--endpoint-file`; see the [HTTP API guide](../../protocol/http-api.md)
for examples, locality checks, and known gaps. The CLI does not start or control
an installed native app session, and the native custom-scheme interface is not
itself an HTTP server.

## Pane sizes

Drag the shared borders in Traffic, Request/Response, Repeater, Sources navigator,
Memory criteria/results/details, and Tools Decoder to resize adjacent panes.
The divider shows an accent on hover or keyboard focus. Tab to a divider and use
the arrow keys along its axis; Shift changes the step from 10 to 50 pixels.
Home or double-click restores that split's default. Escape cancels an active
drag. Sizes persist as proportions in the local `origin-trace.layout.v1`
preference, independently of evidence and backend state.

Minimum pane sizes keep controls and empty states usable. The Sources toolbar
wraps within the editor; its narrow debugger overlay starts below those controls. Saved widths are suspended when the
responsive layout stacks panes, shows a single exchange side, or lacks enough
space. Returning to a wide window restores them. Handles follow scrolling and
are clipped to the active workspace. `pane_layout.js` owns the shared layout controller;
no captured evidence is modified by resizing.
