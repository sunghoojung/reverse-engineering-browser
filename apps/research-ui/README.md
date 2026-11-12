# Origin Trace

Origin Trace reads local event, trace, signal, and artifact stores. The macOS
application is the normal product path. The [Rust backend](../origin-trace-backend/)
serves browser development and native evidence sessions, with the same HTTP
contracts and tools. The native Brave broker, artifact receiver, probes, and
wire formats remain C++. See the [backend boundary](../../docs/architecture/origin-trace-backend-boundary.md).

Project-wide authorization, capture, and privacy policy is in
[SAFETY.md](../../SAFETY.md); this guide describes the product's current controls
and limits.

## Native-only capture

Origin Trace reads native evidence only. The packaged app opens stored evidence
or a native live session started by `make live`, and every view is built from
broker events, retained artifacts and analyzer documents:

- **Traffic** lists native network events with exact session, process and
  sequence identities, linked origin traces and local exports.
- **Sources** shows retained artifacts, static facts, decoding and formatting;
  it never fetches or executes source. Its debugger sidebar shows native
  observation records and never pauses the page.
- **VM** shows analyzer findings, the opcode workspace, native Wasm dispatch and
  guest observations, the owned native fixture, static bytecode, packs and the
  opcode ledger.
- **Console** drives the native console against a disposable profile or an
  explicitly selected native document.
- **Collection**, **Analyst** and the notebook keep local authoring data that
  never sends requests.

The application does not launch, attach to or emulate a Chrome DevTools
Protocol debugger. Historical `cdp-attached` provenance labels and recorded
event schemas remain readable for old captures; they do not enable an
attachment or any live control. Words of the removed debugger (breakpoint,
call stack, step over and the like) appear only inside the debugger sidebar:
in its statement of the pausing availability `get_native_debugger` reports,
which is text and never a control, and in sections registered as presenting
that debugger (`native: 'pausing'`), whose every control stays disabled while
the backend reports it unsupported. `make native-only-check` and the rendered
suite check both.

The Findings **Native observations** tab displays native Wasm module offsets,
function indexes and unsigned selectors/default arms. These are physical Wasm
dispatch observations, not recovered guest-interpreter PCs or guest opcodes.
Guest rows interpreted through an explicit adapter appear beneath them with
their evidence identities. Native `call_indirect` rows follow, naming the
instruction, table, slot and the callee the entry held, or why there was none.
A slot is not a guest opcode. Host causality remains unproven.
`make native-only-check` (part of `make check`) enforces the native-only
contract and `make rendered-ui-check` verifies the rendered packaged app.

A failed VM analysis keeps the last valid evidence and displays the worker reason,
detail (`timeout`, `crash`, `spawn` or `protocol`), omitted-artifact count and retry
guidance as text. An unchanged-input retry reruns the worker.

## VM desktop workspace

The compact Analysis, Navigation, Search and Window menus invoke the existing
workspaces and handler navigation. Escape closes a menu and returns focus to its
trigger; the toolbar keeps all seven workspace modes directly accessible.

The Findings view uses compact CodeBrowser-style docks: Program Trees holds
captured findings, Symbol Tree lists the selected finding's retained handlers,
the central Handler listing drives the linked evidence inspector, and analysis
tools use a bottom tab strip. The layout keeps the Rosé Pine Moon palette.
Symbols and the up/down toolbar navigate the same selection. The literal handler
filter matches retained source offsets, opcodes and labels; selecting a symbol
clears an excluding filter. Arrow keys, Home and End navigate visible listing
rows. No-match filters keep the selected evidence available and disable stepping.
Selecting a retained dispatch site or a Symbol Tree entry opens compact analysis
and reveals its handler at the evidence pane, without a clipped tree fragment.
These docks expose existing evidence, not a native-code decompiler or editable
Ghidra project. The deterministic fixture remains explicitly opt-in.

## Traffic identity and resource filters

Traffic rows come only from native network lifecycle events. A row's exact
identity is the session, process and sequence of its unique retained
`request_started` (or `request_initiated`) event plus its non-zero request ID;
URLs, hosts and timing never substitute for it. Rows whose events carry no
request ID stay visible but cannot open traces, signal profiles or Related VM
candidates. Native network metadata retains the method, URL or host and
lifecycle status only; the inspector states that headers and bodies were not
captured instead of showing empty panes. Content capture sessions add header
blocks and cookie lists, which the **Headers** and **Cookies** tabs show.

Traffic selection updates only the mounted rows and selection summary when the
snapshot, filters, ordering and read block are unchanged. Keyboard navigation
does not repeat search or sorting and does not rebuild rows or reset ledger
scrolling. A changed snapshot, filter, block or explicit refresh renders again. `node tools/check-traffic-selection-work.mjs` checks production
controller work and selection invariants. Add `--baseline-ref=<commit>` for a
reproducible authored 5,000-record before-and-after Node benchmark. Those
timings are not rendered browser or native-app latency; the Requests browser
gate separately exercises actual row keyboard selection.

## Command palette

⌘ K opens a search palette from anywhere, including text fields. Ctrl K opens
it everywhere except text fields, where macOS keeps Ctrl K for deleting to the
end of the line. **Search** at the top of the sidebar opens it too; the icon rail
shows it as an icon named Search with the shortcut in its tooltip. A modal
dialog keeps the keyboard, so the palette never opens over the notebook or the
export dialog, and ⌘ / Ctrl with a digit is ignored while it is open.

An empty query lists the eight workspaces and four actions: open or close the
Console, open the notebook, switch the theme, and collapse or expand the
sidebar. Typing also searches retained Traffic requests (method, host and path,
status, type and exact request identity), captured source files (name, URL,
kind and size) and the VM findings currently listed, and offers one **Search all
sources** entry that runs the Sources text search for the query. Matching is a
case-insensitive literal substring of a result's title or detail. A title that
starts with the query ranks first, then a word inside the title, any title
match, a detail that starts with it or has it at a word start, and any detail
match; ties keep their source order. Each group lists at most 50 results and
says how many more matched; the status line repeats it.

Arrow Up and Down move through the results and wrap, Home and End jump to the
first and last, and Enter or a click runs one. Escape, a click outside or ⌘ K
closes the palette and returns focus to where it was. A result runs the same
function as the control it stands for: workspaces and actions click their
sidebar entries, requests and files open through the exact-identity link (so
Back returns and a changed or ambiguous record is refused), rows without an
exact identity are selected the way a click on the row or Quick Open does, and
a VM finding is selected through its own list row. Captured titles and details
are inserted as text. Typing in the palette reads only what the workspaces
already hold and never fetches, captures or runs anything; only choosing **Search
all sources** reads retained artifact text, through Sources.

Other modules can add result groups through one registry:

```js
const remove = globalThis.RebCommandPalette?.addProvider({
  id: 'names',        // unique; registering the same id replaces the provider
  group: 'Names',     // group heading, at most 64 characters
  search(query) {     // synchronous and bounded; never fetches
    return [{title: 'checkoutSignature', detail: 'cart.js:42', run() { /* open it */ }}];
  }
});
globalThis.RebCommandPalette?.open('checkout');   // optional initial query
```

`command_palette.js` loads before every other module, so `addProvider` is
available while any later script evaluates, before or after the palette is
mounted. `search` receives the trimmed query (1 to 256 characters) and is not
called for an empty query. Return an array of `{title, detail?, run}` with a
non-empty string title, an optional string detail and a function; the palette
keeps only results whose title or detail contains the query, so a superset is
fine, and ranks and caps them like the built-in groups. It scans at most 10,000
candidates per provider and says so when a list is longer. Malformed results are
skipped and counted in the group. A provider that throws or returns anything
other than an array shows a note in its own group, and the other groups are
unaffected. The palette closes and restores focus before `run` is called, and an
exception from `run` is logged without breaking the page. External groups follow
the built-in ones in registration order. `addProvider` throws a `TypeError` for
a malformed provider and returns a function that removes exactly that
registration. `node tools/check-command-palette.mjs` is run by
`make javascript-check` through the debugger check and exercises the registry,
key guards and the app's providers against the production code.

## Connected investigations

Every workspace is a direct sidebar entry; none waits behind a menu. A
sidebar choice keeps keyboard focus on that entry, while linked Back/Forward
keeps its existing destination-focus restoration. A refused link leaves the
current workspace intact.

Cross-workspace navigation uses one in-memory Back/Forward trail (at most 24
stops). Alt+Left and Alt+Right work outside editors; visible controls remain
available. Returns validate the exact retained session/event or artifact/hash,
restore selected request/trace/source or Evidence record and visible pane,
original range, focus and bounded pane
scroll positions, and leave owner-managed drafts in place. Expired or ambiguous
links remain visible and do not switch to similarly named evidence. Sources
returns wait for an evicted preview to finish rendering before restoring pane
scroll and focus. Newer interaction cancels that delayed restoration. An evicted
WASM inspection shows an explicit **Retry inspection** action; Back/Forward and
later catalog refreshes do not silently rerun the analysis.
On phones, expanded **Link context** uses a full-width row below Back/Forward;
long explanations stay in the bounded navigation scroller above the workspace.

A captured request opens its recorded lineage in Flow using its exact session,
process and sequence identity. Reused IDs in other sessions cannot supply its
trace; unsafe numeric identities and ambiguous rows are rejected. **Open retained source** uses
that step's session and artifact identity. A Facts **Original bytes** link
verifies complete retained UTF-8 bytes and SHA-256; **Decode range** copies those
exact bytes, up to 64 KiB, into Decoder. **Open original evidence** retains the
source identity and half-open byte range. Evidence field handoffs distinguish
selected string bytes from unavailable raw HTTP offsets.
Evidence source links use the selected native record’s exact retained artifact
identity. Back restores both observation-list and record-inspector scroll, the
visible trigger and current scope/search without selecting package exports.
Replacing an existing Decoder draft requires confirmation. Input edits mark its
prior origin stale. Navigation never transforms, sends, captures or executes.

The explicit Collection copy action saves only method and a query-free URL
after exact request identity and Collection draft checks. A confirmed recipe ID
is a copied template, never captured evidence; no request is sent.

Console URL links open a bounded, explicitly unverified source search. The
separate disposable browser is not assigned a captured-artifact identity, and
Console line offsets are never applied to search candidates. Host-and-time
matches likewise cannot become exact captured trace links, request-specific
signal profiles, or request-filtered VM candidates.
See [Investigation navigation v1](../../docs/product/investigation-navigation-v1.md)
for the identity boundary, retained limits and integration points.

## Cross-references

The cross-references button at the right end of the title bar, or X outside a
text field, opens a dock on the right that follows the current selection: a request in Traffic, a source in
Sources (or one Wasm inspection row, by click or by tabbing to its gutter), a
handler in VM, or an API call in Fingerprinting. It lists the evidence pointing
at that selection and the evidence it points at, using only recorded links:
request initiator and lifecycle, parent events, host links from retained dispatch
samples, artifact creators, and Wasm import, export and direct-call uses. A
missing link is a gap row with its reason; no caller is inferred. The first line
names the target and shows `0 in · 2 out`, the filter matches only names already
on the rows, and the In and Out pills show or hide each direction. Each row
carries its kind and sequence or artifact identifier; selecting one shows its full
name, source and correlation identifiers below the list, so a truncated value
stays readable.

Arrow keys move through rows, Enter or double-click opens the existing row in
Traffic, Sources, Fingerprinting or Evidence, `/` focuses the filter, and Escape
returns focus to where it came from. Below 1000 px the dock covers the workspace
edge instead of squeezing it. The dock queries [`/api/xrefs`](../../protocol/http-api.md#cross-references)
once per selection, debounces selection changes, and aborts stale requests.
Only visible rows are mounted, and at most a few nearby pages stay in memory; the
rest are refetched as the list scrolls. Closing the dock drops the results and
stops its timers. The stored-evidence window has no backend, so the dock says so
instead of listing nothing.

## Debugger sidebar

**Debugger** in the Sources toolbar opens a sidebar in the column Details uses,
so opening one closes the other; below a 1,112 px window it overlays the editor
as Details does. It is phase 1 of [native debugger v1](../../docs/product/native-debugger-v1.md):
native observation records that never pause the page, read from
`get_native_debugger` ([native debugger observation v1](../../protocol/native-debugger-observation-v1.md)).
The header says "Observes, never pauses" and the status line says what the
sidebar reads and when it last read; only a change of that state is
announced, not the time of each read or the interval. In a live window, while it is open and
Sources is showing, it reads every 2 seconds, or four times as long as the
last read took, up to 30 seconds. The stored-evidence window (`reb://`)
answers the same reads from its fixed store, so it reads once when opened and
again only on **Read again**; its reads wait up to 45 seconds, since the
bundled backend may take 15 seconds to start before it scans the newest
64 MiB. A window without a backend (`file:`) sends
nothing and says it cannot read. Closed or behind another workspace, the
sidebar runs no timer and sends nothing. One read is in flight at a time: a
newer read, closing, leaving Sources or a cleared or replaced store aborts it.
A failed or malformed read keeps the last state, marks each section "last
read" and dims it, and says why.

Each section is a collapsible pane:

- **Threads**, the Threads view: Console documents (top, child and
  out-of-process frames, as the Console listing derives them), observed frames
  (the session, renderer and frame of the observation records among the
  newest 2,048 records that are observations or gaps of any kind, within the
  newest 64 MiB of the store, with the origin of a retained document of that exact frame when there is one)
  and workers that started requests (from the newest 2,048 request records).
  Each row gives the origin a line of its own; the selected thread's kind,
  origin, frame, process and state are listed in full below the list. Arrow
  keys, Home, End and the Page keys move through the list, and Enter, Space, a
  click or a double-click selects or clears a thread once. An observed frame scopes
  Observations and the Sources tree to that exact session and frame, and the
  tree says so. A Console document scopes only Watch rules, because it carries
  no native frame ID; a worker scopes nothing, because rules match only a
  document's main thread and compiled worker scripts carry frame 0.
- **Watch rules**: what the renderer confirmed armed, rule by rule. When the
  Console is connected to a live capture document, selected and confirmed in
  the Console as before, one form, drawn for that document and naming it on
  its button, arms request rules (an optional method, then URL text), event
  types, timers, CSP violations and exceptions there through that
  connection's `watch` command, or clears them with `unwatch`. When the
  Console holds another document by the time the form is submitted, nothing
  is sent, the section says so, and the form is drawn again for the new
  document. Arming replaces the set and keeps the DOM rules the Console armed
  on the same document. A refused set leaves nothing armed, and nothing is
  retried. Without a live connection the section says how to get one and
  shows no form.
- **Observations**: the newest records, 128 at a time and up to 4,096 with
  **Show older records**, filtered by kind. A note says how much of the store
  the rows were read from: the whole store, or its newest bytes and why the
  read stopped. An empty list says that no record exists only when the whole
  store was read. Each row names the kind, what happened, its monotonic time,
  category, renderer process, frame, sequence and request. Choosing a row
  (a click, or the arrow keys) marks it at once, brings its details into view,
  and again once its positions resolve, lists every identifier and resolves its own
  frame (listener, timer callback or throw site) and its stack with
  `get_request_stack`. Enter or **Open …** opens that position in Sources; a
  watched request opens its Traffic row on the Initiator tab through Traffic's
  own row selection, after locating it in the request index when it is
  outside the block Traffic holds. Its link says it is working. A newer
  click, choosing another record, the kind filter, **Show newest**, closing
  the record's details or the sidebar, and leaving Sources (even when the
  researcher comes back before the lookup answers) each cancel it, and a
  cancelled lookup never switches to Traffic. Until the researcher has a place, the
  list follows the newest page. Once a row is selected, the list is scrolled
  from its top or older pages are loaded, the rows are kept: each read adds
  the records written since, reading at most two more pages to reach them,
  and keeps the scroll position and selection. When more was written than
  that, the list stays as it is, names the byte span it does not hold, and
  **Show newest** returns to the newest page. Past 4,096 rows the oldest are
  dropped, and the list says how many. A failed read changes neither the rows
  nor their note. Malformed
  records, a renderer's `debugger_observation_budget` gap and store sequence
  gaps are stated above the list, which is as tall as its rows up to a cap.
- **Pausing**: one statement of the availability `get_native_debugger` reports.
  Today it is unsupported, so the sidebar offers no control to stop, step or
  inspect a paused frame. When sections registered with `native: 'pausing'`
  exist, the statement names them: available, their controls are there;
  unsupported, those controls stay disabled.

Threads and Observations mount only the rows in view, and captured names such
as event types and hosts are inserted as text.

Sections come from one registry, so a later change adds its own; the pausing
debugger adds its sections here. `debugger_sidebar.js` loads right after
`command_palette.js`, so `addSection` exists while any later script evaluates:

```js
const remove = globalThis.RebDebuggerSidebar.addSection({
  id: 'breakpoints',     // 1 to 32 lowercase letters, digits or dashes; the same id replaces
  title: 'Breakpoints',  // the pane's summary, at most 64 characters
  order: 50,             // 50 and above: Threads 10, Watch rules 20, Observations 30, Pausing 40
  collapsed: false,      // optional: start collapsed
  native: 'pausing',     // required for a section of the pausing debugger
  summary(view) { return String(view.document?.breakpoints?.length ?? ''); },  // optional count
  render(body, view) { /* fill body from view; called after every read while the pane is open */ },
  release(body) { /* optional: drop rows and timers when collapsed or closed */ }
});
```

`view` holds `status` (`loading`, `ready`, `disconnected`, `malformed` or
`unavailable`), `document` (the last valid `get_native_debugger` answer, or
null), `error`, `updatedAt`, the selected `thread`, `selectThread(thread)`,
`refresh()`, `repaint()` and `nativeSections()`. `refresh()` asks for a read
soon: from a render, or anything a render queued, it does nothing; while a
read is in flight it runs one more afterwards; otherwise it reads once a
second has passed since the last read started. `repaint()` renders again from
the last read without a read. A section whose `summary` throws keeps its
body, and one whose `render` throws shows the error in its own pane only.
`addSection` throws a `TypeError` for a malformed section and returns a
function that removes exactly that registration.

The contract for a later section, which `make native-only-check` and the
rendered suite enforce:

- A section of the pausing debugger sets `native: 'pausing'` (marked
  `data-debugger-native="pausing"`). Only such sections and the Pausing
  statement (`data-debugger-native="availability"`), and only inside
  `#debugger-sidebar`, may use the paused-state words (breakpoint, paused
  frame, call stack, step over, step into, resume); every other removed
  feature fails there too, and a marker anywhere else, or with another value,
  is a failure.
- While `view.document?.availability` is not `available`, and while
  `view.status` is not `ready`, every control in such a section is a form
  control (`button`, `input`, `select`, `textarea`) with `disabled` set.
  `aria-disabled` does not count, and a `details`, a `summary`, a link, a `tabindex`, an
  editable region or any element with a `role` other than `presentation` or
  `none` cannot be disabled, so none may appear then.
- `render` handles `view.document === null` (before the first read, and in a
  window without a backend).
- Ids other than the built-in `threads`, `watch-rules`, `observations` and
  `pausing`, which cannot be replaced, and an order of 50 or above, so the
  section follows the Pausing statement; `nativeSections()` lists it and the
  statement names it.
- Never call `view.refresh()` from inside `render`, directly or deferred; the
  sidebar reads on its own after every change it makes.

`make native-only-check` drives the production sidebar in DOM models
(`tools/check-native-only-ui.mjs`, and `tools/check-debugger-sidebar.mjs` with
real timers and a stub backend) and `test31DebuggerSidebar` drives it in the
packaged app.

## Local passive security report

The passive security report is an offline command for one saved exact-request
API response (`tools/report-passive-security.mjs`, library
`tools/passive-security.cjs`). Live native Traffic retains no response bodies,
so Origin Trace has no in-app report. See
[Passive security report v1](../../docs/product/passive-security-report-v1.md)
for the schema, rules, bounds and commands.

## Captured request exports

Live native Traffic has no CDP exchange to replay, so Traffic has no capture
actions. **Export…** in the Traffic toolbar converts a local
introspection JSON file (`__schema` or `data.__schema`, up to 1 MiB) to GraphQL
SDL; duplicate keys, invalid UTF-8, partial/error schemas and unsafe SDL
literals are refused. Export never queries an introspection endpoint or sends a
request. SDL is a raw schema export: descriptions and identifiers can be
sensitive.

Saved `reb-network-request-v1` documents remain usable through offline
commands: `tools/export-captured-client.mjs` (client projects, see
[Client project v1](../../docs/product/client-project-v1.md)),
`tools/export-captured-har.mjs` and `tools/export-graphql-sdl.mjs`. They read
local files only and never send captured requests.
`node tools/check-captured-export-ui.mjs` exercises the dialog handlers with an
in-memory DOM; native Save-panel testing remains a macOS gate.

## Saved investigation notebook

Use **Notebook** in the sidebar to create a named local notebook, then **Pin
selected evidence** from a captured Source, native Request, or selected Evidence
observation. Add a concise name and note and choose **Save pin**. Exact captured
source ranges are preserved when they came from verified original-byte navigation.
Reopening resolves the same retained identity; changed, missing or ambiguous
records remain explicit. Names can repeat without confusing their scoped IDs.

Notebooks survive application reload as non-executable JSON scratchpads in the
existing Analyst library. The notebook opens as a side sheet beside the evidence
and clearly discloses its library-wide scope across sessions. Existing scripts and notes stay unchanged. Pins store reference
metadata and event fingerprints, never copied source/request/console content or
capture permissions. Typed notes may contain private information and remain local.
Cancellation cannot undo an already committed save: unconfirmed writes require
an explicit reload before another save. See the [notebook contract](../../protocol/investigation-notebook-v1.md)
for bounds, identity semantics and validation coverage.

## Researcher names

Name what you have understood, as in a disassembler: a request as "session token
mint", a source as "obfuscated loader", a VM handler as `push_const`. Choose the
pencil in the Traffic request header, **Rename** in the Sources **More** menu or
**Rename** in the VM Selected handler pane, or press F2 on the focused or selected
request, source (tree row or tab) or handler (listing or Symbol Tree row). The
inline editor saves on Enter, cancels on Escape or when focus leaves it, and an
empty name clears the name.

A name is your interpretation, not evidence. It appears in italic in the
researcher-name color beside the raw value, which stays visible: first in the
Traffic row's name cell and request header, in the Sources tree and file tab, and
in the VM handler listing, Symbol Tree and Selected handler. Traffic search and
the handler filter also match names. Names attach to exact identities only (the
request's root event and request ID, the artifact's session, ID, SHA-256 and size,
or the handler's finding, source artifact, listing key and source range), so an
item that merely shares a URL, file name or handler label never inherits a name,
and replaced or ambiguous evidence shows none.

Names survive relaunch in one non-executable `Evidence names.reb-names.json`
scratchpad in the Analyst library, written through the existing local Analyst
routes. Each save rereads the library first; a name changed elsewhere since you
opened the editor is shown to you instead of being overwritten. When the command
palette is available, its **Names** group finds named items and opens them
through the normal selection paths. See the
[names contract](../../docs/product/evidence-names-v1.md) for identities, bounds and
concurrency.

## In-app agent

The **Agent** dock (the button at the titlebar's right edge, or ⌘⇧A) puts Claude, ChatGPT or Grok
beside the evidence. It is closed by default, and the agent in it is off by
default. Turning it on is an explicit action for the current session, behind a
disclosure, and stops completely when it is turned off.

The header is one row: **Agent**, a status chip with the running model and how
it is paid for (for example *Claude Opus 5.5 · API key*, or *Off*), a badge
with the running permission level (*Read only*, *Ask*, *Auto-approve* in amber
or *Full access* in red), and icon buttons for **New conversation**, a menu and
close. The menu holds **What leaves this Mac** (the disclosure and the account
details), **Change provider or model**, **Clear transcript** (behind a
confirmation), **Lower to** each level below the running one, **Raise
permission…** and **Turn off**; tool and token counts are in the menu and the
chip's tooltip.

- **Off**: a centered setup with one card per provider and its real readiness
  (a stored key, a ChatGPT sign-in, or what the CLI reported), the card's own
  **Add key**, **Sign in** or **Check again**, and **Turn on for this
  session**. A CLI is asked about its sign-in only when its card is chosen.
- **Consent**: what leaves the machine for the chosen provider and payment, and
  the **Permission** choice below, before anything starts.
- **On**: the conversation, with the composer card at the bottom. Its model
  button opens a picker grouped by provider; choosing another provider, payment
  or model turns the agent off and asks again, as doing it by hand does. Return
  sends and Shift+Return adds a line; during a turn Send becomes Stop and
  Return does nothing. The empty state offers suggestions that fill the
  composer without sending.
- **New conversation** enables the same provider, model, permission level and
  session again with an empty history. Earlier rows stay in the local
  transcript (**Show earlier rows**) unless **Clear transcript** deleted them.
- A tool call is one collapsed line with its state, arguments and result size.
  Click it or press Return or Space to see the arguments and the full result
  sent to the provider in a bounded, scrollable block; the block is drawn only
  while open. An action request is an amber card with **Deny** and **Allow
  once**, focused when it appears while the researcher is in the dock.

### Permission levels

One setting with four ordered levels, chosen in consent for this session. The
same names are used by `reb-api mcp --permission`, so a Claude Code or Codex
client connected through `scripts/reb-api-mcp.sh` can run at the same level
([local coding agents](../../docs/development/local-coding-agents.md#permission-levels)).

| Level | Tools the model gets | What a call needs | What leaves this Mac |
| --- | --- | --- | --- |
| **Read only** (default) | Structural reads | Nothing | Question, pins, structural results |
| **Ask for actions** | Reads and actions | **Allow once** per action | The same |
| **Auto-approve actions** | Reads and actions | Nothing; every call and result is in the transcript | The same |
| **Full access** | Also content reads (`get_artifact_text`, `search_artifact_text`), store-path and draft reads, and its own live sessions (`start_live_session`, `session_action`) | Nothing | Also source, Wasm bytes and disassembly, VM bytecode, request and response bodies and every content field of results |

Below Full access the tool server omits captured content from every result,
and reads that return local store paths (`get_health`) or the researcher's own
drafts (Collection, Analyst workspace) are not offered. `get_artifact_content`
is never offered: Full access reads bytes as text pages instead.

- The default is Read only. The page remembers the last choice across launches
  only up to Ask for actions.
- Consent is the only confirmation. It lists the levels with the chosen one's
  line of text, then one box with what leaves the Mac. For Auto-approve and
  Full access that box is the plain-language warning; for Full access it lists
  exactly what more leaves the Mac and offers a separate **Also allow
  sensitive capture options** box, off by default and never remembered,
  without which the agent's own sessions cannot name `request_content`,
  `response_media`, `canvas_images` or `js_invocation_digests`. The primary
  button names the level (**Turn on Full access**). At the normal window size
  the box and the button are in view together; at a short window, choosing a
  level scrolls them in.
- Native accepts only a known level, and the sensitive choice only with Full
  access (`AgentPermission.requested`), before it touches the running agent.
- **Lower to** applies at once and keeps the conversation: native filters the
  tools, the next tool call is decided at the lower level, the tool server
  restarts at it, and the graph's next model call gets the lower prompt. A CLI
  whose own tool server ran at Full access is ended and starts again at the
  lower level with the next question; a CLI kept running is told the new level
  in its next question.
- **Raise permission…** turns the agent off and opens consent with the next
  level chosen. **Stop** ends a turn and **Turn off** ends everything at every
  level.
- The system prompt has one paragraph per level (`AgentCore.swift`, matched by
  `agent-runtime/src/runtime.mjs`). Below Full access it says content stays on
  the Mac unless pinned; at Full access it says content read through tools goes
  to the provider, how to page through it, and whether sensitive capture
  options are allowed.

### Keys and subscriptions

The chosen provider card chooses how that provider is paid for: **API key**
(the researcher's own key in the Keychain) or **Subscription** (the
researcher's own plan). Grok has only the subscription.

| Provider | Subscription path | Loop | Where the login lives |
| --- | --- | --- | --- |
| ChatGPT | OpenAI token sharing: **Sign in** opens ChatGPT in the default browser | LangGraph, unchanged | Access and refresh tokens in the Keychain |
| Claude | The installed `claude` CLI, already signed in with `claude auth login` | The CLI's own loop (`claude -p`, stream-json) | With the CLI; Origin Trace never reads it |
| Grok | The installed `grok` CLI, already signed in with `grok login` | The CLI's own loop (`grok agent stdio`, ACP) | With the CLI; Origin Trace never reads it |

The Claude and Grok paths are for the researcher's own local use of their own
installed and signed-in CLI. Origin Trace does not offer a claude.ai or Grok
sign-in of its own; the dock asks the CLI (`claude auth status`,
`grok models`) whether it is signed in and, if not, says which command to run
in Terminal.

**ChatGPT token sharing** is the sign-in T3 Code's managed Codex mode uses.
Native (`macos/AgentChatGPTAuth.swift`) reads the OIDC discovery document and
refuses it unless the issuer is `https://auth.openai.com` and every endpoint is
on that origin. It opens an authorization-code request with PKCE S256, `state`
and `nonce`, scope `openid profile email offline_access resource.invoke
chatgpt.tokens.use.direct` and resource `https://api.openai.com/v1`. The first
sign-in registers with `client_id=dynamic_agent_client` and
`agent_name_hint=Origin Trace`; later ones reuse the returned `oaiapp_...`
client with `login_hint` and `id_token_hint`. `ext_agent_host_id` is a random
install id kept in the Keychain. The callback is a one-shot listener on
`http://127.0.0.1:<port>/auth/callback` that accepts only this sign-in's state
and expires after five minutes. The ID token must verify against the issuer's
JWKS (RS256 or ES256) with this client as audience and this nonce, and the
granted scope must include `chatgpt.tokens.use.direct`; otherwise the dock
says token sharing was not allowed. Before each model request native renews
the access token when it is within a minute of expiry, honoring
`earliest_refresh_at`; a refused renewal forgets the tokens and asks for a new
sign-in. The token goes only on the existing `/v1/responses` route and the
model list (`/v1/models`); the web view never sees it. **Sign out of ChatGPT**
in Info revokes the refresh token and forgets the tokens. A real sign-in needs
the researcher's consent in the browser, so it is a manual check.

**The Claude CLI** (`macos/AgentCLI.swift`) runs as `claude -p --input-format
stream-json --output-format stream-json --verbose --include-partial-messages
--permission-prompt-tool stdio --permission-mode default --strict-mcp-config
--mcp-config <reb only> --tools "" --setting-sources "" --disable-slash-commands
--no-session-persistence --system-prompt <the dock's prompt>`, plus
`--disallowed-tools` for every reb-api tool the graph would not list. So it has
no built-in tool, no other MCP server, no user or project settings, hooks or
CLAUDE.md, and writes no session file. `--bare` is not used because it ignores
the claude.ai login. The CLI's `init` report must list only `mcp__reb__*` tools
and the `reb` server, and `apiKeySource: none`, or the CLI is stopped.

**The Grok CLI** runs as `grok --permission-mode default --disable-web-search
--no-subagents agent --agent-profile <profile> --no-leader stdio`. The agent
profile allows only `search_tool` and `use_tool`, through which Grok reaches
MCP tools. Grok merges MCP servers from the researcher's own Grok configuration
into every ACP session, whatever the client sends, so the private working
folder's `.grok/config.toml` replaces each of them with a disabled stub, and
the environment turns off folder trust (so that file applies), memory,
subagents, web fetch, the update check, and Claude, Cursor and Codex skills,
rules, agents, MCP servers, hooks and sessions. `grok inspect --json` must then
show no enabled MCP server, hook or plugin, or Grok is not started. A
`servers_updated` notice naming any server, a tool call that is not
`search_tool` or `use_tool`, or a permission request that is not a `reb__` tool
stops the CLI. Grok keeps its own record of the session under
`~/.grok/sessions`, as it does for any session.

Both CLIs run from a private, user-only folder under
`~/Library/Application Support/Origin Trace/agent-cli/`, in their own process
group, with an environment allowlist: no `ANTHROPIC_API_KEY`,
`ANTHROPIC_BASE_URL`, `XAI_API_KEY` or `GROK_OAUTH2_REFERRER` reaches them, so
they use the subscription. A CLI starts with the first question, not when the
switch turns on, and keeps its conversation between turns. **Stop**, the switch,
a navigation, app exit and 15 idle minutes kill its whole process group,
including helpers it moved to another group; the next question starts a new
conversation and says so. Every tool call it wants comes to native first and
is decided by the running level (`AgentToolGate`): what the level runs, runs;
at Ask for actions an action waits for **Allow once** or **Deny**; anything
else is refused. Lines longer than 16 MiB, more than 128 tool rounds or
repeated unreadable output stop it with a visible row.

### Where the loop runs

The agent loop is LangGraph, in this page's WKWebView. It is a `StateGraph` from
`@langchain/langgraph/web` with three nodes (`model`, `review`, `tools`), the
official `ChatAnthropic` and `ChatOpenAI` chat models, and one LangChain `tool()`
per tool the native tool server lists. The source is
[`agent-runtime/src/`](agent-runtime/src/). LangChain's `createAgent` with its
human-in-the-loop middleware is not used, because that middleware pauses with
`interrupt()`. `interrupt()` reads the graph config from `AsyncLocalStorage`,
which WKWebView does not have, so it fails with "Called interrupt() outside the
context of a graph". The graph instead stops at a static breakpoint before
`review` whenever the model asks for an action. Each action then waits for its
own **Allow once** or **Deny**; there is no standing grant. Deny records a
refused tool result. Allow once resumes the graph, which runs that one call.

Each turn runs on its own checkpoint thread, deleted when the turn ends, so no
checkpoint outlives a turn. The conversation is kept in the page with a 2 MiB
budget (a tool result is at most the 128 KiB inline limit). Older whole turns
leave with a labeled notice; for Claude, their signed thinking leaves with them.
A turn stops visibly after 128 rounds of tool calls.

### Packages and bundle

[`agent-runtime/package.json`](agent-runtime/package.json) pins
`@langchain/langgraph` 1.5.2, `@langchain/core` 1.3.0,
`@langchain/anthropic` 1.6.0 and `@langchain/openai` 1.7.0, with esbuild
0.28.2. Every package in the lockfile was published at least two weeks before
it was pinned (`npm install --before`). `make app-build` runs
[`scripts/build-agent-runtime.sh`](../../scripts/build-agent-runtime.sh):
`npm ci --ignore-scripts` from the lockfile, then one minified browser bundle
per provider, `agent_runtime_claude.js` (about 1.5 MB) and
`agent_runtime_chatgpt.js` (about 1.8 MB). The build refuses any Node built-in,
and the third-party license notices ship as
`Contents/Resources/AgentRuntimeLicenses.txt`. The page loads the bundle for
the selected provider from the packaged resources the first time the agent is
turned on, so a dock that is closed, or never turned on, parses none of it.
Nothing in the bundle fetches on its own: the only network request is the
provider call below. The browser-only `make ui` path has no bundle and says the
agent is unavailable.

### What stays native

The native app keeps what the page must not hold:

- **Keys and tokens.** The Keychain holds one item per provider, and the
  ChatGPT subscription's tokens and registration under their own accounts.
  **Add key** opens a native secure field, so a key never enters the web view. The chat models are
  given a placeholder key and a `fetch` that goes through the native bridge.
  Native forwards a request only to `https://api.anthropic.com/v1/messages`
  (optionally `?beta=true`) or `https://api.openai.com/v1/responses`, by POST and
  for the provider that was enabled. It drops every credential and cookie header
  the page sent and adds the real key itself. The response streams back as
  chunks on SSE event boundaries, so token streaming works. An error body is
  bounded and scrubbed of anything shaped like a key. This is a transport for
  the two chat models, not a general proxy.
- **The permission level**, set only by enabling from consent and by
  lowering. `AgentToolGate` decides every tool call by it for the LangGraph
  loop and both CLI drivers.
- **The tool server.** One `reb-api mcp --permission <level>` child (the
  packaged `OriginTraceAPI`) with `--base-url` set to this workspace's loopback
  API, plus `--allow-sensitive-capture` only when that box was ticked. Below
  Full access its environment is only `LANG` and `LC_ALL`; at Full access it
  also gets `HOME`, `USER`, `LOGNAME`, `TMPDIR`, a fixed `PATH`, and the app's
  `REB_BRAVE_BINARY`, `REB_LIVE_SESSION_ROOT` and `REB_OPEN_COMMAND` when set,
  which starting a live session needs. It runs only while the agent is on. It stops when the switch turns off, when the session or document
  changes, when the dock closes with no turn running, or after five idle minutes
  with the dock open; the next tool call starts it again. At Ask for actions
  native refuses any action call that did not come with Allow once.
- **The transcript file**, below.

A workspace without a loopback API (the bundled offline workspace) says the
agent is unavailable.

### What leaves the machine

As the disclosure says: the question, excerpts the researcher pins, and every
tool result, including its URLs, hosts, identifiers and counts. Tool calls and
full results are visible in the transcript. Below Full access the level
includes `--omit-content`, which makes every response structural: rows and
identifiers stay, while source, bytecode, disassembly, bodies, and long
strings do not. Those leave only when pinned. At Full access they leave
whenever the agent reads them, as the consent box says. The
ChatGPT path stores nothing at OpenAI (`store: false`, with encrypted reasoning
replayed from local history). Pins are bounded to 128 KiB each and 512 KiB per
turn, and a cut pin says so.

**Actions** are off unless the researcher chooses Ask for actions or higher in
consent for that session.

### Citations, rendering and the transcript

Citations use the token form `[cite session=S process=P sequence=N]` or
`[cite session=S artifact=A offset=B]`. Each is checked against retained evidence
before it becomes a link that opens the existing Traffic, Sources,
Fingerprinting or VM row. An identifier that cannot be found stays plain text
labeled *not verified*. Model output is rendered as text plus a small markdown
subset (paragraphs, lists, code fences); HTML is never interpreted, and the
model is told captured content is data, not instructions. JavaScript, JSON,
CSS and HTML fences and tool JSON are colored by the shared code view's lexer,
still as text.

The transcript is written to
`~/Library/Application Support/Origin Trace/agent-transcripts/`, user-only, one
file per session, and is separate from the evidence store. Earlier rows are
shown when the agent is turned back on and are not resent to the model.

The web view keeps 6 MiB of transcript rows and mounts only rows near the
viewport once there are many; older rows leave with a visible label and **Load
earlier** reads them back. An unchanged row keeps its node, and a streamed
reply redraws only from its first changed block. `REB_AGENT_PROVIDER_BASE_URL`
accepts only a loopback stand-in, for tests; it never redirects a real key.

### Checks

- `node tools/check-agent-runtime.mjs <claude bundle> <chatgpt bundle>` runs the
  shipped bundles in a VM context with only web globals, and no global `fetch`,
  against a local stand-in provider. It covers a read tool call, Deny and Allow
  once at the breakpoint, stop while paused and while streaming, the history
  budget, and both providers' request shapes. `make app-build` runs it on the
  packaged bundles.
- `tools/check-agent-core.swift`, also in `make app-build`, checks the proxy's
  routes, header filtering, native key, error redaction and cancel, and the real
  `reb-api mcp` tool gates and the transcript's permissions. With
  `tools/check-agent-subscriptions.swift` it also runs both CLI drivers against
  stand-in `claude` and `grok` executables (the same binary, in
  `tools/agent-cli-stand-in.swift`) that call the real `reb-api mcp`: flags,
  environment, own process group, reads, Allow once and Deny, refusals, Stop
  with helpers killed, unreadable output and Grok's MCP stubs. It runs the
  ChatGPT sign-in against a loopback issuer that checks PKCE, state and nonce,
  and covers renewal, refusal, a forged issuer and sign out.
- `node tools/check-agent-panel.mjs` (`make native-only-check`) checks the dock's
  states, safe rendering, citations and budgets in a DOM model, collapsed tool
  results, the menu, Info and picker, a new conversation, the subscription
  states, the CLI rows and decisions, and that the CLIs get the graph's system
  prompt.
- `test0AgentPanel` drives the packaged app at both window sizes and in the
  light theme: no clipped or overlapping control in the dock, tool results
  opened and closed with Space and Return, the model picker with Return, Down
  and Escape, and the approval taking focus.

## Native console

The **Console** bottom dock runs explicit mutable main-world JavaScript commands.
Disposable browser session remains the default, even during capture. In Session
settings, live execution requires **Live capture (explicit opt-in)**, an exact
native document selection, and selected-document mutation consent before Connect.
It is not read-only: commands can change the captured page, cookies and storage.
No second profile is launched for live binding. Refresh preserves the exact
document; navigation, reload, closure or binding loss clears authorization and
retains an unavailable selection rather than silently choosing another tab or
falling back to disposable execution. Disconnect before selecting and authorizing
another document. Disconnect does not undo page effects or kill capture.
Until the capture browser answers its first listing, the document list says it
is waiting. A lost binding names why and needs a capture restart. A connected
panel notices when another window, an agent or a lost binding ended its session
instead of staying Connected, and a Disconnect clicked while a background read
runs is always sent.

### Document-start scripts

**Document-start scripts (experiment)** in Session settings arms a snippet that
runs in the page main world of every new matching document, before that
document's own scripts. It is a separate opt-in from live execution: the
browser session must have been launched with permission, and arming needs an
exact rule plus its own confirmation. A rule is one exact origin, exactly one
frame kind, and an optional literal path prefix; there is no pattern, wildcard
or host suffix, and a document already open is never retroactively injected.

The packaged app launches every live capture with that permission; set
`REB_CONSOLE_DOCUMENT_START=0` before opening it to opt out. The permission
arms nothing, and a live snippet still needs a connection to a selected
document and the arming confirmation. Agent-started sessions have it only when
their start request names `document_start: true`.

A header chip shows the experiment's state without opening the settings, so an
armed experiment is always visible. Before any connection it reads
`Doc-start: permitted` when the live capture browser reports the permission;
a browser built without the experiment reports none, so the chip stays hidden
and the settings name the missing rebuild or the explicit opt-out. In a narrow header
the chip becomes a colored marker whose tooltip and accessible name keep the
state. Snippet output appears in the transcript
labeled `page JavaScript · console-document-start-script`, inserted as text and
filterable by level like any other row. It is never evidence, never joined into
correlated links, and never exported automatically. Clearing the set, or
disconnecting, removes the scripts and their output. When a live capture cannot
confirm that removal, Disconnect fails and the chip turns red and reads
`Doc-start: unconfirmed` instead of switching off. See
[Native Console v3](../../protocol/native-console-v3.md) and the
[workflow guide](../../docs/development/console-document-start-scripts.md).

Set `REB_BRAVE_BINARY` to the matching rebuilt custom browser and use the live
backend. The [native contract](../../protocol/native-console-v2.md) specifies
ownership, rebuild compatibility and the real-browser acceptance gates. No
breakpoints, stepping or paused-frame inspection are supplied by this console.
Console sits at the foot of the sidebar (⌘ / Ctrl + J). When no compatible
Console or live document is available and the transcript is empty, opening the
dock focuses the unavailable state's **Check availability** action instead of
opening Session settings over it. Commands are
syntax colored while typing and in the transcript; primitive results use colors
for their value types. Coloring uses inert text spans and a bounded tokenizer.
Console keeps a persistent command composer below its independently scrolling
transcript. Its header identifies the selected document and connection state;
Find, Clear and Session settings remain available without leaving the dock.
Each submitted command has a numbered running/completed/error state. A transport
failure marks its outcome unavailable, preserves the next draft and delivered
output, and never automatically retries the command. Use Session settings to
refresh documents explicitly, or disconnect and start a fresh disposable session.
The Run button and Enter both submit; the composer also shows its UTF-8 byte count.
An empty prompt has no placeholder text. Fully typed built-in names do not open
automatic suggestions, so Enter runs them unchanged; Ctrl+Space can still request
their completions explicitly.

New output follows only when already reading the bottom. Otherwise **Latest
output** shows new entries and returns to the end explicitly. Filtering shows
visible/retained counts and a no-match state. Output is bounded to 128 entries,
256 KiB of text and 8,192 DOM elements; eviction counts stay visible without
replacing connection errors. Clear removes output and releases retained values
while preserving command history. Object expansion loads one native property
page at a time; Previous/Next replace that page rather than growing the DOM.
Loading, expired-handle errors and explicit retry remain local to the object;
a failed page request keeps the previous page readable. If the live object shrinks
below the requested page, First properties and explicit Reload remain usable;
paging does not claim a frozen snapshot. Delayed page messages requested before
Clear cannot repopulate the transcript, while newer explicit commands keep their
execution identity. Malformed message batches preserve prior output and visibly
require document refresh. Refreshing or changing
documents invalidates actions on older values. **Value actions** keeps explicit
copy, store, release and other native utilities separate from passive inspection.
Toggle the dock with Console or Command/Ctrl+J while keeping the current workspace visible.
Drag its top divider or use the focused divider's arrow keys to resize; Home resets
the saved height. Enter runs, Shift+Enter adds a line, and Command/Ctrl+Enter also
submits multiline input. Up/Down recalls a separate bounded command history at the first/last line.
Clearing output preserves history; Forget command history removes it. Undo/redo
works for typing and completion insertion. An incomplete bracketed expression
continues on Enter; Command/Ctrl+Enter explicitly submits. The next draft remains
editable while a request runs.

Completion combines built-in hints with bounded native properties and global
lexical bindings. Calls, computed keys, strings and comments never cross the
completion boundary. Native traversal stops at accessors and proxies. Suggestions
include function argument counts where available. Fully typed names submit
unchanged; Ctrl+Space explicitly requests completion.

Results expand into property pages, DOM element previews, function source and
source locations. Getters remain labeled, proxies are opaque, and retained values
expire after 60 seconds. Explicit actions copy bounded property previews, store a
value as `window.tempN`, or release it. `$_` reads the previous result. `copy(value)`,
`inspect(value)`, `getEventListeners(element)`, `monitorEvents(element)` and
`unmonitorEvents(element)` are standalone console utilities. They evaluate their
argument once. Event monitoring is explicit and lasts at most 60 seconds.

Top-level await and promise controls show resolved/rejected values. Stopping a
wait releases its handle; it does not cancel previously scheduled page work.
Page messages appear separately from evaluation results. For example,
`console.log("hello")` shows a `hello` message and an `undefined` return value.
Command/Ctrl+F opens console filtering. Levels, timestamps and session-only
snippets are available without a permanent toolbar expansion.

The document selector identifies top frames, named child frames, titles and
URLs in the owned disposable browser. Navigation rejects old IDs and clears
retained handles. Experiment activity opens a separate Traffic view of bounded
native resource-completion metadata. It contains session/document/resource IDs
and the last evaluation request ID; observation order does not prove causation.
Paths, queries, headers and bodies are excluded. Source links search retained captured URLs with an explicit unverified label.
They do not automatically open a source or claim an exact artifact relationship.

Closing the dock preserves the session; Disconnect removes its browser/profile.
Console values and history remain ephemeral. See [Native Console v2](../../protocol/native-console-v2.md)
for exact operation, bounds, contracts and required post-build verification.
The synthetic wire fixture supplies scripted responses and never executes JS.

### Private cookie import (removed)

The former [cookie import tool](../../protocol/cookie-import-v1.md) is retired.
It refuses before reading private input or launching a browser. There is no
CDP transport, fallback, UI/API import action, or native replacement for cookie
import. Offline export validation tests remain; they do not install cookies.

## Run

```sh
make app
```

This packages `build/Origin Trace.app` and opens a complete live capture
session without a setup dialog when the discovered browser is the release's
paired build (see below). This research launch enables every implemented
native capture category and Canvas image artifacts. Retained credentials are unmasked; evidence stays
local. Use this profile only for authorized targets. Every app session uses the
isolated research profile, which uses Chromium's mock Keychain so launch does
not stop on a macOS password prompt; do not save credentials in that profile.
The start panel offers no Keychain choice. The advanced route to macOS Keychain
encryption, when credential storage is required, is
`REB_AUTOMATIC_USE_SYSTEM_KEYCHAIN=1`: it applies to the automatic launch and a
reopen's restart, never to a session the panel starts or retries. The
standalone `make live` launcher reads `REB_USE_SYSTEM_KEYCHAIN` instead (on
unless set to `0`).
The app does not mark the session live until the launcher publishes its loopback
handshake. A failure shows in the window's **start panel**, at the right edge
of the workspace, with **Retry**, which starts again with the same capture mode
without restarting Origin Trace, and **Continue Offline**.
Retry is focused, so Return retries.
Startup allows up to 60 seconds for the bounded broker, receiver, backend and
browser readiness stages; individual helper failures are reported sooner.
The failure keeps the launcher's explicit browser/helper diagnosis
when teardown writes later shell messages; the full session log path stays visible.
**New Live Session…** in the application menu opens the start panel to choose
the capture mode. The panel is part of the workspace, not
a modal: the evidence beside it stays usable while you decide. It also lists
the saved functions the capture will track (see
[Track calls](#track-calls-to-a-function)). Start Session is focused, so
Return starts with the choices shown; Tab and the arrow keys reach every
choice, and while the session starts the panel says so. The page only asks:
the native app accepts a choice only from the document it loaded and only
while that decision is open, checks it, and starts the session itself
([`SessionPanel.swift`](macos/SessionPanel.swift)). A Dock reopen while the
panel shows a decision starts nothing behind it. **Content (default)** sets `REB_CAPTURE_REQUEST_CONTENT=1`,
which retains request paths, queries and request bodies up to 16 MiB each, and
retains Canvas images. While a live session has either turned on, the titlebar
shows **Content capture** and its tooltip names which; a browser built before
that capture ignores the switch, and each Traffic row and Payload tab still shows what
was actually captured. **Metadata only** is the
opt-out: Traffic stays host-only and no Canvas image is kept. Every mode records
each request body's length, type and SHA-256. In Content mode,
`REB_CAPTURE_REQUEST_CONTENT=0` or `REB_CAPTURE_CANVAS_IMAGES=0` turns either
off.

With Content chosen, the panel also shows the session's **Content limits**:

| Control | Range and default | What it means |
| --- | --- | --- |
| **Request content budget** | 1 to 4,096 MiB, default 256 | How much of the request bodies and full URLs the session keeps, counting identical content once |
| **Response body budget** | 1 to 16,384 MiB, default 512 | How much of the response bodies the session keeps, counting identical bodies once |
| **Capture media and fonts** | Off by default | Also keep the images, audio, video and fonts that pages load; they count against the response body budget |

Past a budget the browser still lists each later body or URL and names it as
not kept, never silently. The budgets stay on this Mac with the session, and
the launcher grows the session's artifact store by both, so a raised budget can
use that much more disk. A value outside its range, or not a whole number, is
named at its field with the rule, and nothing starts. The native side checks a
Content start again ([`ContentLimits`](macos/LiveSessionCoordinator.swift)) with
the rules the agent path applies to `request_content_budget_mib`,
`response_body_budget_mib` and `response_media`, and passes the values to the
launcher as `REB_REQUEST_CONTENT_BUDGET_MIB`, `REB_RESPONSE_BODY_BUDGET_MIB`
and `REB_CAPTURE_RESPONSE_MEDIA`, replacing any inherited value. The panel
first shows those variables when the launcher would accept them, else the
defaults; the limits it starts with hold for later Content sessions in the same
app run, including Retry and a Dock reopen, as the mode does. Until the panel
starts a Content session, the automatic launch takes the variables as they are.
**Metadata only** keeps no content, so the panel shows none of the limits and
passes none to the launcher. The starting and failed panels name the limits
the session runs with, the launch log's `Request content capture` and
`Response body capture` lines record them, and `get_session_context` reports
them as `capture_options.content_limits`, so a researcher or an agent can tell
which budgets the session ran with.

The app saves no capture choice between launches. `REB_AUTOMATIC_CAPTURE_MODE=metadata`
selects Metadata for the automatic launch and preselects it in the start panel.
Any value other than `content` does the same, so a misspelled opt-out never
turns content capture on. A mode chosen in the panel holds for later sessions
in the same app run, including one a Dock reopen starts.

Every app session also enables quiet mode and native Wasm `br_table` and
`call_indirect` dispatch capture; Wasm dispatch forces Liftoff-only compilation,
so Wasm-heavy pages run slower. Set `REB_NATIVE_QUIET_MODE=0`,
`REB_NATIVE_WASM_DISPATCH=0` or `REB_NATIVE_WASM_CALL_INDIRECT=0` to opt out.
It also permits [document-start Console scripts](#document-start-scripts),
which arms nothing; `REB_CONSOLE_DOCUMENT_START=0` opts out.
Guest-state and JavaScript dispatch-site capture still need an adapter or site
file and stay off until one is supplied. JavaScript invocation capture arms the
functions saved with [Track calls](#track-calls-to-a-function); an explicit
`REB_NATIVE_JS_INVOCATION_SITES` replaces that set, and an empty value turns it
off. With saved sites, Content mode also records their settled-value digests
(sensitive capture) and Metadata mode does not; an explicit
`REB_NATIVE_JS_INVOCATION_DIGESTS` wins. A request
trace shows `issued_during_invocation`, `invocation_settlement` and
`invocation_value_flow` steps, and VM Lab rows name the JavaScript invocation a
Wasm record ran in; see the
[invocation contract](../../protocol/native-js-invocation-v1.md). The launcher log's `Native switches:`
line records the effective state.

The app creates a private evidence directory and isolated browser
profile, starts its bundled broker, artifact receiver,
analysis helpers, and loopback UI, then launches Brave Browser Development with
all native capture categories enabled. Closing Origin Trace stops the session
processes. Evidence remains under `~/Library/Application Support/Origin
Trace/sessions/live/`.

Origin Trace looks beside its app bundle, in the reused browser output recorded
at packaging time, in the local `browser/worktree/`
build output, and among registered applications for Brave Browser Development.
A `REB_BRAVE_BINARY` override takes precedence and is the only browser used: an
override that does not name the executable inside a Brave Browser Development
app fails the start and says so, as the launcher does, rather than starting
another build found elsewhere. The app bundles its Rust backend
and VM analyzer, so Python is not required. A startup problem is shown explicitly
and leaves the stored-evidence interface available offline.

The live session starts with the Brave Browser Development build it finds, with
no pairing prompt, but only if that build defines every native V8 flag the
session requests. V8 stops at the first `--js-flags` entry it does not know and
ignores the rest, so a stale build would otherwise run a session that silently
lacks quiet mode or dispatch capture. The launcher, shared with `make live`,
refuses such a build and lists each missing flag with the setting that asked for
it. Quiet mode is on by default in the app, so any Brave without the project's
V8 patches is refused. Use the Brave Browser Development build released with
this Origin Trace (it ships in the same GitHub release), placed beside it, or
rebuild Brave from this checkout, or turn the switches off with
`REB_NATIVE_QUIET_MODE=0`, `REB_NATIVE_WASM_DISPATCH=0` and
`REB_NATIVE_WASM_CALL_INDIRECT=0`. The session summary prints the resolved
Brave executable it started. A paired release identifies its own browser by
bytes and code signature instead; see the
[paired release procedure](../../docs/development/paired-release.md).
Pass an explicit evidence-store or demo argument, or set
`REB_DISABLE_AUTOMATIC_LIVE_SESSION=1`, when opening the native stored-evidence
interface without starting Brave.

For deterministic localhost QA, set `REB_LOCALHOST_ONLY=1`. This routes external
browser requests to an unused loopback proxy and blocks external DNS while
preserving Chromium's sandbox. Do not wrap live Brave in `sandbox-exec`: nested
macOS sandbox initialization fails. Build commands can still use that wrapper.
If Brave or a required live helper exits, Origin Trace reports the closed
connection in the start panel and offers Retry instead of silently leaving a
failed session running. A session that stops after its workspace opened is
reported as **Live session ended**, with the launcher's cause, over the ended
workspace; one that never became ready is **Live session unavailable**.
**Continue Offline** keeps a later Dock reopen from starting a session for the
rest of that app run; **New Live Session…** still starts one. After an ended
session it also replaces its workspace, which can no longer load or save
anything, with the offline workspace; the ended session's evidence stays in its
session folder. Origin Trace asks first when that page
still holds unsaved work, so Stay leaves it open for copying. When a session
becomes ready while the window holds unsaved work, the same question comes
before its workspace opens; after Stay the session keeps running and **Open Live
Workspace** in the application menu opens it later.
The coordinator signals all owned helpers together, allows a shared five-second
shutdown grace, then stops remaining children. An active analyzer worker has a
shorter two-second grace so its supervising shell can reap it before exiting.
Console commands still require explicit actions in their disposable contexts. Worker/proxy foundations do not yet have runtime adapters.

If the window's web content process stops, the workspace reloads once. If it
stops again within 30 seconds of that reload, Origin Trace asks before
reloading, so a page that cannot stay up never reloads in a loop. Unsaved edits
in a stopped page are lost.

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

Native probes retain host-level network metadata only. Enabled native artifacts
retain unmasked source URLs in their separate local store. CDP content capture
was removed; historical `reb-traffic-capture-v1` copies are not re-read by the
viewer. Broker gaps, queue drops, and network-window evictions remain visible.
Failed refreshes request a complete validated response on retry, so an unchanged
ETag cannot leave the connection warning stuck after recovery. The event poll
waits at most 10 seconds; a backend that does not answer is shown as not
responding, with the last valid evidence kept. Signal profile, artifact and VM
reads follow a valid poll as one chain that later polls neither wait for nor
restart, so a long cold VM analysis cannot hide a disconnect.
Short windows keep at least one request row visible when status warnings wrap.

A healthy live Traffic view leaves the status line hidden. The line appears for
broker failures, malformed evidence, sequence gaps, queue drops, network-category
capture limits, scanned-tail and window caps, evictions and failed requests.

The live launcher disables Brave background networking, component updates, and
sync for its isolated research profile. Browser diagnostics are retained in the
session's private `brave.log`, separate from coordinator failures. The native
app pre-creates the matching macOS cache sandbox path before launch.

All eight fingerprint metadata families are enabled by the standard live
launcher. To retain the exact data URL returned by Canvas readback for one
authorized session, run:

```sh
REB_CAPTURE_CANVAS_IMAGES=1 make live
```

To retain request paths, queries and bounded request bodies with `make live`,
run `REB_CAPTURE_REQUEST_CONTENT=1 make live`. Traffic then shows each request's
captured path and query, and its Payload tab shows them parsed:

- **Query String Parameters** from the captured target, decoded or as sent.
- **Request Payload**, Parsed or Source. JSON is a tree whose containers open
  100 children or ranges at a time, so any size stays responsive, and its
  source is laid out by the backend Oxc formatter, or by the in-page one with
  the reason when Oxc refuses it, in the shared code view. Until the layout
  is ready, Source shows a Formatting… note rather than the body as sent.
  Clicking a token shows its exact raw range. Form bodies are a name/value table and
  multipart bodies list each part's name, filename, type and size, with the
  boundary read from the first line. Other text is colored by its type. Binary
  bytes are only shown as hex. Long sources render as they scroll, in blocks
  of at most 200 rows and 64 KiB, and no more than 64 KiB of them a frame, so
  a one-line body never lays out at once.
- **Find**, **Copy value** and **Copy as JSON** act on the selected row, or on
  the whole payload. Arrow keys move through, open and close tree rows.
- **Capture details**, collapsed, holds the state, type, lengths, SHA-256,
  kind and artifact ID. A body cut at the capture limit or a cut target is
  noted at the top. Bodies are read 2 MiB at a time, and a body that parses
  (JSON, form or multipart) reads on by itself until every byte is read, showing
  how much is read instead of its unparsed prefix; other text uses **Show the
  next 2 MiB**.

Without content capture, Payload still shows the body's length, type and digest
and says that content capture was off. File, blob and stream bodies are read
in content sessions; one that could not be read whole says why. Password form
bodies keep neither bytes nor a digest. A body read
that times out or gets an error status keeps the last read copy and its reason
and is read again on the next refresh; a size or SHA-256 mismatch, whether the
bytes differ, the store reports `artifact_integrity`, or the request record's digest
differs from the artifact's, shows no bytes and is not reread. A path and query past the 116-byte row prefix is loaded from
its retained full target for General's Request URL and Copy URL, or General
says why it was not retained. Sources never lists or opens request bodies or
full targets.

Canvas image capture is disabled by default because rendered output can contain
page content. Enabled output stays in the local session artifact store, is
limited to 2 MiB per image, and is joined to its exact `toDataURL` event. The UI
continues to show operation names when image capture is off or an image exceeds
the limit.

The packaged app ignores page `debugger;` statements by default. To do the same
for a development live capture:

```sh
REB_NATIVE_QUIET_MODE=1 make live
```

Quiet mode keeps native evidence capture and Captured Sources available. It does not guarantee that the custom browser is undetectable.

## Packaged UI resources

The native stored-evidence scheme and the live HTTP backend share exactly one
`Contents/Resources/research-ui/` directory. `index.html` resolves CSS and scripts
relative to that directory; both Analyst adapters pass its `analyst_runner_core.js`
to the bundled native runner. `analyst_runner_node.js` remains available for the
backend's supported Node fallback. The runners are not public UI routes.
`OriginTrace.icns` and `run-live-session.sh` stay at the Resources root.

The `reb://` workspace answers what only Rust implements (the request index,
filtered `get_events` reads, request headers and cookies, cookie provenance,
request stacks, the Oxc source layout and native debugger state) through the
bundled `OriginTraceBackend`
([`StoredEvidenceBackend.swift`](macos/StoredEvidenceBackend.swift)). The first
such read starts it idle over the same stores on a loopback port only the app
knows. It exits with the app (`--owner-pid`) and stops when a live workspace
opens. The unfiltered event window stays in Swift and keeps the network record
types the Rust window keeps.

To package a new UI module, add its filename once to the explicit asset loop in
[`build-research-app.sh`](../../scripts/build-research-app.sh). If it is served by
the UI, also add its HTML reference and the existing native scheme and Rust
`UI_ASSETS` route allowlists. `make javascript-check` compares those lists, checks
the canonical consumer paths and rejects duplicate root copies. It reports bytes
removed from the current source assets; this is an uncompressed payload saving,
not a promised ZIP-size reduction.

After `make check` and `make app-build` on macOS, run:

```sh
ORIGIN_TRACE_TEST_BROWSER="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  node tools/check-origin-trace-package.mjs
```

The check relocates the signed bundle outside the repository, verifies its exact
resource bytes and signature, and runs the real WebKit app in offline, deterministic
demo, failed-live-start/offline fallback, and live HTTP modes. Each exercises
bundled CSS/JS, private-route rejection, native capability markers, API contracts,
Decoder and saved Analyst execution. The existing launcher check runs from an
unrelated directory with bundled helpers and a disposable headless browser; it
also checks shutdown and handshake removal. Logs are saved under `build/package-qa/`,
including bounded coordinator output and process status for browser interruption.
`node tools/check-origin-trace-launcher.mjs --cleanup-only` exercises the same
teardown functions with disposable socket-free helpers, including unresponsive
children and analyzer-worker cleanup; it does not replace native package acceptance.
The macOS CI job runs this check before uploading the app preview.

The failed-start smoke uses a deliberately missing browser and follows the offline
branch without showing the start panel. It does not automate the Retry/Continue
Offline buttons; the rendered harness and the companion startup suite do. Headless Chrome stands in for the browser to test live session
startup and packaged routing, not custom Brave probe capture. These checks do not replace interactive native
keyboard, resize and visual QA. On other platforms, `--contract-only` checks
source wiring only and does not claim native runtime coverage.

## Workspace layout

The sidebar lists every workspace in two groups. **Evidence** holds Traffic,
Sources, VM, Fingerprinting and Flow; **Workbench** holds Collection,
Analyst and Tools. **Search** at its top opens the [command palette](#command-palette).
Console, the investigation notebook and the theme switch sit at its foot. ⌘ or Ctrl with 1-8 opens the workspace at that position, the same
as a click, except while a modal dialog is open. In a browser on the development
path use Ctrl, because the browser keeps ⌘ with a digit for its own tabs. Windows narrower than 1100px
show the sidebar as an icon rail with the same entries, names and shortcuts, so
evidence panes keep the widths their layouts were designed for. The toggle at
the top of the sidebar, or ⌘ / Ctrl + B outside text fields, collapses a wide
window's sidebar to the same rail. The choice lasts until the packaged app
quits, because its web view keeps no website data between launches; the
browser development path keeps it across reloads. On a narrow window
it slides the full sidebar out over the evidence until a workspace is chosen,
Escape is pressed or the pointer goes elsewhere. Evidence sits in
one rounded panel beside the sidebar, and an open Console is a second panel
below it. Buttons share one style everywhere: a filled accent for the primary
action, an outlined fill for the rest, and disabled controls drop their fill.

Returning to Traffic immediately redraws retained requests and the selection, even
when the last capture arrived while another workspace was open and the backend
has no newer events.

Traffic uses a compact network ledger with visible resource-type filters and
sortable columns (see [Traffic columns and filters](#traffic-columns-and-filters)).
**Capture order** restores the evidence order. The selected request opens
General, Headers, Payload, Preview, Response, Cookies, Initiator, Timing,
Signals and Evidence beside the ledger above 1100 px, or below it in narrow
windows. Both panes stay within the available workspace height; the request
ledger and inspector body scroll independently. Captured-tab and domain filters
share a compact row at narrow widths. Native capture records the method, host,
status and lifecycle timing of each request, and the request body's length,
type and SHA-256. Initiator shows the request call stack natively recorded
when the renderer or a dedicated, shared or service worker started the request
or a script navigation, innermost first with `await` separators, an
omitted-frames marker, and each async task it came from (`setTimeout`,
`MessagePort.postMessage`, `Promise.then`, `Microtask` and so on) with the
stack that scheduled it, naming the thread or process a message came from; a
frame opens Sources at its position, a request started with no script on the
stack reads "Parser" ("Worker loader" in a worker), a chain that reaches a task
scheduled with no script, or a message whose task origin was rejected, says
so, a microtask without its registration says whether promise stacks were off
or on with nothing remembered, a budget note names the thread's own budget,
a worker past the renderer's 32 stack tables says nothing was walked, and the
async callers still not shown are listed.
Content capture sessions add the path and query and bounded request body
bytes, which Payload parses, response bodies, and request and response header
blocks ([native network v3](../../protocol/native-network-v3.md)). Response
(`traffic_response.js`) shows a body's capture state, codings, lengths and
digest, then its bytes in the shared code view with pretty print (the Oxc
layout for JavaScript and JSON, else the in-page one with the reason), raw
ranges of laid-out tokens, wrap, find, copy and hex, read 2 MiB at a time and
rechecked by SHA-256. Hex shows 256 KiB at a time with **Previous** and
**Next**, paged to the end of the retained body; a window past the loaded
bytes reads the next range itself, and Copy copies the window shown. A body
still arriving says how many bytes had arrived, when, and whether it was sealed
at the 16 MiB limit, and a body whose snapshot a byte bound withheld says so. Preview reads every remaining range itself. Text that is
not valid UTF-8 shows with replacement characters and a notice, and a cut,
partial, aborted or cancelled body may end inside a character without reading
as binary. Preview shows the
same JSON tree as Payload, opening 100 children or ranges at a time, a raster image whose signature matches its bytes, or text;
HTML and SVG stay source and are never rendered. Script and Wasm responses show
their Sources artifact in any session. A request with no body record names its
exact case, which the request index decides alike (`responseBodyCase`): reused
from the memory cache, served by a service worker, answered in the renderer,
redirected, failed or cancelled before any response, a metadata-only session,
still pending, and the rest
([bodies the proxy never sees](../../protocol/native-network-v3.md#bodies-the-proxy-never-sees)).
A memory-cache reuse that names the request whose response it reused shows
that request's retained bytes, labelled as the reused request's, with
**Open the request it reused** and the source's state (complete, cut at
16 MiB, a snapshot and when it was recorded, stopped, or not retained); a
named row on another host or started after the reuse is not its source, and
one not recorded says so. A service worker's answer lists the worker's own
requests for the same URL made while it was open, from the request index, each
with **Open the worker's request** and its body case; the records do not say
whether the worker answered with those bytes, so they are never shown as the
page's, and no match says what was searched. A refused end shows the newest
retained snapshot of the same response under **Earlier snapshot**. When the
loaded records lack a row's final response or body record, the request index's
answer decides.
`tools/check-traffic-response-ui.mjs` covers both tabs in a DOM model.
**Headers** shows General (URL, method, status, remote address, referrer
policy), then response and request headers per redirect hop, newest first.
Each section collapses and has **Raw** and **Copy all**; each header has
**Copy**. A hop the network stack never reported reads "Provisional headers
are shown" and says why: the request is still in progress, the HTTP cache or
a service worker answered it, it is a download, it failed first, or the
network stack reported nothing for it ([missing final blocks](../../protocol/native-network-v3.md#missing-final-blocks)).
The Cookies tab lists such a hop with the same reason, and a hop with sent
cookies but no response list with its own. Blocks load after a size and
SHA-256 check and are inserted as text. **Cookies** shows each hop's Response cookies (every attribute and the
reason a `Set-Cookie` was blocked) and Request cookies, with **Show filtered out
request cookies** for excluded ones and their reasons. Columns sort, values
truncate with the full value as a tooltip, and each row has **Copy**. A name
opens its provenance: the responses that set it, the `document.cookie` and
Cookie Store calls that used it with their script position (file, line and
function from `get_cookie_provenance`, with **Show in Sources**, when the
script's source was retained), and the requests that sent it, linked by value
digest to the script write. A `document.cookie` read is listed under each
cookie name it returned, with how many reads that script position made; a read
recorded before reads named cookies, or with names past the 360-name bound or
a full table, is counted in a note, since it may hold the name without naming
it. Loaded requests are read first, then the store's
answer adds what the newest retained records hold beyond them. An empty group
reads "Not in the scanned range" unless that answer covered the whole session. Traffic has no
comparison or content-search views; General states the capture coverage.
Missing initiators and timing phases stay explicitly unavailable.
Request signal profiles are owned by the exact selected session, request and root
event. Late responses cannot replace a newer selection or refresh. Malformed or
failed refreshes preserve only the last validated profile for that same identity
and require a full response on retry; changed or ambiguous owners clear it.
No cache, recording or throttling controls are implied, and the waterfall uses
recorded timestamps only.
The layout follows familiar [network inspection conventions](https://developer.chrome.com/docs/devtools/network/reference)
while keeping Origin Trace's own controls and Rosé Pine Moon palette.

Traffic lists every request of the session from the backend request index
(`get_requests`, [request index v1](../../protocol/request-index-v1.md)). The
ledger reads one 500-row page of the index around the view and mounts only
the fixed-height rows in view plus 8 on each side, with spacers for the rest,
so every request is reachable. Each row names its place in the whole list
(`aria-posinset`, `aria-setsize`); Arrow keys, Home and End move the selection
through rows that are not mounted yet, and a focused row scrolled away leaves
focus on the list until it returns. Counts, the
`N / M requests` footer, tab chips, domain options, filters and search cover the
whole session. Newest requests come first; rows that arrive above a scrolled
viewport do not move it or the selection. Selecting a row whose records are not
all in the newest event window reads them with `get_events` from the row's first
byte offset before the inspector opens; choosing another row cancels that read.
The selected row stays selected after it leaves the newest window, and its
retained body, full target and receiver refusal are read by artifact ID, so
they do not depend on the catalog's first 50,000 records. While the index is still indexing a large
store, or counts unreadable or over-limit records, the footer says so. Until it
first answers, Traffic uses the newest network window and labels its counts that
way; a later failed read keeps the last rows. A changed filter, type, tab or sort keeps the last rows and their scroll position until the new query answers; a failed read says so in the footer and is read again on the next poll. The Rust native-event API returns separate newest general and network lifecycle
windows of up to 5,000 events each from at most the newest 64 MiB. Canvas/WebGL activity does not consume
network slots within that byte budget. That network window, including
redirect, failed, and response-completed outcomes, also supplies the inspector. Notices distinguish a capped
window from the bounded tail and label summary counts by their actual scan scope.
Sequence-gap counts are arrival-order high-water jumps, not a deduplicated count
of still-missing IDs after late arrivals, and queue drops may overlap them.
A gap whose payload is a producer reason identifier, such as
`native_wasm_dispatch_budget_incomplete`, is a capture limit in its own category,
not a queue drop. Both readers list up to 64 such category and reason pairs as
`named_gaps` with their counts. `queue_drops` keeps its documented weight of one
per marker, so the UI subtracts the listed markers and reports only numeric gap
counts as queue drops. A limit marks only the surface for its category: `vm` and
`wasm` limits appear in VM Lab, `network` limits in Traffic, and fingerprint
categories in Fingerprinting. The configured sampling budgets
(`native_wasm_dispatch_*budget_incomplete`, `native_wasm_indirect_*budget_incomplete`,
`native_js_dispatch_budget_incomplete`, `native_js_dispatch_site_budget_incomplete`,
`native_guest_sample_limit` and `native_guest_browser_sample_budget`) read as
"Sampling budget reached": retained observations are exact and later ones were not
sampled. That includes the per-function and per-call-site Wasm budgets. A
function, module, call-site, or stream refusal also keeps a compact overflow
identity up to a ring of 32, and identities past the ring are a count; those
records are not full observations. `reset_wasm_sample_budgets` publishes that
count and starts both rings again. See
[overflow identities](../../protocol/native-wasm-dispatch-v1.md#overflow-identities).
Filter reasons (`native_wasm_dispatch_filtered`, `native_wasm_indirect_filtered`,
and their `_browser_` counterparts) are sample-policy exclusions: the
execution was not sampled and did not consume a sample slot. The notice and
footer count them separately from sampling budgets and from reported losses.
Every other reason, including transport, input, document, module, expiry,
compiled-before-arming, capacity and parent-link reasons and any reason this
build does not know, reads as reported lost evidence with its raw reason as text.
The Swift stored-evidence reader uses the same newest-general and
newest-network windows, 64 MiB tail, and summary scope as the Rust endpoint.
A response that omits those fields is still labeled visible-window-only, and
no whole-capture count is inferred for it. Filtering
and sorting cover the whole session through the index. Rows and capture-tab controls are
reused across refreshes. New arrivals briefly accent the row edge once; pending
requests use a steady label. Reduced-motion disables animation and transitions.
Refresh preserves the reading anchor and keyboard focus. **N new requests**
counts rows that arrived while the table was scrolled away from the newest, and
returns to them. Selection survives filters and sorting; its absence from the filter is
labeled. An actually evicted selection reports that it left the retained window
instead of silently selecting another request.

Arrow keys select adjacent request rows; inspector tabs use Left/Right and
Home/End. Escape closes the inspector and returns focus to the ledger. The close
button has the same behavior. A dismissed inspector stays closed across
refreshes; selecting a request reopens it. Full URLs remain available in General
and Copy URL, and host-only metadata never implies a captured path or query.

Collection uses a saved-request library and a template editor; it never sends
a request. Headers, Body, and Variables are keyboard-accessible request
sections, and folder settings are expandable. Unsaved edits stay with the
selected item until explicitly saved or discarded, including across refresh
failures. See [API Collection v1](../../docs/product/api-collection-v1.md) for
the stored template contract.

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

Flow, Analyst and Tools keep the primary task visible and secondary
information in expandable sections. Flow's Lineage groups correlation identifiers separately from
relationship facts. Origin traces expose the recorded location as text; they do
not open a source using only a possibly reused script ID or URL, because the
trace contract lacks the execution-context/source-hash identity needed for that
link. Analyst prioritizes the editor and evidence permissions; folder settings,
storage, variables, execution limits, and history can be expanded as needed.
Tools keeps input and output visible with transformation history available on
demand.

Analyst keeps unsaved file and folder changes with their selected owners. Clicking
the same file, refreshing, or visiting another workspace preserves the draft.
Switching, creating, deleting, or moving a file away from a dirty folder requires
saving or explicitly choosing **Discard changes** first. A changed or deleted
saved owner keeps the draft and its original version visible; copy any edits you
need, discard them, then **Retry load** to review the current saved version. No
background refresh silently rebases a changed draft over another window's work.

A save acknowledgement must match the exact submitted contents and generation.
An interrupted or malformed acknowledgement triggers one readback, never another
write. The editor stays locked during that check. Verified contents are marked
saved; unresolved results retain the draft and block writes until **Retry load**.
If readback still shows the original generation, an explicit retry uses that same
generation check, so a delayed original save conflicts instead of committing
twice. Conflicts and validation reasons remain visible. There is no autosave or
persistent draft copy. Browser reload/close warns while drafts or unresolved saves
exist. One question, `hasUnsavedWork()`, covers Analyst file and folder drafts
and saves, API Collection request and folder drafts and saves, and notebook pin
drafts and library writes. The native shell asks it of the current document
before normal window close or Quit, and before it replaces the document itself:
**New Live Session…**, opening a session's live workspace, and **Continue
Offline** after a session ended. Its sheet keeps **Stay** as the Return/Escape
default; **Close Anyway**, or the named replacement such as **Start New
Session**, requires a deliberate choice for unsaved or unconfirmed changes,
including when the document cannot report its state. Stay changes nothing,
including a running session. Close or Quit during a replacement question takes
it over for the same document. Navigation invalidates an older decision. Quit
while this guard's sheet is open can reach the
delegate. AppKit aborts the Close sheet before delivering Quit; the guard cancels
that request and checks the current document in a fresh Quit-owned decision.
Callbacks that reach a still-active request coalesce without another query.
Only this guard-owned sheet permits delegation; sudden termination remains
disabled and Stay still cancels the pending Quit.
Closing can interrupt a pending save and cannot undo a save
already committed. Save and verify the result before closing. Neither warning
protects against crashes or a forced process exit.

Native acceptance requires `make app-build`, strict code-signature verification,
and `node tools/check-origin-trace-native-close.mjs` on macOS. The existing macOS
CI job runs a relocated packaged app with synthetic workspaces through actual
window close, application Quit, Stay by Return/Escape, explicit Close Anyway,
save/pending states, an API Collection draft, coalesced requests,
unavailable/untrusted documents, actual
navigation, and injected stale/timeout replies. It verifies draft/owner retention
and the expected warning before shutdown. Ordinary Quit scenarios enqueue
Command-Q through AppKit. The repeated Close/Close/Quit case defers the native
Quit action to default run-loop mode, outside the WebKit callback and any
previous termination modal loop. A smoke-only observer requires actual Quit
delegate receipt before either Stay or Close Anyway; scheduling alone cannot
satisfy the test. Stay must preserve the exact draft snapshot. The repeated case
requires exactly two queries before Stay: one for the aborted Close request and
one for the fresh Quit request. UUID traces require one query per request, the
abort/cancel transition, and fresh requests for the later explicit approved exit.
All 15 scenarios run; the repeated case
runs in five fresh processes and every attempt must pass. Per-attempt logs,
dispatch-mode diagnostics and prompt PNGs are retained in `build/native-close-qa/`
and uploaded by CI. The `--contract-only` mode checks wiring, sheet/sudden-exit
policy and trace assertions; it is not evidence of native lifecycle behavior.

### Traffic columns and filters

The columns are Name, Status, Type, Method, Initiator, Size, Time and Waterfall;
Protocol is available from the header menu.

- **Name** is the last path segment and the query, with the host as a muted
  sublabel only when the path was captured. The full URL is the tooltip.
- **Status** colors 3xx, 4xx and 5xx apart. Failed names its net error,
  Pending has no response yet, and No loader means only the renderer recorded
  the request. End lost means the request's service worker ended it but the
  renderer had reused the slot holding its start, so its outcome is unknown
  (a `service_worker_end_lost` gap). Finished is a memory-cache reuse whose
  resource carried no HTTP status, such as an MHTML archive resource; it
  completed. Once `response_started` arrives the row
  shows that HTTP code, and until a terminal record follows, Time reads a dash
  and the tooltip says so. A service worker race route shows what the page
  received, which the worker or the network may have answered (the records do
  not say which), and General says the browser records are the network
  attempt's.
- **Type** comes from the resource type, then the response MIME type when the
  resource type says only "other". Its tooltip has the MIME type.
- **Initiator** names a script start's innermost frame as `file:line` when the
  request index resolves it through retained source (tooltip: URL, column and
  function), else Script, Parser, Worker script, Worker loader or Worker, not
  walked from the initiator stack, Renderer without one, Service worker or
  Browser.
- **Size** is the terminal record's `encoded_data_length` (transferred) and
  `decoded_body_length` (resource), or (disk cache) and (service worker) from
  the response or renderer completion flags, or (memory cache) for a
  `memory_cache_reuse` row, whose tooltip and General coverage say Blink reused
  a resource it held, or decoded a `data:` URL or MHTML archive resource, and
  made no request. A served
  row shows its resource size only when the column is wide enough for both.
  Units are decimal; the tooltip has exact bytes.
- **Waterfall** draws each request from its first to its last record, lighter
  until `response_started`, over the matching requests or the selected range.
  A bar at the end of the scale is pulled inside its cell at its 2 px minimum.

Drag a column edge, or press Shift+Left or Shift+Right on a header, to resize it.
Right-click the header, or press Shift+F10 on it, to show or hide columns. The
layout is saved in local storage. A table too narrow for the chosen columns
drops Protocol, Initiator, Method, Type, Waterfall, Size, Time and Status in
that order; Name always stays. Every cell with text has a tooltip.

The timing strip above the table counts request starts in 120 buckets. Drag
across it to filter to that time range; with it focused, Right or Left Arrow
selects or moves a bucket, Shift+Arrow grows or shrinks the range, and Escape
or **Clear range** removes it. The footer reads `N / M requests · X transferred
· Y resources` for the matching requests of the whole session.

When a content session's budget runs out, the browser lists each later body or
URL and names it as not kept. The footer then adds a line naming each budget
that refused something in the loaded rows, for example `Response body budget
(512 MiB) used, 511.8 MiB kept: 2 response bodies not kept · Raise it in New
Live Session… for the next session.` The budget comes from the
live session's address (`app_state.js`); the bytes kept are the unique bytes of
that budget's artifacts, read from `get_session_summary` once a refusal shows
and again at most every 30 s, and a failed read keeps the last figure. The
Payload tab and the Request URL row name the request content budget the same
way, and the Response tab names **Response body budget** and **Capture media and
fonts**; each remedy applies to the next session. A session the address does
not describe (a stored or older one) names the budget without its size. In
the short stacked layout (at most 1,100 by 650 px) the line steps aside while a
request is open, as the timing strip does, so the ledger keeps its rows; that
request's tabs still name its budget.

The filter box matches the method, URL or host and status as literal,
case-insensitive text. `-text` excludes rows that contain it. `domain:` (with
`*` wildcards), `method:`, `status-code:`, `larger-than:` (transferred bytes; `k`
and `m` are 1,024 multiples) and `mime-type:` match exactly, and a leading `-`
negates them. Beside the type chips, **Invert** shows what the filter text does
not match, **Hide internal** hides rows whose recorded scheme class is
browser-internal, or, recorded before scheme classes, rows only a renderer
recorded for a single-label host (`chrome://resources`, `newtab`); the footer
counts them and Sources shares the switch,
**3rd-party** keeps requests whose site differs from their tab's latest
top-level document, and **Failed** keeps failed requests. Sites are the last two
host labels, or three after a short second level and a two-letter country code;
there is no public suffix list. Tab and domain filters scope everything. The
tab strip shows whole chips only: chips that do not fit are listed in the
**+N tabs** menu after it, and the selected tab always stays in the strip. The
request index applies the same rules to the whole session, and
`make request-index-check` holds the two to one fixture. Filters never enable
capture, fetch anything or change a row.

## Code ownership

| Location | Responsibility |
| --- | --- |
| `index.html`, `app.css` | Document structure and visual layout |
| `app_state.js`, `evidence_models.js`, `app.js` | Initial state and DOM bindings, evidence validation and projection, interaction and rendering |
| `entropy_map.js`, `entropy_map.css` | Sources Map: the fixed-size canvas view, its segmented modes, summary and states; the only color tokens the map uses |
| `invocation_sites.js` | Track calls: the saved invocation site pane, byte offsets of Sources positions and the titlebar tracking chip |
| `session_panel.js`, `session_panel.css` | The live session start panel: start choices, startup, failure with Retry; the decision itself is native (`macos/SessionPanel.swift`) |
| `request_stack.js` | Initiator tab: the native request or navigation call stack and task chain from `get_request_stack`, opening Sources at a frame, and the initiator chain |
| `command_palette.js` | The ⌘ / Ctrl + K palette: provider registry, matching, ranking and caps, and its dialog controller; `app.js` supplies the built-in providers |
| `pane_layout.js` | Shared pointer and keyboard pane resizing, responsive constraints, and local size preferences |
| `traffic_view.js` | Native request ledger rows, ordering, the read block and its mounted rows and URL/method/status/name search, the General coverage view, request body record wording, and the saved-capture export document |
| `network_scope.js` | Counted browser-internal exclusions and the reversible browser-internal view filter |
| `request_tabs.js` | Each Traffic row's tabs from tab sets and request tab links, tab page names and rows without a tab |
| `traffic_headers.js` | The Headers tab: hops from native header records, checked block reads, Raw and copy |
| `traffic_cookies.js` | The Cookies tab: checked cookie list reads, request and response tables, filtered-out cookies, sort, copy and name provenance |
| `traffic_payload.js` | The Payload tab: query parameters, the parsed and source request body, find and copy, and Capture details |
| `traffic_index.js` | The request index client: the read block's rows, totals and facets, and a selected row's records from the event store |
| `traffic_filter.js` | The filter grammar, Invert, Hide internal, 3rd-party, Failed and the time range over the newest window, mirroring the request index |
| `traffic_columns.js` | Column widths, hidden columns, the header menu, saved layout and fitting columns to the table width |
| `traffic_overview.js` | The timing strip and its pointer and keyboard time-range selection |
| `evidence_names.js` | Researcher names: exact identities, the closed names document, its Analyst-library store, the inline rename editor and the command palette provider |
| `captured_client.js`, `captured_export_formats.js` | Saved-capture identity, local export dialog, and the client-project/HAR/SDL generators shared with offline commands |
| `source_tree.js` | The Sources navigator: frame, group, origin and folder model, hand-parsed non-special URLs, mounted-window rows, keyboard, type-ahead and filter; `app.js` supplies the catalog and the open path |
| `debugger_sidebar.js`, `debugger_sidebar.css` | The Sources debugger sidebar: its section registry, the Threads view, Watch rules, Observations and Pausing, and their reads of `get_native_debugger` and `get_request_stack` |
| `xrefs_view.js`, `xrefs_view.css` | The cross-references dock: selection following, the paged and virtualized list, and links to existing rows; the projection is [`/api/xrefs`](../../protocol/http-api.md#cross-references) in `../origin-trace-backend/src/xrefs.rs` |
| `source_search.js` | Search all files: the literal matcher on the Find index, the bounded and cancellable search, partial-result notes and the results panel; `app.js` supplies the artifact reader and the open path |
| `source_syntax.js` | Source names, display formatting, the inert hex view for Wasm and guest bytecode artifacts, and bounded tokenization without DOM or application state |
| `source_format.js` | The backend layout client (whole bodies and 1,000-line Sources pages) and its whitespace-only mapping to the displayed evidence |
| `code_view.js` | The code view Payload, Response, Native Console, Analyst and the agent panel share: Sources colors, rows mounted near the view in blocks of at most 200 rows and 64 KiB, find marks, layouts with raw ranges and the colored textarea editor |
| `native_console.js`, `native_console_completion.js` | Disposable browser console controls and local built-in API completion; the live document the debugger sidebar arms rules through |
| `../origin-trace-backend/src/app.rs`, `evidence.rs` | Loopback HTTP routing and bounded evidence reads |
| `../origin-trace-backend/src/workspace.rs`, `analyst.rs`, `workspace_lease.rs` | Workspace contracts, explicit analyst execution, private durable replacement |
| `../origin-trace-backend/src/decoder.rs`, `origin_trace.rs`, `vm.rs` | Native decoder adapter, trace projection, and VM analysis |
| `macos/` | Native shell, evidence readers, and helper processes |

The browser scripts load in the order declared in `index.html`. They use the
same page scope so the native shell and browser development path share one
implementation without a bundler. `evidence_models.js` contains evidence
validation and projections; `source_syntax.js` owns source display algorithms.
Live refresh and DOM updates belong in `app.js`.
The native scheme handler and packaging script explicitly list shipped assets.

Traffic shows every native request row independently; host, method and time
never merge rows. A row is hidden only by an explicit, counted, reversible
filter: **Hide internal** in Traffic, shared with Sources' "Hide browser-internal",
covers `chrome:`, `devtools:` and other internal schemes
([native network v3](../../protocol/native-network-v3.md)), and the footer
reports what capture excluded, including memory-cache reuses past a renderer's
budget ("N memory-cache reuses not recorded") and, apart, those in SVG images
or popups that no tab owns. Header and cookie gaps of the loaded rows are one
footer button, **N header gaps**, so the footer keeps its size: it opens a
breakdown below it (Space or Return; Escape closes it and returns focus) of
header blocks and cookie lists not retained (with each reason: size limit,
session budget, queue, channel or URL), network blocks that arrived after
their request ended ("late header records on no row"), and requests that
ended with only provisional headers, by reason (HTTP cache, service worker,
download, failed, not reported); `get_session_summary` has the same counts
over the newest 64 MiB. Sources reads retained artifact bytes only. A failed
refresh preserves the last valid catalog, and a detached pending load is
cancelled and cannot restore obsolete source text. Artifact loads have a
10-second deadline, including body reads; a timed-out load can be retried
explicitly.

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

### Rendered UI acceptance

```sh
make rendered-ui-check
```

This runs the packaged app, not a browser. `tools/check-origin-trace-rendered-ui.mjs`
copies `build/Origin Trace.app` to a temporary directory, verifies its signature,
and starts the bundled `OriginTraceBackend` on loopback with a bounded synthetic
session: the `make e2e` demo stores, 72 native network rows, a 400-line retained
source, a synthetic guest bytecode buffer, Wasm dispatch and guest events
emitted by the real C++ encoders (`build/reb-native-wasm-dispatch-golden` and
`build/reb-native-wasm-guest-golden`), and debugger observation records. Captured strings and bytecode include
markup that would execute if it were inserted as HTML.

The hosted XCTest bundle in
[`tools/origin-trace-rendered-ui`](../../tools/origin-trace-rendered-ui/) is
injected into that app (`TEST_HOST`) through an `.xctestrun` description. It
drives the production window and WKWebView with native AppKit pointer and key
events, and reads layout only through `probes.js`. At the default 1180×790
window and the enforced 760×560 minimum it checks:

- Traffic: retained rows, list scrolling to the last row, request selection and
  the detail pane; default and fitted columns, cell tooltips, Size and the
  waterfall from recorded lengths and timestamps, the timing strip from the
  keyboard and the column menu from Shift+F10; Payload's query, JSON tree from
  the keyboard, source and Capture details;
- Sources: a retained artifact rendered as literal text and scrolled to its end;
  with a Wasm module open, narrowing from 1180×790 to 760×560 and back keeps the
  toolbar commands on one uncovered row with no blank band;
- Investigation navigation: Back appears after a screen change, Alt+Left returns
  to the selected request, and Forward reopens Sources;
- VM: the opcode workspace for the guest artifact shows the native guest row
  with its wide instance identity, and the physical artifact never claims a
  guest PC;
- native-only coverage: Traffic offers only General, Headers, Payload, Preview,
  Response, Cookies, Initiator, Timing, Signals and Evidence with no content
  search or Compare; a retained response body is inert colored text on
  Response, pretty prints, and is a JSON tree on Preview, reached by arrow key;
  Headers shows a content-session request's retained blocks, Raw view and
  markup as text, and says why a metadata-only request has none; Cookies shows
  its response and request cookies, a blocked cookie's reason, filtered-out
  cookies on request and a name's provenance to its script write; Export offers only local-file
  SDL and says why; golden and hostile guest bytecode render as an inert hex
  view with an unclipped kind icon;
- keyboard order and visible focus for 30 stops (Option+Tab when Full Keyboard
  Access is off, as in Safari), and Shift+Tab reversal;
- no removed CDP control or markup anywhere in the shipped screens;
- cross-references: the dock opens with X, follows the Traffic selection, lists the
  recorded initiator and lifecycle links, and keeps arrow keys, the filter shortcut,
  Escape, truncation and the light theme usable at both window sizes;
- the debugger sidebar: sections in order with Pausing stated as the reported
  availability and no pausing control, rows mounted by view, inert captured
  event types, keyboard focus on the Threads list, an observed frame scoping
  the Sources tree and Observations, a listener record opening its site in
  Sources at the exact line and column, the light theme, Escape, and no read
  while closed.

Layout checks reject horizontal page overflow, controls cut off by a
non-scrolling ancestor, controls covered at their hit-test point, overlapping
controls and text clipped without an ellipsis or line clamp. No captured value
may execute or become an element. Screenshots are written to
`build/rendered-ui-qa/screenshots`; inspect them as well as the result. The
check needs macOS and full Xcode (XCTest); it uses `DEVELOPER_DIR` or the
selected Xcode without changing the global selection. Run one case with
`node tools/check-origin-trace-rendered-ui.mjs --only test4VmNativeGuestRows`.
The window becomes active while the check runs. It does not exercise a live
browser capture.

### Interface styling

The shared shell keeps the existing Rosé Pine Moon tokens, thin pane dividers,
and semantic selection accents; Appearance retains the existing light theme.
Traffic uses independently scrolling ledger and inspector panes. Compact
resource filters stay visible below search and wrap within narrow windows. Selected-field actions sit beside the evidence on wide windows
and below it on narrow windows. Session
counts come from loaded requests, and sample evidence stays visibly labeled.
Keep labels at least 10 px and reserve stronger color for selection, connection
state, errors, and evidence confidence. Sources file icons are the one chrome
tint: JavaScript, WebAssembly, JSON, source map and HTML icons take their code
color at low strength, while folders, origins and frames stay neutral. Code is the exception: Sources and the
Native Console color code like the Rosé Pine Moon VS Code theme (Rosé Pine
Dawn in light mode), with the colors and styles VS Code renders for each token
(there, `JSON` is an italic variable and `stringify(` a plain function call), its
six bracket pair colors, editor colors and Menlo 12/18 px; the Analyst editor, the Traffic Payload and Response
code views, and the agent panel's fenced code and tool arguments and results
take the same editor colors and font. Payload, Response, Native Console,
Analyst and the agent panel use one code view (`code_view.js`) with the Sources lexer
and theme; Analyst colors its text behind the textarea, which keeps editing. With macOS Increase Contrast, comments and
keywords are brightened. `node tools/check-source-format-ui.mjs` (part of
`make lint`) pins the token kinds and colors.

Tool workspaces put the next action before implementation details. Decoder
controls follow input, transformation, and result order; chain editing stays
beside the step list. JWT test-token creation is an optional disclosure below
inspection. Use the interface font for instructions and labels, and monospace
for captured values, code, and identifiers. Empty states explain how to begin.

Flow (formerly Backtraces) lets the researcher select a captured request, load
its recorded predecessors in the Lineage pane, and select a row to inspect event
identifiers, values, and source under **Details**. Empty traces show a next
action rather than a graph or coverage meter. Gaps and shared-identifier
matches remain explicit. Refresh failures retain the previous trace, and arrow
keys move between trace rows. The session's flow graph, the selected function's
CFG and the tracked-call timeline sit beside it ([Flow workspace](#flow-workspace)).

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
readbacks. Only the visible Rendering gallery loads previews, scoped to its
current readbacks. Canvas owns a separate maximum of 24 previews and 8 MiB of
UTF-16 text reservations/retained text; each descriptor reserves twice its
encoded byte size before admission (at most 2 MiB encoded bytes per preview).
Newest previews have priority, and budget omissions remain labeled without
refetching on every refresh. Unchanged polling retains the same cards, native
disclosure controls and admitted image nodes, including across pointer press
and release. Changed render inputs or exact source ownership invalidate that
reuse; updated disclosures preserve their expanded state and focus.
At most two unfinished preview reads are allowed,
including retired reads whose fetch or response-body/reader cancellation has
not settled. Header/body errors remain visible immediately; explicit retries
do not bypass cancellation credits. Their bounded streaming
read buffers total at most 4 MiB; transient text, hashing and image decoding are
separate from the retained-text budget. A ten-second deadline aborts a read;
failed reads expose an explicit Retry preview action.

Activity, leaving Signals, changing the visible readback scope, catalog
replacement/emptying and catalog failures retire obsolete preview ownership,
abort pending reads and remove image sources from the gallery DOM. Late
responses cannot restore retired payloads. Artifact metadata and immutable
files remain available; an empty live catalog still reflects its actual empty
metadata window. Sources previews and verified analysis results keep their
independent budgets and identity checks.

Before assigning any captured image to `img.src`, the UI separately admits a
narrow static PNG profile: non-interlaced 8-bit RGB/RGBA, at most 4096 pixels per
axis and 4 Mi (4,194,304) declared pixels per image. At most 16 Mi (16,777,216)
declared pixels are mounted across the current gallery, with newest captures
first. The UI checks canonical base64, signature, chunk framing/CRC, a single
first IHDR, consecutive nonempty-in-total IDAT data and a final empty IEND with
no trailing bytes. At most 256 chunks are inspected. Only optional fixed-size
sRGB, sBIT and pHYs metadata is admitted, once each and before IDAT. Other chunks,
including animation, compressed profiles/text and unknown extensions, produce
an explicit unsupported-preview reason; the original evidence is unchanged.

The producer retains bounded `data:image/*` output, so this intentionally narrower
preview policy can omit valid captured images, including JPEG, WebP, other PNG
profiles and PNGs carrying embedded color profiles. Unsupported previews retain their exact text
inside the existing text budget and do not cause automatic refetches. Scope
changes release that text normally. A browser decode failure is labeled without
changing stored evidence; errors from detached images or retired owners cannot
poison the current preview. Image admission follows the exact current artifact
owner, and old DOM sources are removed before new sources are assigned.

These checks bound admitted declared dimensions and mounted pixel counts. They
do not inflate IDAT, validate its compressed contents, measure decoder allocations,
or bound JavaScript heap, native decoder caches or process RSS. Removing `src`
does not prove immediate decoder-memory reclamation. Browser/native interaction
and decoder behavior need separate rendered validation; giant-header fixtures
must remain inert. The profile follows the [PNG specification's structure and
chunk rules](https://www.w3.org/TR/png-3/). The native capture still does not retain
drawing arguments or a canvas object identifier, so local replay remains
unavailable and the earlier-call relationship stays renderer-scoped.

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
trace, and request-profile stores. One capture action runs at a time: while it
does, both buttons stay disabled and the notice says so, and an event poll that
overlapped it is discarded and read again, so it cannot restore pre-stop or
pre-clear evidence. A refused action, or one with no answer within 15 seconds,
stays in the notice until the next action. When the backend stops answering,
both controls are withdrawn until a valid poll reports them again. Canvas artifact files and other saved files
remain on disk. Detailed identifiers stay behind a disclosure. The
captured-tab buttons are historical evidence, not an open-tab count. The footer separates missing per-process sequence IDs from
reported queue drops, since a gap report can describe the same missing IDs. It
counts named sampling budgets, sample-policy exclusions, and reported capture
losses separately, with their categories, and never adds them to queue drops.
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

Sources navigation lists every retained Captured artifact (`source_tree.js`).
The catalog is read forward from `get_artifacts` in 5,000-record pages; a
one-record probe carries the ETag and a manifest that only grew is read from its
last boundary. The first 50,000 records of every kind are read in manifest
order, for Traffic, Evidence and packages; after them only the kinds this catalog
alone supplies are read (`kind=`), so request records cannot push a script out.
Loading stops at 100,000 sources with a notice. A stored session reads the same
pages from the bundled backend. The tree reads
**top**, then one row per frame, then the **Workers** (no frame),
**Dynamic (eval / new Function)**, **WebAssembly** (modules compiled from bytes
and their guest artifacts), **Extensions** (by extension ID) and **Browser
internals** groups, then origins, folders and files. The frame seen first is
listed first, other frames by name. A frame is named by its Console document URL
when the Console listing has one, which also marks top-level documents, and
otherwise by the origin of its first document artifact: a retained HTML response or an eval or Wasm artifact. A frame with neither reads `frame · <origin>` from its first source. Extension and
`chrome://` hosts are read by hand because their URL origin is `null`; browser
internals start collapsed. A folder chain with one folder child reads as one row
(`a/b/c`). Files show their plain name, eval code `VM<id>` as in DevTools, with
a mask icon tinted by type and the two-letter kind code kept as its text. The
artifact ID is in the muted meta column, the tooltip and Details; same-named
siblings add a muted query, session or frame suffix, or their artifact ID when nothing else differs. Extension names are not captured,
so extensions show their ID.

Only rows near the viewport are mounted; the focused row stays mounted while
scrolled away. One row is in the Tab order. Up/Down move through rows, Right
opens a branch or enters its first child, Left closes it or returns to its
parent, Home/End reach the first/last row, PageUp/PageDown move a viewport less one row, and typing a name moves to the next
row that starts with it (repeat a letter to cycle). Modified arrows keep their
browser/history meaning; Enter/Space keep native button activation. **Filter
files** above the tree matches file names, URLs and artifact IDs and shows each
match with its folders; Down enters the tree and Escape clears it. Expansion
under a filter is separate, so clearing it restores the saved expansion.
**Expand all** and **Collapse all** act on the current view. Expansion is kept
for the app session. Focus and the open document are separate: collapsing a
selected file's ancestor never reads source bytes or runs analysis. Catalog
refresh keeps keyed rows, focus and the first visible row in place, returning a
removed focused row to its closest surviving ancestor.

The navigator holds at most 400,000 metadata nodes, counted before one-folder
chains collapse, which 20,000 sources cannot exceed in any folder layout. It rejects URLs above 4,096
characters and identities above 8,192 characters, shortens directory structure
after 16 levels, and discloses each limit rather than implying omitted sources
are absent. Selection markers are withheld when the catalog is capped, a source
identity repeats, or an omitted record shares the selected ID. Empty path
segments remain distinct, explicitly labeled folders. **Open file** lists the
first 200 matches. These limits do not evict open source text, change captured
evidence, or relink documents.
Find searches the selected document's owned retained text, independently of
which lines are mounted. It uses a case-insensitive single-line literal of at
most 512 UTF-16 code units. Multiline pastes are refused before the browser can
join their lines. Enter advances and Shift+Enter goes back through the first
1,000 matches, including late matches in minified lines and after line 20,000.
A visible `+` discloses the match cap. Search never fetches more bytes or runs an
analyzer. Complete text, retained prefixes, lossy displays and unavailable or
evicted previews have separate coverage labels; an incomplete negative is never
reported as absence from the complete source. Loading/truncation notices are
excluded. Pretty/Deob Find names the retained display representation, with
transformation completeness separate from search coverage.

**Search** beside **Captured** in the Sources navigator searches the text of
every retained file at once, for the string constants, endpoint paths and magic
numbers that are usually the first thread to pull. The query is a literal single
line of at most 512 UTF-16 code units, case-insensitive unless **Match case** is
on. No pattern syntax is offered, because captured scripts are adversarial and a
regular expression could backtrack catastrophically on crafted input. Typing
retires the running search at once and searches again after a short pause;
Enter searches immediately. The command palette's **Search all sources** entry
opens this view with its query and runs it; typing in the palette never reads
artifact bytes.

Each file is read once through `/api/artifacts/{artifact_id}/content` with a
2 MiB limit and the Sources preview's byte-size and SHA-256 checks. A loaded
preview is reused without a request, and other text is kept in a separate cache
of at most 8 Mi UTF-16 code units, so the next query does not refetch it; files
that leave the catalog leave that cache. One search reads at most 32 MiB and
collects at most 100 matches per file and 1,000 overall. WebAssembly and guest
bytecode are binary and are not searched. The status line counts files as they
finish ("Searched 12 of 40 files"), and a note above the results names every
file that was not searched completely: binary files, files that failed to load
(with the reason), files over the 2 MiB size cap where only their first 2 MiB
was searched, files that are not valid UTF-8 (a miss there is not proof of
absence), files that stopped at the per-file match cap, and files left unsearched
by the overall match cap or read budget. Nothing is dropped without a note.

Results are grouped by file with its name, match count and URL. Each match shows
`line:column` and its line with the match marked; captured text is inserted as
text nodes. Arrow keys move through the matches (Arrow Down from the field enters
them), and Enter or a click opens that file at the match: the same Sources
selection as the tree, revealing the line and marking the match like Find. Opened
from Sources, the previous view becomes a Back stop, so Back returns to the
results with their scroll and focus. A file that changed or left the catalog
after the search is refused rather than reopened. `node tools/check-source-search.mjs`
(part of `make check`) exercises the matcher, caps, cancellation, partial-result
notes, reader checks and this open-and-Back path in the shipped scripts.

The editor mounts at most 1,000 lines. A row above and below them reaches the
previous and next 1,000 lines, and **Go to line** (Ctrl+G, or **More**) takes a
line and column. The target line retains at most 16,384 UTF-16 units (one
additional unit may preserve a surrogate pair); other lines retain at most 512
each. Omitted-column markers sit outside source text. Find and original-byte
links reveal an excerpt containing the requested absolute location, rather than
increasing these limits. Colors resume from lexer checkpoints saved every 4 Ki
UTF-16 units of the document, so later windows and clipped columns color exactly
as a pass from the start would. Checkpoints extend in steps of 64 Ki units
between tasks; a window they have not reached shows **coloring…** in plain text
until they do, and its mounted rows are then colored in place rather than
rebuilt. Captured bytes, line endings, BOMs and absolute runtime locations
stay unchanged. The current document has one sparse line anchor per 128 lines,
within a defensive 64 Mi UTF-16-unit inspection limit.
Derived/Pretty mappings are projected only for mounted lines.

Investigation history retains logical line/column windows with the exact source
and representation owner, then restores pane scroll. A changed derived-analysis
version or intrinsic assumption cannot restore a stale representation window.
Ordinary evidence refresh leaves Find and the current window in place; explicit
original-source pivots choose their own retained location.

The editor toolbar is one row: the URL, **Open file**, Find (Cmd+F), **Inspect**
and **Graph** for a Wasm module, **Map**, **Debugger** and **More**, which holds Go to line,
Rename, Decode range, Facts, Track calls, Static cleanup and Details. The row
never wraps at any width: the URL shortens first (its tooltip keeps it whole),
then Find, and when the commands still do not fit, Debugger, Map, Graph and
Inspect move in that order to the top of More and return once there is room. Find's coverage
sentence is its tooltip. The status bar shows the
caret line and column, with the original location in a pretty-printed or derived
view (`Line 1204, Column 5 (original 1:48213)`), the selection length, the
evidence state (Original or Derived), the language and layout, the **{ }**
toggle and the size. The position is never cut and its tooltip is the full text.
When the bar is too narrow it drops whole items instead of squeezing them: the
hash, then the toggle's label (leaving **{ }**), the language, the size, a
selection's raw offsets, the evidence state, the selection length and a
selection's raw range. Dropped parts of the position stay in its tooltip.

The Sources sidebar starts closed. Details opens source metadata, JavaScript
facts and static cleanup; it remains available at narrow window sizes.
Wasm modules and native guest bytecode buffers open as an inert hex view of
their retained bytes (offset, hex and printable columns, labeled **WebAssembly
hex** or **Guest bytecode hex**); bytecode is never decoded as text. Guest
adapter recipes are JSON text.

VM analysis is a secondary Traffic view, reached through Related VM candidates
for a selected native request with a complete root identity. Incomplete native
rows stay in Traffic with an unlinked notice; they never
silently open session-wide analysis. The request-scoped view uses only acknowledged response
creator chains and has a Back to traffic control. Use workspace navigation
explicitly to inspect unfiltered session analysis.

When the selected finding has a validated opcode workspace, VM Lab adds the
handler mapping, runtime typed-array bytecode preview, characterized coverage,
named omissions, and residual unknowns beneath the unchanged detection detail.
Handler rows keep inferred candidates visible even when the runtime sampler is
unavailable, and support Up, Down, Home, and End selection. With no runtime
samples, the Coverage diagnostic leads with the observed absence of retained
samples and the missing automatic guest-interpreter sampler. A caller-fed writer
is not that sampler; static dispatch, Canvas calls and snapshots still do not
prove a guest PC.
The **Dispatch sites** panel shows each site's structural
[dispatch classification](../../protocol/vm-dispatch-classification-v1.md) as
`kind / selector source / repeats` text on dispatch-inventory and handler-table
rows, and lists every classified site, including JavaScript workspaces. A
one-shot router reads `router, no guest opcodes claimed`. Element handler
tables list each segment's evaluated slot placement.
The **Runtime claims** panel lists
[observed claims](../../protocol/vm-opcode-workspace-v2.md#observed-claims-and-nested-guests)
from retained native rows beside, never inside, the handler list. Each claim
shows its stream, site, selector, opcode, handler and supporting events, and
whether the static claim agrees, disagrees, was withheld or is absent; a
disagreement keeps both statements under an amber rule. A `call_indirect` claim
names the slot and callee function and compares them with the element
segments' entry for that slot; a table filled at run time is withheld. WebAssembly workspaces
also list nested guests: an inner interpreter, its buffer and opcodes, and the
outer site and handler that drove it, named exactly by the capture or inferred
from sequence order. The viewer recomputes every claim and
link from the retained rows and rejects a document that does not match.
Parse failures and binding refusals remain counted, visible text in the
Dispatch sites panel. Worker execution failures return a retryable API error and
are never persisted or cached as an analysis. Workspace failures retain the last
valid workspace and never remove detection findings.

Traffic is grouped by browser tab with an All tabs scope and a domain
selector. Each chip is named by its tab's newest main-frame page. A worker
request linked to several tabs (`request_tabs.js`, from `tab_set` and
`request_tab_link`) appears in each with a marker such as "Service worker · 2
tabs", or "Service worker · installed from 1 tab" for a version that has had
no client yet; All tabs counts it once. The footer also names counted
service-worker requests no page caused and browser prefetches with no page. Extension traffic recorded with
`REB_CAPTURE_EXTENSION_TRAFFIC=1` (`request_extension_link`) has one
"Extension <id>" chip per extension. The request index joins the same links, so
chips, the tab filter and the footer count cover the whole session. There is no
Unattributed group: a row without an owner is a capture error, counted in the
footer, whose button lists those rows.
See [request owners and tabs](../../protocol/native-network-v3.md#request-owners-and-tabs).
Evidence retains the original payload and trace actions; General, Initiator and
Timing display only recorded observations.

## Deobfuscation engines

Deobfuscation stays inside **Sources**. Select a JavaScript source and use the
**Static cleanup** control to switch between original evidence and the mapped derived view.
Open **Details > Static cleanup** to inspect the report. Cleanup preserves the
current sidebar visibility so narrow-screen overlays do not hide the code. It
uses REB's existing local Rust/Oxc worker;
it does not call or embed an online deobfuscation service. No input is executed
or uploaded to a third-party service. **Compare original / cleaned** shows
both inert texts with independently labeled 8,192-UTF-16-unit prefix limits,
without splitting a surrogate pair. Full-source SHA-256 values identify the
original and cleaned UTF-8 text; the cleaned hash is computed locally after
source-map admission and is not an equivalence proof. The existing changed-span
inspector retains exact original/derived ranges beyond those previews.
**Original** returns the editor to retained evidence. **Discard cleaned result**
removes the current option's cached derivation, retires a pending retry and
returns to original text; late responses cannot restore it. Another analysis
requires explicit retry. Neither action edits or deletes the original artifact.
Unsupported behavior remains visibly unresolved even if no resource budget was
reached; no safe rewrites is not a claim that source is unobfuscated. This is a
separate ephemeral derived view, not a persisted replacement capture.

The status-bar **{ }** toggle pretty prints JavaScript, JSON, CSS, and HTML using
the detected source type. JavaScript, CSS and JSON with a line over 16 KiB open
pretty-printed, shown as **Pretty-printed · Show original**; the choice either
way is remembered per artifact for the session. The gutter numbers formatted
lines; its tooltip names the original line and column. A complete JavaScript artifact is laid out by the
backend's Oxc formatter (`get_source_format`, [Source format v1](../../protocol/source-format-v1.md)):
Prettier's layout at 80 columns, with every token printed as captured. Sources
reads it one 1,000-line page at a time; each page's anchor names its first
original offset, so the editor maps every character back by walking that
page against its slice of the evidence, and clicking a formatted token shows
the exact raw range it came from. Each page's colors continue the original's
lexer state where it starts. The page shown stays while the next is read, and
Find searches the complete evidence text and opens the page that shows each
match. While the first page is read the original stays on screen. If
the source does not parse, the backend is unavailable, or the text is derived,
truncated or another language, the in-page formatter is used: the status bar
names the whitespace layout and the row above the code says why. It runs in a Web Worker (on the page, after one task, where
workers are unavailable). It can format either the original evidence or the
active deobfuscated representation, so an unchanged deobfuscation result does
not leave a minified bundle on one line. Pretty printing changes only display
whitespace, keeps source-line mappings back to the captured bytes, and never
rewrites stored evidence. Both layouts map back through one sync point per
4 Ki formatted units rather than a segment per change. The in-page formatter
streams its tokens, accepts the 16 MiB artifact cap and stops when its output
exceeds three times that.
**Details > Static cleanup** shows analysis, limits, omissions, and retry actions. The native app ships a Rust/Oxc worker for bounded static AST rewriting
over captured artifacts. It needs no Python runtime. Building the app
requires a current stable Rust toolchain (`rustup toolchain install stable`).
The Rust backend preserves classification, formatting, and literal-table
analysis for captured artifacts. The Deobfuscation details
name the engine. Dynamic decoding remains unimplemented and is reported as an omission. Static table substitution is
restricted to non-escaping local tables with proven own-index reads.

Failed analysis remains visible until **Retry analysis** is selected. A failed
retry retains the last successful result. Source selection does not switch the
Sources editor away from original evidence. The UI retains at most eight analysis
documents and distinguishes source hashes and artifact identities in its cache.
The report retains the last successful summary and snippets during a retry or
failure. **Cancel analysis** retires the current request; a worker may still
finish, but its late response cannot replace the report. Cancellation and errors
require an explicit retry.

The report's changed-span inspector shows one validated replacement at a time,
with Previous/Next, exact half-open UTF-8 ranges, and original/derived snippets
limited to 2,048 UTF-16 units each. Snippets scroll independently; truncation is
visible and never splits a surrogate pair. In the HTTP live workspace or browser
development UI, **Reveal original range** verifies captured original bytes
through the existing Facts path. Stored-evidence native mode displays an explicit
unavailable reason for that navigation. Neither path executes source. Pretty printing remains a separate display layer.

Transformation families, heuristic classification signals, recovered table
summaries, and assumptions/limits have explicit counts and four-row paging.
Generic omissions do not hide recovered tables. Raw table entries are not shown;
only bounded admitted summary fields and previews are displayed. Family totals
are whole-report metadata, not invented explanations for a selected replacement.
Classification is labelled as a heuristic, not a probability or equivalence proof.
Missing legacy change metadata is shown as unavailable; code-point maps do not
offer exact UTF-8 change inspection. Small selection/page/disclosure metadata
lives with its bounded cached analysis and disappears on eviction. History does
not restore intrinsic options or the selected change.
The [versioned contract](../../protocol/deobfuscation-v1.md) defines source-map
units and how native replacements map back to their original expressions.

The production Rust AST passes and their ReverseJS comparison are documented in
[method coverage](../../docs/product/deobfuscation-method-coverage.md). The browser
server uses a built worker when available (debug before release), or the explicit
`REB_DEOBFUSCATOR_WORKER` executable. Worker failures remain errors; a missing
worker makes AST operations unavailable with an explicit error. Deob stays inside Sources.

## Track calls to a function

To follow calls of a page function such as `window.hsw` in the next capture,
open its captured script in **Sources** and either type the name in the
**Track function calls** pane of **Details** and press Return, or put the
cursor in the function (click it, or use **Go to line**) and
choose **Track calls** in **More**. The position must be in the original
view, not a pretty-printed, derived or Wasm view. The backend resolves the
exact artifact and saves one site; it never guesses. A name bound by several
definitions, or by none, lists the candidates with their line, column and a
context line: **Show** reveals one and **Track this one** saves it. A
bare-parameter or `async` arrow, a generator, a class constructor or a class
initializer is refused with its reason, as is top-level code. Context lines
and labels are captured text, inserted as text.

Saving changes nothing in the open page or the running capture. The pane says
tracking starts with the next capture: the start panel that **New Live
Session…** opens shows "Tracking N functions" with each label and
script URL, a Remove for each and Clear All (which asks once more), and the
capture it starts arms a private copy of the set. The native app reads and
rewrites the saved file for the panel; a Remove names the list the panel
showed, so a list that changed since is refused rather than edited. Content mode also records
the calls' settled-value digests; Metadata mode does not. The titlebar names
what the running capture tracks, says when its Brave predates invocation
capture and started without the sites, and warns when this session retained
another version of a saved script, which the saved site will not match. At
most 8 functions are saved, in
`~/Library/Application Support/Origin Trace/js-invocation-sites-v1.json` with a
label sidecar; `REB_JS_INVOCATION_SITE_STORE` names another file. Stored-evidence
native mode has no backend for these routes and says so. The routes and
matching rules are in the
[HTTP API](../../protocol/http-api.md#saved-javascript-invocation-sites).

## Captured JavaScript facts

In **Sources**, select a captured JavaScript artifact and choose **Facts**.
The existing Rust/Oxc worker returns bounded lexical scopes, declarations,
callables, regions and operations for that exact session, artifact and SHA-256.
This is an explicit, inert analysis action. Derived text is not accepted. The Details pane shows complete-within-profile, partial,
unavailable and truncated states, diagnostics and unknown-effect frontiers.
Each category displays 100 rows per page; fact details are capped at 4,096
characters. In **Bindings**, search declaration names and choose **Find lexical
operations** to inspect exact-ID references, reads, writes, calls and constructs.
The kind filter and paging keep long reports bounded. Same-name declarations in
different scopes remain distinct; operation rows can return to their declaration
explorer. Ambiguous targets offer an explicit candidate chooser and remain
candidate links. Unresolved/dynamic names and property targets never become
binding links. Counts describe static operations, which can share one source
occurrence, not runtime uses or dataflow. Call targets remain unknown.
This panel always analyzes the whole selected artifact; the API's
`region_start_byte`/`region_end_byte` scope is not exposed here, so a bundle
that reports a reached budget is narrowed through `reb-api call
get_source_facts` instead.
**Reveal declaration** and operation **Original bytes** actions use the same
verified UTF-8 reader. Changing the explorer selection cancels its pending
reveal. Source identity changes and successful reanalysis clear selected fact
IDs; a failed retry preserves the existing report and selection. Search supports
Unicode composition and keeps captured labels inert. Nothing executes source,
adds capture, or persists an index. Shadowed declarations retain distinct IDs and ambiguous bindings
remain candidates. Neither is proof of initialized values, dataflow or runtime
call targets; region-local order is conditional on entry and normal completion.

An **Original bytes** link loads the complete original artifact through the
existing verified 2 MiB chunk endpoint (at most 4 MiB total), checks its SHA-256,
and strictly decodes UTF-8 while retaining a byte-order mark. It then switches
the existing editor to original source and reveals the selected half-open byte
range. The start-line span is highlighted when browser highlights are available;
multiline ranges remain explicitly labeled. Links beyond line 20,000 now mount
the corresponding bounded line/column excerpt; a clipped highlight is labeled. A lossy preview,
a different session, changed hash or derived representation is never used as a
byte-coordinate substitute.

Cancel, closing Facts, source changes and leaving Sources discard pending
responses. An already started bounded worker may finish, but its result is not
applied. Response readers own a bounded byte buffer: at most 33 MiB for facts
and 2 MiB per original-source chunk. They reject more than 65,536 stream chunks,
including empty chunks, and yield every 256 chunks so fragmented responses cannot
starve cancellation or deadlines. Cancelling does not wait for producer cleanup.
Requests have a ten-second deadline including response-body reads;
retries are explicit, and a failed retry preserves the last successful report
for the same exact source. Only one report and one verified original source are
retained by this view.

The native app's live workspace loads the bundled Rust HTTP backend and shares
this feature with browser development. The separate `reb://` stored-evidence
native interface does not have the reviewed adapter: Facts is disabled with a
visible explanation in Details, and direct requests return structured HTTP 503
`dependency_unavailable`. No Swift parser or duplicate validator is substituted.
See [JavaScript source facts v1](../../protocol/javascript-source-facts-v1.md).

## Programmatic HTTP access

The Rust backend's endpoints are described in the
[OpenAPI 3.1 specification](../../protocol/openapi.json). Run
`apps/origin-trace-backend/target/debug/reb-api list` from the repository root to discover
CLI operations. The `call` command requires an explicit loopback URL or the
server's `--endpoint-file`; see the [HTTP API guide](../../protocol/http-api.md)
for examples, locality checks, and known gaps. The CLI does not start or control
an installed native app session, and the native custom-scheme interface is not
itself an HTTP server.

## Basic-block graphs

**Graph** on a captured WASM artifact draws one function at a time as basic
blocks, above the linear disassembly and hex. The graph takes about two thirds
of the height; drag the divider between them like the other pane splits, or
use **Linear** to hide the linear pane. The text view's line window and search
notice are hidden while Graph is active. A graph opens at actual size, centered
on the entry block (or the whole graph when it fits), and **Fit** or `0` shows
all of it. Below the zoom where rows are readable, cards keep a screen-size
label and an overview cue says rows are hidden. The footer is one line: the
limits, then the edge legend, which folds behind **Key** in a narrow pane. Selecting a block with the pointer or Enter scrolls the disassembly or hex
to its offset. **Graph** in Static bytecode draws the same view for a decoded
image. Declared flow and an imported **Observed path** are separate layers,
never one graph: the observed layer's cards are retained steps, and a sequence
gap is a card with no edge on either side.

The header gives the name, block count, instruction count and `declared` (or
`observed`). Each block shows its first byte offset as `loc_<hex>`, an
instruction-count badge and rows of offset, mnemonic and operands. A run of
identical `block` openers is one row with a count; the badge still counts every
instruction. Edge kind is never color alone: taken is solid, false is dashed,
table arms are dotted with their case numbers, exception edges are long-dashed,
and an unresolved target is a labeled stub that adds no block. The footer keeps
the limits on screen: declared reachability is not observed execution, and a
complete drawing is not a proof. Nothing here sets `cfg.complete`.

Keyboard: arrows move to the nearest block in that direction, `[` and `]` step
in byte order, Home returns to the entry, Enter shows the block in the
disassembly and hex, `+`, `-` and `0` zoom and fit, and Shift+arrows pan.

The layout runs in a Web Worker. When the backend serves
`POST /api/graph-layout` ([HTTP API](../../protocol/http-api.md#graph-layout)),
the function is laid out by [Triskel](https://github.com/triskellib/triskel), a
CFG layout engine built on single-entry single-exit regions. It is vendored in
the backend and runs in a separate worker process with size and time limits.
The project-authored region layout in `block_graph_layout.js` stays in four
cases:
- Triskel would draw the function more than 1.6 times wider and over 1,400 px.
  A flattened dispatcher's fan is the usual case: the region layout stacks it
  into a grid, where Triskel puts every arm in one row.
- The function has more than 2,000 blocks or 8,000 edges.
- Triskel's answer does not match the function.
- The route is missing or fails, as in the stored-evidence window.

The header says `Triskel layout` when Triskel was used, and hovering the counts
says why the region layout stayed. The region layout also stays when Triskel's
drawing would be more than 1.6 times taller and over 1,600 px taller, as nested
loops can make it. Both layout workers reach the route through
`graph_layout_client.js`, which holds its limits, the 20 s request budget, the
answer check and this acceptance rule, and gives each graph it does not lay out
a reason code that each view words for itself. Triskel's and fmt's licence
texts ship as `Contents/Resources/GraphLayoutLicenses.txt`.

The region layout uses dominator regions: each subtree is entered once, so it
lays out alone and only its members' sizes reach its parent. A layer of one
continues the spine. A wider layer becomes side-by-side boxes and wraps into a
grid past six. Arms with no way out stack on the spine. Edges leaving a box
share a bottom port, and every back edge to a loop shares one rail.

Memory: one function is decoded on demand, layout runs in one worker per view
that stays between jobs and is terminated when a job is replaced or the view
closes, and laid-out graphs stay in a
16 MiB least-recently-used cache that is cleared when the view closes, the
artifact changes or the screen leaves. The canvas is one bounded backing store
that does not grow with graph size, and only visible cards and edges are drawn.
A byte budget cuts row text before structure and labels what it cut.

## Flow workspace

**Flow** (⌘5, formerly Backtraces) is one screen with four linked panes that
share one selection. Each pane keeps its own zoom and scroll, and changing
pane, tab or layout never changes the selection.

- **Graph** (gold): the session [flow graph](#flow-graph).
- **CFG** (iris): one Wasm function's basic blocks, read and drawn exactly as
  Sources does ([basic-block graphs](#basic-block-graphs)), with the block that
  holds the selected byte offset marked. It opens when a Wasm card is selected
  or followed, or a timeline sample is picked, and names the function from the
  module's name section. Empty, it says how to fill it. **Sources** opens the
  module in Sources at the function's first byte (its body's start), revealed
  the way the entropy map reveals a byte once the module's bytes are held; a
  byte the hex view does not hold says so in the status bar. The function's
  blocks are read only while the CFG pane is shown. A card picked in the graph
  waits 150 ms first, so moving across cards reads only the card it stops on;
  a function already loading is not read twice, and the last four functions
  read or failed stay, so returning to one needs no read. A session change
  cancels a read or layout in flight and forgets the decoded graphs and
  names, so nothing from another session is drawn.
- **Lineage** (rose): the selected request's recorded predecessors from
  `/api/origin-trace`, what Steps used to show, with the event under
  **Details**. Each link shows how sure it is by line style (solid observed,
  dashed shared identifiers, dotted time-adjacent, a cut for a gap) and what it
  is by colour. A picked sample's selector counts appear under **Selected**.
- **Timeline** (pine): tracked calls in record order (below).

Traffic's **Trace origin** and Evidence's **Show in Flow** open Flow with that
request selected and Lineage showing.

### Moving around

The keys never act while typing in a field, never with ⌘, Ctrl or Option (the
app's own shortcuts), and never take a key the graph or block graph canvas
already handles while it has focus.
- 1 to 4: Graph, CFG, Lineage, Timeline. In the split they move keyboard focus
  to that pane, showing it if it was hidden; in focus mode and in a narrow
  window they switch panes.
- Z: open the active pane on its own, or return to the split exactly as it
  was, with the same panes and sizes. Each pane's corner button and a
  double-click on its head do the same. Returning, focus stays on the pane
  focus mode showed when the split shows it; otherwise it goes to the pane
  focused before focus mode, else the graph, never to the page.
- ⇧C, ⇧L, ⇧T: show or hide CFG, Lineage and Timeline in the split. A CFG hidden
  this way stays hidden when a function is picked; Enter still opens it.
- Enter: follow the selection into the pane that explains it. A sample or a
  Wasm function opens the CFG at its block; a request opens Lineage.
- ⌫ and ⇧⌫, or the arrows beside the title: walk the trail back and forward,
  including jumps between panes. On the graph canvas ⌫ keeps the graph's own
  Back and ⇧⌫ still walks the trail forward. An entry restores its request in
  the app; when it had none, or its request is no longer listed, the app keeps
  the request it shows (a notice says so) and that is not a pick, so Forward
  stays until another request is selected.
- J and K: in the CFG, the previous or next sample at the selected site; in the
  timeline, samples in record order. Arrows move along and between tracks.

The **trail** in the head reads request › tracked call › function › site ›
sample, and each crumb jumps to its item in its pane. A pick keeps only the
crumbs that are recorded relationships of what was picked: a sample keeps its
call, function and site; a call keeps itself; a request chip makes its request
the request crumb and keeps the call it was issued in; a card keeps its
function and row. A lineage step that lights a card or selects a call replaces
the crumbs under the request with it; any other step leaves the trail alone.
When the app selects another request the trail restarts at it, and the same
request renamed is not a pick. In focus mode a tab bar names what each pane
holds, and the **Related** rail lists what links to the selection: its
lineage links, its samples, the function's sampled sites and the graph card
with its row, callers, callees and request where the graph reports them.
Every entry jumps. The rail is rebuilt only when what it lists changes, so an
evidence poll leaves keyboard focus where it is.

### Layout

Container queries on the Flow screen decide the layout from the screen's own
width, so a docked Console or agent narrows it as a smaller window would.
- 1240 px and wider: every pane, with the timeline docked under them.
- 900 to 1240 px: CFG is a tab beside Lineage and Details, and the timeline is
  a strip that opens with **Open**, 4, or a jump to a sample.
- Narrower, down to the 760 by 560 window minimum: one pane at a time behind
  the Graph, CFG, Lineage and Timeline switch. A request selected on entry
  shows Lineage first.

Dividers resize CFG, Lineage and the timeline: drag, or the arrow keys (Shift
for 50 px), and Home or a double-click resets. Sizes and pane toggles are
remembered per evidence session, at most 16, in the local
`origin-trace.flow-workspace.v1` preference; a store the shell blocks is
ignored.

### Tracked-call timeline

The timeline reads
`GET /api/events?session_id=…&category=vm&type=wasm_dispatch_observation,wasm_indirect_observation,wasm_dispatch_overflow,wasm_indirect_overflow,js_invocation_start,js_invocation_settle,js_invocation_request,gap`
forward from the start of the store, 1,000 records a page, at most 4 pages a
read and 8,000 records held; anything unread is stated, with **Read more**.
It reads again from the start when the session changes and on **Refresh**,
through at least as many records as it holds, so it never undoes **Read
more**. When Flow redraws more than 15 seconds after a complete read, it
continues quietly from where its last page stopped and adds what is new; when
nothing is new it redraws nothing. A partial read waits for **Read more**. A
selection the records still hold stays selected, drawn or not, and keyboard
focus stays on the item it was on.

- One track per invocation, keyed by process and invocation ID, along that
  renderer's `sequence_number` order, never wall-clock time. A run of
  sequence numbers nothing here draws is compressed to a break mark (≈). Its
  tooltip counts the numbers, not records: they can be records of other types
  or numbers that were never stored, and the read cannot tell which.
- A track is named by its invocation (`call #12`); the detail line adds its
  site slot. Saved site labels are not applied: `/api/js-invocation-sites`
  lists what the backend's own launcher armed and names no session, so it
  cannot be tied to the session the timeline reads.
- With the backend's decoded `js_invocation` object, a track has start and
  settle marks, a dotted line while the call is open, a solid span only when
  it settled synchronously (returned or threw without a promise; its samples
  and requests were recorded while it ran), the settle's outcome, value kind
  and length (never content), and the requests started inside it. Without that object, calls are
  grouped from the Wasm records' `js_invocation_id` alone, with no start,
  settle or request marks, and a note says so.
- `br_table` samples are ticks with the selector under each; `call_indirect`
  samples are dots. Samples outside any tracked call (no call, unknown, not
  observed) have their own lane.
- The Requests lane holds requests started inside a call and, dashed, those
  started while some call was open; a chip selects that request.
- Bounds: 64 tracks, 512 samples and 128 requests per renderer, and three rows
  of request chips; the rest are counted where they would be drawn. Several
  renderers are one at a time, behind a renderer picker. A selection past a
  bound, such as a sample J or K stepped to, stays selected: the detail line
  ends with why it is not drawn, and the drawn item nearest it in record order
  keeps the timeline's one tab stop.
- Gaps are never silent. A notice under the banner names the shown
  renderer's `gap` reasons with their counts and what they mean, read from
  each reason's shape in the order the session summary reads it: a sample
  policy filter, a refused malformed record (`limit_or_invalid`), a sampling
  budget named as the evidence banner names it, another budget such as
  `native_js_invocation_budget_incomplete`'s call budget, an unavailable
  stage, missing linkage, code outside Liftoff, else a refusal. It also
  counts the executions `wasm_dispatch_overflow` and `wasm_indirect_overflow`
  say a sample budget refused (identities, and at least the largest omitted
  count) and the queue-drop markers. It names other renderers that have gaps,
  which the renderer picker also marks, and the page counters
  `sequence_gaps` and `queue_drops`, which cover the whole scanned store
  range, every session and type. A Gaps lane marks each record at its
  sequence, and the pane head ends with `gaps`.
- Sample counts read `sample 3 of 16 read`. When the stream refused or lost
  executions they add `more refused here` (an overflow identity at that
  function and offset) or `not every execution`.
- States: loading, empty (with how to track calls), a failed read with Retry, a
  failed refresh that keeps the last records under a banner, partial reads,
  and counts of undecoded, malformed and repeated records.

Picking a sample selects its call, marks its block in the CFG and its card in
the graph, and shows its selector histogram in Lineage.

### Graph selection

The workspace passes `onSelect` and `onFollow` to `createFlowGraphPanel` and
drives the panel through its `select`, `setMark`, `resize` and
`highlightRequest`. A Wasm card
opens its CFG; a sample marks its function's card; Back and Forward reselect
the card a trail entry named. The graph's setters never report back as a
pick, so nothing loops. A pick made through the workspace uses the setter's
answer: a lineage request step lights that request's stack and the card the
graph selects for it becomes the selection, in the same trail entry as the
step, and a card, caller or callee in the Related rail is selected in the
graph and followed like a click on it, with its CFG and a trail entry. What
the graph selects for the host, reported with cause `host` or `replay` (a
queued `select` landing, the stack of the request the app shows, a trail
entry reselected), updates the Related rail and the pane head but is not a
pick. A Related pick of a card the graph has not drawn yet is no pick either:
the graph selects it once drawn and a notice says so. Every setter the
workspace calls is silent, so only the researcher's own picks come back: the
graph's and the block graph view's setters, the timeline's `select`, and the
app's Lineage row selection. The app counts its request changes in
`state.requestRevision`; a change the workspace asked for itself, during its
own pick or while restoring a trail entry, is not an app pick.

## Flow graph

The Flow workspace's **Graph** pane draws every recorded stack of the session
as one graph ([flow graph v1](../../protocol/flow-graph-v1.md)): request, navigation,
async scheduling and walked cookie-write stacks, folded so that each distinct
stack and each retained source is read once. It is observed evidence only; a
call that never reached a recorded request, navigation, task or cookie write is
not drawn, and the status bar says so. The same view is the Graph pane of the
Flow workspace, through the API under [Workspace API](#workspace-api).

### Reading the graph

The view reads top to bottom like a disassembler's CFG: tall and narrow, with
a tall minimap.
- **Realms:** each realm is a full-width band, and the bands are stacked in
  call order. A realm that calls or posts into another sits above it, so an
  iframe sits below its parent; an unrelated out-of-process frame comes after
  the group it is not part of. A call between realms runs down across the band
  boundary.
- **Band label:** each band has a faint tint of its own and names its realm
  in a top corner: the scripts' origin, the realm (execution context), the
  frame its stacks were recorded in and the process. The label takes the
  corner no edge crosses, the right one when both are clear, so it never sits
  on the spine. It stays pinned under the heading while its band is in view,
  and stops short of the minimap.
- **Rows of the graph:** inside a band they are call depth, callers above
  callees. A band entered from another starts at its own top row.
- **Card header:** each card is one function. The header is tinted by the
  card's kind and gives its name, a boxed badge with the number of distinct
  stacks that passed through it, and the kind as a pill (`JS`, `EVAL`, `WASM`,
  `REQUEST`, `NAV`, `COOKIE` or `CHAIN`).
- **Location line:** under the header, the card gives `file:line:column`,
  `VM<id>` for eval code, or `func <index> · module.wasm`.
- **Call rows:** one row per call the function made, in source order, the way
  a block lists its instructions. Each row has:
  - the call site: `line:column`, or `+0x<offset>` in a Wasm module;
  - a mnemonic: `call`, `await`, `postMessage`, `setTimeout`, `rAF`, `request`,
    `navigate` or `cookie`, in its edge's colour;
  - the callee;
  - a note saying what the call crosses: `→ frame.test`, `JS → Wasm`,
    `Wasm → JS`, `into eval` or `via microtask`;
  - how many records walked it.
- **Requests:** a request, navigation or cookie write is a row of each function
  that made it, not a card of its own, unless nothing recorded calls it.
- **Row limit:** a card shows seven rows and counts the rest; Details lists
  them all.
- **Unresolved and cut frames:** an unresolved frame keeps its script ID and
  reason on a dashed card. A card whose earlier async callers were not recorded
  has a dashed stub above it.
- **Recursion:** a recursive call is a small loop on the card's right edge.

### Colour and edges

Colour says what a thing is. Every colour is a custom property in
`flow_graph.css` that aliases an `app.css` token: Rosé Pine Moon in the dark
theme, Dawn and the light app palette in the light one.

| What | Dark | Light |
| --- | --- | --- |
| JavaScript card | foam | Dawn foam tint, pine text |
| Wasm card | iris | Dawn iris tint, code text |
| eval card | gold | Dawn gold tint, amber text |
| Request or navigation card | rose | Dawn rose tint, green text |
| Cookie write card | love | Dawn love tint, red text |
| Chain card | faint, muted text | faint, muted text |
| Call edge and `call` | foam | Dawn foam edge, pine text |
| Await or task edge | gold | amber |
| Crossing edge: a frame change, JavaScript to Wasm or back, a call into eval | love | Dawn love edge, red text |
| Request, navigation or cookie edge | rose | green |
| Frames omitted | faint, dotted | faint, dotted |

- **Hue and ink:** each kind has a hue (`--flow-js` and so on) for its header
  tint, outline, pill and minimap block, and an ink (`--flow-js-ink`) for text
  in that colour. Each edge family has a stroke (`--flow-edge-call`) and a row
  ink (`--flow-ink-call`). Tint strengths are plain numbers
  (`--flow-tint-head` and so on) that the canvas reads as alpha.
- **Contrast:** every ink, and the name, badge and muted text, clears 4.5:1 on
  the card, on its tinted header, on its pill and on a selected or marked row
  in both themes. A hue that would not, such as Moon's pine or Dawn's gold,
  never sets text.
- **Line style:** every v1 edge is observed, so it is solid; only an omitted
  run of frames is dotted. Colour is never the only carrier: a crossing, a task
  kind and a request are written on their rows too.
- **Lit stack:** when a request or a card is selected, the stacks it lights
  glow, with a heavier stroke and a soft shadow of their colour, and their
  cards keep full colour. Cards and edges off them are dimmed: a dimmed card
  keeps its place, its fill fades toward its band, its tint and outline fade,
  and its text turns muted, still at 4.5:1. A match of Find is never dimmed.
  With nothing selected, nothing is dimmed.
- **Selected card:** a 2 px outline, a soft ring and a glow in its kind's
  colour. The selected row has a band and a bar in that colour.

**Routes:**
- Edges leave the caller's bottom and enter the callee's top in orthogonal
  runs with rounded corners, the same shape Triskel's waypoints take. Each edge
  is outlined against the canvas, and its width follows how many records
  walked it.
- A call that skips rows runs straight down between the cards it passes. A
  back edge inside a band runs up the band's right gutter.
- A call into a later band drops straight down when no card is in its way,
  turning once in the gap above the callee's band. Otherwise it runs along the
  gap under the caller's row to the nearer side gutter, which is outside every
  band's cards, down the gutter, and into the callee from the gap above its
  band or above its row.
- A call back up into an earlier band runs up the right gutter.
- No run crosses a card.

**Key** in the status bar explains the edges, the row colours, the kinds, the
card marks, the bands and the limits. It scrolls when the window is short.

### Folding, selection and the request journey

**Folded**, the default, folds runs of pass-through frames inside one realm
into a stacked chain card: one call in, one call out, the same count, no
boundary, no recursion. **Every frame** draws them all. The two form one radio
group. Space, Enter or **Expand chain** opens one chain, and **Fold chain** on
a member closes it again.

Selecting a card lights every stack through it and marks the rows those stacks
took.

**Requests:**
- The **Request** list opens on a placeholder. Requests to the same target
  carry their renderer request ID.
- Choosing a request lights only its stack and selects the row that made it.
- The view fits that stack when it fits legibly, else it shows its top at
  reading size.
- The status bar names the request, the function that made it, the realm, and
  the counts of distinct stacks and cards.
- **Request stack** lights the chosen request again after another selection.

**Hover and menu:**
- Hovering a card, a row or an edge shows its facts beside the card: kind,
  location, realm, call sites, distinct stacks, records, and what it crosses.
- Right-click, the context menu key or Shift+F10 opens the menu, with each
  item's key.
- On a row, the menu offers **Follow call** and **Copy call site**.
- On every card it offers **Open in Sources**, **Expand chain** or **Fold
  chain**, **Go to caller**, **Center on card**, **Show details**, **Copy
  name** and **Copy location**.

**Details** (I) opens a side panel with:
- the location, realm, and script ID or Wasm function index;
- the records and distinct stacks;
- every caller and callee, with the boundary and the call sites;
- the requests the function made.

With nothing selected it lists the realms (each jumps to its band), the
crossings, what was not decoded, and what stacks cannot contain.

**Find** matches names, files, hosts and requested hosts. It says `1 of 3`,
steps with Enter, Shift+Enter or its arrows, and never dims a match.

**Status bar and feedback:**
- The status bar names the selection and the evidence: records, the crossings
  by kind, the layout engine, and any budget or deadline that cut the graph.
- Copy feedback is a toast, so a refresh-failure warning stays until Retry.
- A refresh keeps the selection, the expanded chains, the mark and the view
  wherever the same functions are still in the graph.
- An empty or failed graph asks again on **Refresh** or **Retry**, when the
  view reopens, or when the app has seen more script-started requests; an
  evidence poll never asks again otherwise, and never restarts a read that is
  still running.

### Keyboard and zoom

**Keyboard:**
- Arrows move to the nearest card.
- J and K step through the selected card's calls.
- Enter follows the chosen call. On the card itself it opens the function in
  Sources or expands a chain; a Wasm card goes to the host's `onFollow` when
  there is one.
- Backspace or Alt+Left goes back.
- U goes to the caller that reached the card most often.
- O opens the function in Sources.
- S copies the chosen call site.
- Space expands or folds a chain.
- Escape clears the selection, then closes Details.
- `/` focuses Find.
- `+`, `-` and `0` zoom and fit, and Shift+arrows pan.
- F centers the selection.
- I toggles Details.
- C and L copy the name and location.
- M hides the minimap.
- Letters do the same with Shift. Keys with Command, Control or Option are the
  app's, except Option+Left.
- A key the host claims through `hostKeys` is left to it. The Flow workspace
  claims its own chords: ⇧C, ⇧L and ⇧T show or hide its panes, ⇧⌫ walks its
  trail forward, Z toggles focus mode and 1 to 4 switch panes.

The canvas announces this list through `aria-describedby`.

**Zoom:**
- The first view fits the whole graph when its rows stay legible. A taller or
  wider graph opens at reading size at the top of its first band, with the
  whole width in view when it fits, else centred on the busiest entry of that
  band. It never opens as an unreadable overview; the minimap is the overview.
- Rows show from 85% zoom.
- Below that, cards sketch their rows in their rows' colours and paint their
  names at screen size, and band names sit on plates.
- Below 20% they are boxes filled with their kind's colour, and plain calls
  become hairlines.
- The minimap takes the graph's shape: a tall graph gets a tall column (up to
  440 px, or 55% of the canvas) with bands, cards in their kinds' colours,
  edges in theirs and the view box; a wide one a short strip. Its width
  follows the canvas, from 72 to 170 px. It hides while the whole graph is in
  view, in a short canvas and below 380 px, so a workspace pane keeps it.
- Centring a card keeps it clear of the minimap and of a Details sheet.
- In a canvas narrower than 860 px the tools drop under the heading. In a
  narrow window Details is a sheet over the bottom 40% of the canvas.

### Workspace API

The Flow workspace creates this view as its Graph pane, with the app's `open`
and `available`, and shows or hides it from its own `sync`, which the app
calls with the session, the selected request and the stack count.
`createFlowGraphPanel` takes, besides `host`, `open` and `available`:
- `onSelect(info | null, {cause})`, called whenever the selected card, its
  chosen row or the lit request changes, and with `null` when the selection
  clears. A change to the same card and row is not reported twice. `cause`
  says who changed it:
  - `pick`: the researcher, in the graph (a click, a key, the menu, Details,
    Find, **Request stack**);
  - `host`: the graph acting for the host: the stack of the request `show`
    names, lit on a new request or cleared when `show` names none, a new
    session clearing the selection, a setter called with `silent: false`, or a
    setter called before the graph was drawn, applied once it lands;
  - `replay`: the graph putting back what it had: a refresh keeping the
    selection or the lit request, or a layout redone after the view was
    hidden.
  The Flow workspace records no trail entry for `host` or `replay`.
- `onFollow(info)`, called on Enter or a double-click on a Wasm card. Without
  it a Wasm card opens in Sources, as before. Enter on a call row still
  follows the call.
- `hostKeys(event)`, asked on every key the canvas receives before it acts;
  `true` leaves the key to the host, unhandled. The Flow workspace passes
  its `flowWorkspaceKey`.

`info` is:

| Field | Value |
| --- | --- |
| `key` | `flowGraphNodeKey(node)`; for a chain card, its first member's key |
| `kind` | `javascript`, `eval`, `wasm`, `chain`, `request`, `navigation` or `cookie_write` |
| `name` | the card's name |
| `location` | the full location (URL, line and column, or the module URL and function), or `null` for a chain or an unresolved frame |
| `process_id` | the realm's process, from the node's context (nodes do not carry it) |
| `execution_context_id` | the realm's execution context, from the context, or `null` for an unidentified realm |
| `url` | the script or module URL, or `null` |
| `artifact_id` | the script or module artifact, or `null` |
| `function_index` | the Wasm function index, or `null` |
| `row` | the chosen row as `{index, site, op, target}`, or `null`; `site` is the text the row shows, such as `8:3` or `+0x2f` |
| `request` | the lit request as `{process, request}` while its stack is the highlight, else `null` |
| `callers` | up to eight cards on drawn edges into this one, most stacks first, each `{key, name, kind, note, count}` with `note` the edge kind |
| `callees` | the same for drawn edges out of this card |

`show({session, request, stacks})` shows the view for a session and the
renderer request the app has selected; `stacks`, when given, is how many
captured requests a script started, so an empty graph asks again when it
grows. `hide()` releases the canvas, the minimap and the drawing caches.

The panel returns, besides `show`, `hide` and `focus`, the methods below.
Its setters, `select`, `highlightRequest` and `setMark`, act for the host: a
change they make is never a `pick`. By default they are silent and their
return value is the answer; with `silent: false` the change is also reported
with cause `host`. One called before the graph is
drawn returns `null` and is applied once the graph lands, reported then with
cause `host`, since the call could not answer. After a layout the first of a
queued key, a queued or lit request and the kept card that is in the graph
wins, in that order.
- `select(key, {reveal = true, silent = true} = {})` selects the card that
  holds `key`, any member's key for a chain, and centres it unless `reveal`
  is false. It returns the card's `info`, or `null` when the key is not in
  the graph.
- `highlightRequest(request, {reveal = true, silent = true} = {})` lights the
  stack of the renderer request `{process, request}` and selects the row that
  made it. It returns that card's `info`, or `null` when the request has no
  stack here, which clears the selection.
- `selection()` returns the current `info`, or `null`.
- `resize()` re-measures the stage after the host changed its size, such as
  when a pane opens, closes or is dragged.
- `setMark(mark | null)` marks the card a timeline sample points to, apart
  from the selection: `mark` is `{artifact_id, function_index, offset}`. The
  Wasm card with that module artifact and function index gets a dashed ring in
  the mark colour, and its row whose call site is at module offset `offset`, if
  it shows one, gets the mark's band. IDs may be numbers or strings; `offset`
  may be `null`. It returns whether a card took the mark; `null` clears it.
  The mark survives a refresh and shows on the minimap. It never changes the
  selection.

### Layout

Layout runs in `flow_graph_layout.js` as a Web Worker, through the block
graph's runner, or on the main thread when a shell cannot start one, with the
same engine report either way, on card sizes measured from their text.

**Layered layout:**
- Bands are ordered callers first over the calls between realms: realms that
  call into each other sit together, the busiest connected group first; a
  cycle between realms takes the best ranked one first, and a call back up
  into an earlier band is a back edge.
- Inside each band, cycles are broken by a depth-first walk over the realm's
  own calls, and layers are longest paths, with roots pulled down to their
  first callee. A call from another realm never pushes a card down.
- A band holds at most five cards per layer, more in a large band so it stays
  near square; the rest move down, leaves first. A busy session grows tall,
  not wide.
- An edge longer than one layer gets a waypoint in every layer it passes, up to
  200,000.
- Each band and layer is ordered by its neighbours' mean position over
  alternating sweeps, then placed by a weighted isotonic fit that keeps a single
  chain of calls straight.
- All bands share one width. Each band is shifted sideways inside it so the
  calls between bands run as straight as the cards allow.

**Triskel:** when the backend serves `POST /api/graph-layout`, each realm of 2
to 2,000 cards is then sent to
[Triskel](https://github.com/triskellib/triskel), in band order, at most 64
realms and 8,000 cards per request; a realm past either total keeps the layered
layout and says which total it hit. The layout worker keeps Triskel's last 64
answers by realm, so a new layout of mostly the same realms, such as a chain
folded or a refresh, sends only the realms that changed. A realm takes Triskel's coordinates and waypoints unless Triskel would
draw it more than 1.6 times wider than the layered layout and over 1,400 px,
or more than 1.6 times taller and over 1,600 px taller.
Triskel does not stack a wide fan of calls, and a call tree's breadth would
otherwise run off to the side. The layered layout also stays when Triskel's
answer is missing, too large or the wrong shape. Either way the bands keep the
layered order and are stacked, aligned and routed between the same way. The
status bar says `Triskel layout`, or how many realms it took, and hovering it
gives each other realm's reason.

Six thousand cards lay out in well under a second. The canvas is one bounded
backing store, released with the minimap while the view is hidden, and only
visible bands, cards and edges are drawn. Card text is cut to its card once
per layout, not per frame, and a selection reads per-model path indexes and
per-display edge lists rather than walking every path; cards drop
their lift shadow when more than 160 are in view, and the lit stack drops its
glow past 600 edges. A refresh failure keeps the last graph under a banner.
The `reb://` stored-evidence window has no flow graph route and says so.

## Pane sizes

Drag the shared borders in Traffic, Sources navigator, and Tools Decoder to
resize adjacent panes.
The divider shows an accent on hover or keyboard focus. Tab to a divider and use
the arrow keys along its axis; Shift changes the step from 10 to 50 pixels.
Home or double-click restores that split's default. Escape cancels an active
drag. Traffic saves wide column and narrow row splits separately. Sizes persist as
proportions in the local `origin-trace.layout.v1` preference, independently of evidence and backend state.

Minimum pane sizes keep controls and empty states usable. The Sources toolbar
stays one row (a rename field wraps below it); its narrow details overlay starts below those controls. Saved widths are suspended when the
responsive layout stacks panes or lacks enough space. Returning to a wide window restores them. Handles follow scrolling and
are clipped to the active workspace. `pane_layout.js` owns the shared layout controller;
no captured evidence is modified by resizing.

Captured WASM opens in Hex. **Inspect** shows bounded sections, types, imports,
exports and function disassembly with byte-offset links back to original bytes.
Function indexes include imports. **Find** searches retained Hex text or
offset-bearing inspection rows with an explicit inspection label. Inspection
headings and omission messages are excluded; partial coverage stays visible. Failures
provide **Retry inspection**. Partial coverage and display limits are explicit.
The native shell ships `WasmService.swift` and `OriginTraceWasmInspector`, using
the same Rust provider as HTTP. See [WASM Inspection v1](../../protocol/wasm-inspection-v1.md).

**Map** in the Sources toolbar shows one picture of the whole selected artifact:
a captured script, a Wasm module or a VM bytecode image. **Open map** on a VM
Bytes view opens the same picture for its retained image. Windows follow a
Hilbert curve, so nearby bytes stay nearby on the square. The title line states
the grid and the bytes per cell. **Entropy** colors each window by Shannon
entropy on a 0 to 8 bits per byte scale. **Kind** colors it by the dominant
recorded fact: Wasm section or data segment, string, VM instruction coverage, or
undecoded tail. Hover, or move the focused cell with the arrow keys, to read the
byte range, kind and entropy. A click or Enter opens that byte in Hex or the
Inspect disassembly, and a text script opens at its line. Bytes past what the
existing view holds stay in the map and say so.

A window is marked high-entropy only by the 7.0 bits per byte test stated beside
the map. That mark says nothing about compression or encryption. Windows are
never shorter than 256 bytes, because Shannon entropy over W bytes cannot exceed
log2(W), so small windows make the 0 to 8 scale meaningless. A short artifact
gets a smaller grid instead. See [Artifact map v1](../../protocol/artifact-map-v1.md).

The map costs fixed memory. The backend reads the stored artifact in chunks and
returns one summary of at most 16 KB per mode, whatever the artifact size. The
page keeps two cell arrays and one image for the current artifact only and
releases them when the map closes, the selection changes, Sources is left or the
session changes. A stale request is cancelled. The page keeps no artifact bytes.

## Evidence investigation and metadata packages

Open **Evidence → Inspect observations & artifacts** in the Requests inspector,
or **Evidence** from Flow. The initial view leads with the selected request,
a bounded recorded-observation list and an independently scrolling record inspector.
It separates native request records, explicit same-process parent links, matching
nonzero session/process/navigation/frame context and unlinked retained records.
The compact request summary keeps the missing-parent count and unknown coverage
visible beside the reading panes.
A context match never establishes causation, value flow or request ownership.

The inspector exposes the operation, original bounded inline payload, recorded
outcome, monotonic time and exact artifact reference. API/property markers do not
supply arguments, return values, exceptions or Promise settlement. Observer,
placement, producer and historical build remain unknown. IDs and original hashes
are available in **Provenance & exact identifiers**; they do not crowd every row.
**Coverage & gaps** separates missing parent references, queue markers, sequence
holes, arrival discontinuities, unavailable request records and the retained-window limit without adding
them into a loss total or inventing capture completeness. Numeric holes are counted
from sorted unique session/process IDs, so a later-arriving record can fill one;
absent numbers alone do not prove capture loss. Long request headings ellipsize
with their full displayed text in a tooltip. Coverage opens a bounded, keyboard-
scrollable disclosure above the workspace and never consumes the pane height;
Escape closes it and restores the summary focus. Records remain in retained
order within relationship groups, not a cross-process execution timeline.

The view inspects at most 5,000 events and 500 artifact descriptors, renders 50
observations per page, bounds each parent lookup to 32 links and does not fetch
missing evidence. Search filters existing observations only. Arrow keys, Home and
End move through the displayed order. At 760 px and below, **Observations / Selected
record** switches between full-width panes. Unchanged refreshes preserve inspector
DOM, disclosures, focus and scroll. Eviction explicitly clears the selected record
without silently substituting its neighbor. Selecting a new valid record clears
that selection notice independently of refresh errors. Inspecting a parent
outside the current filter preserves the search/scope draft and clearly labels
the visible parent details as outside it. Empty and failed-refresh states stay
visible; already retained observations remain inspectable after a refresh failure.

**Open captured source** requires a unique session/artifact descriptor, SHA-256,
original byte size and the approved shared investigation adapter. The adapter opens
original Sources passively and preserves shared Back history; URL matches never
substitute. Builds without that adapter show a visible unavailable explanation.
This tab adds no backend read, capture, analysis or execution. Final composed
release acceptance must exercise the working adapter with the Sources ownership
repairs rather than accepting the unavailable standalone state.

**Metadata package** opens the existing selection/export/validation workflow as a
secondary mode. **Return to observations** retains the observation selection and
scroll. Highlighting an observation never selects it for export. Leaving package
mode retires pending package ownership, just as leaving Evidence does.

Choose individual native event identities
(session, process and sequence) or artifact identities (session and artifact).
The selected-request view uses only that request's attached native records;
synthetic gap rows are not export identities. The other
views expose the current retained windows, at most 5,000 events or 500 artifacts,
with 50 candidates per page. They are not an exhaustive store inventory. The
pager stays above the viewport-bounded list. **Limits & privacy** holds the
longer coverage and disclosure explanation without crowding the selection view.

Nothing is selected automatically. Selection spans pages and views, with limits
of 1,024 events and 64 artifacts. **Selected identities** keeps the exact keys
inspectable if their rows leave the window. **Clear selection** removes all keys;
changing the selected request also clears the selection and any prior result.
Refresh does not silently choose a replacement. A missing selected identity
fails export rather than substituting a neighboring record.

**Export selected metadata** explicitly calls the local guarded exporter and
then validates the returned original bytes. It never stops a writer, changes
capture settings, creates a guard for a legacy store, or retries automatically.
An active writer, changed source, unsupported store, failed integrity check or
bounded-scan limit has a visible error. Supported stores must be quiescent under
the existing cooperative leases; see the [package contract](../../protocol/evidence-package-v1.md).

Alternatively, choose a metadata JSON file up to 4 MiB and click **Validate
original bytes**. Duplicate members, invalid UTF-8, BOMs and whitespace reach the
Rust validator unchanged. The UI parses only an accepted document for display.
Validation neither imports evidence nor runs code, fetches references or uploads
data outside the local service. The 15-second UI deadline includes body and file
reads. Response reads retain one buffer (at most 4 MiB for a package, 64 KiB
for a validation result) and reject more than 65,536 transport chunks. Reads yield
every 256 chunks so cancellation/deadline tasks run; cancellation does not wait
for an underlying producer's cleanup. Cancel, Escape, a changed selection/request or leaving Evidence retires
the pending result. An already started bounded server operation may finish.

A valid package is internally consistent, untrusted metadata, not authenticated
evidence. A supplied file's provenance and export-time verification remain
unverified claims. The view separates selected metadata, retained-source scan,
unknown/partial capture, reference resolution and scoped loss observations.
Queue-drop counts and sequence holes are not added into a unique loss total.
Historical builds, capture settings, authorization, observer regime and epochs
remain unknown. API markers do not prove return, throw, WASM trap, reentry or
Promise settlement. Event-time context does not identify the current live page.
Records, references, gaps and issues are paged; captured strings remain text.

No save or clipboard action is automatic. In the browser development UI,
**Download validated package** requests a download of the exact validated bytes;
check the browser's download UI for completion. The native WKWebView has no
reviewed download adapter, so Download is disabled with a visible explanation.
**Copy validated metadata** is an explicit JSON-text clipboard action and reports
clipboard denial without claiming a save. In `reb://` stored-evidence native
mode, export and validation are unavailable; the live native workspace uses the
bundled Rust HTTP backend.

The browser-free contract and DOM-fixture tests run under `make lint` via
`node tools/check-origin-trace-debugger.mjs --field-provenance-only`. These tests
cover byte preservation, identity, bounds, interruption, focus ownership and
explicit saving; they do not establish rendered, native clipboard or macOS
packaging acceptance. Interactive QA must additionally inspect keyboard use,
50-row paging, independent panel scrolling and controls at desktop and narrow
widths, plus Cancel/Escape, Back/reopen, file replacement and late responses.

All native HTTP entry paths, including an explicit loopback `--ui-url` without a
query, normalize to one `native=1` marker. Unrelated encoded/repeated query
parameters are preserved. Stored native loads also carry the marker; ordinary
browser URLs without it remain browser mode. `make app-build` exercises the
actual compiled Swift normalization helper before signing, without starting an
application window. This helper check does not establish native clipboard or
rendered WebKit behavior.

### Sources document ownership and recovery

Opening a file reads its preview only. **Deob** explicitly starts inert static
analysis; entering Sources from another workspace never starts it. Analyzer
responses must match the submitted artifact, its session, SHA-256, source byte
size, intrinsic assumptions and original-source map. SHA-256 is recomputed over
the returned original text. Missing, loading or truncated previews cannot
authenticate analysis. Replacing the preview owner retires pending results.
Changed or closed owners cannot accept a late response, and analyzer text never
replaces the original preview. A failed explicit retry preserves only the last
successful analysis for the same identity. URLs are display/search hints, not
proof of ownership.

Artifact catalog refreshes preserve an exact pending preview owner. Changing
its session, hash or descriptor retires that read. Preview failures and deadlines
show **Retry source**; they do not silently retry during refresh. Preview bodies
reuse the Facts bounded streaming reader in 2 MiB pages: a text preview reads
the whole artifact up to the 16 MiB artifact cap, and a larger one keeps its first
16 MiB, and a notice above the code states the limit in the pretty-printed and
Original views. Binary previews read 2 MiB, and an analyzer
envelope 33 MiB, with at most 65,536 chunks per page. Analyzer deadlines are ten
seconds; a preview has five seconds plus five per page, including SHA-256 work. Cancellation
retires ownership without waiting for a stalled producer's cleanup. Full artifact
previews verify SHA-256 when WebCrypto is available; partial or lossy text is
visibly a preview. Exact byte navigation still belongs to the existing Facts
verified-original reader.

The editor retains at most eight preview owners and 32 Mi UTF-16 units of
preview text across captured files. The selected owner is pinned; older preview
bytes can be evicted while their tab and immutable catalog metadata remain.
**Retry source** or reopening the file loads it again. Closing a file cancels its
preview/Deob reads and releases its preview, Deob and formatting cache entries.
Tab, navigator, Quick Open and retry handlers retain descriptors only; obsolete
empty/retry controls are removed when the editor becomes ready. Hidden UI
closures cannot keep evicted preview or analysis payloads alive. This never
deletes captured evidence. Canvas thumbnails and the existing bounded
Facts/WASM inspectors retain their separate ownership contracts. WASM Hex formats
every retained byte whose text fits in 8 Mi UTF-16 units, about 1.6 MiB of
module bytes. A longer module keeps a labeled prefix, and Find covers that prefix.

Deob retains at most eight documents, 16 MiB of original/derived UTF-16 text and
250,000 map segments and 32 MiB of serialized response data in total. In-page
formatting retains at most eight layouts and 64 Mi UTF-16 units of input and
output text; Oxc layouts at most four (16 pages each in Sources, or one body of at most 4 MiB) and 64 Mi units. The newest layout is kept
even when it alone exceeds its budget. These are explicit text/entry
budgets, not JavaScript heap or process-RSS guarantees. The editor DOM and Facts'
independently verified original also use memory; no duplicate history of source
bytes is introduced.

Unchanged source/representation refreshes keep the editor DOM, scroll, Find
occurrence and focus, including enabled original-source map links in pretty or
derived views.

Cross-workspace callers can pass the investigation-navigation v1 tuple to
`selectArtifact(id, line, {identity})`: `{type:'captured-artifact', session,
artifact, sha256, bytes}`. `sourceArtifactIdentityMatches` advertises this guarded
receiving boundary. Selection returns false before any read when that identity
is stale or the artifact ID is globally ambiguous. When shared investigation
navigation is present, callers should continue using its `openInvestigation`
adapter and bounded Back/Forward trail.

### Compare supplied packages

Evidence still opens on recorded observations. Open **Metadata package**, then
**Compare supplied packages**, to choose two local metadata JSON files and click
**Compare metadata**. File selection alone makes no request. This secondary view
uses the same reviewed local API and bounded reader; it does not export selected
observations, capture more data or save files automatically. The two inputs are
independent of the current observation selection.

Comparison keeps declared metadata differences, scoped references and unknown
capture/observer coverage distinct from raw-byte verification or equivalent
behavior. Failed or malformed replies preserve the last accepted result. Close,
Return to observations, leaving Evidence and a changed request retire pending
ownership while preserving the local file drafts. Ordinary refresh does not
remount the controls, change drafts or rerun a comparison. Starting from Compare
or a paging control moves focus to enabled Cancel while that trigger is disabled.
Completion restores the Compare control only if Cancel still owns focus; newer
focus choices remain untouched. Escape cancels active work; a second Escape closes comparison and returns focus to its explicit entry.
A departing document disposes the owned component; BFCache suspension cancels
work without discarding drafts. Navigation history contains only view metadata,
not file objects, exported keys, comparison buffers or approvals.

Comparison works in browser HTTP and the native application's live HTTP
workspace, including the native=1 entry marker. Stored `reb://` mode has an
explicit unsupported explanation and mounts no comparison file inputs. This
restriction does not apply to the whole native app. macOS runtime and packaged
asset acceptance remain separate checks.

## Float32 comparison

Open Tools → Float32 comparison to inspect exact hexadecimal binary32 words,
base64 bytes, or a selected retained artifact. Declare byte order, channels and
frames; optionally enable a reference. Inspect / compare is explicit. Raw bits,
signed zero, NaN/Infinity counts, input digests, finite deltas/ULP and caller
tolerances remain distinct. Sample pages do not narrow full-buffer metrics.
Edits, cancellation and failures keep the last report visibly stale.

This uses the local Rust backend, including live native sessions. Stored-evidence
native mode displays its limitation. No sample capture, audio graph collection,
platform identity, normalization, spoofing or target execution is added. See
[the versioned contract](../../protocol/float32-comparison-v1.md).

The existing VM findings view now includes an explicit local [execution semantics workflow](../../protocol/vm-semantics-v1.md): bounded trace import, state changes, opcode candidates and hypothesis counterexamples. It preserves existing detection findings and does not claim native guest-opcode capture.

In the VM workflow, opcode support and hypothesis counterexamples link to an
exact retained step. Inspect structured PC, register, stack and sparse-memory
before/after cells; Changes only hides unchanged snapshots. Select a location
to page through its retained occurrences (not inferred reads or writes).
Previous/Next visits retained steps, including across explicitly incomplete gaps.
Raw audits remain collapsed. Unknown null, absent cells and known zero remain
distinct.

An optional second local trace supports a deliberately selected two-step
comparison. Choose each step and press Compare selected steps; there is no
alignment by sequence, PC, opcode or hash. Both exact input-file SHA-256 digests
are separate from supplied artifact-hash claims. A supplied native backend label
does not authenticate capture. Equal snapshots never prove semantic equivalence.
Native canonical fixture traces remain a separate format, with no lossy importer.

Structured state and manual-comparison views show at most 64 location rows per
page, with visible ranges, totals and Previous/Next controls. Opcode groups,
support-step links, validation links and hypothesis mismatch rows also use 64-item pages; location
occurrences use 16. Paging keeps the exact step and selected location; page
controls restore keyboard focus after rerendering. A counterexample link reveals
its first mismatching observed location even when it is on a later page, showing
all locations for that explicit navigation. Raw audits and CLI reports retain
all cells, including the maximum 706 state / 1,218 comparison locations.

### Retained execution workspace

Within VM investigation, **Findings / Execution workspace** switches between two
mounted views. Finding selection, detail scroll and source actions remain in the
Findings view; incoming finding navigation returns there. Identical or failed
analyzer refreshes update the status notice without rebuilding retained findings,
so a poll finishing in another VM mode preserves the same nodes, focus and scroll.
Changed findings, selection and source availability still update the view.
Imported traces never bind themselves to a finding by a supplied ID or hash.

Execution uses the remaining workspace height. At 1,100 px usable width it shows
trace/opcode navigation, a dominant **Retained execution listing**, and the
synchronized selected-step inspector. At 760–1,099 px navigation becomes a
closeable drawer; below 760 px **Listing / State / Evidence** selects one pane.
These thresholds use workspace width, including when the surrounding app changes.
The existing Console remains separate. Occurrences, validation, manual comparison
and complete raw audits open in a contextual area that starts closed.

The workspace has one compact action toolbar and three labeled areas: Navigation,
Execution and State. Paging stays below the listing; provenance and advanced
analysis open on demand. Selected instructions have an accent rail, and changed
snapshot cells have a separate tint plus a literal changed label. These cues do
not infer reads or writes. Full instruction bytes remain unavailable; PC units
remain adapter-defined. The short-height layout scrolls rather than shrinking
the listing or text.

Rows preserve increasing exact sequence IDs, including repeated PCs and explicit
retained gaps. The 64-row pages never choose another step. Literal filtering over
supplied sequence/PC/opcode/operand text and opcode filtering preserve selection;
**Reveal selected step** clears a filter that hides it and returns to its page.
Filtered-out retained observations are labeled separately from missing execution.
With a row focused, Up/Down, Home/End and Page Up/Down select exact matching rows
across pages; Enter inspects that row. **Back to selected row** restores it. No
shortcut runs code, and editor/IME and application history shortcuts are unchanged.

**Instruction**, **Registers**, **Stack** and **Memory** use one selected-step
report. Instruction includes a paged complete snapshot overview; other tabs filter
its exact namespaces. Selected locations remain marked and linked to retained
occurrences. The instruction size is supplied in adapter-defined PC units. Opcode
hex is only the supplied 1–8-byte field, not a verified complete instruction
encoding. Full instruction bytes and operand-byte layout are unavailable; the UI
never reconstructs bytes or treats a PC as a source offset. A fitting candidate
remains **Inferred**, multiple candidates **Ambiguous**, and no fit **Unknown**.

**Provenance and limits** exposes complete supplied identity, coverage and hashes.
The selected-step raw audit now contains the complete shared report, including
instruction size, identity, coverage and all cells, plus the exact input-file
hash and the existing observed-changes view. This is UI audit completeness only;
the trace schema and existing offline CLI envelopes are unchanged.

The existing `node tools/check-vm-semantics.mjs` controller suite also covers the
256-row listing, four pages, large exact IDs, repeated PCs, filter/selection
independence, keyboard navigation, namespaces, durable occurrence-close focus and
100 bounded paging actions. The full Requests rendered gate retains its previous
assertions and adds workspace/Findings/source round trips and 1440/1024/760/600/360
layouts through `tools/check-vm-semantics-ui.mjs`. Controller checks do not establish
rendered or native acceptance; run the rendered gate on a sandbox-capable browser
and inspect the packaged macOS app, including desktop 200% zoom.

### Observed execution path

In the Execution workspace toolbar, **Listing / Path** switches the same retained
execution pane between rows and an observed occurrence graph. The right-hand
State inspector, exact selection, filters and 64-item page remain synchronized.
At narrow widths, choosing Path reveals it inside the existing Listing pane;
Enter opens State, and **Back to selected row** returns to the exact path node.
The tab pair supports Left/Right/Home/End. Nodes support the same Up/Down,
Home/End, Page Up/Down and Enter keys as the listing. Switching views never runs
code or changes the selected sequence.

Each node retains sequence, supplied PC/opcode/operands, evidence references,
and candidate meanings. Repeated PCs remain separate occurrences. Arrows join
only consecutive recorded sequence IDs. Missing execution has an explicit gap;
filters and page boundaries label hidden observations without shortcut edges.
Observed PC movement is separate from unknown branch alternatives. The graph
is not a static CFG, and neither supplied continuity nor matching candidate
semantics establishes completeness, causal dependence or equivalence.
Trace identity remains visible in the path summary; **Provenance and limits**
retains the complete supplied identity, coverage and exact import-file digest.

The bounded shared `observedPath` model and the offline `path` command are
specified in the [VM semantics contract](../../protocol/vm-semantics-v1.md#observed-execution-path).
The UI adds no capture adapter or new production asset. Imported traces from
any admitted backend retain their supplied-provenance limits; owned fixtures
are acceptance data, not a requirement on the investigated VM.

### Static bytecode analysis

In the top-level **VM** tab, **Static bytecode** accepts an independent local
`reb-vm-definition-v1` definition and `reb-vm-bytecode-v1` image. Choose both JSON
files, then **Analyze**. The separate **Owned example** loads authored loop/branch
inputs for an explicit analysis; it is not a capture and does not execute a VM.
Findings, supplied Execution workspace traces/observed Path, and Live owned
fixture keep their existing independent inputs and controls. Active live Stop
and Pause controls remain reachable while static bytecode is visible.

The definition declares literal one- or two-byte opcodes, operand widths,
endianness, register/stack architecture, supported fixed semantic operations and
control-flow targets. The image declares entry byte offsets and up to 64 KiB of
hex bytes. Each JSON file is bounded to 1 MiB. Linear decoding stops explicitly
at an unknown opcode, truncated/invalid instruction or the 4,096-instruction
budget. Undecoded bytes have no synthesized instruction or pseudocode. This is
bounded declared-ISA analysis, not arbitrary-VM recovery or general decompilation.
See [Static VM analysis v1](../../protocol/vm-definition-v1.md) for the exact schema,
supported operations, static-CFG assumptions and offline commands.

The main address listing pages at 64 instructions and retains exact byte ranges.
Select a row to synchronize **Instruction**, instruction-linked **Pseudocode**,
and **Static CFG**. CFG cards show instruction-level nodes, declared directed
edges and explicit unresolved targets; they do not claim recovered basic blocks
or observed execution. Unknown semantics stay unavailable. Declared reachability,
full byte decoding and equal hashes cannot prove runtime behavior, completeness
or equivalence. **Inputs and limits** distinguishes exact JSON-file SHA-256,
canonical definition SHA-256 and decoded-image-byte SHA-256, exposes diagnostics,
and keeps complete raw audit text available in bounded pages.

Literal filtering does not change selection. **Reveal selected** returns to its
exact address; CFG and pseudocode links do the same. With a listing row focused,
Up/Down, Home/End and Page Up/Down navigate matching instructions; Enter opens
details. Detail tabs use Left/Right/Home/End. At less than 760 px of actual
workspace width, **Addresses / Details** switches panes and Escape restores the
selected address. Short and narrow layouts scroll the workspace and preserve
live safety controls. Valid replacement inputs invalidate prior analysis;
rejected imports preserve it, and Clear invalidates pending reads and hashes.
Nothing is fetched, uploaded, run, or bound to findings by a supplied ID.

`node tools/check-vm-static-ui.mjs` runs authored controller/DOM checks. Its
exported rendered flow is part of the integrated browser gate, covering the
16-instruction example, at least 12 visible desktop rows, mode round trips,
responsive focus/scroll and authored live-control coexistence without native
commands. DOM checks are not rendered or packaged-app acceptance; run the browser
gate and inspect the macOS app, including actual desktop 200% zoom.

### Live owned fixture controls

Open **VM tab** without a captured finding. The workspace also offers **Live owned fixture** when the Rust backend has the
bundled `OriginTraceOwnedVmFixture` helper (development binary:
`build/reb-native-vm-fixture`). Create explicitly chooses the fixed register or
stack program and starts paused before instruction one. Run, Pause, Step, Stop,
Reset and Close control that actual native helper. Imported execution traces
remain inert. Controls remain reachable across the VM workspace while a session
exists; leaving VM stops status polling but does not pause execution. Runs expire
after 60 seconds including paused time.

The native state inspector preserves full unsigned 64-bit strings, evidence
classification, initial state, separate live/history selection and recorder loss.
Declared fixture opcode names do not imply recovered semantics for captured VMs.
See [the public contract](../../protocol/owned-vm-debugger-v1.md) for identities,
uncertain outcomes, explicit recovery and API discovery. Stored-evidence native
mode reports these controls unavailable; use a live workspace.

`node tools/check-owned-vm-debugger-ui.mjs` exercises authored response/controller
cases. Its exported rendered flow requires the real backend and helper. Neither
an authored browser harness nor a DOM model substitutes for native end-to-end
acceptance, keyboard/focus QA or packaged-app execution.

### Colored VM controls and compatibility example

VM action, selected and changed-state colors have distinct dark/light palettes
with text and focus contrast checks. Labels and explicit change markers remain
visible. See [the owned compatibility example](../../docs/development/vm-compatibility-demo.md)
for a small source-derived 16bitjs ISA example: generate 14 recorded transitions,
import them through the existing trace input, and inspect call/return, multiply,
memory, stack and a taken branch. It is an owned fixed-program fixture, not the
upstream runtime or unknown-code decompilation.

### Per-build contextual VM analysis

**VM → Contextual build** is an independent offline workspace for supplied
`reb-vm-contextual-definition-v1` definitions and hash-bound
`reb-vm-contextual-image-v1` images. Import both JSON files, optionally import
`reb-vm-contextual-evidence-v1` observations, then choose **Analyze build**.
Every input is strict UTF-8 JSON, at most 1 MiB. The image is at most 64 KiB.
No input is executed, fetched, uploaded, or automatically attached to findings.
**Clear** removes these local inputs; **Remove evidence** returns to declared-only
analysis. Invalid imports preserve previous valid inputs; valid replacements
invalidate the previous report and any pending analysis.

The linked workbench keeps a searchable, paged context listing beside an
inspector with **Instruction**, **Pseudocode**, **Edges**, **Evidence**, and
**Inputs and limits** tabs. Filtering does not change the selected context;
**Reveal selected context** clears the filter and returns to its page.
Resolved declared-edge buttons navigate only to an exact supplied PC/state
context. Inputs collapse after successful analysis and remain available in the
input disclosure. The application Search and Navigation menus target this mode.

Contexts are keyed by byte-offset PC and decoder-state identity. The same opcode
or PC can have different supplied meanings in different states. Missing mappings
or state remain explicit unknowns and stop only that context. Select a context
to see ordered macro operations, abstract pseudocode, declared outgoing edges,
separately labelled supplied observed jumps, and event/capture/run/context
references. All context, jump, reference and diagnostic lists are paged. Unlinked
events remain inspectable under **All supplied event links**; they never borrow
a nearby instruction or invent an adjacency edge. Matching a declared edge does
not verify semantics, evidence authenticity, completeness or equivalence.

The supported contract is declarative, hash-bound per-build decoding and linking
explicit supplied observations. It does not recover vendor VM definitions,
decrypt images, extract keys/seeds, capture a vendor runtime, or bypass anti-debug
checks. Vendor compatibility remains unverified. Existing **Static bytecode**,
**Execution workspace**, **Findings** and **Live owned fixture** workflows remain
independent, with live safety controls preserved when switching modes.

Authored examples (not runtime captures) are in `tools/fixtures/vm-contextual/`:

```sh
node tools/vm-agent.mjs analyze-contextual \
  --definition tools/fixtures/vm-contextual/definition.json \
  --input tools/fixtures/vm-contextual/image.json
node tools/vm-agent.mjs link-contextual \
  --definition tools/fixtures/vm-contextual/definition.json \
  --input tools/fixtures/vm-contextual/image.json \
  --evidence tools/fixtures/vm-contextual/evidence.json
```

The CLI enforces regular non-symlink file bounds, preserves exact source hashes,
and makes no network requests. See [contextual decoding](../../protocol/vm-contextual-v1.md)
and [runtime evidence linking](../../protocol/vm-contextual-evidence-v1.md).
`tools/check-vm-contextual-ui.mjs` covers controller/CLI boundaries; its rendered
flow is part of the existing browser gate, not macOS packaged-app acceptance.

## Owned opcode experiments

VM Lab's exact owned-source workspace offers an explicit isolated native
experiment for declared addition and nonzero branch. Enter fixed inputs 7 and 5
and the expected selected value/next PC, then choose Run isolated native
experiment. Read saved results does not execute. Results show tested inputs and
do not generalize; unsupported inputs are retained without execution. See
[the strict contract](../../protocol/owned-opcode-experiments-v1.md).

## VM analysis packs

**VM → Analysis packs** exposes the same data-only ranking and build-comparison
functions as the offline `origin-trace-vm-pack` CLI. Import local JSON, specify
exact interpreter artifact IDs for comparison, then explicitly apply or compare.
No imported code executes. Invalid schema, stale digests and undeclared source
families are rejected. Cancel, Clear, bounded preview and complete report download
are available. The local Rust HTTP backend is required; native stored-evidence
mode explains how to use the backend or CLI. See the
[versioned pack contract](../../protocol/vm-analysis-pack-v1.md) for limits and
agent-facing `vm_pack_apply`/`vm_pack_compare` routes.

Analysis-pack reports use a searchable, paged listing with a linked row and
provenance inspector. All returned rows remain reachable; the complete report
export preserves the exact backend response. UI filters and paging do not
change the analysis or its original evidence.

## Opcode evidence ledger

The VM **Opcode ledger** workspace imports exact definition JSON and a bounded
ledger JSON locally. The JSON editor exposes all researcher fields, including
handler byte locations, operand notes, source/test citations and unresolved
questions. **Create empty ledger** binds a new draft to the exact definition
source SHA-256 without inventing entries. It refuses to replace nonempty work.
**Validate ledger** uses the same schema and identity checks as the agent's
`opcode-ledger` command. **Export validated ledger JSON** downloads only the
validated ledger, with no extra analysis envelope; edits invalidate export.
In the native shell, **Copy validated ledger JSON** explicitly copies that same
validated document to the clipboard instead. Clipboard refusal leaves the draft
intact and displays an error; native Blob downloads are not attempted.
The searchable coverage listing pages through every declared opcode and links
the selected row to its full researcher entry and definition provenance.
The inspector's edit action opens the existing JSON draft; it does not infer
meaning, generate citations or change test outcomes. Filtering and selection
do not modify the draft or the validated export.
Previous coverage remains visible but is explicitly stale after edits or errors.

Coverage counts declared opcodes, never runtime execution or verified meanings.
Observed/inferred labels, citations and test outcomes remain supplied assertions.
Nothing executes imported code, fetches references, runs tests, promotes VM
semantics, persists inputs automatically or uploads data. Review private data
before exporting. See [ledger v1](../../protocol/vm-opcode-ledger-v1.md).

## VM findings workbench

Effects, Reachability, Host links, session sources, byte attributions and selected
retained samples page through all retained data in groups of 32. The Bytes view
offers every retained snapshot; the compact handler listing keeps its four-sample
preview. A workspace with `sampler-unavailable` says static-only: host links keep
`dispatch-samples-unavailable` and `guest_position` null, and that is the missing
sampler rather than an empty workspace. Session sources lists same-session stored
artifacts only. `chrome://` rows are browser-UI noise. Shared session is
correlation, not loader provenance, and never a guest position.
Operand width zero means unknown, matching the producer contract. Source locations
show exact retained byte ranges without guessing a source line number.

Findings opens retained evidence for the selected finding. The handler listing
sits beside explicit Effects, Bytes, Reachability, Coverage, Unknowns, and
Experiment panels. Panel switching only changes the view; the isolated
experiment still requires its separate explicit run action. Handler highlighting
does not establish an opcode binding or filter the finding-wide analysis.
Execution workspace, Live owned fixture, Static bytecode, and Contextual build
remain separate modes with their existing ownership and execution controls.

The collapsed **Explore a deterministic owned VM example** is an authored
fixture demonstration, not the active capture. Its replay only reveals fixed
fixture transitions. Back/Forward, Go to PC, and arrow/Home/End listing navigation
share the selected instruction with State and Evidence & source. PC units are
instruction indexes; gaps, unknown bytes, unconfirmed effects, and refused
source digests remain explicit. The example never supplies capture provenance.

### Full-page VM navigation check

`node tools/check-vm-full-shell-ui.mjs` loads the shipped page contracts with
authored loopback responses and validates its literal parser and HTTP
contracts without a browser. Rendered VM composition is covered by
`make rendered-ui-check`.

The desktop Findings layout keeps the program navigator, handler listing, and
selected-handler inspector together above a bottom analysis dock. Handler click
or arrow-key selection updates the inspector's exact source range, evidence
class, sample count, retained positions, and notes. These are handler candidates,
not invented guest instructions. The bottom analysis panels remain scoped to
the finding; selecting a handler does not narrow or reclassify them. Detection
scores and artifact identity stay in a compact strip; full detection evidence
and provenance are available in a disclosure beneath the workspace. Narrow or
short windows offer a **Program Trees and handlers** disclosure. Open it to
browse the trees, listing and selected handler in one full-width scroller;
close it to show the analysis dock. Its complete header stays visible in both
states, and switching dock tabs never resizes it. The example disclosure keeps
its own row above the status bar.
Analysis content scrolls within the dock and ends at its wrapping bottom tabs.

### Compact pack and ledger workspaces

Analysis packs and Opcode ledger put local file selection and structured results
first. Expand **Compare two builds** for the comparison workspace inputs and
exact artifact IDs. Pack reports show bounded ranking/comparison tables;
**Inspect raw report JSON** retains the original preview and the export keeps
the complete exact response. Numeric identities too large for exact browser
number display are labeled **See exact JSON**, never silently rounded.

Ledger JSON editors are collapsed beneath coverage. **Create empty ledger**
opens the ledger editor for deliberate authoring. Coverage separates opcode,
evidence status, asserted meaning and supplied test outcome; definition hashes
remain available under **Definition identity**. These presentation changes do
not alter schema checks, research assertions, cancellation or export boundaries.

### Exact request VM candidates

Related VM candidates on a native Traffic row sends the complete request root
(session, process, request ID and sequence). Only findings whose response body
has an acknowledged producer-backed creator chain are shown. Same-frame request
IDs remain labeled correlated context, never exact linkage. Empty or conflicting
chains produce no request findings; a new selection cannot retain findings from
an older request, and late responses cannot replace a newer selection.

Incomplete-root rows remain in Traffic with an explicit unlinked notice.
Use the VM workspace navigation for session-wide analysis. Existing captures
without the new browser artifact-parent event remain unlinked. Generated/runtime
allocating-source artifacts do not gain network ancestry from equal URLs or bytes.
This relation identifies captured source, not executed guest VM instructions.
See [exact request selection](../../protocol/http-api.md#exact-native-traffic-to-vm-selection).
