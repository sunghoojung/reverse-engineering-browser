# Automation Recipes v1

Automation Recipes provides bounded browser-context scripts for the disposable
Experiment BrowserContext. It matches the browser-script workflow pinned from
WireBrowser commit `77e1e48ceb4acaef0356877ee2d09391763613cc`: async page-context
JavaScript, manual execution, page-created execution, before-load execution,
after-load execution, shared variables, and browser-side utility helpers.

The feature does not run on a Baseline target. It does not expose Node.js,
Puppeteer, the filesystem, browser-wide target control, or arbitrary DevTools
commands.

## Recipe library

The investigation-local library contains up to 16 recipes. Each recipe has:

- a stable process-scoped identifier and researcher label;
- one trigger: `manual`, `created`, `before-load`, or `after-load`;
- an enabled flag for automatic triggers; and
- up to 16 KiB of JavaScript source.

Total retained recipe source is capped at 64 KiB. Recipe source is authored by
the researcher, retained in bridge memory across disposable-context recreation,
and erased when the bridge exits. It is not written to the evidence store. A
later reusable-files feature may add explicit disk ownership without changing
this execution contract.

## Permission and target boundary

- Manual execution requires confirmation for each run.
- Automatic triggers remain inert until the researcher explicitly arms them for
  the current disposable context.
- Arming snapshots up to 32 explicitly supplied variables with a 16 KiB total
  limit. Variable values are not returned in public debugger state.
- The current isolated target identifier and experiment session identifier are
  checked before every execution and report.
- Target detach, context disposal, bridge shutdown, cancellation failure,
  timeout, malformed output, or the 64-run automatic ceiling disarms automatic
  execution and removes its before-load script.
- Top-level navigation keeps the library and current armed state so before-load
  and after-load triggers can run. Target detach or reattachment clears the
  variable snapshot and automatic execution state.
- Disarming closes the automatic-run admission gate before protocol cleanup, so
  a queued worker cannot start another recipe during teardown.

## Execution phases

### Manual

One selected recipe runs through `Runtime.evaluate` with `awaitPromise`, a
2-second protocol timeout, breakpoints disabled, and a by-value result. The UI
can cancel the active run because the target is disposable. Cancellation or
timeout terminates page execution and reloads the isolated page so unresolved
promises and queued work cannot survive into a later run.

### Created

When automatic execution is armed, every enabled `created` recipe runs once on
the current disposable page. Arming immediately after context creation provides
the page-created workflow while keeping consent visible.

### Before load

Enabled `before-load` recipes are installed atomically as one
`Page.addScriptToEvaluateOnNewDocument` bundle. The bundle rejects child frames,
runs recipes sequentially in the main-frame page context, and reports bounded
start, log, completion, and failure messages through a session-random
`Runtime.addBinding` name and nonce. A start report arms a 2-second backend
watchdog. The watchdog calls `Runtime.terminateExecution` and disarms automatic
execution if a completion report never arrives, then reloads the isolated page.

Disarming calls `Page.removeScriptToEvaluateOnNewDocument` and
`Runtime.removeBinding`. The stale binding function can remain on an existing
global object per the DevTools protocol, but its random name is no longer
subscribed and all later reports are ignored.

### After load

`Page.loadEventFired` schedules enabled `after-load` recipes on a bounded worker.
Only one recipe executes at a time. One pending trigger batch may be retained;
additional load bursts are counted visibly as dropped automatic work.

## Browser helper surface

Recipes run inside an async function and receive:

- `WB.Browser.Utils.getVar(name)` for the explicitly supplied variable snapshot;
- `WB.Browser.Utils.safeJsonStringify(value)` with circular, BigInt, depth, and
  size handling; and
- `WB.Browser.Utils.iterate(value)` for arrays, typed arrays, sets, maps,
  DOM collections, and own enumerable object properties.

`Utils` aliases `WB.Browser.Utils`, matching the pinned WireBrowser workflow.
The fixed wrapper supplies a bounded console object for `log`, `info`, `warn`,
and `error`. Captured content is inserted into the UI as text.

Serialization traverses own data properties without invoking accessors. It
uses bounded depth and entry counts, handles circular references and BigInt,
and truncates UTF-8 output by byte length. Every run gets a fresh traversal
budget so an earlier log cannot consume the final result's allowance.
Before-load reports that would exceed the binding cap discard their preview and
logs, preserve truncation flags and completion state, and remain valid reports.

## Bounds

| Resource | Limit |
| --- | ---: |
| Recipes | 16 |
| Automatic recipes | 8 |
| Source per recipe | 16 KiB |
| Total recipe source | 64 KiB |
| Variables | 32 |
| Variable snapshot | 16 KiB |
| Execution timeout | 2 seconds |
| Total runs per context | 256 |
| Automatic runs per context | 64 |
| Retained run records | 64 |
| Console entries per run | 32 |
| Console entry | 1 KiB |
| Result preview | 16 KiB |
| Binding report | 8 KiB |
| Pending automatic batches | 1 |

Every run row exposes time, redacted target source, trigger category, outcome,
duration, and experiment, recipe, and run correlation identifiers. Evictions,
dropped trigger batches, cancellation, timeout, malformed reports, and automatic
disarm are visible.

## Performance

Automation Recipes is cold-path debugger control. The inactive state performs
only fixed event-dispatch checks. Recipe evaluation, wrapper construction,
report normalization, logging, and cleanup never enter the C++ event, queue,
probe, transport, protocol ABI, broker, or evidence-storage hot paths.
