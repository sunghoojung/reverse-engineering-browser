# Native debugger v1

Status: phase 1 (observe without pausing) and phase 2 (policy) are settled.
Phase 1 is a source candidate with every hook patched; phase 2 is approved and
written into [SAFETY.md](../../SAFETY.md). Phase 3, the pausing debugger, is
specified by [native debugger pause v1](../../protocol/native-debugger-pause-v1.md),
and its two halves are separate changes. The backend half, the contract, the
records, the projection and the interface are implemented and tested. The
browser half is a source candidate on `t3/pausing-debugger-browser`: three
rounds of review each found code in it that does not compile, and its
`BUILD.gn` edits would add those sources to every Brave build from these
inputs whether or not the experiment is on, so it does not merge until a
machine has compiled it with `make brave-probe-check` and run it live. Until
then `get_native_debugger` reports the pausing debugger unsupported and every
action is refused before anything is sent, and the engine and control-path
sections below are a specification read from the pinned sources rather than a
description of shipped code.

## Phase 1: observe without pausing

Implemented by [native debugger observation v1](../../protocol/native-debugger-observation-v1.md).
An agent arms rules on a selected live document with the Console `watch`
command and waits on a filtered `wait_for_events` cursor, whose records carry
`debugger_observation`: the decoded record, its own frame resolved to file,
line and column, and the `get_request_stack` arguments for its stack
([recipe 25](../development/agent-cookbook.md#25-break-on-a-request-a-click-handler-or-a-csp-violation-without-pausing)).
Nothing pauses, no value is read, and records carry identities, kinds and
positions only. Rules see only the armed document's main thread, its
navigation clears them, and they cannot be armed ahead of a page load; every
place that arms a rule or waits on one says so.

| DevTools feature | Phase 1 equivalent |
| --- | --- |
| XHR/fetch breakpoint | `request_watch_match` plus the request's #429 stack |
| Event listener breakpoint | `listener_dispatch` with the listener's script position |
| Timer breakpoints | `timer_observation` scheduled and fired |
| CSP violation breakpoint | `csp_violation` with directive, blocked host and stack |
| Pause on exceptions | `exception_observation` (uncaught, caught, unhandled rejection) |
| DOM breakpoints | `dom_mutation` on up to 4 selected elements |
| Global listeners | Console `listeners` on `window` and `document` |
| Threads | `get_native_debugger` threads: Console documents, out-of-process frames, observed frames and workers that started requests |

### Sources debugger sidebar

**Debugger** in the Sources toolbar opens the sidebar
([Origin Trace guide](../../apps/research-ui/README.md#debugger-sidebar)). It
reads `get_native_debugger` only while open and visible, polling in a live
window and reading once in the stored-evidence window, and never pauses.

- **Threads** is the Threads view. It lists every thread with its kind, origin,
  frame, process and state. An observed frame (the session, renderer and frame
  that observation records carry) scopes Observations and the Sources tree
  exactly; a Console document carries no native frame ID, so it scopes only
  Watch rules.
- **Watch rules** shows what the renderer confirmed armed. Arming and clearing
  go only through the Console's live connection to the document the researcher
  selected and confirmed there, with its `watch` and `unwatch` commands, from
  one form drawn for that document; a form drawn for another document sends
  nothing. `native_debugger_action` has no watch action.
- **Observations** lists the newest records per kind, with their identities,
  says how much of the store they were read from, and opens a record's own
  frame (`get_request_stack` with `observation_sequence`) in Sources, or a
  watched request in Traffic through Traffic's own row selection. Traffic
  marks a watched request on its row and in General, with its rule, and
  links back to this record (`RebDebuggerSidebar.showObservation`).
- **Pausing** states the availability `get_native_debugger` reports and offers
  no control. Phase 3 adds its paused-state sections through the sidebar's
  section registry (`RebDebuggerSidebar.addSection` with `native: 'pausing'`);
  they follow the statement (ids of their own, order 50 and above), which
  names them, and keep every control disabled while the debugger is not
  available or the last read is not ready.

Phase 1 stays useful after phase 3: it records evidence without stopping the
page, and it is the only one of the two that works on workers.

## Phase 2: approved policy

The maintainer approved this work on 2026-11-11. The policy itself is the
paragraph in [SAFETY.md](../../SAFETY.md) under "Observation and experiments",
which replaced the three sentences that said the product cannot pause a page.
It is the authority; this document does not restate it. The two sentences below
record why it reads the way it does.

Quiet mode. `REB_NATIVE_QUIET_MODE` (V8 `--reb-ignore-debugger-statements`,
patch `v8/0000-ignore-page-debugger-statements.patch`) makes
`Runtime_HandleDebuggerStatement` return before `isolate->debug()`, so a page's
own `debugger;` never reaches the inspector and never pauses, with or without
this experiment. Breakpoints the researcher sets are unaffected: V8's
`Debug::Break` path for a set breakpoint does not go through that runtime
function, and that patch's own inspector test
(`test/inspector/debugger/reb-ignore-debugger-statements.js`) asserts exactly
this pair. The packaged app turns quiet mode on by default, so a researcher who
wants a page's `debugger;` to pause must start the session with
`REB_NATIVE_QUIET_MODE=0`. The debugger reports which of the two is in force,
so the difference from DevTools is visible rather than inferred.

Detectability. Pausing changes timing and enables inspector-visible behavior a
page can measure. The debugger does not hide itself from the page, being
undetectable is a non-goal, and the interface says when it is active.

## Phase 3: pausing debugger behind an experiment

### Engine

An in-process `v8_inspector::V8InspectorSession`, connected to Blink's
`MainThreadDebugger` through a local channel. No remote debugging port, no
protocol endpoint, no DevTools frontend. The decision was taken from the
pinned sources in `browser/config/*.rev` (Chromium 151.0.7922.108, V8
`20ad8d00`):

- A raw `v8::debug::DebugDelegate` was rejected. `Debug` holds exactly one
  delegate per isolate (`v8/src/debug/debug.h`, `debug_delegate_`), and
  `V8Debugger::enable()` installs the inspector as that delegate
  (`v8/src/inspector/v8-debugger.cc:107`). Taking the slot would disable the
  inspector for the whole renderer process, including any DevTools the
  researcher opens, and would leave us reimplementing breakpoints, scopes,
  call frames and blackboxing on top of raw `v8::debug`.
- `V8Inspector::connectShared()` (`v8/include/v8-inspector.h`) takes a context
  group id and a channel and returns an independent session, so several
  sessions can share one context group. The inspector was built for this; the
  pinned tree already carries
  `v8/0002-preserve-embedder-pause-reason.patch` for the multiple-session
  case. The channel is a `ManagedChannel`, allocated on the cppgc heap, which
  is the ownership the header asks for: V8 holds a Persistent on it for the
  session's whole life, and it defers destroying a session while a dispatch is
  on the stack, so a plain channel owned by the embedder could be freed while
  V8 still had a response to deliver. Blink's own `DevToolsSession` is a
  `ManagedChannel` for the same reason. The embedder's wrapper detaches the
  channel from its client as it goes, so a late response is dropped instead.
- Blink hands out the inspector: `ThreadDebugger::GetV8Inspector()` is public
  (`third_party/blink/renderer/platform/bindings/thread_debugger.h`), and
  `MainThreadDebugger::ContextGroupId(LocalFrame*)` gives the id for a frame's
  local root.

The session is driven with inspector protocol messages built and read inside
the renderer, because that is the only interface V8 exposes to breakpoints,
call frames, scopes and `Debugger.evaluateOnCallFrame`: `V8InspectorSession`'s
C++ surface stops at `breakProgram`, `resume`, `stepOver` and
`setSkipAllPauses`. Those messages are a renderer-internal detail. Nothing
accepts them from outside the process, none of them crosses the command socket,
and the socket carries fixed binary records instead.

### Timing the contract has to live with

Two consequences of the pinned sources, not choices:

- A step or resume reply says the page resumed and carries no new pause. The
  inspector quits the nested loop from inside that command and `didContinue`
  sends `Debugger.resumed` only after `runMessageLoopOnPause` returns
  (`v8-debugger.cc`), which is after the reply. The pause the page lands on
  next is read from the state.
- The browser holds the lease deadline, because a paused page's own timers do
  not run: its task queues are paused by `WebScopedPagePauser`. The renderer
  can still tell the browser, because `didPause` delivers `Debugger.paused`
  to the channel before `runMessageLoopOnPause`, so that message is written
  while the thread can still write.

### Control path

While a page is paused its main thread is inside a nested loop and cannot
serve ordinary main-thread Mojo, so resume, step and evaluate-on-frame are
served from the renderer IO thread. Each step of that path exists upstream at
the pins:

1. `MainThreadDebugger::runMessageLoopOnPause` calls
   `ClientMessageLoop::Run`, and does nothing at all when no client message
   loop is installed. The only implementation is `ClientMessageLoopAdapter`
   in `third_party/blink/renderer/core/exported/web_dev_tools_agent_impl.cc`,
   a process singleton that `WebDevToolsAgentImpl::AttachSession` creates. A
   pause with no loop installed would simply continue, so Chromium patch 0050
   adds one public entry point that creates that same adapter without a
   DevTools session. The debugger reuses upstream's pause loop, including its
   `WebScopedPagePauser` and its input-event disabler, rather than adding a
   second one.
2. A normal pause runs `message_loop_->Run()`, a nested run loop; an
   instrumentation pause runs `InspectorTaskRunner::ProcessInterruptingTasks()`,
   which serves only inspector tasks. Neither serves a frame-associated
   main-thread Mojo call.
3. `InspectorTaskRunner::AppendTask` posts the task to the frame's inspector
   task runner *and* calls `Isolate::RequestInterrupt`, so whichever comes
   first runs it (`inspector_task_runner.cc`). The frame's runner is
   `TaskType::kInternalInspector`
   (`local_frame.cc`, `LocalFrame::LocalFrame`), whose queue traits are
   unpausable, with upstream's comment saying it must "run on a paused page"
   (`frame_scheduler_impl.cc`). `AppendTaskDontInterrupt` posts without the
   interrupt, which is what upstream uses for the five methods that run
   JavaScript, `Debugger.evaluateOnCallFrame` among them
   (`ShouldInterruptForMethod` in `devtools_session.cc`): an interrupt would
   run script at a point V8 is not prepared for.
4. The receiver itself must already be bound on the IO thread before the
   pause, exactly as `DevToolsSession::IOSession` binds its receiver with the
   IO task runner. The debugger binds once, on attach, while the page is
   running.

So: the backend's command socket is served in the browser process, which calls
a renderer interface bound on the renderer IO thread, which hands each command
to the frame's `InspectorTaskRunner` with the same interrupt rule DevTools
uses. Nothing in that path waits on the paused main thread for a reply it
cannot get.

### Guard rails

- Off by default. `--reb-native-debugger` is never set by the packaged app or
  by `make live`. Without it the renderer creates no agent and no inspector
  session and the browser opens no command socket. This experiment adds no
  probe to a hot path, because V8's own breakpoint machinery does the pausing,
  so the only cost when the switch is absent is one command-line check per
  frame.
- One document. A pause needs an explicit `select_document` naming a Console
  document id, with `confirm_pause`. That id is itself one document
  generation, so a navigation or a move into the back-forward cache retires it
  and clears the authorization, and there is no second identity a client would
  have to guess. Only a new selection changes which document is authorized;
  any other command naming another one is refused with no effect. Selecting
  another document, losing the browser-side connection, or five minutes
  without a command resumes and disarms what was armed. Nothing is remapped
  and no command is retried.
- One document, and the thread it shares. An inspector session belongs to its
  local root's context group and a pause stops that renderer's main thread, so
  every same-process document on it stops with the selected one. What is
  confined is what the debugger acts on and reads: a stop that arrives from
  another document of the group is ended immediately, recorded as such, and
  never read, so no frames, no values and no lease come from it. Confining the
  stop itself is not possible from here; saying what it stops is.
- A visible lease the browser holds. The renderer tells the browser a page
  stopped before the main thread blocks, so the deadline starts at the pause
  rather than when a client first asks. When it runs out the browser resumes
  the page and the lease says it expired, with or without a client; an
  authorization no command has touched for five minutes ends the same way. An
  automated client that stops calling, crashes or closes its socket cannot
  leave a page frozen.
- Bounded, ephemeral values. Scope and object properties, watch results and
  evaluation results are capped per value and per page, held only while the
  pause lasts, and never written to the event store, the artifact store or an
  export.
- Labeled. While a document is selected, the interface, every state read and
  every command result all say "Debugger active (detectable)".

### Features

Line, conditional and logpoint breakpoints; pause on caught and uncaught
exceptions; step over, into and out, and resume; the full call stack to the
project's existing 1,024-frame bound plus async segments; scopes and objects
expanded on demand in pages; and watch expressions on the paused frame.
[Native debugger pause v1](../../protocol/native-debugger-pause-v1.md) owns
the exact shapes, bounds and states.

The DevTools XHR, event listener, DOM and CSP breakpoints are deliberately
not here. `V8InspectorSession::canDispatchMethod` serves Runtime, Debugger,
Profiler, HeapProfiler, Console and Schema; those four are Blink's
DOMDebugger domain, which an inspector session does not dispatch, and the DOM
one is keyed by a DevTools DOM agent node id this contract cannot produce.
Pausing on them needs four new hooks in Blink hot paths, which this machine
cannot compile, so claiming them would mean shipping four commands the
browser answers with MethodNotFound. Phase 1 already records all four without
pausing, and a later phase can add the pausing variants once it can prove
them compiled.

### Surface

`get_native_debugger` reads state and `native_debugger_action` runs one
command, both in `protocol/openapi.json` and both projected by `reb-api mcp`.
Every pausing action controls the browser, so `native_debugger_action` stays
hidden without `--allow-effects`; `get_native_debugger` sends one read command
to the peer when a socket is configured, so it is classified exactly like
`get_live_wasm` and appears from `--permission ask` upward. Nothing is lost at
`read-only`: the phase 1 records are ordinary events, so `get_events` and
`wait_for_events` still return them there.

Values read out of a paused page, and the page-derived names they are keyed
by, go to a model only at Full access. A property name carries a secret as
well as its value, so `x-reb-mcp.paused_values` names both keys and the
projection omits them below `--allow-content` while identifiers, positions
and counts are still returned.

The gate is content admission itself, not the `--omit-content` flag: the raw
flag path, `--allow-effects` with neither content flag, omits them too. At
Full access the in-app agent may send them to its model, but its transcript
file keeps a debugger result without that result body, so no paused value
outlives the pause in a file.

Until a Brave build serves the peer both report `availability: unsupported`,
the way the live Wasm peer does, and invent no frames, scopes or values.

### Interface

The paused state is five sections of the Sources debugger sidebar: Pause,
with the "Debugger active (detectable)" label, the document and its
generation, what quiet mode does, the lease countdown and the step controls;
Breakpoints; Call stack; Scope, read in pages when a scope is opened; and
Watch. They register through the sidebar's section registry, so they exist
only once that sidebar does and they do not touch its phase 1 sections.
`tools/check-debugger-pause-ui.mjs` drives them offline; the rendered
attestation waits for the sidebar to land.

## Acceptance still required

- Phase 1 on a live fixture: wait for the next fetch to `/api/x` and read its
  stack; the next click handler and its position; the next CSP violation; and
  measure that disarmed probes cost one atomic load. The agent half of these
  waits passes on the deterministic fixture records through `reb-api mcp`
  (`an_agent_waits_on_observation_records_and_reads_their_positions` in
  `apps/origin-trace-backend/tests/mcp_stdio.rs`); a Brave build from these
  inputs has to produce the records.
- Phase 3 on an owned fixture, on a Brave built from these inputs: a
  conditional breakpoint, scopes, step and resume; navigation clears
  authorization; a pause nobody asks about is resumed by the browser's own
  deadline; an authorization left idle ends; selecting a second document
  disarms the first; a same-process iframe can be selected; a `debugger;` in a
  sibling frame of the group is ended at once and leaves no lease; detaching
  the selected iframe from inside an evaluation does not crash the renderer;
  and the experiment off leaves no agent and no inspector session created.
- Phase 3 in the packaged app, once the Sources debugger sidebar is merged: a
  rendered test of the paused sections and its screenshots.
- Phase 3's browser half compiled before it merges: `make brave-probe-check`
  on an initialized toolchain, then the live checks listed on its own branch.
  Policy in [SAFETY.md](../../SAFETY.md) describes the pausing commands and
  what an implementation must do; it says so as a specification, and becomes
  a description of this product only when that half lands.
