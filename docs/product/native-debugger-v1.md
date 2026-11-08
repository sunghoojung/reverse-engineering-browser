# Native debugger v1

Status: Phase 1 is a source candidate. Phases 2 and 3 are a proposal awaiting
maintainer approval; nothing here changes [SAFETY.md](../../SAFETY.md) until
that approval lands.

## Phase 1: observe without pausing

Implemented by [native debugger observation v1](../../protocol/native-debugger-observation-v1.md).
An agent arms rules on a selected live document with the Console `watch`
command and waits on a filtered `wait_for_events` cursor. Nothing pauses, no
value is read, and records carry identities, kinds and positions only.

| DevTools feature | Phase 1 equivalent |
| --- | --- |
| XHR/fetch breakpoint | `request_watch_match` plus the request's #429 stack |
| Event listener breakpoint | `listener_dispatch` with the listener's script position |
| Timer breakpoints | `timer_observation` scheduled and fired |
| CSP violation breakpoint | `csp_violation` with directive, blocked host and stack |
| Pause on exceptions | `exception_observation` (uncaught, caught, unhandled rejection) |
| DOM breakpoints | `dom_mutation` on up to 4 selected elements |
| Global listeners | Console `listeners` on `window` and `document` |
| Threads | `get_native_debugger` threads: Console targets and workers |

## Phase 2: proposed policy (for maintainer approval)

Proposed replacement for the `SAFETY.md` sentences "Origin Trace has no Chrome
DevTools Protocol path" and "The console cannot set breakpoints, step, or
inspect paused frames":

> Origin Trace has no Chrome DevTools Protocol path and no remote debugging
> port. A pausing native debugger exists only behind the
> `--reb-native-debugger` experiment, off by default and never set by the
> packaged app. It attaches an in-process inspector session to one explicitly
> selected and confirmed live document, pinned to its document generation;
> navigation clears the authorization. Paused values are bounded, ephemeral and
> never added to evidence, logged or exported. Every pause holds a visible lease
> of at most 60 seconds; an expired lease resumes the page and says so. Commands
> are never retried. The page can detect an active debugger, and the UI labels it
> "Debugger active (detectable)". Without the experiment the Console still cannot
> set breakpoints, step, or inspect paused frames.

Quiet mode: `REB_NATIVE_QUIET_MODE` keeps ignoring page `debugger;` statements.
The experiment pauses only at breakpoints the researcher set, never at a page's
own `debugger;`.

Detectability: pausing changes timing and enables inspector-visible behavior a
page can measure. Being undetectable is a non-goal.

## Phase 3: pausing debugger behind an experiment

Engine: an in-process `V8InspectorSession` on Blink's `MainThreadDebugger` with
a local channel. A raw `v8::debug::DebugDelegate` was rejected: V8 allows one
delegate per isolate, and the inspector already owns it.

Control path: a pause runs a nested loop that blocks main-thread Mojo, so
resume, step and evaluate-on-frame are served from the renderer IO thread into
the paused loop.

API: `get_native_debugger` (read only) and `native_debugger_action` in
`protocol/openapi.json`, projected by `reb-api mcp`. Every action, including
`release_lease`, controls the browser, so `native_debugger_action` stays
hidden without `--allow-effects`. Until a
Brave build serves the peer, both report `availability: unsupported`, the way
the live Wasm peer does, and invent no frames, scopes or values.

## Acceptance still required

- Phase 1 on a live fixture: wait for the next fetch to `/api/x` and read its
  stack; the next click handler and its position; the next CSP violation; and
  measure that disarmed probes cost one atomic load.
- Phase 3 after approval, on an owned fixture: a conditional breakpoint, scopes,
  step and resume; navigation clears authorization; an expired lease resumes the
  page visibly.
