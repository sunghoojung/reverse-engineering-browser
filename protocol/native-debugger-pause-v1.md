# Native debugger pause v1

Status: this contract, the backend half and the interface are implemented and
tested. No browser implements the peer, and no browser code is part of the
change that landed this file: the source candidate for a browser half is on
`t3/pausing-debugger-browser` and does not merge until it has been compiled
and run live. Until a Brave build serves the peer, `get_native_debugger`
reports the pausing debugger `unsupported` and every pausing action is
refused before anything is sent. Browser requirements below is what an
implementation has to do; it is the authority for both sides, and the
contract peer in `apps/origin-trace-backend/src/native_debugger_pause.rs` is
read against it exactly as a browser is.

Phase 3 of [#434](../docs/product/native-debugger-v1.md). Phase 1,
[native debugger observation v1](native-debugger-observation-v1.md), keeps
working unchanged: it records without pausing, it is the only one of the two
that covers workers, and it is where the XHR, event listener, DOM mutation
and CSP violation cases live. [SAFETY.md](../SAFETY.md) governs this
experiment.

## What this is not

No remote debugging port is opened and no Chrome DevTools Protocol endpoint
exists. The renderer builds and reads inspector protocol messages in process,
because that is V8's only interface to breakpoints, call frames and scopes;
those messages never cross the socket, and nothing outside the renderer can
send one. The socket below carries fixed binary frames with this contract's
own JSON bodies.

The DevTools XHR, event listener, DOM and CSP breakpoints are not here.
`V8InspectorSession::canDispatchMethod` serves Runtime, Debugger, Profiler,
HeapProfiler, Console and Schema; those four breakpoints are Blink's
DOMDebugger domain, which a session does not dispatch, and the DOM one names
a DevTools DOM agent node id this contract cannot produce. Pausing on them
needs Blink hook points of its own, which a later phase can add once it can
be compiled. Phase 1 records all four without pausing today.

A manually opened DevTools window shares V8's pause state with this
experiment: both attach sessions to the same context group, so a lease here
can resume a pause DevTools is holding and the exception mode is whichever
was set last. Do not open DevTools on the document you are debugging.

A pause is not confined to one document, and this contract does not claim it
is. An inspector session belongs to its local root's context group, and a
pause stops that renderer's main thread, so every same-process document on
it, the parent page and its sibling frames included, stops with the selected
one until the page runs again.

What is confined is narrower than "one document", and these are the exact
limits:

- A breakpoint is set in one script, by script id, so only code of the
  selected document can hit one.
- A stop that did not come from the selected document is not read: no frames,
  no values and no lease are produced for it, and a conforming browser ends
  it as described under Browser requirements. It still stopped the thread
  until that resume takes effect.
- A paused stack is whatever V8 reports for the stopped thread, which is not
  the same as "only the selected document". When a same-process document of
  the group calls into the selected one, its frames are on that stack, and
  their scopes can be read with `get_properties`, because the pause happened
  inside the selected document's code with its callers above it. A researcher
  selecting an iframe can therefore read values from a same-process parent
  that called it. That is the shape of a JavaScript call stack, not a leak
  this contract can close; it is why selection needs confirmation and why
  values are gated on Full access.

## Gate

| Layer | Gate |
| --- | --- |
| Browser | `--reb-native-debugger=<socket path>`, in an implementation that serves this contract. Absent, nothing is created: no agent, no inspector session, no socket. The renderer receives the switch without its value. |
| Backend | `--native-debugger-socket`. Unset, every action is `503` and the state is `availability: unsupported`, `reason: browser_debugger_unsupported`. |
| Document | `select_document` with `confirm_pause`, naming one Console document id. |
| Lease | Every pause holds one, at most 60,000 ms, kept and enforced by the browser. |
| Authorization | Ends after 300,000 ms with no command at all, so a client that goes away leaves nothing armed. |

Cost when off is one command-line check per frame, in
`NativeDebuggerPauseAgent::CreateIfEnabled`. There is nothing else to pay:
this experiment adds no probe to a hot path, because V8's own breakpoint
machinery does the pausing. Without the switch no observer, inspector
session, channel, breakpoint table, lease or socket is created, and nothing
allocates. With the switch and no selected document, the per-frame observer
exists and holds nothing else.

## Authorization

`select_document` names `target_id`, a Console document id: the same identity
`get_native_console` and `get_native_debugger` threads list, and itself one
document generation. A navigation retires that id and the Console hands out a
new one, so there is no second identity for the two sides to keep in step and
no epoch to guess. Every later action repeats the same `target_id`.

A `target_id` the browser no longer has is `stale_document`, whatever this
connection selected, and that guard runs first: only a document that still
exists can be reported `not_authorized`. Looking a target up has no side
effect of its own, so running this guard first costs nothing and tells a
client the more specific thing. Nothing is remapped and nothing is retried.

A navigation in the authorized frame clears the authorization in the browser,
not only in the backend: the renderer disposes its inspector session, drops
every breakpoint it set, and resumes the page if it was paused. The next
state read reports `document: null` and `last_clear: navigated`, answered by
the browser from what the renderer told it rather than by asking a session
that no longer exists.

`navigated` covers every way the authorized document itself goes away: a
navigation, being stored into the back-forward cache, or the frame being
detached. `peer_lost` is for one thing only, the browser process losing its
connection to the renderer that held the session, and `idle` for the
authorization ending on its own. A conforming browser reports them that way
round; reporting `peer_lost` for a document that navigated would tell a
client its connection broke when the page simply moved on.

Being stored into the back-forward cache does not retire the Console document
id: a restored document keeps the id it had, so `select_document` with it can
succeed again. What ends is the authorization, which is why that case is a
`navigated` clear and not a stale id. A client that goes back and wants the
debugger again selects the document again.

One document is authorized at a time, and only `select_document` changes
which. Any other action naming a document that is not the selected one is
refused `not_authorized` before anything is attached or detached, so a stale
or wrong `target_id` cannot take the selection away from the document that
holds it.

Selecting a second document resumes and disarms the first: the browser drops
the agent pipe, which fires the renderer's own disconnect handler, and a
second selection of the same frame is discarded in the renderer before the
new session binds. The reply is the new selection's own state, which a fresh
session answers: nothing paused, no lease, `resumed` false. `last_clear`
describes the authorization being read, so it is null for the document that
replaced another; the replaced one is gone, and the records say it was
replaced. A `release_document` reads `released`, a navigation `navigated`, an
authorization no command touched for the idle bound `idle`, and a lost
browser-side connection `peer_lost`.

## Lease

A lease exists while a pause does. The renderer creates it when the page
stops, before the main thread enters the nested loop, and tells the browser
then: V8 delivers `Debugger.paused` to the channel and only afterwards calls
`runMessageLoopOnPause`, so that message is written while the thread can
still write. The browser starts the deadline from that notification, so a
pause nobody ever asks about still has one.

| End | `lease.state` | Page |
| --- | --- | --- |
| `resume`, or a step | `released` | running |
| `release_lease` | `released` | resumed now, reported |
| 60,000 ms elapsed | `expired` | resumed by the browser, reported |
| navigation, `release_document`, a replacement, the idle bound, or a lost browser-side connection | `released` | running |

The browser holds the deadline and resumes without being asked, so a client
that stops calling, crashes or closes its socket cannot leave a page frozen.
It can still leave the page interrupted for a while: its breakpoints stay
armed until the authorization ends, which is up to 300,000 ms after its last
command, and every hit in that window stops the page again for up to the
60,000 ms lease. "Nothing left armed" is true at the end of the idle bound,
not at the moment the client disappears. A researcher who wants it gone now
sends `release_document`.
`lease.expires_in_ms` is 0 for any state but `active`. A command naming a
lease that is no longer active is `stale_lease`; it is never retried and
never silently applied to a newer pause. A step takes a fresh lease for the
pause it lands on, so stepping does not extend a lease past its deadline.

## Socket

One Unix stream socket, `0600`, in a `0700` directory, owned by the user,
same checks as [live Wasm](live-wasm-instance-v1.md): the backend refuses a
socket that is a symlink, is group or world accessible, or has another owner,
and the browser replaces only a socket this user already owns. One request
and one reply per connection. Read and write deadlines are two seconds, and
a command the browser could not answer inside them does not run afterwards.

That deadline is derived from the moment the connection was accepted, less a
margin for writing the reply, and it is carried to whatever runs the command.
Deriving it from the moment a thread got round to reading the request would
make a queued request look fresh: one accept thread serving a queue would
hand every command a full two seconds measured from its own turn, while the
client gave up long before. A conforming browser stamps the deadline at
accept time and refuses, rather than runs, a command that reaches the session
after it.

Request header, 48 bytes, little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `0x44424552` |
| 4 | 2 | version 1 |
| 6 | 2 | operation |
| 8 | 8 | request id, nonzero |
| 16 | 8 | target id, 0 for `state` |
| 24 | 8 | zero |
| 32 | 8 | lease id, 0 when the action names none |
| 40 | 4 | payload length, at most 16,384 |
| 44 | 4 | zero |

Response header, 32 bytes, little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `0x44424552` |
| 4 | 2 | version 1 |
| 6 | 2 | status |
| 8 | 8 | request id, echoed |
| 16 | 1 | paused: 1 while the page is paused after this command |
| 17 | 1 | zero |
| 18 | 2 | flags: bit 0 the page was resumed by this command |
| 20 | 4 | payload length, at most 1,048,576 |
| 24 | 8 | zero |

| Code | Operation | Code | Operation |
| ---: | --- | ---: | --- |
| 1 | `state` | 8 | `resume` |
| 2 | `select_document` | 9 | `step_over` |
| 3 | `release_document` | 10 | `step_into` |
| 4 | `set_breakpoint` | 11 | `step_out` |
| 5 | `remove_breakpoint` | 12 | `release_lease` |
| 6 | `pause_on_exceptions` | 13 | `evaluate_on_frame` |
| 7 | `pause` | 14 | `get_properties` |

Operations 15 and 16, `expire_lease` and `release_idle`, exist only between
the browser process and the renderer. The socket refuses them, so a client
can neither claim a deadline fired nor keep one from firing.

| Code | Status | Meaning |
| ---: | --- | --- |
| 0 | `ok` | The command ran. |
| 1 | `malformed` | The framing or body was refused before anything ran. |
| 2 | `stale_document` | `target_id` names no current document generation. |
| 3 | `not_authorized` | No document is selected, or a different one is. |
| 4 | `not_paused` | The command needs a pause and there is none. |
| 5 | `stale_lease` | The lease ended; the command was not applied. |
| 6 | `unknown_breakpoint` | No breakpoint of this connection has that id. |
| 7 | `unknown_object` | No object of the current pause has that id. |
| 8 | `limit` | A breakpoint, frame or value bound was reached. |
| 9 | `invalid_input` | A condition, expression or handle the engine refused. |
| 10 | `evaluation_error` | The expression threw or ran out of time; its text is returned. |
| 11 | `unsupported` | This browser does not serve the debugger. |
| 12 | `busy` | A command arrived while this session was dispatching another. Nothing ran. The pinned V8 postpones interrupts inside its `DebugScope`, so this cannot happen during a paused evaluation; the guard stays because failing closed is cheaper than reasoning about every future caller, and no client should expect to see it. |
| 13 | `expired` | The deadline carried into the renderer had already passed, so the command did not run. No client reads this: the socket thread stopped waiting first and reported the outcome unknown. |

The reply body is JSON and always names the action it answers, including
every refusal, so the backend reports the status it was told rather than an
outcome it has to guess. `status`, `paused` and the resumed flag appear in
both the header and the body; the backend refuses a reply whose body
disagrees with its header, or whose action is not the action sent, and
reports the outcome unknown rather than guessing.

A reply to a step or a resume says the page resumed and carries no pause.
The inspector quits the nested loop from inside that command and sends
`Debugger.resumed` only after the loop unwinds, which is after the reply, so
the pause the page lands on next is a later fact read from the state. The
contract peer defers its fixture the same way, so a test sees the same order
a client does.

## State

`GET /api/native-debugger` keeps its phase 1 fields and adds the pausing
ones. With a socket configured the read sends one `state` command, which
never pauses, steps, resumes or renews a lease; that is why it is classified
like `get_live_wasm` rather than as a pure local read, and why it is listed
from `--permission ask` upward. Phase 1 records are events, so `get_events`
and `wait_for_events` still return them at `read-only`.

| Field | Meaning |
| --- | --- |
| `availability` | `available` only when a peer answered. |
| `reason` | `browser_debugger_unsupported` (no socket), `peer_unavailable` (socket, no readable answer), else null. A browser without the experiment opens no socket, so there is no third answer. |
| `policy` | `approved`: the SAFETY.md paragraph is in force. |
| `detectable` | Always true. The page can tell. |
| `active_indication` | The words the interface shows wherever the debugger is on, carried by every state read and every action result so an HTTP or MCP client holds the same notice. Null when no document is authorized. |
| `quiet_mode` | True when the browser ignores the page's own `debugger;`, so those never pause. Null when unsupported. |
| `document` | The authorized selection and whether it is the top frame or a same-process iframe, or null. |
| `last_clear` | Why the authorization being read ended: `navigated`, `released`, `replaced`, `peer_lost`, `idle`, or null. A fresh selection has none, so replacing a document leaves this null on the one that replaced it. |
| `exceptions` | `none`, `uncaught` or `all`. |
| `breakpoints` | At most 64, each with its id, kind, bound position and hit count. A hit is a stop, the only thing either side can observe, so a logpoint's stays zero. |
| `lease` | The current or last lease, with its state, or null. |
| `paused` | True while the page is stopped. |
| `pause` | The current pause: reason, lease, call frames and scopes, or null. |

A paused frame carries `index`, `function_name` (at most 128 bytes),
`script_id`, `line`, `column`, an optional `this_object_id` and its scope
chain of at most 8 scopes. A scope carries `type` (`global`, `local`, `with`,
`closure`, `catch`, `block`, `script`, `eval`, `module`,
`wasm_expression_stack`, or `other` for a type this contract has no word
for), an optional `name` (at most 128 bytes), and `object_id`. A scope past
the live-object bound is left out rather than given an id nothing could read.
A frame names no URL: `script_id` resolves through the `script_identity`
records the session already holds, the way a request stack does, so the same
page string is not stored twice. Frames are numbered from the innermost: at
most 1,024 synchronous frames and 32 async frames, indices 0 to 1,055, the
same bound request stacks use
([native network v3](native-network-v3.md)). `frames_truncated` says the
stack was deeper. Scope contents are not in the state: they are read with
`get_properties`, so a state poll never pulls page values. A deep pause with
long names can still outgrow the reply's 1 MiB bound; the state is then
answered without its call frames and `frames_omitted` says so, rather than
being dropped for being too large. `frames_recorded` still says how many
there are.

## Actions

`POST /api/native-debugger/actions` takes one strict JSON object within the
operation's `x-max-body-bytes`; every field is bounded far tighter, and the
command the backend encodes for the browser is at most 16,384 bytes. OpenAPI
defines the exact required fields per action and rejects unknown fields.
Every action names `target_id`; every action that needs a pause also names
the `lease_id` it believes is active. No action is retried, by this backend
or by the browser.

| Action | Adds | Needs a pause |
| --- | --- | --- |
| `select_document` | `confirm_pause` | no |
| `release_document` | | no |
| `set_breakpoint` | `script_id`, `line`, `column`, optional `condition` or `log_message`, `confirm_pause` | no |
| `remove_breakpoint` | `breakpoint_id` | no |
| `pause_on_exceptions` | `mode`, `confirm_pause` | no |
| `pause` | `confirm_pause` | no |
| `resume`, `step_over`, `step_into`, `step_out`, `release_lease` | `lease_id` | yes |
| `evaluate_on_frame` | `lease_id`, `call_frame_index`, `expression` | yes |
| `get_properties` | `lease_id`, `object_id`, `offset` | yes |

`confirm_pause` is on every action that can make a page stop, including a
logpoint, which does not stop it: one confirmation covers arming the debugger
on that document, and a client cannot arm anything without it. `log_message`
makes a logpoint, which never pauses; it is sent as one literal
`console.log` argument, so nothing in it is interpolated, its text goes to
the page's console as in DevTools, and this contract records nothing from it.

A breakpoint's id is a nonzero decimal string the browser assigns. At most 64
breakpoints exist for one document; the 65th is `limit`. A breakpoint is
`line`, `conditional` or `logpoint`, never two at once. `resolved` is true
once V8 has bound it, and the bound `line` and `column` replace the requested
ones when V8 moves them.

A result object carries the action, the status, `active_indication`,
`paused`, `resumed`, the lease, and `pause`, `breakpoint`, `value` and
`properties`, each null when the action does not produce it. No command
result ever carries a pause: a step cannot know the one it lands on, and the
current one is read from the state. `active_indication` is the same notice
the state read and the interface carry, null when nothing is authorized.

This is the whole of it, and both the browser and the contract peer are read
against this table:

| Action, when it returns `ok` | `resumed` | `paused` | Body it adds |
| --- | --- | --- | --- |
| `select_document`, a different document | false | false | none; the new session holds no lease |
| `select_document`, the one already selected | false | unchanged | none; its lease is unchanged |
| `release_document` | true when it ended a pause | false | none |
| `set_breakpoint` | false | unchanged | `breakpoint` |
| `remove_breakpoint` | false | unchanged | none |
| `pause_on_exceptions` | false | unchanged | none |
| `pause` | false | false; the stop is a later fact read from the state | none |
| `resume`, `step_over`, `step_into`, `step_out` | true | false | none |
| `release_lease` | true | false | none |
| `evaluate_on_frame` | false | true | `value`, with `kind` `error` and `threw` true when the expression failed |
| `get_properties` | false | true | `properties` |

Selecting the document that is already selected is not a replacement. The
authorization, its breakpoints, the pause and its lease all survive, and the
reply describes that session: `paused` and the lease as they stand. Only a
selection that names a different document ends the one it replaces.

A refusal carries the action it refused, the status, and null for all four
bodies. `active_indication`, `paused` and the lease still describe the
session, because a refusal changes nothing about it: a refusal is not a way
to learn that nothing is armed. A refusal the browser process makes before a
command reaches the renderer reports what that process knows, which is
whether a document is authorized and whether it is holding a lease.

## Values

Every value the page can see is bounded and ephemeral:

| Bound | Value |
| --- | --- |
| Value text | 2,048 bytes, `truncated` when cut |
| Properties per page | 64 |
| Properties per object | 4,096 |
| Live object ids per pause | 1,024 |
| Expression | 8,192 bytes |
| Evaluation deadline | 200 ms, then `evaluation_error` with V8's own text |

Values belong to one inspector object group, which is released the moment the
page resumes, and their ids become `unknown_object` then. An accessor is
reported as an accessor: this contract never calls one. Nothing read while
paused is written to the event store, the artifact store, the request index,
a log line or an export. The in-app agent's transcript file is the one place
a tool result is kept, and a result from either debugger operation is written
to it without its result body. That bounds what the tool server put there; it
cannot bound what a model does with what it was shown, and an assistant
message that quotes a value is kept in that transcript like any other
assistant text. At Full access, which is the only level where a value reaches
a model at all, the researcher is the one who decides that. `evaluate_on_frame` runs page JavaScript on a paused
frame, so it can change the page; it carries the `code-execution` and
`live-target-mutation` effects.

Through `reb-api mcp` these values, and the page-derived names they are keyed
by, are returned only with `--allow-content`: a property name or a paused
function name can carry a secret as well as its value.
`x-reb-mcp.paused_values` declares both keys, and below that level each is
omitted like any other captured content while identifiers, positions and
counts are still returned.

## Browser requirements

No browser implements this peer. The source candidate for one lives on
`t3/pausing-debugger-browser`, which does not merge until it has been
compiled and run live; until then `get_native_debugger` reports the pausing
debugger `unsupported` and every action is refused before anything is sent.
This section is what a conforming implementation has to do, so the contract
can be read without it.

The control path is `backend socket -> browser process -> renderer IO thread
-> unpausable renderer task -> paused main thread`. A paused main thread
cannot serve ordinary main-thread Mojo, so the renderer must bind the command
receiver on its IO thread while the page runs, as
`DevToolsSession::IOSession` does, and hand each command to the local root's
`InspectorTaskRunner`, whose task type `FrameScheduler` never pauses.
`AppendTask` interrupts V8 and `AppendTaskDontInterrupt` does not, and this
contract uses the second for exactly the commands that run JavaScript,
`evaluate_on_frame` and `get_properties`, as upstream does. A same-process
iframe is an ordinary selection: the session and the task runner belong to
the local root either way, and the exact document is still pinned by its own
token.

The pause itself is upstream's: `MainThreadDebugger`'s single
`ClientMessageLoop`, which an implementation must make sure exists, because
without it `runMessageLoopOnPause` returns at once and the page keeps
running.

Requirements a conforming implementation meets:

- **Every pause is reported to the browser process**, foreign ones included,
  before the main thread blocks. V8 delivers `Debugger.paused` to the channel
  and only then calls `runMessageLoopOnPause`, so that message can still be
  written. A lease therefore exists for every stop, and the deadline that
  ends it does not depend on a client. The lease a foreign stop takes is one
  no client can use: the selected document is not paused, so every command
  that needs a pause is refused, and the state reports no pause. It exists so
  that the browser's deadline is still the thing that ends the stop if the
  resume below never runs.
- **A foreign stop is ended from inside the loop.** Calling `Debugger.resume`
  during the pause notification is not enough: V8 calls
  `runMessageLoopOnPause` afterwards regardless, and a quit requested before
  that loop starts is lost. The resume has to be posted as an inspector task,
  which runs inside the loop.
- **A deadline operation is never dropped.** `expire_lease` and
  `release_idle` are the browser's own, and an implementation that cannot run
  one at the moment it arrives runs it as soon as it can rather than refusing
  it: refusing would leave a page paused past the deadline that exists to
  prevent exactly that.
- **The inspector session, its channel and the object that reads it outlive
  any dispatch on the stack.** V8 defers destroying a session while a
  dispatch is on the stack, and page script can destroy the frame from inside
  an evaluation, so a reference has to be held for the whole command, and no
  callback may run after the authorization has been cleared once.
- **The identity guards run in the contract's order** and the browser refuses
  a non-selection command naming another document with no side effect at all.
- **Refusals carry what their maker knows**, as the reply-shape table says.
- **Records name the selected document's frame**, taken once at selection,
  because they are written with no script running and a record without a
  frame is invalid.
- **The command deadline is stamped at accept time**, as the socket section
  says.
- **Nothing is created without the switch**: no agent, no observer, no
  inspector session, no breakpoint table, no lease and no socket, and no hot
  path gains a check.

## Events

Types 66 to 69 (category `runtime`, 12) record that the debugger acted,
never what it saw. They exist so a session shows when a page was stopped and
why. Bytes 0 to 79 are the shared stack summary of
[native debugger observation v1](native-debugger-observation-v1.md), with the
same states, so a `debugger_paused` record names the same scripts a request
stack would; a record emitted with no script running carries state
`no_script` and a zero digest. Every record names the selected document's
frame, taken from its frame token at selection rather than from whatever
context happens to be entered: attach, clear and breakpoint records are
written with no script running, and a record without a frame is one the
validator refuses and the broker counts invalid. Bytes 80 to 127 are the tail
below; unused bytes are zero. No record names a parent: the lease id joins a pause to its
resume, which is a stronger join because both records already hold it. No
function name, expression, value, property name, URL or condition is ever in
a record.

`debugger_attached` (80): `u8` phase (1 attach, 2 detach), `u8` clear reason
(0 none, 1 navigated, 2 released, 3 replaced, 4 peer lost, 5 idle), `u32`
breakpoints dropped at offset 4. An attach has reason 0 and drops nothing; a
detach names one of the five reasons.

`debugger_paused` (80): `u8` reason (1 breakpoint, 2 exception, 3 step,
4 pause, 5 the page's own `debugger;` statement; 6 to 9 are reserved for a
later phase and version 1 refuses them), `u8` flags (bit 0 the stack was
deeper than the bound), `u16` frames recorded (at most 1,024), `u16` async
frames (at most 32), `u64` lease id at offset 8, `u32` breakpoint id at
offset 16, which only a breakpoint pause carries. Reason 5 cannot occur while
quiet mode is on.

`debugger_resumed` (80): `u8` end (1 resume, 2 step, 3 release, 4 lease
expired, 5 authorization cleared, 6 a stop in another document of the same
context group that was ended at once, 7 a pause something else continued, a
DevTools window on the same isolate for instance), `u32` paused duration in
milliseconds at offset 4, `u64` lease id at offset 8. End 6 carries a lease
number that exists only to join its two records: the browser is never told of
such a stop, so no deadline starts and no client can name it.

`debugger_breakpoint` (80): `u8` phase (1 set, 2 removed, 3 refused), `u8`
kind (1 line, 2 conditional, 3 logpoint), `u32` script id at offset 4 and
`u32` bound line at offset 8, and `u32` breakpoint id at offset 12, zero
exactly when the phase is refused.

Types 70 to 75 are reserved for this contract and unused in version 1.

## Validation

| Check | Covers |
| --- | --- |
| `apps/origin-trace-backend/src/native_debugger_pause.rs` tests | Framing, header and body agreement, every status the peer can reach, bounds, the real lease deadline, and the contract engine |
| `apps/origin-trace-backend/tests/native_debugger_pause.rs` | The HTTP routes against the contract peer: a conditional breakpoint, scopes read in pages, stepping, resume, navigation retiring a generation, lease expiry, a same-process iframe, an action naming a document that is not the selection, a condition the debugger cannot evaluate, replacing a selection while paused, the whole client going away mid-pause, a peer that stops answering, and the disabled path |
| `apps/origin-trace-backend/tests/mcp_stdio.rs` | The projection, the thirteen actions it offers and the four it deliberately does not, the tools hidden without `--allow-effects`, and that no page value or page-derived name reaches the model below `--allow-content`, including the raw-flag path that sets neither content flag |
| `tools/check-debugger-pause-ui.mjs` | The interface sections against the same shapes |
| `tests/debugger_observation_test.cpp` and `make debugger-observation-wire-check` | Event types 66 to 69 against the core record rules, the offline Python validator and the shipped UI poll model, including every clear and end reason and that a record without a frame is refused by the validator and counted invalid by the broker |
| `tools/check-agent-core.swift` | That a debugger tool result is kept in the in-app agent's transcript without its result body |

A browser half adds its own host harness for the wire header it compiles, on
the branch that carries it; nothing in this list depends on browser code.

`busy` and `expired` are the two statuses the contract peer cannot reach.
`busy` would need a command to arrive inside an inspector dispatch, which the
pinned V8's `DebugScope` prevents by postponing interrupts, and `expired`
needs the socket deadline to pass between the browser sending a command and
the renderer running it, which no client observes because the socket has
already reported the outcome unknown. Everything else in the status table is
exercised.
