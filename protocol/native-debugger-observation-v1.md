# Native debugger observation v1

Status: source candidate. Records and hooks compile against the portable
harnesses here and every patch replays at the pins; patched Brave compilation
and a live run are still required.

Phase 1 of [#434](../docs/product/native-debugger-v1.md): non-pausing probes an
agent "breaks" on by waiting on a filtered `wait_for_events` cursor. Nothing
pauses, no value is read, and no debugger protocol is used.
[SAFETY.md](../SAFETY.md) governs capture.

## Arming

Rules are armed per document through the live native Console connection
(`runtime` command `watch`), pinned to that document's frame and the current
capture configuration. A new `watch` replaces the set; a refused one leaves
nothing armed. Navigation, a new configuration, `unwatch`, or a Console Stop
(which sends `unwatch` first) disarms them. A lost backend connection leaves
them armed until navigation or the configuration ends. Records need an active
capture session; without one the Console replies with an error and arms
nothing. `get_native_debugger` reports the rules the renderer confirmed, the
Console documents, recorded workers and observed frames (`threads`), and the
newest 32 records decoded.

Three limits follow from arming through a live document, and each one makes a
wait time out with nothing missing from the store, so every place that arms a
rule or waits on one states them:

- Only the armed document's main thread matches. Workers, other frames and
  same-process iframes never record, and one document is armed at a time.
- Navigation of that document clears the rules.
- Rules cannot be armed ahead of a page load. What a new page does before its
  rules are armed is not observed.

| Rule | Bound |
| --- | --- |
| `requests`: `url_contains` (1-256 bytes) and optional `method` | 8 |
| `events`: event type names (1-27 bytes, ASCII) | 16 |
| `timers`, `csp`: on or off | - |
| `exceptions`: `uncaught` or `all` | - |
| `dom`: element handle with `attributes`, `subtree`, `removal` | 4 nodes, by Blink `DOMNodeId` |

Each configuration admits at most 1,024 observation records per renderer;
the next refused record leaves one `debugger_observation_budget` gap.

## Reading observations

`get_native_debugger` takes optional filters, read-only like the rest of the
operation: `type` (one of the six below), a thread scope of `session_id`,
`process_id` and `frame_id` together, `before` (a byte cursor from
`observations_query.next_before`) and `limit` (1 to 256). The scope matches the
record envelope exactly. Console documents carry no native frame ID, so the
scope names a `threads.observed` frame: the session, renderer and frame of the
observation records among the newest 2,048 records that are observations or
gaps of any kind, within the newest 64 MiB of the store, at most 64.
`observation_budget_gaps` lists the newest `debugger_observation_budget` gaps
(above) in that scan, at most 16.

A filtered or cursor `get_events` read and every `wait_for_events` put
`debugger_observation` beside the hex payload of each record of types 40 to
45, so an agent "breaks" by waiting on a cursor filtered by `type`. The
unfiltered polling window carries none: the UI reads observations through
`get_native_debugger`, and the decode would grow that window by a third. It is
the object `get_native_debugger` lists, from the same decoder, with
`status: decoded`, plus `site`, `stack_read` and `stack_read_operation`, or
`{status: invalid}` with no field for a record the core refuses.

`site` is the record's own frame resolved as `get_request_stack` resolves a
frame below: script URL, one-based line, UTF-16 column and function name when
the source is retained, else a reason with the raw `script_id` and
`position`. A page's sites are grouped by script, and each script's source is
read and walked once for all of them. Every outcome is kept, at most 4,096:
a resolution that can no longer change for good, and one still waiting
(`source_artifact_missing`, `script_identity_missing`,
`script_identity_outside_scan`) with the artifact manifest bytes its lookups
covered and the request index position it was read at, read again only once
either moved.
The manifest is append-only and is read from where the last read stopped, so
a later read parses only the lines appended since. Identities come from the
request index alone, never from a scan of the store. A page reads at most 4
scripts, newest records first on a backward page and oldest first on a
forward one. Before any kept answer is used, the event store and the
artifact manifest are each checked to be the same file they were read from,
grown or not: the same device and inode, a length no shorter, the same first
4 KiB and the same 4 KiB before the length last read. Any other store or
manifest, and clearing the capture, drops everything kept. A read during
which another read found either one replaced shows and keeps nothing it read.

A resolved site names the artifact it was resolved from. If the same bytes
land again under another artifact ID or URL, the kept site still names the
first, while `get_request_stack` names the newest such artifact; both are
the same source, so the line, column and function name agree.

A page's tag covers the store, the manifest's identity and length, the
request index position and the kept sites, as they were before the read. A
read that resolved sites therefore answers the next read with the same tag
in full once more; whatever lands during a read changes the next tag.

A site that does not resolve keeps its raw frame and a reason. These need a
second look:

| Reason | Why | Recourse |
| --- | --- | --- |
| `source_limit` (deferred) | The page's sites name more than 4 scripts not yet resolved | Read the same cursor again: kept sites cost nothing, so the next 4 scripts are read, and the page's tag never matches a later read while it holds one. A smaller `limit` names fewer scripts. |
| `site_read_failed` (deferred) | The script identities or the artifact manifest could not be read, or the event store or manifest was replaced during the read | Read again |
| `source_artifact_missing` | The script's source is retained but its artifact has not landed, or never will (a lost artifact channel, a rejected frame) | Read again after the artifact lands; nothing is re-read until the manifest grows |
| `script_identity_outside_scan` | The request index has not folded the script's identity yet, or holds its 16,384 identities and keeps no more | Read again once the index moves (it folds 64 MiB a step, and the backend's own schedule refreshes it every 30 seconds); `get_request_stack` with `stack_read` also scans the newest 4,096 identities of the store's newest 64 MiB |

`stack_read` is exactly the arguments of the `get_request_stack` read named by
`stack_read_operation`, passed as it is. That read covers the newest 64 MiB of
the store, so for an older record it answers `outside_scan`; the site on the
event page does not depend on it.

These fields are returned at every MCP permission level, `read-only`
included, where the hex payload is withheld: none is captured content. A
request match carries its rule's slot and method flag, never the URL
substring; a listener's event type equals a name a rule armed; a CSP
violation names a host only, never a path or query; an exception says only
its kind, never a message or value; a DOM mutation names an attribute's local
name, never its value or text; the site carries the script URL, position and
function name that `get_request_stack` returns at the same levels. At
`read-only`, `ask` and `auto` a string longer than 160 characters, such as a
long script URL, is withheld like any other.

`get_request_stack` with `process_id` and `observation_sequence` reads one
record of types 40 to 45 and resolves its stack like a request's. It adds
`observation`: the type, the decoded detail and `site`, the record's own frame
(the listener, the timer callback or the throw site) resolved alone, or null
when the type has none or the frame is zero. A listener for a click usually
runs with no script on the stack, so `site` is the position to open.

## Gate

Hooks check one relaxed atomic bitmask before any other work. Disarmed probes
cost that load only. Stacks use the [#429 walker](native-network-v3.md) and
need `--reb-request-stacks`; without it records carry stack state
`no_script` and a zero digest. Every hook matches only the armed document's
frame on its main thread; workers and other frames never match.

| Hook | Call site |
| --- | --- |
| Request | `ResourceRequestSender::SendAsync`, after the request's stack record (Chromium 0029) |
| Listener | `JSBasedEventListener::Invoke`, main world, before the listener runs (0030) |
| Timer | `DOMTimer` constructor and `DOMTimer::Fired` (0030) |
| CSP | `ExecutionContextCSPDelegate::DispatchViolationEvent`, while the violating script is on the stack (0031) |
| Uncaught and caught | `Isolate::Throw` through the V8 0016 throw observer, installed only while exceptions are watched; the catcher is the debugger's prediction, and Console commands' own throws are skipped |
| Rejection | `PromiseRejectHandlerInMainThread`, for a rejection with no handler at that time; a handler added later does not retract it (0031) |
| DOM | `Element::WillModifyAttribute`, `ContainerNode::InsertNodeVector`, `WillRemoveChild`, `WillRemoveChildren` and `ParserRemoveChild` (0032) |

A removal names the watched node itself, else its nearest watched ancestor
with `subtree`, at most 1,024 levels up. Parser insertions are not recorded,
as in DevTools.

## Common payload

128 bytes, little endian. Bytes 0-79 are the `request_initiator_stack` stack
summary with the same states, flags and validation (offsets 24 and 28 stay
Wasm frames and distinct scripts). Bytes 80-127 are per type; unused bytes are
zero. Stacks are kind 13 `stack` artifacts with capture origin 12, shared by
digest with request stacks; the creator is the first record that named it.

## Types

All are category `runtime` (12) except type 40, which is `network` (9).

| Type | Name | Parent |
| ---: | --- | --- |
| 40 | `request_watch_match` | the `request_initiated` record; `request_id` set |
| 41 | `listener_dispatch` | 0 |
| 42 | `timer_observation` | 0; join phases by timer id |
| 43 | `csp_violation` | 0 |
| 44 | `exception_observation` | 0 |
| 45 | `dom_mutation` | 0 |

`request_watch_match` (80): `u8` rule slot, `u8` flags (bit 0 method matched).

`listener_dispatch` (80): `u8` rule slot, `u8` target kind (1 element,
2 document, 3 window, 4 other node, 5 other target), `u16` node type, 16-byte
listener frame (kind 1 at the function start, a bound function's target, or
zero for an object or native listener; no property is read), `u8` event type
length, 27 bytes event type.

`timer_observation` (80): `u8` phase (1 scheduled, 2 fired), `u8` kind
(1 timeout, 2 interval), `u16` flags (bit 0 string callback), `u32` timer id,
`u32` delay ms (the clamped delay when scheduled, the repeat interval or 0
when fired), 16-byte callback frame.

`csp_violation` (80): `u8` directive (network `CSPDirectiveName` at the
Chromium pin), `u8` disposition (1 enforce, 2 report), `u8` host length,
45 bytes blocked host. Never a path or query; a longer or non-ASCII host is
left out, not cut.

`exception_observation` (80): `u8` kind (1 uncaught, 2 caught by JavaScript,
a promise or an await, 3 rejected with no handler), 16-byte throw site (kind 1,
position inside the function starting at `detail`), zero for a rejection;
the stack summary's innermost frame is then the rejecting site.

`dom_mutation` (80): `u8` kind (1 attribute, 2 subtree, 3 removal), `u8` node
slot, `u16` mutated node type, `u8` attribute name length, 32 bytes attribute
local name, cut at 32 bytes; a non-ASCII name is not recorded. Never
attribute values or text.

## Validation

`tests/debugger_observation_test.cpp` checks layout parity with the overlay,
every state and malformed records; `tools/validate-evidence-store.py` and the
backend decoder (`debugger_observation.rs`) apply the same rules. The
admission harness drives every hook through the real sink and validates each
record against the core.
