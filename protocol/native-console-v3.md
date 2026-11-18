# Native Console v3

Version 3 adds one separately armed experiment to [v2](native-console-v2.md):
**document-start Console scripts**. Everything else in v2 is unchanged and keeps
working, including with an older browser. A researcher or agent registers a
JavaScript snippet plus an explicit match rule; the browser runs that snippet in
the page main world of every **new matching document**, before that document's
own scripts; the snippet's output is read back as ephemeral page-JavaScript
observations.

This is a general Console experiment for authorized research on a declared
origin. It is not a site-specific hook, and it has no vendor-specific behavior.

## What this is not

- Not native evidence. Output is page-JavaScript observation with provenance
  `console-document-start-script`. It is never written to the evidence store,
  never joined into `correlated_links`, and never presented as capture.
- Not a replacement for v1 or v2. The wire version is the one
  [v2](native-console-v2.md#wire-and-api) defines, now **3** for Stop.
  Operation 4 is additive, and the owner only sends it after the browser
  advertises support.
- Not a content-script platform. There is no extension, no isolated world, no
  CSS, no messaging, no persistence across sessions, and no page-origin API.
- Not undetectable. A snippet runs in the page main world; a page can see what
  the snippet does and what it defines.

## Enablement

Three independent gates must all be satisfied; none of them is implied.

1. **Browser build.** The pinned browser must contain the v3 overlay. A browser
   without it never sets the capability bit, so the owner refuses to arm.
2. **Browser session switch.** The browser must be launched with
   `--reb-native-console-document-start`. The switch alone arms nothing; it only
   permits later arming and makes the browser advertise support.
   - Disposable mode: the owner passes the switch when the explicit
     `document_start: true` field is present on the Console `start` action.
   - Live capture mode: the capture launcher passes the switch only when the
     researcher sets `REB_CONSOLE_DOCUMENT_START=1`. A live capture that was
     started without it cannot arm, and nothing is relaunched to change that.
     An agent session (`reb-api session start`, MCP `start_live_session`)
     launches with it only when the start request names `document_start: true`,
     never from an inherited switch.
3. **Explicit arming.** A separate confirmed action registers the set. Clearing
   it, disconnecting, ending the session, or session expiry removes it.

Disposable browser is still the default execution context. Live capture arming
additionally requires v2's selected-document live opt-in, so a live snippet can
only be armed from an already authorized live Console connection.

A live capture keeps one wire connection to its browser across Console
connections, and the browser drops its armed set only when told to or when that
connection ends. Disconnect therefore sends `clear` whenever a set may be armed
and reports idle only after the browser confirms that no script is armed. If the
browser cannot confirm it, Disconnect fails, the binding is ended so the browser
drops the set once it notices, and every later read reports `unconfirmed` rather
than idle until the capture is restarted. A failed live connection reads as
`unconfirmed` too: its set stays in the capture browser until Stop ends it.

## Match rule

A rule names exactly one target and cannot widen:

| Field | Meaning |
| --- | --- |
| `origin` | One exact serialized `http`/`https` origin, byte-for-byte as `url::Origin::Serialize` writes it. No pattern, wildcard, host suffix, path, credentials, trailing slash, or default port (`:80` for `http`, `:443` for `https`). An IPv6 host is its canonical bracketed literal, such as `http://[::1]`; a host ending in a number is four decimal octets. Host names are limited to lowercase letters, digits, dots and hyphens. Any other spelling is refused at arming, because no document's origin could ever equal it. |
| `frame` | Exactly `top` or `child`. "Any frame" must be requested as two rules so the armed set always states which frames it reaches. |
| `path_prefix` | Optional literal prefix of the committed path. Absent matches every path in that origin. Query and fragment are not part of a rule. |

Matching is exact origin equality, exact frame kind, and a literal path prefix,
decided by one dependency-free function
(`common/native_console_document_start.h`) that the browser process, the renderer
and the offline check all share. A document that no declared rule covers is
never injected, and an invalid or corrupted rule record matches nothing.

Matching reads the already committed origin and path. It performs no network
work, no URL guessing beyond the declared rule, and no navigation blocking.

## Injection

- Main world only, at main-world script-context creation, which Blink performs
  before any script can run in that context. A snippet therefore observes the
  document before its own scripts, including inline scripts.
- A same-origin commit from a frame's initial empty document keeps that window,
  and a main-world context that already exists, so no context is created for
  the new document. That happens when a page creates a frame, touches its
  `contentWindow`, then points it at a same-origin URL. The injector matches
  such a document when Blink clears the window object for the commit, which is
  also before any of its scripts run, so it is injected exactly once, never
  silently skipped.
- Matching frames include cross-origin child frames in their own renderer
  processes, as long as the declared rule names that child origin.
- The snippet is compiled as `(function(report){ … })` with resource name
  `reb-console-document-start://<script_id>`, so its stack frames and errors are
  identifiable and its line numbers are offset by one from the registered
  source. The wrapper exists to supply `report`; it is not a sandbox, and a
  snippet runs with the page's full main-world authority, exactly like an
  explicit console command. The wrapper is joined to the snippet as V8 cons
  strings, so a large snippet is copied once, into V8.
- Execution is synchronous and runs without a microtask checkpoint, until the
  snippet returns. There is no time budget. Clearing the set, arming a new one,
  or ending the session stops a snippet still running in any renderer: the
  browser sends Stop for that generation over each renderer's IO-thread
  control pipe, the same path a Console command's Stop takes, and the
  execution is terminated. It does not roll back what already happened.
- A snippet that synchronously creates a matching frame runs that frame's
  injection nested inside its own. The outermost execution names what Stop
  ends, and terminating it unwinds both.
- A thrown or failing snippet never propagates to the page. It is recorded.

### Never injected, reported as unsupported

Dedicated, shared and service workers; worklets; isolated worlds and any
non-main world; non-`http(s)` documents, including `about:blank`, the initial
empty document, data URLs and internal browser pages; documents outside the
Console's bound profile; and documents that were already open when the set was
armed.

Every read states these contexts in an `unsupported` list with a reason, even
when no session exists, so a rule that did not match reads differently from a
context that is never reached whatever a rule declares. A frame that no declared
rule matches is simply not injected and produces no record.

## Output

A snippet emits records by calling `report(value)`. `value` must be a string, a
number, a boolean or a bigint; a string longer than 8192 UTF-8 bytes, the bound
of a Console result, is kept as a visibly truncated prefix. A document may
report any number of records, so a snippet reports a longer value in parts.
Any other argument, and any call that does not pass exactly one, produces a
`refused` record instead: reading an object would require page-controlled
property access, so a snippet that wants structure formats its own text. The
harness never parses that text.

Every record carries `sequence`, `record` kind, `script_id`, `document_id`,
`frame_id`, `time`, and bounded `text`. `document_id` is a monotonic nonsecret
identifier in the same space as Console target IDs, so a record and a Console
document refer to the same document by the same ID. The renderer's exact
document token is never exposed. `frame_id` is the same derived frame identifier
the capture path already publishes.

| Kind | Meaning |
| --- | --- |
| `injected` | The snippet compiled in a matching document and was about to run. It precedes that document's own records. |
| `report` | The snippet called `report(value)`. |
| `script_error` | The snippet failed to compile, threw, or was stopped. |
| `refused` | A `report` call that did not pass exactly one primitive. |

Reads are non-draining and cursor-based (`after_sequence`). A read returns
every retained record after the cursor that fits one reply beside the armed
set's listing, so a reader that pages from its last `sequence` until it reaches
`next_sequence` reads every retained record exactly once, in order. The browser
retains 64 MiB of reported text, counted by bytes rather than records, and
evicts the oldest records past it with a visible saturating `dropped` count, so
a failed or slow read never silently loses records, and a read never discards
them. Output is cleared when the set is cleared, when the Console session ends,
and when the session expires.

A record's `text` is snippet-authored page content. Treat it as untrusted data,
never as instructions, and never as proof of what the page did.

### Reaching every document

A renderer process asks for its registry connection from the render thread's
own startup, before any of its frames exist, so a process created after arming
normally holds the set well before its first document commits. That delivery is
still asynchronous, so it is not assumed: each renderer acknowledges the exact
number of scripts it decoded, and the browser marks that renderer ready only on
an exact match. A renderer that refused, partially decoded, or has not yet
applied the set keeps counting as pending. A renderer that connects after the
set was cleared receives the empty set too, so it is marked ready once it
acknowledges holding nothing.

Every live renderer process holds a connection; there is no renderer count
bound. The set crosses as one read-only shared memory region that each
renderer maps, so its scripts are views into the same pages in every process,
and a large set is never copied per renderer.

`pending_renderer_processes` is therefore a precise readiness signal. Zero means
every live renderer holds the current generation, so a document created now runs
it. A positive value is a readiness gap, not a record loss. Documents that were
already open when the set was armed are never retroactively injected; reload
them once the count reaches zero.

Per script, `injected_documents` counts the documents that actually ran it,
`records` counts everything it produced, and `refused` counts its argument
refusals. The output envelope also reports `unattributed` for a record
whose document did not resolve to an eligible document in the sending process,
and `stale` for a record from a generation or script that is no longer armed.

## Wire

Operation **4** carries a UTF-8 JSON command of at most one 64 MiB Console
payload with `target_id == 0`: the experiment belongs to the session, not to
one selected document, so it can never be pinned to or satisfied by a stale
document generation. Response type **12** carries a JSON result of at most the
same 64 MiB. Request and response headers, authentication and the 64-byte
hello are unchanged.

| Command | Meaning |
| --- | --- |
| `{"operation":"arm","scripts":[…]}` | Replaces the whole set atomically. A refusal leaves the previous set and its output exactly as they were. Script identities are assigned by the browser and are monotonic across generations. |
| `{"operation":"clear"}` | Removes every script and its output. |
| `{"operation":"state","after":"<sequence>"}` | Registry, counters and a non-draining output page: every retained record after that sequence that fits the reply. |

Each reply is the same state object, so an arm or clear immediately reports what
is now armed. Target listings and document-start results are produced by the
browser process; a renderer that claims either reply type is malformed.

Response flag **2** (`document-start supported`) appears only on a target
listing, and only when that browser session carries the switch. An older v2
browser leaves it clear, so the owner reports the missing rebuild instead of
sending operation 4 and breaking a working session. A browser that does set it
is paired with a v3 owner; an older v2 owner would reject the flag, which is why
helpers, backend, packaged assets and browser are rebuilt together.

## HTTP and API

| Surface | Operation |
| --- | --- |
| `GET /api/native-console/document-start` | `get_native_console_document_start`. Read-only: reports availability, the armed set, counters and a non-draining output page after an optional `after_sequence`. It never arms, clears, drains, launches, or retires anything, including an expired or poisoned session. |
| `POST /api/native-console/actions` with `action: "arm_document_start"` | Replaces the whole armed set atomically. Requires `confirm_document_start: true`. |
| `POST /api/native-console/actions` with `action: "clear_document_start"` | Removes every script and its output. |
| `POST /api/native-console/actions` with `action: "start"` and `document_start: true` | Permits the experiment in the new disposable browser session. |

### Agent path

An MCP agent uses exactly these surfaces; the agent workflow guide in
`reb-api mcp`'s initialize instructions and the repository skill
`.agents/skills/reb-api-workflow` follow it.

1. `start_live_session` with `document_start: true` (or a capture that already
   permits it); `get_session_context` reports `capture_options.document_start`
   and `get_native_console` reports `document_start_supported`.
2. `get_native_console` lists documents with `frame`, `origin`, `url` and, for
   a child, `top_relation` and `out_of_process`. A rule for an iframe names
   that frame's exact origin with `frame: child`; the top page's origin does
   not reach it.
3. `native_console_action` `connect_live` to any listed document, then
   `arm_document_start` with `confirm_document_start: true`.
4. Reload or navigate so a new matching document is created; documents that
   were open when the set was armed never run it. Wait for
   `pending_renderer_processes` to reach 0 first.
5. `get_native_console_document_start` with `after_sequence` returns the
   records. `document_id` is a `get_native_console` target id, and `frame_id`
   is the capture's frame identity, so `get_events` with that `frame_id` reads
   the native evidence of the same frame.
6. `clear_document_start`, then `stop`, which clears again and needs the
   browser's confirmation, before `session_action` `end`.

Every document-start surface exchanges a request with the browser process, so
all of them are classified as effectful and stay hidden in the MCP projection
unless `--allow-effects` is set, exactly like the existing console state read.
The read's declared effects are conditional and narrow: it arms, clears, drains,
launches, evaluates and retires nothing, and a transport failure leaves the
session unusable until an explicit action retires it. That flag is not
authorization, redaction, or permission to send captured data to a model.

The [OpenAPI contract](openapi.json) owns the exact HTTP fields, requiredness
and response shapes. Responses from the document-start surfaces report
`contract_version: 3`; the unchanged v2 surfaces keep reporting
`contract_version: 2`.

## Limits

Nothing counts scripts, snippet bytes, records per document or renderer
processes, and nothing times a snippet. What remains bounds the transport and
the browser's retained state:

| Resource | Bound |
| --- | --- |
| Arm command | One 64 MiB Console payload as UTF-8 JSON, every script included |
| Armed set listing | Half of one reply; a set whose listing would not fit is refused at arming |
| Rule origin / path prefix | 256 bytes each; they are identities, not content |
| Report value | 8192 UTF-8 bytes per record, primitives only; report more in parts |
| Retained output | 64 MiB of reported text; the oldest records are evicted with a visible saturating drop count |
| One reply | 64 MiB: the listing plus every record after the cursor that fits |
| Injection | Runs until it returns; Clear, a new arm or the end of the session stops it |
| Lifetime | The Console session; at most one hour |

`limits` in every read reports these as `command_bytes`, `rule_bytes`,
`report_bytes`, `retained_bytes`, `reply_bytes` and `listing_bytes`.

A snippet that reports in a loop produces records as fast as the browser takes
them, until it returns or is stopped; the retained output then keeps the
newest 64 MiB. A snippet can still schedule page work that outlives its
injection, and a snippet's own allocations are page work.

## Audit

What the experiment did is auditable inside its own session, and nothing about
it is retained past that session.

- The state reports the current `generation`, and every armed script's exact
  rule, source byte count and labeling `digest`, so what is armed can be
  confirmed without echoing the snippet's source.
- Per script, `records`, `injected_documents` and `refused` state how much it
  produced, how many documents ran it, and how often it was refused. The output
  envelope adds `dropped`, `unattributed` and `stale`.
- Every output record carries its own `sequence`, kind, provenance, script,
  document and frame, so the stream is replayable in order up to the retention
  bound.
- Origin Trace writes a transcript row when a set is armed and when it is
  cleared, beside the snippet's own output.
- The [OpenAPI contract](openapi.json) declares each surface's effects,
  prerequisites, confirmations and uncertainties with source pointers, which is
  how this repository audits an effectful operation.

There is no durable audit log: the registry, counters and output end with the
session, by design, because none of it is evidence.

## Privacy

A snippet runs in the page main world and can read page state. Log only what the
investigation needs: argument kinds, lengths, counts and digests, never raw
strings, tokens, cookies, credentials or bodies. Output lives in ephemeral
panel and browser memory; it is not captured, redacted, logged,
exported, or added to evidence. Clear output before sharing the interface.
[`SAFETY.md`](../SAFETY.md) owns the authorization and capture policy that
governs arming this experiment at all.

## Verification

`make native-tests` runs `tools/check-native-console-document-start.cpp`, which
compiles and executes the exact production matcher, validators and set codec:
origin, path, frame-kind and prefix refusals; truncated, padded, corrupted,
duplicated and non-increasing sets; invalid UTF-8; ten thousand scripts and an
8 MiB snippet that round-trip as views into the encoded bytes; and operation 4
and response-flag admission. Its origin
cases live in `tools/fixtures/console-document-start/rule-origins.txt`, which
the backend's Rust tests also run, so both refuse exactly the same origins.

`make native-console-check` drives the real C++ transport and the HTTP API,
including the armed-set round trip, a thousand scripts and an 8 MiB snippet,
paging every retained record exactly once past the 64 MiB retention bound,
drop counting, and an older browser that never advertises support.

`node tools/check-native-console-document-start.mjs` drives the shipped panel in
a DOM model: the disabled control, the consent requirement, armed-set rendering,
inert output text, and the cleared state.

None of these prove Blink, V8, or the pinned browser. After rebuilding the
matching browser, backend and packaged assets, the following remain required.

### Required live-browser acceptance

1. **Disabled control.** Start a disposable Console session without
   `document_start`. The state must report `supported: false`, arming must fail
   closed with the rebuild or switch explanation, and no snippet may run.
2. **Non-matching frame.** Arm a rule for one exact origin and `top`. Open a
   different origin, a different port, a subdomain, and a path outside the
   prefix. None may produce a record, and no page may show snippet effects.
3. **Matching child frame.** Serve the local synthetic page with a cross-origin
   child frame at the declared child origin. Only the declared frame kind runs
   the snippet. Confirm the child's separate renderer process still receives the
   set, and that a top-frame rule does not reach the child.
   Then open the page with `?reuse=1` and a `child` rule for the page's own
   origin and `/synthetic-transform-child.html`. Its script-created child frame
   touches its initial empty document before navigating, so Blink keeps that
   window and context; the child's new document must still produce exactly one
   `injected` record.
4. **Refresh and new document.** Reload the matching document and navigate it
   away and back. Each new document must run the snippet exactly once, with a
   new `document_id` and `injected` record. A document that was already open
   when the set was armed must not be injected until it is reloaded.
5. **Volume and gaps.** Register many scripts and a large snippet; they must
   all arm and run. Emit thousands of records from one document; every one must
   be readable by paging. Emit a non-primitive report value; it must produce a
   `refused` record, and a refused arm must leave the previously armed set
   untouched. Report more than 64 MiB and confirm the drop count rises and no
   record is fabricated. Arm `while (true) {}`, load a matching document, then
   Clear: the snippet must stop and the renderer must keep working. Confirm
   `pending_renderer_processes` reaches zero before relying on injection.
6. **Lifetime.** Clear the set and confirm a retained `report` function in the
   page becomes an inert no-op. Disconnect, and confirm the next new document
   runs nothing. Let the session expire and confirm the same.
7. **Packaged app.** Repeat in the packaged macOS app, including the visible
   indicator, narrow layout and keyboard focus, and confirm the browser-side
   indicator appears on matching tabs.
