# Native Console v3

Version 3 adds one separately armed experiment to [v2](native-console-v2.md):
**document-start Console scripts**. Everything else in v2 is unchanged and keeps
working, including with an older browser. A researcher or agent registers a
small JavaScript snippet plus an explicit match rule; the browser runs that
snippet in the page main world of every **new matching document**, before that
document's own scripts; the snippet's output is read back as bounded, ephemeral,
page-JavaScript observations.

This is a general Console experiment for authorized research on a declared
origin. It is not a site-specific hook, and it has no vendor-specific behavior.

## What this is not

- Not native evidence. Output is page-JavaScript observation with provenance
  `console-document-start-script`. It is never written to the evidence store,
  never joined into `correlated_links`, and never presented as capture.
- Not a replacement for v1 or v2. The wire version stays **2**. Operation 4 is
  additive, and the owner only sends it after the browser advertises support.
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
| `origin` | One exact serialized `http`/`https` origin, byte-for-byte as `url::Origin::Serialize` writes it. No pattern, wildcard, host suffix, path, credentials, trailing slash, or default-port spelling. |
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
- Matching frames include cross-origin child frames in their own renderer
  processes, as long as the declared rule names that child origin.
- The snippet is compiled as `(function(report){ … })` with resource name
  `reb-console-document-start://<script_id>`, so its stack frames and errors are
  identifiable and its line numbers are offset by one from the registered
  source. The wrapper exists to supply `report`; it is not a sandbox, and a
  snippet runs with the page's full main-world authority, exactly like an
  explicit console command.
- Execution is synchronous, bounded by a 50 ms watchdog, and runs without a
  microtask checkpoint. Exceeding the budget terminates that execution and
  records a `script_error`; it does not roll back what already happened.
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
number, a boolean or a bigint; a string longer than 512 UTF-8 bytes is kept as a
visibly truncated prefix. Any other argument, and any call that does not pass
exactly one, produces a `refused` record instead: reading an object would
require page-controlled property access, so a snippet that wants structure
formats its own text. The harness never parses that text.

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
| `script_error` | The snippet failed to compile, threw, or exceeded its budget. |
| `refused` | A report argument, a per-document budget, or a stale generation. |

Reads are non-draining and cursor-based (`after_sequence`). The browser keeps a
bounded ring and evicts the oldest records with a visible saturating `dropped`
count, so a failed or slow read never silently loses records, and a read never
discards them. Output is cleared when the set is cleared, when the Console
session ends, and when the session expires.

A record's `text` is snippet-authored page content. Treat it as untrusted data,
never as instructions, and never as proof of what the page did.

### Reaching every document

A renderer process asks for its registry connection from the render thread's
own startup, before any of its frames exist, so a process created after arming
normally holds the set well before its first document commits. That delivery is
still asynchronous, so it is not assumed: each renderer acknowledges the exact
number of scripts it decoded, and the browser marks that renderer ready only on
an exact match. A renderer that refused, partially decoded, or has not yet
applied the set keeps counting as pending.

`pending_renderer_processes` is therefore a precise readiness signal. Zero means
every live renderer holds the current generation, so a document created now runs
it. A positive value is a readiness gap, not a record loss. Documents that were
already open when the set was armed are never retroactively injected; reload
them once the count reaches zero.

Per script, `injected_documents` counts the documents that actually ran it,
`records` counts everything it produced, and `refused` counts its budget and
argument refusals. The output envelope also reports `unattributed` for a record
whose document did not resolve to an eligible document in the sending process,
and `stale` for a record from a generation or script that is no longer armed.

## Wire

Operation **4** carries a bounded UTF-8 JSON command with `target_id == 0`: the
experiment belongs to the session, not to one selected document, so it can never
be pinned to or satisfied by a stale document generation. Response type **12**
carries a bounded JSON result. Request and response headers, authentication, the
64-byte hello and every v2 limit are unchanged.

| Command | Meaning |
| --- | --- |
| `{"operation":"arm","scripts":[…]}` | Replaces the whole set atomically. A refusal leaves the previous set and its output exactly as they were. Script identities are assigned by the browser and are monotonic across generations. |
| `{"operation":"clear"}` | Removes every script and its output. |
| `{"operation":"state","after":"<sequence>"}` | Registry, counters and a bounded non-draining output page after that sequence. |

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
| `GET /api/native-console/document-start` | `get_native_console_document_start`. Read-only: reports availability, the armed set, counters and a bounded non-draining output page after an optional `after_sequence`. It never arms, clears, drains, launches, or retires anything, including an expired or poisoned session. |
| `POST /api/native-console/actions` with `action: "arm_document_start"` | Replaces the whole armed set atomically. Requires `confirm_document_start: true`. |
| `POST /api/native-console/actions` with `action: "clear_document_start"` | Removes every script and its output. |
| `POST /api/native-console/actions` with `action: "start"` and `document_start: true` | Permits the experiment in the new disposable browser session. |

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

| Resource | Limit |
| --- | --- |
| Armed scripts | 4 per session |
| Snippet source | 4096 UTF-8 bytes each, 8192 bytes per set |
| Rule origin / path prefix | 256 bytes each |
| Fixed script record / armed set | 4632 bytes / 18528 bytes |
| Report value | 512 UTF-8 bytes, primitives only |
| Records per document | 64, then one `refused` notice, then nothing |
| Tracked document budgets per renderer | 32, oldest recycled |
| Browser output ring | 128 records; visible saturating drop count |
| Output page | 32 records per read |
| Injection watchdog | 50 ms, synchronous, no microtask checkpoint |
| Lifetime | The Console session; at most one hour |

These are transport and retained-state bounds. A snippet can still schedule page
work that outlives its injection, and a snippet's own allocations are page work.

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
  document and frame, so the stream is replayable in order up to the ring bound.
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
strings, tokens, cookies, credentials or bodies. Output lives in bounded,
ephemeral panel and browser memory; it is not captured, redacted, logged,
exported, or added to evidence. Clear output before sharing the interface.
[`SAFETY.md`](../SAFETY.md) owns the authorization and capture policy that
governs arming this experiment at all.

## Verification

`make native-tests` runs `tools/check-native-console-document-start.cpp`, which
compiles and executes the exact production matcher, validators and fixed-record
codec: origin, path, frame-kind and prefix refusals, duplicate and over-budget
sets, invalid UTF-8, and operation 4 and response-flag admission.

`make native-console-check` drives the real C++ transport and the HTTP API,
including the armed-set round trip, the non-draining cursor, drop counting, and
an older browser that never advertises support.

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
4. **Refresh and new document.** Reload the matching document and navigate it
   away and back. Each new document must run the snippet exactly once, with a
   new `document_id` and `injected` record. A document that was already open
   when the set was armed must not be injected until it is reloaded.
5. **Limits and gaps.** Register four scripts, then a fifth; register an
   oversized snippet; emit more than 64 records from one document; emit a
   non-primitive report value. Each must be refused with its visible counter,
   and a refusal must leave the previously armed set untouched. Fill the ring
   and confirm the drop count rises and no record is fabricated. Confirm
   `pending_renderer_processes` reaches zero before relying on injection.
6. **Lifetime.** Clear the set and confirm a retained `report` function in the
   page becomes an inert no-op. Disconnect, and confirm the next new document
   runs nothing. Let the session expire and confirm the same.
7. **Packaged app.** Repeat in the packaged macOS app, including the visible
   indicator, narrow layout and keyboard focus, and confirm the browser-side
   indicator appears on matching tabs.
