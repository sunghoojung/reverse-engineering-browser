# Native JavaScript invocation identity v1

Status: reviewed design, written before any probe code and now implemented by
V8 patch `0011`, Chromium patch `0021`, the overlay and the backend. The wire
contract is
[native JavaScript invocation observations v1](../../protocol/native-js-invocation-v1.md).
[Implementation map](#implementation-map) records which layer does what and
which acceptance layers remain.

## Problem

Origin Trace shows `correlated_links: 0` for every hCaptcha request. Nothing
ties a call of the page's `window.hsw` to the Wasm work it drives or to the
request that later carries its result. Time adjacency cannot supply that tie:
one `hsw(jwt)` call enters Wasm several times (the initial call, then a resume
after a JavaScript callback packs fingerprints), and calls interleave, so a
global "current call" or a timestamp window attributes work to the wrong call.
The residual analysis this design answers is summarized in
[Driving case](#driving-case-windowhsw).

This probe gives one call of an armed JavaScript function an identity that V8
assigns at entry and carries across the call's awaits and promise jobs. While
that identity is current:

- an invocation-start record names the armed site, the frame and the argument
  kinds, with integer low bits only;
- Wasm `br_table`, `call_indirect` and guest-invocation records carry it;
- renderer-initiated network requests carry it;
- a settle record reports fulfilled or rejected, the result kind and length,
  and a SHA-256 digest of the returned value only when the session enables
  value digests (a sensitive capture path).

The backend adds explicit relations: `issued_during_invocation` (identity
only), `invocation_settlement` (a settle record belongs to its start record),
and `invocation_value_flow`, a correlated link that exists only when the exact
returned bytes are found in a retained request body. Time adjacency never
counts as any of them.

## Driving case: `window.hsw`

The captured binder defines (decoded span, digest-only analysis in the
read-only `hsw-reconstruct` tree):

```text
window.hsw=function(aGh,jR,qN){
  if(0===aGh)return Mk().then(function(){return awb(jR)});
  if(1===aGh)return Mk().then(function(){return Yl(jR)});
  if(2===aGh)return Mk().then(function(){return WA(jR,bad(qN))});
  /* nonnumeric: compact-JWT parse -> Fc(JSON.stringify(payload), unix, extras, aU) */
}
```

It is a plain function that returns a promise. Its Wasm work runs in promise
jobs registered during the call, and its result string settles that promise
later. A design that only marks the synchronous call, or only async function
bodies, observes neither the Wasm work nor the result. The rules below cover a
plain function returning a native promise, an async function, and a plain
synchronous function.

## Pinned sources reviewed

| Source | Revision | Scope |
| --- | --- | --- |
| V8 | `20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921` (15.1.206.16) | `include/v8-isolate.h`, `src/api/api.cc` (continuation-preserved embedder data, CPED), `src/execution/isolate-data.h`, `src/objects/microtask.tq`, `src/objects/promise.{tq,h}`, `src/builtins/promise-misc.tq`, `src/builtins/promise-abstract-operations.tq`, `src/builtins/builtins-microtask-queue-gen.cc`, `src/builtins/builtins-async-gen.cc`, `src/builtins/builtins-async-function-gen.cc`, `src/heap/factory.cc`, `src/objects/objects.cc` (`JSPromise::Fulfill`, `Reject`, `TriggerPromiseReactions`), `src/interpreter/bytecode-generator.cc`, `src/parsing/parser.cc`, `src/parsing/parser-base.h`, `src/init/bootstrapper.cc` |
| REB V8 stack | `patches/v8/0000` through `0010` | replayed in lexical order on top of Brave's V8 patches |
| Chromium | `151.0.7922.108` | `third_party/blink/renderer/core/scheduler/task_attribution_tracker_impl.{h,cc}`, `third_party/blink/renderer/platform/loader/fetch/url_loader/resource_request_sender.cc` |

## Arming: function-entry sites

The selection model is the one reviewed for
[JavaScript dispatch sites](native-js-dispatch-v1.md#site-naming): a site is
named by text both the analyzer and V8 can compute, never by URL, artifact or
script ID.

- `source_sha256`: SHA-256 of the script source as V8 compiles it, as UTF-16LE
  code units (artifact decoded as strict UTF-8, one leading U+FEFF removed).
- `source_length`: that text's length in UTF-16 code units.
- `anchor_offset`: the UTF-16 offset of the function's V8 start position,
  `FunctionLiteral::start_position()`, which `SharedFunctionInfo::StartPosition`
  keeps after compilation:
  - a function declaration or expression, method, getter or setter: the `(`
    that opens its formal parameter list (`ParseFunctionLiteral` sets the scope
    start after `Check(Token::kLeftParen)`, `parser.cc`);
  - an arrow function: the first character of its head, which is the `(`, the
    single parameter's identifier, or `async` (`scope->set_start_position(lhs_beg_pos)`,
    `parser-base.h`).
- `shape`: `function-entry`, the only shape in this file.

For `window.hsw=function(aGh,jR,qN){` the anchor is the `(` after `function`.
A script can contain at most one function starting at a given offset, so the
key names exactly one function literal per text. Equal texts are the same site
by design, so a reload is followed. `tools/native-js-invocation-site.py` writes
a site from a retained artifact and the UTF-8 byte offset of that character,
and refuses any other character rather than guessing.

### Supported function kinds

Arming happens in the bytecode generator for the literal whose start position
equals an armed anchor. Supported kinds: normal functions (sloppy or strict),
arrow functions, async functions and async arrows, concise methods, getters
and setters. Refused, with a per-site status and no arming:

| Kind | Why |
| --- | --- |
| generators and async generators | a resumed generator body runs on behalf of whoever calls `next()`, not the original call |
| class constructors (base or derived) | construct stubs own the return value; derived constructors return `this` after user code |
| top-level script, module or eval code | not a function call; there is no caller to return to |
| class member initializer and static block functions | synthesized; never called by page code |

The refusal is the gap `native_js_invocation_site_<n>_unsupported_function`.

### Site file and limits

`native-js-invocation-sites-v1` has the exact form of
`native-js-dispatch-sites-v1` with `shape` fixed to `function-entry`: compact
canonical JSON, at most 4096 bytes, 1 to 8 sites, each
`(source_sha256, anchor_offset)` unique. The browser validates it once, sends
the renderer only fixed 44-byte records (shape byte 3), and the renderer never
parses JSON. The file is immutable for the browser lifetime, like the other
site files.

### Saving sites from Origin Trace

A researcher names a function, such as `window.hsw`, or points at it in
Sources, instead of finding the byte offset of its `(` and running the site
tool. **Track calls** in the Sources toolbar resolves the function at the
current position; the **Track function calls** pane takes a name. Both call
`js_invocation_site_action` `add`, which resolves the exact retained artifact
on the server and saves the site. `resolve_js_invocation_site` does the same
without saving. The rules ([HTTP API](../../protocol/http-api.md#saved-javascript-invocation-sites)):

- **Never guess.** Exactly one supported function resolves. Zero or several
  are refused with at most 32 candidates, each with its line, column, binding
  and a context line, so the researcher picks one by position. Zero matches
  list definitions whose name ends in the same segment.
- **Syntax, not text.** The analysis worker walks its bounded tree-sitter
  preflight tree, so a name in a string, template or comment never matches. A
  name matches an assignment to that identifier or member chain, a
  `var`/`let`/`const` initializer, a function declaration and an
  object-literal property or method, including chained assignments and
  properties of a bound object. `window.`, `self.` and `globalThis.` are one
  prefix: in a document's main world they are the same global object, and
  invocation capture never arms a worker. A prefixed name also matches a
  top-level `var` or function declaration of a classic script, which becomes a
  global property, but never a local or module declaration. A local variable
  named `window` is not told apart from the global object, which is why every
  refusal lists candidates.
- **The anchor this tool accepts.** A position selects the innermost function
  whose definition contains it, with the binding head (`window.hsw=`) counted
  as part of the function. Bare-parameter and `async` arrows, whose anchor is
  not a `(`, generators, class constructors and class field initializers or
  static blocks are refused with a reason; V8 would not arm them at a `(`.
- **One computation.** The backend computes the key exactly as
  `tools/native-js-invocation-site.py` does; both check the cases in
  `tools/fixtures/native-js-invocation/site-cases.json`.

The saved set is the exact `native-js-invocation-sites-v1` file, so the
browser reads it unchanged, at
`~/Library/Application Support/Origin Trace/js-invocation-sites-v1.json`
beside the app's other per-user stores, plus a
`js-invocation-sites-v1.labels.json` sidecar with each site's label, source URL
and session, which the browser never reads. Both are written atomically with
user-only permissions; an empty set has no site file. At most 8 sites, and a
duplicate `(source_sha256, anchor_offset)` is refused.

Every capture the app starts arms the saved set from a private copy made at
launch: the browser rereads the file it was given and refuses a session whose
file changed, and Sources can save more sites while the capture runs. Tracking
therefore starts with the **next** capture, never the open page, and a
function compiled before arming could not gain tracking anyway. The start
dialog shows "Tracking N functions" with each label and Remove and Clear All;
the titlebar names what the running capture tracks.

Digests follow the capture mode: on in Content mode when sites are saved, off
in Metadata mode. An explicit `REB_NATIVE_JS_INVOCATION_SITES` or
`REB_NATIVE_JS_INVOCATION_DIGESTS` wins. Agent-started sessions arm sites and
digests only when the start request names them (`js_invocation_sites`,
`js_invocation_saved_sites`, `js_invocation_digests` with
`confirm_sensitive_capture`), never from the caller's environment. They keep
their own saved set at `~/.config/origin-trace/agent-sessions/`, which an
agent session's site routes edit and a later `js_invocation_saved_sites`
start arms, so an agent never reads or changes the researcher's next capture.
A named set is strict: a Brave without invocation capture refuses the start.

A Brave built before invocation capture would refuse a session that asks for
`--reb-js-invocation-capture`. For the app's saved sites only, the launcher
checks the flag first and starts without them, saying so in the log and the
titlebar. When a later session retains a script with a saved site's URL but
other script text, the pane and titlebar say that the saved site will not
match the new version.

### Compilation paths and late arming

Arming is decided at bytecode generation, so the compilation-path review of the
dispatch probe applies unchanged: code caches are neither consumed nor
produced, the in-memory compilation cache, script streaming and off-thread
compiles are off, and source positions are eager. The new V8 flag
`--reb-js-invocation-capture` implies `--reb-js-dispatch-capture` to inherit
exactly those guarantees rather than restating them. With no dispatch site
file the dispatch probe arms nothing.

A function compiled before its site was armed cannot gain an entry call. When
the arming table changes, V8 scans scripts whose length matches an armed site,
hashes them once, finds the function literal starting at each anchor, and
reports `native_js_invocation_site_<n>_compiled_before_arming` when it already
has bytecode without the entry. The site becomes observable after bytecode
regeneration or a reload. Armed functions are never optimized
(`kNeverOptimize`): at most 8 functions lose optimization, which keeps the
entry, exit and settle calls in the only tiers that run them (Ignition and
Sparkplug) and keeps timing changes declared rather than tier-dependent.

## Identity model

- **What gets an ID.** One admitted call of an armed function. V8 allocates the
  ID at entry from a per-isolate counter that never resets. IDs below the
  current configuration's floor are stale and never treated as current, so a
  configuration change cannot revive an old ID.
- **Scope.** The renderer process's main-thread isolate, so the full identity
  is `(session_id, process_id, invocation_id)`. Like every renderer sequence
  stream, this assumes a renderer process ID is not reused within one session.
- **Parent.** The invocation current when the call entered, if any. A parent is
  a dynamic-extent relation (the call happened on behalf of the parent); it is
  not value flow.
- **Admission.** Before allocating anything, V8 asks the embedder's
  allocation-free predicate, which rechecks session, VM category, generation,
  expiry and the per-configuration and per-site budgets. A call that is not
  admitted gets no ID and does not change the current invocation, so its work
  stays attributed to whatever was current before (its own caller's
  invocation, or none). The budget loss is a coalesced gap. A call admitted
  here spends budget even when the renderer then refuses its start record, and
  a spent budget closes the predicate at once, even while a full ring delays
  the gap. The budget therefore bounds how many calls V8 wraps, not only how
  many starts are retained.

## Propagation rules

V8 already propagates one embedder value across every continuation: the
isolate's continuation-preserved embedder data (CPED) slot. It is captured
when a continuation is created and restored when the continuation runs:

| Continuation | Captured at | Evidence |
| --- | --- | --- |
| Promise reaction (`then`, `catch`, `finally`, `await` on a thenable) | reaction creation | `NewPromiseReaction` and the reaction-to-job morph in `promise-misc.tq`, `promise-abstract-operations.tq` |
| `await` on a non-thenable (`AsyncResumeTask`) | enqueue | `builtins-async-gen.cc` |
| Thenable resolution job | enqueue | `Factory::NewPromiseResolveThenableJobTask` |
| `queueMicrotask` and embedder C++ microtasks | enqueue | `Factory::NewCallableTask`, `NewCallbackTask` |

`RunMicrotasks` sets the slot from each job before it runs and clears it after
every job and at start (`builtins-microtask-queue-gen.cc`), so no job leaks its
context into the next one.

Blink owns the slot for task attribution: `TaskAttributionTaskState` stores its
state there through `Get/SetContinuationPreservedEmbedderDataV2`. The probe
therefore never overwrites Blink's value. Under the flag, the slot may hold a
REB invocation wrapper, an internal `Tuple2{embedder value, Smi invocation}`
that no embedder API can create:

1. **Entry.** An admitted armed call saves the raw slot in a frame record and
   installs `Tuple2{embedder value, new ID}`.
2. **Capture.** Continuations created during the call copy the wrapper as an
   opaque `Object|Undefined` field (the field type in `microtask.tq` and
   `promise.tq`), so each one resumes inside the same invocation. Two
   interleaved calls each capture their own wrapper; neither can see the
   other's, which is why there is no global "current call" anywhere.
3. **Embedder reads.** `GetContinuationPreservedEmbedderData[V2]` returns the
   embedder value inside a wrapper, so Blink sees exactly what it stored.
4. **Embedder writes.** `SetContinuationPreservedEmbedderData[V2]` while a
   wrapper is current and JavaScript is on the stack (`js_entry_sp` nonzero)
   stores a new wrapper with the same invocation. Blink's
   `SetTaskStateVariable` forks (soft navigation, resource timing, script tool
   contexts) happen inside running script and must not drop the invocation.
   With no JavaScript on the stack, a write replaces the wrapper outright: a
   top-level task boundary never inherits an invocation.
5. **Exit.** When the call's synchronous extent ends (return, throw, or an
   async function's first suspension), V8 restores the saved slot exactly, so
   the caller continues in its own context.
6. **Extras binding.** V8's `extras_binding.getContinuationPreservedEmbedderData`
   already returns `undefined` for a non-script value. Chromium does not use the
   extras binding for task attribution; this is recorded as a check for the
   build machine rather than patched.

What propagates: everything in the table above that is created while the
invocation is current, including continuations of continuations. What does not
propagate: Blink task hops (timers, event listeners, `postMessage`,
`MessageChannel`, `scheduler.postTask`, animation and idle callbacks), workers,
worklets and service workers. Blink restores its own value at those hops,
outside any script, so the invocation is dropped, never carried to an unrelated
task. Work reached only through such a hop is reported as outside any
invocation. That absence is a coverage limit, not evidence that the work is
unrelated; the contract says so in every place it can appear.

Embedder microtasks enqueued during an invocation (for example a
`MutationObserver` delivery caused by a DOM change the call made) run inside
it. That is causal scheduling, not proof that the callback's code belongs to
the armed function.

### Synchronous extent

The bytecode generator emits, for an armed function only:

- an entry call immediately after the generator prologue, so a resumed async
  function never re-enters;
- a handler around the whole body that, on an exception escaping the frame,
  saves the pending message, runs the exit call, restores the message and
  rethrows (`ReThrow`, prediction inherited from the enclosing scope, like a
  `finally`);
- an exit call before every `Return` (`BuildReturn` is the single funnel) and,
  in an async function, before every `SuspendGenerator`.

The frame record holds the saved slot and the ID, positive during the initial
synchronous extent. The first exit restores the slot and negates the ID; later
suspensions and the final return of a resumed async body find a negative ID and
change nothing, because `RunMicrotasks` already owns the slot inside jobs.

Nested armed calls save and restore their own frame records, so the inner call
returns its caller to the outer invocation. Termination unwinds without running
handlers, so a terminated call can leave its wrapper in the slot; the next
top-level write or microtask boundary clears it (rules 4 and the
`RunMicrotasks` clear). A nested run loop entered while script is on the stack
(modal dialogs, a debugger pause) is not separated; REB ignores page
`debugger;` statements by default and has no DevTools path, and the contract
lists this as a known limit.

## Settlement

The exit call sees what the caller receives:

| Exit | Settlement recorded |
| --- | --- |
| return of a non-promise value | `fulfilled`, via `sync_return`, with that value |
| exception escaping the frame | `rejected`, via `sync_throw`, with the exception's kind |
| return or first suspension with a settled native promise | that promise's state and result, via `promise` |
| return or first suspension with a pending native promise | recorded when that promise settles, via `promise` |

A native promise covers both `hsw`'s `Mk().then(...)` and an async function's
outer promise. To observe a pending promise without changing page-visible
behavior, V8 appends one internal `PromiseReaction` directly to the promise's
reaction list. Its handlers are two native functions created for this
invocation, its capability is `undefined` (the specification-internal form
`await` uses), and its CPED is `undefined`. It is not `PerformPromiseThen`:

- `has_handler` is untouched, so an unhandled rejection is still reported to
  the page exactly as before (`JSPromise::Reject` consults only that bit);
- no species lookup, `then` lookup or getter runs, so nothing page-defined
  executes;
- the extra job runs no script and has no result promise, so the relative order
  of page-visible jobs is unchanged.

The settle record is emitted from that job with the promise's final value,
after any thenable adoption. A non-promise thenable is a plain object at the
function boundary and is recorded as `fulfilled` with kind `object`; nothing
calls its `then`. A promise that never settles, or whose context is detached
before its job runs, produces no settle record; the backend reports the
invocation's settlement as not observed, never as a value.

## Value digests

Digests are a sensitive capture path and are off unless the session enables
them: `REB_NATIVE_JS_INVOCATION_DIGESTS=1`, which the launcher accepts only
together with an armed site file and prints as a visible sensitive-capture
label. The browser carries the decision in the renderer configuration and the
renderer's predicate answers it per configuration, so V8 never decides policy.
Without it the settle record says `digest_state: not_requested`.

| Fulfilled value | Encoding hashed | Length reported |
| --- | --- | --- |
| string | UTF-8; a lone surrogate becomes U+FFFD and sets the `lossy` flag (what `TextEncoder` and a string request body send) | UTF-16 code units |
| `ArrayBuffer` | its bytes | byte length |
| typed array or `DataView` | the bytes it views | byte length |
| array | not hashed | element count |
| anything else | not hashed | 0 |

A shared, detached, resizable-out-of-bounds or length-tracking buffer is
`unavailable`. More than 1 MiB of encoded bytes is `too_large`. Rejections are
never hashed. Beside the SHA-256 the record carries the encoded byte length and
a 64-bit polynomial rolling hash of the same bytes, which lets the backend find
candidate windows in a body in linear time; only the SHA-256 confirms a match.
Neither is reversible in practice, but both are content-derived, so both are
gated together. No argument, receiver, return or exception content is ever
copied.

## Consumers of the current invocation

`Isolate::GetCurrentJsInvocation()` reads the slot without allocating and
returns `not_observed` (capture inactive), `none`, `inside` with an ID, or
`unknown` (a wrapper from an older configuration). Every consumer records that
state, never an inferred one.

- **Wasm.** `wasm_dispatch_observation` and `wasm_indirect_observation`
  payloads become version 2, and `wasm_guest_invocation` version 4, each with
  the state and ID in previously reserved bytes. Guest dispatch records keep
  version 1: each names its exact guest invocation, which carries the context.
  A Wasm activation runs inside one synchronous extent, and a JSPI resumption
  runs from a promise job that captured the same wrapper.
- **Network.** Blink's `ResourceRequestSender::SendAsync`, where the renderer
  already records `request_initiated`, also records `js_invocation_request`
  when invocation capture is active and either an invocation is current
  (`inside`), or no script is on the stack while at least one admitted
  invocation has not settled (`unknown`: a deferred load start that cannot be
  attributed). The renderer keeps the ID of each admitted start in a fixed
  256-entry table, one entry per sample index, and a settle closes its own
  entry even when its record is lost, so a lost settle never leaves an
  invocation open and the settle of a refused start never closes another. A
  request started by script outside any invocation produces no record.
  Requests from workers are unsupported.

## Ownership versus metadata

| Relation | Kind | Means | Does not mean |
| --- | --- | --- | --- |
| invocation `parent` | observed | the call ran in the dynamic extent of the parent | that the parent computed its arguments |
| Wasm record `inside` | observed | the instruction executed while the invocation was current | which guest operation produced a value |
| `issued_during_invocation` | observed | the request was started by script while the invocation was current | that any returned value is in the request |
| `invocation_settlement` | observed | the settle record belongs to that start record | anything about the request |
| `invocation_value_flow` | correlated | the exact digested bytes of the fulfilled value occur in the request body | that the invocation started the request, or which code copied them |

The value-flow join counts as a correlated link only when all hold:

1. The settle record has a present digest and the request has retained raw
   body bytes, which only exist under sensitive capture: the
   `request_body` artifact of
   [native network v2](../../protocol/native-network-v2.md), created by the
   traced request's `request_body` child record, with verified size and
   SHA-256. Without request content capture, or for a body that was not
   retained, the join has no input and reports nothing.
2. A window of the body equal in length to the digested encoding has the same
   rolling hash and the same SHA-256. Only the stated encoding counts: a
   percent-encoded, JSON-escaped, base64 or encrypted embedding is not matched
   and is not reported as a negative.
3. Exactly one settle record in the session matches. Two matching settles are
   ambiguous and produce no link.
4. The settle and the request were recorded by the same renderer process, and
   the settle precedes the request in that process's sequence. This is causal
   ordering inside one stream, not a time window; no timestamp threshold is
   used anywhere.

## Bounds, loss and failure states

| Bound or failure | Value | Visible as |
| --- | --- | --- |
| Armed sites per configuration | 8 | site file refused at browser startup |
| Invocations per configuration | 256 | `native_js_invocation_budget_incomplete`, once per configuration |
| Invocations per site | 64 | `native_js_invocation_site_budget_incomplete`, once per configuration |
| Request records per configuration | 256 | `native_js_invocation_request_budget_incomplete`, once per configuration |
| Arguments described per start | 8 | `arguments_truncated` flag; the count is still exact up to 65535 |
| Digested bytes per settle | 1 MiB | `digest_state: too_large` |
| Function compiled before arming | per site | `native_js_invocation_site_<n>_compiled_before_arming` |
| Unsupported function kind | per site | `native_js_invocation_site_<n>_unsupported_function` |
| Context is not a live local document | per configuration | `native_js_invocation_input_unavailable` |
| Settle job ran after its document went away | per configuration | `native_js_invocation_settle_unavailable` |
| Emitter refused an admitted record | per configuration | `native_js_invocation_transport_unavailable` |
| Renderer ring full | 8,192 records | existing drop counter |
| Wrapper from an older configuration | per record | state `unknown`, never a guessed ID |
| Settlement never observed | per invocation | a start without a settle record: its settlement was not observed, and no value-flow join can use it |
| Value search in one request body | 16 MiB hashed | gap `value_flow_unsearched`; no link |
| Two settled values match one body | per trace | gap `value_flow_ambiguous`; no link |

Every loss is a gap or a state. Nothing falls back to a time window, a URL or
the last known invocation.

## Cost

- **Flag off.** No wrapper exists. The CPED API adds one flag test per call;
  bytecode is byte-identical (the generator checks one flag per function).
- **Flag on, epoch 0 or no armed site.** Bytecode for unarmed functions is
  byte-identical; the dispatch probe's browser-wide cache and streaming costs
  apply.
- **Armed but not called.** One frame-record register and the handler table
  entry in the armed function only.
- **Armed and called.** Per admitted call: one runtime entry call, one
  `Tuple2`, one two-slot frame record, one exit call, and for a pending promise
  two native functions and one reaction. Per CPED write while a wrapper is
  current: one `Tuple2`. A digest hashes at most 1 MiB once, at settlement.
- **After the budget.** The entry call returns at the embedder predicate before
  any allocation.

## Contracts

| Event | Number | Category | Payload |
| --- | --- | --- | --- |
| `js_invocation_start` | 24 | `vm` | 128 bytes, version 1 |
| `js_invocation_settle` | 25 | `vm` | 128 bytes, version 1 |
| `js_invocation_request` | 26 | `vm` | 128 bytes, version 1 |

Numbers 24 to 26 follow 22 `request_body` and 23 `request_target` of
[native network v2](../../protocol/native-network-v2.md). Renumbering is a mechanical change to the C++
enum tables only; readers use names, and no layout changes. Relation names are added to the Origin Trace edge and document schemas.

## Acceptance and live verification

Portable layers (this repository's gate): encoders and validators in C++,
Python, Rust and JavaScript agree byte for byte; old payload versions stay
readable; the origin-trace index emits `issued_during_invocation` and
`invocation_settlement` only from exact identities; the value-flow join links
only on an exact, unique digest match in the same process stream; the renderer
sink's budgets, expiry, gaps and digest gating behave as specified.

V8 cctests (`RebNativeJsInvocation*`): disabled and unarmed bytecode identity;
armed-but-not-called; argument kinds; sync return, sync throw, pending and
settled promises, async functions; interleaved invocations keep separate IDs
through awaits and `then`; CPED reads and writes preserve Blink's value;
unhandled rejection still reported; budget exhaustion allocates nothing;
compiled-before-arming and unsupported-kind statuses.

Live (needs a rebuilt Brave, on the build machine):

1. the hCaptcha demo: `hsw(jwt)` produces one start, Wasm records `inside`
   that ID across its resume, one settle with a digest under sensitive capture,
   and, with request content capture, the checkcaptcha request trace shows
   `invocation_value_flow`;
2. two overlapping `hsw` calls keep distinct IDs on every record;
3. a disabled control (no site file, and a site file without the flag)
   produces no record and byte-identical behavior;
4. a non-armed function control in the same script produces no start record.

## Implementation map

| Layer | Change |
| --- | --- |
| V8 | patch `v8/0011`: flag (implies the dispatch flag), embedder interface, arming table and statuses, entry/exit/handler emission, frame record, CPED wrapper and API rules, settle reaction, digests, `GetCurrentJsInvocation`, cctests |
| Chromium | patch `chromium/0021`: install the callbacks, admit live documents, read the current invocation for Wasm records and `SendAsync` |
| Overlay | wire header, site-file parsing for `function-entry`, renderer budgets and gaps, Mojo configuration, browser forwarding of Wasm context |
| Protocol and backend | events 24 to 26, Wasm payload versions, C++/Python/Rust/JavaScript validators, origin-trace relations in the broker index, the value-flow join in both the Rust and the native app's Swift trace builders, viewer labels |
| Tooling | `tools/native-js-invocation-site.py` writes the site file; the launcher's `REB_NATIVE_JS_INVOCATION_SITES`, `REB_NATIVE_JS_INVOCATION_DIGESTS` and `REB_NATIVE_JS_INVOCATION_IF_SUPPORTED` |
| Saved sites | the worker's `invocation_site` query, the backend's site key, saved set and routes (`js_invocation_sites.rs`), Sources **Track calls**, the titlebar, and the app's start dialog and `captureDefaults` |

What runs in this repository's gate: the C++ parity and rule test, the Python
validator, the Rust readers and value search, the shared Rust and Swift trace
cases, the broker-to-backend relation check, the real renderer sink under the
portable admission suite, the browser host's configuration and forwarding, and
the launcher. What runs only elsewhere: the `RebNativeJsInvocation*` cctests
(native V8 runtime workflow) and a rebuilt Brave, for which the live checklist
above is the remaining acceptance layer. Ordered replay of `0011` and `0021`
was checked statically: every preimage blob equals the postimage the pinned
upstream, Brave and REB stacks produce for that file.
