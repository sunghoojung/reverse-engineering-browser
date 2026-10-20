# Independent capture completeness harness

This is a controlled localhost experiment, not a losslessness guarantee. The
reference collector has no REB capture imports, and the fixture oracle has no
CDP dependencies. Both observers run against the same disposable browser
session. Server receipts and a version-pinned Chrome NetLog adapter crosscheck
shared CDP blind spots. Only authored operations are in scope.

## Run

Use Node.js 22 or newer. The deterministic offline gate is:

```sh
make capture-completeness-check
```

The browser gate builds the backend and transport, then launches two fresh
profiles. Set `ORIGIN_TRACE_TEST_BROWSER` (or `REB_UI_CHROMIUM`) to an installed
Chromium executable and `REB_REFERENCE_BROWSER_VERSION` to its exact four-part
version. A missing or mismatched version fails the comparison.

```sh
REB_REFERENCE_BROWSER_VERSION=<exact-version> make capture-completeness-browser-check
```

`REB_REFERENCE_ONLY=1 node tools/check-capture-completeness-browser.mjs .` is a
diagnostic reference-only run; it cannot pass the REB comparison. The full
repository handoff gates remain `make lint`, `make check`, `make e2e`,
`make sanitize`, and `git diff --check`.

The startup cohort navigates immediately at browser launch; its early events
remain in the denominator. Immediately after browser launch, the independent
reference startup and REB process launch are initiated together: neither waits
for the other's discovery, socket, version check, initialization, or readiness.
The report's `startupTimeline` contains monotonic millisecond offsets from cohort
setup (0–120000), with null for milestones not reached. `referenceReadyMs` means
its initialization promise settled successfully; ledger gaps still invalidate
coverage. `rebReadyMs` means the existing capture identity/readiness check passed.
`fixtureNavigationMs` is the explicit prearmed navigation only; startup navigation
is requested by the browser launch arguments. These timings diagnose launch skew,
not event completeness. No cache or service-worker bypass is introduced.
The prearmed cohort navigates only after both
collectors are ready. Worker, frame, and popup startup inside either page is
never paused for attachment. The passive collector must not use
`waitForDebuggerOnStart: true` to improve its score.

## Independent fixture API

`createCaptureFixture({runId, limits})` from
`tools/capture-completeness-fixture.mjs` returns `origin`, `crossOrigin`,
`entryUrl`, `manifest`, `receipts`, `completions`, `assertComplete()`,
`waitForCompletion({timeoutMs, drainMs})`, and `close()`.

The manifest declares operations before the page runs. Each operation has
`operationId`, `caseId`, `path`, `method`, `kind`, and `expectedReceipts`.
URLs contain a run-specific path and matching `op` query token. Repeated URL
requests share an operation identity and require multiplicity two. Redirect
hops have distinct identities. OPTIONS and POST share a URL and operation token
but are distinct method-qualified operations. Receipts have a monotonic sequence,
operation identity, method, path, URL, and evidence kind.

Each case posts an explicit success/failure marker. A missing marker, timeout,
wrong multiplicity, failed client assertion, or resource overflow fails the
oracle. Completion has a fixed bounded drain (250 ms by default), rather than
assuming network quiet means all cases ran. These markers are client fixture
assertions, not authoritative browser probes. Offline tests simulate markers;
only the browser gate executes their real page behavior.

## Cases and their assertions

- Initial document, stylesheet, and script; document completion verifies script execution.
- Two fetches to the same URL and a two-hop redirect; every hop counted separately.
- Truncated response body and explicitly aborted streaming body; both must reject client body consumption.
- Cross-site iframe with immediate fetch, using `localhost` versus `127.0.0.1`.
- Dedicated worker and shared worker with immediate fetch and explicit reply.
- Service worker installation fetch and synthetic response with exact expected body.
- Short-lived popup that closes after its fetch and completion marker.
- Cold/warm fetch pair: two client completions, one server receipt, exact body.
- Cross-origin POST with a custom header: one OPTIONS preflight and one POST.
- WebSocket handshake and one text echo; handshake and frame evidence remain separate from HTTP request-hop counts.

The repeat, cache, and service-worker synthetic operations also declare known
`expectedBody` strings. A separate body metric compares retained, available,
nontruncated REB response bodies against those samples. This is neither a check
of every response body nor request-count completeness. Headers are not assessed
by these known-body samples. The combined verdict requires both the HTTP metric
and these body samples to pass; it does not upgrade unassessed headers or
WebSocket frames to passing coverage.

## Bounds and negative controls

Default caps: 512 receipts, 256 KiB serialized receipts, 64 open sockets,
8 KiB request/completion bodies, and 4 KiB buffered WebSocket input. Overflow is
sticky and fatal; evidence is never silently discarded into a passing result.
Run IDs are at most 80 ASCII identifier characters. Completion waits are capped
at 120 seconds and drains at 10 seconds; HTTP sockets have a 15-second timeout.
The tiny WebSocket fixture accepts only masked, unfragmented short text/close
frames; it is not a general WebSocket server.

Negative controls remove or duplicate repeated receipts, remove OPTIONS while
retaining POST, add a forbidden on-wire synthetic response, remove a frame,
omit/fail a case, mismatch operation identity, and exceed receipt count/bytes,
body bytes, or sockets. Collector and integration tests additionally exercise
missing-both observations and lifecycle/gap failures.

## Interpretation and validation limits

Server receipts prove arrival at the owned server, not browser completion,
cache delivery, or service-worker synthesis. Synthetic/cache expectations require
client completion and collector evidence. A cross-site fixture alone does not
prove OOPIF isolation; target evidence is required. A short-lived popup with a
completion marker is not a proof about every possible immediately closing tab.
WebSocket evidence is reported separately; HTTP success does not imply REB
WebSocket frame completeness. CDP collectors can share instrumentation blind spots.

The local cloud execution attempt failed before navigation with Chromium
`process_singleton_posix.cc: socket() failed: Operation not permitted` and a
Crashpad database error. It produced zero fixture receipts. Offline tests pass,
but actual browser behavior and collector coverage require a successful browser
gate in an environment supporting sandboxed Chromium. Do not interpret this
local launch failure as a product capture result. No sandbox bypass is part of
the harness.

Raw NetLog stays in the disposable local profile and is removed after parsing;
only bounded summaries of owned fixture identities/counts are reported. Never
substitute public sites or private user profiles for these authored fixtures.

### Diagnosing controlled-run gaps

The independent recorder admits one Network observer per target. Overlapping
manual discovery and recursive auto-attachment sessions are detached before
Network enablement; request rows are never deduplicated by URL or silently
merged. A failed primary initialization or duplicate cleanup remains incomplete.

The public REB capture epoch advances during selected-debugger initialization.
The harness records pre-ready transitions and locks identity only once that
initialization and browser capture are ready. Later identity changes remain
incomplete. Startup server receipts are retained regardless of readiness.

The sanitized report includes fixed per-operation mismatch reasons, pending
counts, and bounded pre-shutdown lifecycle aggregates. Error observation counts
are counts of snapshots carrying a reason, not counts of distinct incidents.
No shutdown snapshot is included after Browser.close. NetLog source identities
support Chromium's signed 32-bit serialization, including negative partitioned
IDs; unknown shapes still fail with fixed diagnostic codes. These diagnostics
help distinguish test instrumentation problems from capture gaps; they do not
excuse any missing expected operation or prove lossless capture.

Status diagnostics count fixed, mutually exclusive value buckets for each
observer, globally and per authored operation: `missing` (absent or undefined),
`null`, `zero` (including negative zero), `httpRange` (integer 100 through 599),
`otherNumber` (other finite numbers), `nonfiniteNumber`, and `nonnumber`.
Only bounded counts are exported, never status values, URLs, or request IDs.
These buckets do not change validation: finite zero already passes the numeric
status predicate, while null on a completed hop, a missing status, a nonfinite
number, or a nonnumeric value remains malformed. Null on pending or failed
hops retains its existing meaning. Global buckets include all observed rows;
per-operation buckets include only that operation's rows. Neither changes the
24-hop fixture denominator or supplies a missing response.

Producer cleanup diagnostics expose cumulative `cleanup_already_gone` and
`cleanup_failures` counters. A redundant session's detach rejection converges
only after an exact same-connection session/parent detach or target-destroyed
notification confirms its lifetime ended. An event barrier drains that proof;
unknown outcomes and transport failures still fail closed. These counters help
test the cleanup-race hypothesis; a nonzero gap count is not a count of missing
requests and remains a conservative incomplete signal in this harness.

The isolated CI gate builds the pinned prior backend and requires the new
confirmed-disappearing-session regression to fail with its specific assertion,
then builds the candidate and runs the entire session lifecycle suite. Build or
launch failures do not satisfy the negative control. Both builds are serial and
use separate Cargo target directories, with explicit backend paths and logged
source commits/binary hashes. Shared target directories can retain a prior
package fingerprint and invalidate the old/new comparison. Only the allowlisted
controlled-comparison summary is uploaded, never the synthetic logs or raw
browser evidence.

Reference main-resource handoffs retain the original request owner and record
actual terminal-session provenance locally. A unique current-connection iframe
main resource requires exact loader/request/frame identity and observed ancestry;
a worker main script requires its documented request-ID/future-target identity
and explicitly empty loader ID. Only an actual `loadingFinished` event with a
valid timestamp can complete the hop. Collisions, unknown iframe ancestry and
conflicting shared-worker parent lineages remain incomplete. Raw lineage and
terminal IDs are ephemeral, excluded from sanitized reports. This correction
never changes the expected operation denominator or invents completion events.

A not-yet-published DevToolsActivePort file remains startup waiting and is retried
by the existing refresh loop. It does not trigger the 30-second browser-capability
failure backoff. Existing malformed endpoints and unsupported browser discovery
retain that backoff. Reports expose fixed-enum capture transport, scope and
readiness state so a ready page-only fallback cannot be mistaken for browser-wide
child-target readiness. Error diagnostics classify discovery failure prefixes
without publishing their path or raw error suffix.

Response-event diagnostics retain bounded metadata for `responseReceived` and
`responseReceivedExtraInfo`, including events that arrive before a request.
Reports contain fixed status buckets, local event ordinals and session-relation
labels only. Events sharing a protocol request ID are namespace observations,
not attributed responses: redirect hops expose the same sequence and explicit
namespace hop counts. Other-session matches are never accepted as owners.
These diagnostics do not fill missing status or change the comparison verdict.
Limits are 4096 events/1 MiB internally and 8 hops/16 events per operation in
the report; omission makes diagnostic completeness false with explicit counts.
Here `complete` means only that diagnostic metadata was retained within its
bounds, even if zero response events were observed. It never means that HTTP
requests or response events were captured completely.

Browser setup diagnosis exports bounded `lifecycle.browserSetupObservations`
entries `{stage, reason, samples}` from the optional fixed producer diagnostic.
Samples count observed snapshots, not distinct failures. The producer clears its
last setup failure after successful browser setup; observed aggregates retain the
history. Unknown values are ignored by the observer and rejected by the report
sanitizer; raw diagnostics, URLs, and identifiers are never exported. This separates
transport startup failures from discovery-command failures without changing the
30-second failure backoff or attributing an aggregate fallback to a specific cause.

Focused producer ExtraInfo controls run with `REB_EXTRA_STATUS_ONLY=1` in
`tools/check-traffic-browser-sessions.mjs`. Synthetic events cover before/after
request order, responseReceived precedence, cached effective 200 versus wire 304,
304-only evidence, duplicate and malformed observations, redirect/raw-ID reuse,
separate owners and replacement sessions, and dropped-history refusal. Assertions
check both effective status provenance and separate wire status. The fixture
processing barrier uses a separate completed request; it does not infer processing
from an arbitrary sleep. These controls do not establish real-browser completeness.
