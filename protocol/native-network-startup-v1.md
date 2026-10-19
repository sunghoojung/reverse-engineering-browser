# Native network startup observations v1

Status: implemented source candidate; patched Brave compilation and real-browser
acceptance are still required. This is host-level native metadata, not a complete
HTTP wire recorder. The existing CDP content path remains separate.

## Startup and authorization

The pinned Brave `ChromeBrowserMainParts::PreProfileInit` activates the existing
session before delegating to Chromium profile initialization. This precedes
profile creation and startup navigation. Activation no longer waits for a
renderer to launch, and renderer creation does not retry a failed startup.
All existing broker, token, session, category and expiry switches remain required.
No switches means no capture. Token reads and path canonicalization occur once at
startup; this is not an allocation-free or file-I/O-free startup guarantee.
Connect and authentication-hello writes use a non-blocking descriptor and fail
closed on pending connections or backpressure. Sending a hello is not durable
receiver acknowledgment. The existing writer thread handles later socket work;
request hooks never connect, read token files, wait, or write sockets.

The explicit `--user-data-dir` is canonicalized once. Only its exact `Default`
BrowserContext is admitted; off-the-record, system, other profiles, and unresolved
roots are excluded. No origin allowlist is implied. The researcher must authorize
the disposable session's targets under [SAFETY.md](../SAFETY.md). Renderer probe
host admission and response-artifact admission use the same owned-profile gate,
so earlier startup does not authorize unrelated profile capture. Artifact-only
sessions remain supported independently of the Network category.

The owned [live launcher](../scripts/run-live-session.sh) starts the broker first
and polls for its socket pathname and token file up to 100 times at 50 ms
intervals (nominally five seconds); the final timeout guard checks the socket
pathname only. If artifact capture is enabled, it then starts the artifact
receiver and polls for its socket pathname with the same count and interval.
It starts the UI and waits for its endpoint before spawning Brave. The broker
creates its token before binding and listening.
However, a socket pathname can exist after `bind` and before `listen`: these
checks are not a formal listener-ready or authenticated receiver acknowledgment
barrier. Startup connect failure is explicitly logged as `Unable to connect to
native probe broker` in the launcher's `brave.log`; artifact connection failure
is logged as `Unable to connect to native artifact receiver`. Capture stays inactive, with no renderer retry. A failed
connection cannot deliver a gap record, so missing native events must remain
unknown rather than being interpreted as an empty or complete capture.

A fixed, content-free startup log describes activation and known coverage limits.
A failed connection or later disconnect leaves capture unavailable; ordinary
browser operation continues. Absence of events is never evidence of no traffic.

## Request lifetime and ownership

The existing `BraveProxyingURLLoaderFactory` remains the observation boundary.
At `InProgressRequest` construction, before Shields callbacks or downstream
loader creation, capture snapshots its admission generation and available
BrowserContext token, request ID, tab, frame and initiator process identity.

The primary native key is session + full opaque BrowserContext token + Brave's
context-global request ID. Missing tab/frame/renderer attribution stays unknown.
The folded frame token is not collision-free and must not replace that primary
key. Startup navigation may precede a live renderer and therefore have no
renderer correlation. Shared/service workers can lack a frame; no parent tab is
invented. IDs and paths are not queried again during destructor teardown.

One constant-size lifecycle value follows each real loader. No global request
registry, TTL scan or unbounded capture-owned retention is introduced. Requests
created while disabled or outside the owned context are never retroactively
admitted. A configuration generation change rejects late callbacks, including
when a session ID is reused. The session transport also rejects foreign session
IDs. Request start occurs once per proxy lifetime; redirects retain that identity.

Response and real completion/error callbacks preserve existing metadata. Shields
stub responses carry `synthetic_shields; <mime>` rather than masquerading as an
observed remote response. Destructor teardown and Chromium redirect handoff emit
at most one terminal observation with `ERR_ABORTED` and exact dispositions
`proxy_destroyed` / `redirect_handoff`. They use the existing v3 failed-event
transport shape, but mean observation ended, **not** proof of network failure.
Traffic renders them as incomplete; evidence labels explain that the final
network outcome is unavailable. A real error retains ordinary failure semantics.
No success/loadingFinished record is fabricated. If expiry, disconnect or a
queue drop prevents the terminal observation, completeness remains unknown.

## Coverage and limits

| Path | Native coverage in this candidate |
| --- | --- |
| Startup documents, frames, ordinary fetch/XHR through Brave's factory | Start before Shields, redirect, response, terminal observation |
| Shields cancellation or synthetic stub | Start plus failure/stub provenance, including pre-network rejection |
| Network-service HTTP cache through this proxy | Response/cache metadata when callbacks cross the proxy |
| Dedicated/shared/service-worker requests through this proxy | Lifecycle metadata; frame/tab ownership may be unknown |
| Service-worker synthetic responses / CacheStorage interception | Not covered when Chromium uses a separate single-request/intercepting loader |
| Renderer memory-cache reuse | Not covered when no browser URL loader is created |
| WebSocket, WebTransport, other non-URLLoader traffic | Not added by this change |
| Headers, full URLs and arbitrary response bodies | Not retained by native metadata; existing separately authorized artifact/CDP paths only |

Request payloads remain bounded method + host; response payloads remain bounded
MIME/protocol or synthetic provenance. No query, fragment, credentials, headers or
request body is added. Existing explicitly authorized JS/Wasm artifact capture
has its own sensitive-data limits and receiver acknowledgment.

The browser queue holds 1,024 records. Full queues count drops; the existing writer
reports weighted gaps when it can next drain records. The 128-byte payload cap
sets truncation flags. Queue-wide gaps are unattributed and may overlap sequence
discontinuities; never add them as independent losses. Disconnect/final-tail
loss can prevent delivery of a gap or terminal marker. This is bounded loss
accounting, not a complete or durable-delivery guarantee.

## Validation and build acceptance

`make native-network-capture-check` compiles the actual sink, lifetime value,
queue and IPC client against narrow Chromium type boundaries. It checks inactive,
expiry/category, owned/foreign/OTR/system admission, identity, cache/SW flags,
synthetic/abort provenance, duplicate terminal rejection, generation rollover,
truncation, queue drops and real local IPC admission/backlog behavior. These tests
do not compile the upstream proxy template or prove browser hook execution.
The ordinary JS gate checks incomplete vs real-error projections.

Patch 0013 is based on Brave `v1.95.52`; Chromium remains `151.0.7922.108` and V8
`20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921`. No pins change. Partial replay against
fetched exact pinned Brave files is useful source evidence, but is not full
three-stack replay on a Brave-initialized checkout.

Before declaring this browser-ready:

1. Establish and validate a formal broker-ready acknowledgment before browser
   startup; pathname existence alone is insufficient. This is a remaining
   acceptance item, not a new handshake implemented by this source candidate.
2. Replay all stacks and overlays on a disposable initialized pinned checkout;
   verify repeated sync is unchanged. Run `make brave-doctor`, `gn format
   --dry-run` on the changed component GN file, and `make brave-probe-check`.
3. Compile the modified browser main-parts object as well as both proxy template
   instantiations, sink, socket client, IPC client and session. The focused object list now includes the main-parts object, derived from
   the pinned `brave/browser:core` source set; validate it in generated Ninja. Complete the
   guarded [integrated build](../docs/development/integrated-brave-build.md).
4. With an authorized local fixture and CDP capture disabled, launch a fresh
   owned profile directly to a URL. Compare server receipts with native startup
   document/subresource, redirect, cancellation and terminal events. Exercise
   popup, cross-origin frame, workers, cache reload, Shields rejection/stub,
   close-during-request and redirect handoff. Assert exact native ownership and
   no fabricated successful completion; exclude unrelated/OTR/system contexts.
5. Exercise disabled/expired sessions, invalid authentication, disconnected broker
   and bounded queue pressure. Preserve named unsupported SW/memory-cache cases
   in the acceptance report instead of silently removing them from a denominator.

The supported integrated build host is Apple silicon macOS with full Xcode and
an initialized checkout (150 GiB first-build reserve, typically 200–250 GiB free).
A small Linux workspace cannot establish that build or native runtime result.
