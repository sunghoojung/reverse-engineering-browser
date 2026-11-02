# Lane DX, wave52 renderer request frame attribution

**Code fix landed; new captures need a Brave rebuild.** The renderer
`request_initiated` record now carries the same frame attribution its sibling
collectors carry, so the browser bridge can resolve its tab and Origin Trace can
join a network request to a frame. The repository component gate proves the
field is set. No Brave toolchain exists on this machine, so the behavior is not
yet attested inside a running browser.

## What was wrong

`NativeProbeSink::RecordRequestInitiated` builds its header field by field
instead of going through `RecordSurfaceOperation`. Every other renderer emit
path reads `frame_id_provider_` while assembling the event; the network path
did not, so `NativeProbeHeader::frame_id` kept its `0` default.

`tab_id` is then lost as a consequence, not independently. The renderer never
assigns it: `NativeProbeHost::Drain` builds a `frame_id -> tab_id` map from
`CurrentFrameTabs` and stamps `tab_id` only when the record's `frame_id`
matches a live frame. A zero `frame_id` can never match, so a correct
`frame_id` is the whole fix for both fields.

Both sides hash the same Blink frame token the same way: the renderer from
`WebLocalFrame::GetLocalFrameToken`, the browser from
`RenderFrameHost::GetFrameToken`, each as `rotl(high, 17) ^ low`. That is the
join canvas and WebGL records already rely on.

## The change

- `browser/integration/brave/overlay/components/reverse_engineering_browser/renderer/native_probe_sink.cc`
  reads `frame_id_provider_` while assembling the `request_initiated` header,
  with the same relaxed load and the same `0` fallback as the surface-operation
  path. The provider is called after the acquire fence and the configuration
  re-check, so it cannot run against a retired configuration.

The renderer-side Chromium patch
`browser/integration/brave/patches/chromium/0001-record-renderer-network-initiators.patch`
is unchanged. Its call stays
`RecordRequestInitiated(request_id, request->method, request->url.host())`, and
no overlay destination moved, so overlay and patch reproduction is unaffected.

## Known bound

The provider is `CurrentFrameId`, which resolves the frame from the entered
script context. A load with no entered context, such as a parser-inserted
script or an image, still records `frame_id == 0`. That is an explicit unknown
frame rather than a guess, and it is no worse than the previous behavior, which
recorded zero for every request. Attributing parser-initiated loads would need
a frame identifier threaded from `ResourceRequestSender::SendAsync`, which
changes patch context and cannot be verified without the pinned Chromium
checkout.

## Separate finding: `no_predecessor` on this record is expected

The triage note pairs zeroed `frame_id` with `correlated_links:0` and
`no_predecessor`. These are independent. `OriginTraceIndex` does not correlate
on `frame_id` at all: `kRequestInitiator` edges key on
`(session_id, initiator_request_id, initiator_process_id)` and
`kRequestLifecycle` edges key on the request identity. A renderer
`request_initiated` record is the *source* that browser lifecycle events
resolve against through `ResolvePendingInitiators`, so nothing precedes it
unless `parent_event_id` is set. Restoring `frame_id` restores the frame and
tab join on the row; it does not add a predecessor edge, and should not be
expected to.

## Validation

Run in `/tmp/hsw-lane-worktrees/reb-DX-frame-id`.

| Command | Result |
| --- | --- |
| `make lint` | passed |
| `make check` | passed, including the new renderer admission case |
| `make e2e` | passed |
| `make sanitize` | passed |
| `git diff --check` | passed |
| `REB_PROBE_TEST_SANITIZERS=address,undefined make native-probe-admission-check` | passed |
| `make brave-doctor` | unavailable: `Brave checkout is missing: browser/worktree/src/brave` |
| `make brave-probe-check` | unavailable: same missing checkout |
| overlay destinations at the pinned revision | unverified: no Chromium checkout to resolve paths against |
| `gn format --dry-run` | skipped: no GN file changed |

`tools/native-probe-admission/main.cc` gains
`RequestInitiatedFrameAttribution`, which compiles the real overlay sink and
asserts that `request_initiated` reports the same non-zero `frame_id` as a
sibling canvas record, that the renderer leaves `tab_id` at zero for the bridge
to assign, and that a caller without a script context still reports zero.
`tools/native-probe-admission/chromium_stubs.h` gains a thread-local
`test_frame_present` opt-in so the test-only frame lookup can model a present
frame; it defaults to absent, so every existing case is unchanged. The test
aborts on the pre-fix sink, so it is a real regression guard.

This is component evidence. It does not attest frame attribution inside a
running Brave build, end-to-end delivery to the evidence store, or any Origin
Trace document rendered from a live capture. No live session, capture clear or
native console start occurred.
