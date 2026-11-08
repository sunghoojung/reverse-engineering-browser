# Native network observations v3

Status: implemented source candidate. The overlay and patches compile against
portable harnesses of the pinned Chromium types; patched Brave compilation and
a live run are still required (see [Acceptance](#acceptance)).

This version is shared by the Traffic, Sources and debugger parity issues
(#435). This file currently defines the part from #424: request scope, counted
browser-internal exclusions, and completion of requests the browser proxy never
sees. [Startup v1](native-network-startup-v1.md) and
[network v2](native-network-v2.md) keep their records; nothing here changes a
stored v1 or v2 meaning. [SAFETY.md](../SAFETY.md) governs capture and export.

## Scheme class

Byte 140 of the v3 320-byte envelope, formerly reserved, is the request's
scheme class. Bytes 141 to 143 stay reserved and zero. JSON carries it as
`scheme_class`, written only when nonzero; an absent key means 0.

| Value | Class |
| ---: | --- |
| 0 | not recorded (an earlier producer, or a record of another type) |
| 1 | `http` |
| 2 | `https` |
| 3 | `ws` |
| 4 | `wss` |
| 5 | `data` |
| 6 | `blob` |
| 7 | `file` |
| 8 | `chrome-extension` |
| 15 | any other scheme |
| 16 | `chrome` |
| 17 | `chrome-untrusted` |
| 18 | `brave` |
| 19 | `devtools` |
| 20 | `chrome-search` |

Classes 16 to 20 are browser-internal. A nonzero class is valid only on network
`request_initiated`, `request_started`, `request_completed` and
`request_failed`. `request_initiated` (renderer) and `request_started` (browser
proxy) always carry it; the renderer completion below does too. It is one byte
of metadata, so metadata-only sessions can tell a browser-internal row from a
web row whose path was not captured.

## Browser-internal exclusion

Browser-internal evidence is not recorded by default, and every exclusion is
counted:

- A renderer counts a request with a class 16 to 20 instead of recording it.
  One counter per class lives in the shared probe queue (queue version 3), like
  the drop counter, and the browser reports it at the next drain.
- `NativeProbeSession::BindHost` does not admit a renderer process with WebUI
  bindings (`ChildProcessSecurityPolicy::HasWebUIBindings`). A process granted
  bindings after it bound is detached at its next drain; the records it queued
  are discarded with it. Each such process counts once. Its script artifacts,
  fingerprint events and requests are therefore absent.
- Native Console targets are http(s) frames listed from every render process
  and reach their agents through frame interfaces, so they do not depend on
  probe admission.
- `REB_CAPTURE_BROWSER_INTERNAL=1` makes the live launcher pass
  `--reb-capture-browser-internal`, which turns both exclusions off for that
  browser. Sessions started by `reb-api session start` or `start_live_session`
  always set it to 0.

Extension background traffic (#425) is a separate exclusion class that this
file does not define yet.

### `capture_exclusion` (type 36)

Category `network`, produced by the browser in its own sequence space.
`initiator_process_id` names the renderer OS process whose counter this is, or
0 for a browser-wide counter. Tab, navigation, frame, artifact, parent,
request, BrowserContext, lengths, status, error, resource type, initiator
request, scheme class and flags are zero. Payload size 16, little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `16` |
| 4 | 1 | exclusion class |
| 5 | 3 | reserved, zero |
| 8 | 8 | count, nonzero |

Exclusion classes 16 to 20 count requests of that scheme class. Class 64
`webui_renderer` counts renderer processes that were not admitted; its
`initiator_process_id` is 0. The count is cumulative within the session for
one `(initiator_process_id, class)`, so a later record supersedes an earlier
one and a lost record loses nothing that a later one reports. Consumers take
the newest count per producer and class and sum by class. An exclusion is
neither a sequence gap nor a queue drop.

## Requests answered in the renderer

The browser proxy finishes the requests it observes. A request with a scheme
class outside 1 to 4 (`data:`, `blob:` and other local schemes), or whose
response says a service worker supplied it, never reaches that proxy. The
renderer finishes it instead, from Blink's `ResourceRequestSender`:

1. With request content, a `request_target` child of its `request_initiated`:
   renderer process and sequence, the start's frame, thread, request ID and
   time, `parent_event_id` the start's sequence, and the
   [v2 payload](native-network-v2.md#request_target-type-23). Its scheme byte
   is 1 to 4 for an http(s) or ws(s) URL and 0 otherwise.
2. One `request_completed` (status code from the response head, encoded and
   decoded lengths, flags `from_cache` and `from_service_worker`) or
   `request_failed` (the net error), with the start's process, frame and
   request ID, the scheme class, initiator fields 0 and payload `completed` or
   `failed`. A request the renderer cancels before completion fails with
   `ERR_ABORTED`.

`--reb-capture-request-content` reaches the renderer with the session
configuration, so the renderer's target follows the same gate as the
browser's. Only a start the configuration admitted is finished, and only into
that configuration.

`data:` URLs are decoded by Blink's `ResourceLoader` without a URL loader. That
loader now records them: a `request_initiated` with a fresh renderer request
ID, the method, an empty host and class 5, then the completion above once the
URL is decoded (status 200, or the decoding error). A `data:` load cancelled
before decoding fails with `ERR_ABORTED`.

Not covered: synchronous XHR outside `data:`, a service worker failure before
any response, and renderer memory-cache reuse, which creates no request.

## Hot path and bounds

- Inactive: `RecordRequestInitiated` keeps its one atomic load and allocates
  nothing; the loader's completion hooks read a plain field of the value it
  keeps, and the `data:` hook is one atomic load.
- Active: a classification per request, one counter increment per excluded
  request, and for renderer-answered requests one completion record plus, with
  request content, one target record. The `data:` target copies at most its
  116-byte prefix.
- A start the ring refused returns an unrecorded value, so its completion is
  not emitted; the drop counter already reports the start.

## Consumers

- The broker validates both the scheme class and type 36 in `IsValidEvent`.
- `get_session_summary` lists `exclusions` by class and adds the info check
  `browser_internal_excluded`. The backend keeps type 36 in its network window.
- Traffic shows "N browser-internal requests not recorded" in its footer, names
  hostless rows by scheme (`data:`), and joins renderer targets and completions
  to their row. A reversible "Hide browser-internal" filter in Traffic and
  Sources hides class 16 to 20 rows, internal-scheme sources, and, for
  evidence recorded before scheme classes, renderer-only rows whose host is one
  bare label. It shows the hidden count and never changes stored evidence.

## Validation

`tests/network_scope_test.cpp` (in `make native-tests`) checks overlay and core
layout parity, every class and many malformed records, and `make
network-scope-wire-check` compares those verdicts with the Python validator
and the shipped readers, then drives the Traffic model through `data:`,
service-worker, opted-in internal and pre-v3 rows.
`make native-probe-admission-check` drives the real renderer sink and
transport through exclusion counting, opt-in, renderer completion, stale and
refused starts and the inactive path. `make native-network-capture-check`
checks the browser `request_started` scheme class.

## Acceptance

Still required before declaring this browser-ready:

1. Replay all stacks on a disposable initialized pinned checkout, run `make
   brave-doctor` and `make brave-probe-check`, and compile the browser target.
   This adds Chromium patch `0026-finish-renderer-answered-requests`.
2. Open the new tab page, then an https site. Traffic has no `resources` or
   `newtab` rows, `get_session_summary` reports the excluded counts, and
   Sources has no `chrome:` group. The site's own requests, including its first
   document, are unchanged.
3. A `data:` URL and a service-worker-served request show their path (with
   request content) and status.
4. Repeat with `REB_CAPTURE_BROWSER_INTERNAL=1` and confirm the internal rows
   return with classes 16 to 20 and no exclusion is reported.
