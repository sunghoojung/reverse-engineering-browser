# Native network observations v3

Status: implemented source candidate. The overlay and patches compile against
portable harnesses of the pinned Chromium types; patched Brave compilation and
a live run are still required (see [Acceptance](#acceptance)).

This version is shared by the Traffic, Sources and debugger parity issues
(#435). This file currently defines the parts from #424 (request scope, counted
browser-internal exclusions, completion of requests the browser proxy never
sees) and #425 (the tab that caused each request). [Startup v1](native-network-startup-v1.md) and
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

Traffic no tab caused has its own classes, defined in
[Request owners and tabs](#traffic-no-tab-caused).

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
`initiator_process_id` is 0. Classes 65 `extension_worker` and 66
`devtools_load` count requests (see [below](#traffic-no-tab-caused)). The count is cumulative within the session for
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

## Request owners and tabs

Every request record names the tab that caused it. A row without a tab is a
capture error (`network_tab_unresolved`), never a catch-all group. Owners are
resolved where Chromium knows them and carried with the record; no tab is ever
assigned by host, URL or timing.

### Tab identity

`tab_id` is the `FrameTreeNodeId` of the primary main frame of the outermost
`WebContents` (`GetOutermostWebContents()`, so guest views count as their
embedding tab). At pinned Chromium 151.0.7922.108 it is stable for a tab:

- Prerender activation moves the prerendered main `RenderFrameHost` into the
  primary tree's root node (`PrerenderHost::Activate` calls
  `SetFrameTreeNode(*(target_frame_tree.root()))`) and destroys the prerender
  tree. Requests made while prerendering already resolve through the hosting
  `WebContents`, so they keep the same tab.
- A back/forward cache restore swaps the stored `RenderFrameHost` into the same
  root node (`RenderFrameHostManager::RestorePage`); the root node lives as
  long as the `WebContents`.

A per-`WebContents` key would add nothing: the cases that change `tab_id`
(prerender into a new tab, a discard that replaces the contents) also create a
new `WebContents`.

### Loader kind

Byte 141 of the envelope, formerly reserved, is the request's loader kind. It
is nonzero only on network `request_started` (browser, 1 to 10) and
`request_initiated` (renderer, 16 to 21). JSON carries it as `loader_kind`,
written only when nonzero.

| Value | Kind | Meaning |
| ---: | --- | --- |
| 1 | `navigation` | Browser factory kinds, `URLLoaderFactoryType` + 1 |
| 2 | `download` | |
| 3 | `document_subresource` | |
| 4 | `worker_main_resource` | |
| 5 | `worker_subresource` | |
| 6 | `service_worker_script` | |
| 7 | `service_worker_subresource` | |
| 8 | `prefetch` | |
| 9 | `devtools` | |
| 10 | `early_hints` | |
| 16 | `document` | Renderer: the fetch's own `FetchContext` is a document; `frame_id` is its frame |
| 17 | `dedicated_worker` | Renderer: `frame_id` is the fold of the `DedicatedWorkerToken` |
| 18 | `shared_worker` | `frame_id` is the fold of the `SharedWorkerToken` |
| 19 | `service_worker` | `frame_id` is the fold of the `ServiceWorkerToken` |
| 20 | `other_context` | A worklet or shadow realm; not linked |
| 21 | `script_context` | No fetch context reached the loader; `frame_id` is the running script's frame, as before #425 |

A fold is `rotl(high, 17) ^ low` of the 128-bit token, the same function as
frame ids.

### Where the owner comes from

| Request | Owner | Hook |
| --- | --- | --- |
| Browser record from a frame's factory (document, navigation, a download's frame, a document-created worker's main script, a speculation-rules prefetch's referring frame) | The tab of the factory's frame, resolved when `WillCreateURLLoaderFactory` creates the factory | Brave patch `0017-link-requests-to-tab-owners`. A beacon, keepalive fetch or removed iframe keeps the tab its factory recorded. Redirects stay in the same loader |
| Renderer `request_initiated` | The fetch's `FetchContext`, never the running script | Chromium patch `0027-record-renderer-fetch-owners`: `ResourceLoader` and `BackgroundURLLoader` scope the owner around `ResourceRequestSender::SendAsync`. Parser, preload scanner, CSS and image loads therefore name their document |
| Renderer document record drained late | The browser's frame registry, keyed by process and full frame token, filled at factory creation and from live frames, with tombstones that outlive the frame | `browser/native_tab_resolver.h` |
| Dedicated and nested workers | The creator document's tab, resolved at `DedicatedWorkerService::Observer::OnWorkerCreated` through the creator chain | `request_tab_link` kind 1 |
| Shared workers | Every client tab at request start (`SharedWorkerService::Observer::OnClientAdded` / `OnClientRemoved`) | kind 2 |
| Service workers | The controlled client tabs (`ServiceWorkerContextObserver::OnControlleeAdded` / `OnControlleeRemoved`); with none, the registration's last client tabs | kinds 3 and 4 |
| Page request a service worker answers | The page's document (renderer record) plus the renderer completion above | |
| Browser record from a worker factory | Joined to its renderer record (same row) through `initiator_process_id` and `initiator_request_id` | |

`NativeWorkerAuthority` is not used: it holds one selected document's workers
for source transfer under a lease, while tab links need every worker of the
session.

### `tab_set` (type 37)

Category `network`, browser sequence space. A set is immutable; when a worker's
client tabs change, the next link names a new set id. A set is emitted before
the first link that names it in a session. Envelope: `tab_id` the first tab of
this part, `frame_id` the owner's fold, `parent_event_id` the previous part's
sequence for a part after the first, else 0. Request, initiator, BrowserContext,
lengths, status, error, resource type, scheme class, loader kind and flags are
zero. Payload size 128, little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | owner kind: loader kind 17, 18 or 19 |
| 5 | 1 | flags: bit 0 `last_clients`, the owner had no client and these were its last |
| 6 | 2 | part index |
| 8 | 8 | set id, nonzero |
| 16 | 4 | tabs in the whole set, nonzero |
| 20 | 2 | tabs in this part, 1 to 26 |
| 22 | 2 | reserved, zero |
| 24 | 104 | 26 tab id slots, `uint32`; used slots nonzero and ascending, the rest zero |

Part `i` holds tabs `26*i` onward, so a set of `n` tabs has `ceil(n/26)` parts
and no fixed limit. A consumer that lacks a part knows from the counts; the
queue already reported the drop.

### `request_tab_link` (type 38)

Category `network`, browser sequence space. One fixed-size record links one
renderer `request_initiated` to a tab set. Envelope: `initiator_process_id` and
`initiator_request_id` are the linked record's process and request id,
`parent_event_id` its sequence (in that process's space), `frame_id` its frame,
time its time. `tab_id` is the set's tab when the set has one, else 0.
`request_id`, BrowserContext, lengths, status, error, resource type, scheme
class, loader kind and flags are zero. Payload size 24:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `24` |
| 4 | 1 | link kind |
| 5 | 3 | reserved, zero |
| 8 | 8 | set id, nonzero |
| 16 | 4 | tabs in the set, nonzero |
| 20 | 4 | reserved, zero |

| Kind | Name | Tabs |
| ---: | --- | --- |
| 1 | `dedicated_worker` | The document that created the worker, through nested workers |
| 2 | `shared_worker_clients` | Every client tab when the request started |
| 3 | `service_worker_clients` | The controlled client tabs |
| 4 | `service_worker_last_clients` | No current client; the registration's last client tabs, which may be closed |

### Traffic no tab caused

Excluded at capture by default and counted like browser-internal exclusions:

| Class | Name | Unit | Counted by |
| ---: | --- | --- | --- |
| 65 | `extension_worker` | requests | The drain, per renderer, for a renderer record whose owner is an extension worker; the proxy, browser-wide, for a worker main script or service-worker script it fetches for a `chrome-extension` context. The proxy also leaves out the renderer-issued requests of such a context, which the drain counts |
| 66 | `devtools_load` | requests | The proxy, browser-wide, for the DevTools factory |

Content-script requests use their page's document factory and stay with that
tab. Extension pages (background page, popup, options) are their own
`WebContents` and are named by their page like any tab.

### Unresolved requests

A row (records joined as in Traffic) is unresolved when none of its records
has a nonzero `tab_id` and no `request_tab_link` names it. `get_session_summary`
reports `request_tabs` (rows, unresolved rows and up to 16 of them by process
and request id) and the error check `network_tab_unresolved`. Traffic shows the
count in its footer; the button lists those rows. They are never hidden.

Not linked yet, so unresolved: the browser's own service-worker main-script
and update-check fetches (`service_worker_script` with no frame), a nested
dedicated worker's main script (its factory has no creator frame), a
browser-initiated prefetch, worklet requests, and a worker whose creator or
clients were gone before capture started. Early-hints preloads never reach the
proxy at the pin (`NavigationRequest` creates their factory without
`ContentClientParams`), so they are not recorded at all.

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
- Tabs, inactive: the loaders' owner scope and the proxy's factory hook add at
  most one atomic load and allocate nothing. Active: one virtual
  call and a thread-local write per load, one registry insert per factory, and
  for worker requests one link record, plus one `tab_set` per new set. The
  resolver keeps at most 16,384 frames and 4,096 workers, versions and clients
  per worker, evicting the oldest; an evicted owner leaves its later records
  unresolved, which the summary reports.

## Consumers

- The broker validates both the scheme class and type 36 in `IsValidEvent`,
  and the loader kind and types 37 and 38.
- `get_session_summary` lists `exclusions` by class and adds the info checks
  `browser_internal_excluded` and `no_tab_traffic_excluded`, `request_tabs`,
  and the error check `network_tab_unresolved`. The backend keeps types 36 to
  38 in its network window.
- Traffic has no Unattributed group. A row is in every tab its records or link
  name, with a marker such as "Service worker · 2 tabs"; All tabs counts it
  once. Each chip is named by the tab's newest main-frame navigation. The
  footer counts rows without a tab as a capture error and its button lists
  them.
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
checks the browser `request_started` scheme class and loader kind.

`tests/tab_link_test.cpp` checks loader kinds, tab sets and links for parity
and malformed records; `make tab-link-wire-check` compares them with the Python
validator and `request_tabs.js`, then drives Traffic rows through multi-tab,
incomplete-set, unlinked and page-name cases. `make
native-artifact-capture-check` drives the real `NativeProbeHost` drain and
`NativeTabResolver` through tombstoned frames, nested dedicated workers, shared
worker clients, a service worker with 30 clients, last clients and extension
workers. `make native-probe-admission-check` covers the renderer fetch owner.

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
5. With Brave patch `0017-link-requests-to-tab-owners` and Chromium patch
   `0027-record-renderer-fetch-owners`, run the #425 fixture site:
   `get_session_summary` reports no `network_tab_unresolved` beyond the
   unlinked cases listed under [Unresolved requests](#unresolved-requests), and
   each request lands on its tab.
