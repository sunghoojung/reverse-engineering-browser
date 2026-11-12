# Native network observations v3

Status: implemented source candidate. The overlay and patches compile against
portable harnesses of the pinned Chromium types; patched Brave compilation and
a live run are still required. Each part ends with its acceptance list.

This version is shared by the Traffic, Sources and debugger parity issues
(#435). [Startup v1](native-network-startup-v1.md) and
[network v2](native-network-v2.md) keep their records; nothing here changes a
stored v1 or v2 meaning. [SAFETY.md](../SAFETY.md) governs capture and export.

## Numbering

| Item | Value | Part |
| --- | --- | --- |
| Event type 30, 31 | `request_headers`, `response_headers` | Headers and cookies |
| Event type 32 | `cookie_list` | Headers and cookies |
| Event type 33 | `response_body` | Response bodies |
| Event type 34, 35 | `request_initiator_stack`, `script_identity` | Request initiator stacks |
| Event type 36 | `capture_exclusion` | Request scope and tabs |
| Event type 37, 38 | `tab_set`, `request_tab_link` | Request scope and tabs |
| Event type 39 | `script_cookie` | Headers and cookies |
| Event type 40 to 45 | debugger observations | [Debugger observation v1](native-debugger-observation-v1.md) |
| Event type 46, 47 | `navigation_initiator_stack`, `navigation_initiator_link` | Navigation and async task callers |
| Event type 48 | `async_task_stack` | Navigation and async task callers |
| Event type 50 | `request_extension_link` | Request scope and tabs |
| Envelope byte 140, 141 | `scheme_class`, `loader_kind` | Request scope and tabs |
| Artifact kind 9 | `request_target` | [Network v2](native-network-v2.md) |
| Artifact kind 10, 11 | `request_headers`, `response_headers` | Headers and cookies |
| Artifact kind 12 | `cookie_list` | Headers and cookies |
| Artifact kind 13 | `stack` | Request initiator stacks |
| Capture origin 12, 13 | `request_stack`, `stack_script` | Request initiator stacks |
| Brave patch 0017 | `link-requests-to-tab-owners` | Request scope and tabs |
| Brave patch 0018 | `capture-native-network-headers` | Headers and cookies |
| Brave patch 0019 | `tee-native-request-bodies` | Request body reads |
| Brave patch 0020 | `scope-native-proxy-factories` | Request scope and tabs |
| `request_body` flag bit 6, state 12 | `read`, `not_captured_read_incomplete` | Request body reads |
| Chromium patch 0025 | `forward-native-network-headers` | Headers and cookies |
| Chromium patch 0026, 0027 | `finish-renderer-answered-requests`, `record-renderer-fetch-owners` | Request scope and tabs |
| Chromium patch 0028 | `record-script-cookie-access` | Headers and cookies |
| Chromium patch 0029 | `record-request-initiator-stacks` | Request initiator stacks |
| Chromium patch 0035, 0036 | `expose-process-lock-scheme`, `name-frameless-script-fetch-owners` | Request scope and tabs |
| V8 patch 0015 | `capture-native-request-stacks` | Request initiator stacks |
| Chromium patch 0034 | `record-navigation-and-async-initiators` | Navigation and async task callers |
| V8 patch 0017 | `bound-native-async-task-stacks` | Navigation and async task callers |
| Chromium patch 0046 | `record-worker-request-stacks` | Request initiator stacks |
| Chromium patch 0047 | `carry-message-task-origins` | Navigation and async task callers |
| Chromium patch 0048 | `record-promise-registration-stacks` | Navigation and async task callers |
| V8 patch 0021 | `record-native-promise-registrations` | Navigation and async task callers |

Traffic detail tabs, in order: General, Headers, Payload, Preview, Response,
Cookies, Initiator, Timing, Signals, Evidence.

## Request scope and tabs

Defined by #424 (request scope, counted browser-internal exclusions,
completion of requests the browser proxy never sees) and #425 (the tab that
caused each request).

### Scheme class

Byte 140 of the v3 320-byte envelope, formerly reserved, is the request's
scheme class. Byte 141 is the [loader kind](#loader-kind); bytes 142 and 143
stay reserved and zero. JSON carries it as
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

### Browser-internal exclusion

Browser-internal evidence is not recorded by default, and every exclusion is
counted:

- A renderer counts a request with a class 16 to 20 instead of recording it.
  One counter per class lives in the shared probe queue (queue version 3), like
  the drop counter, and the browser reports it at the next drain.
- The browser proxy counts, browser-wide, a request whose URL has a class 16 to
  20 from a factory the renderer does not issue requests through. WebUI
  navigations reach it at the pin: `NavigationURLLoaderImpl::Start` creates the
  WebUI scheme factory through `ContentClientParams`, which calls
  `WillCreateURLLoaderFactory`.
- `NativeProbeSession::BindHost` does not admit a WebUI renderer: a process
  with WebUI bindings (`ChildProcessSecurityPolicy::HasWebUIBindings`) or one
  whose process lock site URL has a class 16 to 20. `chrome-untrusted:` and
  `devtools:` renderers have no bindings, so Chromium patch
  `0035-expose-process-lock-scheme` adds
  `ChildProcessSecurityPolicy::GetProcessLockScheme`; the lock is set before
  the renderer starts, and `ProcessLock` is content-internal at the pin. A
  process granted bindings after it bound is detached at its next drain; the
  records it queued are discarded with it. Each such process counts once. Its
  script artifacts, fingerprint events and requests are therefore absent.
- The proxy counts, browser-wide, every request a WebUI renderer sends through
  a document, worker or service-worker subresource factory, or a worker main
  script it creates (class 67). A navigation is never excluded by the frame
  that starts it, so a site opened from the new tab page keeps its first
  document.
- Native Console targets are http(s) frames listed from every render process
  and reach their agents through frame interfaces, so they do not depend on
  probe admission.
- `REB_CAPTURE_BROWSER_INTERNAL=1` makes the live launcher pass
  `--reb-capture-browser-internal`, which turns these exclusions off for that
  browser. Sessions started by `reb-api session start` or `start_live_session`
  always set it to 0.

Traffic no tab caused has its own classes, defined in
[Request owners and tabs](#traffic-no-tab-caused).

#### `capture_exclusion` (type 36)

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
`webui_renderer` counts renderer processes that were not admitted, and class 67
`webui_request` the requests such processes sent through the proxy; both have
`initiator_process_id` 0. Classes 65 `extension_worker` and 66
`devtools_load` count requests (see [below](#traffic-no-tab-caused)). The count is cumulative within the session for
one `(initiator_process_id, class)`, so a later record supersedes an earlier
one and a lost record loses nothing that a later one reports. Consumers take
the newest count per producer and class and sum by class. An exclusion is
neither a sequence gap nor a queue drop.

### Requests answered in the renderer

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

A synchronous XHR outside `data:` is issued on a Blink pool thread:
`ResourceRequestSender::SendSync` posts `SendAsync` there and blocks the main
thread until it returns. No fetch owner scope and no document main thread reach
that send, so its `request_initiated` carries frame 0 and loader kind
`script_context`, and its `request_initiator_stack` state is
`unsupported_thread`. The owner scope in `RequestSynchronously` only names the
owner of a `data:` URL, which Blink answers on the main thread.

### Request owners and tabs

Every request record names the tab that caused it. A row without a tab is a
capture error (`network_tab_unresolved`), never a catch-all group. Owners are
resolved where Chromium knows them and carried with the record; no tab is ever
assigned by host, URL or timing.

#### Tab identity

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

#### Loader kind

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

#### Where the owner comes from

| Request | Owner | Hook |
| --- | --- | --- |
| Browser record from a frame's factory (document, navigation, a download's frame, a document-created worker's main script, a speculation-rules prefetch's referring frame) | The tab of the factory's frame, resolved when `WillCreateURLLoaderFactory` creates the factory | Brave patch `0017-link-requests-to-tab-owners`. A beacon, keepalive fetch or removed iframe keeps the tab its factory recorded. Redirects stay in the same loader |
| Renderer `request_initiated` | The fetch's `FetchContext`, never the running script | Chromium patch `0027-record-renderer-fetch-owners`: `ResourceLoader` and `BackgroundURLLoader` scope the owner around `ResourceRequestSender::SendAsync`. Parser, preload scanner, CSS and image loads therefore name their document |
| Renderer document record drained late | The browser's frame registry, keyed by process and full frame token, filled at factory creation and from live frames, with tombstones that outlive the frame | `browser/native_tab_resolver.h` |
| Dedicated and nested workers | The creator document's tab, resolved at `DedicatedWorkerService::Observer::OnWorkerCreated` through the creator chain | `request_tab_link` kind 1 |
| Shared workers | Every client tab at request start (`SharedWorkerService::Observer::OnClientAdded` / `OnClientRemoved`) | kind 2 |
| Service workers | The controlled client tabs (`ServiceWorkerContextObserver::OnControlleeAdded`, `OnControlleeNavigationCommitted` for window clients, `OnControlleeRemoved`); with none, the registration's last client tabs | kinds 3 and 4 |
| Page request a service worker answers | The page's document (renderer record) plus the renderer completion above | |
| Browser record from a worker factory | Joined to its renderer record (same row) through `initiator_process_id` and `initiator_request_id` | |
| Nested dedicated worker main script | Its factory has no creator frame; `WorkerScriptFetcher::CreateScriptLoader` scopes the ancestor frame, the document at the root of the creator chain, around the factory's creation | Chromium patch `0036-name-frameless-script-fetch-owners` |
| Service-worker main script and update check | `ServiceWorkerRegisterJob` scopes its `requesting_frame_id_` (the `register()` caller) and the registration's active version around both factory creations. The caller's tab is the factory's tab; without one, each request links to that version's client tabs, which hold the tab whose navigation hinted the update | Patch 0036; `request_tab_link` kinds 3 and 4 naming the browser record |

In a capture launch the proxy observes the owned profile's frames and worker
services from its first factory, before any session starts, and fixes each
factory's exclusion class when it is created, so owners and excluded factories
that predate the session still resolve.

The scoped owner is read by the proxy while `WillCreateURLLoaderFactory` runs
and only for a factory without a frame. A navigation's update hint
(`ServiceWorkerClient::HintToUpdateServiceWorker`) reaches
`ServiceWorkerVersion::ScheduleUpdate`, a coalescing one-second timer that
keeps no client, so the hinting tab itself is not carried; it is a controllee
of the active version and so in the linked set.

`NativeWorkerAuthority` is not used: it holds one selected document's workers
for source transfer under a lease, while tab links need every worker of the
session.

#### `tab_set` (type 37)

Category `network`, browser sequence space. A set is immutable; when a worker's
client tabs change, the next link names a new set id. A set is emitted before
the first link that names it in a session. Envelope: `tab_id` the first tab of
this part, `frame_id` the owner's fold (0 for a service-worker version that has
not run in this browser), `parent_event_id` the previous part's sequence for a
part after the first, else 0. Request, initiator, BrowserContext,
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

#### `request_tab_link` (type 38)

Category `network`, browser sequence space. One fixed-size record links one
request record to a tab set. A renderer `request_initiated` is named by
`initiator_process_id` and `initiator_request_id` (its process and request id),
with `request_id` and BrowserContext zero. A browser record that has no
renderer request (a service-worker script) is named by its `request_id` and
BrowserContext, with both initiator fields zero. `parent_event_id` is the
record's sequence (in its producer's space), `frame_id` its frame, time its
time. `tab_id` is the set's tab when the set has one, else 0. Lengths, status,
error, resource type, scheme class, loader kind and flags are zero. Payload
size 24:

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

#### `request_extension_link` (type 50)

Category `network`, browser sequence space, recorded only with the
[extension opt-in](#traffic-no-tab-caused). One fixed-size record names the
extension whose context made one request. The envelope names the record as
`request_tab_link` does; `tab_id` is 0. Payload size 40:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `40` |
| 4 | 1 | the record's loader kind: 4 or 6 for a browser record, 17 to 19 for a renderer one |
| 5 | 3 | reserved, zero |
| 8 | 32 | extension id, 32 ASCII letters `a` to `p` |

A row named by such a link has an owner and is not unresolved.

#### Traffic no tab caused

Excluded at capture by default and counted like browser-internal exclusions:

| Class | Name | Unit | Counted by |
| ---: | --- | --- | --- |
| 65 | `extension_worker` | requests | The drain, per renderer, for a renderer record whose owner is an extension worker; the proxy, browser-wide, for a worker main script or service-worker script it fetches for a `chrome-extension` context. The proxy also leaves out the renderer-issued requests of such a context, which the drain counts |
| 66 | `devtools_load` | requests | The proxy, browser-wide, for the DevTools factory |

`REB_CAPTURE_EXTENSION_TRAFFIC=1` makes the live launcher pass
`--reb-capture-extension-traffic`; class 65 is then recorded instead of
counted, each request with one `request_extension_link`: the drain links an
extension worker's renderer record, the proxy a worker main script or
service-worker script it fetches. An extension origin whose host is not a valid
id stays counted. Sessions started by `reb-api session start` or
`start_live_session` always set it to 0.

Content-script requests use their page's document factory and stay with that
tab. Extension pages (background page, popup, options) are their own
`WebContents` and are named by their page like any tab.

#### Unresolved requests

A row (records joined as in Traffic) is unresolved when none of its records
has a nonzero `tab_id` and no `request_tab_link` or `request_extension_link`
names it. `get_session_summary`
reports `request_tabs` (rows, unresolved rows and up to 16 of them by process
and request id) and the error check `network_tab_unresolved`. Traffic shows the
count in its footer; the button lists those rows. They are never hidden.

Not linked yet, so unresolved: a service-worker script fetch with neither a
`register()` caller nor an active version with a client tab this browser saw
(a browser-initiated registration, or an update while no client was ever
controlled), a browser-initiated prefetch, worklet requests, and a worker whose
creator or clients were gone before capture started. Early-hints preloads never reach the
proxy at the pin (`NavigationRequest` creates their factory without
`ContentClientParams`), so they are not recorded at all.

### Hot path and bounds

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
- The proxy fixes a factory's scope once, when Chromium creates it: a
  command-line read and, for a frameless factory, the scoped owner. Each
  request then costs one classification of its scheme. Admission reads the
  process lock once per bind and drain.

### Consumers

- The broker validates both the scheme class and type 36 in `IsValidEvent`,
  and the loader kind and types 37, 38 and 50.
- `get_session_summary` lists `exclusions` by class and adds the info checks
  `browser_internal_excluded` and `no_tab_traffic_excluded`, `request_tabs`
  (with `extension_rows`), and the error check `network_tab_unresolved`. The
  backend keeps types 36 to 38 and 50 in its network window.
- Traffic has no Unattributed group. A row is in every tab its records or link
  name, with a marker such as "Service worker · 2 tabs"; All tabs counts it
  once. Each chip is named by the tab's newest main-frame navigation; extension
  traffic gets one chip per extension id. The footer counts rows without an
  owner as a capture error and its button lists them.
- Traffic shows "N browser-internal requests not recorded" in its footer, names
  hostless rows by scheme (`data:`), and joins renderer targets and completions
  to their row. A reversible "Hide browser-internal" filter in Traffic and
  Sources hides class 16 to 20 rows, internal-scheme sources, and, for
  evidence recorded before scheme classes, renderer-only rows whose host is one
  bare label. It shows the hidden count and never changes stored evidence.

### Validation

`tests/network_scope_test.cpp` (in `make native-tests`) checks overlay and core
layout parity, every class and many malformed records, and `make
network-scope-wire-check` compares those verdicts with the Python validator
and the shipped readers, then drives the Traffic model through `data:`,
service-worker, opted-in internal and pre-v3 rows.
`make native-probe-admission-check` drives the real renderer sink and
transport through exclusion counting, opt-in, renderer completion, stale and
refused starts and the inactive path. `make native-network-capture-check`
checks the browser `request_started` scheme class and loader kind, and the
factory scope: which proxy loads are counted where, and the links a frameless
service-worker script carries.

`tests/tab_link_test.cpp` checks loader kinds, tab sets and links for parity
and malformed records; `make tab-link-wire-check` compares them with the Python
validator and `request_tabs.js`, then drives Traffic rows through multi-tab,
incomplete-set, browser-record, extension, unlinked and page-name cases. `make
native-artifact-capture-check` drives the real `NativeProbeHost` drain and
`NativeTabResolver` through tombstoned frames, nested dedicated workers, shared
worker clients, a service worker with 30 clients, last clients, counted and
opted-in extension workers, and renderers locked to an internal scheme. `make
native-probe-admission-check` covers the renderer fetch owner.

### Acceptance

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
5. With Brave patches `0017-link-requests-to-tab-owners` and
   `0020-scope-native-proxy-factories` and Chromium patches
   `0027-record-renderer-fetch-owners` and
   `0036-name-frameless-script-fetch-owners`, run the #425 fixture site:
   `get_session_summary` reports no `network_tab_unresolved` beyond the
   unlinked cases listed under [Unresolved requests](#unresolved-requests), and
   each request lands on its tab, including a nested worker's main script and
   a service worker's registration and update-check fetches.
6. The new tab page's own https requests count as `webui_request`, and a
   `chrome-untrusted:` frame and an open DevTools window add `webui_renderer`
   processes and no scripts to Sources (Chromium patch
   `0035-expose-process-lock-scheme`).
7. With `REB_CAPTURE_EXTENSION_TRAFFIC=1` and an installed extension that
   fetches from its service worker, those requests appear under its extension
   chip and `extension_rows` counts them; without it they count as
   `extension_worker`.

## Response bodies

Defined by #428. It adds one child record, type 33 `response_body`, and
produces the existing sensitive artifact kind 4 `response_body`.

### Capture

Response bodies follow the request content gate of v2: only sessions started
with `--reb-capture-request-content` (`REB_CAPTURE_REQUEST_CONTENT=1`) with the
Network and Artifact categories. Metadata-only sessions record no
`response_body` record and tee nothing new.

The existing proxied-loader tee (`patches/0002`, `patches/0013`) is the only
capture path. `NativeArtifactCaptureSink::MaybeCaptureResponse` keeps scripts
and Wasm as before, in every artifact session, and hands every other response
to `browser/native_response_body_capture.cc`:

- Kept by default: documents, JSON, text, XML, fetch and XHR responses, and any
  other subresource.
- Skipped unless `--reb-capture-response-media` (`REB_CAPTURE_RESPONSE_MEDIA=1`):
  fonts and media (resource types 5 and 8, `font/*`, `audio/*`, `video/*`, font
  application types), and images that page elements load (resource types 4 and
  12, `image/*` except `image/svg+xml`). A fetch or XHR image is kept.
- The tee forwards decoded bytes, so the artifact holds the decoded body. The
  record keeps the `Content-Encoding` codings as sent and flags bodies Chromium
  left encoded for client-side decoding.
- The source pipe closing does not prove a whole body. The loader's completion
  status decides: an error is `aborted`, `net::ERR_ABORTED` or the page closing
  its pipe is `cancelled`. A body whose completion never arrives is kept after
  10 s and flagged.
- Bytes stream to the receiver as they arrive
  ([artifact channel v2](../docs/architecture/artifact-transfer-channel.md#streamed-artifacts-version-2)).
  A body without a declared length that is still open after a second is
  published as `partial` by a receiver checkpoint of what arrived when it has
  grown by half since the last one, at most 15 times, so snapshots stay within
  three times the body. Open bodies at capture end or expiry end their stream
  as one last `partial` record, or `not_captured_artifact_unavailable` when no
  byte has arrived. The record of the ended body supersedes every snapshot.

### `response_body` (type 33)

Category `network`, the v2 child envelope (flags 0, payload size 128,
navigation, status, error, transfer sizes and resource type zero, the parent's
identity, `parent_event_id` below its own sequence). The parent is the
`response_started` record, or the `request_redirected` record for state 8. Its
time is when the body ended or was snapshotted. Little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | state |
| 5 | 1 | flags |
| 6 | 1 | content type length, 0 to 64 |
| 7 | 1 | coding count, 0 to 4 |
| 8 | 8 | body length: decoded bytes that passed the tee, so far for `partial` |
| 16 | 8 | captured length: bytes in the named artifact |
| 24 | 4 | codings, one byte each in `Content-Encoding` order, zero after the count |
| 28 | 2 | partial index: n for the n-th snapshot, else 0 |
| 30 | 2 | reserved, zero |
| 32 | 32 | SHA-256 of the captured bytes, or zero |
| 64 | 64 | normalized content type, as in v2, zero padded |

| State | Meaning |
| ---: | --- |
| 1 `captured` | The whole body is the named artifact |
| 2 `captured_truncated` | The first 16 MiB are the named artifact |
| 3 `partial` | The body is still open; the artifact is what arrived so far |
| 4 `aborted` | The network failed before the end; any bytes that arrived are the artifact |
| 5 `cancelled` | The page or browser stopped the request; any bytes that arrived are the artifact |
| 6 `empty` | The body ended with zero bytes, or the loader sent no body |
| 7 `not_modified` | HTTP 304; no body |
| 8 `redirected` | A redirect hop; Chromium discards its body |
| 9 `not_captured_type` | Media or a font, not asked for |
| 10 `not_captured_artifact_unavailable` | Artifact category off, receiver disconnected or session inactive |
| 11 `not_captured_transfer_refused` | The in-flight pool, the tee or the artifact queue refused it |
| 12 `not_captured_session_budget` | The session's response body budget was used |

Flags: bit 0 `shared`, identical bytes were already retained in this
configuration and `artifact_id` names that earlier artifact; bit 1 served from
the HTTP cache; bit 2 served by a service worker; bit 3 bytes still encoded
(client-side decoding); bit 4 more than four codings, the rest not recorded;
bit 5 completion not observed; bit 6 content type present. Other bits are zero.

Codings: 1 `gzip` (and `x-gzip`), 2 `deflate`, 3 `br`, 4 `zstd`, 5 `dcb`,
6 `dcz`, 7 `compress`, 15 any other token. `identity` is not a coding.

Rules, shared by the C++ core, the Python evidence validator and the Origin
Trace decoder (`make network-request-wire-check`):

- `artifact_id` is nonzero, the digest nonzero and the captured length nonzero
  all together, or none of them. `shared` needs an artifact.
- Captured length is at most body length. With L = min(body length, 16 MiB):
  state 1 has captured equal to a nonzero body length; state 2 has a body over
  16 MiB and captured 16 MiB; state 3 has a nonzero body and captured L;
  states 4 and 5 have captured 0 or L; states 6 to 9 have body length 0;
  states 10 to 12 have no artifact.
- Partial index is nonzero exactly for state 3. Bit 5 only with states 1, 2
  and 6. Bit 4 only with four codings. Coding bytes follow the coding count.
- Content type: bit 6 if and only if the length is nonzero, normalized as in
  v2, zero after its length. Reserved bytes are zero.

### Response body artifact

Kind 4 `response_body`, capture origin 1 `network_response`, always sensitive,
execution context 0. Its `creator_event_id` is the `response_started` record,
the same join as script artifacts: by `request_id` and creator, never by URL. A
shared record's artifact keeps its first creator. The manifest URL is the
request's scheme, host, explicit port, path and query, or its origin past
8 KiB; the MIME type is Chromium's, or `application/octet-stream`. The ACK
becomes `artifact_captured` or `artifact_capture_failed` with the creator as
`parent_event_id`. Script and Wasm responses keep kinds 1 and 2 and get no
`response_body` record unless the artifact channel is unavailable.

The receiver still refuses the kind without `--allow-sensitive`, which the
launcher passes for content sessions.

### Bounds

- Disabled: unchanged; every sink returns at its emitter load. Metadata-only:
  one relaxed load per response start, completion and untyped body.
- Each open body holds at most one pending 64 KiB data frame, plus frames the
  writer has not yet sent, in the 32 MiB in-flight pool it shares with scripts
  and request content; a declared length reserves nothing. A full pool or a
  refused frame is state 11, never a stall.
- At most 16 MiB per body. Past it the tee keeps the prefix and counts every
  byte.
- SHA-256 grows by at most one 64 KiB tee read per task, so the record carries
  the digest when the body ends; the receiver verifies it.
- Unique bytes per session are budgeted: 512 MiB by default, 1 MiB to 16 GiB
  with `--reb-response-body-budget-bytes` (`REB_RESPONSE_BODY_BUDGET_MIB`).
  A body is charged when it ends, once its digest is known: identical bytes
  are stored once by SHA-256 and charge nothing (the repeat stream is aborted),
  each snapshot is charged, and a receiver refusal refunds them. The launcher grows a content session's receiver store
  by both budgets.
- Every refusal is a named state. The session summary counts states 2 and 9 to
  12 under `request_content_not_retained`, category `response_body`.

### Bodies the proxy never sees

Service-worker and memory-cache answers and requests that failed before a
response have no browser `response_started`, so they have no `response_body`
record. Traffic says the proxy recorded no response for them; it never shows
an empty body.

### Agent access

Bytes are read with `get_artifact_content`; `get_events` with
`type=response_body` and `request_id` names the artifact. MCP keeps its rules:
binary is refused and oversized JSON returns a structural summary.

### Consumers

- The broker validates type 33 in `IsValidEvent`; a rejected record is a
  visible sequence gap. The backend keeps it in its network window, and trace
  steps name it instead of decoding it as text.
- Origin Trace joins the newest record whose parent is the request's final
  `response_started` in the Preview and Response tabs (order above). Response
  shows the state, codings, lengths and digest, then the bytes as
  syntax-colored text with pretty print, wrap, find, copy and hex (always hex
  for binary). Preview shows a bounded
  JSON tree, a raster image whose signature matches its bytes, plain text, or
  markup as source. HTML and SVG are never rendered. Reads are ranged 2 MiB at a
  time and rechecked by size and SHA-256.

### Validation

`make native-artifact-capture-check` drives the real network sink, artifact
sink, response capture and production receiver and broker: JSON, gzip HTML,
brotli and service-worker JSON, a fetched PNG, a chunked stream partial then
captured, an aborted prefix, 304, a redirect, a cancelled body, a skipped font,
digest dedupe, budget exhaustion, receiver refusal refund, 50 parallel bodies,
the full pool, 16 MiB truncation, a missing completion, coding order, the
capture-end partial, media opt-in, metadata-only sessions and tee refusal.
`make native-network-capture-check` covers the redirect and unavailable records.
`tests/network_request_test.cpp` checks layout parity and every valid and
malformed record. `tools/check-traffic-response-ui.mjs` and
`make rendered-ui-check` cover the tabs.

### Acceptance

Still required before declaring this browser-ready:

1. Replay all stacks and overlays on a disposable initialized pinned checkout,
   run `make brave-doctor` and `make brave-probe-check`, and compile the
   browser target. No patch changed.
2. With an authorized fixture, compare server bytes with retained artifacts for
   JSON, HTML, an image, gzip and brotli, a chunked response, server-sent
   events, an aborted download, a 304, a redirect and a service-worker-served
   response; load 50 responses in parallel; exhaust a small budget; and watch
   browser memory stay within the pool.

## Request body reads

Defined by #436 and #428. In content sessions a `request_body` (type 22) whose
parts include a file, blob or stream is read instead of only described, and is
retained as a `request_body` artifact with exact bytes and digest.

### Read

- Brave patch 0019 calls `NativeNetworkCaptureSink::TeeRequestBody` right after
  `AssignNetworkHeadersId`. `browser/native_request_body_reader.cc` then reads
  the parts in order on its own background sequence. In-memory parts are
  copied; file parts are read only while unchanged since the page attached them
  (offset, length and expected modification time, as the network service
  checks); blob parts are read through a clone of their getter, so the request
  keeps its own.
- A stream part (`fetch` with a `ReadableStream` body) can be consumed only
  once, so its getter is replaced by one that forwards the size and every byte
  unchanged to the network through a tee. That getter is the only change to the
  request, and the upload is never delayed: a full pool ends the read, not the
  upload.
- Bytes stream to the receiver as they are read. Past 16 MiB a part is sized,
  not read.
- The record is emitted when the read ends, still the child of
  `request_started`; its end frame names it as the artifact's creator. A body
  never handed to the reader (no hook) is recorded as `not_captured_body_kind`
  at the next request start or capture end.

### Record

Payload version 1. Bit 6 `read` marks a body the browser read; it needs bit 0
and kind 2 to 5 (a stream has one element). With bit 6:

| State | Rule |
| ---: | --- |
| 2 `empty` | Length 0, digest of nothing, bit 3 clear |
| 4 `captured` | Exact length up to 16 MiB, captured equal, digest present, bit 3 clear, artifact |
| 5 `captured_truncated` | Exact length over 16 MiB, captured 16 MiB, bit 2, bit 3 clear, artifact |
| 8 `not_captured_transfer_refused` | The pool or queue refused it while reading; bit 3 set |
| 10 `not_captured_session_budget` | The read passed its budget allowance; bit 3 set |
| 12 `not_captured_read_incomplete` | A part changed or failed, the upload was cancelled, capture ended, the body started within the last 250 ms before expiry so it was not read, or the requesting renderer may not read a named file (`ChildProcessSecurityPolicy::CanReadFile`, the check the network service's upload path makes); bit 3 set |

For states 8, 10 and 12 the length counts what was read; no digest and no
artifact. Without bit 6, kinds 2 to 5 may also carry states 7 to 10 when the
read was refused before it started, and state 12 is invalid. Every other v2 rule
is unchanged.

### Bounds

- Disabled and metadata-only: unchanged; nothing is read.
- A read charges `min(16 MiB, remaining budget)` of the request-content budget
  when it starts and settles to its unique bytes when it ends, so parallel reads
  cannot pass the budget together.
- Each read holds at most one pending 64 KiB data frame in the in-flight pool.
  A file or blob read waits for pool space, about 5 s at most, then is state 8.

### Consumers and validation

The C++ core, the Python validator and the Traffic decoder share the rules
(`make network-request-wire-check`); Traffic names state 12 and read lengths;
the session summary counts state 12 under `request_content_not_retained`.
`make native-network-capture-check` covers the deferred record, the hook and
refusals. `make native-artifact-capture-check` retains a multipart upload with a
file and a stream-body `fetch` with exact bytes and digest through the
production receiver and broker, and covers the 16 MiB prefix, the budget
allowance, a stuck pool, incomplete and empty reads, capture end and a missing
hook. The reader's Mojo and file glue compiles only in a Brave build.

### Acceptance

Still required: replay all stacks, compile the browser target, and with an
authorized fixture compare server receipts with retained artifacts for a
multipart upload with a file, a `Blob` upload, a stream-body `fetch` and a file
changed after it was attached.

## Headers and cookies

Defined by #427 (headers) and #430 (cookies): four records and three sensitive
artifact kinds.

### Capture level

Header blocks carry credentials (`Authorization`, `Cookie`, `Set-Cookie`), so
they use the request-content gate of v2 (`--reb-capture-request-content`,
`REB_CAPTURE_REQUEST_CONTENT=1`, agent `request_content` with
`confirm_sensitive_capture`). Metadata-only sessions emit no header record and
retain no header value. The receiver still refuses the sensitive kinds without
`--allow-sensitive`.

### Sources

| Source | Code | Record | Hook | Notes |
| --- | ---: | --- | --- | --- |
| `browser` | 1 | `request_headers` | `network::ResourceRequest::headers` and `cors_exempt_headers` at `request_started` | Provisional: no `Cookie`, `Host`, `Referer` or other headers the network stack adds |
| `network` | 2 | `request_headers` | `network::mojom::DevToolsObserver::OnRawRequest` | The headers the network stack sent, including HTTP/2 and HTTP/3 pseudo-headers |
| `browser` | 1 | `response_headers` | `URLResponseHead::headers` at `response_started` and every `request_redirected` | Keeps `Set-Cookie`: at the pin `url_loader_util::BuildResponseHead` copies `URLRequest::response_headers()`. Recorded before Brave's own header rewrite |
| `early_hints` | 3 | `response_headers` | `DevToolsObserver::OnEarlyHintsResponse` | One per 103 response |

`TrustedURLLoaderHeaderClient` is not used: it can delay or change requests.

#### Network-service binding at the pinned Chromium

The network service calls `OnRawRequest` and `OnEarlyHintsResponse` only when
the request carries `devtools_request_id`. `URLLoaderFactory` binds the observer
per request from `ResourceRequest::TrustedParams::devtools_observer` (navigations)
or else from the factory's `URLLoaderFactoryParams::devtools_observer`. Content
creates both as `NetworkServiceDevToolsObserver::MakeSelfOwned`, which does
nothing unless a DevTools network handler is attached, and Blink and content
set `devtools_request_id` only when one is enabled.

So in content sessions the Brave proxy gives each admitted request without an
ID the ID `reb-<request_id as 16 hex digits>`, and Chromium patch
`0025-forward-native-network-headers.patch` forwards the two notifications to
the `network_headers_hook` component before DevTools dispatch. The ID changes
no request bytes. It does make the network service send SSL info and
transfer-size updates to the loader client, as with DevTools open. Requests
whose factory has no observer get no `network` block, and the UI shows their
provisional headers as such. Unknown IDs, such as CORS preflights, are ignored.

#### Hop attribution

`browser` blocks are children of the exact lifecycle record they describe:
`request_started` for the provisional request block, `request_redirected` or
`response_started` for the response block of that hop.

The DevToolsObserver pipe is not ordered with the loader client pipe. The
network service emits at most one raw request per hop and marks each response
head with `emitted_extra_info`. A `network` request block joins the oldest
finished hop whose head says a raw request was emitted and that has none yet,
or else the open hop. Its parent is that hop's start record (`request_started`
or `request_redirected`). Early hints join the open hop. A block for a request
the sink no longer tracks, including a DevTools-owned ID among the newest 256
finished, increments the unattributed count carried by every later header
record.

### Records

Types 30 `request_headers` and 31 `response_headers` use the v2 child envelope:
category `network`, flags 0, payload size 128, navigation, status, error,
transfer sizes and resource type zero, the parent's identity, and
`parent_event_id` lower than the record's own sequence. Little endian.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | source |
| 5 | 1 | state |
| 6 | 1 | referrer policy: `net::ReferrerPolicy` + 1, or 0 |
| 7 | 1 | remote address family: 0 none, 4 IPv4, 6 IPv6 |
| 8 | 4 | header count |
| 12 | 4 | block length in bytes |
| 16 | 4 | hop: 0 for the first request, n after n redirects |
| 20 | 2 | HTTP status code, or 0 |
| 22 | 2 | remote port |
| 24 | 16 | remote address; IPv4 uses the first 4 bytes |
| 40 | 4 | unattributed `network` blocks so far in this configuration |
| 44 | 4 | reserved, zero |
| 48 | 32 | SHA-256 of the block, or zero |
| 80 | 48 | reserved, zero |

| State | Meaning |
| ---: | --- |
| 1 `captured` | Retained as the named artifact, created by this record |
| 2 `captured_shared` | The receiver already accepted an identical block (kind, length and SHA-256) in this configuration; `artifact_id` names it. A block recorded before that acceptance gets its own artifact |
| 3 `empty` | No headers |
| 4 `not_captured_block_limit` | Longer than 320 KiB; count and length only |
| 5 `not_captured_artifact_unavailable` | Artifact category off, receiver disconnected or session inactive |
| 6 `not_captured_transfer_refused` | The bounded artifact queue refused it |
| 7 `not_captured_session_budget` | This configuration already holds 64 MiB of header blocks; a block the receiver refused, or a second accepted copy, returns its bytes |
| 8 `not_captured_url` | Not HTTP(S), the URL is longer than 8 KiB, or the request is untracked so its hop URL is unknown |

Rules, shared by the C++ core, the Python evidence validator, the Origin Trace
decoder and the backend:

- `request_headers` has source 1 or 2, status 0 and no address. Source 1 has
  referrer policy 1 to 8, source 2 has 0.
- `response_headers` has source 1 or 3 and referrer policy 0. Source 1 has a
  status from 100 to 999, or 0 when Chromium parsed none; source 3 has status
  103 and no address.
- Family 0 has port and address zero; family 4 has address bytes 4 to 15 zero.
- Count, length and state 3 are all zero or none is. Otherwise the length is at
  least 5 bytes per header.
- State 4 if and only if the length exceeds 327,680; its digest is zero. Every
  other state has a nonzero digest.
- `artifact_id` is nonzero exactly for states 1 and 2.
- Reserved bytes are zero.

### Header block artifact

A block is the headers in received or sent order, each written as `name`,
`: `, `value`, CRLF, without a request or status line. Names keep their case.
HTTP/2 and HTTP/3 pseudo-headers keep their leading colon, so a reader splits
each line at the first colon after its first byte. A block is never truncated
or rewritten.

Kinds 10 `request_headers` and 11 `response_headers`, capture origin 10
`network_request` (shared with `request_body`), MIME type `text/plain`, always
sensitive, execution context 0 and a nonzero creator. The manifest URL is the
hop's URL as for request bodies (scheme, host, explicit port, path and query).
A shared artifact keeps the URL of the record that created it; read the
request's URL from its own records. The receiver's ACK joins the creating
record as for request bodies; a shared record reads its artifact's outcome by
`artifact_id`. Sources never lists header artifacts.

### Cookies

Content sessions also record the cookies the network service reported for each
hop, with why each was blocked, and what page script did with
`document.cookie` and the Cookie Store API. Both use the header gate above: a
metadata-only session records no cookie record and no cookie value.

#### Network cookie lists

`OnRawRequest` carries `URLRequest::maybe_sent_cookies()` and `OnRawResponse`
`maybe_stored_cookies()`. At the pin `URLRequestHttpJob` always sets
`CookieOptions::set_return_excluded_cookies()`, so each list holds every
included cookie and every excluded one with its `net::CookieInclusionStatus`.
Chromium patch 0025 forwards both lists with the raw notification.

Type 32 `cookie_list` has the header record envelope and joins a hop like the
`network` request block: a sent list joins the hop its raw request joined, and
a received list the hop of the request's latest raw request, because both
arrive in order on one pipe. Its parent is that hop's start record. One record
per notification, empty lists included, so "no cookies" differs from "not
reported". The cookies are not also parsed from the `Cookie` and `Set-Cookie`
headers; those stay in the header blocks.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | direction: 1 sent with the request, 2 received in the response |
| 5 | 1 | state, as for header blocks; 4 means longer than 2 MiB |
| 6 | 2 | reserved, zero |
| 8 | 4 | cookie count |
| 12 | 4 | blocked count: cookies with at least one exclusion reason |
| 16 | 4 | list length in bytes |
| 20 | 4 | hop |
| 24 | 4 | unattributed cookie lists so far in this configuration |
| 28 | 4 | reserved, zero |
| 32 | 32 | SHA-256 of the list, or zero |
| 64 | 64 | reserved, zero |

Rules: direction 1 or 2; blocked at most count; count, length and state 3 are
all zero or none is, and otherwise the length is at least 16 + 64 per cookie;
state 4 if and only if the length exceeds 2,097,152, with a zero digest; every
other state has a nonzero digest; `artifact_id` is nonzero exactly for states 1
and 2; reserved bytes are zero.

#### Cookie list artifact

Kind 12 `cookie_list`, capture origin 10 `network_request`, MIME type
`application/x-reb-cookie-list`, always sensitive, with the hop's URL like a
header block. Identical lists are shared by direction, length and SHA-256, in
the header table and the header 64 MiB budget. Little endian, never truncated
or rewritten:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `RBCK` |
| 4 | 2 | version, `1` |
| 6 | 1 | direction, as in the record |
| 7 | 1 | reserved, zero |
| 8 | 4 | cookie count |
| 12 | 4 | reserved, zero |
| 16 | … | cookies, in the network service's order |

Each cookie is 64 bytes followed by its strings:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | exclusion reasons: bit n for `CookieInclusionStatus::ExclusionReason` n |
| 8 | 8 | warning reasons: bit n for `WarningReason` n |
| 16 | 8 | expiry, signed milliseconds since the Unix epoch; 0 for a session cookie |
| 24 | 1 | flags: bit 0 parsed, 1 HttpOnly, 2 Secure, 3 partitioned, 4 cross-site partition ancestor, 5 domain cookie |
| 25 | 1 | SameSite: 1 unspecified, 2 None, 3 Lax, 4 Strict |
| 26 | 1 | priority: 1 Low, 2 Medium, 3 High |
| 27 | 1 | effective SameSite: `CookieEffectiveSameSite` + 1 |
| 28 | 1 | source scheme: `CookieSourceScheme` |
| 29 | 3 | reserved, zero |
| 32 | 4 | source port, signed |
| 36 | 24 | lengths of name, value, domain, path, partition site and line |
| 60 | 4 | reserved, zero |
| 64 | … | those six strings, in that order |

Bit 0 is clear only for a received line that failed to parse; such a cookie
has only its exclusion and warning reasons and its line, and every other field
zero. The line is the `Set-Cookie` value as received and is empty for sent
cookies. The partition site is `CookiePartitionKey::site()` serialized. The
list ends exactly after its last cookie. Sizes come from Chromium's limits:
180 cookies per domain, 4,096 bytes of name and value and 1,024 per attribute,
about 1.1 MiB; 2 MiB leaves room for excluded and partitioned cookies.

#### Script cookie access

Chromium patch `0028-record-script-cookie-access.patch` calls the renderer
sink from `CookieJar::SetCookie` and `CookieJar::Cookies` (`document.cookie`)
and from `CookieStore::set`, `get`, `getAll` and `delete`. The browser passes
the content gate to the renderer in `NativeProbeClient::Configure`. Without it,
each call costs one atomic load.

Type 39 `script_cookie` is a renderer record: category `network`, flags 0,
payload size 128, `request_id`, `parent_event_id`, `artifact_id`, navigation,
status, error, lengths and resource type zero. `frame_id` is the document's
frame for `document.cookie` and the calling frame for the Cookie Store API on
the document main thread. In a service worker, whose `cookieStore` calls run
on the worker thread, `frame_id` is the worker's context ID: the frame ID of
its own requests and the isolate key of its [stack scope](#stack-scope).

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `2`; readers also accept `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | API: 1 `document.cookie` set, 2 `document.cookie` get, 3 `cookieStore.set`, 4 `cookieStore.get`, 5 `cookieStore.getAll`, 6 `cookieStore.delete` |
| 5 | 1 | flags |
| 6 | 1 | version 2: the stack thread of the calling isolate, 1 to 4 as in the [stack scope](#stack-scope), or 0 when the thread was never named; version 1: zero |
| 7 | 1 | reserved, zero |
| 8 | 4 | count: 1 for a write; for a read, reads since this key's previous record |
| 12 | 4 | name length in UTF-8 bytes |
| 16 | 4 | value length in UTF-8 bytes; 0 for a read |
| 20 | 4 | `document.cookie` string length, set or returned; 0 for the Cookie Store API |
| 24 | 16 | innermost script frame, in the frame layout of `request_initiator_stack` |
| 40 | 32 | stack digest, the `request_initiator_stack` digest of this call's stack, or zero |
| 72 | 32 | SHA-256 of the value (writes), or zero |
| 104 | 24 | the name's first 24 bytes, zero padded |

Flags: bit 0 the name is longer than 24 bytes; bit 1 a script frame was
recorded; bit 2 a stack digest was recorded; bit 3 a read recorded alone
because the aggregation table was full.

Rules: API 1 to 6; writes (1, 3, 6) have count 1 and a nonzero value digest,
reads have value length 0 and a zero digest; count is nonzero; bit 0 if and
only if the name is longer than 24 bytes, and name bytes past the name are
zero; for API 1 the string length is at least name plus value length, and for
3 to 6 it is 0; bit 1 if and only if the frame's kind is 1 or 2 with a nonzero
script ID, its combinator 0 and only frame flag bits 0 and 1, and without bit
1 the frame is zero; bit 2 if and
only if the stack digest is nonzero, and only with bit 1; bit 3 only for a
read; reserved bytes are zero. Version 2: byte 6 is 0 to 4; with 0, bits 1
and 2 are clear, since no frame could be read in a known isolate; with 2 to 4,
`frame_id` is nonzero.

The script frame and the stack are read in the isolate byte 6 names, with the
worker's context ID as its key: script IDs are unique only per isolate, so a
service worker's `cookieStore.set` resolves to the worker's scripts and never
to a page script with the same ID. Version 1 records, written before byte 6,
were all read as the document's; a service worker's version 1 record could
therefore name a page script, which is why version 2 exists. Blink names each
thread's isolate whether or not request stacks are recorded (`AttachThread`,
two thread-local stores), so byte 6 is 0 only on a thread Blink never named,
and neither API runs on one today.

`document.cookie` set parses the name and value like `ParsedCookie`: up to the
first `;`, split at the first `=`, whitespace trimmed; no `=` means an empty
name. The script frame comes from `v8::StackTrace::CurrentStackTrace` (one
frame): script ID and character position; function start is 0. When the
request stack provider is installed ([gate](#gate)), a write on the document
main thread or in a service worker also walks the stack the way a request
start does, in that thread's isolate, without a
`request_initiator_stack` record: the write carries the walked innermost frame
(with its function start) and the stack digest with bit 2. The record's
sequence is reserved before the walk, so the stack artifact's
`creator_event_id` and the new `script_identity` records' parent are the
`script_cookie` record. Reads stay one-frame.

Reads are frequent, so each renderer aggregates them per frame, thread, API,
script frame and name in a 256-entry table per configuration. A key records its 1st,
2nd, 4th, 8th and later power-of-two reads, each with the reads since the
previous record, and its remainder when the configuration ends. A new key
while the table is full is recorded alone with bit 3.

#### Cookie bounds

- Disabled or metadata-only: no cookie list is serialized, and a script cookie
  call costs one atomic load.
- A sent and a received list per hop, at most 2 MiB each, sharing the header
  table and budget.
- Script cookie records: one per write, at most 2 + log2(reads) per read key,
  and one per read past the table; each is one 320-byte record, one SHA-256 of
  the value and a one-frame stack capture. With request stacks on, a write
  walks its stack instead, inside the request stack bounds.

#### Cookie agent access and UI

`get_request_cookies` (`GET /api/request-cookies?session_id=&request_id=`)
returns each hop's sent and received cookies with every attribute, exclusion
and warning reason. `get_cookie_provenance`
(`GET /api/cookie-provenance?session_id=&name=`) lists what touched a cookie
name in the newest 5,000 network records within the last 64 MiB of events: the
responses that set it, the script writes and reads with their frame, and the
requests that sent it. `coverage` says what was read, so an absent entry is not
proof when `coverage.complete` is false (see
[request index v1](request-index-v1.md#per-request-detail-reads)). Each
script call's `stack` resolves like `get_request_stack`: through
`script_identity` records in the same window to line, column and function name,
with every walked frame when its digest names a retained stack artifact; at
most 64 distinct positions per answer, the rest counted in
`stacks_unresolved`.
Cookie values are withheld as `value_withheld: true` with their byte length
and SHA-256, like credential headers; a script write links to a sent cookie
when their value digests are equal.

Origin Trace's **Cookies** tab shows Request cookies, with "Show filtered out
request cookies" listing excluded ones and each reason, and Response cookies
with name, value, domain, path, expiry, size, HttpOnly, Secure, SameSite,
partition key, priority and block reasons. Columns sort, long values truncate
with the full value as a tooltip, and each value copies. A name opens its
provenance. Values are inserted as text after a size and SHA-256 check.

### Bounds and hot path

- Disabled or metadata-only: unchanged. The proxy adds no ID, and the hook
  costs one atomic load per DevTools raw notification.
- 320 KiB per block: Chromium's 256 KiB response header bound
  (`HttpStreamParser::kMaxHeaderBufSize`, `kSpdyMaxHeaderListSize`) plus the
  byte `: ` normalization can add to a line of at least 4 bytes. Request blocks
  use the same bound.
- 64 MiB of retained blocks per session configuration; shared blocks cost
  nothing. Exhaustion is the visible state 7, never silence.
- Identical blocks are retained once by kind, length and SHA-256, through a
  4,096-entry table per configuration. When it is full, later blocks are
  retained individually.
- Each block is measured, then serialized into a buffer reserved to its exact
  length, and hashed once on the UI sequence.
- At most 4,096 in-flight requests are tracked for hops and `network` blocks.
  The rest keep their provisional block, their response blocks report hop 0
  with state 8, and each adds one to the unattributed count. Tracking ends at
  request completion.

### Agent access

`get_request_headers` (`GET /api/request-headers?session_id=&request_id=`)
returns each hop's request and response blocks with their state, source,
counts, digest, referrer policy, remote endpoint and parsed headers. Values of
`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie` and any header
whose name contains a credential root (`token`, `secret`, `passw`, `csrf`,
`xsrf`, `cookie`, `bearer`, `signature`, `credential`, `sessionid`, `authoriz`
and similar), has the whole word `auth`, `session`, `jwt`, `otp` or `pwd`, or
has a word ending in `key`, except `Sec-WebSocket-Key`, `Idempotency-Key` and
`Public-Key-Pins`, are withheld as `value_withheld: true` with
their byte length: like request bodies, they stay in the binary artifact, which
MCP never inlines. Withholding goes by name, so another value, such as a
`Location` query, is returned as captured.

### Consumers

- The broker accepts types 30 and 31 only when `IsValidEvent` does. The
  backend's network window keeps them with the lifecycle records. Neither
  becomes a lifecycle record.
- Origin Trace's **Headers** tab shows General (URL, method, status, remote
  address, referrer policy), Response headers and Request headers per hop. A
  hop with only a `browser` request block reads "Provisional headers are
  shown". Each section collapses and has a Raw view and copy actions. Values
  are inserted as text after a size and SHA-256 check.

### Validation

`make native-network-capture-check` drives the sink: disabled and metadata
sessions, provisional, network and response blocks over two redirect hops,
out-of-order raw notifications, early hints, pseudo-headers, sharing, a
200 KiB block retained whole, the block limit and the session budget.
It also drives sent and received cookie lists with blocked cookies, an
unparsed `Set-Cookie`, sharing and late lists. `make native-probe-admission-check`
drives the renderer cookie sink: disabled, metadata-only, writes, read
aggregation, a full table and the configuration-end remainder.
`make native-tests` and `make network-request-wire-check` compare the C++
verdicts with the Python validator and the shipped decoders.

### Acceptance

Still required before declaring this browser-ready:

1. Replay all stacks on a disposable initialized checkout, run
   `make brave-doctor` and `make brave-probe-check`, and compile.
2. Against a local echo server, compare the headers it saw and sent with the
   records, across two redirect hops, a 103 response, HTTP/2 and a 200 KiB
   response header block.
3. Repeat in a metadata-only session and confirm no header or cookie record
   exists.
4. On a local fixture with a JavaScript-set cookie and `Set-Cookie` with
   SameSite and Secure variants, compare the sent, received and blocked
   cookies with what the server saw, and link the JavaScript write to its
   script position.

## Request initiator stacks

Defined by #429: the synchronous JavaScript and WebAssembly stack, plus
V8's `await` chain, that was running when a renderer started a request, from
version 2 the async tasks that led there
([task chain](#navigation-and-async-task-callers)), and from version 3 the
isolate the stack was walked in, so requests that dedicated, shared and
service workers start have stacks too. Frames are identities only: no strings,
no values, no debugger.

### Gate

- V8 flag `--reb-request-stacks`, off by default. The launcher adds it for
  `REB_NATIVE_REQUEST_STACKS=1`, which needs Network (256) and Artifact (1024).
  `make live` leaves it off. The packaged app sets it when the mask allows
  both, and with `REB_NATIVE_REQUEST_STACKS_IF_SUPPORTED=1` drops it, with a
  launch log line, from a Brave that does not define it.
- Blink installs the stack provider only when V8 reports the flag on. Without
  it a request start costs one atomic load and nothing is walked.
- The renderer walks, for a request whose `request_initiated` record was
  admitted, on the document main thread and on each dedicated, shared and
  service worker thread ([threads](#threads)). Worklets, the background loader
  thread and the pool thread synchronous XHR uses have no tables and record
  `unsupported_thread`.
- V8 flag `--reb-promise-stacks`, off by default everywhere including the
  packaged app, adds [promise registrations](#promise-registrations). The
  launcher adds it for `REB_NATIVE_PROMISE_STACKS=1` with request stacks on.

### `request_initiator_stack` (type 34)

Category `network`, child of the renderer's `request_initiated` record:
`parent_event_id` is that record's sequence, with the same process, thread,
frame and renderer `request_id`. Payload 128 bytes, little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version: `3`, or `2` and `1` from earlier producers |
| 2 | 2 | payload size, `128` |
| 4 | 1 | state |
| 5 | 1 | flags |
| 6 | 2 | version 2: task segments, at most 32; version 1: zero |
| 8 | 4 | total synchronous depth |
| 12 | 4 | recorded synchronous frames, at most 1,024 |
| 16 | 4 | omitted synchronous frames |
| 20 | 2 | async frames, at most 32 |
| 22 | 2 | async segments: version 1 the async frames, version 2 async frames plus task segments |
| 24 | 4 | Wasm frames among the recorded ones |
| 28 | 4 | distinct scripts among the recorded frames |
| 32 | 32 | stack digest: SHA-256 of the stack artifact content |
| 64 | 16 | innermost frame, in the frame layout below |
| 80 | 16 | version 3: [stack scope](#stack-scope), zero for state 3; earlier versions: zero |
| 96 | 32 | reserved, zero |

| State | Meaning |
| ---: | --- |
| 1 `captured` | Frames walked; the digest names the stack artifact queued with this record, or sent earlier in this configuration and not refused |
| 2 `no_script` | No JavaScript or Wasm was on the stack: the parser, a preload, a worker's script or module loader, or a start the loader deferred |
| 3 `unsupported_thread` | A thread with no tables: a worklet, the background loader thread, or the pool thread synchronous XHR issues its request on. Version 1 and 2 producers also used it for workers |
| 4 `not_retained_artifact_unavailable` | Frames walked; Artifact category off or no artifact path |
| 5 `not_retained_budget` | Frames walked; this configuration already sent 1,024 stacks |

Flags: bit 0 the stack artifact was queued with this record; bit 1 frames were
omitted; bit 2 the `await` chain reached 32 frames and may continue. Bit 3 in
version 1 (always set): task-attributed callers were not captured; from
version 2: the task chain stops at a caller that was not recorded. Bit 4, from
version 2: the task chain reached 32 segments and may continue. Other bits are
zero. Debugger observations keep version 1.

Validation, shared by the C++ core, the Python validator and the backend:

- States 1, 4 and 5 have a nonzero digest, an innermost frame, recorded at
  least 1, `recorded + omitted == total` and `recorded <= 1024`. Omitted is
  nonzero exactly when bit 1 is set, and then recorded is 1,024.
- States 2 and 3 have every count, the digest and the innermost frame zero;
  only bit 3 may be set, and from version 2 no flag.
- Version 3: bytes 80-95 are a valid stack scope, all zero for state 3, and
  bytes 96-127 are zero. Earlier versions: bytes 80-127 are zero.
- Bit 0 only with state 1. Version 1: async segments never exceed async
  frames. From version 2: async segments equal async frames plus task
  segments, and bit 4 needs 32 task segments. Wasm frames and distinct scripts never exceed
  recorded plus async frames.
- The envelope's `artifact_id` is zero: the browser assigns artifact IDs.

### Frame layout

16 bytes, innermost first:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | kind: 1 JavaScript, 2 Wasm, 3 `await` (async function), 4 promise combinator |
| 1 | 1 | flags: bit 0 constructor call, bit 1 top-level script code |
| 2 | 2 | combinator for kind 4: 1 `Promise.all`, 2 `Promise.allSettled`, 3 `Promise.any`; else 0 |
| 4 | 4 | V8 script ID (the Wasm module's script for kind 2); 0 only for kind 4 |
| 8 | 4 | kinds 1, 3: source position, UTF-16 offset into the script source; kind 2: module byte offset; kind 4: promise index |
| 12 | 4 | kinds 1, 3: function start position; kind 2: function index; kind 4: 0 |

Script IDs are unique only within one V8 isolate, so a frame is read with the
record's `process_id` and its [stack scope](#stack-scope).

### Stack scope

16 bytes naming the isolate a stack was walked in:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | thread: 1 document main thread, 2 dedicated worker, 3 shared worker, 4 service worker |
| 1 | 7 | reserved, zero |
| 8 | 8 | isolate key: zero for thread 1; otherwise the worker's context ID, the fold of its global scope token that its own requests carry as `frame_id`, nonzero |

Version 1 and 2 records, version 1 identities and version 1 and 2 artifacts are
the document main thread's. A worker's records carry its context ID as
`frame_id` when no fetch owner names another, as its requests do.

### Threads

Each thread with tables keeps its own frame buffer, digest, script, segment,
task attribution and promise registration tables and its own budgets; only that
thread's walks read or write them, so a walk takes no lock. Blink attaches the
document main thread when it installs the provider, and each dedicated, shared
and service worker thread in `WorkerThread::InitializeOnWorkerThread` once its
global scope exists; a second attach on a thread does nothing. The worker
thread's tables and Blink's frame buffer for V8 are freed in
`PerformShutdownOnWorkerThread`, so a worker costs its tables only while it
lives. Nothing is allocated in a walk.

A browser refusal (`NativeStackArtifactRefused`) arrives on the transport's
sequence and is routed to the thread whose walk queued that artifact: each
queued stack artifact names its table in an 8,192-slot owner ring (one slot per
artifact, written by the walking thread as a seqlock and read with acquire
ordering), and the refusal is pushed into that table's 256-entry mailbox
under the registry lock that attach and detach also take; the mailbox has one
producer, and its owner drains it at its next walk (release on publish,
acquire on read). A thread more than 256 refusals behind cannot tell which it
missed: it forgets every digest and stops calling any remembered segment or
registration captured. A refusal whose owner left the ring, or whose thread
detached, changes nothing.

### Stack artifact

Kind 13 `stack`, capture origin 12 `request_stack`, not sensitive, MIME
`application/x-reb-stack`, URL `reb-stack:sha256-<hex digest>`,
`creator_event_id` the record's sequence (a `script_cookie` write's, for its
walked stack). Its manifest SHA-256 is the record's
digest. Content:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic `RBSK` (`0x4b534252`) |
| 4 | 2 | version: `3` for request, navigation and async task stacks; `1` for debugger observation and cookie stacks; earlier producers wrote the record's payload version |
| 6 | 2 | header size: `48` in version 3, else `32` |
| 8 | 2 | frame size, `16` |
| 10 | 2 | record flags bits 1 and 2, and in version 2 bits 3 and 4 |
| 12 | 4 | total synchronous depth |
| 16 | 4 | recorded synchronous frames |
| 20 | 4 | omitted synchronous frames |
| 24 | 2 | async frames |
| 26 | 2 | async segments |
| 28 | 2 | task segments; zero in version 1 |
| 30 | 2 | reserved, zero |
| 32 | 4 | version 3: the walking renderer's OS process ID, nonzero |
| 36 | 1 | version 3: stack scope thread |
| 37 | 3 | version 3: reserved, zero |
| 40 | 8 | version 3: stack scope isolate key |
| 32 or 48 | 16 x n | recorded synchronous frames, then async frames |
| | 48 x t | versions 2 and 3: [task segments](#task-segment), nearest first |

The process and scope in a version 3 header make a digest name one isolate, so
a task segment a message carried to another thread or process still resolves
its own frames. A request or async task artifact agrees with its record's
process and scope; a navigation record (version 2) has a version 3 artifact of
the document main thread.

A stack deeper than 1,024 keeps the innermost 512 and the outermost 512 frames;
the omitted frames lie between index 511 and 512. Async frames follow the
synchronous ones in chain order; each async frame is one segment.

Each thread remembers 256 digests it sent in the current configuration. A
repeated stack sends no artifact. A digest that falls out of that table, or that
the browser reports refused or lost (`NativeStackArtifactRefused`), is sent again,
never dropped. Each thread sends at most 1,024 request stack artifacts per
configuration; a refused attempt does not count.

### `script_identity` (type 35)

Category `network`, `request_id` 0, child of the `request_initiator_stack`,
`navigation_initiator_stack`, `async_task_stack` (or `script_cookie` write)
record that first named the script in this configuration. Same process, thread and frame. Both records share the Network
and Artifact gate.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version: `2`, or `1` from earlier producers |
| 2 | 2 | payload size, `128` |
| 4 | 1 | kind: 1 JavaScript, 2 Wasm |
| 5 | 1 | flags |
| 6 | 2 | reserved, zero |
| 8 | 4 | V8 script ID, nonzero |
| 12 | 4 | start line in its document or resource, 0-based |
| 16 | 4 | start column, 0-based |
| 20 | 4 | reserved, zero |
| 24 | 8 | execution context ID of the script's realm |
| 32 | 8 | source length: UTF-8 bytes, or Wasm wire bytes |
| 40 | 32 | SHA-256 of those bytes |
| 72 | 16 | version 2: the [stack scope](#stack-scope) of the isolate the script ID belongs to; version 1: zero |
| 88 | 40 | reserved, zero |

Flags: bit 0 `eval` or `new Function` script; bit 1 the source was queued as
an artifact with this record as creator; bit 2 source longer than 16 MiB, not
hashed; bit 3 source unavailable; bit 4 not retained: Artifact category off,
content capture off, or the source budget is spent. Exactly one of bit 1, bit 2, bit 3, bit 4 or none
(a Wasm module, never re-sent) holds. A digest is present unless bit 2 or 3.

JavaScript sources are retained only in content capture
(`--reb-capture-request-content`), so a Metadata only session keeps frames,
script IDs, positions and digests but no script source; the browser refuses
such an artifact from a renderer outside content capture. They are retained as
kind 1 `javascript`, capture origin 13 `stack_script`, at most 64 MiB of
source per renderer configuration, with
the script URL, or the document URL for an inline script, as the artifact URL.
Wasm modules are not re-sent: the compile-time Wasm artifacts join by SHA-256.
A network script the body tee retained also joins by SHA-256.

Each thread remembers 1,024 script IDs it described in the current
configuration; an evicted script is described again. A worker describes its own
scripts even when the main isolate described the same script IDs.

### Resolution

`get_request_stack` (`GET /api/request-stack?process_id=&request_id=`, the
renderer identity) returns the newest stack record for that request with its
frames, reading the bytes the [request index](request-index-v1.md#per-request-detail-reads)
names for it. `status` is `outside_scan`, not `not_recorded`, when the read did
not reach them all; `coverage` says what was read:

- A JavaScript frame resolves through `(process_id, isolate key, script_id)` to
  its identity record, then by SHA-256 to a retained `javascript` artifact, to one-based line
  and column (UTF-16 columns, the identity record's start line and column
  added on the script's first line), and to the enclosing function name read
  at the function start position. The join ignores capture origin: the identity
  and every retained source hash the same UTF-8 text V8 compiled, so a network
  response body, the `stack_script` artifact retained during the walk, and the
  [compiled script](native-compiled-scripts-v1.md) artifacts (`compiled_script`
  for inline, inserted and `blob:` scripts, `dynamic_javascript` for `eval` and
  `new Function` text) all resolve the frame. When several hold the same bytes,
  the session's newest is shown. `eval` and `new Function` frames resolve the
  same way. A Metadata only session retains no source that no response body
  carried, so those frames report `source_not_retained`.
- A Wasm frame resolves to its function index, and to its name when the
  retained module has a name section.
- A frame that does not resolve keeps its raw identity and a reason. Nothing is
  guessed.

The document adds `scope` (`thread`: `document`, `dedicated_worker`,
`shared_worker` or `service_worker`, and `isolate_key` as 16 hex digits or
null), null for `unsupported_thread`. The request index keys identities by
process, isolate key and script ID, so a worker row's Initiator column frame
resolves in the worker's isolate.

`get_events` with `request_id` returns the stack record beside the lifecycle
records.

### Consumers

- The broker accepts both types only when `IsValidEvent` accepts them.
- The trace index treats `request_initiator_stack` as a request child: it never
  becomes the request's latest lifecycle record.
- The backend's network window keeps `request_initiator_stack` records.
- Origin Trace's Initiator tab shows "Request call stack" with `await`
  separators and an "N frames omitted" marker, opening Sources at a resolved
  frame, and "Request initiator chain" from the request's initiator edges.
  `no_script` reads "Parser", or "Worker loader" for a worker; a worker stack
  says which worker kind started it. The Traffic table's Initiator column reads
  "Worker script" and "Worker loader" for version 3 worker stacks. Captured
  values are inserted as text.

### Hot path and bounds

- Flag off: one atomic load per request start.
- Flag on, inactive session or category off: the existing `request_initiated`
  checks; no walk.
- Active: one V8 walk into the thread's frame buffer (1,056 frames, allocated
  with its tables), one SHA-256 of at most 16,944 bytes, one 320-byte record.
  First sightings add one artifact, and for each new script one record and one
  source copy. Draining routed refusals is one acquire load when none arrived.
- Memory: about 520 KiB per attached thread (tables, refusal mailbox and
  Blink's frame buffer), plus a 112 KiB registration ring per thread with
  `--reb-promise-stacks`, allocated when the thread attaches and freed when a
  worker stops. The owner ring is 128 KiB of process-static storage, untouched
  until a stack artifact is queued.

### Validation

`tests/request_stack_test.cpp` (in `make native-tests`) checks layout parity
with the overlay, every state and version, stack scopes, the frame bounds and
malformed records.
`make native-probe-admission-check` drives the real renderer sink with a
fixture provider: disabled, 150 and 5,000 frames, Wasm and `await` frames,
repeated stacks, table eviction, budgets and script identity, and on a second
thread a dedicated worker's own tables, scope, frame IDs and identities,
refusals routed from the transport's thread, mailbox overflow, a thread with
no tables and detach.
`make request-stack-wire-check` compares the C++ verdicts with the Python
validator and the Initiator decoder and renders the Initiator panel in a DOM
model. The backend's `request_stack` tests resolve inline, `eval`, Wasm and
`await` frames, resolve stored frames whose only source is a compiled script
artifact, resolve one script ID to different sources in a worker and in
another renderer, and refuse to guess unresolved ones. `make
request-index-check` covers the worker Initiator column labels.

### Acceptance

Still required before declaring this browser-ready:

1. Replay all stacks and overlays on a disposable initialized pinned checkout,
   run `make brave-doctor` and `make brave-probe-check`, and compile.
2. A 150-frame stack through framework wrappers matches DevTools' synchronous
   initiator stack frame for frame.
3. A 5,000-deep recursion records 1,024 frames, the omitted count and depth.
4. Frames into an inline script, an `eval` script and a network script resolve
   to file, line and column. A `fetch` from a Wasm import shows Wasm frames.
   An `await` chain shows its async frames. Run the `eval` case on a page with
   no CSP, in a content session, where the frame resolves to `stack_script` or
   compiled `dynamic_javascript` text, and in a Metadata only session, where it
   reports `source_not_retained`.
5. Repeated requests from one call site send their stack once.
6. Measure added time per request at p50 and p99 on a request-heavy page before
   keeping the packaged default on.
7. Script-initiated navigations and task chains: see
   [their acceptance](#acceptance-4).
8. A `fetch` in a dedicated, a shared and a service worker shows the worker's
   frames resolved to its script, including an `eval` frame and a Wasm frame
   in a worker; the same script ID in the page resolves to the page's script.
   A worker that stops frees its tables (renderer memory returns), and an
   AudioWorklet module fetch reads `unsupported_thread`.

## Navigation and async task callers

Defined by #429: the stack that started a script navigation, and the async
tasks a request or navigation came from. Both use the
[request stack gate](#gate) and the stack artifact path; nothing more runs
without `--reb-request-stacks`.

### Task chain

At scheduling time Blink's async task probes
(`probe::AsyncTaskContext::Schedule`, the identities DevTools' async stacks
use) walk the innermost 256 frames when script runs on a thread with
[tables](#threads): the document main thread or a worker.
`probe::AsyncTask` marks that task's segment current while it runs. Promise
reactions use Chromium's task attribution: a top-level
`V8ScriptRunner::CallFunction` inside a task forks the current task state
(same soft navigation, resource timing and script tool contexts), and V8
carries that state to every reaction registered in the run. A walk in a
microtask follows the task attribution ID, never the task that happens to run
the checkpoint. Blink creates its task attribution tracker only on the main
thread, so in a worker a microtask's chain is cut after its microtask segment.

| Kind | Scheduled by |
| ---: | --- |
| 1 `set_timeout`, 2 `set_interval` | `setTimeout`, `setInterval` |
| 3 `request_animation_frame`, 4 `request_idle_callback` | `requestAnimationFrame`, `requestIdleCallback` |
| 5 `post_message` | `window.postMessage` |
| 6 `xhr_send` | `XMLHttpRequest.send`, for its events |
| 7 `post_task` | `scheduler.postTask` |
| 8 `event` | a queued event or observer callback (any other async task name) |
| 9 `microtask` | a promise reaction or queued microtask; with `--reb-promise-stacks`, the stack that called `.then`, `.catch`, `.finally` or `await` ([promise registrations](#promise-registrations)) |
| 10 `message_port` | `MessagePort.postMessage`, including ports to shared workers and other renderers ([message task origins](#message-task-origins)) |
| 11 `broadcast_channel` | `BroadcastChannel.postMessage` |
| 12 `worker_message` | `Worker.postMessage` and a dedicated worker's `postMessage` back |

Kinds 10 to 12 exist from task segment version 3 and `async_task_stack`
version 2.

Not shown: `ServiceWorker.postMessage` and `Client.postMessage`, whose browser
path carries no origin; `window.postMessage` to or from a frame in another
process (kind 5 covers same-process frames); a microtask's registering call
without `--reb-promise-stacks`, for a registration made before the capture
started, or after 2,048 later registrations on its thread; registrations by
builtins (a promise combinator shows as a combinator frame instead); and a
worker microtask's task attribution parent.

#### Schedules with no script

A task scheduled while no script runs on a thread with tables, in an active
capture (the browser, the parser or a native callback queuing an event, a
`BroadcastChannel` post deferred to prerender activation) walks nothing and
stores nothing: its handle names a version 3 segment of that kind with state 7
`no_script`, which ends the chain with that reason instead of silently. While
capture is inactive such a task keeps no handle, and a chain reaching it stops
with no segment, as before.

#### `async_task_stack` (type 48)

Category `network`, renderer, `parent_event_id` 0, `request_id` 0, the
scheduling document's frame or, in a worker, the worker's context ID. Emitted
only when a scheduling stack is first sent in this configuration, with its
artifact. Payload 128 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version: `2`, or `1` from earlier producers |
| 2 | 2 | payload size, `128` |
| 4 | 1 | task kind: 1 to 8 and 10 to 12, or 9 for a promise registration (version 2 only) |
| 5 | 1 | flags: bit 0 the walk stopped at its frame limit |
| 6 | 1 | version 2, kind 9: the registration, 1 `.then`, 2 `.catch`, 3 `.finally`, 4 `await`; else zero |
| 7 | 1 | reserved, zero |
| 8 | 4 | recorded frames, 1 to 256, or 1 to 32 for kind 9 (the limit with bit 0) |
| 12 | 4 | Wasm frames |
| 16 | 4 | distinct scripts |
| 20 | 12 | reserved, zero |
| 32 | 32 | stack digest |
| 64 | 16 | innermost frame |
| 80 | 16 | version 2: [stack scope](#stack-scope); version 1: zero |
| 96 | 32 | reserved, zero |

Its artifact is a version 3 (version 1 from earlier producers) stack artifact
of the synchronous frames (total depth equal to recorded), kind 13, capture
origin 12 `request_stack`, creator this record; scripts it names get
`script_identity` children. Stacks share the thread's 256-digest table with
request stacks, so a repeated scheduling site sends nothing; each thread sends
at most 1,024 scheduling stacks and 1,024 registration stacks per
configuration, and a refused attempt does not count.

#### Task segment

48 bytes in a version 2 or 3 stack artifact, nearest first: the task running
now, or the one a microtask's attribution names, then the task that scheduled
it.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | task kind: 1 to 9, and in version 3 also 10 to 12 |
| 1 | 1 | state: 1 captured, 4 not retained (Artifact off, or the browser refused its artifact), 5 not retained (budget), 6 not recorded (kind 9 only), 7 `no_script` (version 3, not kind 9) |
| 2 | 1 | flags: bit 0 the walk stopped at its frame limit |
| 3 | 1 | version 3, kind 9 in state 1, 4 or 5: the registration (1 to 4, as in `async_task_stack`); else zero |
| 4 | 4 | frames in its stack: 1 to 256, or 1 to 32 for a kind 9 registration; 0 in states 6 and 7 |
| 8 | 8 | reserved, zero |
| 16 | 32 | its `async_task_stack` artifact digest; zero in states 6 and 7 |

A state 7 segment is the last one, and its artifact has neither bit 3 nor bit
4 set. Segments carried by a message keep the state they had when posted.

Each thread remembers 2,048 segments and 4,096 task attribution IDs per
configuration; a task scheduled inside a microtask stores a kind 9 segment in
front of itself, so the hop keeps its registration. A chain that reaches a
forgotten segment, a microtask whose attribution names none, or a message
with no valid origin, sets bit 3 and stops; 32 segments set bit 4. When the
browser refuses a stack artifact, every segment and registration that thread
remembers naming that digest changes from state 1 to state 4, so later chains
stop claiming it. Artifacts already sent keep the state they were written with.

#### Message task origins

`MessagePort.postMessage`, `BroadcastChannel.postMessage`, `Worker.postMessage`
and a dedicated worker's `postMessage` walk the posting stack like any schedule
(kinds 10 to 12, or a `no_script` segment) and carry a task origin in the
message beside Chromium's `sender_stack_trace_id`: `BlinkCloneableMessage`
moves it across threads, and the `CloneableMessage` mojom field
`reb_task_origin` carries it to other renderers, directly for a `MessagePort`
and through the browser's `ShallowClone` for a `BroadcastChannel`. It is never
stored. Little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | version, `1` |
| 2 | 1 | segments n, 1 to 32 |
| 3 | 1 | flags: bit 0 the sender's chain continued past these, or was cut there |
| 4 | 4 | sender's OS process ID, nonzero |
| 8 | 8 | sender's table, a process-unique nonzero number per attached thread |
| 16 | 8 | posting segment's serial in that table; zero exactly when it is `no_script` |
| 24 | 48 x n | version 3 task segments, nearest first: the posting segment (kind 10 to 12), then the sender's chain |

At most 1,560 bytes per message, built from at most 32 ring reads when the
message is posted. The receiving renderer treats the bytes as untrusted: an
origin that does not validate, names another kind, or is absent while capture
is active cuts the handler's chain (bit 3); the message itself is never
affected. Received on the thread that posted it, while that segment is still
remembered, the handler's task continues the same chain. Received anywhere
else, the carried segments are copied into the receiving thread's ring
(at most 32 writes), the last one cut when bit 0 is set, so a request in the
handler lists the posting stack and the sender's callers. Each copied segment's
frames resolve in the scope of its own artifact.

#### Promise registrations

With `--reb-promise-stacks`, V8 reports each user `.then`, `.catch`,
`.finally` and `await` to a REB delegate beside the inspector's
(`Isolate::OnPromiseThen` and `OnAsyncFunctionSuspended`), tagging the derived
promise with the 26-bit async task ID DevTools' async stacks use, and reports
the reaction's start and end (`OnPromiseBefore` and `OnPromiseAfter`). The
debugger is never activated and the inspector's delegate is unchanged; both
see the same IDs. The builtins reach these points through the isolate's
`HasAsyncEventDelegate` promise-hook bit, which covers either listener;
`Promise#then`'s CodeStubAssembler check reads that bit instead of the
inspector's delegate pointer. While capture is inactive the delegate's `active` check
fails before V8 scans a frame or assigns an ID.

Each registration in an active capture walks the innermost 32 frames, hashes
at most 560 bytes and stores one 56-byte entry in the thread's 2,048-entry
registration ring keyed by the task ID; a new digest is sent once as an
`async_task_stack` kind 9 record with its artifact, within the thread's
registration budget. When a reaction runs, a request or schedule inside it
reads its entry: the chain's kind 9 segment then carries the registration and
its stack (state 1, 4 or 5) instead of state 6. An entry is used only for its
own task ID and configuration; a later registration in the same slot replaces
it, which reads as not recorded.

Cost, reasoned and not measured (no built browser here): the flag makes V8
take its promise-hook path for every promise operation in every isolate,
active or not, as it does while DevTools records async stacks, a runtime call
on each promise creation, `then` and reaction. In an active capture each user
registration adds V8's own scan to the first user frame, which allocates a
small vector per frame scanned as it does for DevTools, plus one walk of up to
32 frames, one SHA-256 and one table entry, a few microseconds. The flag is
therefore off by default, including in the packaged app; the Initiator tab
says so on every microtask segment it lacks.

### Script navigations

`location` setters, `window.open`, form submission and any other navigation a
local frame begins while script runs record a `navigation_initiator_stack`
from `LocalFrameClientImpl::BeginNavigation`. A form submission navigates from
a later task, so its stack is recorded in `HTMLFormElement::ScheduleFormSubmission`
and taken by that navigation; a later submission replaces it. Navigations with
no script on the stack record nothing.

#### `navigation_initiator_stack` (type 46)

Category `network`, renderer, `parent_event_id` 0, `request_id` 0, the
running script's frame. Bytes 0-79 are a version 2
[`request_initiator_stack`](#request_initiator_stack-type-34) payload with
state 1, 4 or 5 and its stack artifact, creator this record. Then:

| Offset | Size | Field |
| ---: | ---: | --- |
| 80 | 1 | kind: 1 location, 2 form submission, 3 `window.open`, 4 other script navigation |
| 81 | 7 | reserved, zero |
| 88 | 8 | the navigating frame's ID, nonzero |
| 96 | 32 | reserved, zero |

#### `navigation_initiator_link` (type 47)

The renderer's sequence travels in `BeginNavigationParams`
(`[MinVersion=1] reb_initiator_stack_sequence`). The navigation loader passes
it, with the initiator's OS process ID, to `common/native_navigation_initiator_hook.h`
keyed by the navigation's DevTools ID, which it then assigns to the request
when DevTools has not. When the browser records that navigation's
`request_started`, it emits this child: same session, process, thread, tab,
frame, request ID, BrowserContext and initiator fields, `parent_event_id` the
start's sequence. Payload 128 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 4 | renderer OS process ID, nonzero |
| 8 | 8 | that renderer's `navigation_initiator_stack` sequence, nonzero |
| 16 | 112 | reserved, zero |

The browser keeps 64 pending links per configuration and emits each once.

### Resolution and UI

`get_request_stack` adds `task_segments` (kind, state, `registration`, frames
resolved like the request's from each `async_task_stack` artifact, and
`scope` from a version 3 artifact: its thread, `process_id`, `elsewhere` when
it differs from the request's isolate and `other_process`), `task_chain_cut`
and `task_chain_truncated`. Identities for another renderer a carried segment
names are read too. With `navigation_sequence` instead of `request_id` it
resolves a navigation stack and adds `navigation.kind`. The Traffic index and
model read a navigation row with a link as `script`. The Initiator tab shows
each segment under its separator (`setTimeout`, `MessagePort.postMessage`,
`Promise.then`, `await`, `Microtask` and so on), "on a dedicated worker in
process N" for a segment walked elsewhere, the stated end of a `no_script`
segment, "Earlier async callers were not recorded" for a cut chain, and lists
`async_callers_not_shown`: for version 3, `ServiceWorker.postMessage` and
`Client.postMessage`, and `window.postMessage` to or from another process. A
microtask segment without its registration says that
`REB_NATIVE_PROMISE_STACKS=1` records it.

### Hot path and bounds

- Flag off: one atomic load per scheduling, task run, top-level callback,
  navigation, message post and message receipt.
- Active: a scheduling walk of at most 256 frames, one SHA-256 of at most
  4,144 bytes, one ring entry, and an artifact only for a new stack. A
  top-level callback inside a task allocates one task state. A message post
  adds at most 32 ring reads and 1,560 bytes in the message; a receipt on
  another thread at most 32 ring writes. A schedule with no script running
  costs the session checks only.
- Fixed per-thread tables, part of the [thread](#threads) allocation: 2,048
  segments, 4,096 task attribution IDs, 8 pending form submissions, and with
  `--reb-promise-stacks` 2,048 registrations.
- `--reb-promise-stacks`: see the cost in
  [promise registrations](#promise-registrations).

### Validation

`tests/request_stack_test.cpp` checks both versions, task segments, types 46
to 48 and their envelopes; `make request-stack-wire-check` compares those
verdicts with Python and the Initiator decoders and renders segments and a
navigation stack. `make native-probe-admission-check` drives segments, nested
and microtask links, cuts, the 32-segment and 256-frame bounds, ring eviction,
retention, navigation kinds and form submissions through the real sink.
`make native-network-capture-check` emits and validates the browser link. The
backend resolves segment frames and navigation stacks. The same suites check
task segment version 3, `async_task_stack` version 2 and task origins for
parity and malformed input; the admission suite drives no-script schedules,
message origins on the posting thread and on another thread (copies, wrong or
missing origin, a no-script post, the 32-segment bound, Network off) and
promise registrations (flag off, a thread attached before the flag, the
registration in the microtask segment and in the hop of a task scheduled in a
reaction, dedupe, the 32-frame bound, an unknown reaction, the budget and
capture off). `make request-stack-wire-check` renders a worker stack with a
`Promise.then` registration, a message segment from another process and a
no-script end. The standalone V8 runtime check
(`tools/check-native-v8-runtime.py`) compiles the pinned V8 with every V8
patch and runs `test-api/RebNativePromiseRegistrations` (one report per user
`.then`, `.catch`, `.finally` and `await`, each reaction started and finished
with its ID, nothing while inactive) and
`test-api/RebNativePromiseRegistrationsNeedTheFlag`.

### Acceptance

Still required before declaring this browser-ready:

1. Replay all stacks and overlays on a disposable initialized pinned checkout
   and compile, including the `BeginNavigationParams` mojom change.
2. A `fetch` from `setTimeout`, `requestAnimationFrame`, `window.postMessage`
   and an XHR `load` handler shows the scheduling stack, matching DevTools'
   async stack.
3. A `fetch` in a `.then` callback registered in a timer shows `Microtask`
   then `setTimeout`.
4. `location.href`, `form.submit()` and `window.open` show their stacks on the
   navigation's Traffic row.
5. Measure added time per scheduled task and per request at p50 and p99 on a
   timer- and promise-heavy page before keeping the packaged default on.
6. A `fetch` in a `MessageChannel` handler, a `BroadcastChannel` handler in
   another tab's renderer, a worker's `onmessage` and the page's handler for a
   worker message shows the posting stack and the sender's callers, matching
   DevTools' async stack; a post deferred by prerendering ends with
   `no_script`.
7. With `REB_NATIVE_PROMISE_STACKS=1`, `fetch(a).then(() => fetch(b))` and an
   `await` in a fire-and-forget async function show `Promise.then` and `await`
   with the registering stacks; measure the promise-heavy page with the flag on
   and off, and with DevTools open, before changing its default.
8. An image `load` handler's `fetch` ends its chain with `no_script` instead of
   no segment.
