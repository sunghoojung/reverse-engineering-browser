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
| Brave patch 0021, 0022 | `observe-early-hints-preloads-only`, `decide-native-exclusion-once` | Request scope and tabs |
| `request_body` flag bit 6, state 12 | `read`, `not_captured_read_incomplete` | Request body reads |
| Chromium patch 0025 | `forward-native-network-headers` | Headers and cookies |
| Chromium patch 0026, 0027 | `finish-renderer-answered-requests`, `record-renderer-fetch-owners` | Request scope and tabs |
| Chromium patch 0028 | `record-script-cookie-access` | Headers and cookies |
| Chromium patch 0029 | `record-request-initiator-stacks` | Request initiator stacks |
| Chromium patch 0035, 0036 | `expose-process-lock-scheme`, `name-frameless-script-fetch-owners` | Request scope and tabs |
| Chromium patch 0042, 0043 | `name-worklet-fetch-owners`, `record-early-hints-preloads` | Request scope and tabs |
| Chromium patch 0044, 0045 | `name-browser-prefetch-owners`, `name-service-worker-job-causes` | Request scope and tabs |
| V8 patch 0015 | `capture-native-request-stacks` | Request initiator stacks |
| Chromium patch 0034 | `record-navigation-and-async-initiators` | Navigation and async task callers |
| V8 patch 0017 | `bound-native-async-task-stacks` | Navigation and async task callers |
| Chromium patch 0046 | `record-worker-request-stacks` | Request initiator stacks |
| Chromium patch 0047 | `carry-message-task-origins` | Navigation and async task callers |
| Chromium patch 0048 | `record-promise-registration-stacks` | Navigation and async task callers |
| V8 patch 0021 | `record-native-promise-registrations` | Navigation and async task callers |
| Event type 52 | `memory_cache_reuse` | Request scope and tabs |
| Exclusion class 68, 69 | `service_worker_no_page`, `browser_prefetch` | Request scope and tabs |
| Exclusion class 70 | `memory_cache_reuse` | Request scope and tabs |
| Exclusion class 71 | `non_ordinary_page_reuse` | Request scope and tabs |
| Probe queue version 4 | the memory-cache counters | Request scope and tabs |
| Chromium patch 0038 | `record-synchronous-requests-on-calling-thread` | Request scope and tabs |
| Chromium patch 0039, 0040 | `finish-service-worker-ends`, `record-memory-cache-reuse` | Request scope and tabs |
| `memory_cache_reuse` payload version 2 | flag bit 2 `source_named` | Request scope and tabs |
| `response_body` payload version 2 | flag bit 7 `snapshots_withheld` | Response bodies |
| Chromium patch 0062 | `name-memory-cache-reuse-sources` | Request scope and tabs |
| Chromium patch 0058 | `observe-early-hints-preload-headers` | Headers and cookies |
| `script_cookie` version 3, flag bit 4 | a `document.cookie` read named per cookie | Headers and cookies |

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
`request_initiated`, `request_started`, `request_completed`, `request_failed`
and `memory_cache_reuse`. `request_initiated` (renderer), `request_started`
(browser proxy) and `memory_cache_reuse` always carry it; the renderer
completion below does too. It is one byte
of metadata, so metadata-only sessions can tell a browser-internal row from a
web row whose path was not captured.

### Browser-internal exclusion

Browser-internal evidence is not recorded by default, and every exclusion is
counted:

- A renderer counts a request with a class 16 to 20 instead of recording it.
  One counter per class lives in the shared probe queue (queue version 4, which
  adds the [memory-cache](#memory-cache-reuse) counter), like the drop counter,
  and the browser reports it at the next drain.
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
`devtools_load` count requests (see [below](#traffic-no-tab-caused)). Class 70
`memory_cache_reuse` counts the [memory-cache reuses](#memory-cache-reuse) a
renderer did not record past its budget, which would have been tab rows, and
class 71 `non_ordinary_page_reuse` those in a page that is not ordinary, which
no tab owns; both always have its `initiator_process_id`. Consumers keep 68
and 69 valid. The count is cumulative within the session for
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

`data:` URLs that `fetch`, XHR and other raw loads request, and deferred
`data:` loads, are decoded by Blink's `ResourceLoader` without a URL loader.
That loader records them: a
`request_initiated` with a fresh renderer request ID, the method, an empty host
and class 5, then the completion above once the URL is decoded (status 200, or
the decoding error). A `data:` load cancelled before decoding fails with
`ERR_ABORTED`. A `data:` image, style sheet, script or font loaded at once
never reaches that loader: `ResourceFetcher` decodes it itself and reports it
as a [memory-cache load](#memory-cache-reuse).

#### Synchronous requests

A synchronous XHR (or any synchronous Blink load) is sent from a Blink pool
thread: `ResourceRequestSender::SendSync` posts `SendAsync` there and blocks the
calling thread until it returns. Chromium patch
`0038-record-synchronous-requests-on-calling-thread` moves the start to the
calling thread, which runs the script and is inside the fetch owner scope that
`ResourceLoader::RequestSynchronously` sets:

- `SendSync` takes the request ID from `GenerateRequestId` and records, as
  `SendAsync` does for an asynchronous request, the `request_initiated`, the
  JavaScript invocation request, the `request_initiator_stack` and a Console
  request watch match. So the start names the document's frame (loader kind
  16) or the worker's token (17 to 19), and the stack is walked where the
  script runs, so it has frames like any request on the document main thread
  and, with Chromium patch `0046-record-worker-request-stacks`, on a
  dedicated or shared worker's thread, whose version 3 scope names the worker.
- `SyncLoadContext::StartAsyncWithWaitableEvent` carries that request ID and
  the recorded start to the pool thread's `ResourceRequestSender`, whose
  `SendAsync` sends with that ID and records nothing more at the start.
- The browser proxy's records join the start by that ID, and a synchronous
  request the renderer answers finishes from the pool thread as above, with
  the start's frame and the completion's own thread.

A start the configuration did not admit is not recorded on the pool thread
either.

#### Service worker ends without a response

A page request the controlling service worker handles has no browser record:
`content::ServiceWorkerSubresourceLoader` dispatches it to the service worker
inside the renderer. A response it sends carries `from_service_worker` and
finishes as above. Chromium patch `0039-finish-service-worker-ends` finishes the
rest, when the loader ends a request itself
(`NativeServiceWorkerEndsRequest` in `renderer/native_renderer_request.h`): it
sent no response (`kSentBody`), has not ended the request already
(`kCompleted`), and no race network request answered the page
(`kWithoutServiceWorker`):

- `CommitCompleted` with an error: a rejected or timed-out `respondWith`,
  `Response.error()`, a failed Cache Storage route, a worker that could not
  start, too many redirects. The completion is `request_failed` with that
  error.
- Its `URLLoader` pipe closing (the page cancelled or went away):
  `request_failed` with `ERR_ABORTED`.

Requests the loader hands to the network (fallback, a lost controller) are
finished by the browser proxy, so the loader records nothing for them.

A race network request (`RaceNetworkRequest`, a `race-network-and-fetch-handler`
or `race-network-and-cache` route) sends the request through the browser too,
with the same request ID, so the browser's records join the row. When the
network answers first the page gets its response, and the loader leaves the
end to the browser record. When the worker answers, its response or its end
above is what the page received, and the browser's records are the network
attempt's, which may have completed or been cancelled. At the pin a response
the page receives from this loader carries `was_fetched_via_service_worker`
only from the worker (`SaveResponseInfo`) or from a race the network won
(`ServiceWorkerRaceNetworkRequestURLLoaderClient::OnReceiveResponse`); a
fallback's head gets service-worker timing only (`RewriteResponseHead`). So a
renderer completion with `from_service_worker` on a row that also has browser
records is always a race, and consumers take the row's outcome (failed,
status, error) from that completion, and mark the row `race_network`. That
completion is what the page received whichever side answered; the records do
not say which side that was, so consumers do not name it.

The loader knows only the renderer request ID, so the renderer keeps recorded
http(s) starts in 1,024 slots indexed by the request ID's low 10 bits
(`renderer/native_service_worker_starts.h`), each with its configuration,
sequence, time, frame, thread and scheme class. Every renderer request and
every admitted memory-cache reuse takes a request ID, so any later http(s)
start whose ID is a multiple of 1,024 away replaces a slot. Each slot is a
Boehm-style sequence lock with atomic fields: a reader keeps only a copy that
no writer touched. The end then emits, from the loader's thread, the same
records as above: a `request_target` child in content sessions and the
completion, with the start's frame, flags `from_service_worker` and status 0.

A slot that holds another start of the same configuration, or that a writer is
filling, loses that end: the renderer emits a `gap` of category `network` and
payload `service_worker_end_lost` that names the row as a `request_tab_link`
names a renderer record, `initiator_process_id` and `initiator_request_id` its
process and request ID, with `request_id` and `frame_id` 0 (the start's frame
went with the slot). Consumers mark that row `end_lost`: Traffic reads "End
lost" instead of Pending, and the summary names the gap. A writer that finds
its slot busy, which takes two starts a multiple of 1,024 request IDs apart at
the same moment, skips it, so that end is reported lost too. A slot of an
earlier configuration means the start was not recorded in this one, so nothing
is emitted; a start of this configuration that has since reused the slot of a
request started before it makes that request's end read as lost. One loss is
silent: a start skipped because a writer of a configuration that has since
ended was still filling its slot leaves that earlier start there, so its end
reads a slot of an earlier configuration and emits nothing. It takes a
configuration change during one slot write, and the end then belongs to a
request whose start raced that change.

#### Memory-cache reuse

Blink answers some loads from resources it already holds and creates no
request: `ResourceFetcher::DidLoadResourceFromMemoryCache`, the reuse DevTools
shows as "(memory cache)". It runs when a document first uses a resource
another document loaded (the memory cache), for a `data:` image, style sheet,
script or font, or an MHTML archive resource, that `ResourceFetcher` decoded
itself (static data), and from `EmulateLoadStartedForInspector`, which
`CSSImageValue` and `CSSFontFaceSrcValue` call when a style sheet's cached
image or font is restored into a document, DevTools open or not. A matching
preload never reaches it: the preload's own request already put the resource
in the document's cached resources. Chromium patch `0040-record-memory-cache-reuse`
handles each call after its detached and observer check:

1. `NativeProbeSink::AdmitMemoryCacheReuse` checks the Network category,
   expiry and the page, then charges the configuration's budget. A reuse in a
   page that is not ordinary (`Page::IsOrdinary`, checked by
   `FetchContext::IsOrdinaryPageForNativeCapture`: an SVG image's own document,
   whose `IsolatedSVGDocumentHost` frame the browser never registers, or a
   page popup) belongs to no tab: it is counted as exclusion class 71 and
   charges no budget. A reuse past the budget is counted as class 70. Either
   way nothing else is done.
2. Only an admitted reuse takes a fresh renderer request ID, its fetch owner,
   and bounded prefixes of its host and, in content sessions only, its target
   (`NativeRequestTargetRange` keeps the range inside the URL whatever the
   parser left).
3. One `memory_cache_reuse` (type 52) record, a Traffic row of its own, and in
   content sessions a `request_target` child, as above, with `parent_event_id`
   its sequence.

The record names no method: Blink adds only GET resources to the memory cache
(`ShouldResourceBeAddedToMemoryCache`), and static data is GET too, so
consumers show GET.

The reuse also names the request that loaded the resource. At the pin
`URLLoader::Context` keeps the `int` its `ResourceRequestSender::SendAsync`
returns, which is the `GenerateRequestId` value that request's
`request_initiated` record carries, and `WebURLResponse::Create` sets it as
the response's `ResourceResponse::RequestId()`. The memory cache is per
renderer process and Blink reuses only a resource whose status is `kCached`,
whose response is that load's, so Chromium patch
`0062-name-memory-cache-reuse-sources` passes
`resource.GetResponse().RequestId()` to the sink. A revalidation that Blink
answers `304` keeps the first response's request ID, because
`Resource::RevalidationSucceeded` only updates its headers, so the named
request is the one whose bytes Blink holds. Static data had no request.
`GenerateRequestId` starts each renderer process at a random value from 0 to
2^20 (`GetInitialRequestID` in `web_url_request_util.cc`) and counts up, so 0
is a real ID only when that start is 0, and it is also what a response no
request set carries; a reuse names a source only for an ID above 0 that is
not static data. The source names a row as a `request_tab_link` names a renderer
record: `initiator_process_id` (the record's own process) and
`initiator_request_id`. A reuse's own row stays keyed by its own request ID;
consumers never join it to its source by those fields, and they leave them
out of its legacy browser key. They are never its initiator either: Traffic's
Initiator tab shows the reuse's own renderer request and names the source as
"Reused response of", and `get_xrefs` lists it as `reused_response`. A reuse a worker owns is linked to its tabs by the drain
with a `request_tab_link`, as a worker request start is.

##### `memory_cache_reuse` (type 52)

Category `network`, renderer, the renderer sequence space. `frame_id` and
`loader_kind` name the fetch's owner exactly as on `request_initiated`
([loader kind](#loader-kind) 16 to 22), `scheme_class` the URL's class
(nonzero), `request_id` the fresh renderer request ID, `status_code` the
reused response's HTTP status (0 when it has none: at the pin
`CreateResourceForStaticData` sets none for an MHTML archive resource),
`decoded_body_length` its
decoded body length as DevTools reports it (0 or more). Tab, navigation,
artifact, parent, BrowserContext, encoded length, error, resource type, flags
and initiator fields are zero; the drain sets `tab_id` as for any renderer
record. Payload size 128, little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `2` (`1` in older captures) |
| 2 | 2 | payload size, `128` |
| 4 | 1 | resource type: Blink `ResourceType` at the pin, 1 to 15 |
| 5 | 1 | flags: bit 0 `static_data`, bit 1 `host_truncated`, bit 2 `source_named` (version 2) |
| 6 | 1 | host length, 0 to 120 |
| 7 | 1 | reserved, zero |
| 8 | 120 | host as KURL gives it, zero after its length |

| Type | Name | Type | Name |
| ---: | --- | ---: | --- |
| 1 | `image` | 9 | `text_track` |
| 2 | `css_style_sheet` | 10 | `audio` |
| 3 | `script` | 11 | `video` |
| 4 | `font` | 12 | `manifest` |
| 5 | `raw` | 13 | `speculation_rules` |
| 6 | `svg_document` | 14 | `mock` |
| 7 | `xsl_style_sheet` | 15 | `dictionary` |
| 8 | `link_prefetch` | | |

Bit 0 marks static data (a `data:` URL or MHTML archive resource Blink decoded
in place). Bit 1 marks a host longer than 120 bytes, and then the length is
120. Bit 2, in version 2 only and never with bit 0, says the envelope's
`initiator_process_id` equals its `process_id` and its nonzero
`initiator_request_id` is the source request above; without bit 2 both are
zero. Host bytes are printable ASCII. Other bits and reserved bytes are zero.
Version 1 records, which name no source, stay valid.

A browser-internal URL (class 16 to 20) is counted per class as a request
would be, unless the configuration opts in, and returns its budget charge.
Each renderer configuration records at most 4,096 reuses. Every later one is
counted, not recorded, in the queue's counter for exclusion class 70
`memory_cache_reuse`, and every reuse in a page that is not ordinary in the one
for class 71 `non_ordinary_page_reuse`, so a researcher can tell lost tab rows
from reuses no tab owned. The browser reports each as a cumulative
`capture_exclusion` of that renderer like the scheme counters. The count is tagged with the admitting configuration's generation,
so a reuse still in flight from a replaced configuration neither charges nor
resets the new one's budget, and one it admitted is not recorded into the new
configuration.

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
`request_initiated` and `memory_cache_reuse` (renderer, 16 to 22). JSON carries
it as `loader_kind`, written only when nonzero.

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
| 20 | `other_context` | A context with no parent document, which at the pin is only a shared storage worklet; `frame_id` is the fold of its own token, and the row stays unresolved |
| 21 | `script_context` | No fetch context reached the loader; `frame_id` is the running script's frame, as before #425 |
| 22 | `worklet` | A paint, layout, animation or audio worklet; `frame_id` is the fold of the `LocalFrameToken` of the document that created it, and the record resolves like a document's |

A fold is `rotl(high, 17) ^ low` of the 128-bit token, the same function as
frame ids. A shadow realm fetches through its initiator's `ResourceFetcher`
(`ShadowRealmGlobalScope::Fetcher`), so its requests name that document or
worker. A worklet's `WorkletGlobalScope::GetParentExecutionContextToken` is the
creating document's `LocalFrameToken` for every worklet but a shared storage
worklet, whose parent token is a fresh one, so it is told apart by its own
`SharedStorageWorkletToken`.

#### Where the owner comes from

| Request | Owner | Hook |
| --- | --- | --- |
| Browser record from a frame's factory (document, navigation, a download's frame, a document-created worker's main script, a speculation-rules prefetch's referring frame) | The tab of the factory's frame, resolved when `WillCreateURLLoaderFactory` creates the factory | Brave patch `0017-link-requests-to-tab-owners`. A beacon, keepalive fetch or removed iframe keeps the tab its factory recorded. Redirects stay in the same loader |
| Renderer `request_initiated` | The fetch's `FetchContext`, never the running script | Chromium patch `0027-record-renderer-fetch-owners`: `ResourceLoader` and `BackgroundURLLoader` scope the owner around `ResourceRequestSender::SendAsync`. Parser, preload scanner, CSS and image loads therefore name their document |
| Renderer document record drained late | The browser's frame registry, keyed by process and full frame token, filled at factory creation and from live frames, with tombstones that outlive the frame | `browser/native_tab_resolver.h` |
| Dedicated and nested workers | The creator document's tab, resolved at `DedicatedWorkerService::Observer::OnWorkerCreated` through the creator chain, or when a request is linked if the parent was not known yet | `request_tab_link` kind 1 |
| Shared workers | Every client tab at request start (`SharedWorkerService::Observer::OnClientAdded` / `OnClientRemoved`) | kind 2 |
| Service workers | The version's controlled client tabs (`ServiceWorkerContextObserver::OnControlleeAdded`, `OnControlleeNavigationCommitted` for window clients, `OnControlleeRemoved`); with none, its last client tabs; with none, its registrant tabs; with none, the registration's last client tabs | kinds 3, 4, 5 and 4 |
| Worklet renderer `request_initiated` | The document that created the worklet | Chromium patch `0042-name-worklet-fetch-owners`: `BaseFetchContext::GetNativeFetchOwner` names `GetParentExecutionContextToken()` with loader kind 22 |
| Page request a service worker answers | The page's document (renderer record) plus the renderer completion above | |
| Browser record from a worker factory | Joined to its renderer record (same row) through `initiator_process_id` and `initiator_request_id` | |
| Nested dedicated worker main script | Its factory has no creator frame; `WorkerScriptFetcher::CreateScriptLoader` scopes the ancestor frame, the document at the root of the creator chain, around the factory's creation | Chromium patch `0036-name-frameless-script-fetch-owners` |
| Service-worker main script and update check | `ServiceWorkerRegisterJob` keeps its cause: the `register()` caller (`requesting_frame_id_`), else the frame scoped while the job was created, which is the page calling `registration.update()` (`ServiceWorkerContainerHostForClient::Update`) or the page a payment app is installed for (`PaymentAppInstaller`). It scopes that cause and the registration's active version around both factory creations. The cause's tab is the factory's tab; without one, the request links to the active version's tabs | Patches 0036 and `0045-name-service-worker-job-causes`; `request_tab_link` kinds 3 to 5 naming the browser record |
| A service-worker version's registrant | The cause's tab when the job starts the version, else the active version's tabs at that moment. `ServiceWorkerRegisterJob::StartWorkerForUpdate` notes the version and the cause; the version's install-time fetches and imported scripts link to it while it has no client. A job with a caller that starts no version notes that caller for the registration's active and waiting versions: `ContinueWithRegistrationWithSameRegistrationOptions` resolves a `register()` of the current script against an active version, and `OnUpdateCheckFinished` ends an update whose script is identical. So a page that is no controllee and calls `register()` again before messaging the installed worker is that worker's registrant | Patch 0045; kind 5 |
| Scripts a starting service worker imports | `EmbeddedWorkerInstance::Start`, and `ServiceWorkerDevToolsAgentHost::UpdateLoaderFactories` when DevTools replaces them, scope its version and `ServiceWorkerToken` around both factory bundles: the browser record links to that version's tabs, and the resolver knows the worker before its first fetch can be drained. The renderer's start, with patch 0038 for `importScripts`, is the worker's own request | Patch 0045; kinds 3 to 5 |
| Early-hints preload | The navigating main frame's tab, recorded without changing the preload | Chromium patch `0043-record-early-hints-preloads`: `NavigationRequest::CreateNavigationEarlyHintsManagerParams` creates the factory through `ContentClientParams`, with no frame because the document has not committed, and scopes `FrameTreeNode::current_frame_host()`. Brave patch `0021-observe-early-hints-preloads-only` keeps the preloads as stock: see [below](#early-hints-are-observed-only) |
| Browser-initiated prefetch | The referring `WebContents`' primary main frame | Chromium patch `0044-name-browser-prefetch-owners`: `CreatePrefetchURLLoaderFactory` scopes it; a prefetch with no live `WebContents` is traffic no tab caused (class 69) |

In a capture launch the proxy observes the owned profile's frames and worker
services from its first factory, before any session starts, and fixes each
factory's exclusion class when it is created, so owners and excluded factories
that predate the session still resolve. No worker client can predate that
factory: the owned profile is named in `PreProfileInit`, and
`NavigationURLLoaderImpl::Start` creates a navigation's factory before its
interceptors add a service-worker controllee and before the document commits,
which a dedicated or shared worker client needs. Observing seeds the resolver
from Chromium's registries: `EnumerateDedicatedWorkers` and
`EnumerateSharedWorkers` report the workers alive then, and
`GetRunningServiceWorkerInfos` the running service-worker versions. The
enumeration follows token order, so a nested dedicated worker can arrive before
its parent; each dedicated worker keeps its creator's token, and a request
walks that chain, at most 64 workers, to the root document's tab when it is
linked. A dedicated worker is linked when its chain from the document holds
at most 64 workers; a tab a worker inherits at creation or caches when a
request is linked keeps its depth, so the rule does not depend on the order
workers are seen in or on which one fetches first. A starting service worker
names its token with its factories (patch 0045), so a fetch it makes during
its first script evaluation, before `OnVersionStartedRunning`, still finds it.
A worker entry outlives the worker as a tombstone until the capacity below
evicts it, so records drained or started late still resolve.

#### Early hints are observed only

Stock Brave and Chromium create the early-hints factory without
`ContentClientParams`, so no embedder proxy sees those preloads. Patch 0043
lets them reach `ContentBrowserClient::WillCreateURLLoaderFactory` only so
native capture can record them, and Brave patch 0021 keeps that observational:
`BraveContentBrowserClient::WillCreateURLLoaderFactory` returns for
`kEarlyHints` before both Brave Shields and `ChromeContentBrowserClient`, so
neither Shields nor an extension's `webRequest` or `declarativeNetRequest` acts
on them. While native capture runs for the owned profile it first attaches
Brave's proxy with a request handler that answers every hook with `net::OK`, so
no header, referrer, block or redirect decision changes. Capture itself still
adds five things, none visible to the page, the server or DevTools beyond
timing:

- In content sessions the proxy gives a preload without one a `reb-` DevTools
  request ID (Brave patch 0018), so the network service also sends SSL info
  with the response and transfer-size updates. `NavigationEarlyHintsManager`'s
  `PreloadURLLoaderClient` reads only the response head's cache flags and
  records transfer sizes to UMA.
- In a current content session with the Network category, Chromium patch 0058
  gives the preload factory an agentless DevTools observer, so the network
  service reports the preload's raw headers and cookie lists to the capture
  hook and marks its response head `emitted_extra_info`. Only the throttles
  and `PreloadURLLoaderClient` see that head, and no DevTools agent sees a
  preload ([binding](#network-service-binding-at-the-pinned-chromium)).
- In content sessions the response body is teed for artifact capture, as for
  any request; the manager still drains its own copy.
- Each preload's messages take an extra hop through the proxy on the UI thread.
- A redirect `content::IsSafeRedirectTarget` refuses, to a scheme other than
  http(s), ends the preload with `ERR_UNSAFE_REDIRECT`. Stock Chromium leaves
  that preload stalled until the manager goes at commit, because
  `PreloadURLLoaderClient::OnReceiveRedirect` follows nothing. An http(s)
  redirect passes unchanged and the manager ignores it as before.

Without capture nothing is attached, and the factory is built exactly as
without these patches.

The scoped owner is read by the proxy while `WillCreateURLLoaderFactory` runs
and only for a factory without a frame. A navigation's update hint
(`ServiceWorkerClient::HintToUpdateServiceWorker`) reaches
`ServiceWorkerVersion::ScheduleUpdate`, a coalescing one-second timer that
keeps no client. The hinting navigation's client is a controllee of the active
version (`SetControllerRegistration` comes before `AddServiceWorkerToUpdate`),
so its tab is among the active version's current or last clients that the
update check links to. A client whose navigation never committed has no frame
id, so Chromium names no tab for it; its version still counts as having had a
client, so its requests are reported unresolved, never counted as traffic no
tab caused. `registration.update()` from a dedicated worker needs the
`ServiceWorkerInDedicatedWorker` runtime feature, which is not stable at the
pin, and `self.registration.update()` from the service worker names no caller:
both link to the active version's tabs.

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
| 5 | `service_worker_registrant` | No current or last client of the version; the tabs of the `register()`, `update()` or update hint that installed it, which may be closed |

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
| 68 | `service_worker_no_page` | requests | A service worker's requests when its job named no caller and neither its version nor its registration has had a client, last client or registrant in this browser: a browser-initiated registration or update (DevTools, `chrome://serviceworker-internals`), or a push, sync or other functional event for a registration no page used in this browser run. The proxy, browser-wide, for a script it fetches; the drain, per renderer, for the worker's renderer record, a memory-cache reuse included. The proxy also leaves out such a worker's renderer-issued requests and the scripts it imports, which the drain counts |
| 69 | `browser_prefetch` | requests | The proxy, browser-wide, for a browser-initiated prefetch with no live referring `WebContents` (`PrefetchRequest::CreateBrowserInitiatedWithoutWebContents`, or one whose contents closed first) |

`REB_CAPTURE_EXTENSION_TRAFFIC=1` makes the live launcher pass
`--reb-capture-extension-traffic`; class 65 is then recorded instead of
counted, each request with one `request_extension_link`: the drain links an
extension worker's renderer record, the proxy a worker main script or
service-worker script it fetches. An extension origin whose host is not a valid
id stays counted. Sessions started by `reb-api session start` or
`start_live_session` always set it to 0.

An extension worker's [memory-cache reuse](#memory-cache-reuse) starts its own
row, so the drain treats it as a request start: counted, it adds one to
`extension_worker` requests, and its request ID takes one of the 64 the drain
keeps for excluded extension requests so that the reuse's `request_target`
child is dropped too, as a request's later records are. An excluded ID that
has left those 64 has its later records recorded without their start.

A version only ever gains a page: a client, a last client and a registrant
stay recorded. A renderer-issued request of such a worker has two halves, the
browser record and the renderer record, and they take one decision: the proxy
and the drain each ask `NativeTabResolver::SharedServiceWorkerNoPage` with the
renderer's child id and request id. A script a starting worker imports is such
a request too. Its bundle for new scripts, which `EmbeddedWorkerInstance::Start`
creates inside patch 0045's scope, serves only
`ServiceWorkerScriptLoaderFactory`, and that hands the renderer's request id on
(`ServiceWorkerNewScriptLoader` starts its `ThrottlingURLLoader` with it), so the
proxy asks with that id for each request of that bundle. A memory-cache reuse
never reaches the proxy, so the drain decides it alone. The first to ask decides from the
version's state, keeping a request of a version it does not know, and stores
the answer; the second takes it. Both halves are therefore kept, or both left
out and counted once, by the drain, whichever asks first and whether or not a
page arrived in between. The resolver keeps the 4,096 newest answers. An answer
evicted before its other half asked, where that half could have decided
otherwise alone (a no-page answer, or a keep for an unknown version), is one
named network gap `service_worker_page_decision_unshared`. The second half then
decides alone, from the version's state at that moment, so the halves can
part three ways: the proxy left the browser half out and the renderer record
is kept and recorded alone; the drain kept the renderer record and the browser
half is left out; or one half was left out, counted by the drain if it was the
renderer record, and the other kept, which for a browser half is a row with no
tab, reported unresolved with reason `browser_factory`. The summary names the
gap with that meaning. An answer whose other half never asks, such as a
request the renderer cancelled before sending it or an import
`ServiceWorkerScriptLoaderFactory` answers from storage, is evicted and may be
counted the same way. The count is taken only by a drain the session can
record, at a worker record or when `StopSession` disables the host, and
`StartSession` clears the answers and the count, so neither crosses into
another session. A version the resolver evicted counts as new if it runs again.

Classes 65 and 68 count each request they leave out once: the drain counts a
request that has a renderer record, the proxy a script the browser fetches
with none, such as a worker's main script. An imported script of a starting
worker is two records that never join, the browser's fetch on the new-scripts
bundle and the renderer's start. Chromium patch
`0038-record-synchronous-requests-on-calling-thread` records an `importScripts`
start on the worker's thread, inside its fetch owner scope (see
[synchronous requests](#synchronous-requests)), so it carries loader kind 19
and the worker's token, as a module worker's static imports, which load
asynchronously, always did. Both records link to the version's tabs, or both
are left out and the drain counts the import once, with the worker's other
requests. The only other creator of these bundles at the pin is
`ServiceWorkerDevToolsAgentHost::UpdateLoaderFactories`, which replaces both
of a running worker's bundles through `EmbeddedWorkerInstance::UpdateLoaderFactories`
when a DevTools client enables Fetch interception for it. Patch 0045 scopes the
same owner there, the version and its `start_worker_token()`, so the replaced
bundles name, link and count their requests as the originals did. A memory-cache reuse of a worker no
page used is counted as class 68 by the drain, like its requests. Classes 68
and 69 have no opt-in: no tab caused them and they name no extension.

Content-script requests use their page's document factory and stay with that
tab. Extension pages (background page, popup, options) are their own
`WebContents` and are named by their page like any tab.

#### Unresolved requests

A row (records joined as in Traffic) is unresolved when none of its records
has a nonzero `tab_id` and no `request_tab_link` or `request_extension_link`
names it. `get_session_summary` reports `request_tabs` (rows, unresolved rows
by reason, and up to 16 of them by process and request id with their reason).
Rows of reason `no_document` raise the warning `network_tab_no_document`: the
renderer names no creating document for a shared storage worklet, so the
capture does not link it. Every other reason is the error
`network_tab_unresolved`, whose message counts the rows by reason. The request
index gives each such row its `tab_reason`, and Traffic names it in the row's
tooltip. Traffic shows the count in its footer; the button lists those rows.
They are never hidden.

The reason comes from the row's records: the renderer `request_initiated` when
the row has one, else the newest nonzero loader kind of a browser
`request_started`. The first that applies:

| Reason | Row |
| --- | --- |
| `no_loader_kind` | The renderer record, or every browser `request_started`, has no loader kind (an earlier producer) |
| `worker` | A renderer record of loader kind 17 to 19 that no link names: the worker was never seen or was evicted, its creator chain is longer than 64 workers, or it had no tab and was not counted as traffic no tab caused |
| `no_document` | A renderer record of loader kind 20 |
| `no_frame` | A renderer record with frame 0 |
| `document_frame` | A renderer record of loader kind 16, 21 or 22 whose frame the browser held no tab for: never seen, evicted, or sharing its fold with another frame of the process |
| `browser_factory` | Only browser records: a factory with no frame, scoped owner or version tab, or a scoped owner whose frame was gone |
| `no_start` | No renderer `request_initiated` and no browser `request_started`: the start was dropped by a full queue (the queue reports the drop), is older than the scanned records, or belonged to an excluded request whose later records outlived the drain's 64-request exclusion ring |

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
- Synchronous requests: the same start work as an asynchronous request, moved
  to the calling thread; the pool thread copies one value.
- Service-worker ends, inactive: the loader's hook takes a view of the URL's
  path, reads its port and returns after one atomic load; nothing is
  allocated. Active:
  each recorded http(s) start writes one 48-byte slot of a fixed 48 KiB table
  (a sequence lock; a writer that finds the slot busy skips it, which the end
  then reports as lost), and each end reads one slot and emits at most two
  records and one gap.
- Memory-cache reuse, inactive: one atomic load before the hook converts
  anything. Active: one virtual page check and the admission (the category,
  expiry and budget reads and one compare-and-swap of the budget word). Past
  4,096, or in a page that is not ordinary, that is all, plus one counter
  increment; nothing is converted or allocated. An admitted reuse then takes a
  request ID and its owner, copies at most 121 host bytes and, with request
  content only, a 116-byte target prefix, and emits one fixed-size record and
  that target.
- Tabs, inactive: the loaders' owner scope and the proxy's factory hook add at
  most one atomic load and allocate nothing. Active: one virtual
  call and a thread-local write per load, one registry insert per factory, and
  for worker requests one link record, plus one `tab_set` per new set. A
  request through a factory a service-worker job or worker start scoped adds
  one version lookup and, renderer-issued, one shared answer of at most 4,096;
  linking a dedicated worker walks at most 64 creators.
- The proxy reads the capture state before anything else and decides each
  request's exclusion once (Brave patch 0022), so a request outside capture
  costs the sinks' checks and no resolver lookup.
  The resolver keeps at most 16,384 frames and 4,096 workers, versions and
  clients per worker, evicting the oldest; an evicted owner leaves its later
  records unresolved, which the summary reports.
- The proxy fixes a factory's scope once, when Chromium creates it: a
  command-line read and, for a frameless factory, the scoped owner. Each
  request then costs one classification of its scheme. Admission reads the
  process lock once per bind and drain.

### Consumers

- The broker validates both the scheme class and type 36 in `IsValidEvent`,
  and the loader kind and types 37, 38, 50 and 52.
- `get_session_summary` lists `exclusions` by class and adds the info checks
  `browser_internal_excluded` and `no_tab_traffic_excluded` (classes 65, 66,
  68 and 69), `request_tabs` (with `extension_rows` and `unresolved_reasons`),
  and the error check `network_tab_unresolved`. Class 70 is its own info check,
  `memory_cache_reuse_not_recorded`; class 71 is listed in `exclusions` only,
  since no tab lost a row. The backend keeps types 36 to 38, 50 and 52 in its
  network window.
- Traffic has no Unattributed group. A row is in every tab its records or link
  name, with a marker such as "Service worker · 2 tabs" or, for kind 5,
  "Service worker · installed from 1 tab"; All tabs counts it once. Each chip is named by the tab's newest main-frame navigation; extension
  traffic gets one chip per extension id. The footer counts rows without an
  owner as a capture error and its button lists them.
- Traffic's footer also names the counted service-worker and browser prefetch
  requests no tab caused.
- Traffic shows "N browser-internal requests not recorded" in its footer, names
  hostless rows by scheme (`data:`), and joins renderer targets and completions
  to their row. A reversible "Hide browser-internal" filter in Traffic and
  Sources hides class 16 to 20 rows, internal-scheme sources, and, for
  evidence recorded before scheme classes, renderer-only rows whose host is one
  bare label. It shows the hidden count and never changes stored evidence.
- A `memory_cache_reuse` row is complete: the request index gives it
  `memory_cache` true, its status (status `finished` when the record has
  none, which Traffic shows as "Finished" with "No HTTP status: archive
  resource" for static data, never Pending or No loader), its decoded size and
  a type from its resource type, and Traffic labels it "(memory cache)" in Size, with a General
  note that no request was made (from the memory cache, or decoded from a
  `data:` URL or MHTML archive for static data). The footer shows
  "N memory-cache reuses not recorded" for class 70 and "N memory-cache
  reuses in SVG images or popups not recorded" for class 71.
- A row a service worker ended without a response is failed like any other,
  with "(service worker)" in Size. A row whose renderer completion carries
  `from_service_worker` takes its outcome from that completion; with browser
  records too it is `race_network`, and General says the page received a race
  route's answer, from the worker or the network, and that the browser
  records are the network attempt's. A row a `service_worker_end_lost` gap names is
  `end_lost`, status "incomplete", and reads "End lost".

### Validation

`tests/network_scope_test.cpp` (in `make native-tests`) checks overlay and core
layout parity, every class and many malformed records, and `make
network-scope-wire-check` compares those verdicts with the Python validator
and the shipped readers, then drives the Traffic model through `data:`,
service-worker, opted-in internal and pre-v3 rows.
`make native-probe-admission-check` drives the real renderer sink and
transport through exclusion counting, opt-in, renderer completion, stale and
refused starts and the inactive path; service-worker ends with and without
request content, ERR_ABORTED, a non-http ID, an evicted slot and the row its
gap names, an earlier configuration, one completion on either side of the
`kSentBody` boundary, and the inactive path; four writers against a reader
on one start slot, where any accepted mix of two starts fails (accepting every
read, or ignoring the odd version, fails it); target ranges with empty and
invalid components; and memory-cache reuses with their owner, host, status,
size, target, static data, a 200-byte host, counted internal URLs that return
their charge, a page that is not ordinary and its class 71 count, the 4,096 budget and its class 70
count at no allocation, a new configuration's fresh budget, a reuse admitted
by a replaced configuration, and the inactive path.
`tests/network_scope_test.cpp` also checks type 52 and classes 70 and 71 for parity and
malformed records and keeps 68 and 69 valid, and `make network-scope-wire-check`
drives the Traffic model through memory-cache rows, a service-worker failure, a
race network row and a lost end. `make request-index-check` holds the index to
the model on `data:`, memory-cache, service-worker-failure, race network and
lost-end rows and reads the lost end's status cell. `test29RendererAnsweredRows` in
`make rendered-ui-check` opens a memory-cache row and a service-worker
failure in the packaged app. `make native-network-capture-check`
checks the browser `request_started` scheme class and loader kind, and the
factory scope: which proxy loads are counted where, the links a frameless
service-worker script carries, its registrant link, and the class 68 and 69
decisions.

`tests/tab_link_test.cpp` checks loader kinds, tab sets and links for parity
and malformed records; `make tab-link-wire-check` compares them with the Python
validator and `request_tabs.js`, then drives Traffic rows through multi-tab,
incomplete-set, browser-record, registrant, extension, unlinked and page-name
cases. `make native-artifact-capture-check` drives the real `NativeProbeHost`
drain and `NativeTabResolver` through tombstoned frames, nested dedicated
workers enumerated before their parent, a 64-deep creator chain, shared worker
clients, a service worker with 30 clients, last clients, registrants, versions
with no page, worklet records, counted and opted-in extension workers,
renderers locked to an internal scheme, a worker's memory-cache reuse and the
class 70 and 71 reports. `make native-probe-admission-check` covers the
renderer fetch owner and patch 0042's worklet owner. The drain test also takes
one class 68 answer in both orders, with a page arriving in between, and counts
an evicted answer as a named gap. `make native-tab-registry-check` drives the
production `NativeTabRegistry`, `NativeFactoryScopeOf` and factory owner hook
against pinned content API stand-ins: scoped owners and their flags, class 69,
job notes with the caller's frame alive and gone, starting workers named before
their first fetch, and the worker service observers. The backend's
`request_tabs` tests derive each
unresolved reason.

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
5. With Brave patches `0017-link-requests-to-tab-owners`,
   `0020-scope-native-proxy-factories`, `0021` and `0022` and Chromium patches
   `0027-record-renderer-fetch-owners`,
   `0036-name-frameless-script-fetch-owners` and `0042` to `0045`, run the
   #425 fixture site, with Chromium patch 0038 too: `get_session_summary`
   reports no `network_tab_unresolved`, and each request lands on its tab,
   including a nested worker's main script, a service worker's registration,
   both records of its imported scripts and its install-time `cache.addAll`
   fetches, an update
   check from an uncontrolled page's `registration.update()`, a paint
   worklet's module, an early-hints preload and a speculation-rules prefetch.
   An early-hints preload Shields would block is still loaded, as in stock
   Brave. A push event for a registration no page used in that browser run
   counts its fetches as `service_worker_no_page`.
6. The new tab page's own https requests count as `webui_request`, and a
   `chrome-untrusted:` frame and an open DevTools window add `webui_renderer`
   processes and no scripts to Sources (Chromium patch
   `0035-expose-process-lock-scheme`).
7. With `REB_CAPTURE_EXTENSION_TRAFFIC=1` and an installed extension that
   fetches from its service worker, those requests appear under its extension
   chip and `extension_rows` counts them; without it they count as
   `extension_worker`.
8. With Chromium patches `0038-record-synchronous-requests-on-calling-thread`,
   `0039-finish-service-worker-ends` and `0040-record-memory-cache-reuse`: a
   synchronous XHR from a page script and from a dedicated worker lands on its
   tab with its document frame or worker owner, and each has its call stack
   in Initiator (the worker's with `0046-record-worker-request-stacks`). A
   controlled page whose service worker answers
   `Response.error()`, rejects `respondWith`, and stalls until the page aborts
   the fetch shows three failed rows, none Pending. A `race-network-and-fetch-handler`
   route whose worker answers `Response.error()` before the network shows one
   failed `race_network` row, and one whose network answers first shows its
   network status. A second document loading the first one's script, image
   and style sheet, and a `data:` image, show "(memory cache)" rows on their
   tab; a `data:` image inside an SVG used as an `<img>` adds no row and one
   `non_ordinary_page_reuse` exclusion; a page that reuses more than 4,096
   resources reports the rest as `memory_cache_reuse` exclusions.

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
  A body still arriving is published as `partial` on the schedule in
  [partial bodies](#partial-bodies), whether or not it declared a length. Open
  bodies at capture end or expiry end their stream as one last `partial`
  record, or `not_captured_artifact_unavailable` when no byte has arrived. The
  record of the ended body supersedes every snapshot.

### Partial bodies

Server-sent events, long polling and slow downloads stay open for minutes or
the whole session, so a body is readable while it arrives. A snapshot is a
receiver checkpoint: the receiver copies every byte it holds of the stream
into a new artifact, which a `partial` record names. A snapshot costs a copy of
the whole kept prefix, so the schedule bounds copies by bytes and time instead
of by a count. Snapshot n+1 of an open body is taken when a chunk arrives and
all of these hold:

1. The body grew since snapshot n.
2. At least the larger of 1 s and a 32nd of the body's age has passed since
   snapshot n (since the body opened, for the first). A body open for an hour
   is snapshotted at most about 180 times, a day about 300, so the 16-bit
   partial index is never reached.
3. The copy fits the body's allowance, an eighth of the session's response body
   budget (64 MiB of the default 512 MiB). A quarter of it may be spent at
   once; of the rest, the share spendable so far is the larger of the share of
   the session left when the body opened that has passed, and the share of the
   16 MiB limit the body has filled. So a body spends its allowance evenly over
   the session, or faster when it fills toward the limit.
4. All snapshots of the session together stay within a quarter of the budget
   (128 MiB by default), so whole bodies always keep three quarters, and the
   copy fits what is left of the budget. Snapshots are charged to the budget;
   a receiver refusal refunds them.

A snapshot the spacing holds back is not left waiting for the next chunk: the
first chunk that arrives too soon posts one delayed task on the capture's
sequence for the time the spacing allows, which takes the snapshot then if the
body is still open and the byte bounds allow it. The task finds the body by
key and capture ID, as the completion wait does, so a body that ended or a new
configuration leaves it nothing to do. A burst followed by silence is therefore
published within the spacing.

A snapshot the spacing allows but a byte bound withholds (the body's
allowance, the session's quarter, or the budget) is not taken, and the
session quarter goes to whichever bodies asked first. That is a counted limit:
every later record of that body carries flag bit 7, `snapshots_withheld`
(payload version 2), Traffic says the newest snapshot is older than the
schedule would make it, and `get_session_summary` counts such bodies in
`response_bodies.snapshots_withheld` with a `response_snapshots_withheld`
check. The receiver keeps every snapshot it accepted, so a superseded one
cannot be released to make room.

A body whose kept prefix reaches the 16 MiB limit is sealed: those bytes can no
longer change, so its stream ends there and a `partial` record names that
artifact at once, without a copy. Later bytes are counted, and every later
record of the body, including its end, names the sealed artifact.

The bounds come from real streams. Wikimedia's public `recentchange` event
stream ran at about 60 KB/s (42 events a second) and its `page-create` stream at
about 3.6 KB/s (two 1.3 KB events a second); a chat completion streams 1 to
20 KB/s for under a minute, and a notification channel sends a heartbeat of a
few bytes every 15 to 30 s. In a one-hour session with the default budget:

| Stream | Snapshots | Copied | Newest snapshot at most |
| --- | ---: | ---: | --- |
| 60 KB/s | 33 | 58 MiB | 82 s old, then sealed after 279 s |
| 3.6 KB/s | 93 | 57 MiB | 810 s old |
| 10 KB/s for 60 s | 50 | 12 MiB | 1 s old |
| a heartbeat every 15 s | 84 | 0 MiB | 105 s old |

Snapshots count `partial` records, the seal included; copied counts the
receiver checkpoints, so not the seal. `make native-artifact-capture-check`
replays these streams through the capture itself (chunks every 250 ms for the
fast and chat streams, every 500 ms for the medium one, posted timers run as
the clock passes them) and fails when this table differs from the replay.

A larger budget (`REB_RESPONSE_BODY_BUDGET_MIB`) keeps a medium stream
fresher, because its allowance grows with it; the 1 MiB minimum budget leaves
a body 128 KiB of snapshots, so a stream past that is read when it ends.
`make native-artifact-capture-check` drives a two-hour stream past the old
limit of 15 snapshots and checks the spacing, the allowance, the session share
and its refund, a declared length, and the seal.

### `response_body` (type 33)

Category `network`, the v2 child envelope (flags 0, payload size 128,
navigation, status, error, transfer sizes and resource type zero, the parent's
identity, `parent_event_id` below its own sequence). The parent is the
`response_started` record, or the `request_redirected` record for state 8. Its
time is when the body ended or was snapshotted. Little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `2` (`1` in older captures) |
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
bit 5 completion not observed; bit 6 content type present; bit 7, in version 2
only, a snapshot the schedule's spacing allowed was withheld by a byte bound
([partial bodies](#partial-bodies)). Version 1 records stay valid without it.

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
  each snapshot is charged within its [shares](#partial-bodies), and a receiver
  refusal refunds them. The launcher grows a content session's receiver store
  by both budgets.
- Every refusal is a named state. The session summary counts states 2 and 9 to
  12 under `request_content_not_retained`, category `response_body`.

### Bodies the proxy never sees

Some requests have no browser `response_started`, so they have no
`response_body` record. Each request instead has one body case, which Traffic's
`responseBodyCase` and the request index decide alike
([request index v1](request-index-v1.md)): the state of the newest
`response_body` record of its final `response_started`, or `malformed`, else in
this order:

| Case | The request |
| --- | --- |
| `source_artifact` | A script or Wasm response: kinds 1 and 2 are its body |
| `no_record` | Has a response but no body record: a metadata session, a body still arriving, or a record outside what was read |
| `memory_cache` | Is a `memory_cache_reuse`: Blink answered from a resource it held and made no request |
| `service_worker` | Ended with a renderer completion flagged `from_service_worker`: the worker answered in the renderer |
| `failed_before_response`, `cancelled_before_response` | Failed before any response, with `ERR_ABORTED` for the second, after a redirect or not |
| `interrupted` | The proxy's observation ended first (`proxy_destroyed`, `redirect_handoff`) |
| `end_lost` | A `service_worker_end_lost` gap names it |
| `pending` | Has no response and no end yet, after a redirect or not |
| `redirected` | Was redirected, then ended with no other response |
| `renderer_answered` | Was finished by the renderer without a URL loader (`data:`, `blob:` and other local schemes) |
| `no_response` | Ended with no response record otherwise |

A redirect does not decide the case: a request that fails, is cancelled, ends
its observation or is still open after a redirect is that, so "every response
was a redirect" is said only of one that then ended. A newest record that names
no bytes (a refusal or a malformed record) does not hide the newest retained
`partial` of the same response, which the receiver keeps: the row's
`response_body.earlier_snapshot` names it, and Response and Preview open it
under "Earlier snapshot". The loaded records decide only while they hold the
row's final `response_started` and its body record; otherwise Traffic takes the
index's answer, because a live row's `response_started` can leave the retained
window while its later records stay.

The Response and Preview tabs say which case applies, and never show an
absent body as empty. `get_requests` gives every row its case as
`response_body`, and `get_session_summary` counts the cases in
`response_bodies`, with a `response_bodies_not_observed` check when service
workers, the memory cache or the renderer answered some.

Where those bytes are retained under another request, Traffic shows or links
them instead of nothing:

- A version 2 `memory_cache_reuse` names the request whose response Blink
  reused ([memory-cache reuse](#memory-cache-reuse)). A renderer request ID
  names a row only within its process and session, and a process ID can be
  reused within a session, so the named row is the source only when it was
  requested from the reuse's host (a 120-byte reuse host as a prefix) and
  started before the reuse; otherwise `memory_cache_source.found` is false
  with `reason` `host_differs` or `started_after`, and `not_recorded` when no
  such row exists. A found source's `response_body` is shown in Response and
  Preview, labelled as the reused request's, with a control that opens it, and
  with its state: complete, cut at 16 MiB, a snapshot with how much had
  arrived and when relative to the reuse, stopped mid-body, or not retained.
  For a `multipart/x-mixed-replace` source Blink holds the last part while the
  retained body has every part, which the view says.
- A service worker answer has no digest of its own to match. Traffic lists the
  requests the service worker itself made (`request_started` flag 4) for the
  same host, path and query that started while the page's request was open,
  read through `get_requests` with that time range, and links each with its
  body case. The records do not say whether the worker answered with those
  bytes, so they are linked, never shown as the page's body. When none is
  found, Traffic says what it searched (that time range of the index, or the
  loaded rows when the index could not be read) and when the search stopped at
  its 500-row page; a row without a path (a metadata session records the host
  alone) is not searched. A worker that fetched before the page's request
  opened, fetched another URL, read Cache Storage or built its response leaves
  no match, so no match is never a claim that the bytes are nowhere.
- A `shared` record already names the earlier artifact with the same digest.

#### Service-worker bodies are not retained for the page's request

At the pin no response a service worker sends a page passes through
`BraveProxyingURLLoaderFactory`, which wraps only the network factories
`ContentBrowserClient::WillCreateURLLoaderFactory` hands it:

- A controlled page's subresource request goes to
  `content::ServiceWorkerSubresourceLoader` in the page's renderer. It
  dispatches the fetch event over `blink.mojom.ControllerServiceWorker` and
  sends the worker's response to the page's `URLLoaderClient` from the stream
  or blob the worker's renderer gave it (`StartResponse`); the browser sees
  neither.
- A controlled navigation is answered by
  `content::ServiceWorkerMainResourceLoader`, which the navigation's
  interceptor chain runs instead of the network factory, so the proxied
  network loader is never created for it.
- A fallback, a race network request, a synthetic network request and a
  navigation preload do reach a proxied factory. A subresource fallback uses
  the page's own network factory. For a main resource,
  `ServiceWorkerClient::CreateNetworkURLLoaderFactory` passes the factory for
  each of `kNavigationPreload`, `kRaceNetworkRequest` and
  `kSyntheticNetworkRequest` through `WillCreateURLLoaderFactory` as
  `kNavigation`. Those records are the network attempt's
  ([service worker ends](#service-worker-ends-without-a-response)).
- A navigation the worker answers from `event.preloadResponse` therefore shows
  as its preload request's row: a browser request that
  `ServiceWorkerFetchDispatcher::MaybeStartNavigationPreload` gives resource
  type `kNavigationPreloadMainFrame` or `kNavigationPreloadSubFrame` and the
  `Service-Worker-Navigation-Preload` header, whose body case is that of any
  proxied response and whose body is retained under that row. The navigation
  itself has no row of its own, and the records do not say whether the worker
  answered with those bytes unchanged.

Retaining those bytes would mean a second tee in one of those loaders, one in
the renderer, which may not open harness sockets or send artifacts, and one in
a browser loader the proxy does not own. Both are second capture paths, which
#428 rules out. When the worker took the bytes from its own `fetch`, that
request passes through the proxy and its body is retained under the worker's
row, which Traffic links as above.

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
  for binary), hex in 256 KiB windows paged to the end of the retained body,
  reading the next 2 MiB range when a window passes the bytes loaded. A
  partial record says how many bytes had arrived and when, and whether the
  body was sealed at the 16 MiB limit. Preview shows a bounded
  JSON tree, a raster image whose signature matches its bytes, plain text, or
  markup as source. HTML and SVG are never rendered. Reads are ranged 2 MiB at a
  time and rechecked by size and SHA-256. Both tabs name the body case and its
  links ([bodies the proxy never sees](#bodies-the-proxy-never-sees)).

### Validation

`make native-artifact-capture-check` drives the real network sink, artifact
sink, response capture and production receiver and broker: JSON, gzip HTML,
brotli and service-worker JSON, a fetched PNG, a chunked stream partial then
captured, an aborted prefix, 304, a redirect, a cancelled body, a skipped font,
digest dedupe, budget exhaustion, receiver refusal refund, 50 parallel bodies,
the full pool, 16 MiB truncation, a missing completion, coding order, the
capture-end partial, media opt-in, metadata-only sessions and tee refusal, and
the [partial body schedule](#partial-bodies).
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
transfer-size updates to the loader client, as with DevTools open. Unknown IDs,
such as CORS preflights, are ignored.

A request whose factory has no observer gets no `network` block and no cookie
list. At the pin these are the factories the proxy sees, and the observer each
gets:

| Factory | Where Chromium builds its observer | Observer at the pin | With patch 0058 |
| --- | --- | --- | --- |
| Navigation | `NavigationRequest` passes `NetworkServiceDevToolsObserver::MakeSelfOwned(frame_tree_node_)` as the request's `TrustedParams::devtools_observer` | Yes | Unchanged |
| Document subresources, isolated worlds, keepalive and `fetchLater` | `URLLoaderFactoryParamsHelper::CreateForFrame` and `CreateForIsolatedWorld` (the frame tree node); `KeepAliveURLLoaderService` binds the frame's `subresource_proxying_factory_bundle` | Yes | Unchanged |
| Dedicated worker subresources | `DedicatedWorkerHost` uses `CreateForFrame` of its ancestor frame | Yes | Unchanged |
| Service worker subresources and imported scripts | `EmbeddedWorkerInstance::CreateFactoryBundle`: `MakeSelfOwned(devtools_worker_token)` | Yes | Unchanged |
| Speculation-rules prefetch from a live document | `MaybeMakeSelfOwnedNetworkServiceDevToolsObserverForPrefetch`, per request | Yes | Unchanged |
| Dedicated and shared worker main scripts | `WorkerScriptFetcher::CreateScriptLoader`, only when `RenderFrameDevToolsAgentHost::GetFor` finds a host for the ancestor frame, so only while DevTools is attached to it | No | Not changed (below) |
| Shared worker subresources | `SharedWorkerHost::CreateNetworkFactoryParamsForSubresources` passes `mojo::NullRemote()` | No | Not changed (below) |
| Service worker main script and update check | `ServiceWorkerContextWrapper::GetLoaderFactoryForBrowserInitiatedRequest`: `StoragePartitionImpl::CreateURLLoaderFactoryParams` sets none | No | Not changed (below) |
| Early-hints preloads | `URLLoaderFactoryParamsHelper::CreateForEarlyHintsPreload` passes `mojo::NullRemote()` | No | Agentless observer |
| Browser-initiated prefetch, or one whose initiating document is gone | `MaybeMakeSelfOwnedNetworkServiceDevToolsObserverForPrefetch` returns `mojo::NullRemote()` | No | Not changed (below) |
| Downloads | `CreatePendingSharedURLLoaderFactory` wraps the storage partition's browser-process factory, whose params set none | No | Not changed (below) |
| CORS preflights | The network service's `PreflightController`, with `credentials_mode = kOmit`: it sends no cookie and stores none | Reported through `OnCorsPreflightRequest`, not hooked | No Traffic row |

Capture never changes what a page or a real DevTools session observes, and an
observer is observable: with any observer and a `devtools_request_id`,
`URLLoader::DispatchOnRawRequest` sets `emitted_devtools_raw_request_`, the
response head carries it as `emitted_extra_info`, Blink copies it
(`WebURLResponse`) and `InspectorNetworkAgent` reports it as `hasExtraInfo` on
`Network.responseReceived` and redirects. An agentless observer would make
that `true` with no `*ExtraInfo` event ever following, and a CDP client that
waits for them would stall. So a factory gets one only where no DevTools agent
can see its response heads:

- **Early-hints preloads: built.** Content gives preloads no DevTools
  instrumentation (`TODO(crbug.com/40188470)` in
  `NavigationRequest::CreateNavigationEarlyHintsManagerParams`) and
  `NavigationEarlyHintsManager::MaybePreloadHintedResource` sets no
  `devtools_request_id`; only the Brave proxy's `reb-` ID names the request.
  The head goes to the throttles and `PreloadURLLoaderClient`, whose
  `OnReceiveResponse` reads `network_accessed` and `was_fetched_via_cache` and
  whose `OnReceiveRedirect` ignores it; the `PreloadedResource` it reports keeps
  no head. The page's later use of the cached resource is another request,
  whose head the network service builds for that loader.
- **Shared worker subresources: not built.** `WorkerFetchContext` gives a
  worker request a DevTools ID whenever the worker's network agent is on, and
  that agent reports `hasExtraInfo` from the head.
- **Worker main scripts, service worker main scripts and update checks: not
  built.** DevTools can attach to the worker target alone, without the frame
  host that gives the main script its observer, and the head reaches the
  worker's own reporting.
- **Browser-initiated prefetches: not built.** A prefetch can be served to a
  navigation, which forwards the head's `emitted_extra_info` to the frame's
  DevTools.
- **Downloads: not built.** They load through the storage partition's single
  browser-process factory, which every browser-internal fetch of every
  profile shares and which is created once.
- **A service worker script fetched through a header client** (an extension's
  `webRequest` with `extraHeaders`, or DevTools' Fetch interception) builds its
  params inside `NavigationURLLoaderImpl::CreateURLLoaderFactoryWithHeaderClient`.

A request of a kind not built keeps its provisional headers, reads
`not_reported` and is counted as such.
`tools/check-header-observer-patch.py` (`make lint`) refuses an agentless
observer in any other function, or one without the gate.

Chromium patch `0058-observe-early-hints-preload-headers.patch` gives the
early-hints factory `NetworkServiceDevToolsObserver::MakeSelfOwned(std::string())`.
Every method of that class resolves its DevTools agent from its ID or frame
tree node and returns when there is none, and the empty ID names no agent, so
only the hook (patch 0025, before that lookup) sees the raw notifications. It
is created on the UI thread only while `reb::NativeNetworkHeadersObserved()`
holds: a content session is current, its Network category is on and its
expiry has not passed. Otherwise the factory is built exactly as stock. The
factory belongs to the navigation's `NavigationEarlyHintsManager`, which lives
until the navigation commits or ends, and its observer lives as long as the
factory; a preload still running when the session ends keeps it until the
preload completes, and the hook then forwards nothing.

Every request with a provisional block and no `network` block says why on its
Headers and Cookies tabs and is counted in the session summary (see
[missing final blocks](#missing-final-blocks)).

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
| 0 | 2 | payload version, `3`; readers also accept `1` and `2` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | API: 1 `document.cookie` set, 2 `document.cookie` get, 3 `cookieStore.set`, 4 `cookieStore.get`, 5 `cookieStore.getAll`, 6 `cookieStore.delete` |
| 5 | 1 | flags |
| 6 | 1 | versions 2 and 3: the stack thread of the calling isolate, 1 to 4 as in the [stack scope](#stack-scope), or 0 when the thread was never named; version 1: zero |
| 7 | 1 | reserved, zero |
| 8 | 4 | count: 1 for a write; for a read, reads since this key's previous record |
| 12 | 4 | name length in UTF-8 bytes |
| 16 | 4 | value length in UTF-8 bytes; 0 for a read, except a version 3 read record (flag bit 4), where it counts the names those reads returned that no name record counts |
| 20 | 4 | `document.cookie` string length, set or returned; 0 for the Cookie Store API |
| 24 | 16 | innermost script frame, in the frame layout of `request_initiator_stack` |
| 40 | 32 | stack digest, the `request_initiator_stack` digest of this call's stack, or zero |
| 72 | 32 | SHA-256 of the value (writes), or zero |
| 104 | 24 | the name's first 24 bytes, zero padded |

Flags: bit 0 the name is longer than 24 bytes; bit 1 a script frame was
recorded; bit 2 a stack digest was recorded; bit 3 a read recorded alone
because the aggregation table was full; bit 4, version 3 only, the read record
of a `document.cookie` read.

Rules: API 1 to 6; writes (1, 3, 6) have count 1 and a nonzero value digest,
reads have a zero digest and value length 0, except a version 3 read record;
count is nonzero; bit 0 if and only if the name is longer than 24 bytes, and
name bytes past the name are zero; for API 1 the string length is at least
name plus value length, and for 3 to 6 it is 0; bit 1 if and only if the
frame's kind is 1 or 2 with a nonzero script ID, its combinator 0 and only
frame flag bits 0 and 1, and without bit 1 the frame is zero; bit 2 if and
only if the stack digest is nonzero, and only with bit 1; bit 3 only for a
read; reserved bytes are zero. Versions 2 and 3: byte 6 is 0 to 4; with 0,
bits 1 and 2 are clear, since no frame could be read in a known isolate; with
2 to 4, `frame_id` is nonzero. Version 3: bit 4 only with API 2 and a name
length of 0; an API 2 record without bit 4 is a name record, which never has
bit 3 and whose string length is at least its name length. Versions 1 and 2
have no bit 4: their API 2 records are whole reads with no name, which is why
version 3 exists.

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

A `document.cookie` read records each cookie name the returned string holds,
so a cookie's provenance finds the scripts that read it. The sink splits the
string as the page would: at `;`, then at the first `=`, whitespace trimmed;
an entry with no `=` is the empty name, as `CanonicalCookie::BuildCookieLine`
writes a nameless cookie as its bare value, and an empty entry is no cookie. A
name the jar holds twice (another path or domain) counts once per read. Each
read is one read record (bit 4, no name) after one name record per name:
names only, never a value or a value digest, since a read is frequent and its
values are already in the request's sent cookie list. A read parses at most
360 names, the most Chromium returns to one read at the pin: 180 cookies per
eTLD+1 (`CookieMonster::kDomainMaxCookies`) and 180 partitioned ones
(`kPerPartitionDomainMaxCookies`). Every name past them, and every name the
table below cannot hold, is counted at offset 16 of the read record, so an
absent name record is never silent.

Reads are frequent, so each renderer aggregates them per frame, thread, API,
script frame, name and read record in a 4,096-key table per configuration:
one script position reading a jar of 100 cookies uses 101 keys. A key records
its 1st, 2nd, 4th, 8th and later power-of-two reads, each with the reads since
the previous record (and, for a read record, the unrecorded names since then),
and its remainder when the configuration ends. A new read record or Cookie
Store read while the table is full is recorded alone with bit 3; a new name
then is counted on its read record instead. The table is open-addressed at
most half full, so a lookup is a hash and a few probes; it is allocated when a
content-capture configuration starts, on the transport sequence (336 KiB),
and freed when it ends, so a read never allocates and a metadata-only session
holds none.

#### Cookie bounds

- Disabled or metadata-only: no cookie list is serialized, and a script cookie
  call costs one atomic load.
- A sent and a received list per hop, at most 2 MiB each, sharing the header
  table and budget.
- Script cookie records: one per write, at most 2 + log2(reads) per read key,
  and one per read past the table; each is one 320-byte record, one SHA-256 of
  the value and a one-frame stack capture. With request stacks on, a write
  walks its stack instead, inside the request stack bounds.
- A `document.cookie` read: one pass over the returned string, at most 360
  table lookups and at most 361 records (its first read). The configuration
  end records at most 4,096 remainders into the renderer's 8,192-record ring;
  a full ring counts them as drops, as for any record.

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
when their value digests are equal. A `document.cookie` read joins a name by
its version 3 name record. `read_coverage` counts the reads that may hold the
name without naming it: `whole_jar_reads` (version 1 and 2 reads, recorded
before names were) and `reads_with_unrecorded_names` with their
`unrecorded_names`; `complete` is true only when both are zero, so an absent
read is proof only then.

Origin Trace's **Cookies** tab shows Request cookies, with "Show filtered out
request cookies" listing excluded ones and each reason, and Response cookies
with name, value, domain, path, expiry, size, HttpOnly, Secure, SameSite,
partition key, priority and block reasons. Columns sort, long values truncate
with the full value as a tooltip, and each value copies. A name opens its
provenance. Values are inserted as text after a size and SHA-256 check.

### Bounds and hot path

- Disabled or metadata-only: unchanged. The proxy adds no ID, the hook
  costs one atomic load per DevTools raw notification, and an early-hints
  factory costs one atomic load and is built as stock.
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

### Missing final blocks

A content session records a `browser` request block for every hop, so a hop
with one and no `network` block is a request the network service did not
report. Its reason comes from the request's own browser records (those with a
browser context), decided in this order:

| Reason | When | Meaning |
| --- | --- | --- |
| `in_progress` | The final hop, before `request_completed` or `request_failed` | Not an outcome yet; never counted |
| `download` | `request_started` has loader kind 2 | Downloads use the browser-process factory, which has no observer ([binding](#network-service-binding-at-the-pinned-chromium)) |
| `service_worker` | The final hop's `response_started` has flag 4 | A service worker answered; nothing reached the network |
| `from_cache` | The final hop's `response_started` has flag 2 | The HTTP cache answered without sending a request, so there are no sent headers or cookies; DevTools shows provisional headers too |
| `failed` | The final hop ended with `request_failed` and no response | It failed before the network service reported what it sent |
| `not_reported` | Anything else, and every earlier hop without a block | No observer on its factory, or the block arrived for a request the sink no longer tracked (the unattributed count) |

`get_request_headers` gives each hop `network_block_missing` and
`get_request_cookies` gives each hop `sent_missing` and, for a hop with a sent
list but no received one, `received_missing` (`in_progress`, `failed` or
`not_reported`, since the received list comes with the response headers).
Origin Trace's Headers tab adds the reason to "Provisional headers are shown",
and the Cookies tab lists each such hop with it.

`get_session_summary` counts, over the newest 64 MiB of events:

- every header block and cookie list in states 4 to 8, as
  `request_content_not_retained` with category `request_headers`,
  `response_headers` or `cookie_list` and the state as its reason;
- the unattributed blocks and lists, the newest count each producer carried,
  as `network_headers_unattributed`;
- the requests whose final hop ended without a `network` block, one
  `final_headers_missing` check per reason: `info` for `download`,
  `service_worker`, `from_cache` and `failed`, `warning` for `not_reported`.
  It follows at most 131,072 browser requests; records of later ones are
  counted as `final_headers_untracked`.

The Traffic footer shows the same counts for the loaded rows, with reasons.

### Consumers

- The broker accepts types 30 and 31 only when `IsValidEvent` does. The
  backend's network window keeps them with the lifecycle records. Neither
  becomes a lifecycle record.
- Origin Trace's **Headers** tab shows General (URL, method, status, remote
  address, referrer policy), Response headers and Request headers per hop. A
  hop with only a `browser` request block reads "Provisional headers are
  shown" with its [reason](#missing-final-blocks). Each section collapses and
  has a Raw view and copy actions. Values are inserted as text after a size
  and SHA-256 check.

### Validation

`make native-network-capture-check` drives the sink: disabled and metadata
sessions, provisional, network and response blocks over two redirect hops,
out-of-order raw notifications, early hints, pseudo-headers, sharing, a
200 KiB block retained whole, the block limit and the session budget.
It also drives sent and received cookie lists with blocked cookies, an
unparsed `Set-Cookie`, sharing and late lists. `make native-probe-admission-check`
drives the renderer cookie sink: disabled, metadata-only, writes, read
aggregation, a full table and the configuration-end remainder, and per-name
reads: the page's split, a name held twice, the empty jar, the 360-name bound,
a table that fills during a read, unrecorded names in the remainder, and reads
that allocate nothing. The capture check also asserts that
`NativeNetworkHeadersObserved`, the gate of patch 0058, holds only for a
current content session with the Network category before its expiry.
`tools/check-header-observer-patch.py` refuses an agentless observer outside
the early-hints factory or without that gate.
`make native-tests` and `make network-request-wire-check` compare the C++
verdicts with the Python validator and the shipped decoders. The backend's
`request_headers`, `request_cookies` and `session_summary` tests and
`tools/check-traffic-headers-ui.mjs`, `check-traffic-cookies-ui.mjs` and
`check-native-only-ui.mjs` check each missing-block reason, the per-name read
coverage, the refusal counts and the footer. Patch 0058 was replayed on the
pinned sources; it has not been compiled.

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
5. On the same fixture, read `document.cookie` from two script positions and
   confirm each cookie's provenance lists both reads with their counts.
6. Serve a 103 with a cookie-carrying `Link` preload and confirm the preload
   has a `network` block and both cookie lists. With DevTools open on the
   page, and on a shared worker that fetches a subresource, confirm
   `hasExtraInfo` and the `*ExtraInfo` events match a build without patch 0058.

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
  service worker thread ([threads](#threads)), up to 32 workers with tables
  per renderer. Worklets and the background loader thread have no tables and
  record `unsupported_thread`. A synchronous XHR's start is recorded and walked
  on its calling thread, not on the pool thread that sends it
  ([synchronous requests](#synchronous-requests)).
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
| 3 `unsupported_thread` | A thread with no tables: a worklet or the background loader thread. Version 1 and 2 producers also used it for workers. A synchronous request is walked on its calling thread ([synchronous requests](#synchronous-requests)) |
| 4 `not_retained_artifact_unavailable` | Frames walked; Artifact category off or no artifact path |
| 5 `not_retained_budget` | Frames walked; this thread already sent 1,024 stack artifacts in this configuration for requests, navigations, cookie writes and debugger observations, which share that thread's budget |
| 6 `not_walked_thread_limit` | Version 3: nothing was walked, because 32 other workers in this renderer held stack tables ([threads](#threads)); the scope names the worker |

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
- States 2, 3 and 6 have every count, the digest and the innermost frame zero;
  only bit 3 may be set, and from version 2 no flag.
- Version 3: bytes 80-95 are a valid stack scope, all zero for state 3, and
  bytes 96-127 are zero. Earlier versions: bytes 80-127 are zero, and state 6
  does not exist.
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
thread's walks read or write them, so a walk takes no lock after its first.

- Naming. Blink names the document main thread's isolate at V8 initialization
  and each dedicated, shared and service worker's in
  `WorkerThread::InitializeOnWorkerThread`, once its global scope exists,
  with or without `--reb-request-stacks` (`AttachThread`). Naming is two
  thread-local stores: nothing is allocated and no lock is taken, under
  `WorkerThread::lock_` or anywhere else. A second call keeps the first name.
  The name is what `script_cookie` records carry (byte 6), so it exists without
  the provider too. Worklets, the background loader thread and the pool
  thread synchronous XHR uses are never named.
- Tables. A named thread's tables (539,920 bytes) and Blink's buffer for V8's
  frames (1,056 frames of 16 bytes, 16,896 bytes) are allocated by its first
  call that needs them while capture is active: a walk (a request start, a
  schedule or post with script running, a navigation, a cookie write, a
  promise registration or a debugger observation) or a message receipt.
  Never by naming, and never by a schedule or post with no script running,
  whose `no_script` handle needs no tables (worker start schedules such tasks
  under `WorkerThread::lock_`). So a worker that does neither under an active
  configuration costs nothing. With `--reb-promise-stacks` the tables also
  hold the 2,048-entry registration ring (114,688 bytes). Walks run from
  script and receipts from message dispatch, after worker initialization and
  outside `WorkerThread::lock_`; the call that makes the tables takes the
  registry lock once to register them. Nothing else allocates.
- Limit. At most 32 worker threads per renderer process have tables
  (`kNativeStackThreadLimit`), so at most 17,818,112 bytes of worker tables
  and buffers, or 21,488,128 with promise stacks; the document main thread is not counted. A worker that
  walks while 32 others hold tables walks nothing: its requests record state
  6 `not_walked_thread_limit` with its scope, its schedules and received
  messages are not remembered, and one `request_stack_thread_limit` gap per
  configuration counts the thread. Its place is taken by the first call that
  makes tables after a worker's tables are freed.
- Shutdown. `PerformShutdownOnWorkerThread` frees a worker's tables and Blink's
  buffer and forgets its name and its place.

A browser refusal (`NativeStackArtifactRefused`) arrives on the transport's
sequence for the record that created a stack artifact. Every refusal is either
applied or covered, and a cover is counted; none is lost unseen. The order:

1. Before `CaptureGeneratedArtifact` sends an artifact, the walk adds its
   creator sequence, digest and budget to the thread's queued index and
   stores one word, the creator sequence and the table's ordinal together,
   into the 8,192-slot owner ring with release. One word is one writer's
   pair, so two writers that claimed the same slot 8,192 claims apart replace
   each other's word and never mix one's creator with the other's table. A
   creator of 2^44 or more, or an ordinal above 2^20 - 1, stores no word.
2. The browser refuses only an artifact it received, so the refusal follows
   step 1. Under the registry lock it goes to the table whose word holds its
   creator (read with acquire). When no word holds it (the slot was reused, or
   the pair did not fit), it goes to every table with a scope instead; each
   looks the creator up in its own queued index, so only the owner acts on
   it.
3. Each table's mailbox is a 256-entry single-producer, single-consumer ring
   that never overwrites: the producer reads the consumer's published tail with
   acquire and stores an entry only into a free slot (the entry as plain
   memory, then the head with release). With every slot in use it sets the
   table's overflow flag with release instead. Because the entries are plain
   memory ordered only by the head and tail, a slot reused before the consumer
   copied it is a data race ThreadSanitizer reports.
4. The owning thread drains at the start of its next walk: head with acquire,
   the entries below it copied, the tail published with release (only then
   can the producer reuse those slots), then the overflow flag exchanged.
   Each found refusal refunds its budget, forgets its digest and, in one scan
   of the segment and registration rings per drain however many arrived, stops
   calling captured any segment or registration on that digest. An overflow
   instead forgets every digest, stops calling any remembered segment or
   registration captured, and counts a `request_stack_refusals_overflowed`
   gap.

The queued index holds 4,096 entries, more than the three budgets' 3,072 that
can be outstanding in one configuration (each refusal removes its entry and
refunds its budget), so an entry is never displaced; it is cleared when the
configuration changes, when an older configuration's refusals no longer
matter. A refusal for a thread that has detached changes nothing: its
segments are gone with it.

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
null), null for `unsupported_thread`. `not_walked_thread_limit` keeps its
scope and has no digest, frames or segments. The request index keys identities by
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
  says which worker kind started it, and `not_walked_thread_limit` says no
  stack was walked because 32 other workers held tables. The Traffic table's
  Initiator column reads "Worker script", "Worker loader" and "Worker, not
  walked" for version 3 worker stacks. Budget notes name the thread's own
  budget and which one: request stacks, scheduling stacks or promise
  registration stacks. Captured values are inserted as text.

### Hot path and bounds

- Flag off: one atomic load per request start.
- Flag on, inactive session or category off: the existing `request_initiated`
  checks; no walk.
- Active: one V8 walk into the thread's frame buffer (1,056 frames), one
  SHA-256 of at most 18,480 bytes, one 320-byte record. First sightings add
  one artifact, and for each new script one record and one source copy.
  Draining routed refusals is two loads when none arrived; a drain that found
  some does one scan of the 2,048-entry segment ring (and the registration
  ring) however many it applies, plus a bounded index lookup per refusal.
- Memory: 556,816 bytes per thread with tables (539,920 of tables, refusal
  mailbox, queued index and recent posts, 16,896 of Blink's frame buffer), plus 114,688 for
  the registration ring with `--reb-promise-stacks`. Allocated by the thread's
  first walk or message receipt while capture is active, never when it is
  named or by a schedule with no script, and freed when a
  worker stops; at most 32 workers per renderer have them
  ([threads](#threads)). The owner ring is 64 KiB of process-static storage,
  untouched until a stack artifact is queued.

### Validation

`tests/request_stack_test.cpp` (in `make native-tests`) checks layout parity
with the overlay, every state and version, stack scopes, the frame bounds and
malformed records.
`make native-probe-admission-check` drives the real renderer sink with a
fixture provider: disabled, 150 and 5,000 frames, Wasm and `await` frames,
repeated stacks, table eviction, budgets and script identity, and on a second
thread a dedicated worker's own tables, scope, frame IDs and identities; that
naming allocates nothing, a schedule or post with no script makes no tables,
and a thread's first walk or message receipt makes them;
refusals routed from the transport's thread; a counted mailbox overflow; a
refusal whose owner slot 8,192 newer artifacts reused, which still reaches its
owner; over-full bursts from the transport's thread, each counted as an
overflow, after which every refused stack is sent again; refusals racing
drains on two threads, which lose none and are clean under
`REB_PROBE_TEST_SANITIZERS=thread`; the
32-worker limit, its state 6 records and its gap once per configuration; a
thread with no tables and detach.
`make request-stack-wire-check` compares the C++ verdicts with the Python
validator and the Initiator decoder and renders the Initiator panel in a DOM
model. The backend's `request_stack` tests resolve inline, `eval`, Wasm and
`await` frames, resolve stored frames whose only source is a compiled script
artifact, resolve one script ID to different sources in a worker and in
another renderer, and refuse to guess unresolved ones. `make
request-index-check` covers the worker Initiator column labels, `worker_unwalked`
included.

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

Not shown, and listed with every version 3 stack (`async_callers_not_shown`):
`ServiceWorker.postMessage` and `Client.postMessage`, whose browser path
carries no origin; `window.postMessage` to or from a frame in another process
(kind 5 covers same-process frames); `MessagePort.postMessage` from a
worklet, which has no tables, so its message carries no origin and the
handler's chain is cut; the task a promise reaction in a worker continues,
since Blink tracks task attribution only on the document main thread, so a
worker microtask's chain is cut after its kind 9 segment; and reactions a
builtin registered (`Promise.all`, `race`, `any`, `allSettled` and the like),
which V8 tags for neither DevTools nor REB, so they read `not_recorded` (a
combinator still shows as its frame in an `await` chain). A microtask's
registering call is also `not_recorded` without `--reb-promise-stacks`, when
capture was off at registration, or after 2,048 later registrations on its
thread; version 3 kind 9 `not_recorded` segments say which with flag bit 1.
A worker past the [thread limit](#threads) carries no origin either.

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
| 1 | 1 | state: 1 captured, 4 not retained (Artifact off, or the browser refused its artifact), 5 not retained (the thread's scheduling budget, or its registration budget for kind 9), 6 not recorded (kind 9 only), 7 `no_script` (version 3, not kind 9), 8 `origin_rejected` (version 3, kinds 10 to 12) |
| 2 | 1 | flags: bit 0 the walk stopped at its frame limit; bit 1, version 3 kind 9 in state 6 only, promise registration stacks were on but no registration was remembered |
| 3 | 1 | version 3, kind 9 in state 1, 4 or 5: the registration (1 to 4, as in `async_task_stack`); else zero |
| 4 | 4 | frames in its stack: 1 to 256, or 1 to 32 for a kind 9 registration; 0 in states 6, 7 and 8 |
| 8 | 8 | reserved, zero |
| 16 | 32 | its `async_task_stack` artifact digest; zero in states 6, 7 and 8 |

A state 7 or 8 segment is the last one, and its artifact has neither bit 3 nor
bit 4 set. Segments carried by a message keep the state they had when posted.

Each thread remembers 2,048 segments and 4,096 task attribution IDs per
configuration; a task scheduled inside a microtask stores a kind 9 segment in
front of itself, so the hop keeps its registration. A chain that reaches a
forgotten segment, a microtask whose attribution names none, or a message
that carried no origin, sets bit 3 and stops; a message whose origin was
rejected ends at its `origin_rejected` segment; 32 segments set bit 4, and so
does a copy of a sender's chain that went on past the 32 it carried. When the
browser refuses a stack artifact, every segment and registration that thread
remembers naming that digest changes from state 1 to state 4, so later chains
stop claiming it ([refusal order](#threads)). Artifacts already sent keep the state they were written with.

#### Message task origins

`MessagePort.postMessage`, `BroadcastChannel.postMessage`, `Worker.postMessage`
and a dedicated worker's `postMessage` walk the posting stack like any schedule
(kinds 10 to 12, or a `no_script` segment) and carry a task origin in the
message beside Chromium's `sender_stack_trace_id`: `BlinkCloneableMessage`
moves it across threads, and the `CloneableMessage` mojom field
`reb_task_origin` carries it to other renderers, directly for a `MessagePort`
and through the browser's `ShallowClone` for a `BroadcastChannel`. It is never
stored as such. Little endian:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | version, `2` |
| 2 | 1 | segments n, 1 to 32 |
| 3 | 1 | flags: bit 0 the sender's chain was cut after these (a caller not recorded or no longer remembered); bit 1 it went on past these 32; never both |
| 4 | 4 | reserved, zero |
| 8 | 48 x n | version 3 task segments, nearest first: the posting segment (kind 10 to 12), then the sender's chain |

What crosses is the minimum the receiving thread needs to write the chain into
its own stack artifacts: per segment its kind, its state (1, 4, 5, 6, 7 or
8), its flags (bit 0 the walk stopped at its frame limit; bit 1, kind 9 in
state 6, promise registration stacks were on), its registration, its frame
count and the SHA-256 digest naming its stack artifact. That artifact was
stored by the renderer that walked the segment: the poster for its own
posting segment, an earlier renderer for one the poster had itself received.
Segments travel onward: a handler's own posts carry the segments it received
after its posting segment, so a segment can pass through every later hop of
a message chain, never more than 32 segments in one message. The origin names
no process, thread, table or serial: version 1 carried the sender's OS process ID, a table number and
the posting segment's serial so that a receiver on the posting thread could
link the posting segment in place. The posting thread now finds its own posts
in a record it keeps (below), and every other receiver stores copies, which
give the same chain. A no-script or `origin_rejected` segment is only last,
with neither flag (a handler whose origin was rejected carries that end on
when it posts), the posting segment is never `origin_rejected`, and bit 1
needs 32 segments.

At most 1,544 bytes per message, built from at most 32 ring reads when the
message is posted. The receiving renderer treats the bytes as untrusted and
the message itself is never affected:

- Absent while capture is active: the sender carried nothing (capture off
  there, a worklet, or a worker past the thread limit), so the caller is
  unknown and the handler's chain is cut (bit 3).
- Present but not valid, or naming another kind than the API that received
  it: rejected. Nothing of it is kept; the handler's chain ends at a segment
  of the receiving kind with state 8 `origin_rejected`, and each rejection
  counts one `message_task_origin_rejected` gap.
- Longer than 1,544 bytes: the Mojo traits of both `CloneableMessage`
  variants (`blink::CloneableMessage`, which the browser reads when it relays
  a `BroadcastChannel` post, and the renderer's `BlinkCloneableMessage`) and
  `ShallowClone` replace it, without reading it, with one zero byte
  (`kRebTaskOriginOversize`), which never validates, so the receiver rejects
  and counts it as above. `kRebTaskOriginMaxBytes` in
  `third_party/blink/public/common/messaging/cloneable_message.h` is
  static-asserted equal to the contract's bound.
- Valid, on the thread that posted it: each thread remembers its last 16
  posts (the configuration, an FNV-1a hash of the origin bytes and the
  posting segment's serial; kept on that thread, never sent). When one
  matches and the chain rebuilt from that segment equals the carried bytes
  and flags (at most 32 ring reads), the handler's task continues the posting
  segment itself and nothing is copied. So a scheduler that re-posts itself
  through a `MessageChannel`, as React's does, writes one ring entry per tick,
  and older tasks are not pushed out of the 2,048-entry ring. A chain that
  changed since the post (a refused artifact, a forgotten caller) is copied
  instead.
- Valid, anywhere else: the carried segments are copied into the receiving
  thread's ring (at most 32 writes), farthest first, the last one marked cut or truncated as
  bit 0 or 1 says, so a request in the handler lists the posting stack and
  the sender's callers, with bit 3 or bit 4 as the sender's chain had. Each
  copied segment's frames resolve in the scope of its own artifact. A sender
  that has since shut down changes nothing: the copies are already complete.

What it exposes, to whom, and where it is stored is in
[SAFETY.md](../SAFETY.md#default-capture).

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
therefore off by default, including in the packaged app. On each microtask
segment without a registration the Initiator tab says which applies: flag bit
1 clear, promise registration stacks were off; set, they were on but the
thread remembered no registration (a builtin registered it, capture was off
then, or 2,048 later registrations replaced it). `SetNativePromiseCallbacks`
with null removes the callbacks and clears the promise-hook bit they set, but
the promise-hook protector that installing invalidated stays invalid, so the
isolate keeps V8's slower promise path; Blink installs them once per isolate
and never removes them. The V8 cctests remove them before they end.

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
`async_callers_not_shown`: for version 3 the five callers listed under
[task chain](#task-chain). Each segment adds `promise_stacks_on` (kind 9 only,
flag bit 1, else null). A microtask segment without its registration says
whether promise registration stacks were off (and that
`REB_NATIVE_PROMISE_STACKS=1` records them) or on with nothing remembered; an
`origin_rejected` segment says its sender is not known; a `not_retained_budget`
segment names its thread's scheduling budget, or its registration budget for
a microtask.

### Hot path and bounds

- Flag off: one atomic load per scheduling, task run, top-level callback,
  navigation, message post and message receipt.
- Active: a scheduling walk of at most 256 frames, one SHA-256 of at most
  4,144 bytes, one ring entry, and an artifact only for a new stack. A
  top-level callback inside a task allocates one task state. A message post
  adds at most 32 ring reads, one hash of at most 1,544 bytes and those bytes
  in the message; a receipt on the posting thread one hash and at most 32
  ring reads, elsewhere at most 32 ring writes, or one gap record when its
  origin is rejected. A
  schedule with no script running costs the session checks only.
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
parity and malformed input (the version 1 origin that named a process and
table, reserved header bytes, cut with truncated, truncated below 32, a
carried `origin_rejected`, the oversize marker and an origin above 1,544
bytes); the admission suite drives no-script schedules, message origins (that
nothing beyond the segments crosses, copies on the posting thread and on
another thread, forged same-table, damaged, oversize and wrong-kind origins
rejected with a gap each, a missing origin cut, a worker that posts and shuts
down before the page receives, a no-script post, cut and truncated ends
carried apart, Network off) and promise registrations (flag off, tables made
before the flag, the registration in the microtask segment and in the hop of
a task scheduled in a reaction, dedupe, the 32-frame bound, an unknown
reaction marked with promise stacks on, the budget and capture off, where an
attached worker never makes its tables). The Mojo traits and `ShallowClone`
bound are Chromium code no host harness compiles; the harness covers what the
receiver does with their oversize marker. `make request-stack-wire-check` renders a worker stack with a
`Promise.then` registration, a message segment from another process and a
no-script end. The standalone V8 runtime check
(`tools/check-native-v8-runtime.py`) compiles the pinned V8 with every V8
patch and runs `test-api/RebNativePromiseRegistrations` (one report per user
`.then`, `.catch`, `.finally` and `await`, each reaction started and finished
with its ID, nothing while inactive, then removal restoring the promise-hook
bit with nothing reported and the protector still invalid) and
`test-api/RebNativePromiseRegistrationsNeedTheFlag` (nothing installed without
the flag, and removal harmless).

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
9. A service worker's `cookieStore.set` shows the worker's script in Cookie
   provenance, not a page script with the same ID; a `BroadcastChannel`
   message whose origin a test build corrupts reads `origin_rejected` with one
   `message_task_origin_rejected` gap; a page that starts 40 workers which
   each `fetch` shows `Worker, not walked` for the workers past 32 and one
   `request_stack_thread_limit` gap per such worker.
