# Request index v2

Status: implemented in the Rust backend (`apps/origin-trace-backend/src/request_index.rs`)
and Traffic (`apps/research-ui/traffic_index.js`). The bundled `reb://`
stored-evidence workspace answers it, and the filtered `get_events` reads of a
row, through the bundled backend
([`StoredEvidenceBackend.swift`](../apps/research-ui/macos/StoredEvidenceBackend.swift)).

## Why

The polling window (`GET /api/events`) keeps the newest 5,000 network events.
A request is four to seven records, so Traffic could show only the last 700 to
1,250 requests of a session, and its counts described that window. The index
keeps one summary per request for the whole session.

Version 1 held every row in memory and in one JSON file, so it stopped at
131,072 requests, 8 members and 8 response-body parents per row, 4,096 worker
tab sets of 256 tabs, 16,384 script identities, 65,536 `script_cookie` records
and 512 domain facets, and a session past them lost rows, counts and
resolutions. Version 2 keeps the rows in a database beside the store and has
none of those limits: memory stays bounded by the database's page cache
whatever the session's length, and every request of the session is a row.
Its answer is `format: "reb-request-index-v2"`; it drops
`index.unindexed_records`, `index.request_limit`, each row's
`members_limited` and `facets.domains_truncated`, which only described those
limits. The response-body counts of `get_session_summary` drop
`unindexed_records` for the same reason.

## Rows

The backend folds every network lifecycle record (`request_initiated` through
`request_failed`, and `memory_cache_reuse`, which is a whole row on its own)
and every `request_target` and `request_body` child of the event store, in
store order, into one row per request. Row identity, method,
path, status, type, time, tab and the target join follow `requestsFromEvents`
in `apps/research-ui/evidence_models.js`; `make request-index-check` replays one
fixture through both and requires equal rows, sort orders, search and filter
matches, sizes and timelines.
Browser keys that correlate a loader with its renderer request are learned in
store order, so a key that only a later record establishes does not merge rows
already indexed.

Rows also carry what the lifecycle records hold beyond the row model:

| Field | Source |
| --- | --- |
| `transfer_size`, `resource_size` | The last terminal record's `encoded_data_length` and `decoded_body_length`; null when negative or absent |
| `from_cache`, `from_service_worker` | `response_started` flags 2 and 4, or those flags on a renderer `request_completed` or `request_failed` ([requests answered in the renderer](native-network-v3.md#requests-answered-in-the-renderer)) |
| `memory_cache`, `static_data` | The row is a `memory_cache_reuse` record, and its static-data flag ([native network v3](native-network-v3.md#memory-cache-reuse)) |
| `race_network` | A renderer `request_completed` or `request_failed` with flag 4 (`from_service_worker`) on a row that also has browser records: a service worker race route, whose response the worker or the network may have answered (the records do not say which). Its `failed`, `interrupted`, `status` and `error_code` are that completion's, what the page received, not the browser records' network attempt ([service worker ends](native-network-v3.md#service-worker-ends-without-a-response)) |
| `status` | As `requestsFromEvents`: the HTTP status, else `failed`, `incomplete` or `pending`; a `memory_cache_reuse` row with no HTTP status (an MHTML archive resource, which carries none) is `finished`, because the load completed |
| `end_lost` | A `gap` with payload `service_worker_end_lost` names the row by `initiator_process_id` and `initiator_request_id`; a row with no response and no end then has status `incomplete` instead of `pending` |
| `response_body` | Why the row's response body is or is not retained, as `responseBodyCase` in `apps/research-ui/traffic_response.js` decides ([bodies the proxy never sees](native-network-v3.md#bodies-the-proxy-never-sees)): `case` is the state of the newest `response_body` record whose parent is the row's newest `response_started` (or `malformed`), else why there is none; with a record, its artifact, lengths, partial index, `shared`, digest, sequence and time; and the final `response_started` (session, process, sequence), the creator of the row's script, Wasm or response body artifact. When that record names no bytes (a refusal or a malformed record), `earlier_snapshot` names the newest retained `partial` of the same response (artifact, lengths, partial index, digest, sequence, time), else null. The index keeps the newest record of each parent, and each one's newest retained snapshot |
| `memory_cache_source` | For a version 2 `memory_cache_reuse` that names the request whose response Blink reused, that row's `id`, and `found` only when that row exists, was requested from the reuse's web host and started before the reuse; else `reason` is `not_recorded`, `host_differs` or `started_after` ([bodies the proxy never sees](native-network-v3.md#bodies-the-proxy-never-sees)). A found source adds its method, path, type, MIME type and `response_body` as above. Else null |
| `mime_type`, `protocol` | The latest `response_started` payload, `mime; protocol=alpn` or `synthetic_shields; mime`: the MIME essence lowercased, and the ALPN token |
| `response_time_ns` | The first `response_started` record's time |
| `error_code` | The last non-zero `error_code` |
| `loader_observed` | Any lifecycle record other than `request_initiated` and `memory_cache_reuse` |
| `initiator` | `worker` when `request_started` has flag 4; else, for a `request_initiated` record or a non-zero `initiator_process_id` whose version 3 `request_initiator_stack` names a dedicated, shared or service worker (thread 2 to 4), `worker_loader` when no script was on that worker's stack, `worker_unwalked` when the renderer's 32 worker stack tables were in use (state 6), else `worker_script`; else `script` when its `request_initiator_stack` walked frames, `parser` when no script was on the stack, else `renderer` ([native network v3](native-network-v3.md#request-initiator-stacks)); else `script` for a navigation with a `navigation_initiator_link`; else `browser` for a versioned browser record, else null |
| `initiator_frame` | The innermost frame of that walked stack resolved alone through its `script_identity` and retained source, as `get_request_stack` resolves frames: URL, line, column and function name, or a reason; the handler resolves at most 64 new frames per answer, from the whole artifact manifest, and keeps settled outcomes, so a later source artifact shows once the index next changes; else null |
| `tab_ids`, `tab_link` | The row's own `tab_id` plus the tabs of the set its newest `request_tab_link` names, from the `tab_set` parts indexed so far, and that link's kind, tab count and whether every part arrived ([native network v3](native-network-v3.md#request-owners-and-tabs)) |
| `extension_id` | The extension its `request_extension_link` names, else null |
| `watch` | The row's first `request_watch_match` ([native debugger observation v1](native-debugger-observation-v1.md)): its `session_id`, `process_id`, `sequence_number` and `frame_id`, and the `rule` slot and `method_matched` the debugger decoder reads, both null for a record the core refuses; else null. The renderer records at most one match per request, for the first rule that matches; a row holding more (a replayed or merged store) names its first |
| `tab_reason` | For a row with no tab and no extension, why it has no owner: the reason `get_session_summary` gives ([unresolved requests](native-network-v3.md#unresolved-requests)) from the row's renderer and browser start records; else null. A `memory_cache_reuse` is a renderer start for it |
| `main_frame` | `request_started` with resource type 0 |
| `browser_internal` | The row's scheme class is browser-internal (16 to 20, [native network v3](native-network-v3.md#scheme-class)); without a scheme class, not `loader_observed`, a host-only target and a single-label host other than `localhost`, as WebUI loads are |

`type` follows the pinned `blink::mojom::ResourceType`; a request whose type says
only "other" is classed by its MIME type, and a memory-cache row by its Blink
`ResourceType`.

A start of a hostless URL (`data:`, `blob:`) or a browser scheme names its
scheme, as `scopedNetworkTarget` does: `data:` alone, with its target child
the whole URL, or `chrome://host`.

Each row also names its root event (`request_started`, else
`request_initiated`, else the first record with a request ID), the
`(session_id, process_id, request_id)` members whose records form it with their
record counts, and the byte boundaries of its first record and
after its last. Record counts include the lifecycle records and their children
(`request_target`, `request_body`, `response_body`, header blocks, cookie
lists, `request_initiator_stack`, `navigation_initiator_link`,
`request_tab_link`, `request_extension_link` and `request_watch_match`). A link
is no member; the row's
`tab_link`, `tab_ids` and `extension_id` carry it. Reading a row's records is `get_events` per member with `category=network`,
`after=first_offset` and the member's `records` as `limit`: the browser's
`artifact` acknowledgements share the request ID and are not counted.

Paths and targets are captured text, present only when the session retained
request content (protocol/native-network-v2.md). Consumers insert them as text.

## Bounds and coverage

| Bound | Value | When reached |
| --- | --- | --- |
| Folding per read | 200 ms | `index.complete` is false; the backend's indexer folds the rest in 250 ms slices, so a read waits for the index at most one slice |
| Record size | 4,096 bytes | Counted in `index.malformed_records` |
| Page | 500 rows | `limit` is clamped; `offset` pages the rest |
| Tab facet preview | 8 domains | The tab's `domains_truncated`; `facets.domains` with that `tab_id` lists every one |

None of these drops a row. A store indexed for the first time answers with the
rows indexed so far and `index.complete` false until the indexer reaches its end.

A record that names `network` and is not valid JSON or fails event validation
is counted in `index.malformed_records`, and so is any line that is not a whole
JSON object, since it may have lost those bytes. A complete object without the
bytes `network` is not parsed and is not counted: it cannot be told from a
record of another category.

### Per-request detail reads

`get_request_headers`, `get_request_cookies` and `get_request_stack` read the
bytes the index names for a request (from the first to the last record of each
row that has it as a member) instead of the newest window, so a request stays
readable after more than 64 MiB of newer events. Without a row they read the
newest 64 MiB. `get_cookie_provenance` spans a session and has no byte range; it
reads the newest 64 MiB and 5,000 of the network records it uses, plus every
`script_cookie` record of the session that the index located before that window.
The index keeps every one's byte range; `script_coverage` is not complete only
while the index is still catching up with the store.

Each answer carries `coverage`:

| Field | Meaning |
| --- | --- |
| `scope` | `request_range` the request's indexed bytes answered the question, read to their end or to the newest record asked for; `store` the whole store was read; `bounded_range` only part was read |
| `complete` | Absence in this answer is a fact: the read covered its whole scope, or found the one newest record it was asked for |
| `scan_start`, `scan_end`, `store_end` | Decimal byte offsets of the read and the file length |
| `limited` | The record limit stopped the read before its scope ended |
| `budget_exhausted` | The 64 MiB budget stopped the read before its scope ended |
| `malformed_lines` | Lines in the read that were not valid events: counted and skipped, so a damaged record does not fail the answer |

An index still catching up with the store cannot prove a request ended, so its
range reads as `bounded_range`. When `complete` is false, an empty list or a
missing row is unknown. `get_request_stack` then reports status `outside_scan`
instead of `not_recorded`, and a frame reports reason
`script_identity_outside_scan` instead of `script_identity_missing` when its
identity was not found while the index is still catching up.

## Index file

The index is a private (0600) SQLite database beside the store,
`<store>.requests-v2`, with its write-ahead log (`index_db`). Each fold commits
the rows it changed with the byte offset they describe, so a crash keeps an
index that matches its offset, and reads never wait for a periodic write. It
holds one row per request (the folded row, plus the columns that queries
filter, sort and count by), the members of each row, the correlation keys, the
worker tab sets, the script identities, the `script_cookie` byte ranges, the
indexed byte offset, the store's device and inode, and SHA-256 digests of the
first and the last 4 KiB before that offset. An index of another row layout is
rebuilt. A version 1 `<store>.requests-v1` file is removed.

On every call the backend checks that identity and both digests against the
store. A truncated, rewritten or replaced store discards the index, rebuilds it
from byte 0 and changes `index.epoch`. A matching index is reopened after a
restart (`index.reopened`), so reopening a session reads only records appended
since. When the store's directory cannot hold the database, such as read-only
evidence, the index lives in a private temporary directory for as long as the
backend runs: `index.persisted` is false and `index.persist_error` says why.
Capture clear removes the index before it truncates the stores. The index holds
the same sensitive paths as the store and is never exported.

A query's ordered rows are kept in a temporary table, so the next page of the
same query, sort and snapshot reads its rows by position instead of sorting
again; any newly indexed record makes the next read select again.

## `GET /api/requests`

Operation `get_requests`, read-only for MCP (`analysis` effect).

| Parameter | Meaning |
| --- | --- |
| `limit`, `offset` | One page of the filtered, sorted list; `limit` 1 to 500, default 100 |
| `through` | Only requests indexed before this count; a previous `through` keeps paging the same requests. Their fields stay live, so during capture a sort or filter on a changing field can move rows across pages; capture order cannot |
| `since` | Adds `added`: matching requests indexed at or after this count |
| `sort`, `order` | `capture`, `name`, `status`, `type`, `method`, `time`, `size` (transferred), `initiator`, `start` (first record) or `protocol`; `asc` (default) or `desc` |
| `q` | The Traffic filter grammar below |
| `failed`, `invert`, `hide_internal`, `third_party` | `1` keeps failed rows, inverts `q`, hides `browser_internal` rows, or keeps third-party rows |
| `from_ns`, `to_ns` | Rows whose first record is at or before `to_ns` and last at or after `from_ns` |
| `tab_id`, `domain`, `type` | Exact filters; `tab_id` matches any of a row's `tab_ids`, `tab_id=extension:<id>` the rows of that `extension_id`, and `tab_id=unattributed` the rows with neither |
| `named` | At most 64 `session:process:sequence` root events that also match `q` (researcher names) |
| `locate` | At most 4 row IDs; `located` maps each to its position, or null |

Ties and rows without a sort value keep capture order; rows without a value sort
last in both directions. Text keys compare case-folded, then exactly. `time`
compares the displayed microseconds.

`q` is lowercased and split on whitespace. A word `key:value` with a key below
and a valid value is a token; `-` before it negates it. Any other word starting
with `-` excludes rows whose `method path status` contains the rest. The
remaining words, joined by single spaces, must appear in `method path status`
unless the row's root is `named`. `invert=1` with a non-empty `q` keeps the rows
that fail this.

| Token | Matches |
| --- | --- |
| `domain:` | The domain, or the domain without its port; `*` matches any run of characters |
| `method:` | The method |
| `status-code:` | A numeric status, 1 to 3 digits |
| `larger-than:` | `transfer_size` above the value; `k` and `m` multiply by 1,024 and 1,048,576; 1 to 9 digits |
| `mime-type:` | `mime_type` |

A third-party row has a tab and a site that differs from the site of that tab's
latest `main_frame` row at or before its first record. A site is the host without
its port, lowercased: an IP literal or single label is itself, else the last two
labels, or three when the last is two letters and the one before at most three.
There is no public suffix list, so this is an approximation.

The answer has exact `total`, `matching` and `through`, `failed` (failed
requests in the snapshot), `facets.tabs` (count, first time and up to 8 domains
per tab, a linked row counted in each of its tabs, extension traffic under
`extension:<id>` and a row with no owner under tab `0`) and `facets.domains` (every domain within the `tab_id` filter with its count), `sizes` (the
matching rows' summed `transfer_size` and `resource_size`), `hidden_internal`
(rows `hide_internal` removed that every other filter admitted), `timeline`
(first start, last record and 120 equal buckets of starts over the rows every
filter but the time range admits), `index` coverage, the `query` echo and
`requests`. It has an ETag unless initiator frames were left for a later
answer; an unchanged index and query answer 304.

## Traffic

The table mounts one block of at most 500 rows inside padding for the rest and
moves it as the viewport nears an edge, so every request is reachable by
scrolling. It asks the index for that block. Counts, the footer sizes, the timing
strip, tab chips, domain options, filters and search come from the index;
`apps/research-ui/traffic_filter.js` applies the same rules to the newest window. Newest requests come first by default,
and rows that arrive above a scrolled viewport do not move it. Selecting a row
whose records are not all in the newest window reads them as above. Until the
index first answers, and when it cannot be read before then, Traffic uses the
newest window and says so. A failed later read keeps the last rows.
