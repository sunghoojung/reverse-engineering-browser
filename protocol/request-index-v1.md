# Request index v1

Status: implemented in the Rust backend (`apps/origin-trace-backend/src/request_index.rs`)
and Traffic (`apps/research-ui/traffic_index.js`). The bundled `reb://`
stored-evidence workspace does not serve it; Traffic there keeps the newest
network window.

## Why

The polling window (`GET /api/events`) keeps the newest 5,000 network events.
A request is four to seven records, so Traffic could show only the last 700 to
1,250 requests of a session, and its counts described that window. The index
keeps one summary per request for the whole session.

## Rows

The backend folds every network lifecycle record (`request_initiated` through
`request_failed`) and every `request_target` and `request_body` child of the
event store, in store order, into one row per request. Row identity, method,
path, status, type, time, tab and the target join follow `requestsFromEvents`
in `apps/research-ui/evidence_models.js`; `make request-index-check` replays one
fixture through both and requires equal rows, sort orders and search matches.
Browser keys that correlate a loader with its renderer request are learned in
store order, so a key that only a later record establishes does not merge rows
already indexed.

Each row also names its root event (`request_started`, else
`request_initiated`, else the first record with a request ID), the
`(session_id, process_id, request_id)` members whose records form it with their
record counts (at most 8), and the byte boundaries of its first record and
after its last. Reading a row's records is `get_events` per member with
`after=first_offset` and `limit=records`.

Paths and targets are captured text, present only when the session retained
request content (protocol/native-network-v2.md). Consumers insert them as text.

## Bounds and coverage

| Limit | Value | When reached |
| --- | --- | --- |
| Bytes folded per call | 64 MiB | `index.complete` is false; the next call continues |
| Record size | 4,096 bytes | Counted in `index.malformed_records` |
| Requests | 131,072 | Further records counted in `index.unindexed_records` |
| Members per row | 8 | `members_limited` |
| Page | 500 rows | `limit` is clamped |
| Domain facets | 512, plus the domain filter | `facets.domains_truncated` |

A network record that is not valid JSON or fails event validation is counted,
never dropped silently.

## Sidecar

The index is kept beside the store as `<store>.requests-v1`, a private (0600)
JSON file written atomically. The backend writes it itself, every 30 seconds
when the index changed and at shutdown, after folding new records;
`get_requests` folds in memory and writes no file. It holds the rows, the
correlation keys, the indexed byte offset, the store's device and inode, and
SHA-256 digests of the first and the last 4 KiB before that offset.

On every call the backend checks that identity and both digests against the
store. A truncated, rewritten or replaced store discards the index, rebuilds it
from byte 0 and changes `index.epoch`. A matching sidecar is reused after a
restart (`index.reopened`), so reopening a session reads only records appended
since. Capture clear removes the sidecar before it truncates the stores. The
sidecar holds the same sensitive paths as the store and is never exported.

## `GET /api/requests`

Operation `get_requests`, read-only for MCP (`analysis` effect, in memory).

| Parameter | Meaning |
| --- | --- |
| `limit`, `offset` | One page of the filtered, sorted list; `limit` 1 to 500, default 100 |
| `through` | Only requests indexed before this count; a previous `through` keeps paging one snapshot |
| `since` | Adds `added`: matching requests indexed at or after this count |
| `sort`, `order` | `capture`, `name`, `status`, `type`, `method` or `time`; `asc` (default) or `desc` |
| `q` | Case-insensitive text in `method path status`, as Traffic search |
| `tab_id`, `domain`, `type` | Exact filters; `tab_id=unattributed` is tab 0 |
| `named` | At most 64 `session:process:sequence` root events that also match `q` (researcher names) |
| `locate` | At most 4 row IDs; `located` maps each to its position, or null |

Ties and rows without a sort value keep capture order; rows without a value sort
last in both directions. Text keys compare case-folded, then exactly. `time`
compares the displayed microseconds.

The answer has exact `total`, `matching` and `through`, `failed` (failed
requests in the snapshot), `facets.tabs` (count, first time and up to 8 domains
per tab) and `facets.domains` (counts within the `tab_id` filter), `index`
coverage, the `query` echo and `requests`. It has an ETag; an unchanged index
and query answer 304.

## Traffic

The table mounts one block of at most 500 rows inside padding for the rest and
moves it as the viewport nears an edge, so every request is reachable by
scrolling. It asks the index for that block. Counts, tab chips, domain options,
filters and search come from the index. Newest requests come first by default,
and rows that arrive above a scrolled viewport do not move it. Selecting a row
whose records are not all in the newest window reads them as above. Until the
index first answers, and when it cannot be read before then, Traffic uses the
newest window and says so. A failed later read keeps the last rows.
