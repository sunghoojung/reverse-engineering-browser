# Native network observations v3: headers and cookies

Status: implemented source candidate. The overlay compiles against the portable
harness of the pinned Chromium types; patched Brave compilation and a
real-browser run are still required (see [Acceptance](#acceptance)).

Version 1 ([native-network-startup-v1.md](native-network-startup-v1.md)) owns
request identity and lifecycle, version 2
([native-network-v2.md](native-network-v2.md)) the request target and body.
Version 3 adds header blocks and cookies: four records and three sensitive
artifact kinds. Nothing in a v1 or v2 record changes. [SAFETY.md](../SAFETY.md) governs
authorization, capture and export.

## Capture level

Header blocks carry credentials (`Authorization`, `Cookie`, `Set-Cookie`), so
they use the request-content gate of v2 (`--reb-capture-request-content`,
`REB_CAPTURE_REQUEST_CONTENT=1`, agent `request_content` with
`confirm_sensitive_capture`). Metadata-only sessions emit no header record and
retain no header value. The receiver still refuses the sensitive kinds without
`--allow-sensitive`.

## Sources

| Source | Code | Record | Hook | Notes |
| --- | ---: | --- | --- | --- |
| `browser` | 1 | `request_headers` | `network::ResourceRequest::headers` and `cors_exempt_headers` at `request_started` | Provisional: no `Cookie`, `Host`, `Referer` or other headers the network stack adds |
| `network` | 2 | `request_headers` | `network::mojom::DevToolsObserver::OnRawRequest` | The headers the network stack sent, including HTTP/2 and HTTP/3 pseudo-headers |
| `browser` | 1 | `response_headers` | `URLResponseHead::headers` at `response_started` and every `request_redirected` | Keeps `Set-Cookie`: at the pin `url_loader_util::BuildResponseHead` copies `URLRequest::response_headers()`. Recorded before Brave's own header rewrite |
| `early_hints` | 3 | `response_headers` | `DevToolsObserver::OnEarlyHintsResponse` | One per 103 response |

`TrustedURLLoaderHeaderClient` is not used: it can delay or change requests.

### Network-service binding at the pinned Chromium

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

### Hop attribution

`browser` blocks are children of the exact lifecycle record they describe:
`request_started` for the provisional request block, `request_redirected` or
`response_started` for the response block of that hop.

The DevToolsObserver pipe is not ordered with the loader client pipe. The
network service emits at most one raw request per hop and marks each response
head with `emitted_extra_info`. A `network` request block joins the oldest
finished hop whose head says a raw request was emitted and that has none yet,
or else the open hop. Its parent is that hop's start record (`request_started`
or `request_redirected`). Early hints join the open hop. A block for a request
the sink no longer tracks increments the unattributed count carried by every
later header record.

## Records

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
| 2 `captured_shared` | An identical block (kind, length and SHA-256) was already retained in this configuration; `artifact_id` names it |
| 3 `empty` | No headers |
| 4 `not_captured_block_limit` | Longer than 320 KiB; count and length only |
| 5 `not_captured_artifact_unavailable` | Artifact category off, receiver disconnected or session inactive |
| 6 `not_captured_transfer_refused` | The bounded artifact queue refused it |
| 7 `not_captured_session_budget` | This configuration already retained 64 MiB of header blocks |
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

## Header block artifact

A block is the headers in received or sent order, each written as `name`,
`: `, `value`, CRLF, without a request or status line. Names keep their case.
HTTP/2 and HTTP/3 pseudo-headers keep their leading colon, so a reader splits
each line at the first colon after its first byte. A block is never truncated
or rewritten.

Kinds 9 `request_headers` and 10 `response_headers`, capture origin 10
`network_request` (shared with `request_body`), MIME type `text/plain`, always
sensitive, execution context 0 and a nonzero creator. The manifest URL is the
hop's URL as for request bodies (scheme, host, explicit port, path and query).
A shared artifact keeps the URL of the record that created it; read the
request's URL from its own records. The receiver's ACK joins the creating
record as for request bodies; a shared record reads its artifact's outcome by
`artifact_id`. Sources never lists header artifacts.

## Cookies

Content sessions also record the cookies the network service reported for each
hop, with why each was blocked, and what page script did with
`document.cookie` and the Cookie Store API. Both use the header gate above: a
metadata-only session records no cookie record and no cookie value.

### Network cookie lists

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

### Cookie list artifact

Kind 11 `cookie_list`, capture origin 10 `network_request`, MIME type
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

### Script cookie access

Chromium patch `0027-record-script-cookie-access.patch` calls the renderer
sink from `CookieJar::SetCookie` and `CookieJar::Cookies` (`document.cookie`)
and from `CookieStore::set`, `get`, `getAll` and `delete`. The browser passes
the content gate to the renderer in `NativeProbeClient::Configure`. Without it,
each call costs one atomic load.

Type 37 `script_cookie` is a renderer record: category `network`, flags 0,
payload size 128, `request_id`, `parent_event_id`, `artifact_id`, navigation,
status, error, lengths and resource type zero. `frame_id` is the document's
frame for `document.cookie` and the calling frame for the Cookie Store API.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 2 | payload version, `1` |
| 2 | 2 | payload size, `128` |
| 4 | 1 | API: 1 `document.cookie` set, 2 `document.cookie` get, 3 `cookieStore.set`, 4 `cookieStore.get`, 5 `cookieStore.getAll`, 6 `cookieStore.delete` |
| 5 | 1 | flags |
| 6 | 2 | reserved, zero |
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
read; reserved bytes are zero.

`document.cookie` set parses the name and value like `ParsedCookie`: up to the
first `;`, split at the first `=`, whitespace trimmed; no `=` means an empty
name. The script frame comes from `v8::StackTrace::CurrentStackTrace` (one
frame): script ID and character position; function start is 0. The stack
digest is zero until the request stack walker of `request_initiator_stack`
also runs for cookie calls; integration links the two by that digest.

Reads are frequent, so each renderer aggregates them per frame, API, script
frame and name in a 256-entry table per configuration. A key records its 1st,
2nd, 4th, 8th and later power-of-two reads, each with the reads since the
previous record, and its remainder when the configuration ends. A new key
while the table is full is recorded alone with bit 3.

### Cookie bounds

- Disabled or metadata-only: no cookie list is serialized, and a script cookie
  call costs one atomic load.
- A sent and a received list per hop, at most 2 MiB each, sharing the header
  table and budget.
- Script cookie records: one per write, at most 2 + log2(reads) per read key,
  and one per read past the table; each is one 320-byte record, one SHA-256 of
  the value and a one-frame stack capture.

### Cookie agent access and UI

`get_request_cookies` (`GET /api/request-cookies?session_id=&request_id=`)
returns each hop's sent and received cookies with every attribute, exclusion
and warning reason. `get_cookie_provenance`
(`GET /api/cookie-provenance?session_id=&name=`) lists everything in the
newest records that touched a cookie name: the responses that set it, the
script writes and reads with their frame, and the requests that sent it.
Cookie values are withheld as `value_withheld: true` with their byte length
and SHA-256, like credential headers; a script write links to a sent cookie
when their value digests are equal.

Origin Trace's **Cookies** tab shows Request cookies, with "Show filtered out
request cookies" listing excluded ones and each reason, and Response cookies
with name, value, domain, path, expiry, size, HttpOnly, Secure, SameSite,
partition key, priority and block reasons. Columns sort, long values truncate
with the full value as a tooltip, and each value copies. A name opens its
provenance. Values are inserted as text after a size and SHA-256 check.

## Bounds and hot path

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
- At most 4,096 in-flight requests are tracked for hops and `network` blocks;
  the rest keep their provisional block, and their response blocks report hop
  0 with state 8. Tracking ends at request completion.

## Agent access

`get_request_headers` (`GET /api/request-headers?session_id=&request_id=`)
returns each hop's request and response blocks with their state, source,
counts, digest, referrer policy, remote endpoint and parsed headers. Values of
`Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` are withheld
as `value_withheld: true` with their byte length: like request bodies, they
stay in the binary artifact, which MCP never inlines.

## Consumers

- The broker accepts types 30 and 31 only when `IsValidEvent` does. The
  backend's network window keeps them with the lifecycle records. Neither
  becomes a lifecycle record.
- Origin Trace's **Headers** tab shows General (URL, method, status, remote
  address, referrer policy), Response headers and Request headers per hop. A
  hop with only a `browser` request block reads "Provisional headers are
  shown". Each section collapses and has a Raw view and copy actions. Values
  are inserted as text after a size and SHA-256 check.

## Validation

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

## Acceptance

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
