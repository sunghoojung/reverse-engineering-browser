# Repeater v1

Repeater turns an observed request target into an editable, repeatable experiment
without reusing the authorized baseline page's cookies or storage. It shares the
disposable request-lab BrowserContext introduced by Request Interception, so an
armed interception rule can be exercised by the same explicit Repeater request.

## Isolation and lifecycle

- Repeater is unavailable until the disposable BrowserContext and its exact page
  target are attached.
- Requests run through `fetch` in that disposable page with `credentials: omit`,
  `cache: no-store`, and `referrerPolicy: no-referrer`.
- Only one Repeater request can run at a time. The UI remains responsive and can
  send an explicit cancellation to its preinstalled `AbortController`.
- A request also aborts at its configured timeout, which is bounded between 100
  milliseconds and 30 seconds.
- Disposing the BrowserContext erases Repeater variables, request and response
  bodies, history, comparisons, and the controller registry.

The baseline C++ probes, renderer transport, event broker, and evidence store do
not participate in this flow. Repeater is a cold-path debugger control feature.

## Editable request and variables

A request contains an HTTP or HTTPS URL, method, header map, body, and timeout.
Authorization, proxy authorization, cookie, set-cookie, host, content-length,
connection, and transfer-encoding headers are rejected before DevTools receives
the request. URLs with embedded credentials or fragments are also rejected.

Up to 32 session-scoped variables can be used as `{{name}}` tokens in the URL,
method, header values, or body. `{{=name}}` produces the literal `{{name}}` text.
Variable names are restricted to stable identifier characters. Missing or
malformed variables stop execution, and the fully resolved request is validated
again against every URL, method, header, and body bound before it is sent.

The Traffic workspace copies only the selected request's method and URL without
query or fragment into a Repeater draft. It does not copy captured headers,
cookies, or request content. A completed run can copy its explicit resolved
request as bounded JSON for reproducibility.

## History and comparison

History retains at most 24 runs and at most 512 KiB of combined request and
response state. The oldest entries are evicted first, and the eviction count and
current byte usage stay visible. Each entry includes the original variable
template, resolved request, bounded response, duration, truncation state, and a
SHA-256 digest of the retained response body.

Any two retained successful responses can be compared. The comparison reports:

- status before and after;
- duration and retained-body-size deltas;
- exact retained-body digest equality;
- added, removed, and changed response-header names;
- whether response truncation makes the comparison partial.

Header values are used only to determine whether a retained header changed. The
comparison record exposes header names, not their values.

## Hard limits

- URL: 8 KiB; resolved method: 32 bytes; method template: 256 bytes.
- Headers: 64 entries, 128-byte names, 2 KiB values, and 16 KiB total text.
- Request and returned-response bodies: 64 KiB each.
- Variables: 32 entries, 64-byte names, 4 KiB values, and 32 KiB total text.
- History: 24 entries and 512 KiB combined retained state.
- Active requests: one; runtime: 30 seconds maximum.

Returned response streaming stops and cancels the reader as soon as the 64 KiB
body limit is reached. Response-header and body truncation are reported
separately.

## Privacy and storage

Repeater state is ephemeral debugger memory. It is never appended to the event
broker, Origin Trace sidecar, artifact store, or request-interception mutation
audit. The mutation audit retains only its existing redacted metadata. Variables
and complete explicit requests can contain researcher-provided content, so the UI
makes their session lifetime and disposal behavior visible.

## Verification

Tests cover variable substitution and escaping, unresolved and expanded-limit
failures, forbidden headers, asynchronous completion, cancellation, automatic
and selected comparison, increasing history identifiers, entry and byte bounds,
eviction accounting, disposal erasure, malformed public state, keyboard history
selection, and narrow-layout rendering.
