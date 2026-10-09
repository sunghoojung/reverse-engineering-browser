# Traffic capture copies v1

## Boundary and default

`reb-traffic-capture-v1` is an explicitly requested, local, selected-record copy
of the ephemeral CDP Traffic ledger. It is **not** an evidence package, a full
session archive, an HTTP replay request, or an attestation of complete capture.
Existing `reb-metadata-only-v1` package exports and validation are unchanged.

The enabled content-capture path retains raw observed values by default, including
Authorization, Proxy-Authorization, Cookie, Set-Cookie, arbitrary custom headers,
URL userinfo/query/fragments, and request/response body strings or base64. Local
viewing does not redact them. Capture permission, category/session expiration,
loopback controls, inert previews and resource limits remain in force.
Standalone content capture still requires its existing enable flag; the packaged
research profile enables it visibly. Native host-only network events are a
separate observation contract. Native artifact source URLs are retained without
masking, including in sessions with metadata-only Traffic; artifact storage
remains independent of the ephemeral CDP ledger.

## Document

The JSON object contains:

- `format`: `reb-traffic-capture-v1`
- `mode`: `raw` (default) or explicitly selected `redacted_copy`
- `representation`: disclosure that CDP strings/base64 are not original wire bytes
- `warning`: raw sensitivity or best-effort redaction warning
- `coverage`: selected-record/ephemeral scope, header-source coverage, lifecycle,
  network-window dropped count and configured retention limits
- `record`: a deep copy of the selected validated CDP record

In raw mode every retained `record` value is preserved, including whitespace,
JSON number spelling/duplicate keys within body text, form encoding, raw text,
base64 bytes, and unavailable/truncated states. JSON serialization can escape
characters in the outer document; parsing restores the same retained strings.
The document does not embed native artifact bytes or the rest of debugger state.

## Explicit redacted copy

Redaction operates only on the detached copy. It replaces all request/response
header **values** with `<redacted>`, removes body text and base64, marks available
bodies `redacted`, removes URL userinfo/query/fragments from request/document/
initiator source URLs, and removes the target title and error text. Non-network
or unparseable source labels become `<redacted>`. Body availability states and
truncation flags remain; copied body reasons disclose explicit omission.

This is best-effort, not a universal secret detector. URL paths, header names,
function names, identifiers and other metadata may still contain sensitive data.
Review the exact copy before sharing. Export does not modify live evidence,
preview content, source bytes, or a previously produced raw copy.

## User actions and delivery

The selected request's **Export capture** menu exposes distinct raw and redacted
Save/Copy actions. Save creates a local browser download and reports only that
the download was requested. Native web-view downloads are disabled; native
clipboard availability is platform-dependent, not a guaranteed save fallback.
Copy explicitly puts the chosen document on the operating-system clipboard,
which may be synchronized by user-controlled OS settings. No automatic export,
AI handoff, cloud upload, or external network request is added.

Repeated clicks while copy is pending are suppressed. Backend-instance,
attachment-epoch, request/start identity and view revision prevent late clipboard
completion from claiming that a newer selection or reconnected same-id request
was copied. An already initiated clipboard operation cannot be recalled; changing
selection suppresses stale status, not the OS operation. Escape closes the menu
and returns focus to its summary.

## Limits and nonclaims

- 1,000 retained requests; oldest eviction increments the visible drop count.
- 128 KiB per retained body side; missing/loading/error/empty states stay explicit.
- At most 128 headers, 128 bytes per name, 8 KiB per value, 64 KiB aggregate.
  `headers_truncated` reports clipping, omitted malformed values and count/byte caps.
- Request/document URLs: 64 KiB with individual truncation flags. Method: 32 bytes.
- Provenance sources: 8 KiB in backend projections; source-search labels retain
  at most 8,192 UTF-16 units. Visible flags mark retained prefixes.
- Only primary CDP request/response event headers are collected here. Extra-info
  headers, original header casing/order, duplicate wire lines and original HTTP
  wire encodings are not guaranteed. CDP may omit or truncate data upstream.
- Redirect hops can lack bodies; binary responses remain base64. Nothing fetches
  missing bytes on export. Reconnect, target change and process exit discard the
  ledger. Response retrievals from an old attachment cannot populate a new one.
- Native worker-source foundation's versioned URL-status contract, disposable
  experiment request admission/audit/result contracts, and explicit Collection
  recipe imports are separate surfaces and unchanged by this Traffic copy format.
  This change does not claim that every legacy REB feature retains every input.

Synthetic fixtures, never real captures, verify raw values, explicit redaction,
byte preservation, operational bounds, capture-off, ownership and inert rendering.
