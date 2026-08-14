# Shared Protocol

This directory owns contracts shared across the browser, event broker, and
research UI.

## Two representations

1. Native hot paths use the fixed 320-byte C++ `EventRecord` in
   `include/reb/event.hpp`.
2. The browser-process broker expands that record into a versioned transport
   message for local IPC.

The first transport schema is implemented by `EventToJson`. Each JSONL record
preserves protocol version, sequence number, process, thread, frame, navigation,
artifact, parent event, request, browser context, and initiator identifiers,
HTTP status, transfer sizes, resource type, flags, monotonic timestamp,
category, type, payload length, and the bounded inline payload as hexadecimal
bytes. Hex encoding prevents untrusted page bytes from being interpreted as
markup or text by downstream clients.

Protocol v2 encodes every signed or unsigned 64-bit field as a canonical
base-10 JSON string. This preserves exact identifiers, sequence numbers,
timestamps, and byte counts in clients whose JSON number type cannot represent
all 64-bit integers. Smaller integer fields remain JSON numbers. The native
header and record have explicit zero-valued reserved fields and no implicit
padding, so raw record transfer cannot expose indeterminate bytes.

Browser network events carry both 64-bit halves of Chromium's opaque
`BrowserContext::UniqueToken()`. The full token plus the browser-process request
identifier disambiguates independent per-profile Brave request-ID generators.
Non-browser events use zero for both halves. The token is session-local opaque
correlation metadata and does not expose a profile path or captured content.

For network events, `resource_type` carries the integral value from the pinned
Chromium `blink::mojom::ResourceType` contract. Browser adapters must translate
or version this field if upstream changes that enum. Protocol v2 uses value 13
for XMLHttpRequest.

Default network payload prefixes contain only the request method and
destination host. URL paths, queries, fragments, credentials, headers,
cookies, and bodies require a separate visibly enabled sensitive-capture mode.

Renderer-to-browser delivery uses exact 320-byte `EventRecord` objects in a
bounded shared-memory queue. Mojo carries session lifecycle and coalesced
wake-ups, not individual events. The initial configuration carries a nonzero
category bitmask and a monotonic expiration deadline. Both renderer and browser
capture boundaries reject disabled or expired events before enqueueing them.
Browser-to-broker delivery uses the same exact records over a user-only Unix
socket. Before records are accepted, Brave sends
a fixed 64-byte hello containing the IPC magic, version, size, session ID, and
a 256-bit token loaded from a user-owned mode-0600 file. The broker compares the
token in constant time and rejects records whose session differs from the
authenticated connection. The broker independently applies the same category
mask before sequence accounting or storage, and closes the session at its own
monotonic deadline.
When a renderer queue drops records, the browser emits a `gap` record after it
drains the retained batch. Its UTF-8 decimal payload is the number of newly
dropped records. The gap record repeats the last retained sequence number so it
does not hide the missing sequence range from broker accounting.

Protocol changes must remain backward-readable for stored research sessions.
