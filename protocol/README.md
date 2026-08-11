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

The native producer-to-broker boundary currently uses exact 320-byte
`EventRecord` frames over a pipe. The Chromium adapter will replace that
development pipe with shared memory and Mojo without changing the evidence
model consumed by the broker and UI.

Protocol changes must remain backward-readable for stored research sessions.
