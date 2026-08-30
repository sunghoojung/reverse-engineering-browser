# Request Interception v1

Request Interception provides controlled network mutation without changing the
authorized baseline page. A researcher creates a disposable experiment,
configures one bounded rule, sends an explicit credential-free request, reviews
the response and mutation audit, then deletes the complete experiment context.

## Isolation boundary

- `Target.createBrowserContext` creates a new context with no baseline cookies
  or storage.
- `Target.createTarget` creates the only page on which the bridge enables the
  DevTools Fetch domain.
- The bridge closes its baseline page connection and selects the disposable
  page before a rule can be armed.
- A rule cannot be configured or run unless the currently attached target is
  the exact experiment target.
- Disposal uses `Target.disposeBrowserContext`, restores the previous target
  preference, and retains only the bounded public result until the researcher
  clears it.

The baseline capture and C++ event path remain observational. Interception is a
cold-path DevTools control-plane feature and does not add work, allocation, or
branches to native probes, renderer transport, the event broker, or evidence
storage.

## Rule and request contract

The version 1 public state exposes one rule with these modes:

- `continue`: send a matching request unchanged;
- `block`: fail it with `BlockedByClient`;
- `drop`: fail it with `Aborted`;
- `rewrite`: apply explicit URL, method, header, or body overrides;
- `fulfill`: return an explicit synthetic status, headers, and body.

Rules use one HTTP, HTTPS, or wildcard DevTools URL pattern and an optional
method filter. Requests use HTTP or HTTPS URLs with no embedded credentials.
The page runner always sends `credentials: "omit"`, `cache: "no-store"`, and
`referrer: "no-referrer"`. Authorization, proxy authorization, cookie,
set-cookie, host, content-length, connection, and transfer-encoding headers are
rejected for rules, requests, and synthetic responses.

For a synthetic cross-origin response, the bridge also fulfills the browser's
credential-free CORS preflight when its requested method matches the rule. It
reflects only bounded, valid, non-sensitive request-header names and audits the
preflight as a separate mutation.

## Hard limits

- URL: 8 KiB; URL pattern: 2 KiB; method: 32 bytes.
- Headers: 64 entries, 128-byte names, 2 KiB values, and 16 KiB total text.
- Request, rewrite, synthetic-response, and returned-response bodies: 64 KiB.
- In-flight paused requests: 16.
- Mutation audit: 128 entries.
- Explicit request runtime: 15 seconds.

If the paused-request limit is reached, the bridge immediately continues the
overflow request unchanged and records `overflow_continue`. No request is
silently dropped. Returned response headers and bodies expose separate
truncation flags.

## Privacy and audit

The public rule records counts and byte sizes, not header values or bodies.
The last-request summary records method, redacted URL, header count, and body
size. Audit records contain time, request identifier, method, URL without query
or fragment, resource type, rule mode, outcome, and a bounded detail string.
Headers, request bodies, response bodies, cookies, and credentials never enter
the mutation audit or broker evidence store.

Audit eviction is counted and visible. Results and audit records are ephemeral
debugger state and disappear when cleared or when the live session ends.

## Verification

Tests cover all five rule actions, request and response normalization, base64
body transport, credential and forbidden-header rejection, body and header
limits, URL redaction, audit eviction metadata, disposal, and clearing. A
protocol-level fake DevTools target emits `Fetch.requestPaused` over a real
WebSocket and verifies the matching `Fetch.fulfillRequest` command and public
result. UI tests reject malformed and over-limit state before replacing the
last valid debugger snapshot.
