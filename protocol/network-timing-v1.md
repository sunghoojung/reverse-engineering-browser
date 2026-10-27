# Retained network timing evidence v1

> **Retired.** `timing_evidence` was a projection of CDP Traffic rows. CDP, the
> Traffic ledger in `GET /api/debugger` and the exact-request API
> (`GET /api/network/request`) were removed, and the `NetworkTimingEvidence`
> schema left [openapi.json](openapi.json) with them. Offline exporters still
> read the format from previously saved records. This page is a historical
> record of that format.

Traffic rows optionally carry `timing_evidence` with format
`reb-network-timing-v1`. New content-capture rows include it; older rows remain
readable. This is a bounded source projection, not a synthesized HAR waterfall.
The exact-request API preserves it under the existing five-field row identity.
No additional target request or capture permission is introduced.

## Clocks and availability

`request_monotonic_seconds`, `response_monotonic_seconds` and
`completion_monotonic_seconds` retain CDP event timestamps in monotonic seconds.
`request_wall_seconds` retains requestWillBeSent.wallTime in Unix epoch seconds.
An available measurement is `{state:"available",value:number}`; no rounding or
unit conversion is applied. Absent keys become `{state:"missing"}`; null,
wrong types, negative values and values above 8.64e12 become `{state:"invalid"}`.
The magnitude ceiling bounds subsequent epoch/date conversion; it is not a
claim that every value in this range is useful for every exporter.

`resource_timing` is missing, invalid, or available with exactly 14 fields:
requestTime, proxyStart, proxyEnd, dnsStart, dnsEnd, connectStart, connectEnd,
sslStart, sslEnd, sendStart, sendEnd, receiveHeadersStart, receiveHeadersEnd and
workerStart. requestTime is monotonic seconds. Other fields are millisecond
offsets from requestTime; CDP's -1 sentinel is `unavailable`. Missing fields
remain missing. Future CDP properties and arbitrary invalid values are not
copied. There are no inferred zero phases. TLS is contained in connection time
and must not be added twice by consumers.

## Lifecycle and limits

The first response and completion event own their evidence. The booleans
response_observed/completion_observed distinguish absent events from malformed
or missing event timestamps. Repeated events set duplicate_response or
duplicate_completion without overwriting the first timing. A first response
after completion sets response_after_completion. Existing compatibility/display
fields may still change on repeated events: source timing does not validate them.

response_source is none, responseReceived or redirectResponse;
completion_source is none, loadingFinished, loadingFailed or redirectRequest.
A redirect response retains its ResourceTiming but has no response event clock;
the next-hop request timestamp is recorded only as the previous hop's redirect
completion. New hops receive independent timing objects. Capture reset/target
retirement uses the existing row lifecycle; late body retrieval cannot modify
new epoch records. Capture disabled creates no timing records.

Reversed timestamps remain reversed, not clamped. Missing/invalid values,
malformed sequences, failures, cache/service-worker paths and incomplete requests
may be insufficient for export. Consumers must check chronology and explicitly
refuse an unrepresentable HAR entry. The legacy wall_time_ms and duration_ms
remain display/compatibility values and must not be treated as source evidence.

The saved-capture exporter validates this additive projection when present and
retains it unchanged in raw evidence. Existing size budgets, exact identity,
redacted-copy semantics and unknown capture coverage still apply.

Primary source: [Chrome DevTools Protocol Network definitions](https://github.com/ChromeDevTools/devtools-protocol/blob/master/json/browser_protocol.json).
