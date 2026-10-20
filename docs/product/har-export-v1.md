# Offline HAR export v1

Traffic **Export… → Format → HAR** exposes raw and redacted policies (redacted by default) using this same offline generator and strict timing validator. Browser development downloads the file; the native **Clipboard** destination writes text to the local clipboard only when explicitly selected.

Export one reviewed, saved `get_network_request` response without contacting its
URL or executing anything in it:

```sh
node tools/export-captured-har.mjs --input request.json --output request.har
node tools/export-captured-har.mjs --input request.json --output redacted.har --mode redacted_copy
```

The CLI uses the exact-response reader's 1 MiB input limit, duplicate-key and
Unicode validation, regular-file/symlink restrictions and five-field identity.
The UTF-8 HAR 1.2 output is bounded to 2 MiB, mode 0600, and atomically published
without replacing an existing path. It is a single entry, not a session-wide
capture. Existing snapshots without [timing evidence](../../protocol/network-timing-v1.md)
are explicitly unsupported. Re-capture an authorized request with the new backend
if source timing is missing; no timestamp is fabricated from display values.

Raw is the default and may include cookies, tokens, URLs and private bodies.
Review before sharing. `redacted_copy` removes query/userinfo/fragment, all header
values and body text, using the existing copy policy. Identity, status and numeric
timing/size metadata remain. Redaction is best-effort, not proof of anonymity.
No existing evidence is changed. The command reports counts, never captured data.

## Timing fidelity

Only complete, uncached, non-service-worker requests with unambiguous lifecycle
and ordered timing evidence are exported. Redirect hops, failed/pending requests,
unknown/malformed clocks, duplicated lifecycle events, proxy/worker phases,
missing required intervals, overlapping DNS/connection phases and unavailable
first-response-header timestamps are refused. This conservative first version
prefers an explicit unsupported result to an invented waterfall.

The exporter uses ResourceTiming's monotonic requestTime and millisecond offsets:

- send: sendEnd minus sendStart
- wait: receiveHeadersStart minus sendEnd
- receive: loadingFinished minus the first response header timestamp
- DNS and connect: corresponding source end minus start; paired CDP -1 markers
  become HAR -1, with no contribution to the sum
- TLS: sslEnd minus sslStart, verified inside connect and never added twice
- blocked: time from request start to sendStart, less disjoint DNS/connect phases;
  this is a labeled derived pre-send residual, not a separately measured queue

The total is the sum of these non-overlapping HAR phases. Wall time supplies the
ISO start; millisecond formatting loses submillisecond display precision, so the
original source clocks remain in `_reb.timing_evidence`. No time zone is inferred.

## Retained HTTP data

Headers retain their CDP array order/values, with explicit normalized-header and
unknown-wire-coverage limitations. Cookies remain in headers; cookies arrays are
unparsed, explicitly marked `_cookiesParsed:false`. Wire header and response-body
sizes are -1; encodedDataLength includes overhead and is never misreported as
body size. Request body size is unknown unless the source explicitly has no body.

Complete response base64 is validated canonically and emitted with HAR's base64
encoding. Complete text is accepted only for an unambiguous UTF-8 declaration or
JSON's default UTF-8; other charsets cannot establish original decoded byte size.
Text size is identified as retained UTF-8. Binary request bodies, missing bodies,
truncated headers/bodies, malformed queries and unknown protocols are refused.
Request postData text is retained literally. Query pairs preserve order and
duplicates; the raw request URL keeps its spelling except HAR excludes fragments.
HTTP/1.0, HTTP/1.1, h2 and h3 protocol labels map to HAR HTTP versions.

`_reb` extensions retain exact source identity, saved debugger generation, source
timing and unknown global capture coverage. No browser version, connection ID,
cache state, compression savings, original wire sizes or freshness is invented.
HAR readers may ignore extensions; do not mistake this projection for a packet
capture, complete browser session or guaranteed replay.

## Checks and references

`node tools/check-captured-har.mjs` exercises the real CLI, private publication,
no-overwrite behavior, phase accounting/TLS overlap, binary bodies, duplicate
queries, source identity and rejection matrices with authored data only. Backend
unit tests exercise clock precision/availability, redirects and duplicate events.

- [HAR 1.2 specification](https://www.softwareishard.com/blog/har-12-spec/)
- [HAR 1.2 maintained transcription](https://github.com/ahmadnassri/har-spec/blob/master/versions/1.2.md)
- [CDP Network definitions](https://github.com/ChromeDevTools/devtools-protocol/blob/master/json/browser_protocol.json)
