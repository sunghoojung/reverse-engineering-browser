# Local passive security report v1

This is a deliberate, offline interpretation of one selected saved or retained
CDP request/response. It reports header observations and secret-looking
category/location/count metadata. It never sends requests, checks credentials,
reads browser profiles or keychains, executes captured code, makes external
lookups, or changes the source. Active probes and automatic remediation are not
implemented by this workflow. Follow [SAFETY.md](../../SAFETY.md).

## Use it

In Traffic, select a retained CDP request, open **Export capture**, then choose
**Local passive security report**. The report is computed only from the
already-retained selection. There is no fetch, background report or automatic
copy/export. The dialog shows fixed-vocabulary observations, source/identity
hashes and explicit coverage limitations; Close/Escape clears it. A different
selection, an updated body/header on the same identity, or an expired selection
clears the old result. Closing while a digest is pending discards that result.
Keyboard focus returns to the trigger or the Traffic request list if the trigger
is no longer usable.

For a saved exact-request response, use Node.js 22+:

```sh
node tools/report-passive-security.mjs --input selected-request.json --output security-report.json
```

`selected-request.json` is a previously saved response of the retired
`get_network_request` operation; nothing produces new ones since CDP Traffic was
removed. The input is one `reb-network-request-v1` response, including `source`, `debugger_generation` and
`request`. An ordinary `reb-traffic-capture-v1` raw export lacks the complete
owner identity and is not accepted. Neither retrieval nor recapture is performed
by the report command. A partial capture is accepted as partial evidence; it is
never silently repaired or treated as complete.

The CLI reads one regular UTF-8 JSON file of at most 1 MiB. Duplicate keys,
invalid Unicode, excessive JSON nesting, unsafe numeric identity, symlink input,
and mismatched identity are refused. It uses the existing exact-capture
validator. The report is atomically published to a new private (0600) file;
existing files, directories and symlinks are never replaced. The stdout receipt
contains hashes/counts/byte size only, and errors contain no source strings or
file paths. The source is never rewritten. Reports remain local; this tool does
not grant permission to share them.

## Versioned output and source binding

The output `format` is `reb-passive-security-report-v1`, header `rule_set` is
`reb-security-headers-v1`, and secret-pattern `rule_set` is
`reb-secret-shapes-v1`. `mode` is `offline-passive`, `network_requests` is zero,
and `coverage.complete` is always false. There is no pass/fail score, severity
ranking, exploitation claim or site-wide security verdict.

`source.sha256` identifies the exact UTF-8 source bytes. For the CLI these are
the selected input file bytes. For the UI they are UTF-8 `JSON.stringify` of
`{format:'reb-passive-security-selection-v1',identity,record}` captured at the
explicit action, in that property order. The identity object has `instance`,
`epoch`, `request`, `target` and `started` fields. The source is parsed and
checked against the analyzed record and identity before interpretation.

`source.identity_sha256` hashes UTF-8 `JSON.stringify` of the ordered array
`[instance, epoch, request, target, started]`, preserving the original binary64
monotonic start without rounding. It binds the backend instance/capture epoch,
request ID, target ID and start time without echoing attacker-controlled IDs.
These hashes are local evidence references, not authenticity attestations.
Recompute them against your original evidence to resolve the report. The input
and UI snapshot have different source hashes even for equivalent records.

Every reported location is a fixed JSON pointer with numeric header indices,
never a source-derived name. `source.record_pointer` is `/request` for saved
exact responses or `/record` for UI snapshots; all finding/header pointers
include that prefix. Raw URLs, source identifiers, custom header names, body
keys, snippets, values, value hashes and matched substrings are not returned.

Header observations have `rule_id`, `locations`, `outcome`, `reason` and a
primary-standard `reference`. Outcomes are `observed`, `not_observed`,
`not_applicable` or `unknown`. `observed` means only that a retained token/header
was seen. `not_observed` means absent from this bounded header list, never absent
from the browser's policy state. Truncated headers, a pending/failed request or
missing/opaque status produce `unknown` for all header rules.

## Header rules and primary standards

Standards checked on 2026-10-15. The report intentionally has a smaller scope
than a browser policy engine:

- **HSTS v1:** HTTP context is `not_applicable` because HSTS is ignored over
  insecure transport. IP literals are also inapplicable; truncated/unknown URL
  context is unknown. On HTTPS domain names, a single retained header recognizes
  a nonnegative digit-only `max-age` (also simple quoted digits) and optional
  valueless `includeSubDomains`, case-insensitively. Only zero/positive and the
  subdomain flag are returned, not the age. Repeated directives, repeated header
  fields, combined values, extensions such as `preload`, quoted escapes or other
  unsupported syntax are unknown, not automatically invalid. The standard
  processes only the first wire HSTS field; CDP retention does not establish that
  ordering, so this report refuses to choose among duplicates. It does not
  establish transport trust, preloading, inherited policy or current browser
  HSTS state. [RFC 6797 §§6.1 and 8.1](https://www.rfc-editor.org/rfc/rfc6797#section-8.1).
- **CSP v1:** Presence of a nonempty enforcing header is an observation only;
  directive syntax, strength, effective policy and framing protection are not
  evaluated. Multiple header locations are preserved without flattening or
  claiming that one policy overrides another. Report-only headers have separate
  counts/locations and never satisfy enforcing-header presence. Empty enforcing
  headers are unknown. Meta policies are outside scope.
  [CSP Level 3 policy delivery](https://www.w3.org/TR/CSP3/#policy-delivery).
- **nosniff v1:** For a single retained ASCII header without quotes/control
  characters, recognize `nosniff` case-insensitively in the first comma-separated
  token. A later token alone does not count. Duplicate fields or syntax outside
  this subset are unknown. This does not claim that a resource was blocked:
  Fetch's nosniff blocking depends on destination and MIME type.
  [Fetch §3.6](https://fetch.spec.whatwg.org/#x-content-type-options-header).
- **Referrer-Policy v1:** In a single retained plain ASCII comma list, select the
  last recognized, case-sensitive policy token; ignore unknown tokens. Duplicate
  fields/unsupported syntax or no recognized token are unknown. Only one of the
  eight standard policy names can be returned. This does not infer actual
  request referrers, meta/element policy, redirects, user settings or browser
  defaults. [Referrer Policy §8.1](https://www.w3.org/TR/referrer-policy/#parse-referrer-policy-from-header).

## Secret-looking observations and limits

This is a finite heuristic pattern set, not a complete secret detector.
Findings contain only `category`, `location`, `count`, `count_is_lower_bound`
and `confidence:'heuristic'`:

- `credential-header`: nonempty Authorization, Proxy-Authorization, X-Api-Key,
  Api-Key, X-Auth-Token or X-Access-Token retained values (one per header)
- `cookie-header`: a nonempty Cookie or Set-Cookie value (one per header, not
  inferred cookie count; many cookies are not credentials)
- `url-userinfo`: userinfo presence in an HTTP(S)/WS(S) URL
- `credential-parameter`: nonempty URL query parameters with selected credential
  names, including duplicate/percent-decoded names, aggregated at the URL pointer
- `private-key-marker`: a supported PEM private-key opening marker only; no
  key-body extraction or validation
- `jwt-shaped`: an `eyJ`-prefixed three-segment base64url-looking shape with minimum
  segment lengths; no decoding or signature check
- `secret-assignment`: selected secret-like assignment names followed by at least
  eight supported token characters; no object parser or validity inference

Text patterns examine the selected URL, retained header names/values and
unambiguous available text bodies. URL fragments are not parsed as parameters;
raw URL text can still match a text pattern. Metadata outside these surfaces is
not examined. Missing/loading/error bodies, inconsistent empty markers,
base64-only bodies and conflicting text/base64 representations are unknown.
Truncated text and header prefixes can yield observations with partial coverage.
No recursive decoding, decompression, entropy search or browser/file lookup
occurs. Encoded or obfuscated secrets can be missed. Examples, placeholders,
public tokens, harmless cookies and documentation can match. No matches never
means secret-free.

Source is limited to 1 MiB, 128 pairs and 64 KiB per header side, 128 KiB per
text body, 512 finding rows and 100 pattern matches per location/category.
Hitting a match cap sets `count_is_lower_bound`; hitting the row cap increments
`omitted_finding_rows`. Header metadata and body coverage stay independently
visible. Counts can overlap between categories. Private metadata such as source
hashes and pattern counts still merits review before sharing.

## Verification

`node tools/check-passive-security.mjs` covers deterministic source/identity
hashes, immutable evidence, standards edge cases, duplicate/multiple headers,
HTTP/HTTPS/IP context, no-values output, false positives, bounded match/row
counts, malformed/partial/opaque inputs, the real CLI publication path, and
late-result/close/reselection/focus handling. It is included in
`make javascript-check`.

The in-app Traffic report was removed with CDP Traffic, which was its only
source of retained headers and bodies. The offline library is
`tools/passive-security.cjs`.
