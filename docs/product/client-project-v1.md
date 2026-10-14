# Captured request client project v1

This cold-path workflow joins one retained Traffic observation to a reviewed
Repeater draft and an organized project with dependency-free standard Go and JavaScript clients plus
an explicitly enabled experimental Go profile adapter. It does not
discover unused endpoints, infer service semantics, or generate a complete SDK.
The [capture and authorization policy](../../SAFETY.md) still applies.

## User workflow

1. In **Traffic → API catalog**, open an observation's exact captured request.
2. In **Export capture**, choose **Review captured request in Repeater**.
   Inspect the exact retained URL, method, header pairs and body. Unsupported
   inputs are explained; they are not silently dropped. Replacing an existing
   draft requires a separate checkbox.
3. **Create isolated draft** copies the reviewed snapshot. When necessary it
   explicitly creates the existing disposable blank page. This can clear live
   Traffic, so the confirmed source snapshot stays with the copied draft.
   Cancel, a newer edit or a changed disposable context prevents a late write.
   Expiry during an existing-context handoff is refused. No target request is
   sent by reviewing, creating a draft, opening a project, or exporting it.
4. Review/edit in Repeater and use its existing **Send** action deliberately.
   **Export project** exports the selected retained run's resolved inputs.
   Raw evidence includes its original run and the known source capture, when
   retained. The most recently submitted imported capture can link up to 24 execution IDs in one
   disposable lifetime. A later submitted source replaces that bounded provenance owner;
   older or unrelated runs explicitly report unavailable linkage.
5. Alternatively, export a project directly from the selected Traffic capture.
   Unsupported captures remain useful evidence-only exports until the user
   supplies a complete reviewed runnable request in local configuration.

The macOS app uses the standard **Save** dialog for the ZIP. Cancel does not
write a file; failures are surfaced without retry or fallback writes. The bridge
accepts only the owned main app frame at a native-approved page URL, validates
the fixed archive format, and permits only one pending dialog. Navigation and
content-process termination cancel it. Browser development uses a normal ZIP
download. An older native shell without the bridge disables these controls
with an explanation; it never pretends an unsupported download succeeded.

## Fixed project layout

```text
reb-client-project/
  README.md
  package.json
  .gitignore
  config.example.json
  provenance.json
  go/go.mod
  go/client/client.go
  go/client/mimic.go           # optional build tag, excluded by default
  go/services/service001.go
  go/cmd/request-001/main.go
  src/client.mjs
  src/services/service-001.mjs
  requests/request-001.json
  examples/request-001.mjs
  evidence/capture.json        # when exact capture evidence is retained
  evidence/repeater-run.json   # when exporting a retained run
```

Neutral, fixed service/operation names avoid invented semantics and captured
values in filenames. The provenance file records the observed origin and
source identity. All captured values are JSON data, never interpolated into
executable client source. ZIP entries are deterministic stored UTF-8 records
with CRC-32, no compression, encryption, symlinks or ZIP64. Limits: 16 files,
1 MiB per file, 2 MiB per archive, 768 KiB per retained evidence document.

Go is the first entry point: from `go/`, run `go run ./cmd/request-001`
with Go 1.23+ for a dry run, or append `--send` after reviewing configuration.
Both clients share the root request, provenance, evidence and config files.
TypeScript and Python generators are not included in this version.

Run `node examples/request-001.mjs` with Node.js 22+ for the JavaScript dry run. No package
installation is needed. Copy `config.example.json` to `config.json`, review the
request and set `allowedOrigin` to its exact authorized origin. Only an explicit
`--send` sends a request. Redacted/unsupported projects additionally require a
complete reviewed `config.request`; evidence files remain unchanged. Changing
the target requires an explicit matching origin configuration. Mutating methods
can change server data. There are no automatic retries or redirect following.

## Explicit configuration and response checks

`config.example.json` now carries `configVersion: "reb-client-config-v1"`.
Missing version remains compatible with older local configs; other supplied
values and unknown keys fail. Configuration is edited in the exported folder;
no new UI selector changes a capture or silently sends a request.

- `transport`: `{ "mode": "standard", "browserProfile": null }` by default.
- `timeoutMs`: null inherits request `timeout_ms`; 100–30,000 overrides the
  entire send/read deadline. Request/config numeric tokens are safe integers,
  without fraction/exponent coercion.
- `redirectPolicy`: `manual` returns the first response; `error` reports any
  3xx as `redirect_refused`. Neither follows a same-origin or cross-origin hop.
- `cookiePolicy`: only `omit` is supported. No automatic cookie/session sharing.
- `responseChecks`: `statuses` (up to 32 distinct HTTP statuses), `contentType`
  (one lowercase media type without parameters), and `jsonFields` (up to 32
  explicit RFC 6901 pointer/type/optional-equality checks).

An authored stock-operation example is:

```json
{
  "statuses": [200],
  "contentType": "application/json",
  "jsonFields": [
    {"pointer":"/availability","type":"string","equals":"in_stock"},
    {"pointer":"/quantity","type":"number","equals":4}
  ]
}
```

No fields are inferred from a single capture. Empty status/field arrays and null
media type disable those checks. With none configured, the result reports
`validation: {"configured":false,"passed":false}`; HTTP 200 alone is not a
validated operation. A login page, unexpected status, missing quantity, null,
wrong type and wrong value remain distinct outcomes.

Pointers are at most 1,024 UTF-8 bytes and 32 segments; empty selects the root,
`~1` encodes slash and `~0` tilde. Array indexes are canonical decimal integers.
Types are null, boolean, number, string, array and object. Equality is limited
to matching scalar types and safe integer numbers. A numeric response equality
requires an exact integer token (no fractional/exponent notation), avoiding
rounding/underflow matches. JSON checks reject duplicate keys, invalid UTF-8 or
Unicode escapes, malformed/trailing input and nesting beyond 64. Content-Type
parameters are ignored but repeated fields are rejected. Configured checks
never validate a truncated response. This is bounded validation, not JSON Schema
or an inferred business model.

Library error codes distinguish `invalid_input`, `invalid_config`,
`unsupported_transport`, `unsupported_profile`, `wrong_origin`, `network`,
`timeout`, Go `canceled`, `response_read`, `redirect_refused`,
`response_status`, `response_content_type`, `response_truncated`, `response_json`,
`response_field_missing`, `response_field_type` and `response_field_value`.
File parsing may fail earlier. Go returns a typed `*client.ClientError` plus
Result; Node errors carry `code` and `result`. Neither error text nor automatic
logs dump captured response bodies. A transport error is not proof the server
did nothing; the CLI warns to check server state before another deliberate send.

## Optional Go profile adapter

`go/client/mimic.go` is excluded unless built with `-tags mimic`. It targets
[the exact saucesteals/mimic v1.0.2 source](https://github.com/saucesteals/mimic/tree/946a948a9b5a4360847b7f7d4b1f2e63f64ddc9e)
(commit `946a948a9b5a4360847b7f7d4b1f2e63f64ddc9e`, MIT). This API uses
`mimic.NewTransport(mimic.TransportOptions{...})` and the fhttp client, not the
incompatible current-main standard-net/http API. Go 1.24+ is required for the
optional dependency. The generated README gives explicit pinned `go get`,
build and run steps. Ordinary builds remain dependency-free and never download
it. Review and retain resulting module/sum files before use.

Only this coherent profile is accepted:

```json
{"mode":"browser-profile","browserProfile":{"browser":"chrome","version":"133.0.0.0","platform":"linux"}}
```

Mimic v1.0.2 maps all versions >=133 to uTLS `HelloChrome_133`; accepting newer
version strings would overstate support. Other brands/platforms/versions fail
before network. A standard build or Node client selecting the profile reports
`unsupported_transport`, never a silent downgrade. This is a selected
compatibility target, not evidence of the captured browser's exact build.
The allowlisted profile supplies matching User-Agent and low-entropy Client
Hints. It does not restore Accept-CH policy, browser state or credentials.

The adapter passes its own direct fhttp transport, avoiding Mimic's ambient
proxy default. Certificate verification remains enabled; jars, automatic
decompression and redirect following remain disabled. It creates a fresh
single-use connection transport and permits one transport dial invocation.
fhttp's internal HTTP2 retries must not create a second request: the guard
refuses another connection and the pinned single-use H2 pool refuses another
stream. Treat this runtime boundary as unverified until the tagged fixture lane
passes at the exact revision under review; source and test assertions alone are
not a passing acceptance result.

The explicit `node tools/check-captured-client-project.mjs --go --mimic` lane
builds/tests/vets the tagged module separately from standard `--go`. Its authored
fixtures assert HTTP header/profile coherence, dry-run/origin/redirect/cookie
boundaries, and certificate rejection. Owned HTTPS fixtures additionally require
successful ALPN HTTP/1.1 and HTTP/2 for GET, empty POST and text-body POST, with
exactly one connection and request. An isolated test subprocess trusts only its
ephemeral fixture CA through Go's certificate verifier; it never changes the OS
trust store or disables verification. Wrong-hostname and unknown-issuer cases
must still fail before an HTTP request reaches the server.

The H2 fault fixtures inject REFUSED_STREAM or GOAWAY with last-stream ID zero
only after receiving END_STREAM and the complete authored body. They count all
accepted connections and decoded request streams, requiring one of each and an
honest unknown-outcome error from the guarded client. Empty-POST negative controls
remove the dial guard and must observe a second complete request before stopping,
showing that the fixture reaches the underlying retry path. These cases do not
cover every fault timing or GOAWAY variant.

Only a successful exact-revision run establishes these bounded fixture results.
The lane prints its verbose test output and writes `mimic-test.log` plus
`mimic-validation.json` under `build/client-project-qa/`. Its offline module
receipt enumerates tagged package/test dependencies, not the complete lazy module
graph. ClientHello/HTTP2 equivalence against a pinned browser and complete
transitive license notices remain separate unverified gates. The pinned fhttp
v1.0.1 repository has no root LICENSE/COPYING/NOTICE file; resolve its notice chain
before distributing dependency code or binaries. No third-party source or binary
is bundled in the export.

No perfect TLS/browser fingerprint is claimed; JA3 alone is insufficient.
HTTP3/QUIC, browser execution fallback, automatic credential acquisition and
arbitrary-target testing are unsupported. Raw local evidence and best-effort
redacted exports retain their existing separate policy.

## Fidelity and unsupported cases

The Repeater editor displays normalized newlines, but preserves imported CR/CRLF
body text for submission until the user explicitly edits the body. The Body tab
discloses this distinction. History loads preserve the same representation.

Raw exports preserve the original retained capture/run and exact request input
strings, including repeated/encoded query keys and text-body whitespace. These
are **retained CDP strings/base64, not original HTTP wire bytes**. Primary CDP
events may omit duplicate wire lines, extra-info headers, casing/order and
other browser state. HTTP client URL/header normalization, automatic headers,
TLS, compression, CORS and storage behavior can differ.

Go uses standard `net/http` HTTP/1.1 with a fresh transport per deliberate send,
no ambient proxy, cookie jar or automatic response decompression. It requires
ASCII URLs and header values; non-ASCII originals remain in the evidence and
need deliberate reviewed reconstruction. Header casing/order, automatic
User-Agent, Content-Length and Connection differ from captured wire traffic.
TLS certificate verification remains enabled. There is no claim of browser
TLS or HTTP/2 fingerprint parity in the default lane. The optional profile lane
is a separately configured, source-pinned compatibility candidate described above.
Both generated file loaders reject duplicate JSON object keys, unknown or
incorrectly cased request/config keys, invalid Unicode and null header values instead of allowing silent decoder coercion. Library
error results distinguish a network attempt from confirmed request counts: a
transport error before any response reports an unknown (`null`) count, not zero.
Partial response failures preserve observed status, URL, headers and bounded body.
The Node client uses direct built-in HTTP(S), independent of ambient Fetch
dispatchers and proxy variables, with explicit certificate verification and no
automatic decompression.

The initial runnable clients support one complete UTF-8 text request with a
supported uppercase method, complete HTTP(S) URL, at most 64 header pairs and
64 KiB body. It rejects Fetch-forbidden methods, URL credentials/fragments,
duplicate header names, header whitespace/control/encoding losses, non-UTF-8
charsets, multipart/binary/unrecognized media types, encoded bodies, missing or
truncated inputs, and GET/HEAD bodies. Credentials and transport-controlled
headers (including Authorization, Cookie, Host, Content-Length and
Transfer-Encoding) require deliberate manual reconstruction; nothing is
silently stripped into a supposedly equivalent request. Literal Repeater
template delimiters are blocked from import but preserved in direct projects.

GraphQL operations sharing a URL remain distinct observations/requests, without
schema inference. Repeated query keys, pagination tokens and arbitrary JSON
shapes remain exact data; none are promoted into endpoint parameters. Binary,
multipart uploads and WebSocket handshakes are evidence-only. SSE/NDJSON and
other response streams are not modeled as an API: generated response text is
bounded to 64 KiB and the request timeout (100–30,000 ms), with explicit
truncation or timeout. Responses are not durable exports or streaming clients.
The generated client stops at redirects, including cross-origin redirects;
Repeater's existing isolated browser client follows redirects. Neither shares
the original browser's cookies or authentication state.

Raw exports can contain secrets and personal data. **Redacted copy** removes
header values and bodies and strips URL credentials/query/fragment in request,
response and capture evidence. Names, paths and identifiers can still be
sensitive. This best-effort copy never changes retained local data. Review
before sharing. The project `.gitignore` excludes request data, evidence,
provenance and local configuration, but it is not a security boundary.

## Validation

- `node tools/check-captured-client-project.mjs`: exact data/provenance,
  unsupported matrix, immutable redaction, ZIP integrity through Python's
  independent reader, generated Node client against an authored loopback
  server, no implicit sends, redirects, timeouts, response bounds, draft
  ownership/interruption and native save-result controller handling.
- Add `--go` to the client-project check with an installed Go compiler for
  generated `go build`/`go test`/`go vet` and authored loopback transport tests,
  including cancellation accounting, strict JSON decoding and untrusted TLS
  certificate refusal. This is
  required in Ubuntu CI. This standard lane disables module/toolchain downloads.
- Add `--mimic` only for the explicit optional lane. With an installed Go 1.24+
  compiler it fetches the exact upstream source pin through the Go proxy/sum
  database into a temporary project, then runs `go build/test/vet -tags mimic`
  offline. CI requests both lanes. No toolchain is installed automatically.
  Tagged compile/runtime evidence must be reported separately; standard Go
  success is not profile-provider coverage.
- `node tools/check-api-observation-catalog-ui.mjs --browser`: real UI catalog
  handoff, unsupported review, dirty draft confirmation, narrow desktop window
  geometry, exact draft values and explicit ZIP download. Uses authored data.
- `make app-build`: compiled native archive checks and normal app build.
  Packaged WebKit smoke validates owned-page malformed-payload rejection and
  subframe refusal. A test-only Xcode UI bundle targets the already-built,
  relocated app and clicks Apple's out-of-process Save panel. Its native smoke
  uses authored bytes and five real panels for Cancel/no-write, exact saved bytes, repeated-request refusal,
  actual atomic-write failure, navigation cancellation and replacement-document
  save. Test hooks require both explicit native smoke flags and accept no JS
  destination. Xcode screenshots and its result bundle are retained with the
  package diagnostics. The runner must already support Xcode UI testing; the
  test never changes Accessibility, TCC or system security settings.
  Overwrite confirmation and content-process termination during a
  save are not runtime-exercised. A Linux cloud environment cannot compile or
  visually verify the macOS panel; report macOS CI evidence separately.
