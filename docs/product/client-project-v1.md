# Captured request client project v1

This cold-path workflow joins one retained Traffic observation to a reviewed
Repeater draft and an organized, dependency-free Node.js project. It does not
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

Run `node examples/request-001.mjs` with Node.js 22+ for a dry run. No package
installation is needed. Copy `config.example.json` to `config.json`, review the
request and set `allowedOrigin` to its exact authorized origin. Only an explicit
`--send` sends a request. Redacted/unsupported projects additionally require a
complete reviewed `config.request`; evidence files remain unchanged. Changing
the target requires an explicit matching origin configuration. Mutating methods
can change server data. There are no automatic retries or redirect following.

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

The initial runnable client supports one complete UTF-8 text request with a
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
- `node tools/check-api-observation-catalog-ui.mjs --browser`: real UI catalog
  handoff, unsupported review, dirty draft confirmation, narrow desktop window
  geometry, exact draft values and explicit ZIP download. Uses authored data.
- `make app-build`: compiled native archive checks and normal app build.
  Packaged WebKit smoke validates owned-page malformed-payload rejection and
  subframe refusal. A separate packaged smoke uses authored bytes and five real
  Save panels for Cancel/no-write, exact saved bytes, repeated-request refusal,
  actual atomic-write failure, navigation cancellation and replacement-document
  save. Test hooks require both explicit native smoke flags and accept no JS
  destination. Overwrite confirmation and content-process termination during a
  save are not runtime-exercised. A Linux cloud environment cannot compile or
  visually verify the macOS panel; report macOS CI evidence separately.
