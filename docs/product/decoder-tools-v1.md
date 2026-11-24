# Decoder Tools v1

Decoder Tools provides the pinned WireBrowser decoder-chain and JWT workflows
through Origin Trace's local architecture. It does not change captured evidence
and does not run transforms automatically.
Project-wide authorization and data-handling policy is defined in
[`SAFETY.md`](../../SAFETY.md); this document describes the local decoder
controls and their limits.

## Researcher workflow

The Tools workspace has two explicit modes:

1. Decoder chain accepts UTF-8 text, canonical Base64, or hex bytes. Each
   submitted transform becomes a selectable step. A researcher can inspect the
   original input or any result, remove a suffix, or branch from an earlier
   result.
2. JWT inspector decodes a compact token without presenting that action as
   verification. HMAC verification requires a separate click and secret.
   Creation supports HS256, HS384, HS512, and an explicitly confirmed unsigned
   test token.

Sources **Decode range** can copy a verified original byte range of any length
into a fresh decoder chain. This is an ephemeral pivot. It does not modify or
persist the evidence. The former Request Field Trace handoff and **Find sources
for result** read CDP-retained request bodies and were retired with them; see the
historical [Request Field Provenance](./request-field-provenance-v1.md) design.

## Transform set

The native engine implements:

- standard and URL-safe Base64 encode and strict canonical decode;
- hex encode and decode;
- URL-component percent encode and decode;
- arbitrary-precision decimal and Base36 conversion of any length, converting
  nine decimal or six Base36 digits per machine word;
- gzip, zlib, and raw-deflate compression and decompression;
- validating JSON pretty-print and minification.

HTML entity encode and decode runs against inert browser text in the UI. It
never inserts decoded output into the live document. All displayed inputs,
results, JWT fields, and claims use text-only DOM insertion.

## Native execution boundary

`reb-decoder` is a C++20 command-line process shared by the development server
and packaged macOS app. The process accepts raw or length-framed bytes over
standard input, writes only the result to standard output, and receives JWT
secrets through standard input rather than process arguments.

The process disables core dumps, so captured bytes never reach a core file, and
limits itself to the few descriptors it needs before parsing input. It has no
CPU-time, memory, or output-size limit: a decode runs as long as its input
needs. Both native bridges run one operation at a time, and a request waits for
the one before it as a queued task rather than a blocked thread. Neither has a
wall-clock deadline, which would refuse work only because the machine is busy.
The page shows the elapsed seconds while an operation runs, and **Cancel**, or
the request going away for any other reason, stops it, whether it is waiting or
running.

The C++ engine uses zlib for streaming compression and decompression, handing
input larger than zlib's 32-bit counter over in pieces. Gzip decoding consumes
all concatenated members and reuses the inflater state between members. Zlib and raw-deflate decoding accept exactly one stream.
Trailing garbage, corrupt members, and truncated members fail without returning
partial output. SHA-256, SHA-384, SHA-512,
and HMAC are implemented without a runtime service or network dependency, are
covered by independent reference vectors, and compare signatures without an
early byte mismatch exit.

## Size and failure behavior

Transform inputs and outputs, chain steps, retained chain bytes, compact JWTs,
HMAC secrets, JSON nesting, and JSON tokens have no fixed size. JSON is parsed
with an explicit stack, so nesting costs heap rather than the call stack, and a
decompression bomb inflates as far as the researcher lets it run. The page holds
every step's bytes until the chain is reset, and its text, hex, and Base64 views
preview the first part of a large result.

Malformed encodings, invalid JSON, unsupported operations, unavailable helpers,
cancellation, and a decoder that ends on a signal remain visible errors. The UI keeps the last completed chain intact when a later operation
fails. Binary results can be viewed as a bounded hex dump or Base64 without
forcing UTF-8.

## JWT trust model

JWT decoding only validates compact structure, canonical Base64URL segments,
JSON objects, and one string `alg` header. It labels decoded
claims as untrusted until an explicit supported HMAC verification succeeds.
Unsupported algorithms are decoded but never reported as verified. `alg:none`
must have an empty signature and is always labeled unsigned.

The UI evaluates `exp`, `nbf`, and `iat` as separate claim-time observations.
A valid signature does not imply that a token is unexpired, active, intended
for a particular audience, or otherwise authorized. Secrets are held only in
password inputs for the current action and cleared after creation or
verification.

## Contracts and tests

The browser and native app expose a version 2 capability contract at
`/api/decoder` and version 1 action contracts at `/api/decoder/actions`.
Version 2 of the capability contract dropped the version 1 `limits` object.
Responses carry operation IDs, input and output sizes, duration, and
binary-safe result representations. The UI rejects missing, unexpected, or
mismatched response fields.

Native tests cover each transform, binary values, reference JWT signatures,
long-message hash blocks, wrong secrets, unsigned and unsupported algorithms,
duplicate algorithm headers, malformed compression, and inputs past every
former cap: a million nesting levels, 300,000 tokens, 20,000 Protobuf fields,
5,000 gRPC-web frames, 200,000-digit Base36, 64 MiB inflation, and a 270 KB JWT
with a 10 KB secret. HTTP tests cover a queue longer than the two seconds a
request once had and cancellation when a request goes away. Service, HTTP, browser-contract, desktop, narrow-layout, and packaged-app
smoke checks cover the complete user path.

Structured wire inspection adds explicit Protobuf, gRPC-web binary and gRPC-web text operations. See [wire inspection v1](protobuf-grpc-v1.md) for schema-unknown semantics, source offsets, framing and limits.

The existing chain also supports [Magic suggestions and explicit SHA-2 digests](decoder-magic-hashes-v1.md). Magic identifies bounded syntax/signature candidates only; it never follows guessed transforms automatically.
