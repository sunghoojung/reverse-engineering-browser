# Decoder Tools v1

Decoder Tools provides the pinned WireBrowser decoder-chain and JWT workflows
through Origin Trace's local, bounded architecture. It does not change captured
evidence and does not run transforms automatically.

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

Traffic can copy a selected request value into a fresh decoder chain. This is
an ephemeral text pivot. It does not modify or persist the request value.

## Transform set

The native engine implements:

- standard and URL-safe Base64 encode and strict canonical decode;
- hex encode and decode;
- URL-component percent encode and decode;
- arbitrary-precision decimal and Base36 conversion, capped at 4 KiB of input
  digits;
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

The process applies core-dump, CPU, file-size, and open-file limits before
parsing input. Linux also applies a 128 MiB address-space limit. macOS does not
provide a reliable address-space resource limit for this process, so every
input, output, parser, compression buffer, and cryptographic allocation is
bounded structurally. Both native bridges enforce a two-second wall-clock
timeout and serialize operations through one worker lock.

The C++ engine uses zlib for streaming compression and decompression. It stops
before retaining output over the configured cap. SHA-256, SHA-384, SHA-512,
and HMAC are implemented without a runtime service or network dependency, are
covered by independent reference vectors, and compare signatures without an
early byte mismatch exit.

## Limits and failure behavior

| Resource | Limit |
| --- | ---: |
| Transform input | 1 MiB |
| Transform output | 1 MiB |
| Pipeline steps | 16 |
| Total retained chain bytes | 4 MiB |
| Compact JWT | 64 KiB |
| HMAC secret | 4 KiB |
| JSON nesting | 64 levels |
| JSON tokens | 100,000 |
| Native operation | 2 seconds |

Malformed encodings, invalid JSON, decompression bombs, unsupported operations,
oversized data, unavailable helpers, and timeouts remain visible errors. The UI
keeps the last completed chain intact when a later operation fails. Binary
results can be viewed as a bounded hex dump or Base64 without forcing UTF-8.

## JWT trust model

JWT decoding only validates compact structure, canonical Base64URL segments,
bounded JSON objects, and one bounded string `alg` header. It labels decoded
claims as untrusted until an explicit supported HMAC verification succeeds.
Unsupported algorithms are decoded but never reported as verified. `alg:none`
must have an empty signature and is always labeled unsigned.

The UI evaluates `exp`, `nbf`, and `iat` as separate claim-time observations.
A valid signature does not imply that a token is unexpired, active, intended
for a particular audience, or otherwise authorized. Secrets are held only in
password inputs for the current action and cleared after creation or
verification.

## Contracts and tests

The browser and native app expose version 1 capability and action contracts at
`/api/decoder` and `/api/decoder/actions`. Responses carry operation IDs,
input and output sizes, duration, and binary-safe result representations. The
UI rejects missing, unexpected, oversized, or mismatched response fields.

Native tests cover each transform, binary values, reference JWT signatures,
long-message hash blocks, wrong secrets, unsigned and unsupported algorithms,
duplicate algorithm headers, JSON limits, malformed compression, and output
caps. Service, HTTP, browser-contract, desktop, narrow-layout, and packaged-app
smoke checks cover the complete user path.
