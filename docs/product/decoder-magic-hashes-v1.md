# Decoder Magic and SHA-2 v1

In the existing Decoder operation menu, **Identify and hash** contains an
explicit **Magic: suggest encodings** operation and SHA-256/384/512 digests.
Choose input encoding first: UTF-8 means hash the literal text bytes; hex/base64
input means parse those bytes before hashing. The operations are also available
in the existing native worker, loopback API and native app bridge:

```sh
build/reb-decoder transform magic-inspect < input.bin
build/reb-decoder transform sha256 < input.bin
build/reb-decoder transform sha384 < input.bin
build/reb-decoder transform sha512 < input.bin
```

SHA operations produce lowercase hexadecimal digests of the exact input bytes,
without a trailing newline. They are unkeyed SHA-2, not HMAC, encryption,
password hashing, identity/authenticity proof or a reversible transform. No
secret lookup, password cracking or network request is made.

## Magic is a suggestion report

`reb-decoder-magic-v1` lists every supported candidate, without ranking or
silently choosing one. `automatic_transforms:0` and `meaning_verified:false`
are always explicit. Candidates use categorical confidence, not invented
probabilities:

- `syntax-only`: even ASCII hex, valid base64/base64url syntax/pad bits, or
  bounded JSON syntax. Ordinary text can satisfy these grammars accidentally.
- `signature-only`: a gzip fixed header or zlib CMF/FLG match. Body completeness,
  dictionary requirements and checksum remain unverified. No compressed content
  is inflated by Magic, including a possible decompression bomb.

The report also states UTF-8 validity. A 32/40/64/96/128-character hex string
gets a length-only digest-shape observation with algorithm **unknown**. Length
alone neither identifies an algorithm nor establishes that data is a digest.
No automatic hash algorithm or password interpretation is inferred.

Magic performs bounded syntax validation, including local base64 parse checks,
but emits no decoded preview and applies no suggested transform to the chain.
To follow a suggestion, select the original input or earlier step and explicitly
append the chosen operation. Appending a transform to the Magic report instead
would transform its JSON bytes. Original input/history/provenance stay available.
There is no recursive detection or automatic chain search.

## Limits and evidence

Existing native decoder limits remain: 1 MiB input/output, bounded worker
execution, 16 chain steps and 4 MiB retained history. Each explicit operation
keeps the existing success/failure behavior; failed later steps do not rewrite
prior source bytes. No changed credential access or network permissions.

`make magic-decoder-check` exercises the actual native executable. SHA vectors
are compared with independent Node crypto at empty/UTF-8/binary/padding/block/
1-MiB boundaries and a fixed known SHA-256 vector. Magic fixtures cover ambiguous
hex/base64, invalid padding, binary/invalid UTF-8, inert JSON, header-only and
malformed compression candidates, oversized expansion without inflation,
length-only digest ambiguity, byte bounds and exact C++/Rust/Swift/UI/OpenAPI
capability parity. Production chain functions verify explicit-only execution,
root/history retention, failed steps, report-byte hashing and deliberate branching
using the actual CLI with DOM rendering stubbed.
The check is included in normal and sanitizer gates. Rendered/native-platform
acceptance remains a separate UI validation requirement.

Sanitizer checks run the same parser through a test-only driver linked to the
same decoder object. Production process limits remain unchanged. The driver
is not shipped; strict status and diagnostic checks make sanitizer findings
fatal rather than mistaking them for malformed-input rejection.
