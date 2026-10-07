# Float32 comparison v1

`POST /api/float32/compare` (`reb-api call compare_float32`) inspects an explicit
binary32 buffer and optionally compares a reference. The authoritative closed
schemas are `Float32Request` and `Float32Result` in [OpenAPI](openapi.json).
`reb-api describe compare_float32` includes errors, input/result schemas, resource
bounds and advisory effects. This is in-process read-only analysis: no helper,
execution, browser control, capture, target/network request, persistence or upload.
Tools → Float32 comparison uses this same operation. Stored-evidence native mode
shows its actual backend prerequisite; it does not silently compute another result.

## Exact input and coverage

Every input declares `representation` (`float32-le` or `float32-be`), `channels`
(1–64), `frames` (0–65,536), and one closed `source`:

- `bits`: `words`, an array of exactly eight lowercase hexadecimal digits per
  word, most-significant digit first. Example: `3f800000`. These are raw word
  representations, not decimal floating-point values. The declared byte order
  determines their canonical byte serialization and SHA-256.
- `bytes`: `base64`, canonical padded RFC 4648 bytes, without whitespace.
- `artifact`: exact `session_id`, `artifact_id`, expected lowercase `sha256` and
  expected `byte_length`. No path or URL is accepted. The existing manifest
  validator must finish its complete bounded scan, including duplicate checks,
  before selecting a record. A match found before scan exhaustion is insufficient.
  The complete blob must then pass the existing length and SHA-256 verification.

The layout is interleaved: sample index `i` means frame `i / channels` (integer
quotient), channel `i % channels`, and original byte offset `4*i`. Byte length must
be exactly `channels * frames * 4`; partial, unaligned, truncated-by-declaration,
extra or impossible dimensions are rejected, never silently cropped. The input
identity records the SHA-256 of every supplied byte, complete size/count, declared
layout and source type. It does not authenticate an artifact or infer how its
bytes were obtained. An arbitrary selected retained artifact is interpreted only
under the caller's declaration; its kind is not evidence of audio samples.

Coverage refers to complete supplied buffers. It does not establish capture
completeness, graph parameters, sample rate, DSP implementation, environment,
CPU/browser identity, fingerprinting, maliciousness or behavioral equivalence.
No environment labels are inferred. No normalization or spoofing is performed.

## Numerical policy: binary32-finite-steps-v1

The engine retains `u32` words, classifies exponent/fraction/sign bits, and never
performs arithmetic on NaNs. Each detailed sample contains original `bits`,
`sign_bit`, class (`zero`, `subnormal`, `normal`, `infinity`, `nan`) and a finite
binary64 `value`, or explicit null for nonfinite values. Null is a declared
unavailable numeric projection, not JSON conversion of a NaN/Infinity. Raw bits
preserve every NaN representation, payload and sign bit; no signaling behavior or
portable NaN-sign meaning is claimed. Consumers must use raw bits and `sign_bit`
for negative zero because JSON consumers can normalize its numeric spelling.

- `raw_bytes_equal` compares entire serialized byte sequences, even if the
  declared representations/layouts differ. Read the separate match flags.
- Bit equality compares decoded binary32 words. Equivalent LE/BE sequences can
  have equal words but different raw bytes and input hashes.
- Numeric equality treats +0 and −0 as equal, same-sign infinities as equal, and
  every NaN as unequal, including itself. Finite values otherwise need equal bits.
- Absolute delta is `abs(binary64(a) - binary64(b))`. Relative delta is that delta
  divided by `max(abs(a), abs(b))`; zero against zero yields zero. It is symmetric,
  ranges from 0 to 2, and is not reference-only percentage error.
- ULP distance counts finite representable binary32 steps with both zeros at one
  position. For raw magnitude `m = bits & 0x7fffffff`, rank is `0x80000000 - m` for
  a sign bit of 1 and `0x80000000 + m` otherwise. Distance is the unsigned absolute
  rank difference. It is not raw signed-bit subtraction or delta/epsilon.
  −minimum-subnormal to +minimum-subnormal is two steps; −0 to +0 is zero.
- Caller-supplied `tolerances` are always echoed: finite pairs pass absolute OR
  relative OR ULP bounds. Zero tolerances are the UI starting values, not hidden
  engine defaults. Tolerance never changes bit/numeric equality. Nonfinite pairs
  have null deltas, ULP and tolerance outcome, even for equal infinities.
- Finite maximum deltas, maximum ULP, histogram and RMS use only finite pairs.
  RMS is square root of the sequential binary64 sum of squared binary64 deltas
  divided by finite-pair count. Per-input finite absolute sums use sequential
  binary64 addition in ascending sample order. The bounds keep intermediates
  finite. These are rounded binary64 diagnostics, not exact real arithmetic,
  compensated sums or claims to reproduce a browser DSP reduction.

The backend enables the existing `serde_json` `float_roundtrip` feature. Correctly
rounded numeric parsing matters both for caller tolerances and for the existing
CLI's parse/pretty-print boundary. No dependency version or lockfile changes.
A regression compares actual HTTP and CLI reports, including small relative
metrics; raw word identity never depends on JSON floating-point parsing.
The CLI uses the same typed syntax/scalar preflight and transmits original
request bytes, so duplicate members cannot disappear during generic JSON
re-serialization. Artifact loading and full layout verification stay at the server.

## Completeness and paging

With no reference, comparison and reference fields are null. Two empty buffers
have `status=empty`; full bit/numeric/tolerance verdicts are null, not a vacuous
successful comparison. Unequal lengths disclose both tails and compare only
aligned positional pairs for diagnostics. Different channel/frame declarations
report `layout_mismatch`. Either condition makes all full-array verdicts null.
Matching prefixes never imply full equality. A complete same-layout comparison
with NaNs may have all bits equal and all numeric unequal. The full tolerance
verdict requires a nonempty, same-layout comparison with every pair finite.

`detail.start` and `detail.limit` select a window over the larger sample count.
Details include index, byte offset, either sample (null for a missing tail), and
pair diagnostics (null without both samples). Aggregate metrics always cover all
supplied samples; paging cannot hide a mismatch. `next_start`, `returned` and
`total` expose the window. `first_bit_mismatch` covers paired positions only;
missing tails are separately explicit. An empty detail window at `start=total`
is allowed. A start beyond total is rejected.

## Bounds and errors

- 65,536 samples / 262,144 bytes per input; at most two inputs
- 2 MiB request body; 256 detail rows; 512 KiB serialized result
- Artifact manifest: complete scan at most 8 MiB and 8,192 physical lines,
  including blank lines, with the existing 8,192-byte line and 5-second
  cooperative scan checks. This opt-in overload preserves the old loader's
  default scan behavior for all existing callers.
- Existing four-slot blocking-I/O admission pool; one-second admission deadline.
  A dropped HTTP caller cannot release a running task's permit. Bounded work can
  finish after caller cancellation; there are no mutations to undo.
- Existing loopback origin guards, one Content-Length, no Transfer-Encoding, and
  five-second body deadline. Typed parsing rejects duplicate/unknown fields,
  unsupported versions, malformed hex/base64, nonfinite/negative tolerances and
  impossible dimensions. Input strings and unknown member names are not echoed.
- HTTP 400 invalid request, 403 origin rejected, 404 missing selected identity,
  408 body/admission/manifest deadline, 409 stale expected identity, 413 explicit
  resource exhaustion, 422 failed artifact integrity, 500 malformed store/internal
  failure, 503 unavailable admission. No unsuccessful read yields partial equality.

Tools preserves the last successful result and labels it stale on edits, failure,
cancellation or deadline. It binds successful reports to exact input hashes,
layout and tolerances, bounds streaming response bytes/chunks, and rejects stale
arrivals. Analysis is explicit; switching away cancels response ownership.

## Sources and original fixtures

The result's `source_ids` resolve in the existing analysis catalog. REB's
finite-step ordering and tolerance policy are versioned project definitions:
primary documentation supports representation facts, not an externally supplied
comparison algorithm.

- [Rust f32 documentation](https://doc.rust-lang.org/std/primitive.f32.html): raw
  bit conversions, NaN representation limits, signed-zero and NaN equality.
- [Oracle Single Format](https://docs.oracle.com/cd/E37069_01/html/E39019/z4000ac019178.html):
  sign/exponent/fraction layout and finite/exceptional encodings.

Original tests include positive/negative adjacency, exponent/subnormal boundaries,
cross-zero, maximum finite magnitudes, signed zero, NaN payload variants, infinity,
finite/nonfinite exclusions, and equal-sum/different-array controls. For example,
`[1,-1]` and `[0.5,-1.5]` have identical absolute sums without equal samples.
No vendor captures or external implementation code are included.
