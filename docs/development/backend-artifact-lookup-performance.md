# Exact artifact lookup performance

Measured on 2026-10-23 against main `f81f757c797711d48e02a9647988971a1b94f3a0`.
This is a targeted backend change, not a claim that browser capture, UI rendering,
all API routes, or full application startup have been optimized.

## Finding and change

A 16-byte artifact content request still validated and parsed every JSON row in
`manifest.jsonl`, allocated every row's JSON tree, and rebuilt duplicate-ID
tracking. Repeating the request repeated that work. Blob hash verification is
required and remains unchanged; manifest JSON parsing was the avoidable cost.

The candidate retains at most 64 MiB of exact manifest bytes and 100,000 numeric
ID/offset pairs, with no retained JSON trees or blob contents. It rereads the
manifest and checks file identity/change stamps before reusing a byte-identical
terminated prefix. Unchanged rows need no new JSON trees; append-only growth
validates new rows, and the selected row alone is materialized for the API.
Rewrites, truncation, rotation, malformed rows, duplicate IDs, observed concurrent
changes, and missing files cannot silently use a stale result.

Oversized stores use the original complete streaming validator under the same
five-second deadline. The cache guard is dropped before streaming, while the
original reader permit remains held. A single file-identity/minimum-size hint
avoids repeated preflight reads for over-record-cap stores. It can only choose a
full scan, never authenticate an artifact; shrink and replacement clear it.
A same-size rewrite to fewer, larger rows can remain uncached, without changing
validation. On non-Unix platforms, index reuse is conservatively disabled.

This trades bounded extra memory and cold index-building work for faster repeated
lookups. Previous and current manifest buffers can coexist, up to 128 MiB plus
one bounded index. Every warm lookup still rereads bytes: this is not an O(1)
disk lookup, a content-integrity cache, or a stopped-store lease.

## Reproduction

Both preserved binaries were built with the same release toolchain, Rust
`1.99.1 (58cf8f9c3 2026-10-13)`, on the same Linux x86_64 cloud host. The baseline
and candidate use separate worktrees/build outputs; no debug/release comparison
or shared-target executable replacement is involved. Binary SHA-256:

- Baseline: `50517b3bd41ea39d797bcd04f724786b9ef4c32205d758fab23784fbf538f41e`
- Candidate: `de84131c0f11b84d1492b3f9350c97ab0284713823c531873a66d1be43ff9b8e`

Build each revision and preserve its executable before switching revisions:

```sh
CARGO_TARGET_DIR=/tmp/reb-baseline-target cargo build --release --locked \
  --manifest-path /path/to/baseline/apps/origin-trace-backend/Cargo.toml
CARGO_TARGET_DIR=/tmp/reb-candidate-target cargo build --release --locked \
  --manifest-path /path/to/candidate/apps/origin-trace-backend/Cargo.toml
```

Run the candidate's benchmark script against each preserved executable. It
creates only authored synthetic metadata and a 24-byte blob, starts its own
loopback backend and validates every 16-byte HTTP response. It never opens a real
capture store. Alternate baseline/candidate order in successive paired rounds;
run with other builds idle. For example:

```sh
taskset -c 0 python3 tools/benchmark-artifact-lookup.py /path/to/backend \
  --records 50000 --rounds 1 --warm-reads 5 --parallel 1
```

Each round uses a fresh backend process. "Cold" means process/index-cold, not a
flushed kernel page cache. After cold and warm requests, one valid manifest row
is appended and requested again. Parallel samples time the entire batch, not one
request's average. CPU time is the backend process's user plus system time over
startup and all requests in the round, excluding Python fixture generation.

## Results

Primary paired run, both processes pinned to CPU 0 to reduce migration noise.
The four-request case consequently tests concurrent admission on one CPU, not
four-core throughput. All figures are medians in milliseconds, baseline →
candidate. The 50,000-row manifest is 22,038,894 bytes.

| Requests per batch | Pairs / warm batches per process | Process-cold | Warm | After append | Backend CPU per round |
| --- | --- | --- | --- | --- | --- |
| 1 | 5 / 5 | 222.6 → 251.7 | 219.8 → 22.0 | 216.6 → 20.3 | 1533.0 → 367.5 |
| 4 | 3 / 1 | 872.4 → 323.1 | 875.8 → 70.2 | 872.7 → 84.3 | 2591.9 → 468.4 |

For individual requests, warm latency fell about 10.0× and seven-request-round
backend CPU fell 76%. The cost is visible: the first individual lookup was 13%
slower while constructing the index. Cold samples ranged 218.8–240.5 ms before
and 244.7–377.8 ms after; the 25 warm samples ranged 207.0–281.4 ms before and
15.4–29.4 ms after. The cold concurrent batch benefits because its first request
builds one shared index instead of all four independently parsing the manifest.

An earlier complete unpinned paired run also exercised ordinary and over-cap
concurrent reads. The 100,001-row case is 44,089,337 bytes (ID cap only); the
160,000-row case is 70,608,895 bytes (byte cap). Two paired rounds per row below,
except three for the first row:

| Records / requests per batch | Warm batches per process | Process-cold | Warm | After append | Backend CPU per round |
| --- | --- | --- | --- | --- | --- |
| 50,000 / 1 | 5 | 240.3 → 357.3 | 225.4 → 29.6 | 236.1 → 64.7 | 1677.5 → 720.0 |
| 50,000 / 4 | 1 | 384.2 → 340.4 | 322.7 → 104.0 | 317.4 → 92.9 | 3323.5 → 555.0 |
| 100,001 / 1 | 3 | 489.4 → 539.5 | 466.0 → 441.6 | 580.5 → 445.5 | 2523.5 → 2304.9 |
| 100,001 / 4 | 3 | 896.9 → 796.4 | 833.0 → 679.2 | 785.4 → 679.6 | 13969.5 → 11404.9 |
| 160,000 / 4 | 1 | 1236.1 → 1108.2 | 1373.2 → 1071.3 | 1239.0 → 1640.8 | 12395.4 → 12505.2 |

No speedup is claimed for over-cap full scans. Their complete validation is
unchanged; the ID-cap first lookup pays one bounded read/lookahead before
streaming. The byte-cap CPU difference was under 1%, with large latency noise
(including a slower append median). In development, attempting the over-ID-cap
preflight on every request added 12–15% CPU; the final metadata-only hint removes
that repeated attempt, with a regression asserting zero preflight bytes on
subsequent growing-file lookups.

The final pinned batch completed both 50,000-row cases, then stopped on an HTTP
408 in the *baseline* second 100,001-row pair. No partial pinned over-cap timing
is included and the deadline was not increased to make the benchmark pass. The
complete unpinned over-cap comparisons above all returned validated content.

The measurements are observations, not timing assertions or portable guarantees.
The shared host is noisy; the regression tests assert semantic behavior and
bounded work, not hardware-dependent wall-clock thresholds. Full blob hashing
can dominate requests for larger content, so these gains must not be extrapolated
to large-blob transfer or unrelated endpoints.

## Regression coverage and validation

New tests compare cached results/errors with complete scanning, including warm
reuse, append, maximum unsigned IDs, same-size rewrites with restored mtime,
replacement, truncation, deletion/recreation, malformed/oversized rows, duplicate
IDs, unterminated tails, symlinks, observed mutation, expired deadlines, byte/ID
caps, and overflow-hint recovery. Admission tests prove cancelled cache waiters
do not consume reader permits and streaming fallback releases the cache guard
without dropping its reader permit or resetting the deadline. HTTP tests warm a
selection, replace it, and ensure malformed/duplicate rows after it still fail.
The existing full-blob corruption/range test remains intact.

Final-source checks:

- Full backend `cargo test --locked --offline --manifest-path
  apps/origin-trace-backend/Cargo.toml -- --test-threads=1`: passed, 377 tests,
  eight existing ignored tests. This includes 284 library and 73 HTTP tests.
- Final backend `cargo clippy ... -- -D warnings`, `cargo fmt --check`, benchmark
  Ruff/bytecode checks, and `git diff --check`: passed.
- `make lint`: passed before the final overflow hint; the affected Rust and
  Python checks were rerun on final source and passed.
- `make check`: unavailable beyond `native-network-capture-check`; the cloud
  sandbox rejects `AF_UNIX socket: Operation not permitted`.
- `make e2e`: unavailable at `check-native-console.py`; creating its AF_UNIX
  socket raises `PermissionError: [Errno 1] Operation not permitted`.
- `make sanitize`: unavailable after building sanitized native targets;
  LeakSanitizer reports that it does not work under ptrace. A synthetic broker
  input reproduced that runtime failure, rather than an application sanitizer
  finding. No sanitizer success is claimed.

An earlier parallel debug suite, run during other build/benchmark work, hit two
unrelated evidence-package resource/deadline limits. Both tests passed in
isolation without code/limit changes; the complete final serial suite also
passed. Release HTTP tests passed separately. Native transport/sanitizer checks
still need an unrestricted supported runner. No Mac, native app packaging, or
full Chromium build was exercised by this backend-only change.
