# Artifact Receiver

The artifact receiver is a cold-path native service for JavaScript files, WASM
modules, source maps, and explicitly approved response bodies. It consumes the
framed contract in `include/reb/artifact.hpp` on its own input stream. It does
not share the event broker's input, queue, limits, or storage.

Build it with:

```sh
make artifact-receiver
```

The development fixture runs both independent paths:

```sh
make e2e
```

To receive a browser-process artifact stream directly:

```sh
build/reb-artifact-producer |
  build/reb-artifact-receiver \
    --store build/sessions/artifacts \
    --disk-reserve-bytes 4294967296
```

For the authenticated live transport, use a token already created by the event
broker and the same session identifier:

```sh
build/reb-artifact-receiver \
  --store build/sessions/live/42/artifacts \
  --socket build/sessions/live/42/artifact.sock \
  --token-file build/sessions/live/42/auth.token \
  --session-id 42
```

Version 2 streams interleave with whole frames on one input: an open header,
then data, checkpoint, end or abort frames, each acknowledged
([wire contract](../../docs/architecture/artifact-transfer-channel.md#streamed-artifacts-version-2)).
Any number of streams may be open at once; each holds only its metadata and a
partial file. A stream still open when its connection closes, or when standard
input ends, is discarded and counted as `streams_abandoned`.
Every stored byte is hashed on the receiver's one thread, with the ARMv8
SHA-256 instructions where the processor has them, and a socket connection asks
for a 1 MiB receive buffer so a whole data frame arrives in one read
([throughput](../../docs/architecture/artifact-transfer-channel.md#throughput)).

The socket is mode 0600 and accepts only same-user peers that prove possession
of the 256-bit token. Every frame must also match the authenticated session ID.
Stores and their files are restricted to the current user. Each accepted
artifact receives a fixed acknowledgment only after its immutable blob,
manifest entry, and containing directory entries are committed.

A rejected frame keeps the connection when its header is valid and matches the
authenticated session: the receiver reads and discards the rest of the frame,
whatever its size, through a fixed 64 KiB buffer and then acknowledges it. The
browser therefore always reads the real status, even for a body larger than the
socket buffers. An invalid header, a session mismatch or a truncated stream
leaves the stream unsynchronized, so the receiver acknowledges and closes that
connection. Socket mode then keeps the listener and
accepts a later authenticated connection; the browser reconnects within a
bounded budget and records an `artifact_channel_lost` gap if it cannot. The live
launcher stops the listener explicitly when the browser session ends.

Response bodies, request bodies, full request targets and Canvas data URLs are
rejected by default.
Add `--allow-sensitive` only under the sensitive-capture rules in
[`SAFETY.md`](../../SAFETY.md), for a session whose visible authorization scope
permits that bounded content. The live launcher adds it for
`REB_CAPTURE_CANVAS_IMAGES=1` or `REB_CAPTURE_REQUEST_CONTENT=1`.

The store contains immutable SHA-256-named blobs plus `manifest.jsonl`.
Manifest records preserve execution-context and capture-origin provenance for
runtime-generated source while remaining readable when those fields are absent
from older version 1 sessions.
The store has no artifact size, artifact count or manifest size limit. Its only
bound is the disk reserve below: every artifact, empty ones included, adds a
manifest record, and the reserve counts those bytes like any other. The
receiver's identifier set holds 8 bytes per artifact; readers that index the
manifest bound their own memory
([artifact lookup](../../apps/origin-trace-backend/src/artifact_lookup.rs)).

### Disk reserve

The store has no byte budget. Instead the receiver keeps free space on the
store's volume: it refuses any artifact, stream data frame or checkpoint copy
that would leave less than the reserve free, 4 GiB unless `--disk-reserve-bytes`
names another. The refusal is its own acknowledgment status, `disk_reserve`
(7), so the browser records it as `not_captured_disk_reserve` or as an
`artifact_capture_failed` record with that reason, never as a generic transfer
failure ([native network v3](../../protocol/native-network-v3.md#bounds-2)).
The free space counted is what `fstatvfs` reports available to this user, so
it excludes space only root may use and purgeable space macOS has not freed.
Each admission reads it again rather than caching it: a reading costs about
0.3 µs, a small part of writing one 64 KiB frame, and a fresh reading also sees
what the browser's cache, the event store and other applications wrote since.
Once space returns, later artifacts are accepted again.

4 GiB leaves room for what keeps writing to the same volume after artifacts
stop: the event store, which records every refusal; the capture browser's
profile and HTTP cache; and macOS itself, which places its swap files (1 GiB
each) and local snapshots on the boot volume and slows down or fails writes as
that volume nears full. It is small next to a typical free volume, and large
against what one admission can add: a data frame is at most 64 KiB, and a
checkpoint copies at most the stream it names. The live launcher passes
`REB_ARTIFACT_DISK_RESERVE_MIB`, when set, as `--disk-reserve-bytes`; tests set
it above the free space to force the refusal.

In standard-input mode, the receiver stops on invalid or rejected input: there
is no acknowledgment, so the exit status is the producer's only signal.

The receiver's stored-byte and manifest accounting always matches the files on
disk. A new blob counts from the moment it is linked. Any failure before its
manifest record is durable rolls the manifest back to the last acknowledged
record and then removes that blob. If the rollback itself fails, or the manifest
changed outside the receiver, the store stops accepting for the rest of the run
and answers every later frame with an I/O status. On start, a final record with
no newline, which only an interrupted append leaves and which was never
acknowledged, is cut back to the last complete record. The receiver reports the
removed byte count on stderr after `Artifact store ready`.

## Store ownership

`ArtifactReceiver` itself holds the immutable mode-0600 `evidence.reb-lock-v1`
guard exclusively from construction through its final close. A second receiver
or shared package export cannot bypass that ownership. Manifest, blob and
temporary I/O stays relative to pinned directory descriptors; symlink/hardlink
aliases fail before mutation. Temporary files use exclusive creation and blobs
use atomic no-clobber publication before manifest acknowledgment. An orphaned
temporary entry or unsupported linked store fails safely rather than overwriting
existing evidence. Store roots are user-owned and not group/other writable.

The fixed `Artifact store ready` diagnostic follows successful initialization;
the next line names the disk reserve in bytes.
A live idle receiver still owns its writer lease after the broker stops. Stop
this receiver before artifact package export; never remove or replace its guard.
See [Evidence Package v1](../../protocol/evidence-package-v1.md#cooperative-leases-and-safe-local-files)
for the cooperative threat boundary and legacy-store compatibility.
