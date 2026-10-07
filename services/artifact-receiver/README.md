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
    --max-artifact-bytes 16777216 \
    --max-store-bytes 268435456 \
    --max-artifacts 4096 \
    --max-manifest-bytes 67108864
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

The socket is mode 0600 and accepts only same-user peers that prove possession
of the 256-bit token. Every frame must also match the authenticated session ID.
Stores and their files are restricted to the current user. Each accepted
artifact receives a fixed acknowledgment only after its immutable blob,
manifest entry, and containing directory entries are committed. A rejection
closes that connection because declared frame lengths cannot be trusted for
resynchronization. Socket mode then keeps the listener and accepts a later
authenticated connection, so a browser-side reconnect does not silently end
artifact capture. The live launcher stops the listener explicitly when the
browser session ends.

Response bodies are rejected by default. Add `--allow-sensitive` only under the
sensitive-capture rules in [`SAFETY.md`](../../SAFETY.md), for a session whose
visible authorization scope permits bounded response body capture.

The store contains immutable SHA-256-named blobs plus `manifest.jsonl`.
Manifest records preserve execution-context and capture-origin provenance for
runtime-generated source while remaining readable when those fields are absent
from older version 1 sessions.
Content bytes, artifact count, and manifest bytes have independent bounds, so
empty artifacts cannot grow storage or duplicate checks indefinitely. In
standard-input mode, the receiver stops on invalid or rejected input because a
pipe cannot resynchronize safely.

## Store ownership

`ArtifactReceiver` itself holds the immutable mode-0600 `evidence.reb-lock-v1`
guard exclusively from construction through its final close. A second receiver
or shared package export cannot bypass that ownership. Manifest, blob and
temporary I/O stays relative to pinned directory descriptors; symlink/hardlink
aliases fail before mutation. Temporary files use exclusive creation and blobs
use atomic no-clobber publication before manifest acknowledgment. An orphaned
temporary entry or unsupported linked store fails safely rather than overwriting
existing evidence. Store roots are user-owned and not group/other writable.

The fixed `Artifact store ready` diagnostic follows successful initialization.
A live idle receiver still owns its writer lease after the broker stops. Stop
this receiver before artifact package export; never remove or replace its guard.
See [Evidence Package v1](../../protocol/evidence-package-v1.md#cooperative-leases-and-safe-local-files)
for the cooperative threat boundary and legacy-store compatibility.
