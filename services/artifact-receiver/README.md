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
    --max-store-bytes 268435456
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
of the 256-bit token. Each accepted artifact receives a fixed acknowledgment
only after its immutable blob and manifest entry are committed. A rejection
closes that connection because declared frame lengths cannot be trusted for
resynchronization. The live launcher treats that as the end of the artifact
receiver for the session.

Response bodies are rejected by default. Add `--allow-sensitive` only for a
session whose visible authorization scope explicitly permits bounded response
body capture.

The store contains immutable SHA-256-named blobs plus `manifest.jsonl`. In
standard-input mode, the receiver stops on invalid or rejected input because a
pipe cannot resynchronize safely.
