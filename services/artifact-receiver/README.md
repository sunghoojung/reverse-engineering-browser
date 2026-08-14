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

Response bodies are rejected by default. Add `--allow-sensitive` only for a
session whose visible authorization scope explicitly permits bounded response
body capture.

The store contains immutable SHA-256-named blobs plus `manifest.jsonl`. The
receiver stops on invalid or rejected input because the development pipe cannot
resynchronize safely. The browser integration will use an authenticated local
IPC connection owned by the browser process.
