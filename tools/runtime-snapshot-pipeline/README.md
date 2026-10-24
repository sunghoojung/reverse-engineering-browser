# Runtime snapshot component pipeline

Run from the repository root after building the receiver, broker and Rust backend:

```sh
python3 tools/check-runtime-snapshot-pipeline.py \
  --receiver build/reb-artifact-receiver \
  --broker build/reb-event-broker \
  --analyzer apps/origin-trace-backend/target/debug/origin-trace-vm \
  --backend apps/origin-trace-backend/target/debug/origin-trace-backend
```

`make e2e` includes this check. `--output` may name a **new** directory to retain
owned-fixture output for inspection; existing output is never overwritten.
`REB_PROBE_TEST_SANITIZERS=undefined` or `address,undefined` instruments the
compiled capture component. Omitting `--analyzer` explicitly skips analysis;
omitting `--backend` skips the HTTP stage.

The driver compiles the production renderer admission sink, event queue and
browser artifact capture sink unchanged. Authored JavaScript source and initialized
buffer bytes enter the native sink. The browser sink, not the test, assigns parent
artifact IDs. Its unchanged wire records pass through the real artifact receiver
and broker, then the Rust analyzer and optional HTTP backend. The shipped UI model
validators accept the resulting reports, with runtime snapshots but no invented
guest dispatch samples or program counters.

Cases cover creator-ring rejection and recovery, deterministic reconfiguration
interleavings at creator/artifact emission, renderer/context/frame parent identity,
disabled/expired/stale capture, rejected parent enqueue and missing source. The
scope case directly invokes the browser boundary to check exact identity; it does
not claim that its supplied creator IDs were emitted by a renderer.

The narrow adapters replace Chromium platform types, Mojo delivery and the
artifact socket queue. `NativeProbeTransport::EmitStatus` rejects in this
driver because that Mojo queue is not linked; runtime snapshots still use the
injected emitter. The test does **not** execute a JavaScript allocator,
V8/Blink allocation hooks, real Mojo IPC or the browser socket writer. It does not
render the UI or establish patched-browser acceptance. Those gates still require
the supported pinned browser build and the owned task-checkpoint fixture.
