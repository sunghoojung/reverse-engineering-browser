# Native response artifact linkage component pipeline

Run the component and production-service checks:

```sh
python3 tools/check-native-artifact-capture.py \
  --receiver build/reb-artifact-receiver \
  --broker build/reb-event-broker
```

Add `--analyzer /path/to/origin-trace-vm --backend /path/to/origin-trace-backend`
for the real analyzer and loopback HTTP/UI-controller path. The configured
`make native-artifact-capture-check` runs these stages. `--output NEW_DIRECTORY`
retains an inspectable corpus and refuses an existing directory. With no optional
binaries, the native sinks and in-process production receiver are still compiled
and executed; omitted stages are explicitly reported as skipped.
`REB_PROBE_TEST_SANITIZERS=address,undefined` enables instrumented component builds.

## What actually executes

- The unchanged production `native_network_capture_sink.cc` assigns request and
  response sequences. The unchanged `native_artifact_capture_sink.cc` admits the
  source body, carries its exact response creator, processes completions, and
  emits the capture result.
- Production `ArtifactReceiver::ReceiveOne` consumes the actual native artifact
  wire bytes, validates them, computes the content hash, and persists source and
  metadata. ACK status and artifact ID come from its return value and
  `LastArtifactId`, not a canned success callback. Its ACK is serialized through
  the matching production/native wire structures before delivery to the sink.
- Optional production artifact-receiver and event-broker executables read those
  unchanged bytes over their supported stdin boundary. Metadata and immutable
  bytes are compared with the in-process receiver's store. Corpus wire hashes
  must remain unchanged after every downstream stage.
- Optional `origin-trace-vm` analyzes the retained repository-authored
  `tools/fixtures/vm-workspace-effects/stack.js` and initialized runtime bytes.
  Candidate results and their exact request links are asserted. No interpreter
  source, guest program, or captured code is executed to make a finding.
- Optional `tools/check-vm-request-linkage-ui.mjs --pipeline` starts the real
  backend, loads its HTTP evidence, and invokes the production Traffic/VM
  controller. The pipeline runner supplies `REB_VM_LINKAGE_PIPELINE` (manifest)
  and `REB_VM_LINKAGE_BACKEND` (binary). The shared opcode cache remains
  session-wide; the selected workspace resolver must match the exact artifact,
  content hash, and finding, and resolve no workspace for an unlinked request.

## Cases

The native corpus contains unique exact matches, two independent out-of-order
body/ACK matches, a stored body without a delivered ACK, a missing creator,
generated JavaScript, runtime allocating source/typed-array bytes, and a reused
request ID with distinct BrowserContexts. All sources deliberately share a URL,
so URL matching cannot distinguish them. Browser sequences are natively emitted
above `2^53`, exercising decimal-string identity preservation through JSON and UI.

Additional component assertions cover old body and old ACK completion after
same-session and different-session emitter reconfiguration, disable/re-enable,
expiry, disabled/category/disconnected admission, an invalid body, unknown MIME,
declared size and metadata limits, the 32 MiB active reservation bound and release,
tee and enqueue failure, incomplete bodies, generated/runtime input validation,
real receiver rejection and duplicate/unknown ACKs.

`manifest.json` identifies `session_dir` and cases with exact request selection
objects and `expected_artifact_ids`. `events.bin`, `artifacts.bin`, and `acks.bin`
are native output, not hand-written golden evidence. `cases.json` is expectation
metadata, never substituted into production evidence. `in-process-artifacts`
also contains independent lifecycle-test artifacts that are deliberately excluded
from the corpus sent to the optional production services.

## Deliberate limits

Chromium process/thread/time/profile types and the browser sequence allocator
are minimal adapters. The Mojo adapter schedules the real sink's body callback
but does not test data-pipe forwarding, backpressure, watches, or Chromium task
execution. The artifact socket enqueue adapter allows deterministic delayed,
missing, reordered, and rejected transfers; it does not test the production
socket writer's queue/thread/authentication behavior. Only the receiver return
status creates an ACK in the normal success and rejection cases.

The runner reports whether AF_UNIX socket creation is permitted on the current
host. An unavailable AF_UNIX boundary does not masquerade as socket coverage:
service replay uses stdin even when sockets are available. This is not a Brave
checkout build, a V8/Blink capture runtime, a rendered-browser UI test, or macOS
packaged-app acceptance. Those remain separate repository/Brave validation gates.
All retained bytes are authored test fixtures, never private captures.
