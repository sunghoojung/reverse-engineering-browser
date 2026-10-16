# Capture launch provenance v1

`ARTIFACT_STORE/capture-provenance-v1.json` records the launch mode for exact
session IDs. The [schema](capture-provenance-v1.schema.json) admits only
`native-stealth`, `cdp-attached`, and `unknown`. The live launcher writes it
privately and atomically after browser startup succeeds. `native-stealth` means
that launch omitted the DevTools endpoint; `cdp-attached` means it opened the
endpoint for CDP. Neither asserts undetectability, inspector-domain activation,
or a current connection. No inspector-hiding control is introduced.

The bounded reader accepts at most 64 KiB and 1024 sessions. Session IDs are
canonical, nonzero uint64 strings. Duplicate JSON keys, duplicate session IDs
(including matching repeats), invalid modes, symlinks, non-regular files, and
unknown fields fail validation. A missing file or session resolves to `unknown`.
The sidecar contains no target URLs, credentials, or captured bytes.

New VM analysis documents include `capture_mode` and
`inputs.capture_provenance_digest` (SHA-256 of the exact sidecar bytes, or null).
These fields are inside the document digest. Existing analysis v1 documents
without them remain readable as unknown. Workspace documents carry their own
aggregate mode and each workspace's exact interpreter-session mode. Aggregate
mode is known only when every retained input record has the same declared mode;
empty, conflicting, or unmarked sessions remain unknown. Per-workspace modes
can therefore differ from a mixed aggregate. Copy the sidecar with its local
store to preserve provenance; copying an event file alone proves no mode.

The HTTP cache tracks sidecar identity and changes along with event and manifest
inputs. Invalid provenance fails analysis visibly instead of keeping a guessed
mode. VM Lab prefers the selected workspace's stored mode only when it belongs
to the current analysis digest, otherwise the analysis aggregate. A live or
missing debugger never relabels stored evidence.
