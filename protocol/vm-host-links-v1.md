# VM host links v1

The closed [schema](vm-host-links-v1.schema.json) defines
`ARTIFACT_STORE/analysis/vm-host-links-v1.json` and
`GET /api/analysis/vm/host-links`. The report binds the exact workspace document
digest and each interpreter artifact ID and source SHA-256. Its document digest
uses the existing sorted-key ASCII canonical JSON, excluding `document_digest`.
Hashes identify content, not authenticity or authorization.

Only the already admitted, deduplicated VM event stream and retained validated
workspace samples participate. The report has one row for every workspace of
that document; workspace producers before 2.21.0 kept 256 workspaces, so
reports bound to them hold at most 256. Each workspace counts the host events sharing
the interpreter's session, navigation and frame (`frame_host_records`) and
those naming the interpreter artifact (`attributed_host_records`), and names
the `get_events` parameters that list them (`events_filter`). It lists the
host events naming the interpreter whose direct parent is a VM record, as only
those can carry a guest position. A proven guest position additionally requires the exact
interpreter artifact, same process/session, and a direct `parent_event_id` naming
an earlier retained dispatch sample whose invocation and PC units were validated.
Shared frame, invocation, opcode, approximate time, or a matching index alone
cannot prove a guest position. A conflicting duplicate event identity was removed
by the analyzer before this join. Unretained samples do not prove a link.

Rows carry host category/type, original host event identity and a nullable guest
position with sample/invocation event identities, invocation ID, PC and units.
They never copy the host payload. A direct dispatch-parent link is `observed`;
a VM-record parent without that proof is `correlated`; absent samples are
`unknown` with reason `dispatch-samples-unavailable` and `guest_position` null.
That state is the static-only sampler gap. It is not an empty workspace and it
is not a guest program counter. Same session, navigation, and frame counts a
host event, including `network`/`request_initiated`, as correlation only. It
does not identify the Wasm loader and does not prove request-value provenance.
VM Lab prints the reason, the null guest position, and that limitation on the
workspace and on each host-link row. It does not invent a PC. Request edges
retain their existing correlated-not-causal semantics: even an exact dispatch
link does not prove where request values originated.

No row is dropped: every listed host event is in the report, and every other
host event of the frame is in its counts. Named omissions distinguish absent
dispatch samples, truncated sample retention and absent host events.
Invalid/failed report generation does not suppress the independent VM analysis
or opcode workspace API. The UI binds report and source digests before display,
rejects stale/malformed replies, retains matching prior rows on failure, shows
the counts, and pages the rows 64 at a time.

## Owned clock fixture

The explicit `reb-native-vm-fixture --emit-host-dispatch-events-v1` mode accepts
the same fixture and eight identity arguments as
[owned dispatch export](vm-opcode-workspace-v2.md#owned-producer-and-instruction-units).
Both compiled owned programs perform a real native monotonic-clock read after
instruction-index 2 commits. A runtime/api_call event identifies
`owned.monotonic_clock.after_instruction` and directly names that instruction's
sample as parent. The callback is a declared cooperative boundary in this owned
fixture, not browser API capture and not captured JavaScript execution. The
caller-supplied artifact binding remains a reference claim. Fixed event storage
is populated at instruction boundaries and exported only after the bounded run.
Existing dispatch-only/disabled/interactive modes do not gain a host call.

`make native-vm-recorder-check` runs both actual compiled host modes through the
broker. `make e2e` additionally runs the actual analyzer, checks PC 2 and original
host/sample identities, then checks absent samples, shared invocation alone,
and conflicting host identities. Tests use only authored fixtures. No page
JavaScript probe, browser attachment or target request is introduced.

Caller-supplied `vm_dispatch_report` positions are never native parent evidence.
They are explicitly excluded from guest-position joins and from the native
sample-availability check, so caller-only workspaces retain
`dispatch-samples-unavailable` even when report rows are visible. See
[caller report v1](vm-dispatch-input-v1.md).
