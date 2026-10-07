# Native dedicated-worker authority and transfer (dormant v1)

## Status and trust boundary

This is a dependency-free, locally tested authority and transfer state machine,
plus an unbound Mojo schema. No `DedicatedWorkerService` observer, Mojo binder,
field-mapping adapter, browser controller, broker persistence route or activation
is installed. The existing CDP route remains unchanged. The [metadata hooks and
queue](native-worker-observation-v1.md) remain dormant. A schema or a passing
component test is not browser IPC or production security-boundary validation.

Only a browser control sequence may populate `NativeWorkerAuthority`. Its scope
binds one browser-context token, one storage-partition token, one selected frame,
one selected document token/generation, one observer epoch, one session and an
absolute monotonic expiry. The future observer must be attached to that actual
browser-owned context/partition's service, resolve document identity at creation,
and unsubscribe before destruction. Renderer token claims, URLs, PIDs and
proximity in time never establish ownership. A LocalFrameToken survives document
replacement and cannot establish the selected document by itself.

Each observed worker records its full token, renderer incarnation and exact
creator variant. Document parents require the frame token, document token and
document generation. Dedicated-worker parents resolve recursively through the
same browser-owned table, including out-of-order enumeration. Unknown parents,
cycles, conflicting ownership and retired ancestors remain unproven. The table
retains at most 64 workers and 64 renderer tombstones without eviction/reuse in an
epoch; overflow is counted. Exhausting renderer tombstones revokes the scope.

Only one current lease exists per authority. Issuing another invalidates the
prior lease and increments a non-wrapping generation. The lease additionally binds
a connection token and issue time; expiry is at most ten minutes after scope
creation. Exact document teardown, worker/ancestor destruction, renderer death,
explicit revocation, expiry and contradictory ownership invalidate publication.
Stale teardown epochs cannot revoke a later scope. Reset is deliberately
fail-closed: an invalid reset disables the current scope.

This prevents accidental or forged identity reuse at the local publication gate;
it does not make renderer evidence truthful. A compromised renderer can still
fabricate observations under its allowed lease. Browser-authoritative ownership
and renderer-observed behavior are separate claims.

## Bounded transfer and ownership

The renderer sender exclusively owns configuration of a queue that outlives it
and every capture callback. Destruction disables its active queue; closed senders
cannot revoke a later configuration. Sender, receiver and authority are not
copyable or movable. All endpoint methods are single-control-sequence operations;
there are no endpoint callbacks, posted tasks or remotes in this implementation.
The existing capture queue supports bounded concurrent producers separately.

The browser owns at most one outstanding pull and one unpublished staging slot.
It polls no more frequently than once per 20 milliseconds, with a five-second
request deadline clipped to lease expiry. One pull drains at most 16 of the
queue's 128 metadata records. The sender retains exactly one immutable batch,
reserving downstream credit until the browser explicitly acknowledges its full
acceptance. Dequeue alone is not acknowledgment. Retries without acknowledgment
return the identical pending batch and never drain more. Acknowledgments bind
connection, session, generation and batch ID; request and batch IDs cannot wrap.
Reconfiguring a receiver requires a new authority generation.

Every received batch is validated before staging: epoch, request ID, schema
version, reserved fields, fixed capacity, nonzero increasing batch ID, bounded
acknowledgment deadline, queue count, all record identities, operation semantics,
monotonic record sequences and timestamps within the current lease. Unused slots
must contain the canonical default record. No arbitrary byte blob, variable
array, URL, source, payload or message body crosses this schema. Local C++ structs
are not raw wire layouts; the future Mojo adapter must explicitly map every field,
validate the lease version and enum values, and reject conversion overflow.

`PendingForPublication` returns a borrowed batch only after checking the live
browser authority and acknowledgment deadline again. Use it only in bounded,
non-reentrant publication on that sequence. An asynchronous durable adapter must
condition its final commit on the same live authority generation; a late ack
cannot undo an unauthorized stale write. `AcknowledgePublished` is called only
after complete bounded downstream acceptance or persistence. A partial write is
not sufficient. The authority must outlive its receiver.

A production Mojo adapter must reserve its only request/reply credit before
posting work and retain it through callback completion. It must serialize
Configure/Pull/Revoke, bound configure and callback lifetimes, disconnect on
revocation with a pull outstanding, and call sender revocation on disconnect.
No renderer-to-browser event method exists. Fixed-size schema arrays bound one
message but do not alone bound IPC queues or protect a future implementation
from a compromised peer. These adapter requirements are unimplemented gates.

## Retirement, loss and limitations

Worker capture retirement preserves accepted terminal metadata until drained;
browser ownership retirement independently prevents stale publication. Queue
pressure remains nonblocking and reports drops. A stats-only batch reports losses
when no later event can carry a gap, including an empty retired queue. Poll on idle
as well as activity so expiry, request timeout and unacknowledged-batch timeout
cannot leave capture live indefinitely. Explicit sender revoke/disconnect clears
queued and staged metadata.

Queue counters are lifetime diagnostics; transfer counters independently report
staged/acknowledged records, retired in-flight records, invalid controls and
timeouts. Receiver counters report retired staging and abandoned requests. These
observations overlap, and an unacknowledged batch may already have been persisted:
do not add the counters or present their sum as exact lost events. Renderer
counters are untrusted claims. No new normalized loss event is emitted yet.

There is no source transfer, source/request association, cross-isolate script-ID
join, request-from-message edge, task/Promise/timer ancestry, MessagePort,
SharedWorker or ServiceWorker support here. Exact carried direct-message tags
survive the local transfer without converting native trace IDs into causal links.
No UI or Sources behavior changes in this stage.

## Verification and activation gates

`make demo && build/reb-event-demo --queue-iterations 1000` exercises disabled
state, endpoint destruction, out-of-order ancestry, cycles, conflicting ownership,
document/profile/partition/connection lease forgery, worker/process tombstones,
capacity, stale epochs, lease replacement, exact send-tag projection through
transfer, acknowledgment credit, replay, batch mutation, queue pressure, terminal
loss, expiry, publication-time revocation, timeouts and disconnect.

Run the repository's full lint/check/e2e/sanitize gate as well. Required browser
gates remain exact-pinned overlay/patch synchronization, generated Mojo and GN
include checks, affected-target compilation, full Brave build and authorized
localhost browser acceptance. Real service enumeration, navigation/BFCache,
process replacement, early-message buffering, controller teardown and IPC queue
pressure must pass before any activation or CDP cutover. Unavailable browser
checks must be reported as unavailable, never inferred from component tests.
