# Native dedicated-worker metadata foundation (local v1)

## Status and scope

This dependency-free component is dormant. It records no production browser
activity and does not replace the existing CDP source route. It defines a
bounded local queue and single-consumer projection for dedicated-worker object
creation, scope start/disposal, successful classic/module compilation, direct
`Worker.postMessage` send/dispatch, messageerror, and termination requests.
These are separate observation points: compile success is not execution success;
send is accepted-for-handoff, not guaranteed delivery or a completed handler.
Lifecycle flags do not infer an ordered complete lifecycle.

No message content, source, URL, worker name, origin string, stack, JS value,
V8 handle, or GC object enters these metadata records. Sensitive source capture
remains a separate explicit policy in [native-worker-source-v1.md](native-worker-source-v1.md).
There is no renderer file/socket write, browserDrain shortcut, Rust counterpart,
normalized broker adapter, or production configuration/drain caller here.

## Identity and exact joins

A policy binds a nonzero session and strictly increasing generation, absolute
monotonic expiry, full browser-context and renderer-incarnation tokens, exact
worker and creator tokens, and creator kind. This is a browser-owned authority
contract, not authentication of an untrusted renderer. A browser controller must
validate the actual creator relation, storage-partition identity and selected
document/navigation generation before configuring; these browser checks are
not implemented by this local component. Do not infer authority from URLs,
PIDs, token claims, or nearest timestamps.

An accepted send returns a 24-byte `{session, generation, send_sequence}` tag.
The send sequence is the queue's saturating process-lifetime observation sequence;
exhaustion closes capture instead of wrapping. A future hook must copy this tag
into the actual moved message before handoff and copy it back at dispatch.
Receives with an all-zero tag remain explicitly unpaired. Partial, stale-epoch,
zero-sequence and future-sequence tags are rejected with loss accounting. A valid
receive whose send was not projected remains receive-only, never guessed.

Projection keys are carried send tags within the full authorized identity.
Repeated Chromium native trace IDs, including zero, are legal diagnostic values
and never establish a link. Duplicated endpoints or inconsistent direction/trace
metadata make that tag permanently ambiguous. The fixed projection never evicts
and reuses keys within an authority. V8 script IDs are worker/isolate-local hints;
repeated IDs are ambiguous, with compile-observation sequence kept distinct.
No source association, request-from-message edge, Promise/timer ancestry, or
MessagePort/SharedWorker/ServiceWorker coverage is inferred.

## Limits, retirement and loss

The queue owns 128 fixed 160-byte records. Projection owns at most 64 message
entries and 64 script entries. Both have constant storage; projection insertion
scans at most 64 entries. Inactive capture returns before locking or allocating.
Active Begin/Capture/Take try-lock once and never spin, block for capacity, post
unbounded tasks, or allocate. Configure/Disable/Stats are serialized control-path
operations and may wait for the mutex.

The queue must outlive all producers/consumers; Retire is not a callback join or
safe-destruction fence. The proposed renderer sink owns process-lifetime storage.
Worker Retire atomically stops only the ticket's matching capture generation.
Already accepted metadata, including a terminal disposal record, remains
readable until drained or expiry. An in-flight capture may complete if its final
active-generation check precedes retirement. Explicit Disable or reconfiguration
revokes publication and clears pending metadata; expiry does the same on Begin/Capture/Take.
Take rechecks readable generation before returning, and a future browser adapter
must revalidate authority before publishing. The controller must poll Take and
final Stats after retirement, enforce expiry on every read/publish, and explicitly
Disable when the drain is done. No timer or production controller exists here.
Projection Retire clears retained entries; Expire must be called on idle polls
and before exposing a retained view, not merely when new records arrive.

`attempted`, `dropped`, `stale`, and `retired` are exactly saturating lifetime
counters. `contended` uses a bounded atomic increment and overflow latch: at its
first uint64 wrap a concurrent Stats snapshot can transiently see a wrapped value
before the latch is published; subsequent snapshots remain UINT64_MAX. No
unbounded compare/exchange retry is hidden in the probe. This theoretical
2^64-contention boundary is a known local diagnostic limitation. `retired` counts unread records erased by revocation/expiry, not records
successfully drained after worker teardown. `pending_gap` and queued count refer
to the current authority. Malformed records and capacity overflow consume an
attempted sequence and increment drops; lock contention is separate/unattributed
because it can race generation changes. Take contention is not capture loss.
Sequence gaps, reported drops and lifetime drop totals overlap and must not be
summed. A final status read is required when no later record can carry a gap.
Projection explicitly counts rejection, out-of-order records, capacity loss,
missing sequences, reported loss, ambiguity, untagged receives and retired entries.

## Required later stages

1. Independently review exact-pinned, disabled native hook placement and prove
   the tag survives dedicated-worker direct moves and early-message buffering.
   Do not serialize or trust it through Mojo/MessagePort without a new contract.
2. Observe browser `DedicatedWorkerService` lifecycle/creator ownership, including
   nested workers arriving out of order, process death and lost teardown messages.
3. Add versioned, generation-bound, acknowledged bounded IPC. Reserve downstream
   bytes/slots before copying or posting; retain credit until browser acknowledgment.
   Bound tasks and work per drain; report disconnect and terminal losses. The
   existing general mapped probe queue is not sufficient for this guarantee.
4. Add browser validation, normalized broker/evidence projection and UI. Explicitly
   represent unknown ancestry, missing endpoints and unsupported worker kinds.
5. Test the full pinned build and authorized localhost classic/module/nested/blob,
   early message, messageerror, close/terminate/restart, expiry/revocation, queue
   pressure and disconnect paths before any production activation or CDP cutover.

## Focused verification

`make demo && build/reb-event-demo --queue-iterations 1000` exercises the component:
identity/creator-kind checks, malformed records, future times, lifecycle/compile,
zero/reused trace IDs, exact tag joining, false-pair prevention, stale tag rejection,
duplicate/direction ambiguity, missing endpoints, bounded capacity and gap recovery,
stale retirement, terminal dispose drain, explicit revocation, expiry and concurrent
capture/dequeue accounting. This is local component evidence, not browser acceptance.

## Dormant pinned hook stage

Chromium patch `0011-observe-dedicated-worker-metadata.patch` follows the source
foundation patch. It observes successful classic/module compile returns, worker
object creation, global-scope allocation (before V8 context initialization),
termination request and scope disposal. Window creators expose a LocalFrameToken,
not a document token; browser-side document/navigation generation remains required.
The observed LocalFrameToken/DedicatedWorkerToken variant is compared with policy
creator kind before admission; other parent variants are rejected.

Direct-message sends are observed after serialization/disentangling and before
native handoff in both directions. Dispatch observations occur immediately before
the success/messageerror DispatchEvent branches. They do not prove a listener ran
or completed. Early suppression, termination and absent callbacks remain missing
receives. Custom events and traffic over transferred MessagePorts are out of scope.
The added all-zero-default 24-byte tag is in BlinkTransferableMessage only. Pinned
defaulted move construction/assignment, CrossThreadBindOnce forwarding and early
TaskInfo ownership preserve it on these two direct paths. FromTransferableMessage
and Mojo traits deliberately do not copy/serialize it. No upstream trace-ID join,
inspector enablement or payload access is added.

The process-lifetime sink has a separate constinit disabled atomic gate. Disabled
checks never initialize its queue, acquire a static-init guard, or allocate. There
is deliberately no production activation API. If a teardown Begin loses to
contention, there is no ticket to retire; this explicit contention and missing
terminal observation require independent browser lifecycle revocation. A completed
Begin retires its exact ticket even if terminal Capture loses to contention/full.

The Blink-aware helper is an authored Brave overlay but belongs to Blink's core
GN sources; renderer_sink contains only dependency-free observation code and the
base-only sink. This prevents a reverse Blink-core include dependency in the sink.
GN/include-check correctness still requires validation with the actual toolchain.

Source applicability was forward/reverse checked against Git-blob-verified files
at Chromium commit `4744b886309d987d292e43232776d2206cccb13d`
(`151.0.7922.108`), after every preceding tracked Chromium patch affecting those
files. Brave stays `v1.95.52`; V8 stays
`20ad8d002c17ccc7ccfbefc6c4dcf1242fe80921`. This focused fixture is not an initialized
Brave checkout, complete synchronization check, GN generation or browser build.
`brave-probe-check` now lists all newly affected native objects. Full browser,
message move/early-queue runtime and UI/API acceptance remain release gates.
