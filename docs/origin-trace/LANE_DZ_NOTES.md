# Lane DZ, wave53 `monotonic_time_ns` proximity as its own confidence class

**Backend and UI change landed; no browser attestation.** Origin Trace now
declares timestamp proximity as a third correlation confidence class,
`time_adjacent`, reported beside the identity classes rather than inside them.
Where the identity chain ends, one cross-process record of the same retained
request within a bounded timestamp window is shown as a terminal
`temporal_adjacency` step. It is counted only in the new `time_adjacent_links`
coverage field. It never becomes an `observed` or `correlated` link, never
replaces the `no_predecessor` gap, and never moves `linked_steps` or `percent`.

The repository gate proves the class in both document builders and in the
production UI consumer. No Brave toolchain exists on this machine, so nothing
here is attested inside a running browser against live capture.

## Why the class exists

Lane DV measured a POST pair whose two records already matched at roughly
113 µs on `monotonic_time_ns` while every identity join failed. Lane DX then
established that the failure is structural, not a missing field:
`OriginTraceIndex` keys `kRequestInitiator` edges on
`(session_id, initiator_request_id, initiator_process_id)` and resolves them
through `ResolvePendingInitiators`. When that resolution does not close, no
edge exists, the renderer `request_initiated` record is simply absent from the
trace, and the browser `request_started` reports `no_predecessor`. Restoring
`frame_id` does not change this, because the index never correlated on
`frame_id`.

Before this change the retained renderer record was invisible in the document
even though it was in the window. The researcher had no way to see that a
candidate existed, and no way to see on what basis it was a candidate. The
alternative of widening the identity edge would have meant inventing a join the
capture layer did not record. Declaring proximity as a separate, visibly weaker
class shows the candidate and shows exactly how weak the claim is.

## Mechanism

Implemented identically in `apps/origin-trace-backend/src/origin_trace.rs`
(`adjacent_candidate`) and `apps/research-ui/macos/OriginTraceDocument.swift`
(`adjacentCandidate`). The macOS application serves `/api/origin-trace` from
the Swift builder, so parity is a correctness requirement, not a convenience.

Proximity is consulted at exactly one place: the point where backward traversal
finds no edge out of the current event and the current event is not a source
boundary. That is the same place the `no_predecessor` gap is emitted. A
candidate must satisfy all of:

- the current event is itself a `network` lifecycle record;
- it is an addressable retained event, not a queue-drop marker;
- it is not already a step in this trace;
- same `session_id` as the current event;
- `category` is `network`;
- same nonzero `request_id` as the current event;
- a different `process_id` from the current event;
- `monotonic_time_ns` at or before the current event's;
- the difference is at most `ADJACENCY_WINDOW_NS`, one millisecond.

If exactly one event survives, it is projected as a step with relation
`temporal_adjacency` and confidence `time_adjacent`. If zero or more than one
survive, nothing is reported and the gap stands alone.

## Why this is a correlation input and not the failed join repeated

The scope fields above narrow the candidate pool; `monotonic_time_ns` is the
field that selects within it. The scope fields are deliberately not the keys
the index failed on: nothing here reads `initiator_request_id`,
`initiator_process_id`, `parent_event_id`, or `frame_id`. A request identity
shared across two processes is not sufficient on its own, because the renderer
and browser records of unrelated retries can share it inside one session; the
timestamp bound is what makes a single pair resolvable. Equally, a timestamp
bound alone is not sufficient, because a busy renderer produces many records
inside one millisecond. The class is the conjunction, and the document says so
in the gap detail and in the step's inspector text.

## Why proximity cannot inflate `correlated_links`

Three independent reasons, each enforced by a check:

1. **It is terminal.** The adjacency row is appended at a `break`. Traversal
   never continues from it, so no identity edge can ever be walked out of a
   timestamp match and counted as `correlated`. `identity_preempts_time_adjacency`
   also proves the reverse: when an identity edge exists, proximity is never
   consulted at all.
2. **It is counted elsewhere.** `observed` and `correlated` are incremented only
   inside the edge branch. `linked_steps` is computed as
   `steps - 1 - time_adjacent_links`, so an adjacency row raises the step count
   without raising the link count, and `percent` keeps the identity-only
   numerator and denominator.
3. **The contract refuses the alternative.** Both schema copies pair the
   relation and the confidence with `if`/`then`, cap `time_adjacent_links` at 1,
   and require it. `isOriginTraceResponse` in
   `apps/research-ui/evidence_models.js` additionally rejects a document whose
   adjacency row is counted as a link, is not the last step, or arrives without
   the `no_predecessor` gap it failed to close.

## Known bounds

- **One millisecond is a chosen bound, not a measured distribution.** It was
  picked to cover DV's observed 113 µs renderer-to-browser hop with roughly an
  order of magnitude of headroom while staying far below navigation scale. No
  lane has characterised the real distribution of that interval across machines
  or load. A slower hop is reported as no candidate, never as a wider match.
- **Cross-process clock comparability is assumed.** `monotonic_time_ns` is
  compared across two processes' records. The ordering requirement is
  one-directional on purpose: a candidate that skew places after the current
  event is dropped. Skew can therefore hide a real pair, but cannot invent an
  order or produce a reversed claim.
- **Ties are refused, not ranked.** Two candidates inside the window produce no
  row. In a busy capture this will be the common outcome for requests with more
  than two retained network records, so absence of an adjacency row is not
  evidence that no renderer record exists.
- **Adjacency is not causality and not invocation ownership.** The class says
  two retained records share a request identity across a process boundary and
  sit close together on one clock. It does not claim either produced the other,
  and no value flow is implied. The same wording appears in the gap detail, the
  row label, the inspector, and the coverage tooltip.
- **At most one row per trace.** The bound is structural, not a cap on a larger
  candidate set: more than one candidate means no row at all.
- **Only a network head is scoped.** An artifact, VM or Wasm event at the end of
  the identity chain keeps the bare `no_predecessor` gap. Those records can
  carry a request identity, so an adjacency claim there would be mechanically
  possible, but no lane has characterised that interval, so it is not made.
  `time_adjacent_only_scopes_a_network_head` pins this.
- **A step slot can be consumed at the limit.** The adjacency row may occupy the
  32nd step. Both builders subtract `time_adjacent_links` before testing the
  step limit, so that is not misreported as the traversal having run out of
  budget.

## Privacy

No new field is read and no new data is retained. `monotonic_time_ns` is
already a projected step field on every row, and the adjacency row is a record
the retained window already held. This lane does not touch body retention;
DV's separate retention question is out of scope here and remains a policy
decision under [`SAFETY.md`](../../SAFETY.md).

## Changed files

| File | Purpose |
| --- | --- |
| `apps/origin-trace-backend/src/origin_trace.rs` | The class, the bounded selector, and identity-only coverage arithmetic |
| `apps/research-ui/macos/OriginTraceDocument.swift` | The same mechanism in the native builder that serves the macOS app |
| `protocol/origin-trace-document-v1.schema.json` | Relation and confidence values, their pairing, and `time_adjacent_links` |
| `protocol/openapi.json` | The mirrored document schema and the declared behavior on the route |
| `apps/research-ui/evidence_models.js` | Contract admission, including the invariants that keep proximity out of coverage |
| `apps/research-ui/app.js` | One shared row classifier, the new relation label, and the coverage summary |
| `apps/research-ui/app.css` | A row style that does not rely on color discrimination alone |
| `apps/origin-trace-backend/assets/origin-trace-gap-cases.json` | Shared events, one identity edge, and seven cases |
| `apps/origin-trace-backend/tests/http.rs` | Case assertions and the step-budget regression |
| `tools/check-origin-trace-gaps.swift` | The same case assertions against the native builder |
| `tools/check-investigation-navigation.mjs` | Production-consumer, classifier and renderer assertions |

## Validation

Run in `/tmp/hsw-lane-worktrees/reb-DZ-proximity-corr`.

| Command | Result |
| --- | --- |
| `make lint` | passed |
| `make check` | passed |
| `make e2e` | passed |
| `make sanitize` | passed |
| `git diff --check` | passed |
| `make app-build` | passed, including `check-origin-trace-gaps` in pipeline |
| `codesign --verify --deep --strict "build/Origin Trace.app"` | passed |
| `cargo test --test http origin_trace` | passed, 4 tests |
| `node tools/check-origin-trace-debugger.mjs --field-provenance-only` | passed |
| `make rendered-ui-check` | unavailable: `xcrun: error: missing DEVELOPER_DIR path: /Applications/Xcode.app/Contents/Developer`; only Command Line Tools are installed |
| `make brave-doctor` | skipped: no file under `browser/integration/brave/`, no pin and no probe changed |
| `make brave-probe-check` | skipped: same reason |

`make app-build` compiles the production Swift builder and runs
`tools/check-origin-trace-gaps.swift` against the same shared fixture the Rust
HTTP test consumes, so native parity is proven at the builder level in the
packaged pipeline, and the resulting bundle verifies its signature. The rendered
UI was not driven: `make rendered-ui-check` needs full Xcode for its hosted
XCTest and none is installed, so no screenshot evidence exists for the new row
label, its style, or the coverage line. The global Xcode selection was not
changed.

Every new case was confirmed to fail before the change: setting
`ADJACENCY_WINDOW_NS` to 0 fails the Rust case and traps the Swift check, and
removing the coverage invariant from `evidence_models.js` fails the navigation
check.

This is repository and component evidence. It does not attest the class inside
a running Brave build, against live capture, or in the rendered Origin Trace
application. No live session, capture clear, or `native_console start` occurred.
