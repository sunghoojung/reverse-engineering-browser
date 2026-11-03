# Request Origin Trace v1

Request Origin Trace works backward from a captured network request through
relationships already present in normalized evidence. It gives a researcher a
short, inspectable chain before they move to a more expensive runtime or replay
experiment.

## Why this feature

Reverse-engineering workflows are most useful when a claim can be checked
against retained evidence. Request-first traces, origin following, evidence
graphs, differential experiments, and explicit verification oracles recur
across the reviewed research tools. The repository already captured stable
session, process, frame, artifact, request, event, parent, and initiator
identifiers, but its request backtrace screen used sample data. This feature
connects those existing identifiers without adding capture work to the renderer.

## Evidence path

1. The event broker validates and stores a normalized event.
2. An optional broker cold-path index emits up to three fixed-size edges for
   that accepted event.
3. The HTTP or native application handler reads bounded event and edge tail
   windows and selects one concrete request-start event.
4. The query walks backward for at most 32 steps.
5. The UI renders every step, confidence label, retained-evidence gap, and
   supporting record as text.

The edge store is append-only JSONL. Its version 1 contract is
`protocol/origin-trace-edge-v1.schema.json`. Query results use
`protocol/origin-trace-document-v1.schema.json`.

## Relationship semantics

- `parent_event` is an explicit same-process parent identifier.
- `request_initiator` is an explicit renderer-to-browser initiator identifier.
- `request_lifecycle` joins events only when their full retained request
  identity matches. Request target and body records
  ([native network v2](../../protocol/native-network-v2.md)) join their
  lifecycle parent only through `parent_event`; lifecycle edges skip them.
  Their binary payloads appear in a step as a fixed record summary, never
  decoded as text.
- `artifact_request` joins an artifact event to a matching request identity and
  is labeled `correlated`, not causal.
- `issued_during_invocation` joins the renderer's request record to the start
  record of the JavaScript invocation that was current when script started the
  request. It is observed identity, not value flow.
- `invocation_settlement` joins a settle record to its invocation's start
  record by the same identity.
- `invocation_value_flow` is not an edge. It is a trace step, labeled
  `correlated`, only where identity ends at the renderer's request record and
  exactly one settled value's exact digested bytes occur in a retained body of
  that request. See
  [native JavaScript invocation](../../protocol/native-js-invocation-v1.md#identity-and-relations).
- `temporal_adjacency` is not an edge. It is reported only where the identity
  chain has already ended, for one cross-process record of the same request
  identity within a bounded `monotonic_time_ns` window, and is labeled
  `time_adjacent`: a third confidence class that is weaker than `correlated`.

Observed edges preserve explicit identifiers. Correlated edges preserve shared
context only. The index never claims that one event's value produced another
event's value. Reused request IDs without a concrete process and sequence root
produce an ambiguous result instead of an arbitrary trace.

## Bounds and failure behavior

- The broker index has the same configured capacity as broker retention and
  evicts deterministically in insertion order.
- Each ingest emits at most three edges and performs no work when the optional
  trace store is disabled beyond one cold-path branch.
- Renderer probes, the shared-memory queue, and browser-process transport are
  unchanged.
- HTTP and native readers retain at most 10,000 events, 30,000 edges, and
  10,000 artifact records for one query. Event records are capped at 4 KiB,
  edge records at 2 KiB, and artifact records at 8 KiB.
- Traversal stops after 32 steps and reports `step_limit`. A time-adjacent row
  may occupy the last step without the limit being the reason traversal stopped.
- Timestamp proximity is bounded to one millisecond, requires a different
  process and the same nonzero request identity, is refused outright when more
  than one record qualifies, and is terminal: no traversal continues from it, so
  it can never add an observed or correlated link. It is counted only in
  `time_adjacent_links` and leaves `linked_steps` and `percent` unchanged.
  Both builders always emit that field. It is additive within contract version
  1, so a reader treats its absence in an older document as zero; an older
  reader still rejects a document that contains a `time_adjacent` step.
- Missing retained predecessors, cycles, ambiguous request identifiers, and
  events with no predecessor remain visible as named gaps.
- Native queue-drop markers share their last retained event's reference. They
  are validated separately and never become request roots or predecessor steps;
  duplicate addressable events still fail closed. A trace reports one
  `capture_gap` when its retained session/process streams contain such markers,
  including markers whose anchor is outside the event window. This is a stream
  coverage warning, not proof of a missing predecessor or value flow. Repeated
  markers remain counted as marker records, not a unique lost-event total.
  Coverage compares recorded links with named gaps, including this warning.
- A named capture-limit gap, whose payload is a reason such as
  `native_wasm_dispatch_budget_incomplete` rather than a drop count, takes its
  own sequence slot and is a sampling limit of its own category. Like Traffic,
  a request trace neither counts it as a `capture_gap` nor refuses the window
  over it. A gap whose payload is neither a count nor a reason identifier is
  still malformed.

## User workflow

Select any live network request in Traffic and choose **Trace origin**. The
trace remains available when structured request fields were not captured. The
result starts at the exact request-start event selected by the UI, works
backward to the earliest retained browser signal, and exposes the same records
under Supporting evidence.

The current feature traces event origin. Exact field-level JavaScript value
provenance and asynchronous continuation capture remain future work.
