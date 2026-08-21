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
  identity matches.
- `artifact_request` joins an artifact event to a matching request identity and
  is labeled `correlated`, not causal.

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
- Traversal stops after 32 steps and reports `step_limit`.
- Missing retained predecessors, cycles, ambiguous request identifiers, and
  events with no predecessor remain visible as named gaps.

## User workflow

Select any live network request in Traffic and choose **Trace origin**. The
trace remains available when structured request fields were not captured. The
result starts at the exact request-start event selected by the UI, works
backward to the earliest retained browser signal, and exposes the same records
under Supporting evidence.

The current feature traces event origin. Exact field-level JavaScript value
provenance and asynchronous continuation capture remain future work.
